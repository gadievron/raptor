"""(v)snprintf truncation-boundary idiom family (item 8, CWE-193).

``n = vsnprintf(buf, sizeof(buf), ...)`` followed by ``n > sizeof(buf)``
(instead of ``>=``) treats the exact-fit return as untruncated — libc
reports would-be length excluding the NUL, so ``n == size`` IS a
truncated (NUL-clipped) buffer. A real instance of this shape lived in
an in-scope file the final comparison audit never reviewed. The rule
is universal libc vocabulary (tier-A — no project names).

Dispatch wiring is hermetic; the rule-behaviour tests run spatch and
skip when it is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_RULE = (
    _REPO / "engine" / "coccinelle" / "rules"
    / "snprintf_truncation_boundary.cocci"
)

# Recreated bio_print.c shape (not copied): vsnprintf into a stack
# buffer, wrong `>` boundary, buffer consumed afterwards — plus an
# operand-flipped snprintf variant.
_POSITIVE_C = """\
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

int emit_line(char *dst, const char *fmt, ...)
{
    char tmp[256];
    int n;
    va_list ap;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > sizeof(tmp))
        return -1;
    memcpy(dst, tmp, n + 1);
    return n;
}

int fmt_hdr(char *out, unsigned long cap, const char *name)
{
    int r;
    r = snprintf(out, cap, "hdr:%s", name);
    if (cap < r)
        return -1;
    return r;
}
"""

# The correct boundaries: >= size, and > size-1 (equivalent).
_NEGATIVE_C = """\
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

int emit_line(char *dst, const char *fmt, ...)
{
    char tmp[256];
    int n;
    va_list ap;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n >= sizeof(tmp))
        return -1;
    memcpy(dst, tmp, n + 1);
    return n;
}

int fmt_hdr(char *out, unsigned long cap, const char *name)
{
    int r;
    r = snprintf(out, cap, "hdr:%s", name);
    if (r >= cap)
        return -1;
    if (r > cap - 1)
        return -1;
    return r;
}
"""


class TestDispatchWiring:
    def test_rule_file_exists(self):
        assert _RULE.is_file()

    def test_rule_role_is_verification(self):
        from core.audit.sweep import get_rule_role

        assert get_rule_role(str(_RULE)) == "verification"

    def test_cwe_193_dispatch_entry(self):
        from core.audit.cwe_dispatch import cocci_rule_for_cwe, lookup

        assert lookup("CWE-193") is not None
        assert (
            cocci_rule_for_cwe("CWE-193")
            == "snprintf_truncation_boundary.cocci"
        )

    def test_fallback_chain_carries_cocci_and_census(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        types = {e["type"] for e in _cwe_fallback_chain("CWE-193")}
        assert "coccinelle" in types
        assert "consistency" in types  # pre-existing census family

    def test_hypothesis_keyword_inference(self):
        from core.audit.cwe_dispatch import infer_cwe_from_hypothesis

        assert infer_cwe_from_hypothesis(
            "vsnprintf return compared with > misses the exact-fit "
            "truncation case",
        ) == "CWE-193"
        assert infer_cwe_from_hypothesis(
            "off-by-one in the truncation boundary check",
        ) == "CWE-193"


def _spatch_missing() -> bool:
    from packages.coccinelle.runner import is_available

    return not is_available()


@pytest.mark.skipif(
    _spatch_missing(), reason="spatch not installed",
)
class TestRuleBehaviour:
    def _run(self, tmp_path, source):
        from packages.coccinelle.runner import run_rule

        target = tmp_path / "fixture.c"
        target.write_text(source)
        result = run_rule(
            target, _RULE, timeout=120, allow_scripting=True,
        )
        assert not result.errors, result.errors
        return result.matches

    def test_wrong_boundary_matches(self, tmp_path):
        matches = self._run(tmp_path, _POSITIVE_C)
        lines = {m.line for m in matches}
        assert len(matches) == 2, matches
        assert 14 in lines   # vsnprintf: n > sizeof(tmp)
        assert 24 in lines   # snprintf, flipped: cap < r

    def test_correct_boundaries_do_not_match(self, tmp_path):
        assert self._run(tmp_path, _NEGATIVE_C) == []
