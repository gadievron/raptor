"""Dispatch resolution for the straggler classes live runs warned
about: ``review emitted CWE-377 / CWE-150 / CWE-316 / CWE-323 but no
tool-chain dispatch entry exists``.

CWE-377 and CWE-150 are tool-verifiable and get real chains (cocci +
codeql for the temp-file races; joern taint plus a presence-capped
semgrep keyword leg for terminal escape injection). CWE-316 and
CWE-323 are not-tool-verifiable by policy — the adjudicating fact
(data sensitivity / cross-invocation nonce recurrence) is outside
every static tool's observables — so they join the policy park and
their refusals persist to ``suppressions.jsonl`` instead of falling
through to the loud unmapped warning. Hermetic — no LLM, no tool
subprocesses.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest

from core.audit.checker_synthesis import ondemand_synthesis_refusal_reason
from core.audit.cwe_dispatch import (
    cocci_rule_for_cwe,
    codeql_query_for_cwe,
    infer_cwe_from_hypothesis,
    joern_applicable,
    lookup,
    not_tool_verifiable_reason,
    sinks_for_cwe,
)
from core.audit.hypothesis_mapping import (
    _ESCAPE_INJECTION_PATTERN,
    hypothesis_to_semgrep_rule_keyed,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _cwe_fallback_chain,
    _hypothesis_to_tool_chain,
    _synthesize_unmapped_suspicious,
)
from core.audit.sweep import get_rule_role, negative_control_fixture

_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "engine" / "coccinelle" / "rules"
)


class TestCwe377InsecureTempFile:
    """Temp-file races → the new insecure_temp_file.cocci rule
    (name-generation APIs + mkstemp reopen-by-path) plus the Python
    CodeQL leg; fixed libc vocabulary, the CWE-367 TOCTOU sibling."""

    def test_dispatch_entry(self):
        entry = lookup("CWE-377")
        assert entry is not None
        assert cocci_rule_for_cwe("CWE-377") == "insecure_temp_file.cocci"
        assert codeql_query_for_cwe("CWE-377") == "py/insecure-temporary-file"
        assert not joern_applicable("CWE-377")

    def test_cocci_rule_on_disk_verification_role(self):
        rule = _RULES_DIR / "insecure_temp_file.cocci"
        assert rule.is_file()
        assert get_rule_role(str(rule)) == "verification"
        text = rule.read_text()
        # Both witness shapes present in the rule material.
        assert "mktemp" in text
        assert "mkstemp" in text

    def test_fallback_chain(self):
        types = {e["type"] for e in _cwe_fallback_chain("CWE-377")}
        assert "coccinelle" in types
        # The dispatch table's codeql value is a pack query ID
        # ("py/insecure-temporary-file") no resolver in this codebase
        # maps to a query file — run_codeql_sweep requires a file, so
        # the entry is not emitted (honest degradation instead of an
        # error on every dispatch).
        assert "codeql" not in types

    def test_keyword_inference(self):
        assert infer_cwe_from_hypothesis(
            "writes to an insecure temporary file created with mktemp "
            "before opening it",
        ) == "CWE-377"
        assert infer_cwe_from_hypothesis(
            "the temp file name from tmpnam is predictable and can be "
            "hijacked via symlink",
        ) == "CWE-377"

    def test_template_phrasings_do_not_misroute(self):
        # Word boundary after temp(?:orary)?: template/temperature
        # phrasings must not gain the temp-file chain (SSTI-shaped
        # hypotheses would lose their on-demand synthesis fallback).
        for hyp in (
            "insecure template rendering allows expression injection",
            "predictable template path lets the attacker pick the view",
            "insecure temperature threshold disables the rate limiter",
        ):
            assert infer_cwe_from_hypothesis(hyp) != "CWE-377", hyp

    def test_toctou_phrasing_keeps_routing_to_367(self):
        # Appended row: temp-file races phrased as TOCTOU keep the
        # earlier CWE-367 row (also a real chain).
        assert infer_cwe_from_hypothesis(
            "toctou race between stat and open on the temporary file",
        ) == "CWE-367"


def _spatch_missing() -> bool:
    from packages.coccinelle.runner import is_available

    return not is_available()


# All four insecure shapes: three name-generation APIs plus the
# mkstemp template reopened by path.
_TEMP_POSITIVE_C = """\
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int bug_mktemp(void)
{
    char tpl[] = "/tmp/appXXXXXX";
    if (mktemp(tpl) == NULL)
        return -1;
    return open(tpl, O_CREAT | O_WRONLY, 0600);
}

char *bug_tmpnam(void)
{
    static char buf[L_tmpnam];
    return tmpnam(buf);
}

char *bug_tempnam(void)
{
    return tempnam("/tmp", "app");
}

int bug_reopen(void)
{
    char tpl[] = "/tmp/appXXXXXX";
    int fd = mkstemp(tpl);
    if (fd < 0)
        return -1;
    close(fd);
    FILE *f = fopen(tpl, "w");
    if (!f)
        return -1;
    fclose(f);
    return 0;
}
"""

# Safe: mkstemp with the fd kept (fdopen), and a template pointer
# reassigned before the later open (different object, no race).
_TEMP_NEGATIVE_C = """\
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int safe_mkstemp(void)
{
    char tpl[] = "/tmp/appXXXXXX";
    int fd = mkstemp(tpl);
    if (fd < 0)
        return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return -1;
    }
    fputs("data", f);
    fclose(f);
    return 0;
}

int safe_reassigned(const char *other)
{
    char tpl[] = "/tmp/appXXXXXX";
    char *path = tpl;
    int fd = mkstemp(path);
    if (fd < 0)
        return -1;
    close(fd);
    path = (char *)other;
    FILE *f = fopen(path, "r");
    if (f)
        fclose(f);
    return 0;
}
"""


@pytest.mark.skipif(
    _spatch_missing(), reason="spatch not installed",
)
class TestCwe377RuleBehaviour:
    def _run(self, tmp_path, source):
        from packages.coccinelle.runner import run_rule

        target = tmp_path / "fixture.c"
        target.write_text(source)
        result = run_rule(
            target, _RULES_DIR / "insecure_temp_file.cocci",
            timeout=120, allow_scripting=True,
        )
        assert not result.errors, result.errors
        return result.matches

    def test_all_four_insecure_shapes_match(self, tmp_path):
        matches = self._run(tmp_path, _TEMP_POSITIVE_C)
        lines = {m.line for m in matches}
        assert len(matches) == 4, matches
        assert 9 in lines    # mktemp(tpl)
        assert 17 in lines   # tmpnam(buf)
        assert 22 in lines   # tempnam("/tmp", "app")
        assert 32 in lines   # fopen(tpl) after mkstemp at line 28

    def test_safe_usage_does_not_match(self, tmp_path):
        assert self._run(tmp_path, _TEMP_NEGATIVE_C) == []


class TestCwe150EscapeInjection:
    """Terminal escape injection → joern taint to the raw
    terminal-print sinks (CWE-90/829 precedent: joern+sinks-only
    entries are real chains); the semgrep keyword leg is
    presence-capped by its fixture."""

    def test_dispatch_entry(self):
        entry = lookup("CWE-150")
        assert entry is not None
        assert entry["joern"] is True
        sinks = sinks_for_cwe("CWE-150")
        assert "printf" in sinks
        assert "fputs" in sinks
        assert codeql_query_for_cwe("CWE-150") is None

    def test_joern_applicable(self):
        assert joern_applicable("CWE-150")

    def test_fallback_chain(self):
        types = {e["type"] for e in _cwe_fallback_chain("CWE-150")}
        assert "joern" in types

    def test_keyword_inference(self):
        assert infer_cwe_from_hypothesis(
            "terminal escape-sequence injection: attacker-controlled "
            "fields are printed with raw printf without filtering "
            "control characters",
        ) == "CWE-150"
        assert infer_cwe_from_hypothesis(
            "control bytes from a hostile input reach the operator "
            "terminal, enabling display spoofing",
        ) == "CWE-150"

    def test_existing_first_match_behaviour_unchanged(self):
        assert infer_cwe_from_hypothesis(
            "format string vulnerability: attacker controls the "
            "format argument",
        ) == "CWE-134"
        assert infer_cwe_from_hypothesis(
            "command injection via unsanitized filename",
        ) == "CWE-78"

    def test_semgrep_keyword_leg(self):
        keyed = hypothesis_to_semgrep_rule_keyed(
            "terminal escape-sequence injection via raw printf of "
            "untrusted fields",
            "show.c",
        )
        assert keyed is not None
        path, keyword = keyed
        assert keyword == "terminal escape"
        assert "printf" in Path(path).read_text()
        Path(path).unlink()

    def test_semgrep_leg_gated_to_c_family(self):
        # The pattern is a C printf idiom: on other languages a
        # zero-match would falsely refute e.g. SQL/regex
        # escape-sequence hypotheses (format-string/.go precedent).
        assert hypothesis_to_semgrep_rule_keyed(
            "escape sequence handling is broken in the query builder",
            "app.py",
        ) is None
        keyed = hypothesis_to_semgrep_rule_keyed(
            "terminal escape-sequence injection via raw printf",
            "show.cpp",
        )
        assert keyed is not None and keyed[1] == "terminal escape"
        Path(keyed[0]).unlink()

    def test_presence_fixture_wired(self):
        # The safe idiom (sanitize into a buffer, then print) is
        # textually identical at the printf site — the fixture MUST
        # match so the sweep caps the semgrep leg at inconclusive.
        fixture = negative_control_fixture("terminal escape", "a.c")
        assert fixture is not None and fixture.is_file()
        text = fixture.read_text()
        assert any(
            re.search(_ESCAPE_INJECTION_PATTERN, line)
            for line in text.splitlines()
        )

    def test_pattern_shape(self):
        # Unsafe shape: %s fed a bare variable/member.
        assert re.search(
            _ESCAPE_INJECTION_PATTERN, 'printf("%s\\n", key_id);',
        )
        assert re.search(
            _ESCAPE_INJECTION_PATTERN, 'fprintf(stdout, "%s", opt->name);',
        )
        # Filtered / non-terminal printf-family names must not match.
        assert not re.search(
            _ESCAPE_INJECTION_PATTERN, 'fmprintf(stdout, "%s\\n", key_id);',
        )
        assert not re.search(
            _ESCAPE_INJECTION_PATTERN,
            'snprintf(buf, sizeof(buf), "%s", name);',
        )
        # Sanitizer-wrapped argument (a call) must not match.
        assert not re.search(
            _ESCAPE_INJECTION_PATTERN, 'printf("%s\\n", vis_encode(name));',
        )


def _outcome(status="suspicious", hypothesis="h", cwe=""):
    o = ReviewOutcome(
        file="a.c", function="f", status=status,
        body="b", hypothesis=hypothesis, line=3,
    )
    o.review_result = {"hypothesis": hypothesis}
    if cwe:
        o.review_result["cwe"] = cwe
    return o


class TestNotToolVerifiable316And323:
    """CWE-316 / CWE-323: the adjudicating fact (which data is
    sensitive; whether a nonce recurs under the same key) is outside
    static observables — parked by policy with the reason recorded,
    never synthesis candidates."""

    def test_policy_reasons_present(self):
        assert not_tool_verifiable_reason("CWE-316")
        assert not_tool_verifiable_reason("CWE-323")
        assert not_tool_verifiable_reason("316")  # normalization
        # The newly dispatchable stragglers are NOT parked.
        assert not_tool_verifiable_reason("CWE-377") == ""
        assert not_tool_verifiable_reason("CWE-150") == ""

    def test_no_dispatch_entry(self):
        assert lookup("CWE-316") is None
        assert lookup("CWE-323") is None
        assert _cwe_fallback_chain("CWE-316") == []
        assert _cwe_fallback_chain("CWE-323") == []

    def test_unmapped_log_states_policy_not_synthesis(self, caplog):
        import core.audit.orchestrator as _orch

        for cwe in ("CWE-316", "CWE-323"):
            _orch._UNMAPPED_CWES_LOGGED.discard(cwe)
            caplog.clear()
            with caplog.at_level(
                logging.INFO, logger="core.audit.orchestrator",
            ):
                _orch._warn_unmapped_cwe(cwe)
            assert "not tool-verifiable by policy" in caplog.text
            assert "checker-synthesis candidates" not in caplog.text

    def test_refusal_reason_for_policy_classes(self):
        assert "not tool-verifiable by policy" in (
            ondemand_synthesis_refusal_reason("CWE-316", "any hypothesis")
        )
        assert "not tool-verifiable by policy" in (
            ondemand_synthesis_refusal_reason("CWE-323", "any hypothesis")
        )

    def test_refusal_persisted_to_suppressions(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "core.audit.checker_synthesis.synthesize_verification_rule",
            lambda *a, **kw: (_ for _ in ()).throw(
                AssertionError("synthesis must not run for refused class"),
            ),
        )
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)
        hypothesis = "the session nonce may repeat across connections"
        outcome = _outcome(hypothesis=hypothesis, cwe="CWE-323")
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        _synthesize_unmapped_suspicious(
            result, config, 0, outcome, hypothesis, "CWE-323", "src",
        )
        assert outcome.status == "suspicious"
        assert "not tool-verifiable by policy" in (
            outcome.review_result["synthesis_refused"]
        )
        assert result.ondemand_synthesized == 0
        recs = [
            json.loads(line)
            for line in (out / "suppressions.jsonl")
            .read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(recs) == 1
        rec = recs[0]
        assert rec["verdict"] == "synthesis_policy_refused"
        assert rec["dropped"] is False  # outcome SURVIVES at suspicious
        assert rec["cwe"] == "CWE-323"
        assert "not tool-verifiable by policy" in rec["reason"]


class TestWarningTail:
    def test_no_empty_dispatch_warning_for_dispatchable_stragglers(
        self, monkeypatch,
    ):
        import core.audit.orchestrator as _orch

        warned = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        for cwe in ("CWE-377", "CWE-150"):
            chain = _hypothesis_to_tool_chain("", "a.c", cwe=cwe)
            assert chain, f"{cwe} must dispatch at least one channel"
        assert warned == []

    def test_unmapped_tail_outside_policy_keeps_warning(self, caplog):
        import core.audit.orchestrator as _orch

        _orch._UNMAPPED_CWES_LOGGED.discard("CWE-1104")
        with caplog.at_level(
            logging.WARNING, logger="core.audit.orchestrator",
        ):
            _orch._warn_unmapped_cwe("CWE-1104")
        assert "checker-synthesis candidates" in caplog.text
