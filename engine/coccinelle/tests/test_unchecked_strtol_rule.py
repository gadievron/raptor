"""Fixture tests for the unchecked_strtol rule.

Input-validation candidates require provenance and parsing-contract review.
The rule emits two ids: unchecked_strtol (endptr captured but neither it
nor errno is consulted) and strtol_null_endptr (NULL endptr — partial
conversion undetectable by construction). Negatives pin every
documented check shape: *endptr, endptr == s / endptr != s, and
errno.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "unchecked_strtol.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_endptr_captured_but_never_checked_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v = strtol(s, &end, 10);
                return v;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "unchecked_strtol"
        assert results[0]["line"] == 4

    def test_null_endptr_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned long parse(const char *s)
            {
                return strtoul(s, NULL, 10);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "strtol_null_endptr"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_endptr_deref_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v = strtol(s, &end, 10);
                if (*end != 0)
                    return -1;
                return v;
            }
        """)
        assert results == []

    def test_endptr_equals_input_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v = strtol(s, &end, 10);
                if (end == s)
                    return -1;
                return v;
            }
        """)
        assert results == []

    def test_errno_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                char *end;
                long v;
                errno = 0;
                v = strtol(s, &end, 10);
                if (errno != 0)
                    return -1;
                return v;
            }
        """)
        assert results == []

    def test_null_endptr_with_errno_check_does_not_fire(self, tmp_path):
        # The canonical errno-checked overflow idiom: a NULL endptr is
        # discards the stopping position, and the errno check catches
        # overflow without proving whole-string validity — same suppression the &endptr arm
        # already grants.
        results = _run_rule(tmp_path, """\
            long parse(const char *s)
            {
                long v;
                errno = 0;
                v = strtol(s, NULL, 10);
                if (errno == ERANGE)
                    return -1;
                return v;
            }
        """)
        assert results == []

    def test_null_endptr_errno_elsewhere_still_fires(self, tmp_path):
        # Recall guard: an errno check bound to a DIFFERENT conversion
        # does not license the unchecked one.
        results = _run_rule(tmp_path, """\
            long parse(const char *s, const char *t)
            {
                long v, w;
                errno = 0;
                v = strtol(s, NULL, 10);
                if (errno == ERANGE)
                    return -1;
                w = strtol(t, NULL, 10);
                return v + w;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 8


@pytest.mark.slow
@pytest.mark.parametrize('variant,expected', [('literal_null', 1), ('literal_end', 1), ('errno_only', 0), ('dynamic', 1)])
def test_conversion_candidates_require_parsing_contract(tmp_path, monkeypatch, variant, expected):
    from core.audit.sweep import (
        is_confirm_only_coccinelle_rule, run_coccinelle_file_sweep, scope_coccinelle_result,
    )
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from packages.coccinelle import runner
    from packages.coccinelle.models import SpatchMatch, SpatchResult
    rule = _RULE
    bodies = {
        'literal_null': 'return strtol("12", NULL, 10);',
        'literal_end': 'char *end; long n = strtol("12", &end, 10); return n;',
        'errno_only': 'errno = 0; long n = strtol(s, NULL, 10); if (errno == ERANGE) return -1; return n;',
        'dynamic': 'return strtol(s, NULL, 10);',
    }
    source = 'long candidate(const char *s) {\n '+bodies[variant]+'\n}\nvoid untouched(void) {}\n'
    target = tmp_path / 'owned.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(rule), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned conversion provenance syntax classification',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert len(rows) == expected
    expected_id = 'unchecked_strtol' if variant == 'literal_end' else 'strtol_null_endptr'
    assert all(row['rule'] == expected_id and 'review' in row['message'] for row in rows)
    native = SpatchResult(rule=rule.stem, rule_path=str(rule),
        matches=[SpatchMatch.from_dict(row) for row in rows], files_examined=[str(target)])
    calls = []
    def replay(file_path, rule_path, **kwargs):
        assert file_path == target and rule_path == rule
        calls.append((str(file_path), str(rule_path)))
        return native
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, 'run_rule', replay)
    result = run_coccinelle_file_sweep(target_path=tmp_path, file_path=target.name,
        cocci_rule=str(rule), language='c')
    assert len(calls) == 1
    assert is_confirm_only_coccinelle_rule(str(rule))
    assert result.details['confirm_only']
    assert result.outcome == ('confirmed' if expected else 'inconclusive')
    last = len(source.splitlines())
    scoped = scope_coccinelle_result(result, target_path=tmp_path, function_name='untouched',
        line_start=last, line_end=last, language='c')
    assert scoped.matches == [] and scoped.outcome == 'inconclusive'
    assert scoped.details['confirm_only']
    assert len(result.matches) == expected
