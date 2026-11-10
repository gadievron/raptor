"""Fixture tests for the inet_ntoa_double_call rule.

Duplicate conversions are candidates: shared output storage does not prove
that distinct address data was lost. Equal-address cases retain discovery
without verification authority; silence remains inconclusive.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "inet_ntoa_double_call.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_two_calls_in_one_arglist_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_route(struct in_addr src, struct in_addr dst)
            {
                printf("%s -> %s\n", inet_ntoa(src), inet_ntoa(dst));
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "inet_ntoa_double_call"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_single_call_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_peer(struct in_addr src)
            {
                printf("peer %s\n", inet_ntoa(src));
            }
        """)
        assert results == []


def test_shared_buffer_calls_require_context_review(tmp_path, monkeypatch):
    import json

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from core.audit.evidence_grade import is_verification_evidence
    from core.audit.sweep import (
        get_rule_role, is_confirm_only_coccinelle_rule,
        run_coccinelle_file_sweep, scope_coccinelle_result,
    )
    from packages.coccinelle import runner
    from packages.coccinelle.models import SpatchMatch, SpatchResult

    rule = _RULE
    source = r"""#include <arpa/inet.h>
#include <stdio.h>
void same(struct in_addr addr) { printf("%s %s\n", inet_ntoa(addr), inet_ntoa(addr)); }
void aliases(struct in_addr addr) { struct in_addr a = addr; struct in_addr b = addr; printf("%s %s\n", inet_ntoa(a), inet_ntoa(b)); }
void different(struct in_addr src, struct in_addr dst) { printf("%s %s\n", inet_ntoa(src), inet_ntoa(dst)); }
void single(struct in_addr addr) { printf("%s\n", inet_ntoa(addr)); }
"""
    target = tmp_path / "owned.c"
    target.write_text(source)
    result = run_pinned_subprocess(
        ["spatch", "--sp-file", str(rule), str(target), "--no-show-diff", "--no-includes"],
        timeout=45, context="Owned identical-address inet_ntoa candidate role baseline",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line.removeprefix("COCCIRESULT:")) for stream in (result.stdout,result.stderr) for line in stream.splitlines() if line.startswith("COCCIRESULT:")]
    assert {row["line"] for row in rows} == {3,4,5}, rows
    assert len(rows) == 3
    monkeypatch.setenv("RAPTOR_DIR", str(Path(__file__).resolve().parents[3]))
    role = get_rule_role(str(rule))
    verification = is_verification_evidence("coccinelle:inet_ntoa_double_call")
    assert role == "detection"
    assert not verification
    assert is_confirm_only_coccinelle_rule(str(rule))
    native = SpatchResult(
        rule="inet_ntoa_double_call", rule_path=str(rule),
        matches=[SpatchMatch.from_dict(row) for row in rows],
        files_examined=[str(target)],
    )
    calls = []

    def replay(file_path, rule_path, **kwargs):
        calls.append((file_path, rule_path))
        assert file_path == target
        assert rule_path == rule
        return native

    monkeypatch.setattr(runner, "run_rule", replay)
    file_result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path=target.name,
        cocci_rule=str(rule), language="c",
    )
    assert len(calls) == 1
    assert len(file_result.matches) == 3
    assert file_result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        file_result, target_path=tmp_path, function_name="single",
        line_start=6, line_end=6, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.matches == []
    assert len(file_result.matches) == 3
