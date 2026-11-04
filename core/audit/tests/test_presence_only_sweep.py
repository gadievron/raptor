"""Presence matches must not acquire defect-confirmation authority."""

from pathlib import Path

import pytest

from core.audit import orchestrator as orch
from core.audit import sweep
from packages.semgrep.models import SemgrepResult


@pytest.mark.parametrize("suffix", ["c", "cpp", "go"])
@pytest.mark.parametrize("keyword", list(sweep._MECHANICAL_CHECK_PATTERNS))
def test_presence_match_is_not_confirmed_without_a_control(tmp_path, monkeypatch, suffix, keyword):
    import packages.semgrep.runner as runner

    target = tmp_path / f"record.{suffix}"
    target.write_text("value = convert(input);\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "run_rule", lambda *a, **kw: SemgrepResult(
        name="presence", config="rule.yaml", target=str(target),
        findings=[{"start": {"line": 1}}], files_examined=[str(target)],
    ))
    monkeypatch.setattr(sweep, "_rule_matches_negative_control", lambda *a: False)
    monkeypatch.setattr(sweep, "_negative_control_batch_plan", lambda *a: pytest.fail(
        "presence-only queries need no control run or shared control-cache writes",
    ))
    result = sweep.run_semgrep_sweep(
        target_path=tmp_path, file_path=target.name, function_name="Read",
        rule_config="rule.yaml", rule_keyword=keyword, presence_only=True,
    )
    assert result.outcome == "inconclusive"
    assert len(result.matches) == 1  # still supplied to review as a lead
    assert "presence-only" in result.details["reason"]


def test_generated_mechanical_chain_declares_its_evidence_limit():
    chain = orch._hypothesis_to_tool_chain(
        "unchecked return value from transform", "record.go", cwe="CWE-252",
    )
    entries = [entry for entry in chain if entry["type"] == "semgrep"]
    assert entries
    assert entries[0]["config"]["presence_only"] is True


def test_presence_role_reaches_runner_and_cannot_reuse_a_confirming_memo(tmp_path, monkeypatch):
    (tmp_path / "record.go").write_text("package p\nfunc Read() {}\n")
    rule = tmp_path / "rule.yaml"
    rule.write_text("rules: []\n")
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    seen = []

    def run_sweep(**kwargs):
        seen.append(kwargs["presence_only"])
        return sweep.SweepResult(
            tool="semgrep", file_path="record.go", function_name="Read",
            rule_id="r", outcome="inconclusive" if kwargs["presence_only"] else "confirmed",
        )

    monkeypatch.setattr(orch, "run_semgrep_sweep", run_sweep)
    for presence_only in (False, True, True):
        inconclusive = set()
        confirmed = orch._run_tool_chain(
            [{"type": "semgrep", "config": {"rule": str(rule), "presence_only": presence_only}}],
            config=config, file_path="record.go", function_name="Read", source="", hypothesis="",
            inconclusive_types=inconclusive,
        )
        assert bool(confirmed) is not presence_only
        if presence_only:
            assert "semgrep" in inconclusive
    assert seen == [False, True]  # role participates in the memo key


def test_live_go_assignment_query_is_only_a_lead(tmp_path):
    from packages.semgrep.runner import is_available

    if not is_available():
        pytest.skip("requires local Semgrep")
    source = (
        "package p\n"
        "type Record struct { Items []string }\n"
        "func merge(a, b []string) []string { return append(a, b...) }\n"
        "func Read(r *Record, values []string) {\n"
        "    r.Items = merge(r.Items, values)\n"
        "}\n"
    )
    (tmp_path / "record.go").write_text(source)
    pattern = sweep.mechanical_check_to_semgrep("unchecked return value")
    rule = orch._pattern_rule_file(pattern, "record.go")
    assert rule
    try:
        rows = []
        for presence_only in (False, True):
            result = sweep.run_semgrep_sweep(
                target_path=tmp_path, file_path="record.go", function_name="Read",
                rule_config=rule, line_start=4, line_end=6,
                hypothesis="unchecked return value from merge", rule_keyword="unchecked return",
                presence_only=presence_only,
            )
            rows.append(result)
        assert rows[0].outcome == "confirmed"  # reproduces the old false confirmation
        assert rows[1].outcome == "inconclusive"
        assert rows[0].matches == rows[1].matches
        assert rows[1].matches
    finally:
        Path(rule).unlink(missing_ok=True)


@pytest.mark.parametrize("guarded", [False, True])
def test_live_specific_error_discard_rule_retains_its_authority(tmp_path, guarded):
    from packages.semgrep.runner import is_available

    if not is_available():
        pytest.skip("requires local Semgrep")
    body = (
        '_, err := decode("bad"); if err != nil { return err }; return nil'
        if guarded else '_, _ = decode("bad"); return nil'
    )
    (tmp_path / "record.go").write_text(
        'package p\nimport "errors"\n'
        'func decode(s string) (int, error) { return 0, errors.New("invalid") }\n'
        'func Read() error { ' + body + ' }\n'
    )
    rule = tmp_path / "discard.yaml"
    rule.write_text(
        'rules:\n- id: explicit-error-discard\n  languages: [go]\n'
        '  message: decode error is discarded\n  severity: WARNING\n'
        '  pattern: _, _ = decode(...)\n'
    )
    result = sweep.run_semgrep_sweep(
        target_path=tmp_path, file_path="record.go", function_name="Read",
        rule_config=str(rule), line_start=4, line_end=4,
    )
    assert result.outcome == ("refuted" if guarded else "confirmed")
