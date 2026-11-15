"""RCU read-order candidates retain source and evidence limits."""
from pathlib import Path

import pytest

from core.audit import sweep
from core.audit.cwe_dispatch import resolve_cocci_rules_for_cwe
from core.testing.module_views import scoped_function_imports
from packages.coccinelle import runner
from packages.coccinelle.models import SpatchMatch, SpatchResult

_ROOT = Path(__file__).resolve().parents[3]
_RULE = _ROOT / "engine/coccinelle/rules/rcu_split_decision.cocci"


def test_rcu_dispatch_keeps_detection_authority():
    from core.audit.evidence_grade import is_verification_evidence
    from core.audit.orchestrator import _is_detection_only

    assert str(_RULE) in resolve_cocci_rules_for_cwe("CWE-362")
    assert sweep.is_confirm_only_coccinelle_rule(str(_RULE))
    assert _is_detection_only("coccinelle:rcu_split_decision")
    assert not is_verification_evidence("coccinelle:rcu_split_decision")


@pytest.mark.parametrize("line,expected", [
    (None, "inconclusive"), (2, "confirmed"), (20, "inconclusive"),
], ids=["quiet", "candidate", "outside-function"])
def test_rcu_scope_keeps_candidates_without_refuting(tmp_path, monkeypatch, line, expected):
    source = tmp_path / "publication.c"
    source.write_text("void publish(struct item *p) {\n p->data = 1;\n ordinary_handoff(p);\n}\n")
    calls = []

    def execute(target, path, **options):
        calls.append((target, path))
        matches = [] if line is None else [SpatchMatch(
            file=str(source), line=line, column=1,
            rule="rcu_split_decision", message="inert publication candidate",
        )]
        return SpatchResult(rule="rcu_split_decision", matches=matches)

    with scoped_function_imports(
        sweep, ("run_coccinelle_file_sweep",),
        {"packages.coccinelle.runner": runner},
    ) as imports:
        private = getattr(imports, "packages.coccinelle.runner")
        monkeypatch.setattr(private, "is_available", lambda: True)
        monkeypatch.setattr(private, "run_rule", execute)
        result = sweep.run_coccinelle_file_sweep(
            target_path=tmp_path, file_path="publication.c",
            cocci_rule=str(_RULE), language="c",
        )
    scoped = sweep.scope_coccinelle_result(
        result, target_path=tmp_path, function_name="publish",
        line_start=1, line_end=4, language="c",
    )
    assert len(calls) == 1
    assert scoped.outcome == expected
    assert bool((scoped.details or {}).get("confirm_only"))
    assert len(scoped.matches) == (1 if line == 2 else 0)

def test_embedded_message_preserves_span_and_candidate_limits():
    import ast
    import io
    import json
    from types import SimpleNamespace

    body = _RULE.read_text().split("T << rcusplit.T;\n@@\n", 1)[1]
    tree = ast.parse(body)
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    output = io.StringIO()
    position = SimpleNamespace(file="owned.c", line=8, column=4, line_end=8, column_end=6)
    exec(compile(tree, str(_RULE), "exec"), {
        "p": [position], "T": "task", "json": json,
        "sys": SimpleNamespace(stderr=output),
    })
    rows = [json.loads(line.removeprefix("COCCIRESULT:")) for line in output.getvalue().splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert (row["file"], row["line"], row["col"], row["line_end"], row["col_end"]) == ("owned.c", 8, 4, 8, 6)
    assert row["rule"] == "rcu_split_decision"
    assert "candidate" in row["message"]
    assert "__task_cred(task)" in row["message"] and "task->mm" in row["message"]
    assert "review target identity, access-decision use, concurrent mutation and ordering" in row["message"]
