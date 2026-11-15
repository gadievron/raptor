"""Publication candidates remain visible without refuting wider protocols."""
from pathlib import Path

import pytest

from core.audit import sweep
from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
from core.testing.module_views import scoped_function_imports
from packages.coccinelle import runner
from packages.coccinelle.models import SpatchMatch, SpatchResult

_ROOT = Path(__file__).resolve().parents[3]
_RULE = _ROOT / "engine/coccinelle/rules/missing_memory_barrier.cocci"


def test_memory_barrier_dispatch_keeps_detection_authority():
    from core.audit.evidence_grade import is_verification_evidence
    from core.audit.orchestrator import _is_detection_only

    assert hypothesis_to_cocci_check("missing memory barrier in publication") == str(_RULE)
    assert sweep.is_confirm_only_coccinelle_rule(str(_RULE))
    assert _is_detection_only("coccinelle:missing_memory_barrier")
    assert not is_verification_evidence("coccinelle:missing_memory_barrier")


@pytest.mark.parametrize("line,expected", [
    (None, "inconclusive"), (2, "confirmed"), (20, "inconclusive"),
], ids=["quiet", "candidate", "outside-function"])
def test_publication_scope_keeps_candidates_without_refuting(tmp_path, monkeypatch, line, expected):
    source = tmp_path / "publication.c"
    source.write_text("void publish(struct item *p) {\n p->data = 1;\n ordinary_handoff(p);\n}\n")
    calls = []

    def execute(target, path, **options):
        calls.append((target, path))
        matches = [] if line is None else [SpatchMatch(
            file=str(source), line=line, column=1,
            rule="missing_memory_barrier", message="inert publication candidate",
        )]
        return SpatchResult(rule="missing_memory_barrier", matches=matches)

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
