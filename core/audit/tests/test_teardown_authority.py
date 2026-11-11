"""Inert transport controls for teardown candidate authority, without spatch."""
from pathlib import Path

import pytest

from core.audit import sweep
from core.testing.module_views import scoped_function_imports
from packages.coccinelle import runner
from packages.coccinelle.models import SpatchMatch, SpatchResult

_ROOT = Path(__file__).resolve().parents[3]
_RULE = _ROOT / "engine/coccinelle/rules/teardown_lifetime.cocci"


def test_stamp_requires_independent_lifetime_evidence(monkeypatch):
    from core.audit.evidence_grade import is_verification_evidence
    from core.audit.orchestrator import _is_detection_only

    monkeypatch.setenv("RAPTOR_DIR", str(_ROOT))
    assert _is_detection_only("coccinelle:teardown_lifetime")
    assert not is_verification_evidence("coccinelle:teardown_lifetime")


@pytest.mark.parametrize("line,expected", [
    (None, "inconclusive"), (2, "confirmed"), (20, "inconclusive"),
], ids=["quiet", "candidate", "outside-function"])
def test_scope_preserves_candidates_without_refuting(tmp_path, monkeypatch, line, expected):
    source = tmp_path / "teardown.c"
    source.write_text("void teardown(void) {\n    cancel_work(&item->work);\n    kfree(item);\n}\n")
    calls = []

    def execute(target, path, **options):
        calls.append((target, path))
        matches = [] if line is None else [SpatchMatch(
            file=str(source), line=line, column=1,
            rule="teardown_lifetime", message="inert transport row",
        )]
        return SpatchResult(rule="teardown_lifetime", matches=matches)

    with scoped_function_imports(
        sweep, ("run_coccinelle_file_sweep",),
        {"packages.coccinelle.runner": runner},
    ) as imports:
        private = getattr(imports, "packages.coccinelle.runner")
        monkeypatch.setattr(private, "is_available", lambda: True)
        monkeypatch.setattr(private, "run_rule", execute)
        result = sweep.run_coccinelle_file_sweep(
            target_path=tmp_path, file_path="teardown.c",
            cocci_rule=str(_RULE), language="c",
        )
    scoped = sweep.scope_coccinelle_result(
        result, target_path=tmp_path, function_name="teardown",
        line_start=1, line_end=4, language="c",
    )
    assert len(calls) == 1
    assert scoped.outcome == expected
    assert bool((scoped.details or {}).get("confirm_only"))
    assert len(scoped.matches) == (1 if line == 2 else 0)
