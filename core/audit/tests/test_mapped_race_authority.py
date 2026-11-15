"""Narrow concurrency candidates cannot refute broader dispatched hypotheses."""
from pathlib import Path

import pytest

from core.audit import sweep
from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
from core.testing.module_views import scoped_function_imports
from packages.coccinelle import runner
from packages.coccinelle.models import SpatchMatch, SpatchResult

_ROOT = Path(__file__).resolve().parents[3]
_CASES = [
    ("lock_order_violation", "deadlock in cross-function lock ordering"),
    ("lock_scope_gap", "unprotected access outside lock"),
    ("toctou_check_use", "filesystem time-of-check to time-of-use"),
    ("unsafe_list_del", "linked list corruption"),
    ("use_after_unlock", "concurrent use after free"),
]


@pytest.mark.parametrize("name,hypothesis", _CASES, ids=[case[0] for case in _CASES])
@pytest.mark.parametrize("line,expected", [
    (None, "inconclusive"), (2, "confirmed"), (20, "inconclusive"),
], ids=["quiet", "candidate", "outside-function"])
def test_narrow_rule_keeps_candidate_authority(tmp_path, monkeypatch, name, hypothesis, line, expected):
    from core.audit.evidence_grade import is_verification_evidence
    from core.audit.orchestrator import _is_detection_only

    rule = _ROOT / "engine/coccinelle/rules" / f"{name}.cocci"
    assert hypothesis_to_cocci_check(hypothesis) == str(rule)
    assert sweep.is_confirm_only_coccinelle_rule(str(rule))
    assert _is_detection_only(f"coccinelle:{name}")
    assert not is_verification_evidence(f"coccinelle:{name}")
    source = tmp_path / "candidate.c"
    source.write_text("void owned(void) {\n ordinary();\n more();\n}\n")
    calls = []

    def execute(target, path, **options):
        calls.append((target, path))
        matches = [] if line is None else [SpatchMatch(
            file=str(source), line=line, column=1,
            rule=name, message="inert mapped candidate",
        )]
        return SpatchResult(rule=name, matches=matches)

    with scoped_function_imports(
        sweep, ("run_coccinelle_file_sweep",),
        {"packages.coccinelle.runner": runner},
    ) as imports:
        private = getattr(imports, "packages.coccinelle.runner")
        monkeypatch.setattr(private, "is_available", lambda: True)
        monkeypatch.setattr(private, "run_rule", execute)
        result = sweep.run_coccinelle_file_sweep(
            target_path=tmp_path, file_path="candidate.c",
            cocci_rule=str(rule), language="c",
        )
    scoped = sweep.scope_coccinelle_result(
        result, target_path=tmp_path, function_name="owned",
        line_start=1, line_end=4, language="c",
    )
    assert len(calls) == 1
    assert scoped.outcome == expected
    assert bool((scoped.details or {}).get("confirm_only"))
    assert len(scoped.matches) == (1 if line == 2 else 0)
