"""End-to-end acceptance: a synthetic mutant family diverges.

The full differential lane with NOTHING stubbed on the execution
side: a clean four-member guard family is written to a target tree,
the deviant is mutated through the corpus mutation machinery
(``flip-bound`` — the classic off-by-one that admits the boundary
index its siblings reject), and the pass runs with the REAL sandboxed
witness executor.

Four mirrored cases pin the lane end-to-end:

- the mutant family confirms directional divergence in the SECURITY
  direction (deviant accepts what every executed sibling rejects) and
  promotes with the differential receipt;
- the same divergence in the SAFE direction (a deviant that rejects
  what its siblings accept) is recorded nondirectional and promotes
  nothing — divergence alone never convicts;
- a signature-heterogeneous family (peers whose call boundary refuses
  the shared vector before their guard logic runs) poisons to
  inconclusive — a boundary refusal is never a semantic rejection, so
  arity differences alone can never assemble the confirming pattern;
- the unmutated family agrees, and agreement promotes nothing and
  demotes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.corpus.label import (
    FunctionLabel,
    SourcePin,
    compute_span_sha,
)
from core.audit.corpus.mutation import (
    OPERATOR_INFO,
    apply_mutation_to_text,
    build_mutation_spec,
)
from core.audit.dark_verify import _execute as ex
from core.audit.differential import (
    VERDICT_CONFIRMED,
    VERDICT_FAMILY_AGREES,
    VERDICT_INCONCLUSIVE,
    VERDICT_NONDIRECTIONAL,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _run_differential_verification,
)

_OPERATOR = "flip-bound"
_DIMENSION, _CWE = OPERATOR_INFO[_OPERATOR]

_PEERS = ("check_alpha", "check_beta", "check_gamma")
_DEVIANT = "check_dev"

# The clean family member: a compound guard whose upper bound is the
# census-visible predicate the mutation flips.
_MEMBER_TEMPLATE = (
    "def {name}(index, limit=4):\n"
    "    if index is None:\n"
    '        raise ValueError("missing index")\n'
    "    if index >= limit:\n"
    '        raise ValueError("index out of range")\n'
    "    return index\n"
)
_SPAN = (1, 6)
_GUARD_LINE = 4


@pytest.fixture()
def real_execution_sandbox():
    """Real execution needs an achievable containment tier — the
    executors fail closed to verdict="error" without one, which must
    read as skip, not failure (same probe as the dark-verify real
    execution tests)."""
    if ex._import_sandbox_run() is None:
        pytest.skip("core.sandbox unavailable")
    try:
        from core.sandbox import check_landlock_available
        from core.sandbox._spawn import mount_ns_available
    except ImportError:
        pytest.skip("core.sandbox unavailable")
    if not (check_landlock_available() or mount_ns_available()):
        pytest.skip("no sandbox containment tier on this host")


def _member_text(name: str) -> str:
    return _MEMBER_TEMPLATE.format(name=name)


def _mutant_text(guard_replacement: str) -> str:
    """The deviant's text after a corpus-machinery mutation replacing
    the upper-bound guard line — content-verified at both ends by
    ``apply_mutation_to_text`` (parent span pin, mutated span sha)."""
    clean = _member_text(_DEVIANT)
    spec = build_mutation_spec(
        clean,
        line_start=_SPAN[0],
        line_end=_SPAN[1],
        operator=_OPERATOR,
        site_line=_GUARD_LINE,
        edits=[(_GUARD_LINE, _GUARD_LINE, [guard_replacement])],
    )
    label = FunctionLabel(
        function_id=f"pkg/{_DEVIANT}.py:{_DEVIANT}",
        bug_class="consistency",
        expected_status="finding",
        rationale="Synthetic flip-bound mutant of a clean guard family.",
        source=SourcePin(
            repo="local-fixture",
            sha="0000000",
            file=f"pkg/{_DEVIANT}.py",
            line_start=_SPAN[0],
            line_end=_SPAN[1],
            span_sha=compute_span_sha(clean, *_SPAN),
        ),
        labeler="test-harness",
        labeled_at="2026-09-26",
        cwe=_CWE,
        provenance_kind="synthetic_mutant",
        mutation=spec,
        expected_mechanism="consistency",
        excerpt_scope="peer_set",
    )
    return apply_mutation_to_text(clean, label)


def _write_tree(
    tmp_path: Path, deviant_text: str,
    peer_template: str = _MEMBER_TEMPLATE,
) -> Path:
    tree = tmp_path / "tree"
    pkg = tree / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    for name in _PEERS:
        (pkg / f"{name}.py").write_text(
            peer_template.format(name=name), encoding="utf-8",
        )
    (pkg / f"{_DEVIANT}.py").write_text(deviant_text, encoding="utf-8")
    return tree


def _lead() -> dict[str, object]:
    return {
        "dimension": _DIMENSION,
        "file": f"pkg/{_DEVIANT}.py",
        "function": _DEVIANT,
        "line": _SPAN[0],
        "cwe": _CWE,
        "description": (
            "deviant upper-bound guard admits the boundary index its "
            "siblings reject"
        ),
        "family_functions": [
            {"file": f"pkg/{n}.py", "function": n, "line": _SPAN[0]}
            for n in _PEERS
        ],
    }


def _vector_client(*args_lists: list):
    """LLM stub: one vector proposal, then garbage — any metamorphic
    follow-up must fail intake rather than execute."""
    responses = [json.dumps({
        "contract": "accept-reject-equivalence",
        "vectors": [
            {"args": a, "kwargs": {}, "rationale": "boundary index"}
            for a in args_lists
        ],
    }), "not json"]
    calls: list[str] = []

    def client(prompt: str, system: str) -> str:
        calls.append(prompt)
        return responses[min(len(calls) - 1, len(responses) - 1)]

    return client


def _run(
    tmp_path: Path, deviant_text: str, vector_args: list,
    peer_template: str = _MEMBER_TEMPLATE,
):
    tree = _write_tree(tmp_path, deviant_text, peer_template)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    config = OrchestratorConfig(target_path=tree, out_dir=out_dir)
    outcome = ReviewOutcome(
        file=f"pkg/{_DEVIANT}.py", function=_DEVIANT, status="dark",
        body="suspected off-by-one", hypothesis="boundary guard flipped",
    )
    result = OrchestratorResult()
    result.outcomes = [outcome]
    result.dormant = 1
    _run_differential_verification(
        result, config, {"leads": [_lead()]},
        llm_client=_vector_client(vector_args),
    )
    records = json.loads(
        (out_dir / "differential-results.json").read_text(),
    )
    return outcome, result, records


class TestMutantAcceptance:
    def test_mutant_divergence_confirms_and_promotes(
        self, tmp_path, real_execution_sandbox,
    ):
        # Security direction: `>= limit` flipped to `> limit`, so the
        # deviant ACCEPTS index == limit while every sibling rejects
        # it — executed divergence, directional, promoted.
        outcome, result, records = _run(
            tmp_path,
            _mutant_text("    if index > limit:"),
            vector_args=[4],
        )
        assert outcome.status == "finding"
        assert outcome.evidence_tool == "differential:confirmed"
        assert result.findings == 1
        assert result.dormant == 0
        fam = [r for r in records if r["kind"] == "family-differential"]
        assert fam[0]["verdict"] == VERDICT_CONFIRMED
        assert fam[0]["promoted"] is True
        assert fam[0]["meets_family_floor"] is True
        assert fam[0]["executed_conforming"] == len(_PEERS)

    def test_safe_direction_divergence_never_promotes(
        self, tmp_path, real_execution_sandbox,
    ):
        # Mirrored negative, same machinery: the deviant is STRICTER
        # (rejects the in-range index its siblings accept). Real
        # divergence — but not in the security direction, so it is
        # recorded nondirectional and nothing is promoted or demoted.
        outcome, result, records = _run(
            tmp_path,
            _mutant_text("    if index >= 1:"),
            vector_args=[2],
        )
        assert outcome.status == "dark"
        assert result.findings == 0
        assert result.dormant == 1
        fam = [r for r in records if r["kind"] == "family-differential"]
        assert fam[0]["verdict"] == VERDICT_NONDIRECTIONAL
        assert fam[0]["promoted"] is False

    def test_signature_heterogeneity_never_confirms(
        self, tmp_path, real_execution_sandbox,
    ):
        # Arity confound, real execution: every peer REQUIRES a
        # second argument the shared one-element vector never
        # supplies, so its call boundary refuses the vector before
        # any guard logic runs, while the single-parameter deviant
        # accepts it. Were a boundary refusal ever read as the peer
        # semantically rejecting the input, this family would
        # assemble the confirming pattern — deviant accepts, every
        # "peer rejects" — out of pure signature heterogeneity. It
        # must poison to inconclusive instead, and promote nothing.
        strict_peer = (
            "def {name}(index, limit):\n"
            "    if index >= limit:\n"
            '        raise ValueError("index out of range")\n'
            "    return index\n"
        )
        outcome, result, records = _run(
            tmp_path,
            f"def {_DEVIANT}(index):\n    return index\n",
            vector_args=[4],
            peer_template=strict_peer,
        )
        assert outcome.status == "dark"
        assert result.findings == 0
        assert result.dormant == 1
        fam = [r for r in records if r["kind"] == "family-differential"]
        assert fam[0]["verdict"] == VERDICT_INCONCLUSIVE
        assert fam[0]["verdict"] != VERDICT_CONFIRMED
        assert fam[0]["promoted"] is False
        assert "did not execute validly" in fam[0]["reason"]

    def test_clean_family_agrees_and_nothing_moves(
        self, tmp_path, real_execution_sandbox,
    ):
        # Mirrored negative: the unmutated family rejects the boundary
        # unanimously — agreement is only a failure to promote.
        outcome, result, records = _run(
            tmp_path,
            _member_text(_DEVIANT),
            vector_args=[4],
        )
        assert outcome.status == "dark"
        assert result.findings == 0
        assert result.dormant == 1
        fam = [r for r in records if r["kind"] == "family-differential"]
        assert fam[0]["verdict"] == VERDICT_FAMILY_AGREES
        assert fam[0]["promoted"] is False
