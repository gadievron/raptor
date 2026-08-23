"""Tests for ``core.witness.matching`` — finding → witness
ranking semantics."""

from __future__ import annotations

import sys
from pathlib import Path


# core/witness/tests/test_matching.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness import (  # noqa: E402
    Witness,
    WitnessOutcome,
    WitnessSource,
    best_match_for_finding,
    compute_bytes_hash,
    score_witness_for_finding,
)


def _make_witness(
    detail: dict = None,
    *,
    source: WitnessSource = WitnessSource.LLM_EMIT_RUN,
    outcome: WitnessOutcome = WitnessOutcome.EXIT_SIGNAL,
    target_binary_hash: str = None,
    data: bytes = b"witness-bytes",
) -> Witness:
    return Witness(
        bytes_hash=compute_bytes_hash(data),
        bytes_len=len(data),
        source=source,
        observed_outcome=outcome,
        outcome_detail=detail or {},
        target_binary_hash=target_binary_hash,
    )


_FINDING = {
    "id": "FIND-0001",
    "cwe_id": "CWE-120",
    "file": "src/auth.c",
    "feasibility": {"binary_path": "/usr/bin/svc"},
}


# ----------------------------------------------------------------------
# Score thresholds
# ----------------------------------------------------------------------


def test_exact_finding_id_match_scores_10():
    w = _make_witness({"finding_id": "FIND-0001"})
    score, reason = score_witness_for_finding(w, _FINDING)
    assert score == 10
    assert "finding-id" in reason


def test_cwe_plus_file_match_scores_7():
    w = _make_witness({
        "cwe_id": "CWE-120",
        "file_path": "src/auth.c",
    })
    score, _ = score_witness_for_finding(w, _FINDING)
    assert score == 7


def test_file_only_match_scores_4():
    w = _make_witness({"file_path": "src/auth.c"})
    score, _ = score_witness_for_finding(w, _FINDING)
    assert score == 4


def test_binary_hash_without_finding_hash_scores_0():
    """The witness carries a binary hash but the finding side has no
    hash and no readable binary — nothing to compare, so the binary
    criterion must award nothing (the old "hash-pending" rule scored
    2 on mere truthiness of both sides)."""
    w = _make_witness({}, target_binary_hash="deadbeef" * 8)
    score, _ = score_witness_for_finding(w, _FINDING)
    assert score == 0


def test_binary_hash_equality_scores_2():
    w = _make_witness({}, target_binary_hash="deadbeef" * 8)
    finding = dict(_FINDING)
    finding["feasibility"] = {
        "binary_path": "/usr/bin/svc",
        "binary_sha256": "deadbeef" * 8,
    }
    score, reason = score_witness_for_finding(w, finding)
    assert score == 2
    assert "hash match" in reason


def test_binary_hash_mismatch_scores_0():
    w = _make_witness({}, target_binary_hash="deadbeef" * 8)
    finding = dict(_FINDING)
    finding["feasibility"] = {
        "binary_path": "/usr/bin/svc",
        "binary_sha256": "cafef00d" * 8,
    }
    score, _ = score_witness_for_finding(w, finding)
    assert score == 0


def test_binary_hash_computed_from_disk(tmp_path):
    """When the finding has no explicit hash field, the feasibility
    binary_path is hashed from disk and compared."""
    import hashlib

    binary = tmp_path / "svc"
    binary.write_bytes(b"binary content")
    digest = hashlib.sha256(b"binary content").hexdigest()
    w = _make_witness({}, target_binary_hash=digest)
    finding = {
        "id": "FIND-0002",
        "feasibility": {"binary_path": str(binary)},
    }
    score, reason = score_witness_for_finding(w, finding)
    assert score == 2
    assert "hash match" in reason

    w_other = _make_witness({}, target_binary_hash="ab" * 32)
    assert score_witness_for_finding(w_other, finding)[0] == 0


def test_no_signal_scores_0():
    w = _make_witness({})
    score, _ = score_witness_for_finding(w, _FINDING)
    assert score == 0


def test_cwe_only_or_file_only_doesnt_promote_to_7():
    """CWE without matching file stays at 0 (or 4 for file
    alone). Pin that the cwe-only case doesn't elevate."""
    w_cwe_only = _make_witness({"cwe_id": "CWE-120"})
    assert score_witness_for_finding(w_cwe_only, _FINDING)[0] == 0


# ----------------------------------------------------------------------
# Tie-breaking
# ----------------------------------------------------------------------


def test_tie_break_prefers_llm_emit_run_over_fuzz():
    """Same score (file match), different source — LLM emit was
    synthesised against the finding's bug class; ranked higher."""
    w_fuzz = _make_witness(
        {"file_path": "src/auth.c"},
        source=WitnessSource.FUZZ,
        data=b"fuzz-data",
    )
    w_llm = _make_witness(
        {"file_path": "src/auth.c"},
        source=WitnessSource.LLM_EMIT_RUN,
        data=b"llm-data",
    )
    best = best_match_for_finding(
        [(Path("/a"), w_fuzz), (Path("/b"), w_llm)], _FINDING,
    )
    assert best is not None
    assert best.witness.source is WitnessSource.LLM_EMIT_RUN


def test_tie_break_prefers_sanitizer_over_exit_signal():
    """Same score + same source, different outcome — sanitizer
    report identifies the bug class more specifically."""
    w_signal = _make_witness(
        {"file_path": "src/auth.c"},
        source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL,
        data=b"signal",
    )
    w_san = _make_witness(
        {"file_path": "src/auth.c"},
        source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.SANITIZER_REPORT,
        data=b"san",
    )
    best = best_match_for_finding(
        [(Path("/a"), w_signal), (Path("/b"), w_san)], _FINDING,
    )
    assert best.witness.observed_outcome is WitnessOutcome.SANITIZER_REPORT


# ----------------------------------------------------------------------
# best_match_for_finding semantics
# ----------------------------------------------------------------------


def test_best_match_picks_highest_score():
    """Exact id beats cwe+file beats file alone."""
    w_file = _make_witness({"file_path": "src/auth.c"}, data=b"file-only")
    w_cwe = _make_witness({
        "cwe_id": "CWE-120", "file_path": "src/auth.c",
    }, data=b"cwe-file")
    w_id = _make_witness({"finding_id": "FIND-0001"}, data=b"exact")
    best = best_match_for_finding(
        [
            (Path("/a"), w_file),
            (Path("/b"), w_cwe),
            (Path("/c"), w_id),
        ],
        _FINDING,
    )
    assert best is not None
    assert best.score == 10
    assert best.witness.bytes_hash == compute_bytes_hash(b"exact")


def test_best_match_returns_none_when_no_signal():
    """All score-0 → None, not the random first one."""
    w1 = _make_witness({}, data=b"a")
    w2 = _make_witness({"cwe_id": "CWE-789"}, data=b"b")  # mismatching CWE
    best = best_match_for_finding(
        [(Path("/a"), w1), (Path("/b"), w2)], _FINDING,
    )
    assert best is None


def test_best_match_handles_empty_iterable():
    best = best_match_for_finding([], _FINDING)
    assert best is None


def test_is_real_flag():
    w = _make_witness({"finding_id": "FIND-0001"})
    best = best_match_for_finding([(Path("/a"), w)], _FINDING)
    assert best is not None
    assert best.is_real is True


# ----------------------------------------------------------------------
# Defensive: malformed outcome_detail
# ----------------------------------------------------------------------


def test_outcome_detail_non_dict_does_not_crash():
    """``outcome_detail`` being None / list / string should not
    crash the scorer; treat as "no signal"."""
    w = _make_witness({}, data=b"x")
    # Bypass the dataclass init for outcome_detail
    object.__setattr__(w, "outcome_detail", None)  # type: ignore[arg-type]
    score, _ = score_witness_for_finding(w, _FINDING)
    assert score == 0


def test_finding_missing_id_does_not_crash():
    """A finding without an id field doesn't match by id but
    can still match by file/cwe. Pin no exception."""
    w = _make_witness({"file_path": "src/auth.c"})
    finding = {"file": "src/auth.c"}
    score, _ = score_witness_for_finding(w, finding)
    assert score == 4


# ----------------------------------------------------------------------
# Binary criterion: the ON-DISK hash is authoritative
# ----------------------------------------------------------------------


def test_forged_declared_hash_never_beats_on_disk_content(tmp_path):
    """A declared ``binary_sha256`` is copy-paste satisfiable: when
    the on-disk binary at binary_path is readable, its content hash
    decides — a declared field equal to the witness hash but
    CONTRADICTED by the on-disk content must not award."""
    binary = tmp_path / "svc"
    binary.write_bytes(b"the real binary content")
    forged = "deadbeef" * 8
    w = _make_witness({}, target_binary_hash=forged)
    finding = {
        "id": "FIND-0003",
        "feasibility": {
            "binary_path": str(binary),
            "binary_sha256": forged,  # copy-pasted from the witness
        },
    }
    score, _ = score_witness_for_finding(w, finding)
    assert score == 0


def test_on_disk_match_wins_over_stale_declared_hash(tmp_path):
    """Symmetric direction: the on-disk content matches the witness
    while the declared field is stale/bogus — the on-disk hash
    governs."""
    import hashlib

    binary = tmp_path / "svc"
    binary.write_bytes(b"the real binary content")
    digest = hashlib.sha256(b"the real binary content").hexdigest()
    w = _make_witness({}, target_binary_hash=digest)
    finding = {
        "id": "FIND-0004",
        "feasibility": {
            "binary_path": str(binary),
            "binary_sha256": "cafef00d" * 8,  # stale
        },
    }
    score, reason = score_witness_for_finding(w, finding)
    assert score == 2
    assert "on-disk" in reason


def test_declared_fallback_only_when_binary_unreadable(tmp_path):
    """No readable binary on disk → declared-vs-declared equality is
    still accepted (fall-back only)."""
    w = _make_witness({}, target_binary_hash="deadbeef" * 8)
    finding = {
        "id": "FIND-0005",
        "feasibility": {
            "binary_path": str(tmp_path / "gone"),
            "binary_sha256": "deadbeef" * 8,
        },
    }
    score, reason = score_witness_for_finding(w, finding)
    assert score == 2
    assert "hash match" in reason


def test_finding_level_binary_path_is_hashed(tmp_path):
    """binary_path at the finding level (not only under feasibility)
    feeds the on-disk hash."""
    import hashlib

    binary = tmp_path / "svc"
    binary.write_bytes(b"content")
    digest = hashlib.sha256(b"content").hexdigest()
    w = _make_witness({}, target_binary_hash=digest)
    finding = {"id": "FIND-0006", "binary_path": str(binary)}
    score, _ = score_witness_for_finding(w, finding)
    assert score == 2
