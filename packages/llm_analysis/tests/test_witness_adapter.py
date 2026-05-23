"""Tests for ``packages.llm_analysis.witness_adapter.witness_from_exploit``.

The adapter wraps LLM-emitted exploit source as a canonical
``Witness`` so reporting + future ZKPoX consumers see fuzz
witnesses and LLM-emitted-exploit witnesses on the same data
path.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


# packages/llm_analysis/tests/test_witness_adapter.py
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness import (  # noqa: E402
    WitnessOutcome,
    WitnessSource,
    WitnessStore,
)
from packages.llm_analysis.witness_adapter import (  # noqa: E402
    witness_from_exploit,
)


_SAMPLE_EXPLOIT = (
    "// PoC for CWE-120 in src/auth.c::check_password\n"
    "#include <string.h>\n"
    "int main(void) {\n"
    "    char buf[8];\n"
    '    strcpy(buf, "AAAAAAAAAAAAAAAAAAAA");\n'
    "    return 0;\n"
    "}\n"
)


# ----------------------------------------------------------------------
# Basic adapter contract
# ----------------------------------------------------------------------


def test_returns_witness_and_bytes():
    witness, bytes_ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    assert bytes_ == _SAMPLE_EXPLOIT.encode("utf-8")
    assert witness.bytes_hash == hashlib.sha256(bytes_).hexdigest()
    assert witness.bytes_len == len(bytes_)


def test_source_is_llm_emit_run():
    """Downstream consumers filter by source to distinguish
    fuzz-verified from LLM-emitted-but-unrun witnesses."""
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    assert witness.source is WitnessSource.LLM_EMIT_RUN


def test_outcome_is_not_run():
    """``/agentic`` never executes exploits. The outcome encoding
    must match — future Tier-1.5 native execution will emit
    EXIT_SIGNAL / SANITIZER_REPORT / FLAG_CAPTURED witnesses
    for the same bytes_hash."""
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    assert witness.observed_outcome is WitnessOutcome.NOT_RUN


def test_default_produced_by_is_agentic():
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    assert witness.produced_by == "agentic"


def test_produced_by_overrideable():
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        produced_by="agentic:claude-opus-4-7",
    )
    assert witness.produced_by == "agentic:claude-opus-4-7"


# ----------------------------------------------------------------------
# Outcome detail
# ----------------------------------------------------------------------


def test_outcome_detail_carries_finding_id_minimum():
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0042",
    )
    assert witness.outcome_detail["finding_id"] == "FIND-0042"


def test_outcome_detail_optional_fields_omitted_when_absent():
    """Adapter should NOT bloat outcome_detail with None /
    falsy markers — absence is the right encoding."""
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    od = witness.outcome_detail
    for k in (
        "cwe_id", "rule_id", "file_path", "compiled",
        "compile_error_count", "intent_verdict", "intent_confidence",
    ):
        assert k not in od


def test_outcome_detail_full():
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        cwe_id="CWE-120",
        rule_id="cpp/buffer-overflow",
        file_path="src/auth.c",
        compiled=True,
        compile_error_count=0,
        intent_verdict="matches",
        intent_confidence=0.91,
    )
    od = witness.outcome_detail
    assert od["cwe_id"] == "CWE-120"
    assert od["rule_id"] == "cpp/buffer-overflow"
    assert od["file_path"] == "src/auth.c"
    assert od["compiled"] is True
    # compile_error_count=0 is falsy and is omitted by design
    assert "compile_error_count" not in od
    assert od["intent_verdict"] == "matches"
    assert od["intent_confidence"] == 0.91


def test_outcome_detail_compile_failure():
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        compiled=False,
        compile_error_count=3,
        intent_verdict="off_target",
    )
    od = witness.outcome_detail
    assert od["compiled"] is False
    assert od["compile_error_count"] == 3
    assert od["intent_verdict"] == "off_target"


def test_outcome_detail_compiled_none_omitted():
    """``compiled=None`` means verification wasn't attempted —
    absence is the right encoding, not a ``null`` value."""
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        compiled=None,
    )
    assert "compiled" not in witness.outcome_detail


# ----------------------------------------------------------------------
# Target source hashing
# ----------------------------------------------------------------------


def test_target_source_hashing_when_path_provided(tmp_path):
    src = tmp_path / "auth.c"
    src.write_text("int check_password() { return 0; }\n")
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        target_source_path=src,
    )
    assert witness.target_source_hash is not None
    assert len(witness.target_source_hash) == 64
    expected = hashlib.sha256(src.read_bytes()).hexdigest()
    assert witness.target_source_hash == expected


def test_target_source_hash_none_when_path_missing(tmp_path):
    """Path doesn't exist → ``None`` rather than raising. Witness
    records are best-effort about bindings."""
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        target_source_path=tmp_path / "does_not_exist.c",
    )
    assert witness.target_source_hash is None


def test_target_source_hash_none_when_path_not_supplied():
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    assert witness.target_source_hash is None


def test_target_binary_hash_default_none():
    """``/agentic``'s common path emits source only with no
    binary to hash — slot stays ``None``. The fuzz-derived
    crash-agent path supplies ``target_binary_path`` explicitly."""
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    assert witness.target_binary_hash is None


def test_target_binary_hashing_when_path_provided(tmp_path):
    """crash_agent's path supplies the binary that was fuzzed —
    same slot semantics as the fuzz adapter."""
    binary = tmp_path / "target"
    binary.write_bytes(b"\x7fELF...mock binary content")
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        target_binary_path=binary,
    )
    assert witness.target_binary_hash is not None
    assert len(witness.target_binary_hash) == 64
    expected = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert witness.target_binary_hash == expected


def test_target_binary_hash_none_when_missing(tmp_path):
    witness, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        target_binary_path=tmp_path / "does_not_exist",
    )
    assert witness.target_binary_hash is None


# ----------------------------------------------------------------------
# Edge cases
# ----------------------------------------------------------------------


def test_empty_exploit_code():
    """LLM occasionally emits an empty exploit (truncation,
    refusal). Adapter still produces a valid witness — the
    bytes_hash is just sha256(b'')."""
    witness, bytes_ = witness_from_exploit("", finding_id="FIND-0001")
    assert bytes_ == b""
    assert witness.bytes_len == 0
    assert witness.bytes_hash == hashlib.sha256(b"").hexdigest()


def test_unicode_exploit_code():
    """Non-ASCII source survives the UTF-8 round trip."""
    code = '// PoC for finding\nprintf("héllo\\n");\n'
    witness, bytes_ = witness_from_exploit(
        code, finding_id="FIND-0001",
    )
    assert bytes_ == code.encode("utf-8")
    assert witness.bytes_hash == hashlib.sha256(bytes_).hexdigest()


def test_unpaired_surrogate_does_not_raise():
    """Pre-fix this raised ``UnicodeEncodeError`` ('surrogates
    not allowed') from ``str.encode("utf-8")``. The adapter now
    encodes with ``errors="replace"`` so an LLM response that
    survived a sloppy decode (carrying unpaired surrogates)
    still produces a valid Witness — the broken codepoints
    become U+FFFD bytes and the surrounding exploit text
    survives intact."""
    code = "// preamble\n\udcff exploit body\n"
    witness, bytes_ = witness_from_exploit(
        code, finding_id="FIND-0001",
    )
    assert witness.bytes_len > 0
    assert witness.bytes_hash == hashlib.sha256(bytes_).hexdigest()
    # surrogate replaced; surrounding text preserved
    assert b"preamble" in bytes_
    assert b"exploit body" in bytes_


def test_identical_exploits_dedup_by_hash():
    """Two findings, same exploit text → same bytes_hash.
    WitnessStore dedups blobs by hash so this is intentional
    behaviour — operators inspecting the store can spot
    cross-finding exploit reuse."""
    w1, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0001",
    )
    w2, _ = witness_from_exploit(
        _SAMPLE_EXPLOIT, finding_id="FIND-0002",
    )
    assert w1.bytes_hash == w2.bytes_hash
    # but outcome_detail differs
    assert w1.outcome_detail["finding_id"] != w2.outcome_detail["finding_id"]


# ----------------------------------------------------------------------
# Store round-trip
# ----------------------------------------------------------------------


def test_round_trip_through_witness_store(tmp_path):
    """The ``(witness, bytes_)`` tuple plugs straight into
    ``WitnessStore.put`` with no impedance — same contract as
    the fuzz adapter."""
    witness, data = witness_from_exploit(
        _SAMPLE_EXPLOIT,
        finding_id="FIND-0001",
        cwe_id="CWE-120",
        compiled=True,
        intent_verdict="matches",
    )
    store_root = tmp_path / "store"
    store = WitnessStore(store_root)
    store.put(witness, data)

    loaded = store.get_witness(witness.bytes_hash)
    loaded_bytes = store.get_bytes(witness.bytes_hash)
    assert loaded.bytes_hash == witness.bytes_hash
    assert loaded.source == WitnessSource.LLM_EMIT_RUN
    assert loaded.observed_outcome == WitnessOutcome.NOT_RUN
    assert loaded.outcome_detail["finding_id"] == "FIND-0001"
    assert loaded.outcome_detail["cwe_id"] == "CWE-120"
    assert loaded.outcome_detail["compiled"] is True
    assert loaded.outcome_detail["intent_verdict"] == "matches"
    assert loaded_bytes == data
