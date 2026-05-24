"""Tests for ``packages.sca.bump.binary_capability_delta``.

The finding wrapper sits on top of :mod:`core.binary.capability_
diff`. Substrate-level tests (bucket classification, raw diff
behaviour, graceful degradation) live in
``core/binary/tests/test_capability_diff.py``. This module owns
the SCA-side concerns: ``SupplyChainFinding`` shape, severity
mapping, evidence dict, finding_id encoding.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
)
from packages.sca.bump.binary_capability_delta import (
    binary_capability_delta_finding,
)


def _ctx(path, *, imports: List[str]) -> BinaryContextMap:
    """Minimal BinaryContextMap stub — only ``imports`` is read."""
    return BinaryContextMap(
        binary_path=Path(path),
        arch="x86", bits=64, binary_format="elf",
        imports=list(imports),
    )


@pytest.fixture
def patched_analyser(monkeypatch, tmp_path):
    """Stub the radare2 analyser path. ``add_binary(name,
    imports)`` writes a real non-ELF file at ``tmp_path/name``
    (so the tier-0 ELF parser bails to tier 1) and registers
    its stubbed analyse output.
    """
    state = {"available": True, "ctxs": {}}

    def fake_analyse(path: Path, **kwargs):
        if path in state["ctxs"]:
            return state["ctxs"][path]
        raise FileNotFoundError(f"no stub for {path}")

    def fake_probe():
        return {"available": state["available"], "reason": "stub"}

    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand."
        "analyse_binary_context",
        fake_analyse,
    )
    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand.probe_capability",
        fake_probe,
    )

    def add_binary(name: str, *, imports: List[str]) -> Path:
        p = tmp_path / name
        p.write_bytes(b"stub-non-elf-bytes")
        state["ctxs"][p] = _ctx(name, imports=imports)
        return p

    state["add_binary"] = add_binary
    yield state


class TestBinaryCapabilityDeltaFinding:
    def test_high_severity_finding_for_exec_add(self, patched_analyser):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["malloc", "execve"],
        )
        finding = binary_capability_delta_finding(
            ecosystem="Container", name="alpine",
            current_version="3.18", target_version="3.19",
            current_binary=cur, target_binary=tgt,
        )
        assert finding is not None
        assert finding.kind == "binary_capability_delta"
        assert finding.severity == "high"
        assert "execve" in finding.evidence["new_dangerous_imports"]["exec"]
        # The finding_id encodes the bump coordinates for dedup
        assert "alpine@3.19" in finding.finding_id

    def test_medium_severity_finding_for_strovf_add(self, patched_analyser):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["malloc", "strcpy"],
        )
        finding = binary_capability_delta_finding(
            ecosystem="GHA", name="some-action",
            current_version="v1", target_version="v2",
            current_binary=cur, target_binary=tgt,
        )
        assert finding is not None
        assert finding.severity == "medium"

    def test_no_finding_when_unchanged(self, patched_analyser):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["strcpy"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["strcpy"],
        )
        out = binary_capability_delta_finding(
            ecosystem="Container", name="x", current_version="1",
            target_version="2", current_binary=cur,
            target_binary=tgt,
        )
        assert out is None

    def test_no_finding_when_radare2_unavailable(
        self, patched_analyser, tmp_path,
    ):
        """No tier 0 match (non-ELF) AND tier 1 unavailable →
        None."""
        patched_analyser["available"] = False
        cur = tmp_path / "cur.bin"
        tgt = tmp_path / "tgt.bin"
        cur.write_bytes(b"not-elf")
        tgt.write_bytes(b"not-elf")
        out = binary_capability_delta_finding(
            ecosystem="Container", name="x", current_version="1",
            target_version="2",
            current_binary=cur, target_binary=tgt,
        )
        assert out is None

    def test_detail_lists_buckets(self, patched_analyser):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin",
            imports=["malloc", "execve", "recv"],
        )
        finding = binary_capability_delta_finding(
            ecosystem="Container", name="x", current_version="1",
            target_version="2",
            current_binary=cur, target_binary=tgt,
        )
        assert finding is not None
        assert "exec" in finding.detail
        assert "network" in finding.detail


class TestEvidenceFingerprintShape:
    """The bump finding's evidence carries the per-side
    fingerprint dicts (binary_sha256 + arch/bits/format + bucket
    list) so SBOM-side ``raptor:cap_fp:*`` properties can be
    correlated with which bump triggered the finding."""

    def test_evidence_has_current_and_target_fingerprints(
        self, patched_analyser,
    ):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["malloc", "execve"],
        )
        finding = binary_capability_delta_finding(
            ecosystem="Container", name="alpine",
            current_version="3.18", target_version="3.19",
            current_binary=cur, target_binary=tgt,
        )
        assert finding is not None
        ev = finding.evidence
        # Bump-specific fields preserved
        assert ev["current_version"] == "3.18"
        assert ev["target_version"] == "3.19"
        # Fingerprint sub-dicts present + populated
        cur_fp = ev["current_fingerprint"]
        tgt_fp = ev["target_fingerprint"]
        assert len(cur_fp["binary_sha256"]) == 64
        assert len(tgt_fp["binary_sha256"]) == 64
        # Format/arch/bits surfaced from the fingerprint
        assert cur_fp["format"] in ("elf", "macho", "pe", None)
        # Target binary's bucket set includes the new exec bucket;
        # current's does not (this is the real signal)
        assert "exec" in tgt_fp["buckets"]
        assert "exec" not in cur_fp["buckets"]

    def test_fingerprint_buckets_sorted_for_stable_evidence(
        self, patched_analyser,
    ):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["malloc", "execve", "recv", "strcpy"],
        )
        finding = binary_capability_delta_finding(
            ecosystem="Container", name="x", current_version="1",
            target_version="2",
            current_binary=cur, target_binary=tgt,
        )
        tgt_buckets = finding.evidence["target_fingerprint"]["buckets"]
        # Sorted = stable diffs between successive bump runs
        assert tgt_buckets == sorted(tgt_buckets)


@pytest.mark.slow
def test_real_radare2_against_ls():
    """Diff /bin/ls against itself via the full
    capability_diff → binary_capability_delta_finding wire-
    through. Skipped unless r2pipe is installed.

    Slow-gated: two real radare2 ``aaa`` passes (``_T_AAA=600s``
    budget each in radare2_understand.py) against ``/bin/ls`` —
    fast locally but minutes-long on a 2-core CI runner where it
    was the lone outlier in shard 1.
    """
    from packages.binary_analysis.radare2_understand import (
        probe_capability,
    )
    cap = probe_capability()
    if not cap.get("available"):
        pytest.skip(f"radare2 stack not available: {cap}")
    ls = Path("/bin/ls")
    if not ls.exists():
        pytest.skip("/bin/ls not present on host")
    # Same binary → no new capabilities → no finding
    out = binary_capability_delta_finding(
        ecosystem="Container", name="alpine",
        current_version="3.18", target_version="3.19",
        current_binary=ls, target_binary=ls,
    )
    assert out is None
