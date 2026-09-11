"""Tests for ``packages.sca.supply_chain.artefacts``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.supply_chain.artefacts import scan_target


def test_pth_file_flagged(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "evil.pth").write_text(
        "import os; os.system('rm -rf /')\n", encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1
    assert findings[0].kind == "python_pth_file"
    assert findings[0].severity == "high"


def test_pth_file_inside_excluded_dir_skipped(tmp_path: Path) -> None:
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "junk.pth").write_text("import junk\n")
    assert scan_target(tmp_path, []) == []


def test_binary_in_tests_flagged(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    blob = b"\x7fELF\x02\x01\x01" + b"\x00" * (20 * 1024)
    (tmp_path / "tests" / "evil.bin").write_bytes(blob)
    findings = scan_target(tmp_path, [])
    assert any(f.kind == "binary_in_tests" for f in findings)


def test_small_test_binary_below_threshold_skipped(tmp_path: Path) -> None:
    """A small image fixture shouldn't trip the binary_in_tests heuristic.

    The full 8-byte PNG magic is needed so the new disguised_filename
    check (which validates extension/content) doesn't flag it instead.
    """
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "tiny.png").write_bytes(
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    )
    assert scan_target(tmp_path, []) == []


def test_text_file_in_tests_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.txt").write_text("ascii " * 5000)
    assert scan_target(tmp_path, []) == []


def test_finding_anchored_to_nearest_manifest(tmp_path: Path) -> None:
    """The artefact finding's host is the manifest closest in the tree."""
    (tmp_path / "frontend").mkdir()
    pkg = tmp_path / "frontend" / "package.json"
    pkg.write_text("{}", encoding="utf-8")
    (tmp_path / "frontend" / "src").mkdir()
    (tmp_path / "frontend" / "src" / "evil.pth").write_text("x")
    manifests = [Manifest(path=pkg, ecosystem="npm", is_lockfile=False)]
    findings = scan_target(tmp_path, manifests)
    assert findings and findings[0].dependency.declared_in == pkg
    assert findings[0].dependency.ecosystem == "npm"


def test_node_modules_excluded(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.pth").write_text("x")
    assert scan_target(tmp_path, []) == []


# ---------------------------------------------------------------------------
# Obfuscation metrics — vectorised forms must equal the reference loops
# ---------------------------------------------------------------------------

def _reference_longest_line(data: bytes) -> int:
    """The original per-byte cursor walk, kept here as the reference
    the vectorised implementation must reproduce byte-for-byte."""
    longest = 0
    line_start = 0
    for i, b in enumerate(data):
        if b == 0x0A:
            longest = max(longest, i - line_start)
            line_start = i + 1
    return max(longest, len(data) - line_start)


def _reference_entropy(data: bytes) -> float:
    """The original 256-bucket per-byte histogram entropy."""
    import math
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def test_entropy_and_longest_line_match_reference() -> None:
    from packages.sca.supply_chain.artefacts import _shannon_entropy

    samples = [
        b"",
        b"\n",
        b"no newline at all",
        b"trailing line is longest\nshort\nthe very longest final line here",
        b"\n\n\nempty lines\n\n",
        bytes(range(256)) * 3 + b"\nmixed\x00binary\xff\n",
    ]
    for data in samples:
        assert _shannon_entropy(data) == _reference_entropy(data)
        if data:  # longest-line split form
            assert (
                max(len(s) for s in data.split(b"\n"))
                == _reference_longest_line(data)
            )


def test_obfuscated_detection_still_fires_and_reports_metrics(
    tmp_path: Path,
) -> None:
    """End-to-end through ``_check_obfuscated``: a large single-line
    high-entropy .js payload still classifies, with the line length
    the reference loop would have computed."""
    import base64
    import os
    # Base64 text: ~6 bits/byte entropy (above the 5.5 threshold),
    # one giant line, no NULs / binary magic (which would classify
    # as disguised_filename first — _classify emits one kind per file).
    payload = base64.b64encode(os.urandom(120 * 1024))
    src = tmp_path / "loader.js"
    src.write_bytes(payload)
    findings = scan_target(tmp_path, [])
    obf = [f for f in findings if f.kind == "large_obfuscated_artefact"]
    assert len(obf) == 1
    assert f"{_reference_longest_line(payload):,}-char" in obf[0].detail


# ---------------------------------------------------------------------------
# Test-path classification — shared predicate
# ---------------------------------------------------------------------------

def test_test_dir_classification_unchanged(tmp_path: Path) -> None:
    """Directory-name classification behaves as before the shared
    ``_test_paths`` predicate replaced the local copy: binaries under
    ``tests/`` fire ``binary_in_tests``; the same payload outside a
    test dir does not."""
    blob = b"\x7fELF" + b"\x00" * (20 * 1024)
    in_tests = tmp_path / "tests" / "payload.bin"
    in_tests.parent.mkdir()
    in_tests.write_bytes(blob)
    outside = tmp_path / "src" / "payload.bin"
    outside.parent.mkdir()
    outside.write_bytes(blob)
    findings = scan_target(tmp_path, [])
    bit = {str(f.path) for f in findings if f.kind == "binary_in_tests"}
    assert str(in_tests) in bit
    assert str(outside) not in bit
