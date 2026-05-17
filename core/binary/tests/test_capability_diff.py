"""Tests for ``core.binary.capability_diff``.

The diff primitive compares two binaries' capability surfaces via
:func:`core.binary.fingerprint.bucket_imports` over each binary's
import table. Tests stub ``analyse_binary_context`` so the suite
doesn't require r2pipe / radare2.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import pytest

# parents[3] climbs:
#   [0] core/binary/tests/  (this file's directory)
#   [1] core/binary/
#   [2] core/
#   [3] <repo root>         (where ``packages/`` lives)
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from core.binary.capability_diff import diff_binary_capabilities
from core.binary.fingerprint import bucket_imports
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
)


def _ctx(path, *, imports: List[str]) -> BinaryContextMap:
    """Build a minimal BinaryContextMap with the supplied imports.
    The diff primitive only reads ``ctx.imports``; metadata
    defaults are fine."""
    return BinaryContextMap(
        binary_path=Path(path),
        arch="x86", bits=64, binary_format="elf",
        imports=list(imports),
    )


def _make_non_elf_file(path: Path, content: bytes = b"stub-bytes") -> Path:
    """Create a real on-disk file that is NOT ELF — defeats the
    tier-0 ELF parser so tier-1 (the stubbed radare2) is reached.
    Also gives ``_sha256_of_file`` something to hash so
    ``capability_fingerprint`` doesn't bail on OSError."""
    path.write_bytes(content)
    return path


@pytest.fixture
def patched_analyser(monkeypatch, tmp_path):
    """Replace ``analyse_binary_context`` + ``probe_capability``
    on the radare2 module so tests drive the substrate without
    r2pipe. Yields a state dict with an ``add_binary(name, imports)``
    helper that creates a real (non-ELF) file at ``tmp_path/name``
    AND registers its stubbed analyse output, returning the Path.
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
        p = _make_non_elf_file(tmp_path / name)
        state["ctxs"][p] = _ctx(name, imports=imports)
        return p

    state["add_binary"] = add_binary
    yield state


# ---------------------------------------------------------------------------
# bucket_imports — substrate classification
# ---------------------------------------------------------------------------


class TestBucketImports:
    def test_exec_imports_classified(self):
        out = bucket_imports({"execve", "popen", "fread"})
        assert "exec" in out
        assert "execve" in out["exec"]
        assert "popen" in out["exec"]
        # fread is not in any high-CVE bucket
        assert "fread" not in {
            fn for fns in out.values() for fn in fns
        }

    def test_network_imports_classified(self):
        out = bucket_imports({"recv", "accept", "bind"})
        assert "network" in out
        assert out["network"] >= {"recv", "accept", "bind"}

    def test_string_overflow_classified(self):
        out = bucket_imports({"strcpy", "strcat", "gets"})
        assert "string_overflow" in out

    def test_ubiquitous_imports_dropped(self):
        """``malloc`` / ``printf`` / ``read`` aren't in the
        high-CVE-density taxonomy. Bucket map empty."""
        assert bucket_imports({"malloc", "printf", "read"}) == {}


# ---------------------------------------------------------------------------
# diff_binary_capabilities
# ---------------------------------------------------------------------------


class TestDiffBinaryCapabilities:
    def test_no_change_returns_empty_delta(self, patched_analyser):
        """Same imports in both → empty delta (not None).
        Callers distinguish 'couldn't compare' (None) from 'no
        change' (empty delta)."""
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["strcpy", "recv"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["strcpy", "recv"],
        )
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert delta.is_empty()

    def test_new_exec_capability_high_severity(self, patched_analyser):
        """Target adds ``execve`` → ``high_severity()`` True."""
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["strcpy"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["strcpy", "execve"],
        )
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert not delta.is_empty()
        assert "exec" in delta.new_dangerous_imports
        assert delta.new_dangerous_imports["exec"] == ["execve"]
        assert delta.high_severity() is True

    def test_new_network_capability_high_severity(self, patched_analyser):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["malloc", "recv", "accept"],
        )
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert "network" in delta.new_dangerous_imports
        assert delta.high_severity() is True

    def test_new_string_overflow_only_medium_severity(self, patched_analyser):
        """Adding a non-exec / non-network bucket doesn't escalate."""
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["malloc", "strcpy"],
        )
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert "string_overflow" in delta.new_dangerous_imports
        assert delta.high_severity() is False

    def test_removed_capabilities_ignored(self, patched_analyser):
        """Bumps that drop dangerous capabilities aren't flagged
        — those are usually security improvements."""
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["strcpy", "execve"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["strcpy"],
        )
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert delta.is_empty()

    def test_radare2_unavailable_returns_none(self, patched_analyser, tmp_path):
        """When the tier-0 ELF parser doesn't match AND radare2
        is unavailable, no fingerprint, no diff."""
        patched_analyser["available"] = False
        # Create non-ELF files so ELF parser bails to tier 1
        cur = tmp_path / "cur.bin"
        tgt = tmp_path / "tgt.bin"
        cur.write_bytes(b"not-elf")
        tgt.write_bytes(b"not-elf")
        out = diff_binary_capabilities(cur, tgt)
        assert out is None

    def test_current_analyse_failure_returns_none(
        self, patched_analyser, tmp_path,
    ):
        """``cur`` has no analyser stub → both tier-0 (non-ELF)
        and tier-1 (FileNotFoundError) fail → None."""
        cur = tmp_path / "cur_unstubbed.bin"
        cur.write_bytes(b"not-elf")
        tgt = patched_analyser["add_binary"](
            "tgt.bin", imports=["execve"],
        )
        out = diff_binary_capabilities(cur, tgt)
        assert out is None

    def test_target_analyse_failure_returns_none(
        self, patched_analyser, tmp_path,
    ):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["strcpy"],
        )
        tgt = tmp_path / "tgt_unstubbed.bin"
        tgt.write_bytes(b"not-elf")
        out = diff_binary_capabilities(cur, tgt)
        assert out is None

    def test_multiple_added_buckets(self, patched_analyser):
        cur = patched_analyser["add_binary"](
            "cur.bin", imports=["malloc"],
        )
        tgt = patched_analyser["add_binary"](
            "tgt.bin",
            imports=["malloc", "execve", "recv", "strcpy"],
        )
        delta = diff_binary_capabilities(cur, tgt)
        assert delta is not None
        assert set(delta.added_buckets()) >= {
            "exec", "network", "string_overflow",
        }
        assert delta.high_severity() is True
