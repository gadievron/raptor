"""Tests for ``packages.sca.supply_chain._intree_resolve``."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from packages.sca.supply_chain._intree_resolve import (
    IntreeTarget,
    resolve_intree_targets,
)


# ---------------------------------------------------------------------------
# Iron Worm shape — the case we're built to catch
# ---------------------------------------------------------------------------

def test_dotslash_binary_classified_as_binary(tmp_path: Path) -> None:
    """``preinstall: ./tools/setup`` where ``./tools/setup`` is an
    ELF: this is the Iron Worm signature."""
    (tmp_path / "tools").mkdir()
    setup = tmp_path / "tools" / "setup"
    setup.write_bytes(b"\x7fELF" + b"\x00" * 16)
    os.chmod(setup, 0o755)
    out = resolve_intree_targets("./tools/setup", tmp_path)
    assert len(out) == 1
    assert out[0].kind == "binary"
    assert out[0].is_executable_payload


def test_bare_relative_path_binary_also_resolved(tmp_path: Path) -> None:
    """``./tools/setup`` and ``tools/setup`` are interchangeable
    forms; both must resolve."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "setup").write_bytes(b"\x7fELF" + b"\x00")
    out = resolve_intree_targets("tools/setup", tmp_path)
    assert len(out) == 1 and out[0].kind == "binary"


def test_mach_o_classified_as_binary(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "agent").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00")
    out = resolve_intree_targets("./bin/agent", tmp_path)
    assert out and out[0].kind == "binary"


def test_pe_classified_as_binary(tmp_path: Path) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "agent.exe").write_bytes(b"MZ" + b"\x00" * 64)
    out = resolve_intree_targets("./tools/agent.exe", tmp_path)
    assert out and out[0].kind == "binary"


# ---------------------------------------------------------------------------
# Legitimate shapes — must NOT classify as binary
# ---------------------------------------------------------------------------

def test_path_lookup_tool_not_in_tree_no_finding(tmp_path: Path) -> None:
    """``node-gyp rebuild`` references a $PATH tool, not anything in
    the package source tree.  Must produce zero targets."""
    out = resolve_intree_targets("node-gyp rebuild", tmp_path)
    assert out == []


def test_node_e_inline_with_no_intree_path(tmp_path: Path) -> None:
    """``node -e "require('build-tools/foo')"`` references something
    that isn't a real path in the tree.  No false positive."""
    out = resolve_intree_targets(
        "node -e \"require('build-tools/foo')\"", tmp_path,
    )
    assert out == []


def test_in_tree_javascript_classified_as_source(tmp_path: Path) -> None:
    """A hook that references a script in the tree: should classify
    as ``source`` (text/JS), NOT ``binary``.  Composite-pair logic
    only escalates to critical for ``binary`` — sources stay at the
    softer signal."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "install.js").write_text(
        "console.log('hi')\n", encoding="utf-8",
    )
    out = resolve_intree_targets("node scripts/install.js", tmp_path)
    assert len(out) == 1
    assert out[0].kind == "source"
    assert not out[0].is_executable_payload


def test_shebang_script_classified_as_script(tmp_path: Path) -> None:
    """An in-tree shell script gets ``script`` classification — a
    softer signal than binary but still notable."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "init.sh").write_text(
        "#!/bin/sh\necho hi\n", encoding="utf-8",
    )
    out = resolve_intree_targets("bash ./tools/init.sh", tmp_path)
    # ``bash`` is a $PATH lookup; the second token is the in-tree
    # script.
    assert any(t.kind == "script" for t in out)


# ---------------------------------------------------------------------------
# Adversarial — escapes that must be blocked
# ---------------------------------------------------------------------------

def test_parent_dir_traversal_rejected(tmp_path: Path) -> None:
    """A token like ``../../etc/passwd`` must NOT classify a host
    file as the package's in-tree payload."""
    out = resolve_intree_targets("./../../etc/passwd", tmp_path)
    assert out == []


def test_absolute_path_rejected(tmp_path: Path) -> None:
    """``/usr/bin/foo`` is a host file, not in-tree.  Must be
    rejected without any read."""
    out = resolve_intree_targets("/usr/bin/foo", tmp_path)
    assert out == []


def test_symlink_target_not_followed(tmp_path: Path) -> None:
    """A symlink in the package pointing OUT of the tree must NOT
    be classified as the package's binary."""
    outside = tmp_path.parent / "outside-target"
    outside.write_bytes(b"\x7fELF" + b"\x00")
    link = tmp_path / "tools"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    out = resolve_intree_targets("./tools", tmp_path)
    assert out == []


def test_unterminated_quote_does_not_crash(tmp_path: Path) -> None:
    """Malformed shell input must NOT raise — uninterpretable inputs
    are silently skipped."""
    out = resolve_intree_targets("./tools/'unterminated", tmp_path)
    assert out == []


def test_compound_command_each_subcmd_scanned(tmp_path: Path) -> None:
    """``cmd-a && ./tools/setup; cmd-c`` — the in-tree binary is on
    the SECOND sub-command.  Must be detected."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "setup").write_bytes(b"\x7fELF" + b"\x00")
    out = resolve_intree_targets(
        "echo hi && ./tools/setup; node-gyp rebuild", tmp_path,
    )
    assert any(t.kind == "binary" for t in out)


def test_dedup_across_repeated_references(tmp_path: Path) -> None:
    """A body that references the same in-tree file twice yields
    one IntreeTarget."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "setup").write_bytes(b"\x7fELF")
    out = resolve_intree_targets(
        "./tools/setup; ./tools/setup --verbose", tmp_path,
    )
    assert len(out) == 1


def test_empty_body_no_targets(tmp_path: Path) -> None:
    assert resolve_intree_targets("", tmp_path) == []
    assert resolve_intree_targets("   ", tmp_path) == []


def test_giant_file_only_first_bytes_read(tmp_path: Path) -> None:
    """Even a multi-MB file must classify from the first 256 bytes
    only — never read the whole thing."""
    (tmp_path / "tools").mkdir()
    big = tmp_path / "tools" / "setup"
    # ELF magic + lots of zero padding past the 256-byte read window.
    big.write_bytes(b"\x7fELF" + b"\x00" * (1024 * 1024))
    out = resolve_intree_targets("./tools/setup", tmp_path)
    assert out and out[0].kind == "binary"


def test_iron_target_dataclass_executable_predicate() -> None:
    assert IntreeTarget(Path("/x"), "binary").is_executable_payload
    assert not IntreeTarget(Path("/x"), "script").is_executable_payload
    assert not IntreeTarget(Path("/x"), "source").is_executable_payload
    assert not IntreeTarget(Path("/x"), "unknown").is_executable_payload
