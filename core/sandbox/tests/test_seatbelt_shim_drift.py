"""Equivalence tests for the deliberate _macos_spawn ↔ seatbelt-shim
hand-synced pairs.

The shim runs ``python -I`` with no repo on sys.path, so it carries
inline copies of the parent side's grant-pin mismatch check and
descendant-collection logic ("keep in sync" comments on both sides).
These tests hold the two implementations against the SAME fixtures and
fail when either side drifts — the copies stay separate by design
(the shim cannot import core), so behavioral equivalence is the only
enforceable contract.

Pure-logic + lstat only: runs on any POSIX host, no sandbox-exec.
"""

from __future__ import annotations

import os
import sys
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

from core.sandbox import _macos_spawn

SHIM_PATH = (
    Path(__file__).resolve().parents[3] / "libexec" / "raptor-seatbelt-shim"
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX lstat/symlink semantics")


@pytest.fixture(scope="module")
def shim_mod():
    """Import the shim as a module (its trust-marker gate sys.exit(2)s
    without the env marker)."""
    old = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = SourceFileLoader(
            "raptor_seatbelt_shim_drift_under_test", str(SHIM_PATH))
        spec = spec_from_loader(loader.name, loader)
        mod = module_from_spec(spec)
        loader.exec_module(mod)
        return mod
    finally:
        if old is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = old


def _pin_of(path: Path, btime: "float | None | str" = "auto"
            ) -> tuple[str, int, int, "float | None"]:
    st = os.lstat(path)
    if btime == "auto":
        raw = getattr(st, "st_birthtime", None)
        btime = float(raw) if raw is not None else None
    return (str(path), int(st.st_dev), int(st.st_ino), btime)


def _classify(reason: str) -> str:
    """Collapse both sides' reason strings onto the three tamper
    shapes so wording can differ without masking a semantic drift."""
    if "no longer exists" in reason:
        return "vanished"
    if "symlink" in reason:
        return "symlink"
    if "changed identity" in reason:
        return "swapped"
    return f"UNRECOGNISED:{reason}"


def _both_verdicts(shim_mod, pin: tuple[str, int, int, "float | None"]):
    """(core_verdict, shim_verdict) as None-or-shape strings."""
    path, dev, ino, btime = pin
    core_reason = _macos_spawn._grant_pin_mismatch(path, dev, ino, btime)
    core_verdict = _classify(core_reason) if core_reason else None
    shim_hit = shim_mod._pin_violation([pin])
    shim_verdict = None if shim_hit is None else _classify(shim_hit[1])
    return core_verdict, shim_verdict


class TestGrantPinEquivalence:
    """One lstat decides three tamper shapes — both sides must agree
    on all four fixture states."""

    def test_intact_pin_holds_on_both(self, shim_mod, tmp_path):
        f = tmp_path / "granted.txt"
        f.write_text("x")
        core, shim = _both_verdicts(shim_mod, _pin_of(f))
        assert core is None and shim is None

    def test_vanished_path(self, shim_mod, tmp_path):
        f = tmp_path / "granted.txt"
        f.write_text("x")
        pin = _pin_of(f)
        f.unlink()
        core, shim = _both_verdicts(shim_mod, pin)
        assert core == shim == "vanished"

    def test_symlink_swapped_in(self, shim_mod, tmp_path):
        f = tmp_path / "granted.txt"
        f.write_text("x")
        pin = _pin_of(f)
        f.unlink()
        target = tmp_path / "victim.txt"
        target.write_text("y")
        os.symlink(target, f)
        core, shim = _both_verdicts(shim_mod, pin)
        assert core == shim == "symlink"

    def test_relocate_and_link_back_to_original_inode(
            self, shim_mod, tmp_path):
        # lstat reports the LINK: a symlink pointing at the ORIGINAL
        # inode must still trip the pin on both sides.
        f = tmp_path / "granted.txt"
        f.write_text("x")
        pin = _pin_of(f)
        moved = tmp_path / "moved.txt"
        f.rename(moved)
        os.symlink(moved, f)
        core, shim = _both_verdicts(shim_mod, pin)
        assert core == shim == "symlink"

    def test_different_object_renamed_in(self, shim_mod, tmp_path):
        f = tmp_path / "granted.txt"
        f.write_text("x")
        pin = _pin_of(f)
        other = tmp_path / "other.txt"
        other.write_text("y")
        other.rename(f)
        core, shim = _both_verdicts(shim_mod, pin)
        assert core == shim == "swapped"

    def test_recycled_inode_btime_mismatch(self, shim_mod, tmp_path):
        """dev/ino EQUAL but the birth-time witness differs — the
        unlink+recreate signature on an inode-recycling filesystem.
        Staged by forging the pinned birth time against the live file
        (the observable is identical either way: the path re-stats
        with the pinned dev/ino but not the pinned birth time). Both
        sides must refuse, including on hosts whose stat reports NO
        birth time (a pin that carries the witness never downgrades
        to dev+ino-only equivalence)."""
        f = tmp_path / "granted.txt"
        f.write_text("x")
        st = os.lstat(f)
        real_btime = getattr(st, "st_birthtime", None)
        forged = (real_btime + 1.0) if real_btime is not None else 123.0
        pin = _pin_of(f, btime=forged)
        core, shim = _both_verdicts(shim_mod, pin)
        assert core == shim == "swapped"

    def test_btime_none_pin_skips_only_that_arm(self, shim_mod,
                                                tmp_path):
        """A pin whose capture host observed no birth time (btime
        None) still enforces the vanish/symlink/dev-ino arms and holds
        on an intact file — on both sides."""
        f = tmp_path / "granted.txt"
        f.write_text("x")
        pin = _pin_of(f, btime=None)
        core, shim = _both_verdicts(shim_mod, pin)
        assert core is None and shim is None
        f.unlink()
        core, shim = _both_verdicts(shim_mod, pin)
        assert core == shim == "vanished"


# Synthetic (pid, ppid, pgid) tables covering every attribution shape
# the two sweeps reason about. Root pid = 100.
_TABLES: list[tuple[str, list[tuple[int, int, int]], tuple, frozenset]] = [
    ("direct children",
     [(100, 50, 100), (101, 100, 101), (102, 101, 101)], (), frozenset()),
    ("setsid escapee via ppid chain",
     [(100, 50, 100), (101, 100, 101), (102, 101, 101), (103, 102, 103)],
     (), frozenset()),
    ("escapee children transitively",
     [(100, 50, 100), (101, 100, 101), (103, 101, 103), (104, 103, 103)],
     (), frozenset()),
    ("unrelated processes excluded",
     [(100, 50, 100), (101, 100, 101), (200, 1, 200), (201, 200, 200),
      (50, 1, 50)], (), frozenset()),
    ("reparented group member via extra_pgids",
     [(100, 50, 100), (101, 100, 101), (105, 1, 101)], (101,), frozenset()),
    ("extra-pgid member descendants",
     [(100, 50, 100), (105, 1, 101), (106, 105, 106)], (101,), frozenset()),
    ("protect set honoured",
     [(100, 50, 100), (101, 100, 101), (102, 101, 101)], (),
     frozenset({102})),
    ("pid 1 never collected",
     [(100, 50, 100), (1, 100, 1)], (), frozenset()),
    ("cyclic garbage terminates",
     [(100, 50, 100), (300, 301, 300), (301, 300, 300)], (), frozenset()),
    ("post-exit orphan invisible",
     [(100, 50, 100), (103, 1, 103), (200, 1, 200)], (), frozenset()),
]


class TestCollectDescendantsEquivalence:
    @pytest.mark.parametrize(
        ("label", "table", "extra_pgids", "protect"),
        _TABLES, ids=[t[0] for t in _TABLES])
    def test_same_kill_set(self, shim_mod, label, table, extra_pgids,
                           protect):
        core_set = _macos_spawn.collect_descendants(
            table, 100, extra_pgids=extra_pgids, protect=protect)
        shim_set = shim_mod._collect_descendants(
            table, 100, extra_pgids=extra_pgids, protect=protect)
        assert core_set == shim_set


class TestParsePsTableEquivalence:
    CASES = [
        "  100    50   100\n  101   100   101\n",
        "garbage line\n100 50 100\nnot ints here x\n",
        "100 50\n",          # short line skipped
        "",                   # empty
        "1 2 3 extra-col\n",  # extra columns tolerated
    ]

    @pytest.mark.parametrize("text", CASES)
    def test_same_table(self, shim_mod, text):
        assert (_macos_spawn._parse_ps_table(text)
                == shim_mod._parse_ps_table(text))
