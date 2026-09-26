"""The checklist-build bound is caught, reported, and work-scaled.

First defect (landed earlier): the raptor-build-checklist children in
`gaps` and `run` set timeout=300 but nothing caught
subprocess.TimeoutExpired — `gaps` died with a raw traceback, and
`run` (where the build fires after lifecycle start) left the run
wedged in status=running with no fail transition.

Second defect (live-hit twice in one day): the flat 300s bound itself.
`raptor-audit run <large-binary>` failed with "checklist build timed
out after 300s" on 41 MiB and 55 MiB re-databased binaries (12.5k
functions) whose identical untimed builds succeeded. The bound now
scales with cheap pre-build stats (target size, Ghidra ``.rep``
payload, cached re-database.json) at 30 s/MiB between the historical
300 s floor and a 3600 s ceiling (the Ghidra --decompile-all import
bound), with a verbatim operator override
(RAPTOR_CHECKLIST_BUILD_TIMEOUT_S) and a timeout message that names
the untimed raptor-build-checklist workaround.

Two-direction regression tests per the churn-prone-limit doctrine:
small targets keep the floor (never tighter), large inputs scale
(never the flat bound again), the ceiling clamps, and the override
wins unclamped in both directions.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"

_MIB = 1024 * 1024
_CLI_MOD = None

ENV = "RAPTOR_CHECKLIST_BUILD_TIMEOUT_S"


def _load_cli():
    global _CLI_MOD
    if _CLI_MOD is not None:
        return _CLI_MOD
    loader = SourceFileLoader("raptor_audit_cli_cktimeout", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_cktimeout", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"  # script trust gate (see header)
    try:
        loader.exec_module(mod)
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior
    _CLI_MOD = mod
    return mod


def _sparse(path: Path, size: int, head: bytes = b"") -> Path:
    """A file whose st_size is ``size`` without touching the disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        if head:
            f.write(head)
        f.truncate(size)
    return path


@pytest.fixture(autouse=True)
def _no_override(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)


def test_gaps_checklist_build_timeout_reported(
        tmp_path, monkeypatch, capsys):
    mod = _load_cli()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("def f():\n    return 1\n")

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 300))

    monkeypatch.setattr(subprocess, "run", fake_run)
    # Only out/target are read before the timeout path returns.
    rc = mod.cmd_gaps(SimpleNamespace(out=str(out_dir), target=str(target)))
    captured = capsys.readouterr()
    assert rc == 1
    assert "timed out" in captured.err


def test_run_checklist_build_timeout_fails_lifecycle(
        tmp_path, monkeypatch, capsys):
    mod = _load_cli()
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("def f():\n    return 1\n")

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        cmd_s = [str(c) for c in cmd]
        calls.append(cmd_s)
        joined = " ".join(cmd_s)
        if "raptor-run-lifecycle" in joined:
            stdout = f"OUTPUT_DIR={out_dir}\n" if "start" in cmd_s else ""
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        if "raptor-build-checklist" in joined:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 300))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc = mod.cmd_run(SimpleNamespace(
        target=str(target), out=str(out_dir),
    ))
    captured = capsys.readouterr()
    assert rc == 1
    assert "timed out" in captured.err
    # The run must transition to failed, not stay wedged in running.
    fail_calls = [c for c in calls
                  if "raptor-run-lifecycle" in " ".join(c) and "fail" in c]
    assert fail_calls, f"no lifecycle fail transition in {calls}"


class TestScalingFunction:
    def test_small_source_tree_keeps_the_floor(self, tmp_path: Path):
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main(void) { return 0; }\n")
        out = tmp_path / "out"
        out.mkdir()
        # Never tighter than the historical flat bound.
        assert mod._checklist_build_timeout_s(target, out) == 300

    def test_large_binary_scales_at_30s_per_mib(self, tmp_path: Path):
        mod = _load_cli()
        # A live-hit shape: a 41 MiB binary must get far more than
        # the flat 300s that failed it (and not the ceiling either —
        # the rate is pinned in both directions).
        target = _sparse(tmp_path / "big.bin", 41 * _MIB, head=b"\x7fELF")
        out = tmp_path / "out"
        out.mkdir()
        assert mod._checklist_build_timeout_s(target, out) == 41 * 30

    def test_cached_redb_joins_the_scale(self, tmp_path: Path):
        mod = _load_cli()
        # The other live-hit shape: a 55 MiB binary plus a cached
        # re-database.json the binary route loads and inventories.
        target = _sparse(tmp_path / "big.bin", 55 * _MIB, head=b"\x7fELF")
        out = tmp_path / "out"
        out.mkdir()
        _sparse(out / "re-database.json", 40 * _MIB)
        assert mod._checklist_build_timeout_s(target, out) == (55 + 40) * 30

    def test_ceiling_clamps(self, tmp_path: Path):
        mod = _load_cli()
        target = _sparse(tmp_path / "huge.bin", 500 * _MIB, head=b"\x7fELF")
        out = tmp_path / "out"
        out.mkdir()
        # Never unbounded: a wedged builder pins the CLI (and, on the
        # run path, a lifecycle-started run) for the whole bound.
        assert mod._checklist_build_timeout_s(target, out) == 3600

    def test_large_source_tree_scales(self, tmp_path: Path):
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        _sparse(target / "gen" / "blob.c", 60 * _MIB)
        out = tmp_path / "out"
        out.mkdir()
        assert mod._checklist_build_timeout_s(target, out) == 60 * 30

    def test_git_object_store_is_not_work(self, tmp_path: Path):
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int x;\n")
        # A multi-GiB .git must not drive a small repo to the ceiling.
        _sparse(target / ".git" / "objects" / "pack" / "p.pack", 500 * _MIB)
        out = tmp_path / "out"
        out.mkdir()
        assert mod._checklist_build_timeout_s(target, out) == 300

    def test_gpr_counts_the_rep_payload(self, tmp_path: Path):
        mod = _load_cli()
        gpr = tmp_path / "proj.gpr"
        gpr.write_text("ghidra project pointer\n")
        _sparse(tmp_path / "proj.rep" / "db" / "payload", 60 * _MIB)
        out = tmp_path / "out"
        out.mkdir()
        # The .gpr itself is tiny; the import work is the payload dir.
        assert mod._checklist_build_timeout_s(gpr, out) == 60 * 30

    def test_override_wins_verbatim_both_directions(
            self, tmp_path: Path, monkeypatch):
        mod = _load_cli()
        target = _sparse(tmp_path / "huge.bin", 500 * _MIB, head=b"\x7fELF")
        out = tmp_path / "out"
        out.mkdir()
        # Below the floor: the operator value is never floor-clamped.
        monkeypatch.setenv(ENV, "77")
        assert mod._checklist_build_timeout_s(target, out) == 77
        # Above the ceiling: never ceiling-clamped either (the Ghidra
        # --timeout precedent — operator value verbatim).
        monkeypatch.setenv(ENV, "7200")
        assert mod._checklist_build_timeout_s(target, out) == 7200

    @pytest.mark.parametrize("bad", ["banana", "0", "-5", "3.5"])
    def test_invalid_override_refuses_loudly(
            self, bad: str, tmp_path: Path, monkeypatch):
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.setenv(ENV, bad)
        with pytest.raises(ValueError, match=ENV):
            mod._checklist_build_timeout_s(target, out)

    def test_symlinks_are_never_followed(self, tmp_path: Path):
        """A link out of the tree must not inflate the sum — in either
        walk direction (a followed file link would count the outside
        blob; a followed dir link would descend into it)."""
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int x;\n")
        outside = _sparse(tmp_path / "outside" / "blob.bin", 500 * _MIB)
        (target / "link-file").symlink_to(outside)
        (target / "link-dir").symlink_to(outside.parent)
        out = tmp_path / "out"
        out.mkdir()
        # Followed in either direction, the 500 MiB blob drives the
        # bound to the ceiling; unfollowed, the tree is tiny → floor.
        assert mod._checklist_build_timeout_s(target, out) == 300

    def test_override_cap_boundary_both_directions(
            self, tmp_path: Path, monkeypatch):
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        # At the 7-day cap: still the operator's value, verbatim.
        monkeypatch.setenv(ENV, "604800")
        assert mod._checklist_build_timeout_s(target, out) == 604800
        # One past the cap: refused (never silently clamped — the
        # verbatim contract must not be rewritten behind the operator).
        monkeypatch.setenv(ENV, "604801")
        with pytest.raises(ValueError, match="at most"):
            mod._checklist_build_timeout_s(target, out)

    def test_oversized_override_refused_not_overflowed(
            self, tmp_path: Path, monkeypatch):
        """A 400-digit override passes isdigit()/>0 and then overflows
        float conversion inside subprocess.run (OverflowError), an
        exception class the call sites' except TimeoutExpired does not
        catch — the validator must refuse it up front."""
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.setenv(ENV, "9" * 400)
        with pytest.raises(ValueError, match="at most") as excinfo:
            mod._checklist_build_timeout_s(target, out)
        # The refusal is bounded: the 400 digits never paste whole.
        assert "9" * 400 not in str(excinfo.value)
        assert "elided" in str(excinfo.value)

    def test_unicode_digit_override_refuses_via_the_contract(
            self, tmp_path: Path, monkeypatch):
        """'²' passes str.isdigit() (Unicode digit class) but fails
        int() — without the isascii() guard the refusal is Python's
        raw ValueError with the character embedded unescaped, not the
        env-var-named contract message."""
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.setenv(ENV, "²")
        with pytest.raises(ValueError, match=ENV) as excinfo:
            mod._checklist_build_timeout_s(target, out)
        assert "positive integer" in str(excinfo.value)
        assert "invalid literal" not in str(excinfo.value)

    def test_conversion_limit_length_override_refuses_via_the_contract(
            self, tmp_path: Path, monkeypatch):
        """A 5000-digit override passes isdigit() and then trips
        CPython's integer-string conversion limit inside int() — the
        raw limit message names neither the env var nor the cap. The
        digit-count pre-check must refuse with the bounded cap
        message."""
        mod = _load_cli()
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.setenv(ENV, "9" * 5000)
        with pytest.raises(ValueError, match=ENV) as excinfo:
            mod._checklist_build_timeout_s(target, out)
        msg = str(excinfo.value)
        assert "at most" in msg
        assert "Exceeds the limit" not in msg
        assert "9" * 5000 not in msg
        assert "elided" in msg


class _FakeRun:
    """subprocess.run stand-in: lifecycle children succeed, the
    build-checklist child times out (or records its bound)."""

    def __init__(self, out_dir: Path, build_behaviour: str = "timeout"):
        self.out_dir = out_dir
        self.build_behaviour = build_behaviour
        self.build_timeouts: list[object] = []
        self.lifecycle_cmds: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        joined = " ".join(str(c) for c in cmd)
        if "raptor-build-checklist" in joined:
            self.build_timeouts.append(kwargs.get("timeout"))
            if self.build_behaviour == "timeout":
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
            return SimpleNamespace(returncode=1, stdout="", stderr="stop")
        if "raptor-run-lifecycle" in joined:
            self.lifecycle_cmds.append([str(c) for c in cmd])
            return SimpleNamespace(
                returncode=0,
                stdout=f"OUTPUT_DIR={self.out_dir}\n",
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _run_args(target: Path, out: Path) -> SimpleNamespace:
    return SimpleNamespace(target=str(target), out=str(out), project=None)


class TestRunPathWiring:
    """`raptor-audit run` passes the scaled bound to the builder and
    fails actionably — the exact live-hit surface."""

    def _invoke(self, mod, monkeypatch, target: Path, out: Path,
                behaviour: str = "timeout") -> tuple[int, _FakeRun]:
        out.mkdir(parents=True, exist_ok=True)
        fake = _FakeRun(out, behaviour)
        monkeypatch.setattr(subprocess, "run", fake)
        rc = mod.cmd_run(_run_args(target, out))
        return rc, fake

    def test_large_target_gets_the_scaled_bound(
            self, tmp_path: Path, monkeypatch, capsys):
        mod = _load_cli()
        target = _sparse(tmp_path / "huge.bin", 500 * _MIB, head=b"\x7fELF")
        rc, fake = self._invoke(mod, monkeypatch, target, tmp_path / "out")
        assert rc == 1
        # The flat 300s live-failed here; the ceiling-clamped scaled
        # bound must reach the child.
        assert fake.build_timeouts == [3600]
        err = capsys.readouterr().err
        assert "checklist build timed out after 3600s" in err
        # Actionable refusal: the message names the untimed workaround
        # with the run's actual paths, and the override env.
        assert "libexec/raptor-build-checklist" in err
        assert str(target) in err
        assert ENV in err
        # The run must not wedge in status=running.
        assert any("fail" in c for c in fake.lifecycle_cmds[-1])

    def test_small_target_keeps_the_floor_bound(
            self, tmp_path: Path, monkeypatch, capsys):
        mod = _load_cli()
        target = _sparse(tmp_path / "small.bin", 1 * _MIB, head=b"\x7fELF")
        rc, fake = self._invoke(mod, monkeypatch, target, tmp_path / "out")
        assert rc == 1
        assert fake.build_timeouts == [300]
        assert "checklist build timed out after 300s" in \
            capsys.readouterr().err

    def test_override_reaches_the_child_verbatim(
            self, tmp_path: Path, monkeypatch):
        mod = _load_cli()
        monkeypatch.setenv(ENV, "7200")
        target = _sparse(tmp_path / "small.bin", 1 * _MIB, head=b"\x7fELF")
        rc, fake = self._invoke(mod, monkeypatch, target, tmp_path / "out")
        assert rc == 1
        assert fake.build_timeouts == [7200]

    def test_invalid_override_fails_the_run_loudly(
            self, tmp_path: Path, monkeypatch, capsys):
        mod = _load_cli()
        monkeypatch.setenv(ENV, "banana")
        target = _sparse(tmp_path / "small.bin", 1 * _MIB, head=b"\x7fELF")
        rc, fake = self._invoke(mod, monkeypatch, target, tmp_path / "out")
        assert rc == 1
        # Refused before any builder spawn, run recorded failed.
        assert fake.build_timeouts == []
        assert ENV in capsys.readouterr().err
        assert any("fail" in c for c in fake.lifecycle_cmds[-1])

    def test_oversized_override_never_wedges_the_run(
            self, tmp_path: Path, monkeypatch, capsys):
        """The empirically-proven wedge: a 309+-digit override passes
        an isdigit()/>0 validator, then subprocess.run(timeout=...)
        raises OverflowError ('int too large to convert to float'),
        which escapes except TimeoutExpired AFTER lifecycle start —
        run stuck in status=running. The validator must refuse the
        value before any spawn and the run must record the fail."""
        mod = _load_cli()
        monkeypatch.setenv(ENV, "1" + "0" * 400)
        target = _sparse(tmp_path / "small.bin", 1 * _MIB, head=b"\x7fELF")
        # No OverflowError may escape cmd_run.
        rc, fake = self._invoke(mod, monkeypatch, target, tmp_path / "out")
        assert rc == 1
        assert fake.build_timeouts == []
        err = capsys.readouterr().err
        assert ENV in err
        assert "at most" in err
        # Lifecycle fail recorded — never wedged in status=running.
        assert any("fail" in c for c in fake.lifecycle_cmds[-1])


class TestGapsPathWiring:
    """`raptor-audit gaps` (the on-demand rebuild) shares the scaled
    bound and the actionable timeout message."""

    def test_timeout_message_names_the_workaround(
            self, tmp_path: Path, monkeypatch, capsys):
        mod = _load_cli()
        target = _sparse(tmp_path / "huge.bin", 500 * _MIB, head=b"\x7fELF")
        out = tmp_path / "out"
        out.mkdir()
        fake = _FakeRun(out)
        monkeypatch.setattr(subprocess, "run", fake)
        rc = mod.cmd_gaps(SimpleNamespace(out=str(out), target=str(target)))
        assert rc == 1
        assert fake.build_timeouts == [3600]
        err = capsys.readouterr().err
        assert "checklist build timed out after 3600s" in err
        assert "libexec/raptor-build-checklist" in err
        assert ENV in err

    def test_invalid_override_refused_before_spawn(
            self, tmp_path: Path, monkeypatch, capsys):
        mod = _load_cli()
        monkeypatch.setenv(ENV, "-1")
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int x;\n")
        out = tmp_path / "out"
        out.mkdir()
        fake = _FakeRun(out)
        monkeypatch.setattr(subprocess, "run", fake)
        rc = mod.cmd_gaps(SimpleNamespace(out=str(out), target=str(target)))
        assert rc == 1
        assert fake.build_timeouts == []
        assert ENV in capsys.readouterr().err
