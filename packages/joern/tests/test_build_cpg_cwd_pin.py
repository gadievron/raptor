"""cwd hygiene for the two bare (non-sandbox) build_cpg spawn lanes.

A fleet battery once found a ``workspace/cpg.bin/{cpg.bin,
cpg.bin.tmp, project.json}`` tree at a worktree root — the shape
Joern writes under the process cwd. The sandboxed build lane pins the
child cwd (core.sandbox defaults cwd to its ``output=`` grant), and
both run_query lanes pin a per-query scratch cwd; the two bare build
lanes — the TypeError fallback for runners without the sandbox
kwargs, and the stall monitor's raw Popen — inherited the caller's
cwd. These tests drive both lanes with a stub joern-parse that writes
a ``workspace/`` tree into ITS OWN cwd and pin that the debris lands
in the build's output dir, never the caller's cwd, while rc/stdout
handling stays byte-for-byte as before.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from packages.joern.runner import _build_cpg_with_stall_monitor, build_cpg


def _stub_joern_parse(bin_dir: Path, *, returncode: int = 0,
                      write_output: bool = True) -> Path:
    """A fake joern-parse that mimics the offending behavior: it drops
    a ``workspace/cpg.bin/`` tree into ITS CWD, then (optionally)
    writes the ``--output`` file and exits with *returncode*."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "joern-parse"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "ws = os.path.join(os.getcwd(), 'workspace', 'cpg.bin')\n"
        "os.makedirs(ws, exist_ok=True)\n"
        "with open(os.path.join(ws, 'cpg.bin'), 'wb') as f:\n"
        "    f.write(b'workspace-copy')\n"
        "with open(os.path.join(ws, 'project.json'), 'w') as f:\n"
        "    f.write('{}')\n"
        f"if {write_output!r} and '--output' in sys.argv:\n"
        "    out = sys.argv[sys.argv.index('--output') + 1]\n"
        "    with open(out, 'wb') as f:\n"
        "        f.write(b'cpg-bytes')\n"
        "print('language: c')\n"
        f"sys.exit({returncode})\n"
    )
    stub.chmod(0o755)
    return stub


@pytest.fixture
def caller_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A simulated repo-root cwd for the build's CALLER — the directory
    the observed debris landed in. Every test asserts it stays clean."""
    root = tmp_path / "caller-root"
    root.mkdir()
    monkeypatch.chdir(root)
    return root


def _bare_runner(
    cmd: list[str],
    capture_output: bool,
    text: bool,
    timeout: int,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """bare subprocess.run shape: raises TypeError on the sandbox
    kwargs (target=, output=, ...), so build_cpg's fallback lane
    fires; then actually runs the command like subprocess.run."""
    return subprocess.run(
        cmd, capture_output=capture_output, text=text,
        timeout=timeout, cwd=cwd,
    )


class TestTypeErrorFallbackCwdPin:
    """Lane 1: ``except TypeError`` fallback in build_cpg."""

    def test_workspace_debris_lands_in_output_dir_not_caller_cwd(
        self, tmp_path: Path, caller_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = _stub_joern_parse(tmp_path / "bin")
        monkeypatch.setattr(
            "packages.joern.runner._joern_parse_path", lambda: str(stub),
        )
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }")
        out = tmp_path / "out"

        cpg = build_cpg(
            target, subprocess_runner=_bare_runner, output_dir=out,
        )

        assert not (caller_root / "workspace").exists(), (
            "unpinned fallback cwd: the stub's workspace/ landed in "
            "the caller's cwd (the observed repo-root debris shape)"
        )
        assert (out / "workspace" / "cpg.bin" / "cpg.bin").is_file()
        # Behavior parity: same success shape as before the pin.
        assert cpg.path == out.resolve() / "cpg.bin"
        assert cpg.path.is_file()
        assert not cpg.build_failed
        assert cpg.languages == {"c"}

    def test_failing_parse_keeps_rc_handling_and_cwd_clean(
        self, tmp_path: Path, caller_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = _stub_joern_parse(
            tmp_path / "bin", returncode=2, write_output=False,
        )
        monkeypatch.setattr(
            "packages.joern.runner._joern_parse_path", lambda: str(stub),
        )
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"

        cpg = build_cpg(
            target, subprocess_runner=_bare_runner, output_dir=out,
        )

        assert not (caller_root / "workspace").exists()
        assert (out / "workspace" / "cpg.bin" / "project.json").is_file()
        # Behavior parity: a nonzero rc still returns a handle whose
        # cpg.bin simply does not exist — never raises.
        assert cpg.path == out.resolve() / "cpg.bin"
        assert not cpg.exists()


class TestStallMonitorCwdPin:
    """Lane 2: the stall monitor's raw Popen (sandbox unavailable)."""

    def test_workspace_debris_lands_beside_cpg_not_caller_cwd(
        self, tmp_path: Path, caller_root: Path,
    ) -> None:
        stub = _stub_joern_parse(tmp_path / "bin")
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        cpg_path = out / "cpg.bin"

        cpg = _build_cpg_with_stall_monitor(
            [str(stub), "--output", str(cpg_path), str(target)],
            cpg_path=cpg_path,
            target=target,
            languages=None,
            timeout=30,
            on_progress=lambda m: None,
        )

        assert not (caller_root / "workspace").exists(), (
            "unpinned Popen cwd: the stub's workspace/ landed in the "
            "caller's cwd (the observed repo-root debris shape)"
        )
        assert (out / "workspace" / "cpg.bin" / "cpg.bin").is_file()
        # Behavior parity: same success shape as before the pin.
        assert cpg.path == cpg_path
        assert cpg.path.is_file()
        assert not cpg.build_failed
        assert cpg.languages == {"c"}
        assert cpg.build_time_ms < 30_000

    def test_failing_parse_keeps_rc_handling_and_cwd_clean(
        self, tmp_path: Path, caller_root: Path,
    ) -> None:
        stub = _stub_joern_parse(
            tmp_path / "bin", returncode=2, write_output=False,
        )
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        cpg_path = out / "cpg.bin"

        cpg = _build_cpg_with_stall_monitor(
            [str(stub), "--output", str(cpg_path), str(target)],
            cpg_path=cpg_path,
            target=target,
            languages=None,
            timeout=30,
            on_progress=lambda m: None,
        )

        assert not (caller_root / "workspace").exists()
        assert (out / "workspace" / "cpg.bin" / "project.json").is_file()
        assert not cpg.exists()


class TestRelativeOutputDirStaysCallerAnchored:
    """The cwd pin must not re-anchor a caller-relative output_dir:
    every path in the spawned argv is absolutized at assembly, so
    ``--output`` keeps meaning "relative to the CALLER's cwd" exactly
    as it did when the child inherited that cwd."""

    def test_relative_output_dir_resolves_against_caller_cwd(
        self, tmp_path: Path, caller_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = _stub_joern_parse(tmp_path / "bin")
        monkeypatch.setattr(
            "packages.joern.runner._joern_parse_path", lambda: str(stub),
        )
        target = tmp_path / "src"
        target.mkdir()

        cpg = build_cpg(
            target, subprocess_runner=_bare_runner,
            output_dir=Path("rel-out"),
        )

        assert cpg.path == caller_root.resolve() / "rel-out" / "cpg.bin"
        assert cpg.path.is_file()
        assert not (caller_root / "workspace").exists()
        assert (caller_root / "rel-out" / "workspace").is_dir()
