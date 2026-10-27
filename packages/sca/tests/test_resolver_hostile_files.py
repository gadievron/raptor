"""Resolver-side file handling against hostile scanned directories.

Resolvers read / copy files that live inside the SCANNED directory: a
symlink there must not steer reads at operator files (exfil into run
artifacts), and a FIFO must never be opened (blocking open hangs the
worker). The requirements.txt include bound must confine ``-r`` lines
to the scan target — never to the checkout's parent directory.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from packages.sca.parsers import requirements
from packages.sca.parsers._safe_read import scan_root_context
from packages.sca.resolvers._safe_io import (
    copy_regular_file,
    read_regular_bytes,
    read_regular_text,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file-type semantics")


# ---------------------------------------------------------------------------
# _safe_io primitives
# ---------------------------------------------------------------------------

def test_read_regular_bytes_reads_regular_file(tmp_path: Path) -> None:
    p = tmp_path / "gradle.lockfile"
    p.write_bytes(b"org.example:lib:1.0=runtimeClasspath\n")
    assert read_regular_bytes(p) == b"org.example:lib:1.0=runtimeClasspath\n"


def test_read_regular_bytes_refuses_symlink(tmp_path: Path) -> None:
    secret = tmp_path / "operator-secret"
    secret.write_bytes(b"hunter2")
    link = tmp_path / "scanned" / "gradle.lockfile"
    link.parent.mkdir()
    link.symlink_to(secret)
    assert read_regular_bytes(link) is None


def test_read_regular_bytes_refuses_fifo_without_blocking(
    tmp_path: Path,
) -> None:
    fifo = tmp_path / "gradle.lockfile"
    os.mkfifo(fifo)
    # lstat gate rejects before any open — a blocking open would hang
    # this test forever (no writer on the FIFO).
    assert read_regular_bytes(fifo) is None


def test_read_regular_bytes_refuses_oversize(tmp_path: Path) -> None:
    p = tmp_path / "big"
    p.write_bytes(b"x" * 128)
    assert read_regular_bytes(p, max_bytes=64) is None


def test_read_regular_text_missing_file(tmp_path: Path) -> None:
    assert read_regular_text(tmp_path / "nope.toml") is None


def test_copy_regular_file_refuses_symlink_and_fifo(tmp_path: Path) -> None:
    secret = tmp_path / "operator-secret"
    secret.write_bytes(b"hunter2")
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "Cargo.toml").symlink_to(secret)
    os.mkfifo(hostile / "Cargo.lock")
    dst_dir = tmp_path / "work"
    dst_dir.mkdir()

    assert not copy_regular_file(
        hostile / "Cargo.toml", dst_dir / "Cargo.toml")
    assert not copy_regular_file(
        hostile / "Cargo.lock", dst_dir / "Cargo.lock")
    assert list(dst_dir.iterdir()) == []


def test_copy_regular_file_copies_content(tmp_path: Path) -> None:
    src = tmp_path / "Cargo.toml"
    src.write_bytes(b"[package]\nname = \"x\"\n")
    dst = tmp_path / "out"
    dst.mkdir()
    assert copy_regular_file(src, dst / "Cargo.toml")
    assert (dst / "Cargo.toml").read_bytes() == src.read_bytes()


# ---------------------------------------------------------------------------
# PoetryResolver.matches — probe must not follow links or open FIFOs
# ---------------------------------------------------------------------------

def test_poetry_matches_regular_project(tmp_path: Path) -> None:
    from packages.sca.resolvers.poetry import PoetryResolver
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry]\nname = \"x\"\n", encoding="utf-8")
    assert PoetryResolver().matches(tmp_path)


def test_poetry_matches_refuses_symlinked_pyproject(tmp_path: Path) -> None:
    from packages.sca.resolvers.poetry import PoetryResolver
    outside = tmp_path / "outside.toml"
    outside.write_text("[tool.poetry]\nname = \"y\"\n", encoding="utf-8")
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "pyproject.toml").symlink_to(outside)
    assert not PoetryResolver().matches(hostile)


def test_poetry_matches_refuses_fifo_pyproject(tmp_path: Path) -> None:
    from packages.sca.resolvers.poetry import PoetryResolver
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    os.mkfifo(hostile / "pyproject.toml")
    # Would hang forever on a blocking open; the lstat gate refuses.
    assert not PoetryResolver().matches(hostile)


# ---------------------------------------------------------------------------
# requirements.txt include bound
# ---------------------------------------------------------------------------

def test_include_cannot_escape_to_checkout_parent(tmp_path: Path) -> None:
    """A root-level manifest's ``-r ../x`` used to be admitted by the
    grandparent fallback bound — everything BESIDE the checkout was
    readable. The default bound is now the manifest's own directory."""
    beside = tmp_path / "operator-notes.txt"
    beside.write_text("secretpkg==1.0\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "-r ../operator-notes.txt\nrequests==2.31.0\n", encoding="utf-8")

    deps = requirements.parse(repo / "requirements.txt")

    names = {d.name for d in deps}
    assert "requests" in names
    assert "secretpkg" not in names


def test_include_inside_manifest_dir_still_parses(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    (repo / "sub" / "base.txt").write_text(
        "flask==3.0.0\n", encoding="utf-8")
    (repo / "requirements.txt").write_text(
        "-r sub/base.txt\nrequests==2.31.0\n", encoding="utf-8")

    deps = requirements.parse(repo / "requirements.txt")

    assert {d.name for d in deps} == {"flask", "requests"}


def test_deep_layout_supported_when_scan_root_is_known(
    tmp_path: Path,
) -> None:
    """``requirements/dev.txt → -r ../base.txt`` keeps working through
    the pipeline's scan-root context (and the explicit parameter)."""
    repo = tmp_path / "repo"
    (repo / "requirements").mkdir(parents=True)
    (repo / "base.txt").write_text("django==4.2.7\n", encoding="utf-8")
    manifest = repo / "requirements" / "dev.txt"
    manifest.write_text("-r ../base.txt\npytest==8.0.0\n", encoding="utf-8")

    with scan_root_context(repo):
        via_context = requirements.parse(manifest)
    via_param = requirements.parse(manifest, scan_root=repo)

    assert {d.name for d in via_context} == {"django", "pytest"}
    assert {d.name for d in via_param} == {"django", "pytest"}


def test_scan_root_context_does_not_admit_escapes(tmp_path: Path) -> None:
    beside = tmp_path / "beside.txt"
    beside.write_text("evilpkg==1.0\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "-r ../beside.txt\n", encoding="utf-8")

    with scan_root_context(repo):
        deps = requirements.parse(repo / "requirements.txt")

    assert {d.name for d in deps} == set()


# ---------------------------------------------------------------------------
# Resolver temp-copy stage — every resolver must refuse symlinked /
# special manifest files from the scanned directory
# ---------------------------------------------------------------------------

class _StopAfterCopy(Exception):
    """Raised by the stubbed ``_run`` so each dry_run test stops right
    after the temp-copy stage — the copy posture is what's under test,
    not the (absent) package-manager tool."""


def _stub_run_recording(record: dict):
    """Return a ``_run`` stand-in that snapshots the temp dir the
    resolver populated, then aborts the dry_run."""
    def _fake_run(cmd, cwd, timeout, proxy_hosts, env=None,
                  block_network=False):
        record["files"] = {
            p.name: p.read_bytes()
            for p in Path(cwd).iterdir() if p.is_file()
        }
        raise _StopAfterCopy
    return _fake_run


# (module path, resolver class name, filenames the resolver copies)
_COPYING_RESOLVERS = [
    ("packages.sca.resolvers.bundler", "BundlerResolver",
     ("Gemfile", "Gemfile.lock")),
    ("packages.sca.resolvers.composer", "ComposerResolver",
     ("composer.json", "composer.lock")),
    ("packages.sca.resolvers.gomod", "GoResolver", ("go.mod", "go.sum")),
    ("packages.sca.resolvers.npm", "NpmResolver",
     ("package.json", "package-lock.json")),
    ("packages.sca.resolvers.nuget", "NugetResolver",
     ("app.csproj", "packages.lock.json")),
    ("packages.sca.resolvers.pnpm", "PnpmResolver",
     ("package.json", "pnpm-lock.yaml")),
    ("packages.sca.resolvers.yarn", "YarnResolver",
     ("package.json", "yarn.lock")),
]


@pytest.mark.wall_budget(seconds=15)
@pytest.mark.parametrize(
    ("mod_name", "cls_name", "fnames"), _COPYING_RESOLVERS,
    ids=[m.rsplit(".", 1)[1] for m, _, _ in _COPYING_RESOLVERS],
)
def test_resolver_copy_refuses_symlink_and_fifo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    mod_name: str, cls_name: str, fnames: tuple,
) -> None:
    """A manifest that is a symlink to an operator file must not have
    its target's content copied into the resolver's temp dir; a FIFO
    lockfile must be refused without blocking."""
    import importlib
    mod = importlib.import_module(mod_name)

    secret = tmp_path / "operator-secret"
    secret.write_bytes(b"AWS_SECRET=hunter2\n")
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    manifest_name, lock_name = fnames
    (hostile / manifest_name).symlink_to(secret)
    os.mkfifo(hostile / lock_name)

    record: dict = {}
    monkeypatch.setattr(mod, "_run", _stub_run_recording(record))
    monkeypatch.setattr(mod, "_check_tool", lambda *a, **k: True)
    if hasattr(mod, "_detect_major_version"):
        monkeypatch.setattr(mod, "_detect_major_version", lambda: 1)

    resolver = getattr(mod, cls_name)()
    with pytest.raises(_StopAfterCopy):
        resolver.dry_run(hostile)

    copied = record["files"]
    assert lock_name not in copied, "FIFO lockfile must be refused"
    for content in copied.values():
        assert b"hunter2" not in content, (
            "symlink target content leaked into the resolver copy"
        )


def test_bundler_copy_refuses_symlinked_gemspec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from packages.sca.resolvers import bundler

    secret = tmp_path / "operator-secret"
    secret.write_bytes(b"hunter2")
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "Gemfile").write_text("source 'https://rubygems.org'\n",
                                     encoding="utf-8")
    (hostile / "evil.gemspec").symlink_to(secret)

    record: dict = {}
    monkeypatch.setattr(bundler, "_run", _stub_run_recording(record))
    monkeypatch.setattr(bundler, "_check_tool", lambda *a, **k: True)
    with pytest.raises(_StopAfterCopy):
        bundler.BundlerResolver().dry_run(hostile)

    assert "evil.gemspec" not in record["files"]


def test_gomod_go_file_copy_refuses_symlink_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``*.go`` source-copy loop must not follow a symlink even
    when it appears as a regular ``.go`` path at copy time."""
    from packages.sca.resolvers import gomod

    secret = tmp_path / "operator-secret"
    secret.write_bytes(b"hunter2")
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "go.mod").write_text("module example.com/x\n",
                                    encoding="utf-8")
    (hostile / "main.go").write_text("package main\n", encoding="utf-8")
    (hostile / "leak.go").symlink_to(secret)

    record: dict = {}
    monkeypatch.setattr(gomod, "_run", _stub_run_recording(record))
    monkeypatch.setattr(gomod, "_check_tool", lambda *a, **k: True)
    with pytest.raises(_StopAfterCopy):
        gomod.GoResolver().dry_run(hostile)

    assert "main.go" in record["files"]
    assert "leak.go" not in record["files"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
