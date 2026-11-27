"""Tests for the traced-build binary capture seam in create_database:
binaries a traced/autobuild create writes into the repo tree land in
the persistent build ledger (content-hash delta), including under
parallel per-language creation and on failed builds. Buildless creates
never snapshot — no build executes."""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest

# packages/codeql/tests/... -> repo root
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parents[3]))

from core.analysis.binary_build_ledger import load_build_ledger
from core.build.build_detector import BuildSystem
from core.hash import sha256_file
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture(autouse=True)
def _xdg_home(tmp_path, monkeypatch):
    """Point the build ledger at a per-test XDG data home."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture(autouse=True)
def _all_pre_carriers_untracked(monkeypatch):
    """Hermetic provenance partition for the pre-build exemption: the
    real ``_filter_locally_built`` spawns sandboxed git, and these tmp
    repos are not git repos (the conservative split would exempt
    nothing). This seam pins capture mechanics; the exemption's
    provenance directions are pinned in
    core/analysis/tests/test_binary_build_ledger.py."""
    import core.analysis.binary_oracle_cli as oracle_cli
    monkeypatch.setattr(
        oracle_cli, "_filter_locally_built",
        lambda repo, candidates: (list(candidates), []))


@pytest.fixture
def db_manager(tmp_path):
    """DatabaseManager with a fake codeql binary (no __init__ probing)."""
    with TemporaryDirectory(
            prefix="codeql-test-cache-", dir=tmp_path.parent) as cache:
        with patch.object(DatabaseManager, '__init__', lambda self: None):
            mgr = DatabaseManager()
            mgr.codeql_cli = "/usr/bin/codeql"
            mgr.db_root = Path(cache)
        yield mgr


def _build_system(tmp_path, command="make"):
    return BuildSystem(
        type="make", command=command, working_dir=tmp_path,
        env_vars={}, confidence=1.0, detected_files=[],
    )


def _elf_bytes(payload: bytes) -> bytes:
    return b"\x7fELF" + payload


def _fake_run(repo: Path, writes: dict[str, bytes], returncode: int = 0):
    """A sandbox-run fake that plays the build: creates the staging DB
    dir (the dirent-type gate requires a real directory) and writes
    *writes* ({relpath: content}) into the repo tree, as a
    repo-controlled build script would through its write grant."""
    def run(cmd, **kwargs):
        if "database" in cmd and "create" in cmd:
            staging = Path(cmd[3])
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "db-info.json").write_text("{}")
            for rel, content in writes.items():
                out = repo / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(content)
                out.chmod(0o755)
        r = MagicMock()
        r.returncode = returncode
        r.stdout = ""
        r.stderr = "Finalizing database.\n"
        return r
    return run


def _patched(db_manager, tmp_path, fake_run, version="2.26.3"):
    db_path = tmp_path / "db"
    return (
        patch('core.sandbox.run', side_effect=fake_run),
        patch.object(db_manager, 'get_codeql_version',
                     return_value=version),
        patch.object(db_manager, '_count_database_files', return_value=0),
        patch.object(db_manager, 'save_metadata'),
        patch.object(db_manager, 'get_cached_database', return_value=None),
        patch.object(db_manager, 'compute_repo_hash', return_value='abc'),
        patch.object(db_manager, 'get_database_dir',
                     side_effect=lambda _h, lang: db_path / lang),
    )


def _run(db_manager, repo, *, language, build_system, traced_build,
         fake_run, version="2.26.3"):
    patches = _patched(db_manager, repo, fake_run, version=version)
    with patches[0], patches[1], patches[2], patches[3], \
            patches[4], patches[5], patches[6]:
        return db_manager.create_database(
            repo, language, build_system, traced_build=traced_build,
        )


class TestCaptureSeam:
    def test_traced_build_delta_recorded(self, db_manager, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        content = _elf_bytes(b"made-by-build")
        result = _run(
            db_manager, repo, language="cpp",
            build_system=_build_system(repo), traced_build=True,
            fake_run=_fake_run(repo, {"build/planted": content}),
        )
        assert result.success
        planted = repo / "build" / "planted"
        view = load_build_ledger(repo)
        assert view.status == "ok"
        assert sha256_file(planted) in view.hashes

    def test_preexisting_binary_not_recorded(self, db_manager, tmp_path):
        repo = tmp_path / "repo"
        (repo / "build").mkdir(parents=True)
        mine = repo / "build" / "mine"
        mine.write_bytes(_elf_bytes(b"operator-built"))
        mine.chmod(0o755)
        _run(
            db_manager, repo, language="cpp",
            build_system=_build_system(repo), traced_build=True,
            fake_run=_fake_run(repo, {"build/planted": _elf_bytes(b"new")}),
        )
        view = load_build_ledger(repo)
        assert view.status == "ok"
        assert sha256_file(mine) not in view.hashes
        assert sha256_file(repo / "build" / "planted") in view.hashes

    def test_failed_build_still_captures(self, db_manager, tmp_path):
        # The build may write binaries before dying; the post-snapshot
        # sits in a finally so the delta still lands.
        repo = tmp_path / "repo"
        repo.mkdir()
        content = _elf_bytes(b"written-then-failed")
        result = _run(
            db_manager, repo, language="cpp",
            build_system=_build_system(repo), traced_build=True,
            fake_run=_fake_run(repo, {"build/partial": content},
                               returncode=1),
        )
        assert not result.success
        view = load_build_ledger(repo)
        assert view.status == "ok"
        assert sha256_file(repo / "build" / "partial") in view.hashes

    def test_buildless_create_does_not_snapshot(self, db_manager, tmp_path):
        # cpp defaults to buildless: no build executes, so nothing can
        # have been build-produced and no ledger appears.
        repo = tmp_path / "repo"
        (repo / "build").mkdir(parents=True)
        b = repo / "build" / "app"
        b.write_bytes(_elf_bytes(b"operator"))
        b.chmod(0o755)
        result = _run(
            db_manager, repo, language="cpp",
            build_system=None, traced_build=False,
            fake_run=_fake_run(repo, {}),
        )
        assert result.success
        assert load_build_ledger(repo).status == "absent"


class TestParallelCapture:
    def test_parallel_traced_builds_record_both_deltas(
            self, db_manager, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        cpp_content = _elf_bytes(b"cpp-artifact")
        go_content = _elf_bytes(b"go-artifact")

        def fake_run(cmd, **kwargs):
            if "database" in cmd and "create" in cmd:
                staging = Path(cmd[3])
                staging.mkdir(parents=True, exist_ok=True)
                (staging / "db-info.json").write_text("{}")
                lang = next(
                    (a.split("=", 1)[1] for a in cmd
                     if a.startswith("--language=")), "")
                rel, content = (
                    ("build/cpp-bin", cpp_content) if lang == "cpp"
                    else ("build/go-bin", go_content))
                out = repo / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(content)
                out.chmod(0o755)
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = "Finalizing database.\n"
            return r

        patches = _patched(db_manager, repo, fake_run)
        with patches[0], patches[1], patches[2], patches[3], \
                patches[4], patches[5], patches[6]:
            results = db_manager.create_databases_parallel(
                repo,
                {"cpp": _build_system(repo, "make"),
                 "go": _build_system(repo, "go build ./...")},
                traced_languages={"cpp", "go"},
            )
        assert all(r.success for r in results.values())
        view = load_build_ledger(repo)
        assert view.status == "ok"
        assert sha256_file(repo / "build" / "cpp-bin") in view.hashes
        assert sha256_file(repo / "build" / "go-bin") in view.hashes
