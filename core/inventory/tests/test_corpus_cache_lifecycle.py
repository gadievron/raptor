"""All corpus drivers own failed builds and reuse only complete caches."""

from contextlib import contextmanager
import importlib
import logging
import os
from pathlib import Path
import threading

import pytest

from core.atomic_fs import rmtree_hardened
from core.build import artifacts
from core.inventory.binary_oracle_corpora import _cache
from core.testing.threads import retiring_threads

pytestmark = pytest.mark.skipif(os.name != "posix", reason="corpus caches require POSIX locks")

DRIVERS = {
    "zlib": ("_ZlibDriver", "ZLIB_SHA"),
    "libsodium": ("_LibsodiumDriver", "LIBSODIUM_TAG"),
    "zstd_holdout": ("_ZstdHoldoutDriver", "ZSTD_TAG"),
    "snappy": ("_SnappyDriver", "SNAPPY_SHA"),
    "leveldb": ("_LeveldbDriver", "LEVELDB_SHA"),
    "regex_rust": ("_RegexRustDriver", "REGEX_TAG"),
}


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    logger = logging.getLogger("test.corpus-cache-owned")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "level", logging.DEBUG)
    monkeypatch.setattr(artifacts, "logger", logger)
    monkeypatch.setattr(_cache, "logger", logger)


@pytest.fixture(params=DRIVERS)
def case(request, tmp_path, monkeypatch):
    name = request.param
    module = importlib.import_module(f"core.inventory.binary_oracle_corpora.{name}")
    driver_name, pin = DRIVERS[name]
    driver = getattr(module, driver_name)()
    token = getattr(module, pin)
    if pin.endswith("SHA"):
        token = token[:12]
    elif name == "libsodium":
        token = token.replace("-", "_")
    elif name == "zstd_holdout":
        token = token.replace(".", "_")
    work = tmp_path / "work"
    root = work / token
    root.mkdir(parents=True)
    (root / "operator.txt").write_text("unrelated metadata")
    if name in {"zlib", "libsodium", "zstd_holdout"}:
        dirs = [root / "build_o0", root / "build_o2"]
        tail = {"zlib": "example", "libsodium": "test/default/aead_aegis128l", "zstd_holdout": "programs/zstd"}[name]
        files = [path / tail for path in dirs]
        profile = None
        builder = "_build_fresh"
    else:
        dirs = [root / ("target" if name == "regex_rust" else "build")]
        tail = {"snappy": "snappy_unittest", "leveldb": "leveldb_tests", "regex_rust": "release/deps/regex-owned"}[name]
        files = [dirs[0] / tail, root / "merged.profdata"]
        profile = root / {"snappy": "snappy_123.profraw", "leveldb": "leveldb_123.profraw", "regex_rust": "cov-123-456.profraw"}[name]
        builder = "_build_and_run"
    state = {"calls": 0, "error": None, "stage": "merge", "omit": False, "hook": None, "profiles_at_start": []}

    def build(*args):
        assert Path(args[0]) == root
        state["calls"] += 1
        state["profiles_at_start"].append([] if profile is None else list(root.glob("*.profraw")))
        source = root / "src/locked"
        source.mkdir(parents=True)
        (source / "checkout").write_text("source")
        source.chmod(0o000)
        if name == "regex_rust":
            download = root / "cargo-home/registry"
            download.mkdir(parents=True)
            (download / "crate").write_text("private download")
        if state["stage"] != "clone":
            for path in dirs:
                path.mkdir(parents=True)
                (path / "partial").write_text("partial build")
        if state["stage"] == "merge" and not state["omit"]:
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"generated artifact")
                path.chmod(0o700)
            if profile is None:
                (dirs[0] / "coverage.gcda").write_bytes(b"coverage counters")
        if profile is not None:
            profile.write_bytes(b"raw counters")
        if state["hook"] is not None:
            state["hook"]()
        if state["error"] is not None:
            raise state["error"]("primary build failure")

    monkeypatch.setattr(module, builder, build)
    if hasattr(module, "_collect_gcov_liveness"):
        monkeypatch.setattr(module, "_collect_gcov_liveness", lambda path: {"function"})
        monkeypatch.setattr(module, "_enumerate_candidates", lambda path: ["function"])
        from core.inventory.binary_oracle_corpora import toolchain
        monkeypatch.setattr(toolchain, "record_toolchain", lambda **kw: {})
    else:
        monkeypatch.setattr(module, "_liveness_from_llvm_cov", lambda *a: ({"function"}, {"function"}))
    try:
        yield driver, module, root, work, dirs, files, profile, state
    finally:
        assert rmtree_hardened(work)


def _clean_failure(root, dirs, files, profile):
    assert (root / "operator.txt").read_text() == "unrelated metadata"
    assert not (root / "sentinel.ok").exists()
    assert not (root / "src").exists()
    assert not (root / "cargo-home").exists()
    assert all(not path.exists() for path in [*dirs, *files])
    if profile is not None:
        assert not profile.exists()


@pytest.mark.parametrize("stage", ["clone", "build", "merge"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_or_cancelled_build_reclaims_every_owned_tree(case, stage, error):
    driver, module, root, work, dirs, files, profile, state = case
    state.update(stage=stage, error=error)
    with pytest.raises(error, match="primary build failure"):
        driver.prepare(work)
    _clean_failure(root, dirs, files, profile)


def test_success_prunes_sources_downloads_and_merged_profiles(case):
    driver, module, root, work, dirs, files, profile, state = case
    result = driver.prepare(work)
    assert result["o2_binary"].is_file()
    assert all(path.exists() for path in files)
    assert (root / "sentinel.ok").read_text() == module.CACHE_VERSION
    assert not (root / "src").exists()
    assert not (root / "cargo-home").exists()
    if profile is not None:
        assert not profile.exists()
    assert (root / "operator.txt").read_text() == "unrelated metadata"


def test_warm_hit_retries_disposable_cleanup_without_rebuilding(case):
    driver, module, root, work, dirs, files, profile, state = case
    driver.prepare(work)
    marker = root / "sentinel.ok"
    before = marker.stat()
    source = root / "src/locked"
    source.mkdir(parents=True)
    (source / "residue").write_text("old source")
    source.chmod(0o000)
    if profile is not None:
        profile.write_bytes(b"old counters")
    if module.__name__.endswith("regex_rust"):
        (root / "cargo-home").mkdir()
    driver.prepare(work)
    assert state["calls"] == 1
    assert marker.stat().st_ino == before.st_ino
    assert marker.stat().st_mtime_ns == before.st_mtime_ns
    assert not (root / "src").exists()
    assert not (root / "cargo-home").exists()
    assert profile is None or not profile.exists()


@pytest.mark.parametrize("damage", ["missing", "empty", "missing-coverage", "oversize-marker", "symlink-marker", "fifo-marker"])
def test_incomplete_or_untrusted_cache_is_rebuilt(case, tmp_path, damage):
    driver, module, root, work, dirs, files, profile, state = case
    driver.prepare(work)
    marker = root / "sentinel.ok"
    outside = tmp_path / "operator-version"
    outside.write_text(module.CACHE_VERSION)
    if damage == "missing":
        files[0].unlink()
    elif damage == "empty":
        files[0].write_bytes(b"")
    elif damage == "missing-coverage":
        (dirs[0] / "coverage.gcda" if profile is None else files[-1]).unlink()
    elif damage == "oversize-marker":
        marker.write_bytes(b"x" * 65)
    else:
        marker.unlink()
        if damage == "symlink-marker":
            marker.symlink_to(outside)
        else:
            os.mkfifo(marker)
    driver.prepare(work)
    assert state["calls"] == 2
    assert outside.read_text() == module.CACHE_VERSION
    assert marker.read_text() == module.CACHE_VERSION and not marker.is_symlink()


def test_stale_profiles_are_removed_before_build(case):
    driver, module, root, work, dirs, files, profile, state = case
    if profile is not None:
        profile.write_bytes(b"stale counters")
    driver.prepare(work)
    assert state["profiles_at_start"] == [[]]


def test_missing_build_artifacts_cannot_publish_a_completion_marker(case):
    driver, module, root, work, dirs, files, profile, state = case
    state["omit"] = True
    with pytest.raises(RuntimeError, match="required artifacts"):
        driver.prepare(work)
    _clean_failure(root, dirs, files, profile)


def test_marker_write_failure_cleans_a_completed_build(case, monkeypatch):
    driver, module, root, work, dirs, files, profile, state = case
    def fail(*args, **kwargs):
        raise OSError("marker write failed")
    monkeypatch.setattr(_cache, "write_text_atomically", fail)
    with pytest.raises(OSError, match="marker write failed"):
        driver.prepare(work)
    _clean_failure(root, dirs, files, profile)


def test_pruning_failure_retains_valid_build_for_cleanup_retry(case, monkeypatch):
    driver, module, root, work, dirs, files, profile, state = case
    remove = artifacts.rmtree_hardened
    with monkeypatch.context() as fault:
        fault.setattr(artifacts, "rmtree_hardened", lambda path: False if Path(path).name == "src" else remove(path))
        with pytest.raises(OSError, match="Could not clear"):
            driver.prepare(work)
    assert (root / "sentinel.ok").exists()
    assert all(path.exists() for path in files)
    driver.prepare(work)
    assert state["calls"] == 1
    assert not (root / "src").exists()


def test_lock_failure_never_enters_the_builder(case, monkeypatch):
    driver, module, root, work, dirs, files, profile, state = case
    @contextmanager
    def fail(*args, **kwargs):
        raise OSError("lock unavailable")
        yield
    monkeypatch.setattr(_cache, "artifact_lock", fail)
    with pytest.raises(OSError, match="lock unavailable"):
        driver.prepare(work)
    assert state["calls"] == 0


def test_registry_overlap_is_refused_before_creating_cache_metadata(case, monkeypatch):
    driver, module, root, work, dirs, files, profile, state = case
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(root / "operator"))
    with pytest.raises(ValueError, match="overlaps operator registry"):
        driver.prepare(work)
    assert state["calls"] == 0
    assert not (root / "sentinel.ok.lock").exists()


def test_root_replacement_cannot_redirect_failure_cleanup(case, tmp_path):
    driver, module, root, work, dirs, files, profile, state = case
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("operator data")
    parked = root.with_name(root.name + "-old")
    def replace():
        root.rename(parked)
        root.symlink_to(outside, target_is_directory=True)
    state["hook"] = replace
    with pytest.raises(OSError, match="root changed"):
        driver.prepare(work)
    assert (outside / "keep").read_text() == "operator data"
    assert list(outside.iterdir()) == [outside / "keep"]


def test_concurrent_preparations_build_once(case, monkeypatch):
    driver, module, root, work, dirs, files, profile, state = case
    entered, release, second_attempt = threading.Event(), threading.Event(), threading.Event()
    lock = _cache.artifact_lock
    attempts = []
    results, errors = [], []
    @contextmanager
    def observed_lock(*args, **kwargs):
        attempts.append(None)
        if len(attempts) == 2:
            second_attempt.set()
        with lock(*args, **kwargs):
            yield
    def pause():
        entered.set()
        assert release.wait(30), "build was not released"
    state["hook"] = pause
    monkeypatch.setattr(_cache, "artifact_lock", observed_lock)
    def prepare():
        try:
            results.append(driver.prepare(work))
        except BaseException as exc:
            errors.append(exc)
    workers = [threading.Thread(target=prepare), threading.Thread(target=prepare)]
    with retiring_threads(workers, release=release.set, timeout=15):
        workers[0].start()
        assert entered.wait(10), "first build did not enter"
        workers[1].start()
        assert second_attempt.wait(10), "second prepare did not attempt the lock"
    assert not any(worker.is_alive() for worker in workers), "owned prepare workers did not exit"
    assert not errors
    assert len(results) == 2 and state["calls"] == 1


def test_failed_builder_cannot_leave_a_forged_success_marker(case):
    driver, module, root, work, dirs, files, profile, state = case
    state["hook"] = lambda: (root / "sentinel.ok").write_text(module.CACHE_VERSION)
    state["error"] = OSError
    with pytest.raises(OSError, match="primary build failure"):
        driver.prepare(work)
    _clean_failure(root, dirs, files, profile)


def test_cleanup_cancellation_preserves_build_error_and_continues(case, monkeypatch):
    driver, module, root, work, dirs, files, profile, state = case
    remove = artifacts.cleanup_build_paths
    interrupted = []
    def cleanup(paths):
        if state["calls"] and Path(paths[0]).name == "src" and not interrupted:
            interrupted.append(paths[0])
            raise KeyboardInterrupt("secondary cleanup cancellation")
        return remove(paths)
    state["error"] = OSError
    monkeypatch.setattr(artifacts, "cleanup_build_paths", cleanup)
    with pytest.raises(OSError, match="primary build failure"):
        driver.prepare(work)
    assert interrupted
    assert not (root / "cargo-home").exists()
    assert all(not path.exists() for path in dirs)
    assert profile is None or not profile.exists()
    assert not (root / "sentinel.ok").exists()
