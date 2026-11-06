"""Own ephemeral calibration roots through queued, abandoned and retry work."""

import concurrent.futures
import logging
import subprocess
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.atomic_fs import rmtree_hardened
from core.run import scratch
from core.testing.stress_state import isolated_stress_workers
from packages.sca.calibration import project_samples, stress


@pytest.fixture
def owned(tmp_path, monkeypatch, _owned_calibration_keepalive):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    roots = []
    original = tempfile.mkdtemp

    def allocate(*args, **kwargs):
        root = Path(original(*args, **{**kwargs, "dir": runtime}))
        roots.append(root)
        return str(root)

    monkeypatch.setattr(scratch, "tempfile", SimpleNamespace(**{**vars(tempfile), "mkdtemp": allocate}))
    monkeypatch.setattr(scratch, "logger", logging.Logger("calibration-scratch-test"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "registry"))
    monkeypatch.setenv("RAPTOR_SCA_STRESS_EPHEMERAL", "1")
    try:
        yield SimpleNamespace(roots=roots, pins=_owned_calibration_keepalive, tmp=tmp_path)
        assert all(not p.exists() for p in roots), roots
        assert not _owned_calibration_keepalive
    finally:
        assert rmtree_hardened(runtime)


def sample(name="fixture"):
    return project_samples.ProjectSample(name=name, ecosystem="PyPI",
        repo_url="https://example.invalid/fixture.git", git_ref="v1", license_spdx="MIT")


def result(name="fixture"):
    return stress.StressResult(project=name, ecosystem="PyPI", elapsed_seconds=0,
        deps_analysed=1, vuln_findings=0, eco_breakdown={})


def dirty(root):
    child = root / "download-cache" / "restricted"
    if child.exists():
        child.chmod(0o700)
    child.mkdir(parents=True, exist_ok=True)
    (child / "payload").write_bytes(b"cache" * 1024)
    child.chmod(0)


@pytest.mark.parametrize("completion", ["success", "error", "cancel"])
@pytest.mark.parametrize("early", [False, True], ids=["after-driver", "before-driver"])
def test_workspace_tracks_queued_future(owned, completion, early):
    workspace = stress._SweepWorkspace()
    future = concurrent.futures.Future()
    pool = SimpleNamespace(submit=lambda *args, **kwargs: future)
    try:
        workspace.submit(pool, lambda: None)
        dirty(workspace.path)
        assert str(workspace.path) in owned.pins
        if not early:
            workspace.release()
            assert workspace.path.is_dir()
            assert str(workspace.path) in owned.pins
        if completion == "cancel":
            assert future.cancel()
        elif completion == "error":
            future.set_exception(RuntimeError("scan failed"))
        else:
            future.set_result(None)
        if early:
            assert workspace.path.is_dir()
    finally:
        if not future.done():
            future.cancel()
        if early:
            workspace.release()
    assert not workspace.path.exists()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_workspace_failed_submit_releases_job_lease(owned, error):
    workspace = stress._SweepWorkspace()

    def fail(*args, **kwargs):
        raise error("submit failed")

    try:
        with pytest.raises(error, match="submit failed"):
            workspace.submit(SimpleNamespace(submit=fail), lambda: None)
        assert workspace.path.is_dir()
    finally:
        workspace.release()


def test_already_finished_submission_keeps_driver_ownership(owned):
    workspace = stress._SweepWorkspace()
    future = concurrent.futures.Future()
    future.set_result(None)
    try:
        workspace.submit(SimpleNamespace(submit=lambda *a, **k: future), lambda: None)
        assert workspace.path.is_dir()
        assert str(workspace.path) in owned.pins
    finally:
        workspace.release()


def test_retry_pool_and_sweep_pool_share_root_ownership(owned):
    workspace = stress._SweepWorkspace()
    futures = [concurrent.futures.Future(), concurrent.futures.Future()]
    try:
        for future in futures:
            workspace.submit(SimpleNamespace(submit=lambda *a, f=future, **k: f), lambda: None)
        workspace.release()
        futures[0].set_result(None)
        assert workspace.path.is_dir() and str(workspace.path) in owned.pins
    finally:
        for future in futures:
            if not future.done():
                future.cancel()
    assert not workspace.path.exists()


@pytest.mark.parametrize("interrupt", [False, True], ids=["timeout", "interrupt"])
@pytest.mark.parametrize("worker_error", [None, RuntimeError, SystemExit], ids=["success", "error", "exit"])
def test_live_abandoned_worker_keeps_root_until_exit(owned, interrupt, worker_error):
    release, started = threading.Event(), threading.Event()
    seen = []

    def scan(item, root, **kwargs):
        seen.append(root)
        (root / "started").write_text("owned")
        started.set()
        assert release.wait(10), "test worker was not released"
        assert (root / "started").read_text() == "owned"
        (root / "late-result").write_text("complete")
        dirty(root)
        if worker_error:
            raise worker_error("late failure")
        return result(item.name)

    with pytest.MonkeyPatch.context() as patch:
        with isolated_stress_workers(stress, patch):
            patch.setattr(stress, "_scan_one_inner", scan)
            if interrupt:
                def stop_driver(*args, **kwargs):
                    assert started.wait(5)
                    raise KeyboardInterrupt("driver interrupted")
                patch.setattr(stress.concurrent.futures, "wait", stop_driver)
            try:
                if interrupt:
                    with pytest.raises(KeyboardInterrupt, match="driver interrupted"):
                        stress.run_stress_sweep(samples=[sample(), sample("queued")], max_workers=1,
                            git_clone_timeout=0, sca_timeout=0)
                else:
                    outcomes = stress.run_stress_sweep(samples=[sample(), sample("queued")], max_workers=1,
                        git_clone_timeout=0, sca_timeout=0)
                    assert len(outcomes) == 2
                    assert all(r.error for r in outcomes)
                assert started.is_set() and len(seen) == 1
                assert seen[0].is_dir() and str(seen[0]) in owned.pins
            finally:
                release.set()
    assert not seen[0].exists()


@pytest.mark.parametrize("failure", ["mkdir", "heartbeat", "executor"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_ephemeral_setup_failure_cleans_root(owned, monkeypatch, failure, error):
    def fail(*args, **kwargs):
        raise error("setup failed")

    if failure == "mkdir":
        original = Path.mkdir
        def mkdir(path, *args, **kwargs):
            if path in owned.roots:
                fail()
            return original(path, *args, **kwargs)
        monkeypatch.setattr(Path, "mkdir", mkdir)
    else:
        with pytest.MonkeyPatch.context() as patch:
            with isolated_stress_workers(stress, patch):
                if failure == "executor":
                    patch.setattr(stress.concurrent.futures, "ThreadPoolExecutor", fail)
                else:
                    class FailedThread(stress.threading.Thread):
                        def start(self):
                            fail()
                    patch.setattr(stress.threading, "Thread", FailedThread)
                with pytest.raises(error, match="setup failed"):
                    stress.run_stress_sweep(samples=[])
        return
    with pytest.raises(error, match="setup failed"):
        stress.run_stress_sweep(samples=[])


@pytest.mark.parametrize("shape", ["restricted-tree", "file", "symlink", "dangling", "missing"])
def test_stale_scan_cleanup_handles_node_shapes(owned, shape):
    path = owned.tmp / "stale"
    outside = owned.tmp / "operator"
    outside.mkdir()
    (outside / "keep").write_text("operator")
    if shape == "restricted-tree":
        path.mkdir()
        dirty(path)
    elif shape == "file":
        path.write_text("partial result")
    elif shape in ("symlink", "dangling"):
        path.symlink_to(outside if shape == "symlink" else owned.tmp / "absent", target_is_directory=True)
    stress._rmtree(path)
    assert not path.exists() and not path.is_symlink()
    assert (outside / "keep").read_text() == "operator"


def test_registry_overlap_refuses_stale_scan_deletion(owned, monkeypatch):
    path = owned.tmp / "stale"
    registry = path / "operator-registry"
    registry.mkdir(parents=True)
    (registry / "keep").write_text("operator")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(registry))
    with pytest.raises(ValueError):
        stress._rmtree(path)
    assert (registry / "keep").read_text() == "operator"


def test_retained_stale_scan_prevents_clone_and_scan(owned, monkeypatch):
    from core.build import artifacts
    from packages.sca import pipeline
    root = owned.tmp / "persistent"
    stale = root / "PyPI-fixture" / "src"
    stale.mkdir(parents=True)
    (stale / "keep").write_text("old checkout")
    monkeypatch.setattr(artifacts, "rmtree_hardened", lambda path: False)
    monkeypatch.setattr(pipeline, "run_sca", lambda **kw: pytest.fail("scan started over old output"))
    # Clone is incidental and must not be reached after failed cleanup.
    monkeypatch.setattr(stress, "subprocess", SimpleNamespace(run=lambda *a, **kw: pytest.fail("clone started")))
    with pytest.raises(OSError, match="cleanup incomplete"):
        stress._scan_one_inner(sample(), root, git_clone_timeout=1)
    assert (stale / "keep").read_text() == "old checkout"


@pytest.mark.parametrize("stage", ["clone", "scan"])
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt, SystemExit], ids=["success", "error", "interrupt", "exit"])
def test_sample_collection_owns_clone_and_output(owned, monkeypatch, stage, error):
    from packages.sca import pipeline

    def action(where):
        root = owned.roots[-1]
        assert str(root) in owned.pins
        dirty(root)
        if stage == where and error:
            raise error("collection failed")
        return root

    def clone(*args, **kwargs):
        root = action("clone")
        (root / "fixture").mkdir()
        return subprocess.CompletedProcess([], 0, "", "")

    def scan(**kwargs):
        root = action("scan")
        output = root / "sca-out"
        output.mkdir()
        (output / "findings.json").write_text("[]")

    view = SimpleNamespace(**{**vars(subprocess), "run": clone})
    monkeypatch.setattr(project_samples, "subprocess", view)
    monkeypatch.setattr(pipeline, "run_sca", scan)
    call = lambda: project_samples._collect_one(sample(), owned.tmp / "samples", http=None,
        cache=None, git_clone_timeout=1, sca_timeout=1)
    if error and (stage == "clone" or error is not RuntimeError):
        with pytest.raises(error, match="collection failed"):
            call()
    else:
        collected = call()
        assert collected.written == (error is None)
        if collected.written:
            assert (owned.tmp / "samples" / "PyPI" / "fixture.json").is_file()


@pytest.mark.parametrize("error", [None, RuntimeError, SystemExit], ids=["success", "error", "exit"])
def test_timed_out_retry_keeps_ephemeral_root(owned, error):
    first_timed_out, first_done = threading.Event(), threading.Event()
    retry_started, release = threading.Event(), threading.Event()
    slow_calls = []

    class Sink(list):
        def append(self, item):
            super().append(item)
            if item.project == "slow" and item.error:
                first_timed_out.set()

    def scan(item, root, **kwargs):
        if item.name == "quick":
            assert first_done.wait(5), "orphan did not complete"
            return result(item.name)
        slow_calls.append(root)
        if len(slow_calls) == 1:
            assert first_timed_out.wait(5), "driver did not record timeout"
            return result(item.name)
        retry_started.set()
        assert release.wait(10), "retry was not released"
        assert root.is_dir() and str(root) in owned.pins
        (root / "late-retry-result").write_text("complete")
        if error:
            raise error("retry failed late")
        return result(item.name)

    with pytest.MonkeyPatch.context() as patch:
        with isolated_stress_workers(stress, patch):
            base = stress.concurrent.futures.ThreadPoolExecutor

            class ObservedExecutor(base):
                def submit(self, fn, item, *args, **kwargs):
                    future = super().submit(fn, item, *args, **kwargs)
                    if item.name == "slow" and not first_done.is_set():
                        future.add_done_callback(lambda future: first_done.set())
                    return future

            patch.setattr(stress.concurrent.futures, "ThreadPoolExecutor", ObservedExecutor)
            patch.setattr(stress, "_scan_one_inner", scan)
            original_started_at = stress._scan_started_at
            # The coordinator waits for the orphan's completion callback. It
            # has no work budget in this ownership test; only slow times out.
            patch.setattr(stress, "_scan_started_at",
                lambda label: None if label == "PyPI/quick" else original_started_at(label))
            try:
                outcomes = stress.run_stress_sweep(samples=[sample("slow"), sample("quick")],
                    max_workers=2, git_clone_timeout=0.05, sca_timeout=0.05, results_sink=Sink())
                assert retry_started.wait(5), "retry never started"
                assert len(slow_calls) == 2 and slow_calls[0] == slow_calls[1]
                assert slow_calls[-1].is_dir() and str(slow_calls[-1]) in owned.pins
                assert next(r for r in outcomes if r.project == "slow").error
            finally:
                release.set()
    assert not slow_calls[-1].exists()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_heartbeat_join_failure_keeps_driver_error(owned, error):
    with pytest.MonkeyPatch.context() as patch:
        with isolated_stress_workers(stress, patch):
            base = stress.threading.Thread

            class InterruptedJoin(base):
                def join(self, *args, **kwargs):
                    super().join(*args, **kwargs)
                    if not getattr(self, "reported", False):
                        self.reported = True
                        raise error("secondary join failure")

            def fail(*args, **kwargs):
                raise RuntimeError("primary executor failure")

            patch.setattr(stress.threading, "Thread", InterruptedJoin)
            patch.setattr(stress.concurrent.futures, "ThreadPoolExecutor", fail)
            with pytest.raises(RuntimeError, match="primary executor failure"):
                stress.run_stress_sweep(samples=[])
