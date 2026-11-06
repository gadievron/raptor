"""Failed source acquisition cleans only the destination it reserved."""

import logging
import subprocess

import pytest

from core.atomic_fs import rmtree_hardened
from core.audit.corpus import sources
from core.audit.corpus.sources import SourceEntry, SourceFetchError


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    logger = logging.getLogger("test.source-lifecycle-owned")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(sources, "logger", logger)
    try:
        yield
    finally:
        # Fault injection may intentionally retain a mode-0 partial tree.
        assert rmtree_hardened(tmp_path / "downloads")


@pytest.fixture(params=["tag", "sha", "sparse"])
def acquisition(request, tmp_path, monkeypatch):
    kind = request.param
    dest = tmp_path / "downloads/checkout"
    entry = SourceEntry(repo_key="owned", url="https://origin.invalid/owned", mirror_urls=("https://mirror.invalid/owned",))
    state = {"attempts": [], "error": None, "ok": True, "mirror": False, "hook": None}
    def fetch(*args, **kwargs):
        url = args[0]
        destination = args[3] if kind == "sparse" else args[2]
        assert destination == dest and dest.is_dir()
        assert not list(dest.iterdir()), "mirror inherited a partial checkout"
        state["attempts"].append(url)
        (dest / ".git").mkdir()
        locked = dest / "locked"
        locked.mkdir()
        (locked / "partial").write_text("downloaded objects")
        locked.chmod(0)
        if state["hook"]:
            state["hook"]()
        if state["error"]:
            raise state["error"]
        return state["ok"] or state["mirror"] and len(state["attempts"]) > 1, "connection refused"
    seam = {"tag": "_clone_at_ref", "sha": "_clone_at_sha", "sparse": "_fetch_files_from"}[kind]
    monkeypatch.setattr(sources, seam, fetch)
    def acquire():
        if kind == "sparse":
            return sources.fetch_files("owned", "v1", ["a.c"], dest, entry=entry)
        return sources.clone_source("owned", "a" * 40 if kind == "sha" else "v1", dest, entry=entry)
    return dest, entry, state, acquire


@pytest.mark.parametrize("failure", ["io", "timeout", "cancel", "post-clone"])
def test_exception_reclaims_partial_checkout(acquisition, monkeypatch, failure):
    dest, entry, state, acquire = acquisition
    error = {"io": OSError("download failed"), "timeout": subprocess.TimeoutExpired("git", 1),
             "cancel": KeyboardInterrupt("download cancelled"), "post-clone": ValueError("symlink setup failed")}[failure]
    if failure == "post-clone":
        def apply(*args):
            raise error
        monkeypatch.setattr(sources, "_apply_symlinks", apply)
    else:
        state["error"] = error
    with pytest.raises(type(error)) as caught:
        acquire()
    assert caught.value is error
    assert len(state["attempts"]) == 1
    assert not dest.exists()


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_unowned_existing_destination_is_preserved(acquisition, kind, tmp_path):
    dest, entry, state, acquire = acquisition
    dest.parent.mkdir(parents=True)
    outside = tmp_path / "operator"
    outside.mkdir()
    (outside / "keep").write_text("operator data")
    if kind == "directory":
        dest.mkdir()
        (dest / "keep").write_text("operator data")
    elif kind == "file":
        dest.write_text("operator data")
    else:
        dest.symlink_to(outside, target_is_directory=True)
    with pytest.raises((FileExistsError, SourceFetchError)):
        acquire()
    assert not state["attempts"]
    assert (outside / "keep").read_text() == "operator data"
    if kind == "directory":
        assert (dest / "keep").read_text() == "operator data"
    elif kind == "file":
        assert dest.read_text() == "operator data"
    else:
        assert dest.is_symlink()


def test_mirror_gets_clean_destination_after_restricted_failure(acquisition):
    dest, entry, state, acquire = acquisition
    state.update(ok=False, mirror=True)
    assert acquire() == dest
    assert state["attempts"] == list(entry.urls)
    assert (dest / ".git").is_dir()


def test_all_failed_mirrors_leave_no_checkout(acquisition):
    dest, entry, state, acquire = acquisition
    state["ok"] = False
    with pytest.raises(SourceFetchError) as caught:
        acquire()
    assert caught.value.connectivity
    assert state["attempts"] == list(entry.urls)
    assert not dest.exists()


def test_failed_cleanup_stops_mirror_retry(acquisition, monkeypatch):
    dest, entry, state, acquire = acquisition
    state["ok"] = False
    monkeypatch.setattr(sources, "rmtree_hardened", lambda path: False)
    with pytest.raises(SourceFetchError, match="retained after failed removal"):
        acquire()
    assert len(state["attempts"]) == 1
    assert dest.is_dir()


def test_cleanup_cancellation_cannot_replace_fetch_error(acquisition, monkeypatch):
    dest, entry, state, acquire = acquisition
    original = OSError("fetch stopped")
    state["error"] = original
    def remove(path):
        raise KeyboardInterrupt("secondary teardown interruption")
    monkeypatch.setattr(sources, "rmtree_hardened", remove)
    with pytest.raises(OSError) as caught:
        acquire()
    assert caught.value is original
    assert len(state["attempts"]) == 1


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
@pytest.mark.parametrize("failed", [False, True])
def test_root_replacement_cannot_be_adopted_or_removed(acquisition, tmp_path, replacement, failed):
    dest, entry, state, acquire = acquisition
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("operator data")
    parked = dest.parent / "parked"
    def redirect():
        dest.rename(parked)
        if replacement == "symlink":
            dest.symlink_to(outside, target_is_directory=True)
        else:
            dest.mkdir()
            (dest / "keep").write_text("replacement data")
    state.update(error=OSError("fetch stopped") if failed else None, hook=redirect)
    with pytest.raises(OSError if failed else SourceFetchError, match="fetch stopped" if failed else "root changed"):
        acquire()
    assert dest.is_symlink() == (replacement == "symlink")
    if replacement == "directory":
        assert (dest / "keep").read_text() == "replacement data"
    assert (outside / "keep").read_text() == "operator data"
    assert list(outside.iterdir()) == [outside / "keep"]


def test_operator_registry_is_refused_before_allocation(acquisition, monkeypatch):
    dest, entry, state, acquire = acquisition
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(dest))
    with pytest.raises(ValueError, match="registry"):
        acquire()
    assert not state["attempts"]
    assert not dest.exists()


@pytest.mark.parametrize("cleanup", ["success", "retained", "cancelled"])
def test_sparse_refetch_requires_complete_old_checkout_cleanup(tmp_path, monkeypatch, cleanup):
    dest = tmp_path / "downloads/cache"
    (dest / ".git").mkdir(parents=True)
    locked = dest / "locked"
    locked.mkdir()
    (locked / "partial").write_text("old objects")
    locked.chmod(0)
    monkeypatch.setattr(sources, "_run_git", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "b" * 40, ""))
    fetched = []
    def fetch(url, ref, files, destination, **kwargs):
        assert destination == dest and not list(dest.iterdir())
        fetched.append(None)
        (dest / ".git").mkdir()
        return True, ""
    monkeypatch.setattr(sources, "_fetch_files_from", fetch)
    if cleanup == "retained":
        monkeypatch.setattr(sources, "rmtree_hardened", lambda path: False)
    elif cleanup == "cancelled":
        def remove(path):
            raise KeyboardInterrupt("old cleanup cancelled")
        monkeypatch.setattr(sources, "rmtree_hardened", remove)
    entry = SourceEntry(repo_key="owned", url="https://origin.invalid/owned")
    if cleanup == "success":
        assert sources.fetch_files("owned", "a" * 40, ["a.c"], dest, entry=entry) == dest
        assert fetched == [None]
        assert not locked.exists()
    else:
        with pytest.raises(SourceFetchError if cleanup == "retained" else KeyboardInterrupt):
            sources.fetch_files("owned", "a" * 40, ["a.c"], dest, entry=entry)
        assert not fetched
        assert locked.exists()
