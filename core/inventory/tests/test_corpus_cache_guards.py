"""Cache ownership validation precedes deletion and build startup."""

import logging

import pytest

from core.build import artifacts
from core.inventory.binary_oracle_corpora import _cache


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    logger = logging.getLogger("test.corpus-cache-guards-owned")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(artifacts, "logger", logger)
    monkeypatch.setattr(_cache, "logger", logger)


@pytest.mark.parametrize("bad", ["outside-slot", "root-slot", "nested-slot", "lock-slot", "outside-required", "transient-required", "profile-escape", "no-outputs", "no-required", "blank-version", "oversize-version", "root-alias"])
def test_bad_ownership_cannot_remove_unrelated_data(tmp_path, bad):
    root, outside = tmp_path / "cache", tmp_path / "operator"
    root.mkdir()
    outside.mkdir()
    (outside / "keep").write_text("operator data")
    builds = []
    options = dict(version="1", build=lambda: builds.append(None),
                   persistent=(root / "build",), required=(root / "build/executable",),
                   transient=(root / "src",))
    if bad == "outside-slot":
        options["persistent"] = (outside,)
    elif bad == "root-slot":
        options["persistent"] = (root,)
    elif bad == "nested-slot":
        options["persistent"] = (root / "build/nested",)
    elif bad == "lock-slot":
        options["persistent"] = (root / "sentinel.ok.lock",)
    elif bad == "outside-required":
        options["required"] = (outside / "keep",)
    elif bad == "transient-required":
        options["required"] = (root / "src/executable",)
    elif bad == "profile-escape":
        options["profile_pattern"] = "../*.profraw"
    elif bad == "no-outputs":
        options["persistent"] = ()
    elif bad == "no-required":
        options["required"] = ()
    elif bad == "blank-version":
        options["version"] = " "
    elif bad == "oversize-version":
        options["version"] = "v" * (_cache._MAX_VERSION_BYTES + 1)
    else:
        root.rmdir()
        root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        with _cache.prepared_corpus(root, **options):
            pytest.fail("bad cache should not yield")
    assert builds == []
    assert (outside / "keep").read_text() == "operator data"
    assert not (outside / "sentinel.ok.lock").exists()


@pytest.mark.parametrize("preserve", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_cleanup_attempts_remaining_paths_after_an_interruption(tmp_path, monkeypatch, preserve, error):
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_text("first")
    second.write_text("second")
    cleanup = artifacts.cleanup_build_paths
    attempted = []
    def remove(paths):
        attempted.extend(paths)
        if paths == [first]:
            raise error("first cleanup failed")
        return cleanup(paths)
    monkeypatch.setattr(artifacts, "cleanup_build_paths", remove)
    if preserve:
        _cache.clear_build_paths([first, second], preserve_error=True)
    else:
        with pytest.raises(error, match="first cleanup failed"):
            _cache.clear_build_paths([first, second])
    assert attempted == [first, second]
    assert first.exists() and not second.exists()


def test_profile_enumeration_failure_cannot_mask_build_failure(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    output, source = root / "build", root / "src"
    state = {"started": False}
    def build():
        source.mkdir()
        (source / "checkout").write_text("source")
        output.mkdir()
        (output / "partial").write_text("partial")
        state["started"] = True
        raise OSError("primary build error")
    def profiles(*args):
        if state["started"]:
            raise RuntimeError("secondary profile enumeration error")
        return []
    monkeypatch.setattr(_cache, "_profiles", profiles)
    with pytest.raises(OSError, match="primary build error"):
        with _cache.prepared_corpus(root, version="1", build=build,
                                    persistent=(output,), required=(output / "binary",),
                                    transient=(source,), profile_pattern="cov-*.profraw"):
            pytest.fail("failed build should not yield")
    assert not output.exists() and not source.exists()
    assert not (root / "sentinel.ok").exists()
