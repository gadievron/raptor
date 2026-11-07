"""Compose staging budgets apply to actual copies and failed teardown."""

import os
from pathlib import Path

import pytest

from core.container import compose as cco


import core.container.compose as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def staging_case(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    config = source / "compose.yml"
    config.write_text("services: {}\n")
    staging = tmp_path / "staging"
    live = set()

    def allocate(**kwargs):
        staging.mkdir()
        return str(staging)

    patch_module_attribute(monkeypatch, cco, 'tempfile', "mkdtemp", allocate)
    monkeypatch.setattr(cco, "keepalive_register", live.add)
    monkeypatch.setattr(cco, "keepalive_unregister", live.discard)
    monkeypatch.setattr(cco, "_rewrite_ports_in_place", lambda *a, **kw: None)
    return source, config, staging, live


@pytest.mark.parametrize("axis", ["bytes", "entries"])
def test_growth_after_preflight_is_bounded(staging_case, monkeypatch, axis):
    source, config, staging, live = staging_case
    monkeypatch.setattr(cco, "_STAGING_MAX_BYTES", 128)
    monkeypatch.setattr(cco, "_STAGING_MAX_ENTRIES", 4)
    preflight = cco._require_stageable_size

    def grow_after_check(root):
        preflight(root)
        if axis == "bytes":
            (source / "blob").write_bytes(b"x" * 256)
        else:
            for i in range(5):
                (source / f"new-{i}").touch()

    monkeypatch.setattr(cco, "_require_stageable_size", grow_after_check)
    try:
        with pytest.raises(cco.ComposeError, match="staging budget"):
            cco.rewrite_for_localhost(config)
        assert not staging.exists()
        assert not live
    finally:
        cco.rmtree_hardened(staging)


def test_unregister_failure_still_removes_staging(staging_case, monkeypatch):
    source, config, staging, live = staging_case
    staging.mkdir()
    (staging / "partial").write_bytes(b"payload")

    def fail_unregister(path):
        raise OSError("unregister failed")

    monkeypatch.setattr(cco, "keepalive_unregister", fail_unregister)
    try:
        cco.cleanup_staging(staging)
        assert not staging.exists()
    finally:
        cco.rmtree_hardened(staging)


class _ReadHook:
    def __init__(self, stream, hook):
        self.stream = stream
        self.hook = hook

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def fileno(self):
        return self.stream.fileno()

    def read(self, size):
        chunk = self.stream.read(size)
        self.hook(chunk)
        return chunk


def test_growing_file_cannot_write_past_remaining_budget(staging_case, monkeypatch):
    source, config, staging, live = staging_case
    payload = source / "blob"
    payload.write_bytes(b"a" * 16)
    monkeypatch.setattr(cco, "_STAGING_MAX_BYTES", 40)
    original_open = cco.open_regular_beneath
    consumed = 0
    grown = False

    def open_source(root, rel, mode):
        stream = original_open(root, rel, mode)

        def after_read(chunk):
            nonlocal consumed, grown
            consumed += len(chunk)
            if Path(rel).name == "blob" and chunk and not grown:
                grown = True
                with payload.open("ab") as writer:
                    writer.write(b"x" * 80)

        return _ReadHook(stream, after_read)

    monkeypatch.setattr(cco, "open_regular_beneath", open_source)
    with pytest.raises(cco.ComposeError, match="staging budget"):
        cco.rewrite_for_localhost(config)
    assert grown and consumed <= 41
    assert not staging.exists()
    assert not live


@pytest.mark.parametrize("kind", ["fifo", "symlink"])
def test_changed_regular_source_is_refused(staging_case, monkeypatch, kind):
    source, config, staging, live = staging_case
    payload = source / "blob"
    payload.write_bytes(b"payload")
    outside = source.parent / "outside"
    outside.write_bytes(b"outside data")
    original_open = cco.open_regular_beneath

    def replace_before_open(root, rel, mode):
        if Path(rel).name == "blob":
            payload.unlink()
            if kind == "fifo":
                os.mkfifo(payload)
            else:
                payload.symlink_to(outside)
        return original_open(root, rel, mode)

    monkeypatch.setattr(cco, "open_regular_beneath", replace_before_open)
    with pytest.raises(cco.ComposeError, match="not a readable regular file"):
        cco.rewrite_for_localhost(config)
    assert outside.read_bytes() == b"outside data"
    assert not staging.exists()
    assert not live


def test_copy_preserves_executable_mode_and_timestamp(staging_case):
    source, config, staging, live = staging_case
    script = source / "build.sh"
    script.write_bytes(b"#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    os.utime(script, ns=(1_600_000_000_000_000_000,) * 2)
    staged, tree = cco.rewrite_for_localhost(config)
    try:
        copy = tree / script.name
        assert copy.read_bytes() == script.read_bytes()
        assert copy.stat().st_mode & 0o777 == 0o755
        assert copy.stat().st_mtime_ns == script.stat().st_mtime_ns
    finally:
        cco.cleanup_staging(tree)
    assert not live


def test_staging_keeps_internal_links_and_prunes_external_links(staging_case):
    source, config, staging, live = staging_case
    (source / "data").write_text("local")
    (source / "alias").symlink_to("data")
    outside = source.parent / "outside"
    outside.write_text("outside")
    (source / "external").symlink_to(outside)
    _, tree = cco.rewrite_for_localhost(config)
    try:
        assert (tree / "alias").is_symlink()
        assert (tree / "alias").read_text() == "local"
        assert not os.path.lexists(tree / "external")
        assert outside.read_text() == "outside"
    finally:
        cco.cleanup_staging(tree)
    assert not live


def test_staging_inside_source_is_refused_and_removed(staging_case, monkeypatch):
    source, config, staging, live = staging_case
    nested = source / "staging"

    def allocate(**kwargs):
        nested.mkdir()
        return str(nested)

    patch_module_attribute(monkeypatch, cco, 'tempfile', "mkdtemp", allocate)
    with pytest.raises(cco.ComposeError, match="outside the source tree"):
        cco.rewrite_for_localhost(config)
    assert not nested.exists()
    assert config.is_file()
    assert not live


def test_unremovable_external_link_refuses_publication(staging_case, monkeypatch):
    source, config, staging, live = staging_case
    outside = source.parent / "outside"
    outside.write_bytes(b"untouched")
    (source / "external").symlink_to(outside)
    unlink = Path.unlink

    def refuse_link(path, *args, **kwargs):
        if path == staging / "external":
            raise PermissionError("cannot prune link")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_link)
    with pytest.raises(cco.ComposeError, match="cannot prune escaping staging link"):
        cco.rewrite_for_localhost(config)
    assert outside.read_bytes() == b"untouched"
    assert not staging.exists()
    assert not live


def test_cleanup_cancellation_still_attempts_removal(staging_case, monkeypatch):
    source, config, staging, live = staging_case
    staging.mkdir()

    def cancel(path):
        raise KeyboardInterrupt("cancelled unregister")

    monkeypatch.setattr(cco, "keepalive_unregister", cancel)
    with pytest.raises(KeyboardInterrupt, match="cancelled unregister"):
        cco.cleanup_staging(staging)
    assert not staging.exists()


@pytest.mark.parametrize("cancel_cleanup", [False, True])
def test_cleanup_failure_keeps_setup_error(staging_case, monkeypatch, cancel_cleanup):
    source, config, staging, live = staging_case

    def fail_rewrite(*args, **kwargs):
        raise ValueError("primary rewrite failure")

    def fail_cleanup(path):
        if cancel_cleanup:
            raise KeyboardInterrupt("cleanup cancelled")
        raise OSError("cleanup failed")

    try:
        with monkeypatch.context() as faults:
            faults.setattr(cco, "_rewrite_ports_in_place", fail_rewrite)
            faults.setattr(cco, "rmtree_hardened", fail_cleanup)
            with pytest.raises(ValueError, match="primary rewrite failure"):
                cco.rewrite_for_localhost(config)
        assert not live
    finally:
        cco.rmtree_hardened(staging)


def test_preflight_stops_enumerating_at_entry_budget(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    for index in range(20):
        (source / str(index)).touch()
    scandir = os.scandir
    seen = 0

    class CountingScan:
        def __init__(self, path):
            self.scan = scandir(path)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.scan.close()

        def __iter__(self):
            return self

        def __next__(self):
            nonlocal seen
            item = next(self.scan)
            seen += 1
            return item

    monkeypatch.setattr(cco, "_STAGING_MAX_ENTRIES", 3)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, _os_fault_consumer, "os", "scandir", CountingScan)
        with pytest.raises(cco.ComposeError, match="entry staging budget"):
            cco._require_stageable_size(source)
    assert seen == 4


@pytest.mark.parametrize("axis", ["bytes", "entries"])
def test_exact_copy_budget_is_accepted(staging_case, monkeypatch, axis):
    source, config, staging, live = staging_case
    (source / "empty").touch()
    if axis == "bytes":
        monkeypatch.setattr(cco, "_STAGING_MAX_BYTES", config.stat().st_size)
    else:
        monkeypatch.setattr(cco, "_STAGING_MAX_ENTRIES", 2)
    _, tree = cco.rewrite_for_localhost(config)
    try:
        assert (tree / "empty").read_bytes() == b""
        assert (tree / config.name).read_bytes() == config.read_bytes()
    finally:
        cco.cleanup_staging(tree)
    assert not live
