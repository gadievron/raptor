"""Owned empty notice directories and synthetic embedded metadata, no capture."""
import base64
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from packages.sca import sbom_notices as module


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture
def notice_io(tmp_path, monkeypatch):
    root = tmp_path / "owned"
    (root / "notices" / "sha256").mkdir(parents=True)
    config = json.dumps({"os": "linux", "architecture": "amd64",
                         "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "1" * 64]}}).encode()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"digest": _digest(config), "size": len(config)},
                           "layers": [{"digest": "sha256:" + "2" * 64, "size": 1,
                                       "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]}).encode()
    native = {"schema": {"version": "16.1.11"},
              "source": {"type": "image", "metadata": {
                  "manifest": base64.b64encode(manifest).decode(), "manifestDigest": _digest(manifest),
                  "config": base64.b64encode(config).decode(), "imageID": _digest(config)}},
              "descriptor": {"configuration": {"search": {"scope": "squashed"}}},
              "artifacts": [], "files": []}
    digest = hashlib.sha256(json.dumps(native).encode()).hexdigest()
    report = {"version": 1, "catalogue_sha256": digest, "subject": module.subject(native)[0],
              "packages": [], "files": []}
    state = {"root": root, "native": native, "digest": digest, "report": report,
             "opened": [], "closed": [], "live": set(), "errors": {}, "identities": {},
             "open_error": None, "open_args": []}

    def opened(*args, **kwargs):
        try:
            fd = os.open(*args, **kwargs)
        except BaseException as exc:
            state["open_error"] = exc
            raise
        state["open_args"].append((args, kwargs))
        state["opened"].append(fd)
        state["live"].add(fd)
        st = os.fstat(fd)
        state["identities"][fd] = st.st_dev, st.st_ino
        return fd

    def close(fd):
        st = os.fstat(fd)
        assert (st.st_dev, st.st_ino) == state["identities"][fd]
        os.close(fd)
        state["live"].remove(fd)
        state["closed"].append(fd)
        index = state["opened"].index(fd)
        if index in state["errors"]:
            raise state["errors"][index]

    def no_notice_reads(*_args, **_kwargs):
        pytest.fail("empty directory fixture must not read notice bytes")

    monkeypatch.setattr(module, "read_capped", no_notice_reads)
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "open": opened, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            st = os.fstat(fd)
            assert (st.st_dev, st.st_ino) == state["identities"][fd]
            os.close(fd)
        state["errors"].clear()
        state["open_error"] = None


def _load(state):
    return module.load_notices(state["root"], state["native"], state["digest"], state["report"])


def test_deepest_close_failure_still_retires_owned_parent_directories(notice_io):
    cleanup = OSError("after deepest native directory close")
    notice_io["errors"][2] = cleanup
    with pytest.raises(OSError) as raised:
        _load(notice_io)
    assert raised.value is cleanup
    # Probe every leftover before the harness's independent final cleanup.
    live_native = [fd for fd in notice_io["opened"] if fd in notice_io["live"] and os.fstat(fd)]
    assert live_native == []
    assert notice_io["closed"] == list(reversed(notice_io["opened"]))


def _assert_all_retired(state):
    assert state["closed"] == list(reversed(state["opened"]))
    assert not state["live"]
    for fd in state["opened"]:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_each_fresh_close_failure_still_retires_siblings(notice_io, index, close_type):
    cleanup = close_type("after native directory close")
    notice_io["errors"][index] = cleanup
    with pytest.raises(close_type) as raised:
        _load(notice_io)
    assert raised.value is cleanup
    assert len(notice_io["opened"]) == 3
    _assert_all_retired(notice_io)


@pytest.mark.parametrize("first_type,later_type", [(OSError, KeyboardInterrupt), (KeyboardInterrupt, OSError)])
def test_first_reverse_order_close_error_stays_primary(notice_io, first_type, later_type):
    first = first_type("deepest directory close")
    notice_io["errors"].update({2: first, 1: later_type("middle directory close"),
                                0: MemoryError("root directory close")})
    with pytest.raises(first_type) as raised:
        _load(notice_io)
    assert raised.value is first
    _assert_all_retired(notice_io)


@pytest.mark.parametrize("missing", ["notices", "sha256"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_native_partial_acquisition_refusal_retires_every_parent(notice_io, missing, close_type):
    (notice_io["root"] / "notices" / "sha256").rmdir()
    if missing == "notices":
        (notice_io["root"] / "notices").rmdir()
    notice_io["errors"].update({0: close_type("root close"), 1: close_type("middle close")})
    with pytest.raises(FileNotFoundError) as raised:
        _load(notice_io)
    assert raised.value is notice_io["open_error"]
    assert len(notice_io["opened"]) == (1 if missing == "notices" else 2)
    _assert_all_retired(notice_io)


def test_native_root_absence_has_no_descriptor_to_retire(notice_io):
    (notice_io["root"] / "notices" / "sha256").rmdir()
    (notice_io["root"] / "notices").rmdir()
    notice_io["root"].rmdir()
    with pytest.raises(FileNotFoundError) as raised:
        _load(notice_io)
    assert raised.value is notice_io["open_error"]
    assert notice_io["opened"] == []
    _assert_all_retired(notice_io)


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_existing_layer_schema_refusal_survives_all_close_errors(notice_io, close_type):
    notice_io["report"]["files"] = [{"path": "/plain", "catalogue_layer_diff_id": "sha256:" + "1" * 64,
                                     "layer_blob_digest": "sha256:" + "3" * 64}]
    notice_io["errors"].update({2: close_type("deep close"), 1: close_type("middle close")})
    with pytest.raises(ValueError, match="duplicate notice location or unrelated layer"):
        _load(notice_io)
    assert len(notice_io["opened"]) == 3
    _assert_all_retired(notice_io)


def test_native_empty_inventory_retains_result_and_open_relationships(notice_io):
    summary, blobs = _load(notice_io)
    assert summary["version"] == 1
    assert summary["subject"] == notice_io["report"]["subject"]
    assert summary["packages"] == summary["unassociated_files"] == []
    assert blobs == {}
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_DIRECTORY
    assert notice_io["open_args"] == [((notice_io["root"], flags), {}),
                                      (("notices", flags), {"dir_fd": notice_io["opened"][0]}),
                                      (("sha256", flags), {"dir_fd": notice_io["opened"][1]})]
    _assert_all_retired(notice_io)
