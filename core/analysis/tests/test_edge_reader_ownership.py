"""Pinned edge caller cleanup on plaintext; extraction is a non-executing seam."""
import pytest

from core.analysis import binary_oracle_edges as module
from core.analysis.tests.test_pin_reader_ownership import pin_io as pin_io
from core.config import RaptorConfig


@pytest.fixture
def edge_io(pin_io, monkeypatch):
    monkeypatch.setattr(RaptorConfig, "BINARY_ORACLE_IDENTITY_PINS", {str(pin_io["path"]): pin_io["pin"]})
    pin_io["result"] = module.BinaryEdgeIndex(binary_path=str(pin_io["path"]))
    pin_io["calls"] = []
    return pin_io


def test_post_hash_error_survives_consumed_close(edge_io, monkeypatch):
    primary = KeyboardInterrupt("after native post-verification hash")

    def extracted(path, **kwargs):
        edge_io["calls"].append((path, kwargs))
        edge_io["primary"] = primary
        edge_io["cleanup"] = MemoryError("after native close")
        return edge_io["result"]

    monkeypatch.setattr(module, "_extract_direct_call_edges_impl", extracted)
    with pytest.raises(KeyboardInterrupt) as raised:
        module.extract_direct_call_edges(edge_io["path"], timeout=7, use_cache=False)
    assert raised.value is primary
    assert edge_io["calls"] == [(edge_io["path"], {"timeout": 7, "use_cache": False})]
    assert edge_io["hashes"] == 2
    assert edge_io["closes"] == 1
    assert edge_io["streams"][0].closed


@pytest.mark.parametrize("site", ["extract", "post_hash"])
@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_active_caller_error_keeps_identity(edge_io, monkeypatch, site, primary_type, close_type):
    primary = primary_type("caller operation failed")

    def extracted(*_args, **_kwargs):
        edge_io["cleanup"] = close_type("after native close")
        if site == "extract":
            raise primary
        edge_io["primary"] = primary
        return edge_io["result"]

    monkeypatch.setattr(module, "_extract_direct_call_edges_impl", extracted)
    with pytest.raises(primary_type) as raised:
        module.extract_direct_call_edges(edge_io["path"])
    assert raised.value is primary
    assert edge_io["hashes"] == (1 if site == "extract" else 2)
    assert edge_io["closes"] == 1
    assert edge_io["streams"][0].closed


@pytest.mark.parametrize("close_type", [None, OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_healthy_caller_retains_close_policy(edge_io, monkeypatch, close_type):
    monkeypatch.setattr(module, "_extract_direct_call_edges_impl", lambda *_a, **_k: edge_io["result"])
    cleanup = close_type("after native close") if close_type else None
    edge_io["cleanup"] = cleanup
    if close_type in (MemoryError, KeyboardInterrupt, SystemExit):
        with pytest.raises(close_type) as raised:
            module.extract_direct_call_edges(edge_io["path"])
        assert raised.value is cleanup
    else:
        assert module.extract_direct_call_edges(edge_io["path"]) is edge_io["result"]
    assert edge_io["hashes"] == 2
    assert edge_io["closes"] == 1
    assert edge_io["streams"][0].closed


@pytest.mark.parametrize("close_type", [None, OSError])
def test_native_content_drift_still_withholds_callback_result(edge_io, monkeypatch, close_type):
    def extracted(path, **_kwargs):
        path.write_bytes(b"changed plain text")
        edge_io["cleanup"] = close_type("after native close") if close_type else None
        return edge_io["result"]

    monkeypatch.setattr(module, "_extract_direct_call_edges_impl", extracted)
    result = module.extract_direct_call_edges(edge_io["path"])
    assert result is not edge_io["result"]
    assert result.binary_path == str(edge_io["path"])
    assert result.edges == []
    assert result.callees == set()
    assert edge_io["hashes"] == 2
    assert edge_io["closes"] == 1
    assert edge_io["streams"][0].closed


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_handled_post_hash_io_retains_demotion_and_fresh_close_policy(edge_io, monkeypatch, close_type):
    def extracted(*_args, **_kwargs):
        edge_io["primary"] = OSError("after native post hash")
        edge_io["cleanup"] = cleanup
        return edge_io["result"]

    cleanup = close_type("after native close") if close_type else None
    monkeypatch.setattr(module, "_extract_direct_call_edges_impl", extracted)
    if close_type is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt) as raised:
            module.extract_direct_call_edges(edge_io["path"])
        assert raised.value is cleanup
    else:
        result = module.extract_direct_call_edges(edge_io["path"])
        assert result is not edge_io["result"]
        assert result.edges == []
        assert result.callees == set()
    assert edge_io["hashes"] == 2
    assert edge_io["closes"] == 1
    assert edge_io["streams"][0].closed
