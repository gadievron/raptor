"""Tests for import-table input-channel recovery — the Win32
registry channel, the Winsock/XPC additions, and the pre-existing
POSIX channels staying byte-for-byte stable."""

from __future__ import annotations

from packages.binary_analysis.input_channels import (
    recover_static_channels,
)

_SHA = "b" * 64


def _channels(imports):
    channels, evidence = recover_static_channels(_SHA, imports)
    return {c.kind: c for c in channels}, evidence


def test_registry_channel_from_read_primitives():
    by_kind, evidence = _channels(
        ["RegQueryValueExW", "RegGetValueA", "CreateFileW"])
    assert "registry" in by_kind
    channel = by_kind["registry"]
    assert channel.details["symbols"] == [
        "RegGetValueA", "RegQueryValueExW"]
    assert channel.observed is False
    assert any(rec.data["channel"] == "registry" for rec in evidence)


def test_registry_setup_calls_alone_claim_no_channel():
    """Open/create are setup, not reads — the taxonomy's
    read-primitives-only rule holds through this consumer."""
    by_kind, _ = _channels(["RegOpenKeyExW", "RegCreateKeyExW"])
    assert "registry" not in by_kind


def test_winsock_extension_forms_join_network_channel():
    by_kind, _ = _channels(["WSARecvFrom", "AcceptEx"])
    assert "network" in by_kind
    assert by_kind["network"].details["symbols"] == [
        "AcceptEx", "WSARecvFrom"]


def test_xpc_names_join_ipc_channel():
    by_kind, _ = _channels(
        ["xpc_connection_set_event_handler",
         "xpc_dictionary_get_data"])
    assert "ipc" in by_kind
    assert by_kind["ipc"].details["symbols"] == [
        "xpc_connection_set_event_handler",
        "xpc_dictionary_get_data"]


def test_ipc_channel_composes_whole_xpc_group():
    """The ipc channel takes the ENTIRE darwin XPC ingress group from
    the taxonomy — a getter added there (e.g. the string/bytes-ptr
    read primitives) must join this channel without a second edit."""
    from core.function_taxonomy import MACOS_XPC_INGRESS_SUBSTRINGS
    from packages.binary_analysis.input_channels import _IMPORT_CHANNELS
    assert MACOS_XPC_INGRESS_SUBSTRINGS <= set(_IMPORT_CHANNELS["ipc"])
    by_kind, _ = _channels(
        ["xpc_dictionary_get_string", "xpc_data_get_bytes_ptr"])
    assert by_kind["ipc"].details["symbols"] == [
        "xpc_data_get_bytes_ptr", "xpc_dictionary_get_string"]


def test_network_channel_composition_pinned():
    """Two-direction pin of the network channel's composition rule:
    the whole taxonomy ingest group MINUS the setup calls (bind and
    listen ingest nothing) PLUS accept4 (channel marker only, not a
    taxonomy sink candidate). WSAAccept stays: like accept it proves
    a serving channel exists, even though no bytes land at the call."""
    from core.function_taxonomy import NETWORK_INGEST_FUNCS
    from packages.binary_analysis.input_channels import _IMPORT_CHANNELS
    assert set(_IMPORT_CHANNELS["network"]) == (
        (NETWORK_INGEST_FUNCS - {"bind", "listen"}) | {"accept4"}
    )
    assert "bind" not in _IMPORT_CHANNELS["network"]
    assert "listen" not in _IMPORT_CHANNELS["network"]
    assert "accept4" in _IMPORT_CHANNELS["network"]


def test_posix_channels_unchanged():
    """No-ELF-regression pin: a typical Linux import set recovers
    exactly the channels it did before the Win32/darwin additions."""
    by_kind, _ = _channels(
        ["recv", "accept", "read", "fgets", "open", "getenv",
         "readlink", "strcpy"])
    assert set(by_kind) == {"network", "stream", "file",
                            "environment", "ipc"}
    assert by_kind["network"].details["symbols"] == ["accept", "recv"]
    assert by_kind["ipc"].details["symbols"] == ["readlink"]


def test_no_imports_no_channels():
    by_kind, evidence = _channels([])
    assert by_kind == {}
    assert evidence == []
