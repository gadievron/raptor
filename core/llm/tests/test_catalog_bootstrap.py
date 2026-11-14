"""Actual socket handoff, bounded failures and endpoint ownership."""

from __future__ import annotations

import socket
import struct
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.llm.catalog import MAX_CATALOG_BYTES, prepare_catalog
from core.llm.catalog_bootstrap import (
    CatalogBootstrapError,
    receive_catalog,
    send_catalog,
)
from core.llm.config import ModelConfig


def _public(count=1):
    return prepare_catalog([
        ModelConfig(provider="openai", model_name="fixture-model" * 50,
                    api_key="canary-private-key")
        for _ in range(count)
    ]).public


def test_large_snapshot_handoff_consumes_both_endpoints():
    catalog = _public(400)
    # Larger than ordinary socket buffers: the producer must not prefill a
    # pipe/socket synchronously before a worker starts consuming the frame.
    assert len(catalog.to_bytes()) > 200000
    with ThreadPoolExecutor(max_workers=1) as executor:
        sender, receiver = socket.socketpair()
        try:
            future = executor.submit(send_catalog, sender, catalog)
            actual = receive_catalog(receiver)
            future.result(timeout=6)
            assert actual == catalog
            assert sender.fileno() == receiver.fileno() == -1
        finally:
            sender.close()
            receiver.close()


@pytest.mark.parametrize("raw", [
    b"", b"\0", struct.pack("!I", 0),
    struct.pack("!I", MAX_CATALOG_BYTES + 1),
    struct.pack("!I", 100) + b"short",
    struct.pack("!I", 4) + b"null",
], ids=["missing-header", "short-header", "zero", "oversize", "short-body", "bad-schema"])
def test_invalid_frames_close_receiver_without_fallback(raw):
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(raw)
        sender.close()
        with pytest.raises(CatalogBootstrapError):
            receive_catalog(receiver)
        assert receiver.fileno() == -1
    finally:
        sender.close()
        receiver.close()


def test_extra_frame_is_rejected():
    raw = _public().to_bytes()
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(struct.pack("!I", len(raw)) + raw + b"extra")
        sender.close()
        with pytest.raises(CatalogBootstrapError, match="Trailing"):
            receive_catalog(receiver)
        assert receiver.fileno() == -1
    finally:
        sender.close()
        receiver.close()


def test_stalled_sender_has_a_deadline_and_receiver_is_closed():
    sender, receiver = socket.socketpair()
    try:
        with pytest.raises(CatalogBootstrapError):
            receive_catalog(receiver, timeout=0.02)
        assert receiver.fileno() == -1
    finally:
        sender.close()
        receiver.close()


def test_stalled_receiver_bounds_send_and_closes_sender():
    catalog = _public(400)
    sender, receiver = socket.socketpair()
    try:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        with pytest.raises(CatalogBootstrapError):
            send_catalog(sender, catalog, timeout=0.1)
        assert sender.fileno() == -1
        receiver.settimeout(0.5)
        # Prove the send reached the socket rather than failing at encoding.
        assert receiver.recv(4) == struct.pack("!I", len(catalog.to_bytes()))
    finally:
        sender.close()
        receiver.close()


def test_private_holder_cannot_be_sent_as_a_public_snapshot():
    sender, receiver = socket.socketpair()
    try:
        private = prepare_catalog([ModelConfig(provider="openai", model_name="fixture-model")])
        with pytest.raises(CatalogBootstrapError, match="Expected public"):
            send_catalog(sender, private)
        assert sender.fileno() == -1
        assert receiver.recv(1) == b""
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), 10**1000],
                         ids=["zero", "negative", "bool", "nan", "huge-int"])
def test_invalid_deadline_closes_owned_endpoint(timeout):
    sender, receiver = socket.socketpair()
    try:
        with pytest.raises(CatalogBootstrapError, match="timeout"):
            receive_catalog(receiver, timeout=timeout)
        assert receiver.fileno() == -1
    finally:
        sender.close()
        receiver.close()
