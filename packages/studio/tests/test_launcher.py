"""Tests for the raptor_studio.py launcher's bind-address gate."""

from __future__ import annotations

import pytest

import raptor_studio


def test_loopback_bind_hosts():
    f = raptor_studio._is_loopback_bind_host
    assert f("127.0.0.1")
    assert f("localhost")
    assert f("LOCALHOST")
    assert f("::1")
    assert f("[::1]")
    assert f("127.0.0.5")


def test_non_loopback_bind_hosts():
    f = raptor_studio._is_loopback_bind_host
    assert not f("0.0.0.0")
    assert not f("::")
    assert not f("192.168.1.10")
    assert not f("studio.internal")  # unknown hostname: conservative


def test_remote_bind_refused_without_flag(monkeypatch):
    monkeypatch.setattr("sys.argv", ["raptor_studio.py", "--host", "0.0.0.0"])
    with pytest.raises(SystemExit) as exc:
        raptor_studio.main()
    assert exc.value.code == 2  # argparse parser.error


def test_remote_bind_provisions_token(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv", ["raptor_studio.py", "--host", "0.0.0.0", "--allow-remote"]
    )
    monkeypatch.delenv("STUDIO_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("STUDIO_ALLOW_REMOTE", raising=False)

    import os

    seen = {}

    def fake_run(*args, **kwargs):
        seen["allow_remote"] = os.environ.get("STUDIO_ALLOW_REMOTE")
        seen["token"] = os.environ.get("STUDIO_AUTH_TOKEN")

    uvicorn = pytest.importorskip("uvicorn")
    monkeypatch.setattr(uvicorn, "run", fake_run)
    try:
        raptor_studio.main()
    finally:
        # main() writes os.environ directly; monkeypatch never saw the
        # vars (absent at delenv time), so scrub them ourselves.
        os.environ.pop("STUDIO_AUTH_TOKEN", None)
        os.environ.pop("STUDIO_ALLOW_REMOTE", None)

    assert seen["allow_remote"] == "1"
    assert seen["token"] and len(seen["token"]) >= 32
    warning = capsys.readouterr().err
    assert "WARNING" in warning
    assert seen["token"] in warning
