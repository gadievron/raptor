"""_handle_probe payload-size caps for the sandbox host daemon.

Every probe step that produces bytes to send at the target must
enforce the ``_MAX_SEND_BYTES`` cap: ``send_template`` and
``build_fmtstr_write`` output are capped by the same mechanism as
``send_hex``, so no step type can push an unbounded payload into the
target's stdin.
"""

from __future__ import annotations

import shutil
import sys as _sys

import pytest

from core.sandbox import _daemon as daemon

pytestmark = pytest.mark.skipif(
    _sys.platform != "linux" or shutil.which("cat") is None,
    reason="probe handler spawns a real target subprocess",
)

_CAT = shutil.which("cat") or "/bin/cat"


class TestSendTemplateCap:

    def test_oversized_template_rejected(self):
        big = "A" * (daemon._MAX_SEND_BYTES + 1)
        resp = daemon._handle_probe({
            "target_argv": [_CAT],
            "steps": [{"send_template": big}],
            "per_recv_timeout": 0.2,
            "total_wait_seconds": 0.5,
        })
        assert resp["ok"] is False
        assert "send_template" in resp["error"]
        assert str(daemon._MAX_SEND_BYTES) in resp["error"]
        assert resp["steps_completed"] == 0

    def test_under_cap_template_still_sent(self):
        resp = daemon._handle_probe({
            "target_argv": [_CAT],
            "steps": [{"send_template": "hello\\n",
                       "recv_until": "newline"}],
            "per_recv_timeout": 2.0,
            "total_wait_seconds": 2.0,
        })
        assert resp["ok"] is True
        assert resp["steps_completed"] == 1
        assert "hello" in resp["target_stdout_tail"]


class TestBuildFmtstrWriteCap:

    def test_oversized_fmtstr_payload_rejected(self, monkeypatch):
        # Bypass pwntools: the cap check is on the OUTPUT length, so
        # substitute a builder that returns an oversized payload.
        monkeypatch.setattr(
            daemon, "_build_fmtstr_write",
            lambda spec, bindings: b"A" * (daemon._MAX_SEND_BYTES + 1),
        )
        resp = daemon._handle_probe({
            "target_argv": [_CAT],
            "steps": [{"build_fmtstr_write": {"offset": 6,
                                              "writes": {"1": "2"}}}],
            "per_recv_timeout": 0.2,
            "total_wait_seconds": 0.5,
        })
        assert resp["ok"] is False
        assert "build_fmtstr_write" in resp["error"]
        assert str(daemon._MAX_SEND_BYTES) in resp["error"]


class TestSendHexCapUnchanged:

    def test_oversized_hex_still_rejected(self):
        big_hex = "41" * (daemon._MAX_SEND_BYTES + 1)
        resp = daemon._handle_probe({
            "target_argv": [_CAT],
            "steps": [{"send_hex": big_hex}],
            "per_recv_timeout": 0.2,
            "total_wait_seconds": 0.5,
        })
        assert resp["ok"] is False
        assert "send_hex" in resp["error"]
