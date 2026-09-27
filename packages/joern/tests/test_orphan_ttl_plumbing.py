"""Orphan-idle-TTL plumbing (forwarder CLI → server → construction sites).

The forwarder's orphan watchdog default horizon matches the lifecycle
warm-handoff staleness horizon — right for a lifecycle-recorded server
a later run can re-acquire, pure squatting time for a run-private one
nothing can ever reconnect to. These tests pin the override channel:
the ``--orphan-idle-ttl`` flag parses (and rejects garbage), ``main()``
hands it to the watchdog, ``JoernServer`` emits it onto the forwarder
command line only when a caller opted in, and the lifecycle fresh-start
site deliberately does NOT opt in.
"""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from typing import Any

import pytest

from packages.joern import lifecycle
from packages.joern import netns_forwarder as nf
from packages.joern.server import JoernServer


class TestPositiveFloat:
    def test_accepts_positive(self):
        assert nf._positive_float("900") == 900.0
        assert nf._positive_float("0.5") == 0.5

    @pytest.mark.parametrize("bad", ["0", "-5", "nan", "inf", "-inf"])
    def test_rejects_non_positive_and_non_finite(self, bad):
        with pytest.raises(argparse.ArgumentTypeError):
            nf._positive_float(bad)

    def test_rejects_non_numeric(self):
        with pytest.raises(ValueError):
            nf._positive_float("soon")


def _run_main(monkeypatch, argv: list[str]) -> tuple[int, dict[str, Any]]:
    """Drive ``main()`` with every side-effecting seam stubbed out.

    No namespace is entered, no socket bound, no child spawned, no
    signal handler installed — the test observes only what the orphan
    watchdog was armed with.
    """
    captured: dict[str, Any] = {}
    monkeypatch.setattr(nf, "enter_private_netns", lambda: None)
    monkeypatch.setattr(nf, "bring_loopback_up", lambda: None)
    monkeypatch.setattr(
        nf, "create_listener",
        lambda path: SimpleNamespace(close=lambda: None),
    )

    class _FakeForwarder:
        def __init__(self, listener: Any, upstream: Any,
                     socket_path: str | None = None) -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

    monkeypatch.setattr(nf, "Forwarder", _FakeForwarder)

    def _fake_watchdog(get_child: Any, forwarder: Any, **kw: Any) -> None:
        captured.update(kw)

    monkeypatch.setattr(nf, "_start_orphan_watchdog", _fake_watchdog)
    monkeypatch.setattr(nf.signal, "signal", lambda *_a: None)
    monkeypatch.setattr(
        nf.subprocess, "Popen",
        lambda cmd: SimpleNamespace(wait=lambda: 0),
    )
    return nf.main(argv), captured


class TestMainWiring:
    _BASE = ["--socket", "/nonexistent-ttl-test/fwd.sock",
             "--port", "12345", "--", "true"]

    def test_default_ttl_reaches_watchdog(self, monkeypatch):
        rc, captured = _run_main(monkeypatch, list(self._BASE))
        assert rc == 0
        assert captured["idle_ttl_s"] == nf._ORPHAN_IDLE_TTL_S

    def test_explicit_ttl_reaches_watchdog(self, monkeypatch):
        rc, captured = _run_main(
            monkeypatch, ["--orphan-idle-ttl", "900", *self._BASE],
        )
        assert rc == 0
        assert captured["idle_ttl_s"] == 900.0

    def test_non_positive_ttl_is_a_parse_error(self):
        # Rejected before any namespace/socket work happens.
        with pytest.raises(SystemExit):
            nf.main(["--orphan-idle-ttl", "0", *self._BASE])


class TestForwarderArgv:
    def _bare(self, ttl: float | None) -> JoernServer:
        srv = JoernServer.__new__(JoernServer)
        srv.stop = lambda: None  # type: ignore[method-assign] — fabricated handle
        srv._uds_path = "/x/fwd.sock"
        srv._port = 1234
        srv._orphan_idle_ttl_s = ttl
        return srv

    def test_omitted_when_unset(self):
        argv = self._bare(None)._forwarder_argv(["joern", "--server"])
        assert "--orphan-idle-ttl" not in argv

    def test_appended_before_command_separator_when_set(self):
        argv = self._bare(900.0)._forwarder_argv(["joern", "--server"])
        i = argv.index("--orphan-idle-ttl")
        assert argv[i + 1] == "900.0"
        # Forwarder flag, not a flag of the wrapped command.
        assert i < argv.index("--")

    def test_flag_value_parses_back(self):
        # The float's str() round-trips through the CLI type: a format
        # drift here would fail every strong-tier boot at parse time.
        argv = self._bare(900.0)._forwarder_argv(["joern"])
        value = argv[argv.index("--orphan-idle-ttl") + 1]
        assert nf._positive_float(value) == 900.0


class TestFromTunablesPlumb:
    def test_kwarg_reaches_instance(self):
        srv = JoernServer.from_tunables(None, orphan_idle_ttl_s=123.0)
        assert srv._orphan_idle_ttl_s == 123.0

    def test_default_is_no_override(self):
        assert JoernServer.from_tunables(None)._orphan_idle_ttl_s is None


class TestLifecycleFreshStartKeepsDefault:
    def test_start_fresh_passes_no_ttl_override(self, monkeypatch):
        # A lifecycle-recorded server is warm-handoff re-acquirable:
        # its forwarder must keep the long default horizon.
        captured: dict[str, Any] = {}

        class _StubServer:
            @staticmethod
            def from_tunables(
                tunables: Any = None, *,
                orphan_idle_ttl_s: float | None = None,
            ) -> Any:
                captured["ttl"] = orphan_idle_ttl_s
                return SimpleNamespace(start=lambda: None)

        monkeypatch.setattr(lifecycle, "JoernServer", _StubServer)
        assert lifecycle._start_fresh(None) is not None
        assert captured["ttl"] is None
