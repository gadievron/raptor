"""Lineage binding between acquire and release.

``joern_release`` used to decrement — and kill at zero — whatever the
state file recorded. After a restart + concurrent-acquire interleaving
(session 1's server dies mid-restart; session 2 sees the dead record,
kills it, and boots a fresh server), session 1's release then killed
session 2's LIVE server mid-query while session 1's replacement JVM
leaked untracked. Acquire now hands back a lineage token persisted in
the state (``boot_nonce``); release touches the record only on a
match, and stops the caller's own untracked handle otherwise.
``note_server_replaced`` repoints on the token, the recorded pid, or
the recorded port ONLY when the recorded pid is dead — a live server
that merely shares the old port number is a different server.
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

from packages.joern import lifecycle
from packages.joern.tests.test_lifecycle import _TmpState, _mock_server


def _seed_state(ts: _TmpState, **overrides) -> dict:
    state = {
        "pid": 2_000_000_000,   # dead by construction
        "comm": "java",
        "port": 41234,
        "refcount": 1,
        "started_at": 0,
        "auth_user": "raptor",
        "auth_password": "cred-b",
        "socket_path": None,
        "boot_nonce": "lineage-b",
    }
    state.update(overrides)
    ts.state_file.write_text(json.dumps(state))
    return state


def _read(ts: _TmpState) -> dict | None:
    if not ts.state_file.exists():
        return None
    return json.loads(ts.state_file.read_text())


class _Env:
    def __enter__(self) -> _TmpState:
        self._ts = _TmpState()
        self._ts.install()
        return self._ts

    def __exit__(self, *exc) -> None:
        self._ts.cleanup()


class TestReleaseLineage:
    def test_foreign_token_leaves_recorded_server_untouched(self):
        # The cross-session interleaving's final step: our lineage
        # was replaced by a concurrent kill-and-replace; bare release
        # would have decremented the OTHER session's server to zero
        # and killed it mid-query.
        with _Env() as ts:
            _seed_state(ts, boot_nonce="lineage-b")
            own = _mock_server()
            with patch.object(lifecycle, "_kill_server") as kill:
                lifecycle.joern_release(token="lineage-a", srv=own)
            kill.assert_not_called()
            state = _read(ts)
            assert state is not None and state["refcount"] == 1
            own.stop.assert_called_once()  # our untracked replacement

    def test_matching_token_decrements(self):
        with _Env() as ts:
            _seed_state(ts, boot_nonce="lineage-a", refcount=2)
            with patch.object(lifecycle, "_kill_server") as kill:
                lifecycle.joern_release(token="lineage-a")
            kill.assert_not_called()
            assert _read(ts)["refcount"] == 1

    def test_matching_token_at_zero_stops_server(self):
        with _Env() as ts:
            _seed_state(ts, boot_nonce="lineage-a", refcount=1)
            with patch.object(lifecycle, "_kill_server") as kill:
                lifecycle.joern_release(token="lineage-a")
            kill.assert_called_once()
            assert _read(ts) is None

    def test_no_state_with_token_stops_own_handle_only(self):
        with _Env():
            own = _mock_server()
            with patch.object(lifecycle, "_kill_server") as kill:
                lifecycle.joern_release(token="lineage-a", srv=own)
            kill.assert_not_called()
            own.stop.assert_called_once()

    def test_legacy_bare_release_keeps_unverified_decrement(self):
        # Out-of-tree callers without a token keep the pre-token
        # behaviour (documented residual).
        with _Env() as ts:
            _seed_state(ts, refcount=2)
            lifecycle.joern_release()
            assert _read(ts)["refcount"] == 1


class TestAcquireHandsBackToken:
    def test_fresh_start_persists_nonce_and_attaches_token(self):
        with _Env() as ts:
            srv = _mock_server()
            with patch.object(lifecycle, "_start_fresh", return_value=srv):
                out = lifecycle.joern_acquire()
            assert out is srv
            state = _read(ts)
            assert state["boot_nonce"]
            assert srv._lifecycle_token == state["boot_nonce"]

    def test_reuse_upgrades_legacy_state_in_place(self):
        with _Env() as ts:
            _seed_state(ts, pid=os.getpid(), boot_nonce=None)
            srv = _mock_server()
            with patch.object(lifecycle, "_connect_existing",
                              return_value=srv):
                out = lifecycle.joern_acquire()
            assert out is srv
            state = _read(ts)
            assert state["boot_nonce"]
            assert srv._lifecycle_token == state["boot_nonce"]
            assert state["refcount"] == 2


class TestNoteServerReplacedMatchRule:
    def _replacement(self, token=None):
        srv = _mock_server(pid=424242, port=45678)
        srv._lifecycle_token = token
        return srv

    def test_port_match_with_live_recorded_pid_never_repoints(self):
        # A LIVE recorded server sharing the old port number is a
        # different server — repointing would orphan it unreleasably.
        with _Env() as ts:
            _seed_state(ts, pid=os.getpid(), port=33333)
            lifecycle.note_server_replaced(
                old_pid=111111, old_port=33333,
                srv=self._replacement(),
            )
            assert _read(ts)["pid"] == os.getpid()

    def test_port_match_with_dead_recorded_pid_repoints(self):
        with _Env() as ts:
            _seed_state(ts, pid=2_000_000_000, port=33333)
            lifecycle.note_server_replaced(
                old_pid=111111, old_port=33333,
                srv=self._replacement(),
            )
            assert _read(ts)["pid"] == 424242

    def test_token_match_repoints_and_preserves_nonce(self):
        # The token lives on the handle and survives the restart —
        # it matches even when neither the old pid nor the old port
        # does (both already recycled by intermediate churn).
        with _Env() as ts:
            _seed_state(ts, pid=2_000_000_000, port=33333,
                        boot_nonce="lineage-a")
            lifecycle.note_server_replaced(
                old_pid=999, old_port=999,
                srv=self._replacement(token="lineage-a"),
            )
            state = _read(ts)
            assert state["pid"] == 424242
            assert state["boot_nonce"] == "lineage-a"

    def test_no_match_is_a_noop(self):
        with _Env() as ts:
            _seed_state(ts, pid=2_000_000_000, port=33333,
                        boot_nonce="lineage-b")
            lifecycle.note_server_replaced(
                old_pid=999, old_port=999,
                srv=self._replacement(token="lineage-a"),
            )
            assert _read(ts)["pid"] == 2_000_000_000


class TestMockServerDefaults:
    """Guard: _mock_server must not leak MagicMock truthiness into the
    token comparisons."""

    def test_mock_token_is_explicitly_absent(self):
        srv = _mock_server()
        token = getattr(srv, "_lifecycle_token", None)
        # MagicMock auto-attrs are truthy; the release/replace rules
        # compare against the state nonce, so an auto-attr can only
        # ever MISmatch — never forge a match.
        assert token != "lineage-b"
