"""Tests for ``core.llm.dispatcher.lifecycle``.

Confirms:
  * ``dispatcher_for_run`` derives ``run_id`` from the run dir basename.
  * Audit log lands at ``<run_dir>/audit-llm-dispatcher.jsonl``.
  * Context-manager shuts the dispatcher down on normal + exceptional exits.
  * Missing run_dir raises early (rather than silently writing audit
    to a nonexistent path and losing entries).
"""

from __future__ import annotations

import os
import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.lifecycle import (
    _AUDIT_FILENAME,
    dispatcher_for_run,
    llm_dispatcher_in_run,
)


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {"anthropic": "fake-key", "openai": None, "gemini": None}
    return creds


class TestDispatcherForRun:

    def test_audit_path_is_inside_run_dir(self, fake_creds, tmp_path):
        run_dir = tmp_path / "run_20260507_120000"
        run_dir.mkdir()
        d = dispatcher_for_run(run_dir, creds=fake_creds)
        try:
            assert d._audit_path == run_dir / _AUDIT_FILENAME
            # An event is written immediately on start, so the file
            # must already exist.
            assert (run_dir / _AUDIT_FILENAME).exists()
        finally:
            d.shutdown()

    def test_run_id_matches_run_dir_name(self, fake_creds, tmp_path):
        run_dir = tmp_path / "scan_alpha"
        run_dir.mkdir()
        d = dispatcher_for_run(run_dir, creds=fake_creds)
        try:
            assert d.run_id == "scan_alpha"
        finally:
            d.shutdown()

    def test_missing_run_dir_raises(self, fake_creds, tmp_path):
        run_dir = tmp_path / "does-not-exist"
        with pytest.raises(FileNotFoundError):
            dispatcher_for_run(run_dir, creds=fake_creds)

    def test_kwargs_flow_through_to_dispatcher(self, fake_creds, tmp_path):
        run_dir = tmp_path / "tuned"
        run_dir.mkdir()
        d = dispatcher_for_run(
            run_dir, creds=fake_creds,
            token_ttl_s=1234, token_budget=42,
        )
        try:
            assert d._token_ttl_s == 1234
            assert d._token_budget == 42
        finally:
            d.shutdown()


class TestLlmDispatcherInRun:

    def test_normal_exit_shuts_down(self, fake_creds, tmp_path):
        run_dir = tmp_path / "ctx_normal"
        run_dir.mkdir()
        with llm_dispatcher_in_run(run_dir, creds=fake_creds) as d:
            sock_dir = d._sock_dir
            assert sock_dir.exists()
        # After context exit, socket dir is gone
        assert not sock_dir.exists()

    def test_exception_still_shuts_down(self, fake_creds, tmp_path):
        run_dir = tmp_path / "ctx_excpt"
        run_dir.mkdir()
        sock_dir_holder = {}
        with pytest.raises(RuntimeError):
            with llm_dispatcher_in_run(run_dir, creds=fake_creds) as d:
                sock_dir_holder["path"] = d._sock_dir
                raise RuntimeError("boom")
        assert not sock_dir_holder["path"].exists()
