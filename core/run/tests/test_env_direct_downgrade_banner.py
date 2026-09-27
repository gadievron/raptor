"""Tests for raptor.py's env-direct credential-fallback posture.

When the credential-isolating LLM dispatcher cannot start, raptor.py
deliberately KEEPS the env-direct fallback (dispatcher-down
resilience) — but the downgrade must be loud: one prominent stderr
banner naming the isolation downgrade and why the dispatcher is
unavailable, plus a durable ``credential-posture.json`` record in the
run's output directory. Credential VALUES never appear in either.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_raptor():
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor
    return raptor


# ---------------------------------------------------------------------------
# _announce_env_direct_downgrade
# ---------------------------------------------------------------------------


class TestAnnounce:
    def test_banner_names_downgrade_and_reason(self, monkeypatch, capsys):
        raptor = _import_raptor()
        monkeypatch.setattr(
            raptor, "_dispatcher_failure_reason",
            "RuntimeError: socket dir not writable",
        )
        raptor._announce_env_direct_downgrade("scanner.py", None)
        err = capsys.readouterr().err
        assert "CREDENTIAL-ISOLATION DOWNGRADE" in err
        assert "env-direct" in err
        assert "scanner.py" in err
        assert "RuntimeError: socket dir not writable" in err

    def test_record_written_to_out_dir(self, monkeypatch, capsys,
                                       tmp_path):
        raptor = _import_raptor()
        monkeypatch.setattr(
            raptor, "_dispatcher_failure_reason",
            "OSError: boom",
        )
        raptor._announce_env_direct_downgrade("scanner.py", tmp_path)
        record = json.loads(
            (tmp_path / "credential-posture.json").read_text(),
        )
        assert record["posture"] == "env_direct_fallback"
        assert record["credential_isolation"] == "downgraded"
        assert record["reason"] == "OSError: boom"
        assert record["script"] == "scanner.py"
        assert record["timestamp"]

    def test_no_recorded_reason_still_announces(self, monkeypatch,
                                                capsys):
        """A dispatcher that was never attempted (reason global unset)
        must not crash the banner — it states no failure was
        recorded."""
        raptor = _import_raptor()
        monkeypatch.setattr(raptor, "_dispatcher_failure_reason", None)
        raptor._announce_env_direct_downgrade("scanner.py", None)
        err = capsys.readouterr().err
        assert "CREDENTIAL-ISOLATION DOWNGRADE" in err
        assert "no failure recorded" in err

    def test_hostile_reason_text_is_terminal_inert(self, monkeypatch,
                                                   capsys):
        """The reason quotes exception text, which can carry bytes
        from config files or the environment — escapes must be
        neutralised before the TTY sees them."""
        raptor = _import_raptor()
        monkeypatch.setattr(
            raptor, "_dispatcher_failure_reason",
            "ValueError: \x1b]0;pwned\x07 bad config",
        )
        raptor._announce_env_direct_downgrade("scanner.py", None)
        err = capsys.readouterr().err
        assert "\x1b" not in err and "\x07" not in err
        assert "bad config" in err

    def test_record_write_failure_never_raises(self, monkeypatch,
                                               capsys, tmp_path):
        raptor = _import_raptor()
        monkeypatch.setattr(
            raptor, "_dispatcher_failure_reason", "OSError: x",
        )
        missing = tmp_path / "not" / "a" / "dir"
        raptor._announce_env_direct_downgrade("s.py", missing)
        # Banner still printed; no exception.
        assert "CREDENTIAL-ISOLATION DOWNGRADE" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# _run_script wiring
# ---------------------------------------------------------------------------


class TestRunScriptFallback:
    def test_fallback_announces_and_records(self, monkeypatch, capsys,
                                            tmp_path):
        """dispatcher=None → the env-direct branch prints the banner
        and drops credential-posture.json into the run dir, and the
        child still runs (fallback preserved)."""
        raptor = _import_raptor()
        monkeypatch.setattr(
            raptor, "_dispatcher_failure_reason",
            "RuntimeError: no socket",
        )
        ran: dict = {}

        def fake_run(cmd, **kwargs):
            ran["cmd"] = cmd
            return SimpleNamespace(returncode=7)

        with patch.object(raptor, "_get_or_start_dispatcher",
                          return_value=None), \
             patch.object(raptor.subprocess, "run", fake_run):
            rc = raptor._run_script(
                Path("scanner.py"), ["--repo", "/x"], out_dir=tmp_path,
            )

        assert rc == 7                       # fallback still runs
        assert ran["cmd"][-2:] == ["--repo", "/x"]
        err = capsys.readouterr().err
        assert "CREDENTIAL-ISOLATION DOWNGRADE" in err
        assert "RuntimeError: no socket" in err
        record = json.loads(
            (tmp_path / "credential-posture.json").read_text(),
        )
        assert record["posture"] == "env_direct_fallback"

    def test_dispatcher_path_stays_silent(self, monkeypatch, capsys,
                                          tmp_path):
        """Two-direction: with a live dispatcher there is no banner
        and no posture record — the downgrade machinery must not fire
        on the isolated path."""
        raptor = _import_raptor()

        class _Proc:
            def wait(self) -> int:
                return 0

        with patch.object(raptor, "_get_or_start_dispatcher",
                          return_value=object()), \
             patch("core.llm.dispatcher.spawn.spawn_worker",
                   return_value=_Proc()):
            rc = raptor._run_script(
                Path("scanner.py"), ["--repo", "/x"], out_dir=tmp_path,
            )

        assert rc == 0
        err = capsys.readouterr().err
        assert "CREDENTIAL-ISOLATION DOWNGRADE" not in err
        assert not (tmp_path / "credential-posture.json").exists()


# ---------------------------------------------------------------------------
# out_dir pass-through on the lifecycle-less _run_script call sites
# ---------------------------------------------------------------------------


class TestOutDirPassthrough:
    """The analyze and standalone-fuzz paths run OUTSIDE the run
    lifecycle, so ``_run_script`` only learns the run directory if the
    call site peeks the operator's ``--out`` itself — otherwise an
    env-direct fallback banners without its durable
    ``credential-posture.json`` record."""

    def _capture_run_script(self, raptor):
        calls: dict = {}

        def fake(script_path, args, out_dir=None):
            calls["args"] = list(args)
            calls["out_dir"] = out_dir
            return 0

        return calls, fake

    def test_analyze_peeks_out_for_posture_record(self, tmp_path):
        raptor = _import_raptor()
        calls, fake = self._capture_run_script(raptor)
        with patch.object(raptor, "_run_script", fake):
            rc = raptor.mode_llm_analysis(
                ["--repo", "/nonexistent-repo", "--out", str(tmp_path)],
            )
        assert rc == 0
        assert calls["out_dir"] == tmp_path
        # Peek, not strip: the child still receives --out to parse.
        assert "--out" in calls["args"]
        assert str(tmp_path) in calls["args"]

    def test_standalone_fuzz_peeks_out_for_posture_record(self,
                                                          tmp_path):
        raptor = _import_raptor()
        calls, fake = self._capture_run_script(raptor)
        with patch.object(raptor, "_run_script", fake):
            rc = raptor.mode_fuzz(
                ["--export-seed-corpus", "http",
                 "--out", str(tmp_path)],
            )
        assert rc == 0
        assert calls["out_dir"] == tmp_path
        assert "--out" in calls["args"]

    def test_no_out_flag_passes_none(self, tmp_path):
        raptor = _import_raptor()
        calls, fake = self._capture_run_script(raptor)
        with patch.object(raptor, "_run_script", fake):
            rc = raptor.mode_llm_analysis(["--repo", "/nonexistent-repo"])
        assert rc == 0
        assert calls["out_dir"] is None


# ---------------------------------------------------------------------------
# _get_or_start_dispatcher failure capture
# ---------------------------------------------------------------------------


class TestFailureReasonCapture:
    def test_startup_failure_captures_reason(self, monkeypatch):
        raptor = _import_raptor()
        monkeypatch.setattr(raptor, "_active_dispatcher", None)
        monkeypatch.setattr(raptor, "_dispatcher_failure_reason", None)

        def boom():
            raise RuntimeError("store exploded")

        with patch("core.llm.dispatcher.auth.CredentialStore",
                   side_effect=boom):
            result = raptor._get_or_start_dispatcher()

        assert result is None
        assert raptor._dispatcher_failure_reason is not None
        assert "RuntimeError" in raptor._dispatcher_failure_reason
        assert "store exploded" in raptor._dispatcher_failure_reason
