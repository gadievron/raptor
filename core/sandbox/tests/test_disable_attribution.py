"""Bare-run attribution for the accepted CLI sandbox disable.

A run that executed with ``--sandbox none`` / ``--no-sandbox`` in
force produces no denials and no posture record — without dedicated
plumbing its sandbox-summary would simply not exist and downstream
readers could not tell "clean sandboxed run" from "ran unsandboxed".
Pinned here:

* parent memory — ``record_cli_disable`` / ``get_cli_disable`` are
  keyed per run dir, so a cross-process sweep of ANOTHER run's
  leftovers never inherits this process's disable state.
* summary — a disabled run with ZERO denials still writes
  ``sandbox-summary.json`` carrying ``cli_sandbox_disabled`` +
  ``disable_consent``; both fields are MAC-bound (strip or rewrite
  either → tampered on the verifying triage path).
* display reader — ``read_cli_disable_annotation`` is the
  display-tier read-back: escaped, bounded, best-effort.
* context wiring — a real disabled ``sandbox()`` call with an output
  dir lands the parent-memory record end-to-end.
* operator CLI — ``raptor-verified-outcomes`` human render carries
  the run-context line; the ``--json`` shape stays annotation-free.
"""

import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from core.sandbox import summary as summary_mod
from core.sandbox import triage as triage_mod

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path,
                    monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(summary_mod, "_cli_disables", {})
    monkeypatch.setattr(summary_mod, "_run_postures", {})
    monkeypatch.setattr(summary_mod, "_floor_refusals", {})
    summary_mod.set_active_run_dir(None)
    yield
    summary_mod.set_active_run_dir(None)


def _write_real_denial_summary(run_dir: Path) -> dict[str, Any] | None:
    """Produce a genuinely-stamped denial summary via the writer API."""
    summary_mod.set_active_run_dir(run_dir)
    try:
        summary_mod.record_denial(
            "cat /root/.ssh/id_rsa", 1, "write", path="/root/.ssh/id_rsa")
        return summary_mod.summarize_and_write(run_dir)
    finally:
        summary_mod.set_active_run_dir(None)


class TestParentMemory:
    def test_roundtrip(self, tmp_path):
        summary_mod.record_cli_disable(tmp_path, "interactive-tty")
        assert summary_mod.get_cli_disable(tmp_path) == "interactive-tty"

    def test_unknown_run_is_none(self, tmp_path):
        assert summary_mod.get_cli_disable(tmp_path) is None

    def test_keyed_per_run_dir_not_process_global(self, tmp_path):
        """The whole point of the per-dir keying: a record for run A
        must not attribute run B (a sweep finalising another run's
        leftovers would otherwise stamp it with this process's
        disable)."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        summary_mod.record_cli_disable(a, "nonce")
        assert summary_mod.get_cli_disable(a) == "nonce"
        assert summary_mod.get_cli_disable(b) is None

    def test_first_writer_wins(self, tmp_path):
        summary_mod.record_cli_disable(tmp_path, "interactive-tty")
        summary_mod.record_cli_disable(tmp_path, "nonce")
        assert summary_mod.get_cli_disable(tmp_path) == "interactive-tty"


class TestSummaryAnnotation:
    def test_zero_denial_disabled_run_writes_annotated_summary(
            self, tmp_path):
        """The load-bearing case: no denials JSONL exists (nothing was
        enforced), yet the summary must still be written so the bare
        run is attributable after the fact."""
        summary_mod.record_cli_disable(tmp_path, "interactive-tty")
        written = summary_mod.summarize_and_write(tmp_path)
        assert written is not None
        assert written["total_denials"] == 0
        assert written["cli_sandbox_disabled"] is True
        assert written["disable_consent"] == "interactive-tty"
        on_disk = json.loads(
            (tmp_path / summary_mod.SUMMARY_FILE).read_text())
        assert on_disk["cli_sandbox_disabled"] is True
        assert on_disk["disable_consent"] == "interactive-tty"

    def test_no_disable_zero_denials_still_writes_nothing(self, tmp_path):
        """Pre-existing contract preserved: an ordinary evidence-free
        run produces no summary file."""
        assert summary_mod.summarize_and_write(tmp_path) is None
        assert not (tmp_path / summary_mod.SUMMARY_FILE).exists()

    def test_sweep_of_other_dir_stays_silent(self, tmp_path):
        """A disable recorded for run A must not leak into a
        summarisation of run B."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        summary_mod.record_cli_disable(a, "nonce")
        assert summary_mod.summarize_and_write(b) is None
        assert not (b / summary_mod.SUMMARY_FILE).exists()

    def test_annotation_joins_denial_summary(self, tmp_path):
        summary_mod.record_cli_disable(tmp_path, "nonce")
        written = _write_real_denial_summary(tmp_path)
        assert written["total_denials"] == 1
        assert written["cli_sandbox_disabled"] is True
        assert written["disable_consent"] == "nonce"

    def test_annotated_summary_verifies(self, tmp_path):
        summary_mod.record_cli_disable(tmp_path, "interactive-tty")
        summary_mod.summarize_and_write(tmp_path)
        summary_mod._cli_disables.clear()  # fresh-process view
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert (result["inputs"]["integrity"]["sandbox_summary"]
                == "verified")

    def _tamper(self, tmp_path: Path,
                mutate: Callable[[dict[str, Any]], None],
                ) -> dict[str, Any] | None:
        summary_mod.record_cli_disable(tmp_path, "interactive-tty")
        summary_mod.summarize_and_write(tmp_path)
        path = tmp_path / summary_mod.SUMMARY_FILE
        payload = json.loads(path.read_text())
        mutate(payload)
        path.write_text(json.dumps(payload))
        summary_mod._cli_disables.clear()
        return triage_mod.triage_run(tmp_path)

    def test_stripping_flag_breaks_the_token(self, tmp_path):
        result = self._tamper(
            tmp_path, lambda p: p.pop("cli_sandbox_disabled"))
        assert (result["inputs"]["integrity"]["sandbox_summary"]
                == "tampered")

    def test_stripping_consent_breaks_the_token(self, tmp_path):
        result = self._tamper(
            tmp_path, lambda p: p.pop("disable_consent"))
        assert (result["inputs"]["integrity"]["sandbox_summary"]
                == "tampered")

    def test_rewriting_consent_breaks_the_token(self, tmp_path):
        result = self._tamper(
            tmp_path,
            lambda p: p.__setitem__("disable_consent", "nonce"))
        assert (result["inputs"]["integrity"]["sandbox_summary"]
                == "tampered")

    def test_stripping_both_breaks_the_token(self, tmp_path):
        def _strip(p: dict[str, Any]) -> None:
            p.pop("cli_sandbox_disabled")
            p.pop("disable_consent")
        result = self._tamper(tmp_path, _strip)
        assert (result["inputs"]["integrity"]["sandbox_summary"]
                == "tampered")


class TestDisplayReader:
    def _plant(self, run_dir: Path, payload: dict[str, Any]) -> None:
        (run_dir / summary_mod.SUMMARY_FILE).write_text(
            json.dumps(payload))

    def test_reads_back_the_real_writer(self, tmp_path):
        summary_mod.record_cli_disable(tmp_path, "interactive-tty")
        summary_mod.summarize_and_write(tmp_path)
        assert (summary_mod.read_cli_disable_annotation(tmp_path)
                == "interactive-tty")

    def test_no_summary_is_none(self, tmp_path):
        assert summary_mod.read_cli_disable_annotation(tmp_path) is None

    def test_plain_denial_summary_is_none(self, tmp_path):
        _write_real_denial_summary(tmp_path)
        assert summary_mod.read_cli_disable_annotation(tmp_path) is None

    def test_missing_consent_reads_unrecorded(self, tmp_path):
        self._plant(tmp_path, {"cli_sandbox_disabled": True})
        assert (summary_mod.read_cli_disable_annotation(tmp_path)
                == "unrecorded")

    def test_malformed_summary_is_none(self, tmp_path):
        (tmp_path / summary_mod.SUMMARY_FILE).write_text("{not json")
        assert summary_mod.read_cli_disable_annotation(tmp_path) is None

    def test_planted_control_bytes_are_escaped(self, tmp_path):
        """The field sits in the target-writable run dir: a planted
        OSC sequence must come back escaped, never raw."""
        self._plant(tmp_path, {
            "cli_sandbox_disabled": True,
            "disable_consent": "pwn\x1b]0;evil\x07",
        })
        label = summary_mod.read_cli_disable_annotation(tmp_path)
        assert label is not None
        assert "\x1b" not in label
        assert "\\x1b" in label

    def test_planted_long_label_is_bounded(self, tmp_path):
        self._plant(tmp_path, {
            "cli_sandbox_disabled": True,
            "disable_consent": "A" * 500,
        })
        label = summary_mod.read_cli_disable_annotation(tmp_path)
        assert label is not None
        assert len(label) <= summary_mod._DISABLE_CONSENT_DISPLAY_MAX

    def test_display_bound_pinned(self):
        """Literal pin (both directions): smaller would truncate none
        of the three legit labels but is pointless churn; larger
        re-opens room for terminal-injection payloads the bound
        exists to cut."""
        assert summary_mod._DISABLE_CONSENT_DISPLAY_MAX == 64


class TestWiring:
    def test_run_activation_records_the_disable(
            self, tmp_path, no_sandbox_consent):
        """Lifecycle anchor: the 'none' profile sheds per-call
        output= by design, so the run-activation seam is what
        attributes a lifecycle run — end-to-end through the real
        gate (set_cli_profile) and the real finalisation."""
        from core.sandbox import set_cli_profile
        set_cli_profile("none")
        out = tmp_path / "out"
        out.mkdir()
        summary_mod.set_active_run_dir(out)
        try:
            assert summary_mod.get_cli_disable(out) == "nonce"
        finally:
            summary_mod.set_active_run_dir(None)
        written = summary_mod.summarize_and_write(out)
        assert written is not None
        assert written["cli_sandbox_disabled"] is True
        assert written["disable_consent"] == "nonce"

    def test_run_activation_without_disable_records_nothing(
            self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        try:
            assert summary_mod.get_cli_disable(tmp_path) is None
        finally:
            summary_mod.set_active_run_dir(None)

    def test_disabled_call_with_audit_run_dir_records(
            self, tmp_path, no_sandbox_consent):
        """Per-call anchor: audit_run_dir survives the 'none'
        profile's kwarg shedding, so a disabled sandbox() call that
        carries one records the disable against it in the epilogue."""
        from core.sandbox import sandbox, set_cli_profile
        set_cli_profile("none")
        out = tmp_path / "audit"
        out.mkdir()
        with sandbox(profile="full", audit_run_dir=str(out)) as run:
            result = run(["echo", "ok"], capture_output=True, text=True)
        assert result.returncode == 0
        assert summary_mod.get_cli_disable(out) == "nonce"


class TestVerifiedOutcomesCli:
    """Run-context annotation on the operator CLI. The planted (no
    MAC) summaries are deliberate: the annotation is a display-tier
    read (see ``read_cli_disable_annotation``'s trust note)."""

    SHIM = REPO_ROOT / "libexec" / "raptor-verified-outcomes"

    def _run(self, run_dir: Path,
             *extra: str) -> "subprocess.CompletedProcess[str]":
        env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
        return subprocess.run(
            [sys.executable, str(self.SHIM), str(run_dir), *extra],
            capture_output=True, text=True, timeout=60, env=env,
        )

    @pytest.fixture()
    def annotated_run_dir(self, tmp_path: Path) -> Path:
        (tmp_path / summary_mod.SUMMARY_FILE).write_text(json.dumps({
            "cli_sandbox_disabled": True,
            "disable_consent": "interactive-tty",
        }))
        return tmp_path

    def test_human_render_carries_run_context_line(
            self, annotated_run_dir):
        out = self._run(annotated_run_dir)
        assert out.returncode == 0, out.stderr
        assert "run context: sandbox DISABLED" in out.stdout
        assert "consent: interactive-tty" in out.stdout

    def test_clean_run_dir_has_no_run_context_line(self, tmp_path):
        out = self._run(tmp_path)
        assert out.returncode == 0, out.stderr
        assert "run context" not in out.stdout

    def test_json_shape_stays_annotation_free(self, annotated_run_dir):
        out = self._run(annotated_run_dir, "--json")
        assert out.returncode == 0, out.stderr
        assert "run context" not in out.stdout
        assert isinstance(json.loads(out.stdout), list)

    def test_hostile_label_never_reaches_the_terminal_raw(
            self, tmp_path):
        (tmp_path / summary_mod.SUMMARY_FILE).write_text(json.dumps({
            "cli_sandbox_disabled": True,
            "disable_consent": "pwn\x1b]0;evil\x07",
        }))
        out = self._run(tmp_path)
        assert out.returncode == 0, out.stderr
        assert "run context: sandbox DISABLED" in out.stdout
        assert "\x1b" not in out.stdout
