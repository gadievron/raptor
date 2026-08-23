"""Tests for core.sandbox.observe_cli.

Three layers:
  1. Argparse construction + dispatch — pure-Python, no spawn.
  2. Output rendering (summary / JSON) — synthetic ObserveProfile.
  3. End-to-end: real subprocess via shim. Linux-only because the
     observe stack relies on ptrace/seccomp.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from core.sandbox import state
from core.sandbox.observe_cli import (
    _build_parser,
    _cli_main,
    _format_summary,
    _profile_to_json,
)
from core.sandbox.observe_profile import ConnectTarget, ObserveProfile


def _materialise_observe_log(run_dir) -> None:
    """Write a minimal observe log at the CANONICAL parent-owned
    location (``<run_dir>/.audit/``) — where the real tracer writes.
    A nonce-less CLI parse (degraded audit) refuses the legacy
    run-root location, so stubs must materialise the canonical one."""
    d = Path(run_dir) / ".audit"
    d.mkdir(mode=0o700, exist_ok=True)
    (d / ".sandbox-observe.jsonl").write_text("{}\n")


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


class TestArgparse:

    def test_no_cmd_errors(self, capsys):
        # parser.error exits with code 2 (argparse default)
        with pytest.raises(SystemExit) as exc:
            _cli_main([])
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert "no command" in captured.err

    def test_help_does_not_import_sandbox(self, capsys):
        # `--help` runs before any sandbox imports — verifies the
        # lazy-import contract documented in observe_cli.
        before = sys.modules.get("core.sandbox.context")
        with pytest.raises(SystemExit) as exc:
            _cli_main(["--help"])
        # argparse exits 0 on --help.
        assert exc.value.code == 0
        # If sandbox.context wasn't already loaded, --help must not
        # have loaded it. (When the test suite has already imported
        # it, this assertion is a no-op — the contract is "don't add
        # NEW imports", not "module is unloaded".)
        if before is None:
            assert "core.sandbox.context" not in sys.modules

    def test_double_dash_separator_stripped(self, monkeypatch):
        # Ensure cmd parsing strips a leading "--" so a downstream
        # spawn doesn't see it as an arg to the probed binary.
        seen_cmd = []

        def fake_run(cmd, **kwargs):
            seen_cmd.append(list(cmd))
            class _R:
                returncode = 0
            return _R()

        # Monkeypatch sandbox import path. Lazy-imported, so we patch
        # at the module level.
        # Force the parser to consume "--" then the cmd.
        # We won't actually spawn — fake_run + abort via early return
        # by saying observe log doesn't exist.
        with patch("core.sandbox.run", side_effect=fake_run), \
             patch("core.sandbox.parse_observe_log") as _parse:
            _cli_main(["--", "/usr/bin/true", "x"])
        # The spawn failed (no observe log), so rc is _SOFTWARE_EX.
        assert seen_cmd == [["/usr/bin/true", "x"]]


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------


def _sample_profile() -> ObserveProfile:
    return ObserveProfile(
        paths_read=["/lib/libc.so.6", "/etc/ld.so.cache",
                    "/etc/passwd"],
        paths_written=["/tmp/scratch"],
        paths_stat=["/etc/ld.so.preload"],
        connect_targets=[
            ConnectTarget(ip="1.2.3.4", port=443, family="AF_INET"),
        ],
    )


class TestFormatSummary:

    def test_summary_contains_all_sections(self, tmp_path):
        out = _format_summary(
            _sample_profile(), run_dir=tmp_path, kept=False,
            return_code=0,
        )
        assert "command exit code: 0" in out
        assert "paths read (3):" in out
        assert "/lib/libc.so.6" in out
        assert "paths written (1):" in out
        assert "/tmp/scratch" in out
        assert "paths stat'd" in out
        assert "/etc/ld.so.preload" in out
        assert "connect targets (1):" in out
        assert "1.2.3.4:443 (AF_INET)" in out

    def test_summary_truncates_long_lists(self, tmp_path):
        prof = ObserveProfile(
            paths_read=[f"/p/{i}" for i in range(25)],
        )
        out = _format_summary(prof, run_dir=tmp_path, kept=False,
                              return_code=0)
        # First 10 + truncation note.
        assert "/p/0" in out
        assert "/p/9" in out
        assert "+15 more" in out
        # 11th entry should NOT appear in the human summary.
        assert "/p/10" not in out

    def test_summary_kept_run_dir_shown(self, tmp_path):
        out = _format_summary(_sample_profile(), run_dir=tmp_path,
                              kept=True, return_code=0)
        assert f"audit-run-dir kept at: {tmp_path}" in out

    def test_summary_sanitises_attacker_chosen_strings(self, tmp_path):
        """Every path / connect target / drop category in the profile
        is attacker-chosen (the probed binary picked what to touch) —
        the summary is operator-terminal output and must route them
        through the credential-banner sanitiser: ascii alone keeps
        ESC/CR/BEL, so a crafted filename could inject terminal
        control sequences (title-set, cursor games, screen clear)
        into the operator's terminal."""
        evil = "\x1b]0;pwned\x07/etc/passwd\rCLEAN"
        prof = ObserveProfile(
            paths_read=[evil],
            paths_written=["\x1b[2J/tmp/x"],
            paths_stat=["/ok\x07bel"],
            connect_targets=[
                ConnectTarget(ip="\x1b[31m1.2.3.4", port=443,
                              family="AF\x1bINET"),
            ],
            budget_truncated=True,
            dropped_by_category={"file-read\x1b[0m": 3},
        )
        out = _format_summary(prof, run_dir=tmp_path, kept=False,
                              return_code=0)
        for ch, name in ((chr(0x1B), "ESC"), ("\r", "CR"),
                         ("\x07", "BEL")):
            assert ch not in out, (
                f"raw {name} reached the operator terminal via the "
                f"observe summary"
            )
        # The content itself survives, escaped and readable.
        assert "/etc/passwd" in out
        assert "1.2.3.4" in out

    def test_summary_bounds_pathological_path_length(self, tmp_path):
        """A 100KB 'path' must not flood the terminal — the sanitiser
        truncates with an explicit elision marker."""
        prof = ObserveProfile(paths_read=["/" + "A" * 100_000])
        out = _format_summary(prof, run_dir=tmp_path, kept=False,
                              return_code=0)
        assert len(out) < 10_000
        assert "chars]" in out  # elision marker

    def test_summary_empty_profile_communicates_clearly(self, tmp_path):
        out = _format_summary(ObserveProfile(), run_dir=tmp_path,
                              kept=False, return_code=0)
        assert "(none — binary did no reads)" in out
        assert "(none — binary did no writes)" in out
        assert "(none — binary did no stats)" in out
        assert "(none — binary made no connect" in out


class TestJsonOutput:

    def test_json_round_trip(self, tmp_path):
        s = _profile_to_json(_sample_profile(), run_dir=tmp_path,
                             kept=True, return_code=42)
        payload = json.loads(s)
        assert payload["return_code"] == 42
        assert payload["run_dir"] == str(tmp_path)
        assert payload["paths_read"][0] == "/lib/libc.so.6"
        assert payload["connect_targets"][0] == {
            "ip": "1.2.3.4", "port": 443, "family": "AF_INET",
        }

    def test_json_kept_false_run_dir_null(self, tmp_path):
        s = _profile_to_json(_sample_profile(), run_dir=tmp_path,
                             kept=False, return_code=0)
        payload = json.loads(s)
        assert payload["run_dir"] is None


# ---------------------------------------------------------------------------
# Degraded-audit trust
# ---------------------------------------------------------------------------


class TestDegradedAuditTrust:
    """When audit degrades the run yields no observe nonce; the CLI
    must not fall back to the target-writable run-root log (a probed
    binary can plant a forged profile there) and must surface the
    unauthenticated state on whatever it does parse."""

    def test_planted_legacy_log_refused_without_nonce(self, tmp_path):
        """The attack shape: audit degraded (no nonce, no .audit log)
        and the probed binary planted a forged legacy run-root log.
        Pre-fix the CLI parsed it as the run's profile; now it must
        report the degraded run (exit 70) and name the untrusted
        planted file."""

        class _Result:
            returncode = 0
            sandbox_info: dict = {}   # degraded — no observe_nonce

        def fake_run(cmd, **kwargs):
            run_dir = Path(kwargs["output"])
            # Forged log at the target-writable legacy location ONLY.
            (run_dir / ".sandbox-observe.jsonl").write_text(
                json.dumps({"syscall": "openat", "observe": True,
                            "path": "/forged", "args": [0] * 6}) + "\n"
            )
            return _Result()

        buf_out, buf_err = io.StringIO(), io.StringIO()
        with patch("core.sandbox.run", side_effect=fake_run), \
             patch("sys.stdout", buf_out), patch("sys.stderr", buf_err):
            rc = _cli_main(["--out", str(tmp_path), "--",
                            "/usr/bin/true"])
        assert rc == 70, (
            f"degraded run with only a planted legacy log must exit "
            f"70, got {rc}; stdout={buf_out.getvalue()!r}")
        assert "NOT trusted" in buf_err.getvalue()
        assert "/forged" not in buf_out.getvalue()

    def test_parser_called_with_current_run_flag(self, tmp_path):
        """The CLI is always a current-run consumer — it must pass
        current_run=True so nonce-less parses demote and refuse the
        legacy location inside the parser too."""
        seen = {}

        class _Result:
            returncode = 0
            sandbox_info = {"observe_nonce": "n-42"}

        def fake_run(cmd, **kwargs):
            _materialise_observe_log(kwargs["output"])
            return _Result()

        def fake_parse(run_dir, **kwargs):
            seen.update(kwargs)
            return ObserveProfile()

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch("core.sandbox.parse_observe_log",
                   side_effect=fake_parse), \
             patch("sys.stdout", io.StringIO()), \
             patch("sys.stderr", io.StringIO()):
            rc = _cli_main(["--out", str(tmp_path), "--",
                            "/usr/bin/true"])
        assert rc == 0
        assert seen.get("current_run") is True
        assert seen.get("expected_nonce") == "n-42"

    def test_unauthenticated_profile_flagged_in_summary(self, tmp_path):
        prof = ObserveProfile(paths_read=["/x"], nonce_trusted=False)
        out = _format_summary(prof, run_dir=tmp_path, kept=False,
                              return_code=0)
        assert "UNAUTHENTICATED" in out

    def test_authenticated_profile_not_flagged(self, tmp_path):
        out = _format_summary(_sample_profile(), run_dir=tmp_path,
                              kept=False, return_code=0)
        assert "UNAUTHENTICATED" not in out

    def test_json_payload_carries_nonce_trusted(self, tmp_path):
        prof = ObserveProfile(nonce_trusted=False)
        payload = json.loads(_profile_to_json(
            prof, run_dir=tmp_path, kept=False, return_code=0))
        assert payload["nonce_trusted"] is False
        payload = json.loads(_profile_to_json(
            _sample_profile(), run_dir=tmp_path, kept=False,
            return_code=0))
        assert payload["nonce_trusted"] is True


# ---------------------------------------------------------------------------
# CLI dispatch — sandbox stubbed out
# ---------------------------------------------------------------------------


class TestCliDispatch:
    """Check the spawn/parse plumbing without actually spawning a
    sandbox. Mocks `core.sandbox.run` + `core.sandbox.parse_observe_log`
    and verifies argv → stdout, exit codes."""

    def _run_with_stubs(self, argv, *, profile, return_code,
                        observe_log_exists=True):

        class _Result:
            def __init__(self, rc): self.returncode = rc

        def fake_run(cmd, **kwargs):
            # Materialise the observe log file so the existence
            # check downstream of run() passes (or doesn't, per
            # observe_log_exists).
            run_dir = Path(kwargs["output"])
            if observe_log_exists:
                _materialise_observe_log(run_dir)
            return _Result(return_code)

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch(
                 "core.sandbox.parse_observe_log",
                 return_value=profile,
             ):
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with patch("sys.stdout", buf_out), \
                 patch("sys.stderr", buf_err):
                rc = _cli_main(argv)
        return rc, buf_out.getvalue(), buf_err.getvalue()

    def test_returncode_forwarded(self):
        rc, _, _ = self._run_with_stubs(
            ["--", "/usr/bin/true"],
            profile=_sample_profile(), return_code=7,
        )
        assert rc == 7

    def test_summary_default_output(self):
        _, out, _ = self._run_with_stubs(
            ["--", "/usr/bin/true"],
            profile=_sample_profile(), return_code=0,
        )
        assert "paths read (3)" in out
        # Not JSON.
        assert not out.startswith("{")

    def test_json_flag_outputs_json(self):
        _, out, _ = self._run_with_stubs(
            ["--json", "--", "/usr/bin/true"],
            profile=_sample_profile(), return_code=0,
        )
        loaded = json.loads(out)
        assert "paths_read" in loaded
        assert loaded["return_code"] == 0

    def test_missing_observe_log_returns_70(self):
        rc, _, err = self._run_with_stubs(
            ["--", "/usr/bin/true"],
            profile=ObserveProfile(),
            return_code=0,
            observe_log_exists=False,
        )
        assert rc == 70
        assert "observe log not produced" in err

    def test_timeout_returns_124_with_diagnostic_not_traceback(self):
        """``--timeout`` expiry must produce a one-line diagnostic and
        exit 124 (timeout(1) convention). Pre-fix the TimeoutExpired
        escaped _cli_main as an unhandled traceback."""

        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(
                cmd=list(cmd), timeout=kwargs.get("timeout"),
            )

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch(
                 "core.sandbox.parse_observe_log",
                 return_value=_sample_profile(),
             ):
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with patch("sys.stdout", buf_out), \
                 patch("sys.stderr", buf_err):
                rc = _cli_main(
                    ["--timeout", "1", "--", "/usr/bin/sleep", "5"],
                )
        assert rc == 124
        assert "did not finish" in buf_err.getvalue()
        assert "Traceback" not in buf_err.getvalue()

    def test_timeout_renders_partial_observe_log(self):
        """Records captured before the kill are still rendered —
        a partial profile beats none — with return_code null."""

        def fake_run(cmd, **kwargs):
            run_dir = Path(kwargs["output"])
            _materialise_observe_log(run_dir)
            raise subprocess.TimeoutExpired(
                cmd=list(cmd), timeout=kwargs.get("timeout"),
            )

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch(
                 "core.sandbox.parse_observe_log",
                 return_value=_sample_profile(),
             ):
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with patch("sys.stdout", buf_out), \
                 patch("sys.stderr", buf_err):
                rc = _cli_main(
                    ["--json", "--timeout", "1",
                     "--", "/usr/bin/sleep", "5"],
                )
        assert rc == 124
        loaded = json.loads(buf_out.getvalue())
        assert loaded["return_code"] is None
        assert "paths_read" in loaded

    def test_keep_flag_preserves_run_dir(self, tmp_path):
        # --keep: even with no --out, the run_dir should survive
        # _cli_main exit. We can't easily inspect tempdir survival
        # without relying on cleanup_callbacks; assert via JSON output's
        # run_dir field instead, which reflects kept-state.
        _, out, _ = self._run_with_stubs(
            ["--keep", "--json", "--", "/usr/bin/true"],
            profile=_sample_profile(), return_code=0,
        )
        loaded = json.loads(out)
        assert loaded["run_dir"] is not None
        # The kept dir is a real mkdtemp under the system temp dir —
        # verify it survived _cli_main, then clean it up ourselves so
        # every test run doesn't strand one in /tmp.
        kept = Path(loaded["run_dir"])
        assert kept.is_dir()
        shutil.rmtree(kept)

    def test_explicit_out_dir_used(self, tmp_path):
        # --out implies kept=True.
        _, out, _ = self._run_with_stubs(
            ["--out", str(tmp_path), "--json", "--", "/usr/bin/true"],
            profile=_sample_profile(), return_code=0,
        )
        loaded = json.loads(out)
        assert loaded["run_dir"] == str(tmp_path)

    def test_json_mode_captures_probe_stdout(self):
        """``--json`` mode sets capture_output=True so the probed
        binary's stdout doesn't interleave with the JSON we emit on
        the same fd.

        Pre-fix the runner spawned ``cat /etc/hosts`` with
        capture_output=False — cat's hostname-file content went
        into the same pipe operators read JSON from, corrupting
        every downstream `jq` invocation."""
        seen = {}


        class _Result:
            def __init__(self): self.returncode = 0

        def fake_run(cmd, **kwargs):
            seen["capture_output"] = kwargs.get("capture_output")
            run_dir = Path(kwargs["output"])
            _materialise_observe_log(run_dir)
            return _Result()

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch("core.sandbox.parse_observe_log",
                   return_value=_sample_profile()):
            buf_out = io.StringIO()
            with patch("sys.stdout", buf_out):
                _cli_main(["--json", "--", "/usr/bin/true"])

        assert seen.get("capture_output") is True, (
            f"--json mode must capture probe stdout to keep the "
            f"shim's JSON output uncorrupted; got "
            f"capture_output={seen.get('capture_output')!r}"
        )

    def test_human_mode_passes_probe_stdout_through(self):
        """Human-readable mode keeps capture_output=False so an
        operator reading the summary sees the probe's output too."""
        seen = {}

        class _Result:
            def __init__(self): self.returncode = 0

        def fake_run(cmd, **kwargs):
            seen["capture_output"] = kwargs.get("capture_output")
            run_dir = Path(kwargs["output"])
            _materialise_observe_log(run_dir)
            return _Result()

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch("core.sandbox.parse_observe_log",
                   return_value=_sample_profile()):
            buf_out = io.StringIO()
            with patch("sys.stdout", buf_out):
                _cli_main(["--", "/usr/bin/true"])

        assert seen.get("capture_output") is False


class TestAuditBudgetFlag:
    """The budget-truncation summary tells the operator to re-run with
    ``--audit-budget``; the CLI's parser must actually define that
    flag, validate it like the main sandbox CLI, and plumb it into the
    budget state slot the tracer reads.

    The conftest state guard snapshots and restores
    ``state._cli_sandbox_audit_budget`` around every test.
    """

    def test_parser_accepts_flag(self):
        args = _build_parser().parse_args(
            ["--audit-budget", "5000", "--", "/usr/bin/true"],
        )
        assert args.audit_budget == 5000

    def test_hint_flag_matches_parser(self):
        # The truncation summary suggests `--audit-budget`; keep the
        # suggestion and the parser surface in lock-step.
        assert any(
            "--audit-budget" in a.option_strings
            for a in _build_parser()._actions
            if a.option_strings
        )

    def test_zero_rejected(self, capsys):
        with pytest.raises(SystemExit) as exc:
            _cli_main(["--audit-budget", "0", "--", "/usr/bin/true"])
        assert exc.value.code == 2
        assert "positive integer" in capsys.readouterr().err

    def test_typo_scale_rejected(self, capsys):
        with pytest.raises(SystemExit) as exc:
            _cli_main(
                ["--audit-budget", "100000000", "--", "/usr/bin/true"],
            )
        assert exc.value.code == 2
        assert "upper clamp" in capsys.readouterr().err

    def test_flag_propagates_to_state_slot(self):
        state._cli_sandbox_audit_budget = None

        class _Result:
            returncode = 0
            sandbox_info: dict = {}

        seen_at_spawn = []

        def fake_run(cmd, **kwargs):
            # The slot must be populated BEFORE the sandbox spawn —
            # the spawn serialises it into the tracer filter config.
            seen_at_spawn.append(state._cli_sandbox_audit_budget)
            _materialise_observe_log(kwargs["output"])
            return _Result()

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch("core.sandbox.parse_observe_log",
                   return_value=ObserveProfile()), \
             patch("sys.stdout", io.StringIO()), \
             patch("sys.stderr", io.StringIO()):
            rc = _cli_main(
                ["--audit-budget", "42", "--", "/usr/bin/true"],
            )
        assert rc == 0
        assert seen_at_spawn == [42]

    def test_no_flag_leaves_state_untouched(self):
        state._cli_sandbox_audit_budget = None

        class _Result:
            returncode = 0
            sandbox_info: dict = {}

        def fake_run(cmd, **kwargs):
            _materialise_observe_log(kwargs["output"])
            return _Result()

        with patch("core.sandbox.run", side_effect=fake_run), \
             patch("core.sandbox.parse_observe_log",
                   return_value=ObserveProfile()), \
             patch("sys.stdout", io.StringIO()), \
             patch("sys.stderr", io.StringIO()):
            _cli_main(["--", "/usr/bin/true"])
        assert state._cli_sandbox_audit_budget is None


# ---------------------------------------------------------------------------
# End-to-end via shim — Linux only
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="ptrace tracer + seccomp Linux-only — observe shim degrades silently elsewhere",
)
@pytest.mark.slow
class TestE2EShim:
    """Run the libexec shim against /usr/bin/true and verify the
    summary lands on stdout. Only runs on Linux."""

    def test_shim_exits_zero_and_prints_summary(self, tmp_path):
        repo_root = Path(__file__).resolve().parents[3]
        shim = repo_root / "libexec" / "raptor-sandbox-observe"
        if not shim.exists():
            pytest.skip(f"shim not present at {shim}")

        # Observe works under either path:
        #   * mount-ns spawn (when available)
        #   * Landlock-only audit fallback (Ubuntu 24.04+ default
        #     where unprivileged user-ns is blocked by AppArmor)
        # mount-ns is not a hard prereq for observe.
        from core.sandbox.ptrace_probe import check_ptrace_available
        from core.sandbox.seccomp import check_seccomp_available
        if not check_seccomp_available():
            pytest.skip("libseccomp unavailable")
        if not check_ptrace_available():
            pytest.skip("ptrace blocked")

        env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
        result = subprocess.run(
            [str(shim), "--out", str(tmp_path), "--",
             "/usr/bin/true"],
            env=env, capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 0, (
            f"shim exited {result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "paths read" in result.stdout

    def test_shim_json_mode_produces_parseable_json(self, tmp_path):
        repo_root = Path(__file__).resolve().parents[3]
        shim = repo_root / "libexec" / "raptor-sandbox-observe"
        if not shim.exists():
            pytest.skip(f"shim not present at {shim}")

        from core.sandbox.ptrace_probe import check_ptrace_available
        from core.sandbox.seccomp import check_seccomp_available
        if not (check_seccomp_available()
                and check_ptrace_available()):
            pytest.skip("observe-mode prerequisites unavailable (libseccomp / ptrace)")

        env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
        result = subprocess.run(
            [str(shim), "--out", str(tmp_path), "--json", "--",
             "/usr/bin/true"],
            env=env, capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        # The 3 reads /usr/bin/true definitely makes (libc, ld.so.cache,
        # /proc/self/stat) — assert non-empty.
        assert len(payload["paths_read"]) > 0


# ---------------------------------------------------------------------------
# Trust-marker check (libexec convention)
# ---------------------------------------------------------------------------


class TestTrustMarker:
    """raptor-sandbox-observe shim refuses to run without
    CLAUDECODE / _RAPTOR_TRUSTED, mirroring other libexec shims."""

    def test_shim_refuses_without_trust_marker(self):
        repo_root = Path(__file__).resolve().parents[3]
        shim = repo_root / "libexec" / "raptor-sandbox-observe"
        if not shim.exists():
            pytest.skip(f"shim not present at {shim}")

        env = {k: v for k, v in os.environ.items()
               if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
        result = subprocess.run(
            [str(shim), "--", "/usr/bin/true"],
            env=env, capture_output=True, text=True, timeout=10, check=False,
        )
        assert result.returncode == 2, (
            f"shim must refuse without trust marker; got "
            f"rc={result.returncode}, stderr={result.stderr!r}"
        )
        assert "internal dispatch script" in result.stderr
