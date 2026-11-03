"""Tests for the Semgrep runner."""

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.semgrep.models import SemgrepResult
from packages.semgrep.runner import (
    _SCOPE_ISOLATION_MIN_VERSION,
    _config_to_name,
    build_cmd,
    is_available,
    run_rule,
    run_rules,
    scope_isolation_available,
    version,
)


@pytest.fixture(autouse=True)
def _scope_isolation_ok():
    """Most tests don't care about the version gate — default to available."""
    with patch("packages.semgrep.runner.scope_isolation_available",
               return_value=True):
        yield


# Helpers ----------------------------------------------------------------------

def _make_sarif(rule_id="r1", file="a.py", line=1, count=1) -> str:
    """Build a minimal SARIF JSON string with `count` findings."""
    results = []
    for i in range(count):
        results.append({
            "ruleId": rule_id,
            "message": {"text": f"finding {i}"},
            "level": "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": line + i},
                },
            }],
        })
    return json.dumps({"runs": [{"results": results}]})


def _make_json_output(scanned=None, errors=None, version="1.79.0",
                      skipped=None) -> str:
    """Build minimal --json-output content."""
    return json.dumps({
        "paths": {"scanned": scanned or [], "skipped": skipped or []},
        "errors": errors or [],
        "version": version,
    })


# Availability and version -----------------------------------------------------

class TestAvailability:
    def test_is_available_found(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            assert is_available()

    def test_is_available_missing(self):
        with patch("shutil.which", return_value=None):
            assert not is_available()

    def test_version_returns_string(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.79.0\n",
                stderr="",
                returncode=0,
            )
            assert version() == "1.79.0"

    def test_version_unavailable(self):
        with patch("shutil.which", return_value=None):
            assert version() is None

    def test_version_handles_timeout(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("semgrep", 10)):
            assert version() is None


class TestScopeIsolationAvailable:
    def test_true_at_floor(self):
        ver = ".".join(str(p) for p in _SCOPE_ISOLATION_MIN_VERSION)
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=f"{ver}\n", stderr="", returncode=0,
            )
            assert scope_isolation_available()

    def test_false_below_floor(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.79.0\n", stderr="", returncode=0,
            )
            assert not scope_isolation_available()

    def test_false_when_missing(self):
        with patch("shutil.which", return_value=None):
            assert not scope_isolation_available()


# build_cmd --------------------------------------------------------------------

class TestBuildCmd:
    def test_minimal(self):
        cmd = build_cmd(Path("/src"), "p/security-audit", semgrep_bin="semgrep")
        assert cmd[0] == "semgrep"
        assert "scan" in cmd
        assert "--config" in cmd
        idx = cmd.index("--config")
        assert cmd[idx + 1] == "p/security-audit"
        assert "--sarif" in cmd
        assert cmd[-1] == "/src"

    def test_target_ignore_files_neutralised(self):
        """Scan scope must be RAPTOR-owned, never target-owned.

        Without these flags a hostile repo's ``.semgrepignore`` (root
        or nested) or ``.gitignore`` silently exempts its own subtrees
        from the scan — empirically verified on semgrep 1.172.0: a
        planted ``.semgrepignore`` of ``*`` drops every finding with a
        clean exit, and both flags restore them.
        """
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep")
        assert "--no-git-ignore" in cmd
        assert "--x-ignore-semgrepignore-files" in cmd

    def test_scope_isolation_false_omits_flag(self):
        """Below-floor semgrep: the flag is omitted so the scan can run,
        but --no-git-ignore (always available) stays."""
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep",
                        scope_isolation=False)
        assert "--no-git-ignore" in cmd
        assert "--x-ignore-semgrepignore-files" not in cmd

    def test_scope_exclude_baseline_pinned(self):
        """The RAPTOR-owned exclude baseline is a curated security
        boundary (dependency/build/artifact names ONLY — adding a
        first-party-plausible name like ``tests/`` re-opens a
        name-steerable hiding channel), so its exact contents are
        pinned literally: any edit must consciously update this test.
        """
        from packages.semgrep.runner import SCOPE_EXCLUDE_BASELINE
        assert SCOPE_EXCLUDE_BASELINE == (
            "node_modules/",
            "bower_components/",
            ".yarn/",
            ".npm/",
            "vendor/",
            "third_party/",
            "site-packages/",
            ".venv/",
            ".tox/",
            "build/",
            "dist/",
            "*.min.js",
            "*.min.css",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "Pipfile.lock",
            "Cargo.lock",
            "composer.lock",
            "Gemfile.lock",
            "go.sum",
        )
        # First-party names a target could hide real code under must
        # never creep in (reject-direction guard for the curation rule).
        for steerable in ("test/", "tests/", "examples/", "docs/", ".env/"):
            assert steerable not in SCOPE_EXCLUDE_BASELINE

    def test_scope_exclude_baseline_in_cmd(self):
        """Every baseline pattern rides as an ``--exclude <pattern>``
        pair — --x-ignore-semgrepignore-files drops semgrep's built-in
        default ignores, and these args are what restores the
        dependency/build/artifact part of that set."""
        from packages.semgrep.runner import SCOPE_EXCLUDE_BASELINE
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep")
        pairs = [
            (cmd[i], cmd[i + 1])
            for i, a in enumerate(cmd[:-1]) if a == "--exclude"
        ]
        assert pairs == [("--exclude", p) for p in SCOPE_EXCLUDE_BASELINE]

    def test_verbose_not_quiet(self):
        """``paths.skipped`` is only populated at --verbose (mutually
        exclusive with --quiet); --quiet both starved skipped_summary
        and hid semgrep's own skipped-paths notice."""
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep")
        assert "--verbose" in cmd
        assert "--quiet" not in cmd

    def test_includes_disable_version_check(self):
        """The post-scan version-check HTTP GET must never fire: its
        cache lives in the throwaway fake HOME, so it would re-pay a
        network round-trip (or a blocked connect) per pack."""
        cmd = build_cmd(Path("/target"), "rules/")
        assert "--disable-version-check" in cmd

    def test_includes_metrics_off(self):
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep")
        assert "--metrics" in cmd
        idx = cmd.index("--metrics")
        assert cmd[idx + 1] == "off"

    def test_rule_timeout(self):
        cmd = build_cmd(Path("/src"), "p/x", rule_timeout=120, semgrep_bin="semgrep")
        idx = cmd.index("--timeout")
        assert cmd[idx + 1] == "120"

    def test_json_output_path(self, tmp_path):
        out_path = tmp_path / "out.json"
        cmd = build_cmd(
            Path("/src"), "p/x",
            json_output_path=out_path,
            semgrep_bin="semgrep",
        )
        assert "--json-output" in cmd
        idx = cmd.index("--json-output")
        assert cmd[idx + 1] == str(out_path)

    def test_no_json_output_path_omits_flag(self):
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep")
        assert "--json-output" not in cmd

    def test_extra_args_passed_through(self):
        cmd = build_cmd(
            Path("/src"), "p/x",
            extra_args=["--severity", "ERROR"],
            semgrep_bin="semgrep",
        )
        assert "--severity" in cmd
        idx = cmd.index("--severity")
        assert cmd[idx + 1] == "ERROR"

    def test_target_appears_last(self):
        cmd = build_cmd(Path("/src/foo"), "p/x", semgrep_bin="semgrep")
        assert cmd[-1] == "/src/foo"

    def test_uses_path_lookup_when_bin_not_specified(self):
        with patch("shutil.which", return_value="/opt/bin/semgrep"):
            cmd = build_cmd(Path("/src"), "p/x")
            assert cmd[0] == "/opt/bin/semgrep"


# run_rule with mocked subprocess ----------------------------------------------

class TestRunRuleMocked:
    def test_not_installed_returns_error_result(self):
        with patch("packages.semgrep.runner.is_available", return_value=False):
            result = run_rule(Path("/src"), "p/x")
        assert result.returncode == -1
        assert "not installed" in result.errors[0]
        assert result.findings == []
        assert not result.ok

    @pytest.mark.parametrize("root_level", ["WARNING", "ERROR", "CRITICAL"])
    @pytest.mark.parametrize("root_capture", [True, False])
    def test_below_floor_warns_and_omits_scope_flag(self, tmp_path, caplog, root_level,
                                                  root_capture):
        import logging
        from packages.semgrep import runner as semgrep_runner

        # CLI tests can replace root handlers or change propagation. Capture
        # this unit's real records directly through a fresh, unregistered logger.
        capture_logger = logging.Logger(semgrep_runner.logger.name, logging.WARNING)
        capture_logger.addHandler(caplog.handler)
        target = tmp_path / "src"
        target.mkdir()
        json_output = _make_json_output(scanned=["src/a.py"])
        with patch.object(semgrep_runner, "is_available", return_value=True), \
             patch.object(semgrep_runner, "scope_isolation_available", return_value=False), \
             patch.object(semgrep_runner, "version", return_value="1.79.0"), \
             patch.object(semgrep_runner, "logger", capture_logger), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                assert "--x-ignore-semgrepignore-files" not in cmd
                if "--json-output" in cmd:
                    idx = cmd.index("--json-output")
                    Path(cmd[idx + 1]).write_text(json_output)
                return MagicMock(stdout=_make_sarif(count=0), stderr="",
                                returncode=0)
            mock_run.side_effect = side_effect
            root = logging.getLogger()
            handlers = [handler for handler in root.handlers
                        if root_capture or handler is not caplog.handler]
            with patch.object(root, "handlers", handlers), \
                 caplog.at_level(getattr(logging, root_level)), \
                 caplog.at_level(logging.WARNING, logger=capture_logger.name):
                result = semgrep_runner.run_rule(target, "p/x", unsandboxed=True)
                # Warn once within a process, then reset that state between
                # parametrized cases via the package fixture.
                repeated = semgrep_runner.run_rule(target, "p/x", unsandboxed=True)
        assert result.ok
        assert repeated.ok
        assert len([r for r in caplog.records
                    if r.name == capture_logger.name and "semgrepignore" in r.message]) == 1

    def test_run_basic(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        sarif = _make_sarif(count=2)
        json_output = _make_json_output(
            scanned=["src/a.py", "src/b.py"],
            version="1.79.0",
        )
        # The runner writes to a temp file; we mock json_output_path read by writing
        # the json content into whatever path subprocess "received". Easier to just
        # let it use a tempfile we pre-write.
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                # Find --json-output path argument and write content there
                if "--json-output" in cmd:
                    idx = cmd.index("--json-output")
                    Path(cmd[idx + 1]).write_text(json_output)
                return MagicMock(stdout=sarif, stderr="", returncode=1)
            mock_run.side_effect = side_effect
            result = run_rule(target, "p/security-audit", unsandboxed=True)

        assert result.returncode == 1
        assert result.ok  # 1 is fine for semgrep --error
        assert len(result.findings) == 2
        assert result.files_examined == ["src/a.py", "src/b.py"]
        assert result.semgrep_version == "1.79.0"
        assert result.sarif == sarif
        assert result.elapsed_ms >= 0

    def test_run_surfaces_skipped_summary(self, tmp_path, caplog):
        """Paths semgrep did NOT scan must reach the result and the
        log — an empty-findings scan over a heavily skipped tree must
        not read as a clean verdict."""
        import logging

        target = tmp_path / "src"
        target.mkdir()
        json_output = _make_json_output(
            scanned=["src/a.py"],
            skipped=[
                {"path": "src/vendored/x.js", "reason": "cli_exclude_flags_match"},
                {"path": "src/huge.py", "reason": "exceeded_size_limit"},
                {"path": "src/vendored/y.js", "reason": "cli_exclude_flags_match"},
            ],
        )
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                idx = cmd.index("--json-output")
                Path(cmd[idx + 1]).write_text(json_output)
                return MagicMock(stdout=_make_sarif(), stderr="", returncode=0)
            mock_run.side_effect = side_effect
            with caplog.at_level(logging.INFO, logger="packages.semgrep.runner"):
                result = run_rule(target, "p/x", unsandboxed=True)

        assert result.skipped_summary["total"] == 3
        reasons = result.skipped_summary["reasons"]
        assert reasons["cli_exclude_flags_match"]["count"] == 2
        assert reasons["exceeded_size_limit"]["sample"] == ["src/huge.py"]
        assert result.to_dict()["skipped_summary"] == result.skipped_summary
        # Log line: counts per reason, no target-derived sample paths.
        log_text = "\n".join(r.getMessage() for r in caplog.records)
        assert "3 path(s) excluded or not fully analysed" in log_text
        assert "cli_exclude_flags_match=2" in log_text
        assert "src/huge.py" not in log_text

    def test_partial_parse_retains_findings_and_coverage_failure(self, tmp_path, caplog):
        """Recovery can yield a finding without establishing full file coverage."""
        import logging

        source = "src/partial.c"
        reason = "analysis_failed_parser_or_internal_error"
        payload = _make_json_output(
            scanned=[source],
            skipped=[{"path": source, "reason": reason}],
            errors=[{"type": "PartialParsing", "path": source,
                     "message": "unrecognised annotation"}],
        )
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                Path(cmd[cmd.index("--json-output") + 1]).write_text(payload)
                return MagicMock(stdout=_make_sarif(file=source), stderr="", returncode=0)
            mock_run.side_effect = side_effect
            with caplog.at_level(logging.INFO, logger="packages.semgrep.runner"):
                result = run_rule(tmp_path, "p/x", unsandboxed=True)

        assert len(result.findings) == 1
        assert result.files_examined == [source]
        assert any(row["path"] == source for row in result.files_failed)
        assert result.skipped_summary["reasons"][reason]["count"] == 1
        assert result.to_dict()["skipped_summary"] == result.skipped_summary
        log_text = "\n".join(record.getMessage() for record in caplog.records)
        assert "1 path(s) excluded or not fully analysed" in log_text
        assert "not scanned" not in log_text
        assert source not in log_text

    def test_run_no_skips_no_summary_no_log(self, tmp_path, caplog):
        import logging

        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                idx = cmd.index("--json-output")
                Path(cmd[idx + 1]).write_text(_make_json_output(scanned=["a.py"]))
                return MagicMock(stdout=_make_sarif(), stderr="", returncode=0)
            mock_run.side_effect = side_effect
            with caplog.at_level(logging.INFO, logger="packages.semgrep.runner"):
                result = run_rule(target, "p/x", unsandboxed=True)
        assert result.skipped_summary == {}
        assert "skipped" not in "\n".join(
            r.getMessage() for r in caplog.records)

    def test_run_handles_timeout(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("semgrep", 5)):
            result = run_rule(target, "p/x", timeout=5, unsandboxed=True)
        assert result.returncode == -1
        assert any("Timeout" in e for e in result.errors)

    def test_run_handles_oserror(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run", side_effect=OSError("permission denied")):
            result = run_rule(target, "p/x", unsandboxed=True)
        assert result.returncode == -1
        assert "permission denied" in result.errors[0]

    def test_completed_process_bad_exit_populates_errors(self, tmp_path):
        # Regression: a completed subprocess exiting outside {0, 1}
        # (invalid rule YAML, internal crash on a hostile source file)
        # used to return errors=[] — downstream sweeps then read the
        # empty findings as a refutation the tool never made.
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="", stderr="fatal: invalid rule schema", returncode=2,
            )
            result = run_rule(target, "p/x", unsandboxed=True)
        assert result.returncode == 2
        assert result.errors
        assert "exited with code 2" in result.errors[0]
        assert "invalid rule schema" in result.errors[0]
        assert not result.ok

    def test_signal_kill_populates_errors(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="", stderr="", returncode=-11,
            )
            result = run_rule(target, "p/x", unsandboxed=True)
        assert result.errors and "exited with code -11" in result.errors[0]
        assert not result.ok

    def test_run_with_empty_sarif(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "p/x", unsandboxed=True)
        assert result.findings == []
        assert result.returncode == 0
        # No json file written → empty parse
        assert result.files_examined == []

    def test_run_with_provided_json_output_path(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        json_path = tmp_path / "out.json"
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                idx = cmd.index("--json-output")
                Path(cmd[idx + 1]).write_text(_make_json_output(scanned=["a.py"]))
                return MagicMock(stdout=_make_sarif(), stderr="", returncode=0)
            mock_run.side_effect = side_effect
            result = run_rule(target, "p/x", json_output_path=json_path,
                              unsandboxed=True)
        # Provided path should NOT be deleted by the runner
        assert json_path.exists()
        assert result.files_examined == ["a.py"]

    def test_run_passes_env(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        custom_env = {"PATH": "/safe/path", "MY_VAR": "set"}
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            run_rule(target, "p/x", env=custom_env, unsandboxed=True)
        kwargs = mock_run.call_args.kwargs
        assert kwargs["env"] == custom_env

    def test_run_passes_timeout(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            run_rule(target, "p/x", timeout=42, unsandboxed=True)
        kwargs = mock_run.call_args.kwargs
        assert kwargs["timeout"] == 42

    def test_run_friendly_name_from_pack(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "p/security-audit", unsandboxed=True)
        assert result.name == "p/security-audit"

    def test_run_friendly_name_from_dir(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "/abs/path/to/crypto", unsandboxed=True)
        assert result.name == "crypto"

    def test_run_explicit_name(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "/abs/path", name="my_run", unsandboxed=True)
        assert result.name == "my_run"


# sandbox-by-default policy -----------------------------------------------------

class TestSandboxDefaultPolicy:
    """No injected runner + no opt-out ⇒ sandboxed or refused."""

    def test_default_engages_sandbox_runner(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        calls = {}

        def fake_sandbox_runner(cmd, **kwargs):
            calls["cmd"] = cmd
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("packages.semgrep.runner._default_sandbox_runner",
                   return_value=fake_sandbox_runner) as mk, \
             patch("subprocess.run") as mock_run:
            result = run_rule(target, "p/x")
        mk.assert_called_once()
        assert "cmd" in calls, "default sandbox runner was not used"
        mock_run.assert_not_called()
        assert result.returncode == 0

    def test_refuses_when_sandbox_unavailable(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("packages.semgrep.runner._default_sandbox_runner",
                   return_value=None), \
             patch("subprocess.run") as mock_run:
            result = run_rule(target, "p/x")
        mock_run.assert_not_called()
        assert result.returncode == -1
        assert "refusing" in result.errors[0]

    def test_explicit_optout_uses_subprocess_run(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="", stderr="", returncode=0)
            run_rule(target, "p/x", unsandboxed=True)
        mock_run.assert_called_once()

    def test_injected_runner_bypasses_default(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        calls = {}

        def injected(cmd, **kwargs):
            calls["cmd"] = cmd
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("packages.semgrep.runner._default_sandbox_runner") as mk:
            run_rule(target, "p/x", subprocess_runner=injected)
        mk.assert_not_called()
        assert "cmd" in calls

    def test_registry_config_gets_proxied_egress_local_blocks(
            self, tmp_path):
        """Posture pin: registry configs route through the egress
        proxy with the shared semgrep hostname allowlist — never
        open network (semgrep parses attacker-controlled source; a
        parser compromise must not get a free exfil channel). Local
        rule paths keep the full network block."""
        from packages.semgrep.runner import _default_sandbox_runner
        captured = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured.update(kwargs)
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch("core.sandbox.context.run", side_effect=fake_sandbox_run):
            runner = _default_sandbox_runner(tmp_path, "p/security-audit")
            runner(["semgrep"], capture_output=True)
            assert captured.get("block_network") is not False
            assert captured["use_egress_proxy"] is True
            assert captured["proxy_hosts"], (
                "registry lane must carry a hostname allowlist"
            )
            assert any("semgrep" in h for h in captured["proxy_hosts"])

            captured.clear()
            runner = _default_sandbox_runner(tmp_path, "/local/rules.yaml")
            runner(["semgrep"], capture_output=True)
            assert captured["block_network"] is True
            assert "use_egress_proxy" not in captured
            assert captured["target"] == str(tmp_path)


# run_rules --------------------------------------------------------------------

class TestRunRules:
    def test_runs_each_config(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        configs = [("a", "p/aaa"), ("b", "p/bbb"), ("c", "p/ccc")]
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            results = run_rules(target, configs, unsandboxed=True)
        assert len(results) == 3
        assert [r.name for r in results] == ["a", "b", "c"]
        assert mock_run.call_count == 3

    def test_empty_configs(self, tmp_path):
        results = run_rules(tmp_path, [])
        assert results == []

    def test_not_installed_returns_error_per_config(self, tmp_path):
        with patch("packages.semgrep.runner.is_available", return_value=False):
            results = run_rules(tmp_path, [("a", "p/a"), ("b", "p/b")],
                                unsandboxed=True)
        assert len(results) == 2
        assert all(r.returncode == -1 for r in results)
        assert all("not installed" in r.errors[0] for r in results)


# Helpers ----------------------------------------------------------------------

class TestConfigToName:
    def test_pack(self):
        assert _config_to_name("p/security-audit") == "p/security-audit"

    def test_category(self):
        assert _config_to_name("category/security") == "category/security"

    def test_directory(self):
        assert _config_to_name("/abs/path/to/crypto") == "crypto"

    def test_relative_directory(self):
        assert _config_to_name("rules/injection") == "injection"

    def test_empty(self):
        assert _config_to_name("") == "semgrep"


# Integration ------------------------------------------------------------------

# Marked ``integration`` so pytest.ini's default
# ``-m "not integration and not slow"`` deselects this class in
# regular suite runs. Reason: the tests call ``run_rule(... "p/python"
# ...)`` which downloads the ``p/python`` rule pack from semgrep.dev
# at scan time. Two consequences:
#   * The default suite shouldn't depend on outbound HTTPS to
#     semgrep.dev — flaky on sandboxed CI, fails when an unrelated
#     test in the same process has spun up the egress-proxy with a
#     narrower allowlist.
#   * 6-second wall per test (real semgrep invocation) is integration
#     territory, not unit-test cadence.
class TestErrorTruth:
    """Engine failure must never read as verified silence (U14-F3).

    Pre-fix, run_rule hardcoded errors=[] on every completed run —
    an rc=7 invalid rule or an rc=2 crash was indistinguishable from
    a clean no-match scan, so every fail-closed consumer branch
    (sweep error outcome, synthesis dual/fix-mutant controls) was
    dead code for semgrep.
    """

    def _run_with(self, tmp_path, returncode, stderr="", json_errors=None):
        target = tmp_path / "src"
        target.mkdir(exist_ok=True)
        json_output = _make_json_output(errors=json_errors or [])

        def runner(cmd, **kwargs):
            if "--json-output" in cmd:
                idx = cmd.index("--json-output")
                Path(cmd[idx + 1]).write_text(json_output)
            return MagicMock(stdout="", stderr=stderr, returncode=returncode)

        with patch("packages.semgrep.runner.is_available", return_value=True):
            return run_rule(target, "rules.yaml", subprocess_runner=runner)

    def test_rc7_invalid_rule_populates_errors(self, tmp_path):
        result = self._run_with(tmp_path, returncode=7)
        assert result.errors
        assert "code 7" in result.errors[0]
        assert not result.ok

    def test_rc_error_includes_stderr_tail(self, tmp_path):
        result = self._run_with(
            tmp_path, returncode=2, stderr="fatal: semgrep-core crashed\n",
        )
        assert any("semgrep-core crashed" in e for e in result.errors)
        assert not result.ok

    @pytest.mark.parametrize("rc", [2, 3, 4, 7, 13, 128])
    def test_every_nonzero_rc_outside_findings_contract_errors(
        self, tmp_path, rc,
    ):
        # 0 = clean, 1 = findings (with --error). Everything else is a
        # real failure and must surface a non-empty errors list.
        result = self._run_with(tmp_path, returncode=rc)
        assert result.errors, f"rc={rc} read as verified silence"
        assert not result.ok

    def test_real_error_array_parsed_into_errors(self, tmp_path):
        result = self._run_with(
            tmp_path, returncode=7,
            json_errors=[
                {"code": 4, "level": "error",
                 "type": "InvalidRuleSchemaError",
                 "short_msg": "Invalid rule schema"},
            ],
        )
        assert any("InvalidRuleSchemaError" in e for e in result.errors)
        assert not result.ok

    def test_clean_run_keeps_errors_empty(self, tmp_path):
        result = self._run_with(tmp_path, returncode=0)
        assert result.errors == []
        assert result.ok

    def test_findings_rc1_keeps_errors_empty(self, tmp_path):
        result = self._run_with(tmp_path, returncode=1)
        assert result.errors == []
        assert result.ok


@pytest.mark.skipif(not is_available(), reason="semgrep not installed")
class TestErrorTruthLive:
    """Real-semgrep regression for the errors=[] hardcode: a
    deliberately-invalid rule must produce an error result, never
    verified silence. Runs the real binary (trusted local fixtures,
    hence unsandboxed=True)."""

    @pytest.fixture(autouse=True)
    def _scope_isolation_ok(self):
        """Override the module-level fixture — live tests need the real check."""
        yield

    def test_invalid_rule_reports_error_not_silence(self, tmp_path):
        rule = tmp_path / "invalid.yaml"
        rule.write_text(
            "rules:\n"
            "  - id: deliberately.invalid\n"
            "    message: x\n"
            "    languages: [python]\n"
            "    severity: ERROR\n"
            "    patterns-oops: [x]\n",
            encoding="utf-8",
        )
        target = tmp_path / "t.py"
        target.write_text("x = 1\n", encoding="utf-8")
        result = run_rule(target, str(rule), timeout=120, unsandboxed=True)
        assert result.returncode not in (0, 1)
        assert result.errors, "invalid rule read as verified silence"
        assert not result.ok
        assert result.findings == []


@pytest.mark.skipif(not is_available(), reason="semgrep not installed")
@pytest.mark.skipif(
    is_available() and not scope_isolation_available(),
    reason="semgrep below scope-isolation floor",
)
class TestScanScopeLive:
    """Real-semgrep regression for target-steered scan scope: semgrep
    honours the SCANNED repo's ``.semgrepignore`` by default, so a
    hostile target shipping one line of config could silently exempt
    its own subtrees (clean exit, empty findings). Runs the real
    binary (trusted local fixtures, hence unsandboxed=True)."""

    @pytest.fixture(autouse=True)
    def _scope_isolation_ok(self):
        """Override the module-level fixture — live tests need the real check."""
        yield

    @staticmethod
    def _eval_rule(tmp_path):
        rule = tmp_path / "rule.yaml"
        rule.write_text(
            "rules:\n"
            "  - id: eval.use\n"
            "    pattern: eval(...)\n"
            "    message: eval use\n"
            "    languages: [python]\n"
            "    severity: ERROR\n",
            encoding="utf-8",
        )
        return rule

    def test_planted_semgrepignore_does_not_suppress(self, tmp_path):
        rule = self._eval_rule(tmp_path)
        target = tmp_path / "tgt"
        target.mkdir()
        (target / "vuln.py").write_text('eval("x")\n', encoding="utf-8")
        (target / ".semgrepignore").write_text("*\n", encoding="utf-8")
        result = run_rule(target, str(rule), timeout=120, unsandboxed=True)
        assert result.ok, result.errors
        assert any(f.file.endswith("vuln.py") for f in result.findings), (
            "target-shipped .semgrepignore suppressed the scan scope"
        )

    @pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
    def test_planted_gitignore_untracked_file_still_scanned(self, tmp_path):
        """--no-git-ignore semantic pin: inside a git repo, semgrep by
        default drops files matched by the TARGET's ``.gitignore`` —
        an untracked-but-gitignored source file vanishes from scope.
        A hostile repo gitignoring its own payload must not work."""
        import subprocess as sp
        rule = self._eval_rule(tmp_path)
        target = tmp_path / "tgt"
        target.mkdir()
        sp.run(
            ["git", "init", "-q", str(target)],
            check=True, capture_output=True, timeout=60,
        )
        (target / ".gitignore").write_text("vuln.py\n", encoding="utf-8")
        (target / "vuln.py").write_text('eval("x")\n', encoding="utf-8")
        result = run_rule(target, str(rule), timeout=120, unsandboxed=True)
        assert result.ok, result.errors
        assert any(f.file.endswith("vuln.py") for f in result.findings), (
            "target-shipped .gitignore suppressed an untracked source file"
        )

    def test_tests_dirname_is_scanned(self, tmp_path):
        """Steerable-channel pin: semgrep's built-in defaults skip any
        directory NAMED ``tests/`` — a target could hide real code by
        picking the name. SCOPE_EXCLUDE_BASELINE deliberately leaves
        first-party-plausible names in scope."""
        rule = self._eval_rule(tmp_path)
        target = tmp_path / "tgt"
        (target / "tests").mkdir(parents=True)
        (target / "tests" / "vuln.py").write_text(
            'eval("x")\n', encoding="utf-8",
        )
        result = run_rule(target, str(rule), timeout=120, unsandboxed=True)
        assert result.ok, result.errors
        assert any("tests" in f.file and f.file.endswith("vuln.py")
                   for f in result.findings), (
            "a dir named tests/ was silently exempted from the scan"
        )

    def test_baseline_excludes_node_modules_and_reports_skip(self, tmp_path):
        """The RAPTOR-owned baseline replaces semgrep's built-in
        defaults for dependency trees: node_modules/ stays out of
        scope AND the skip is visible in skipped_summary."""
        rule = self._eval_rule(tmp_path)
        target = tmp_path / "tgt"
        (target / "node_modules").mkdir(parents=True)
        (target / "node_modules" / "dep.py").write_text(
            'eval("x")\n', encoding="utf-8",
        )
        (target / "app.py").write_text('eval("x")\n', encoding="utf-8")
        result = run_rule(target, str(rule), timeout=120, unsandboxed=True)
        assert result.ok, result.errors
        assert any(f.file.endswith("app.py") for f in result.findings)
        assert not any("node_modules" in f.file for f in result.findings)
        reasons = result.skipped_summary.get("reasons", {})
        assert reasons.get("cli_exclude_flags_match", {}).get("count", 0) >= 1, (
            "baseline exclusion happened but was invisible in skipped_summary"
        )


# Opt-in with ``pytest -m integration``.
@pytest.mark.integration
@pytest.mark.skipif(not is_available(), reason="semgrep not installed")
class TestIntegration:
    """Real-semgrep tests. Skipped when binary unavailable."""

    def test_run_on_simple_file(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("import os\nos.system('hi')\n")
        result = run_rule(target, "p/python", timeout=120)
        # Either finds something or doesn't, but should not error.
        assert result.ok or result.returncode == 0
        assert result.semgrep_version

    def test_files_examined_populated(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("a = 1\n")
        result = run_rule(target, "p/python", timeout=120)
        # paths.scanned should include at least our file
        assert result.ok, result.errors
        assert any("x.py" in f for f in result.files_examined)


class TestOutputBudget:
    """Over-budget tool output must surface as a FAILED scan — never
    as a verified-clean one. Semgrep exits 0/1 on a successful scan
    regardless of output size, so without an error entry a hostile
    repo could inflate the output past the cap and suppress its own
    findings (empty findings + empty errors + rc 0 reads as clean)."""

    def test_oversize_json_output_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import packages.semgrep.runner as runner_mod

        target = tmp_path / "src"
        target.mkdir()
        json_path = tmp_path / "out.json"
        # Pad the --json payload so ONLY it exceeds the cap — the
        # SARIF stdout must stay under budget and keep parsing.
        payload = _make_json_output(
            scanned=[f"f{i}.py" for i in range(200)],
        )
        assert len(payload) - 1 > len(_make_sarif())
        monkeypatch.setattr(
            runner_mod, "_MAX_TOOL_OUTPUT_BYTES", len(payload) - 1,
        )
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                idx = cmd.index("--json-output")
                Path(cmd[idx + 1]).write_text(payload)
                return MagicMock(stdout=_make_sarif(), stderr="", returncode=0)
            mock_run.side_effect = side_effect
            result = run_rule(target, "p/x", json_output_path=json_path,
                              unsandboxed=True)
        # Metadata is unavailable AND the scan reports the refusal.
        assert result.files_examined == []
        assert result.findings  # stdout SARIF (under budget) still parses
        assert any("bytes" in e and "budget" in e for e in result.errors)
        assert not result.ok
        assert result.json_output == ""  # oversized text never retained

    def test_oversize_sarif_stdout_is_a_failed_scan_not_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Inverted suppression PoC: rc=0 with SARIF stdout past the
        budget must yield errors (size-naming), not a clean result."""
        import packages.semgrep.runner as runner_mod

        target = tmp_path / "src"
        target.mkdir()
        sarif_payload = _make_sarif()

        def _run(sarif_text: str) -> SemgrepResult:
            with patch("packages.semgrep.runner.is_available",
                       return_value=True), \
                 patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=sarif_text, stderr="", returncode=0,
                )
                return run_rule(target, "p/x", unsandboxed=True)

        # Control: under budget, the finding surfaces and the run is ok.
        baseline = _run(sarif_payload)
        assert baseline.findings
        assert baseline.ok

        # Over budget: findings are gone WITH an error naming the size
        # — a failed scan, never verified silence.
        monkeypatch.setattr(
            runner_mod, "_MAX_TOOL_OUTPUT_BYTES", len(sarif_payload) - 1,
        )
        result = _run(sarif_payload)
        assert result.findings == []
        assert any(
            str(len(sarif_payload)) in e and "budget" in e
            for e in result.errors
        )
        assert not result.ok
        assert result.sarif == ""  # oversized text never retained


class TestBudgetMeasuresBytes:
    def test_non_ascii_payload_over_byte_budget_is_refused(
        self, tmp_path, monkeypatch,
    ):
        """The budget is declared in bytes; len(str) counts
        characters and UTF-8 encodes up to 4 bytes per char — a
        non-ASCII payload could weigh 4x the budget while passing a
        character-count gate."""
        import packages.semgrep.runner as runner_mod

        target = tmp_path / "src"
        target.mkdir()
        # 100 chars, 200 bytes in UTF-8.
        payload = "é" * 100
        monkeypatch.setattr(runner_mod, "_MAX_TOOL_OUTPUT_BYTES", 150)
        with patch("packages.semgrep.runner.is_available",
                   return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=payload, stderr="", returncode=0,
            )
            result = run_rule(target, "p/x", unsandboxed=True)
        assert not result.ok
        assert any("budget" in e and "bytes" in e for e in result.errors)
        assert result.sarif == ""


def test_home_tool_runtime_and_exact_local_config_are_declared(tmp_path):
    from packages.semgrep.runner import _default_sandbox_runner
    configuration = tmp_path / 'private-rules/rule.yml'
    configuration.parent.mkdir()
    configuration.write_text('rules: []')
    (tmp_path / 'target').mkdir()
    with patch('core.sandbox.python_paths.python_tool_paths', return_value=['/tool/bin', '/tool/lib']), \
            patch('core.sandbox.context.run') as run:
        wrapper = _default_sandbox_runner(tmp_path / 'target', str(configuration))
        wrapper(['/tool/bin/semgrep'], tool_paths=['/explicit-dependency'], capture_output=True)
    paths = run.call_args.kwargs['tool_paths']
    assert paths == ['/tool/bin', '/tool/lib', str(configuration), '/explicit-dependency']
    assert str(configuration.parent) not in paths
    assert run.call_args.kwargs['block_network'] is True


def test_single_file_scan_binds_exact_file_without_changing_scan_argv(tmp_path):
    from packages.semgrep.runner import _default_sandbox_runner
    source = tmp_path / 'source'
    source.mkdir()
    target = source / 'fixture.py'
    target.write_text('print(42)')
    command = ['/usr/bin/semgrep', '--config', 'p/x', str(target)]
    with patch('core.sandbox.context.run') as run:
        wrapper = _default_sandbox_runner(target, 'p/x')
        wrapper(command, capture_output=True)
    assert run.call_args.kwargs['target'] is None
    assert str(target) in run.call_args.kwargs['tool_paths']
    assert str(source) not in run.call_args.kwargs['tool_paths']
    assert run.call_args.args[0] == command
    assert run.call_args.kwargs['output'] != str(source)


def test_extra_target_gets_its_own_exact_readonly_bind(tmp_path):
    from packages.semgrep.runner import _default_sandbox_runner
    target = tmp_path / 'fixture.py'
    target.write_text('print(42)')
    additional = tmp_path / 'separate/control.py'
    with patch('core.sandbox.context.run') as run:
        wrapper = _default_sandbox_runner(target, 'p/x', extra_targets=[additional])
        wrapper(['/usr/bin/semgrep', str(target), str(additional)])
    assert str(additional) in run.call_args.kwargs['tool_paths']
    assert str(additional.parent) not in run.call_args.kwargs['tool_paths']


def test_relative_file_rule_and_extra_target_are_independent_of_sandbox_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path('fixture.py').write_text('print(42)')
    Path('rule.yml').write_text('rules: []')
    invocation = MagicMock(return_value=MagicMock(stdout='', stderr='', returncode=0))
    with patch('packages.semgrep.runner.is_available', return_value=True), \
            patch('packages.semgrep.runner.scope_isolation_available', return_value=True):
        run_rule(Path('fixture.py'), 'rule.yml', extra_targets=[Path('control.py')],
                 subprocess_runner=invocation)
    command = invocation.call_args.args[0]
    assert command[-2:] == [str(tmp_path / 'fixture.py'), str(tmp_path / 'control.py')]
    assert command[command.index('--config') + 1] == str(tmp_path / 'rule.yml')


@pytest.mark.parametrize('configuration', ['p/security-audit', 'category/security'])
def test_registry_identifier_is_not_rewritten_by_local_path_collision(tmp_path, monkeypatch, configuration):
    monkeypatch.chdir(tmp_path)
    Path(configuration).mkdir(parents=True)
    target = tmp_path / 'fixture.py'
    target.write_text('print(42)')
    invocation = MagicMock(return_value=MagicMock(stdout='', stderr='', returncode=0))
    with patch('packages.semgrep.runner.is_available', return_value=True), \
            patch('packages.semgrep.runner.scope_isolation_available', return_value=True):
        run_rule(target, configuration, subprocess_runner=invocation)
    command = invocation.call_args.args[0]
    assert command[command.index('--config') + 1] == configuration

    from packages.semgrep.runner import _default_sandbox_runner
    with patch('core.sandbox.context.run') as run:
        wrapper = _default_sandbox_runner(target, configuration)
        wrapper(['/usr/bin/semgrep', '--config', configuration, str(target)])
    assert run.call_args.kwargs['use_egress_proxy'] is True
    assert str(Path(configuration).absolute()) not in run.call_args.kwargs['tool_paths']


def _diagnose_failed_semgrep(directory, execute, command, scope, failed):
    """Collect evidence without replacing or accepting the original failure."""
    diagnostics = {
        "original_returncode": failed.returncode,
        "original_backend": getattr(failed, "sandbox_info", {}),
        "command": list(map(str, command)),
        "workflow_python": sys.version,
    }
    (directory / "sandbox-stderr.txt").write_text((failed.stderr or "")[-1024 * 1024:])
    try:
        selected = shutil.which(command[0]) or command[0]
        with Path(selected).open("rb") as stream:
            header = stream.readline(4096).decode("utf-8", errors="replace").strip()
        diagnostics["launcher"] = header if header.startswith("#!") else "native executable"
        interpreter = Path(header[2:]) if header.startswith("#!/") else None
        if interpreter is not None and interpreter.name.startswith("python") and interpreter.is_file():
            import tempfile
            with tempfile.TemporaryDirectory(prefix="probe-", dir=directory) as output:
                probe_scope = dict(scope, output=output)
                probe = execute([str(interpreter), "-I", "-S", "-c",
                    "import json,os,resource,sys; print(json.dumps(dict("
                    "python=sys.version,executable=sys.executable,"
                    "stack=resource.getrlimit(resource.RLIMIT_STACK),"
                    "memory=resource.getrlimit(resource.RLIMIT_AS),"
                    "processes=resource.getrlimit(resource.RLIMIT_NPROC),"
                    "files=resource.getrlimit(resource.RLIMIT_NOFILE),"
                    "libc=os.confstr('CS_GNU_LIBC_VERSION'),"
                    "infinity=resource.RLIM_INFINITY,cpus=os.cpu_count(),"
                    "affinity=sorted(os.sched_getaffinity(0)))))"], **probe_scope)
                diagnostics["tool_python_probe"] = {
                    "returncode": probe.returncode, "stdout": probe.stdout, "stderr": probe.stderr,
                }
        replay_scope = dict(scope, observe=True, audit_run_dir=str(directory))
        replay = execute(command, **replay_scope)
        diagnostics["observed_replay"] = {
            "returncode": replay.returncode,
            "backend": getattr(replay, "sandbox_info", {}),
        }
        (directory / "sandbox-replay-stderr.txt").write_text((replay.stderr or "")[-1024 * 1024:])
        trace = directory / ".audit" / ".sandbox-observe.jsonl"
        if trace.is_file():
            # Keep the tail, including the crash/last syscalls, within a
            # fixed artifact budget. This is diagnostic data, never a receipt.
            with trace.open("rb") as stream:
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - 8 * 1024 * 1024))
                (directory / "sandbox-observe.jsonl").write_bytes(stream.read(8 * 1024 * 1024))
            diagnostics["trace_bytes"] = size
    except Exception as exc:  # Diagnostics must never hide the first failure.
        diagnostics["diagnostic_error"] = str(exc)
    (directory / "sandbox-diagnostics.json").write_text(json.dumps(diagnostics, indent=2, default=str) + "\n")


@pytest.mark.integration
@pytest.mark.skipif(not is_available(), reason="semgrep not installed")
class TestSandboxMetadataIntegration:
    @pytest.mark.parametrize("external_output", [False, True])
    def test_positive_control_keeps_sidecar_inside_writable_output(self, tmp_path, monkeypatch, external_output):
        import core.sandbox.context as context
        actual_run = context.run
        seen = []
        def scoped(command, **kwargs):
            kwargs["restrict_reads"] = True
            seen.append((command, kwargs))
            completed = actual_run(command, **kwargs)
            if completed.returncode not in (0, 1):
                try:
                    _diagnose_failed_semgrep(tmp_path, actual_run, command, kwargs, completed)
                except Exception as exc:
                    print(f"Failure diagnostics unavailable: {exc}", file=sys.stderr)
            return completed
        monkeypatch.setattr(context, "run", scoped)
        target = tmp_path / "target.py"
        target.write_text("foo()\n")
        rule = tmp_path / "rule.yaml"
        rule.write_text('rules:\n- id: positive\n  languages: [python]\n  pattern: foo()\n  message: positive\n  severity: ERROR\n')
        output = tmp_path / "metadata.json" if external_output else None
        result = run_rule(target, str(rule), timeout=60, json_output_path=output)
        assert result.ok, result.errors
        assert len(result.findings) == 1
        assert str(target) in result.files_examined
        scan, scope = next((cmd, kw) for cmd, kw in seen if "scan" in cmd)
        sidecar = Path(scan[scan.index("--json-output") + 1])
        assert sidecar.parent == Path(scope["output"])
        assert not sidecar.exists()  # parsed and cleaned even with explicit output
        if output is not None:
            assert json.loads(output.read_text())["paths"]["scanned"]
            assert str(tmp_path) not in scope.get("writable_paths", [])


class TestSandboxSidecarSafety:
    @pytest.mark.parametrize("mode", ["scanner-symlink", "destination-symlink", "save-error"])
    def test_parent_refuses_unsafe_sidecar_and_keeps_explicit_destination_confined(self, tmp_path, monkeypatch, mode):
        import subprocess
        import core.sandbox.context as context
        import packages.semgrep.runner as module
        monkeypatch.setattr(module, "is_available", lambda: True)
        source = tmp_path / "source.py"
        source.write_text("foo()\n")
        secret = tmp_path / "host-secret"
        secret.write_text("private-content")
        output = tmp_path / "metadata.json"
        if mode == "destination-symlink":
            output.symlink_to(secret)
        elif mode == "save-error":
            output.mkdir()
        def execute(command, **scope):
            sidecar = Path(command[command.index("--json-output") + 1])
            assert sidecar.parent == Path(scope["output"])
            if mode == "scanner-symlink":
                sidecar.unlink()
                sidecar.symlink_to(secret)
            else:
                sidecar.write_text(_make_json_output(scanned=[str(source)]))
            return subprocess.CompletedProcess(command, 0, _make_sarif(), "")
        monkeypatch.setattr(context, "run", execute)
        result = run_rule(source, "local-rule.yaml", json_output_path=output)
        assert secret.read_text() == "private-content"
        assert "private-content" not in result.json_output
        if mode == "destination-symlink":
            assert result.ok, result.errors
            assert not output.is_symlink()
            assert json.loads(output.read_text())["paths"]["scanned"] == [str(source)]
        else:
            assert not result.ok
            assert result.errors


def test_failure_diagnostics_cannot_launder_a_successful_replay(tmp_path, monkeypatch):
    from types import SimpleNamespace
    launcher = tmp_path / "semgrep"
    launcher.write_text("#!/not-an-interpreter\n")
    first = SimpleNamespace(returncode=139, stderr="original crash", sandbox_info={"backend": "mountless-ns"})
    calls = []
    def replay(command, **scope):
        calls.append(scope)
        audit = tmp_path / ".audit"
        audit.mkdir()
        (audit / ".sandbox-observe.jsonl").write_text('{"syscall": "openat"}\n')
        return SimpleNamespace(returncode=0, stderr="replay succeeded", sandbox_info={})
    _diagnose_failed_semgrep(tmp_path, replay, [str(launcher)], {"restrict_reads": True, "block_network": True}, first)
    saved = json.loads((tmp_path / "sandbox-diagnostics.json").read_text())
    assert saved["original_returncode"] == first.returncode == 139
    assert saved["observed_replay"]["returncode"] == 0
    assert (tmp_path / "sandbox-stderr.txt").read_text() == "original crash"
    assert calls[0]["restrict_reads"] is True
    assert calls[0]["block_network"] is True
    assert (tmp_path / "sandbox-observe.jsonl").is_file()
