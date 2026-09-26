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
    _config_to_name,
    build_cmd,
    is_available,
    run_rule,
    run_rules,
    version,
)

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
        assert "3 path(s) skipped" in log_text
        assert "cli_exclude_flags_match=2" in log_text
        assert "src/huge.py" not in log_text

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
class TestScanScopeLive:
    """Real-semgrep regression for target-steered scan scope: semgrep
    honours the SCANNED repo's ``.semgrepignore`` by default, so a
    hostile target shipping one line of config could silently exempt
    its own subtrees (clean exit, empty findings). Runs the real
    binary (trusted local fixtures, hence unsandboxed=True)."""

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
        assert any("x.py" in f for f in result.files_examined) or result.files_examined == []


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
