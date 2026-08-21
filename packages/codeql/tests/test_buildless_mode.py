"""Tests for buildless (--build-mode=none) C/C++ database creation.

Buildless is the DEFAULT for languages in BUILDLESS_DEFAULT_LANGUAGES:
an untrusted repo's build scripts must never execute during
``codeql database create`` unless the operator explicitly opts into
traced-build mode. These tests are fully mocked — no codeql CLI, no
network — plus version-probe tests that only need the probe seam.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# packages/codeql/tests/test_buildless_mode.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.build.build_detector import BuildSystem
from packages.codeql.database_manager import (
    BUILDLESS_DEFAULT_LANGUAGES,
    DatabaseManager,
)


@pytest.fixture
def db_manager(tmp_path):
    """DatabaseManager with a fake codeql binary (no __init__ probing)."""
    with patch.object(DatabaseManager, '__init__', lambda self: None):
        mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.db_root = tmp_path / "cache"
        mgr.db_root.mkdir()
        return mgr


def _build_system(tmp_path, command="make -j"):
    return BuildSystem(
        type="make", command=command, working_dir=tmp_path,
        env_vars={}, confidence=1.0, detected_files=[],
    )


def _run_create(db_manager, tmp_path, *, language, build_system=None,
                traced_build=False, version="2.26.3"):
    """Run create_database with a capturing fake subprocess."""
    captured = {"cmd": None}

    def fake_run(cmd, **kwargs):
        if "database" in cmd and "create" in cmd:
            captured["cmd"] = list(cmd)
        r = MagicMock()
        r.returncode = 0
        r.stdout = ""
        r.stderr = "Finalizing database.\n"
        return r

    db_path = tmp_path / "db"
    with patch('core.sandbox.run', side_effect=fake_run), \
         patch.object(db_manager, 'get_codeql_version', return_value=version), \
         patch.object(db_manager, '_count_database_files', return_value=0), \
         patch.object(db_manager, 'save_metadata'), \
         patch.object(db_manager, 'get_cached_database', return_value=None), \
         patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
         patch.object(db_manager, 'get_database_dir', return_value=db_path):
        result = db_manager.create_database(
            tmp_path, language, build_system, traced_build=traced_build,
        )
    return result, captured["cmd"]


# ---------------------------------------------------------------------------
# Version probe
# ---------------------------------------------------------------------------


class TestSupportsBuildlessCpp:
    def _probe(self, db_manager, version):
        with patch.object(db_manager, 'get_codeql_version', return_value=version):
            return db_manager.supports_buildless_cpp()

    def test_modern_cli_supported(self, db_manager):
        supported, detail = self._probe(db_manager, "2.26.3")
        assert supported
        assert detail == "2.26.3"

    def test_exact_minimum_supported(self, db_manager):
        supported, _ = self._probe(db_manager, "2.16.0")
        assert supported

    def test_old_cli_unsupported(self, db_manager):
        supported, detail = self._probe(db_manager, "2.15.5")
        assert not supported
        assert "2.16" in detail

    def test_missing_version_unsupported(self, db_manager):
        supported, detail = self._probe(db_manager, None)
        assert not supported
        assert "could not be determined" in detail

    def test_unparseable_version_unsupported(self, db_manager):
        supported, _detail = self._probe(db_manager, "release candidate")
        assert not supported

    def test_probe_is_cached_per_instance(self, db_manager):
        calls = []

        def counting(*a, **k):
            calls.append(1)
            return "2.26.3"

        with patch.object(db_manager, 'get_codeql_version', side_effect=counting):
            db_manager.supports_buildless_cpp()
            db_manager.supports_buildless_cpp()
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# Buildless is the C/C++ default
# ---------------------------------------------------------------------------


class TestBuildlessDefault:
    def test_cpp_is_a_buildless_default_language(self):
        assert "cpp" in BUILDLESS_DEFAULT_LANGUAGES

    def test_cpp_gets_build_mode_none(self, db_manager, tmp_path):
        result, cmd = _run_create(db_manager, tmp_path, language="cpp")
        assert result.success
        assert "--build-mode=none" in cmd

    def test_cpp_never_gets_a_build_command(self, db_manager, tmp_path):
        # Even when a build system WAS detected, buildless mode must
        # not pass --command — the repo's build never executes.
        result, cmd = _run_create(
            db_manager, tmp_path, language="cpp",
            build_system=_build_system(tmp_path, "make && ./configure"),
        )
        assert result.success
        assert "--build-mode=none" in cmd
        assert "--command" not in cmd

    def test_metadata_records_buildless(self, db_manager, tmp_path):
        result, _cmd = _run_create(
            db_manager, tmp_path, language="cpp",
            build_system=_build_system(tmp_path),
        )
        assert result.metadata.build_system == "buildless"
        assert result.metadata.build_command == ""

    def test_interpreted_language_unaffected(self, db_manager, tmp_path):
        result, cmd = _run_create(db_manager, tmp_path, language="javascript")
        assert result.success
        assert "--build-mode=none" not in cmd

    def test_java_defaults_to_buildless(self, db_manager, tmp_path):
        """Java autobuild executes gradlew/mvnw from the repo — the
        same code-execution vector the cpp gate closes, so java gets
        the same buildless default."""
        result, cmd = _run_create(
            db_manager, tmp_path, language="java",
            build_system=_build_system(tmp_path, "mvn"),
        )
        assert result.success
        assert "--build-mode=none" in cmd
        assert "--command" not in cmd

    def test_non_buildless_language_keeps_build_command(
            self, db_manager, tmp_path):
        result, cmd = _run_create(
            db_manager, tmp_path, language="go",
            build_system=_build_system(tmp_path, "go build ./..."),
        )
        assert result.success
        assert "--command" in cmd
        assert "--build-mode=none" not in cmd

    def test_csharp_is_buildless_by_default(self, db_manager, tmp_path):
        result, cmd = _run_create(db_manager, tmp_path, language="csharp")
        assert result.success
        assert "--build-mode=none" in cmd

    def test_java_traced_opt_in_keeps_build_command(self, db_manager, tmp_path):
        result, cmd = _run_create(
            db_manager, tmp_path, language="java",
            build_system=_build_system(tmp_path, "mvn"),
            traced_build=True,
        )
        assert result.success
        assert "--build-mode=none" not in cmd
        assert "--command" in cmd

    def test_java_old_cli_falls_back_to_traced_with_banner(
        self, db_manager, tmp_path, caplog,
    ):
        """java/csharp on a CLI without buildless keep the
        pre-existing traced behaviour — but loudly disclosed, never
        silently."""
        import logging
        with caplog.at_level(logging.WARNING):
            result, cmd = _run_create(
                db_manager, tmp_path, language="java",
                build_system=_build_system(tmp_path, "mvn"),
                version="2.15.5",
            )
        assert result.success
        assert "--build-mode=none" not in cmd
        assert "--command" in cmd
        joined = " ".join(r.getMessage() for r in caplog.records)
        assert "trust marker" in joined

    def test_go_traced_build_banners_without_trust(
        self, db_manager, tmp_path, caplog,
    ):
        """Languages with no buildless mode (go) keep autobuild but
        the untrusted-build banner must fire."""
        import logging
        with caplog.at_level(logging.WARNING):
            result, _cmd = _run_create(db_manager, tmp_path, language="go")
        assert result.success
        joined = " ".join(r.getMessage() for r in caplog.records)
        assert "trust marker" in joined

    def test_go_traced_build_no_banner_with_trust(
        self, db_manager, tmp_path, caplog,
    ):
        import logging
        with caplog.at_level(logging.WARNING):
            result, _cmd = _run_create(
                db_manager, tmp_path, language="go", traced_build=True,
            )
        assert result.success
        joined = " ".join(r.getMessage() for r in caplog.records)
        assert "trust marker" not in joined


# ---------------------------------------------------------------------------
# Explicit traced-build opt-in
# ---------------------------------------------------------------------------


class TestTracedOptIn:
    def test_traced_build_restores_command(self, db_manager, tmp_path):
        result, cmd = _run_create(
            db_manager, tmp_path, language="cpp",
            build_system=_build_system(tmp_path, "make"),
            traced_build=True,
        )
        assert result.success
        assert "--build-mode=none" not in cmd
        assert "--command" in cmd
        assert cmd[cmd.index("--command") + 1] == "make"

    def test_traced_build_skips_version_gate(self, db_manager, tmp_path):
        # Old CLI + explicit traced opt-in: the traced path never
        # needed build-mode support, so it must not be gated.
        result, cmd = _run_create(
            db_manager, tmp_path, language="cpp",
            build_system=_build_system(tmp_path, "make"),
            traced_build=True, version="2.12.0",
        )
        assert result.success
        assert "--build-mode=none" not in cmd


# ---------------------------------------------------------------------------
# Graceful degradation on old / absent CLI
# ---------------------------------------------------------------------------


class TestOldCliDegradation:
    def test_old_cli_clear_error_no_crash(self, db_manager, tmp_path):
        result, cmd = _run_create(
            db_manager, tmp_path, language="cpp", version="2.15.5",
        )
        assert not result.success
        assert result.database_path is None
        assert any("buildless" in e for e in result.errors)
        assert any("2.16" in e for e in result.errors)
        # Critically: database create was never invoked — no silent
        # fallback to a traced build.
        assert cmd is None

    def test_unknown_version_clear_error(self, db_manager, tmp_path):
        result, cmd = _run_create(
            db_manager, tmp_path, language="cpp", version=None,
        )
        assert not result.success
        assert cmd is None

    def test_error_mentions_explicit_opt_in(self, db_manager, tmp_path):
        result, _cmd = _run_create(
            db_manager, tmp_path, language="cpp", version="2.15.5",
        )
        joined = " ".join(result.errors)
        assert "--traced-build" in joined or "traced" in joined


# ---------------------------------------------------------------------------
# Parallel creation threads the per-language opt-in
# ---------------------------------------------------------------------------


class TestParallelThreading:
    def test_traced_languages_forwarded(self, db_manager, tmp_path):
        calls = {}

        shares = {}

        def fake_create(repo_path, lang, build_system, force,
                        audit_run_dir, traced_build=False,
                        concurrent_workers=1):
            calls[lang] = traced_build
            shares[lang] = concurrent_workers
            r = MagicMock()
            r.success = True
            return r

        with patch.object(db_manager, 'create_database', side_effect=fake_create):
            db_manager.create_databases_parallel(
                tmp_path,
                {"cpp": None, "javascript": None},
                traced_languages={"cpp"},
            )
        assert calls == {"cpp": True, "javascript": False}
        # Two concurrent builds share the cores two ways.
        assert set(shares.values()) == {2}

    def test_default_is_untraced(self, db_manager, tmp_path):
        calls = {}

        shares = {}

        def fake_create(repo_path, lang, build_system, force,
                        audit_run_dir, traced_build=False,
                        concurrent_workers=1):
            calls[lang] = traced_build
            shares[lang] = concurrent_workers
            r = MagicMock()
            r.success = True
            return r

        with patch.object(db_manager, 'create_database', side_effect=fake_create):
            db_manager.create_databases_parallel(tmp_path, {"cpp": None})
        assert calls == {"cpp": False}
        # A single build keeps the full-core auto value downstream.
        assert shares == {"cpp": 1}


# ---------------------------------------------------------------------------
# Agent skips build detection for buildless languages
# ---------------------------------------------------------------------------


class TestAgentBuildlessRouting:
    def _agent(self, tmp_path):
        from packages.codeql.agent import CodeQLAgent
        agent = CodeQLAgent.__new__(CodeQLAgent)
        agent.repo_path = tmp_path
        agent.out_dir = tmp_path / "out"
        agent.start_time = 0.0
        agent.language_detector = MagicMock()
        agent.build_detector = MagicMock()
        agent.database_manager = MagicMock()
        agent.query_runner = MagicMock()
        agent.build_detector.generate_no_build_config.return_value = BuildSystem(
            type="no-build", command="", working_dir=tmp_path,
            env_vars={}, confidence=1.0, detected_files=[],
        )
        agent.database_manager.create_databases_parallel.return_value = {}
        return agent

    def test_cpp_skips_build_detection(self, tmp_path):
        agent = self._agent(tmp_path)
        agent.database_manager.supports_buildless.return_value = (
            True, "2.26.3",
        )
        agent.run_autonomous_analysis(languages=["cpp"])
        agent.build_detector.detect_build_system.assert_not_called()
        agent.build_detector.synthesise_build_command.assert_not_called()
        agent.build_detector.generate_no_build_config.assert_called_with("cpp")
        _, kwargs = agent.database_manager.create_databases_parallel.call_args
        assert kwargs["traced_languages"] == set()

    def test_cpp_with_traced_build_runs_detection(self, tmp_path):
        agent = self._agent(tmp_path)
        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = None
        agent.run_autonomous_analysis(languages=["cpp"], traced_build=True)
        agent.build_detector.detect_build_system.assert_called_with("cpp")
        _, kwargs = agent.database_manager.create_databases_parallel.call_args
        assert kwargs["traced_languages"] == {"cpp"}

    def test_explicit_build_command_implies_traced(self, tmp_path):
        agent = self._agent(tmp_path)
        agent.run_autonomous_analysis(
            languages=["cpp"], build_commands={"cpp": "make"},
        )
        _, kwargs = agent.database_manager.create_databases_parallel.call_args
        assert kwargs["traced_languages"] == {"cpp"}
        lang_map = agent.database_manager.create_databases_parallel.call_args[0][1]
        assert lang_map["cpp"].command == "make"

    def test_old_cli_skips_language_with_error(self, tmp_path):
        agent = self._agent(tmp_path)
        agent.database_manager.supports_buildless.return_value = (
            False, "CodeQL 2.15.5 < 2.16 — cpp --build-mode=none unsupported",
        )
        result = agent.run_autonomous_analysis(languages=["cpp"])
        # cpp never reached database creation and never fell back to
        # a traced build; the workflow reports a clear error.
        lang_map = agent.database_manager.create_databases_parallel.call_args[0][1]
        assert "cpp" not in lang_map
        agent.build_detector.detect_build_system.assert_not_called()
        assert any("buildless" in e for e in result.errors)

    def test_java_routes_buildless_like_cpp(self, tmp_path):
        agent = self._agent(tmp_path)
        agent.database_manager.supports_buildless.return_value = (
            True, "2.26.3",
        )
        result = agent.run_autonomous_analysis(languages=["java"])
        agent.build_detector.detect_build_system.assert_not_called()
        agent.build_detector.generate_no_build_config.assert_called_with("java")
        assert result.untrusted_build_languages == []

    def test_untrusted_autobuild_language_recorded(self, tmp_path):
        """A compiled language with no buildless mode (go) executes
        repo build logic via autobuild — it must land in the run
        metadata when no trust was asserted."""
        agent = self._agent(tmp_path)
        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = None
        result = agent.run_autonomous_analysis(languages=["go"])
        assert result.untrusted_build_languages == ["go"]

    def test_trusted_autobuild_language_not_recorded(self, tmp_path):
        agent = self._agent(tmp_path)
        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = None
        result = agent.run_autonomous_analysis(
            languages=["go"], traced_build=True,
        )
        assert result.untrusted_build_languages == []


class TestBuildlessDegradationSummary:
    """Degradation visibility: unresolved-include diagnostics are
    counted and surfaced so reduced coverage never reads as full
    coverage in the run log."""

    def _db_with_diag(self, tmp_path, lines):
        db = tmp_path / "db"
        diag = db / "diagnostic"
        diag.mkdir(parents=True)
        (diag / "extraction.jsonl").write_text("\n".join(lines))
        return db

    def test_counts_unresolved_includes(self, tmp_path):
        from packages.codeql.database_manager import (
            buildless_degradation_summary,
        )
        db = self._db_with_diag(tmp_path, [
            '{"message": "could not find include file: config.h"}',
            '{"message": "cannot open include file generated/proto.pb.h"}',
            '{"message": "unrelated warning"}',
        ])
        hits, summary = buildless_degradation_summary(db)
        assert hits == 2
        assert "unresolved includes" in summary
        assert "--traced-build" in summary

    def test_clean_database_generic_notice(self, tmp_path):
        from packages.codeql.database_manager import (
            buildless_degradation_summary,
        )
        db = self._db_with_diag(tmp_path, [
            '{"message": "extraction completed"}',
        ])
        hits, summary = buildless_degradation_summary(db)
        assert hits == 0
        assert "without executing the build" in summary

    def test_missing_diagnostic_dir_is_generic_not_error(self, tmp_path):
        from packages.codeql.database_manager import (
            buildless_degradation_summary,
        )
        db = tmp_path / "db"
        db.mkdir()
        hits, summary = buildless_degradation_summary(db)
        assert hits == 0
        assert "without executing the build" in summary

    def test_non_json_files_ignored(self, tmp_path):
        from packages.codeql.database_manager import (
            buildless_degradation_summary,
        )
        db = self._db_with_diag(tmp_path, ['{"message": "ok"}'])
        (db / "diagnostic" / "notes.txt").write_text(
            "could not find include file: decoy.h"
        )
        hits, _ = buildless_degradation_summary(db)
        assert hits == 0


class TestTracedBuildTrustIndependence:
    """--traced-build does NOT imply --trust-repo, deliberately.

    The pack-config check is an anomaly alarm: legitimate projects
    essentially never carry custom CodeQL extractors or build hooks,
    and the alarm matters most on repos the operator otherwise
    trusts, where a poisoned analysis would be believed. A traced
    run hitting unsafe pack config must still refuse and print the
    findings; the operator escalates with --trust-repo only after
    auditing them. Capability-wise traced-build dominates, but trust
    encodes what the operator REVIEWED — the build system, not
    yaml-buried extractor hooks.
    """

    @pytest.fixture(autouse=True)
    def _reset_overrides(self):
        import core.security.cc_trust as cct
        import core.security.codeql_trust as qlt
        qlt.set_trust_override(False)
        cct.set_trust_override(False)
        yield
        qlt.set_trust_override(False)
        cct.set_trust_override(False)

    def _run_main(self, tmp_path, extra_args):
        """Drive agent.py main() on an empty repo (no languages ->
        fast no-op path); only the trust side effects of arg
        parsing matter here."""
        import contextlib

        import core.security.cc_trust as cct
        import core.security.codeql_trust as qlt
        from packages.codeql import agent as agent_mod
        argv = ["agent.py", "--repo", str(tmp_path),
                "--out", str(tmp_path / "out"), *extra_args]
        with patch.object(sys, "argv", argv), \
                contextlib.suppress(SystemExit):
            agent_mod.main()
        return (qlt._trust_override_set, cct._trust_override_set)

    def test_traced_build_sets_no_trust_override(self, tmp_path):
        ql, cc = self._run_main(tmp_path, ["--traced-build"])
        assert ql is False
        assert cc is False

    def test_default_sets_neither(self, tmp_path):
        ql, cc = self._run_main(tmp_path, [])
        assert ql is False
        assert cc is False


# ---------------------------------------------------------------------------
# Per-language probe + traced-failure buildless fallback
# ---------------------------------------------------------------------------


class TestSupportsBuildlessPerLanguage:
    def _probe(self, db_manager, language, version):
        with patch.object(db_manager, 'get_codeql_version',
                          return_value=version):
            return db_manager.supports_buildless(language)

    def test_java_modern_cli_supported(self, db_manager):
        supported, detail = self._probe(db_manager, "java", "2.26.3")
        assert supported
        assert detail == "2.26.3"

    def test_java_exact_minimum_supported(self, db_manager):
        supported, _ = self._probe(db_manager, "java", "2.16.4")
        assert supported

    def test_java_below_minimum_unsupported(self, db_manager):
        supported, detail = self._probe(db_manager, "java", "2.16.3")
        assert not supported
        assert "java" in detail

    def test_unknown_language_unsupported(self, db_manager):
        supported, detail = self._probe(db_manager, "go", "2.26.3")
        assert not supported
        assert "go" in detail

    def test_probe_cached_per_language(self, db_manager):
        with patch.object(db_manager, 'get_codeql_version',
                          return_value="2.26.3") as gv:
            db_manager.supports_buildless("java")
            db_manager.supports_buildless("java")
            db_manager.supports_buildless("cpp")
        assert gv.call_count == 2  # one probe per language, then cached

    def test_java_in_buildless_defaults(self):
        assert "java" in BUILDLESS_DEFAULT_LANGUAGES


class TestBuildlessFallback:
    def _run_with_failure_then_success(self, db_manager, tmp_path, *,
                                       language, traced_build):
        """First (traced) create fails; a buildless retry succeeds."""
        calls = []

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.stdout = ""
            if "database" in cmd and "create" in cmd:
                calls.append(list(cmd))
                if "--build-mode=none" in cmd:
                    r.returncode = 0
                    r.stderr = "Finalizing database.\n"
                else:
                    r.returncode = 1
                    r.stderr = "autobuild failed\n"
            else:
                r.returncode = 0
                r.stderr = ""
            return r

        db_path = tmp_path / "db"
        with patch('core.sandbox.run', side_effect=fake_run), \
             patch.object(db_manager, 'get_codeql_version',
                          return_value="2.26.3"), \
             patch.object(db_manager, '_count_database_files',
                          return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, '_salvage_creation_log',
                          return_value=""), \
             patch.object(db_manager, 'get_cached_database',
                          return_value=None), \
             patch.object(db_manager, 'compute_repo_hash',
                          return_value='abc'), \
             patch.object(db_manager, 'get_database_dir',
                          return_value=db_path):
            result = db_manager.create_database(
                tmp_path, language,
                _build_system(tmp_path, "mvn package"),
                traced_build=traced_build,
            )
        return result, calls

    def test_traced_java_failure_falls_back_to_buildless(
            self, db_manager, tmp_path):
        result, calls = self._run_with_failure_then_success(
            db_manager, tmp_path, language="java", traced_build=True)
        assert len(calls) == 2
        assert "--command" in calls[0] or "--build-mode=none" not in calls[0]
        assert "--build-mode=none" in calls[1]
        assert result.success
        assert any("buildless fallback" in e for e in result.errors)

    def test_untraced_failure_never_recurses(self, db_manager, tmp_path):
        # go is not buildless-capable: a plain failure returns failure,
        # exactly one create attempt.
        result, calls = self._run_with_failure_then_success(
            db_manager, tmp_path, language="go", traced_build=False)
        assert len(calls) == 1
        assert not result.success

    def test_fallback_skipped_below_version_floor(
            self, db_manager, tmp_path):
        calls = []

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.stdout = ""
            r.stderr = "autobuild failed\n"
            r.returncode = 1
            if "database" in cmd and "create" in cmd:
                calls.append(list(cmd))
            return r

        db_path = tmp_path / "db"
        with patch('core.sandbox.run', side_effect=fake_run), \
             patch.object(db_manager, 'get_codeql_version',
                          return_value="2.16.3"), \
             patch.object(db_manager, '_count_database_files',
                          return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, '_salvage_creation_log',
                          return_value=""), \
             patch.object(db_manager, 'get_cached_database',
                          return_value=None), \
             patch.object(db_manager, 'compute_repo_hash',
                          return_value='abc'), \
             patch.object(db_manager, 'get_database_dir',
                          return_value=db_path):
            result = db_manager.create_database(
                tmp_path, "java", _build_system(tmp_path, "mvn package"),
                traced_build=True,
            )
        assert len(calls) == 1
        assert not result.success
