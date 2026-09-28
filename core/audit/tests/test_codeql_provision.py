"""CodeQL database provisioning for standalone /audit.

Discovery-before-build order, the no-target-build-commands build
gate, the trust gate for autobuild languages, the bounded await, and
the loud report degradation for languages left without a database.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace

import pytest

import packages.codeql.database_manager as dbm
import packages.codeql.language_detector as ldet
from core.audit.codeql_provision import (
    STATUS_FILENAME,
    await_provisioned_dbs,
    discover_codeql_dbs,
    load_provision_status,
    provision_codeql_dbs,
    stamp_run_config_dbs,
    validate_db_paths,
)


class _FakeManager:
    def __init__(
        self,
        cached: dict[str, Path] | None = None,
        buildless: frozenset[str] = frozenset({"cpp", "java", "csharp"}),
        built: dict[str, Path] | None = None,
    ):
        self.cached = cached or {}
        self.buildless = buildless
        self.built = built or {}
        self.cache_probes: list[str] = []
        self.build_calls: list[dict] = []

    def get_cached_database(self, repo_path, language, max_age_days=7):
        self.cache_probes.append(language)
        return self.cached.get(language)

    def supports_buildless(self, language):
        if language in self.buildless:
            return True, ""
        return False, "no buildless mode for this language"

    def create_databases_parallel(
        self, repo_path, language_build_map,
        audit_run_dir=None, traced_languages=None,
    ):
        self.build_calls.append({
            "languages": sorted(language_build_map),
            "traced": set(traced_languages or ()),
        })
        results = {}
        for lang in language_build_map:
            path = self.built.get(lang)
            results[lang] = SimpleNamespace(
                success=path is not None,
                database_path=path,
                errors=[] if path is not None else ["extractor failed"],
            )
        return results


class _FakeDetector:
    languages: dict[str, object] = {}

    def __init__(self, target):
        pass

    def detect_languages(self, min_files=3):
        return dict(self.languages)

    def filter_codeql_supported(self, detected):
        return detected


@pytest.fixture
def fake_env(monkeypatch, tmp_path):
    """Stub the manager + detector; returns the fake manager holder."""
    holder: dict[str, object] = {"manager": _FakeManager()}
    monkeypatch.setattr(
        dbm, "DatabaseManager", lambda: holder["manager"],
    )
    monkeypatch.setattr(ldet, "LanguageDetector", _FakeDetector)
    monkeypatch.setattr(_FakeDetector, "languages", {})
    # Explicit traced_build values bypass the project store; the
    # default-None tests stub the resolver instead.
    import core.project.trust as trust
    monkeypatch.setattr(
        trust, "resolve_build_execution",
        lambda explicit, **kw: bool(explicit),
    )
    return holder


def _wait(provision, timeout=10):
    if provision.build_future is None:
        return []
    return provision.build_future.result(timeout=timeout)


class TestDiscovery:
    def test_cached_database_is_reused_without_building(
        self, fake_env, tmp_path,
    ):
        db = tmp_path / "cpp-db"
        fake_env["manager"] = _FakeManager(cached={"cpp": db})
        _FakeDetector.languages = {"cpp": object()}
        provision = provision_codeql_dbs(tmp_path)
        assert provision.db_paths == [str(db)]
        assert provision.building_languages == []
        assert provision.build_future is None
        assert provision.skipped == []

    def test_stale_cache_miss_falls_through_to_build(
        self, fake_env, tmp_path,
    ):
        # get_cached_database owns the staleness stamps (repo hash +
        # TTL); a miss (stale/absent) must trigger a build, never a
        # reuse of a wrong-tree database.
        built = tmp_path / "python-db"
        fake_env["manager"] = _FakeManager(built={"python": built})
        _FakeDetector.languages = {"python": object()}
        provision = provision_codeql_dbs(tmp_path)
        assert provision.db_paths == []
        assert provision.building_languages == ["python"]
        assert _wait(provision) == [str(built)]
        assert fake_env["manager"].cache_probes == ["python"]


class TestBuildGate:
    def test_extractor_only_language_builds_untrusted(
        self, fake_env, tmp_path,
    ):
        built = tmp_path / "python-db"
        fake_env["manager"] = _FakeManager(built={"python": built})
        _FakeDetector.languages = {"python": object()}
        provision = provision_codeql_dbs(tmp_path, traced_build=False)
        assert provision.building_languages == ["python"]
        _wait(provision)
        assert fake_env["manager"].build_calls[0]["traced"] == set()

    def test_buildless_compiled_builds_untrusted_untraced(
        self, fake_env, tmp_path,
    ):
        built = tmp_path / "cpp-db"
        fake_env["manager"] = _FakeManager(built={"cpp": built})
        _FakeDetector.languages = {"cpp": object()}
        provision = provision_codeql_dbs(tmp_path, traced_build=False)
        assert provision.building_languages == ["cpp"]
        assert provision.skipped == []
        _wait(provision)
        assert fake_env["manager"].build_calls[0]["traced"] == set()

    def test_autobuild_language_skipped_without_trust(
        self, fake_env, tmp_path,
    ):
        fake_env["manager"] = _FakeManager()
        _FakeDetector.languages = {"go": object()}
        provision = provision_codeql_dbs(tmp_path, traced_build=False)
        assert provision.building_languages == []
        assert provision.build_future is None
        assert len(provision.skipped) == 1
        skip = provision.skipped[0]
        assert skip.language == "go"
        assert "build logic" in skip.reason
        assert "--codeql-db" in skip.remedy
        assert "/project trust build" in skip.remedy

    def test_trust_marker_authorises_traced_build(
        self, fake_env, tmp_path,
    ):
        built = tmp_path / "go-db"
        fake_env["manager"] = _FakeManager(built={"go": built})
        _FakeDetector.languages = {"go": object()}
        provision = provision_codeql_dbs(tmp_path, traced_build=True)
        assert provision.building_languages == ["go"]
        assert provision.skipped == []
        _wait(provision)
        assert fake_env["manager"].build_calls[0]["traced"] == {"go"}

    def test_build_gate_receives_out_dir_as_run_dir(
        self, fake_env, tmp_path, monkeypatch,
    ):
        """default-None resolution must consult the RUN PIN's project
        (``run_dir=out_dir``), not the ambient session — an autobuild
        language under a pinned run otherwise gains/loses the 'build'
        marker of whatever project the SESSION happens to be bound
        to."""
        import core.project.trust as trust

        seen: dict = {}

        def fake_gate(traced, *, banner=True, target_path=None,
                      run_dir=None):
            seen["run_dir"] = run_dir
            return False

        monkeypatch.setattr(trust, "resolve_build_execution", fake_gate)
        _FakeDetector.languages = {"go": object()}
        target = tmp_path / "repo"
        target.mkdir()
        out_dir = tmp_path / "audit-out"
        out_dir.mkdir()
        provision_codeql_dbs(target, out_dir=out_dir, traced_build=None)
        assert "run_dir" in seen, "build gate never consulted"
        assert seen["run_dir"] == out_dir

    def test_kill_switch_short_circuits(self, fake_env, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)
        _FakeDetector.languages = {"python": object()}
        provision = provision_codeql_dbs(tmp_path)
        assert provision.db_paths == []
        assert provision.build_future is None
        assert provision.skipped
        assert "tuning.json" in provision.skipped[0].reason


class TestStatusAndAwait:
    def test_status_written_and_loud_failures_recorded(
        self, fake_env, tmp_path,
    ):
        out = tmp_path / "out"
        out.mkdir()
        fake_env["manager"] = _FakeManager()
        _FakeDetector.languages = {"go": object()}
        provision = provision_codeql_dbs(
            tmp_path, out_dir=out, traced_build=False,
        )
        status = load_provision_status(out)
        assert status is not None
        assert status["skipped"][0]["language"] == "go"
        assert provision.build_future is None

    def test_await_returns_built_paths_and_updates_status(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        fut: Future = Future()
        fut.set_result(["/dbs/python-db"])
        assert await_provisioned_dbs(fut, out_dir=out) == ["/dbs/python-db"]
        assert load_provision_status(out)["built"] == ["/dbs/python-db"]

    def test_await_timeout_degrades_and_records(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        fut: Future = Future()  # never completes
        assert await_provisioned_dbs(fut, out_dir=out, timeout_s=0.05) == []
        status = load_provision_status(out)
        assert status["build_timed_out"] is True
        assert status["build_wait_stopped"] == "deadline"

    def test_await_clamps_to_run_deadline(self, tmp_path):
        # Near-deadline join must conclude before the wall bound —
        # the margin eats the whole budget here, so it returns at
        # once instead of waiting out timeout_s.
        fut: Future = Future()  # never completes
        start = time.monotonic()
        got = await_provisioned_dbs(
            fut, out_dir=tmp_path, timeout_s=900.0,
            deadline_monotonic=time.monotonic() + 5.0,
        )
        assert got == []
        assert time.monotonic() - start < 2.0

    def test_await_abort_interrupts_the_join(self, tmp_path):
        # SIGTERM/environment-guard during the join must salvage
        # promptly, not after the full wait budget.
        fut: Future = Future()  # never completes
        polls = {"n": 0}

        def abort() -> bool:
            polls["n"] += 1
            return polls["n"] >= 2

        start = time.monotonic()
        got = await_provisioned_dbs(
            fut, out_dir=tmp_path, timeout_s=900.0, should_abort=abort,
        )
        assert got == []
        assert time.monotonic() - start < 30.0
        status = load_provision_status(tmp_path)
        assert status["build_wait_stopped"] == "abort"
        # A shutdown is not a wait-budget timeout — the record (and
        # the report wording keyed off it) must not conflate them.
        assert status["build_aborted"] is True
        assert "build_timed_out" not in status

    def test_await_build_failure_degrades_and_records(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        fut: Future = Future()
        fut.set_exception(RuntimeError("extractor exploded"))
        assert await_provisioned_dbs(fut, out_dir=out) == []
        assert load_provision_status(out)["build_failed"] is True

    def test_await_none_future_is_noop(self, tmp_path):
        assert await_provisioned_dbs(None, out_dir=tmp_path) == []


class TestReportSurfacing:
    def test_report_names_missing_db_and_remedy(self, tmp_path):
        from core.audit.report import generate_report

        (tmp_path / STATUS_FILENAME).write_text(json.dumps({
            "discovered": [],
            "building": [],
            "skipped": [{
                "language": "cpp",
                "reason": "extraction for cpp would execute the "
                          "target's build logic",
                "remedy": "pass --codeql-db <path>, or authorise the "
                          "build with `/project trust build`",
            }],
        }))
        report = generate_report(tmp_path)
        assert report["codeql_provision"]["skipped"]
        assert "CodeQL database(s) missing" in report["summary"]
        assert "--codeql-db" in report["summary"]
        assert "/project trust build" in report["summary"]
        assert "skipped, not refuted" in report["summary"]

    def test_report_words_abort_distinctly(self, tmp_path):
        from core.audit.report import generate_report

        (tmp_path / STATUS_FILENAME).write_text(json.dumps({
            "discovered": [],
            "building": ["cpp"],
            "skipped": [],
            "build_aborted": True,
            "build_wait_stopped": "abort",
        }))
        report = generate_report(tmp_path)
        assert "interrupted by a shutdown request" in report["summary"]
        assert "wait budget" not in report["summary"]

    def test_report_quiet_when_provisioning_succeeded(self, tmp_path):
        from core.audit.report import generate_report

        (tmp_path / STATUS_FILENAME).write_text(json.dumps({
            "discovered": ["/dbs/cpp-db"],
            "building": [],
            "skipped": [],
        }))
        report = generate_report(tmp_path)
        assert "codeql_provision" not in report
        assert "CodeQL database(s) missing" not in report["summary"]


class TestResumeRevalidation:
    def test_validate_db_paths_drops_evicted(self, tmp_path):
        good = tmp_path / "cpp-db"
        good.mkdir()
        (good / "codeql-database.yml").write_text("primaryLanguage: cpp\n")
        structural_miss = tmp_path / "empty-db"
        structural_miss.mkdir()
        gone = tmp_path / "evicted-db"
        assert validate_db_paths(
            [str(good), str(structural_miss), str(gone)],
        ) == [str(good)]
        assert validate_db_paths(None) == []

    def test_discover_probe_returns_cache_hits(
        self, fake_env, tmp_path,
    ):
        db = tmp_path / "python-db"
        fake_env["manager"] = _FakeManager(cached={"python": db})
        _FakeDetector.languages = {"python": object()}
        assert discover_codeql_dbs(tmp_path) == [str(db)]

    def test_stamp_merges_built_paths_into_run_config(self, tmp_path):
        from core.audit.resume import load_run_config, save_run_config

        save_run_config(tmp_path, {
            "version": 1,
            "codeql_db_path": "/dbs/cpp-db",
            "codeql_db_paths": ["/dbs/cpp-db"],
        })
        stamp_run_config_dbs(tmp_path, ["/dbs/python-db", "/dbs/cpp-db"])
        cfg = load_run_config(tmp_path)
        assert cfg["codeql_db_paths"] == ["/dbs/cpp-db", "/dbs/python-db"]
        assert cfg["codeql_db_path"] == "/dbs/cpp-db"


class TestTrustSeamIntegration:
    """traced_build=None defers to the project build marker via the
    REAL resolve_build_execution — only the project-store reads are
    stubbed. (These tests build their own stubs instead of using
    fake_env, whose fixture replaces the resolver.)"""

    def _stub_env(self, monkeypatch, manager):
        monkeypatch.setattr(dbm, "DatabaseManager", lambda: manager)
        monkeypatch.setattr(ldet, "LanguageDetector", _FakeDetector)

    def test_marker_resolution_through_real_seam(
        self, tmp_path, monkeypatch,
    ):
        import core.project.trust as trust

        built = tmp_path / "go-db"
        manager = _FakeManager(built={"go": built})
        self._stub_env(monkeypatch, manager)
        monkeypatch.setattr(_FakeDetector, "languages", {"go": object()})
        monkeypatch.setattr(
            trust, "active_project_trust",
            lambda run_dir=None: ({"build"}, "proj"),
        )
        monkeypatch.setattr(
            trust, "run_target_matches_project",
            lambda target, run_dir=None: True,
        )
        provision = provision_codeql_dbs(tmp_path, traced_build=None)
        assert provision.building_languages == ["go"]
        provision.build_future.result(timeout=10)
        assert manager.build_calls[0]["traced"] == {"go"}

    def test_no_marker_skips_through_real_seam(
        self, tmp_path, monkeypatch,
    ):
        import core.project.trust as trust

        manager = _FakeManager()
        self._stub_env(monkeypatch, manager)
        monkeypatch.setattr(_FakeDetector, "languages", {"go": object()})
        monkeypatch.setattr(
            trust, "active_project_trust",
            lambda run_dir=None: (set(), None),
        )
        provision = provision_codeql_dbs(tmp_path, traced_build=None)
        assert provision.building_languages == []
        assert provision.skipped
        assert provision.skipped[0].language == "go"

