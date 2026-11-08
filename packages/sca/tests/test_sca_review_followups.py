"""Regression contracts for safe SCA readback, isolation and machine workflows."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar, copy_context
from datetime import datetime, timedelta, timezone
from importlib import import_module
import json
from threading import Barrier

import pytest

from core.testing.logging_state import isolated_cli_logging
from packages.sca import cli, pipeline
from packages.sca.finding_stream import FindingsFile
from packages.sca.resolvers import bundler
from packages.sca.resolvers._cache import manifest_hash
from packages.sca.sbom_inventory.advisory_coverage import read_coverage
from packages.sca.sbom_inventory.model import Inventory, Record
from packages.sca.sbom_inventory.output import record_chunks
from packages.sca.sbom_inventory.statistics import statistics
from packages.sca.tests.test_thresholds import _vuln
from packages.sca.thresholds import evaluate, ThresholdConfig


@pytest.fixture(autouse=True)
def owned_cache_policy(tmp_path, monkeypatch):
    from packages.sca.resolvers import _cache
    monkeypatch.setattr(_cache, "_OVERRIDE_CONFIG_PATH", tmp_path / "proxy-hosts.json")


@pytest.mark.parametrize("name", ("npm", "pnpm", "yarn", "composer", "cargo", "gomod", "nuget", "poetry", "bundler"))
def test_resolver_readback_refuses_links_and_oversize(tmp_path, name):
    reader = import_module("packages.sca.resolvers." + name)._read_if_exists
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"owned sentinel")
    link = tmp_path / "lock"
    link.symlink_to(sentinel)
    assert reader(link) is None
    link.unlink()
    with link.open("wb") as stream:
        stream.truncate(50 * 1024 * 1024 + 1)
    assert reader(link) is None
    link.write_bytes(b"valid")
    assert reader(link) == b"valid"


def test_bundler_cache_tracks_consumed_gemspec(tmp_path):
    (tmp_path / "Gemfile").write_text("gemspec\n")
    spec = tmp_path / "example.gemspec"
    spec.write_text("first")
    before = manifest_hash(bundler.BundlerResolver(), tmp_path)
    spec.write_text("second")
    assert manifest_hash(bundler.BundlerResolver(), tmp_path) != before


@pytest.mark.parametrize("row", (None, _vuln("critical", suppressed="false"), _vuln("unexpected")))
def test_active_gate_refuses_malformed_findings(row):
    with pytest.raises(ValueError):
        evaluate([row], ThresholdConfig(fail_on_severity="high"))


def test_incomplete_gate_is_opt_in_and_cannot_be_suppressed():
    row = {"vuln_type": "sca:scan_health:lookup", "severity": "info", "description": "unavailable", "suppressed": True}
    assert evaluate([row], ThresholdConfig(fail_on_severity="high"))[0]
    assert not evaluate([row], ThresholdConfig(fail_on_incomplete=True))[0]


def test_context_settings_are_isolated_and_propagated(monkeypatch):
    from packages.sca.parsers import requirements, pom_inheritance
    from packages.sca.resolvers import pip
    monkeypatch.setattr(requirements, "_INCLUDE_COMMENTED", ContextVar("test_requirements", default=False))
    monkeypatch.setattr(pip, "_ALLOW_SDIST_BUILDS_DEFAULT", ContextVar("test_pip", default=False))
    monkeypatch.setattr(pom_inheritance, "_RESOLVER", ContextVar("test_pom", default=None))
    barrier = Barrier(2)
    def worker(value):
        requirements.set_include_commented(value)
        pip.set_allow_sdist_builds(value)
        pom_inheritance.set_inheritance_resolver(value)
        barrier.wait(timeout=5)
        return (requirements._INCLUDE_COMMENTED.get(), pip.PipResolver().allow_sdist_builds,
                pom_inheritance.get_inheritance_resolver())
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(copy_context().run, worker, value) for value in (True, False)]
        assert [future.result(timeout=5) for future in futures] == [(True, True, True), (False, False, False)]
    assert requirements._INCLUDE_COMMENTED.get() is False
    assert pip.PipResolver().allow_sdist_builds is False
    assert pom_inheritance.get_inheritance_resolver() is None



def test_findings_file_is_repeatable_and_bounded(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text('[{"id":"a"},{"id":"b"}]')
    rows = FindingsFile(path)
    assert len(rows) == 2
    assert list(rows) == list(rows) == rows[:]
    with pytest.raises(ValueError):
        list(FindingsFile(path, max_bytes=4))


@isolated_cli_logging()
def test_explain_plan_has_no_scan_or_output_side_effects(tmp_path, monkeypatch, capsys):
    def unexpected(**kwargs):
        pytest.fail("plan preview executed a scan")
    monkeypatch.setattr(cli, "run_sca", unexpected)
    out = tmp_path / "out"
    assert cli.main([str(tmp_path), "--profile", "fast", "--explain-plan", "--out", str(out)]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert not plan["native_resolution"] and not plan["llm_review"] and not plan["image_scanning"]
    assert not out.exists()


def test_ambiguous_fix_target_is_rejected(capsys):
    assert cli.main(["fix", "project", "--findings", "findings.json"]) == 2
    assert "choose" in capsys.readouterr().err


def test_statistics_preserve_gpl_versions_and_compound_choices():
    inv = Inventory("test", "a" * 64, records=[
        Record("a", "a", "1", "library", declarations=["GPL-2.0-only OR MIT"]),
        Record("b", "b", "1", "library", declarations=["GPL-3.0-only"]),
        Record("c", "c", "1", "library", scope="source-candidates", declarations=["MIT"])])
    result = statistics(inv, inv.records)
    packages = result["selection_scopes"]["packages"]
    assert packages["license_operands"] == {"GPL-2.0-only": 1, "GPL-3.0-only": 1, "MIT": 1}
    assert packages["license_expressions"]["GPL-2.0-only OR MIT"] == 1
    assert result["selection_scopes"]["source-candidates"]["records"] == 1


def test_selected_record_exports_are_explicit_and_parseable():
    inv = Inventory("test", "a" * 64, records=[Record("a", "a", "1", "library"), Record("b", "b", "1", "library")])
    selected = inv.records[:1]
    document = json.loads("".join(record_chunks(inv, selected)))
    assert document["selection_only"] is True and len(document["records"]) == 1
    lines = "".join(record_chunks(inv, selected, jsonl=True)).splitlines()
    assert json.loads(lines[0])["record"]["id"] == "a"


def test_receipt_age_policy_is_explicit_and_rejects_stale_or_unknown(tmp_path):
    now = datetime.now(timezone.utc)
    path = tmp_path / "coverage.json"
    data = {"format": "raptor-sca-advisory-coverage", "schema_version": 1,
            "sources": {"findings.json": "a" * 64, "sbom.cdx.json": "b" * 64}, "queries": []}
    path.write_text(json.dumps(data))
    assert not read_coverage(path, "b" * 64, "a" * 64)[2]
    assert read_coverage(path, "b" * 64, "a" * 64, max_age_hours=24, now=now)[2]
    data["generated_at"] = (now - timedelta(hours=25)).isoformat()
    path.write_text(json.dumps(data))
    assert read_coverage(path, "b" * 64, "a" * 64, max_age_hours=24, now=now)[2]
    data["generated_at"] = now.isoformat()
    path.write_text(json.dumps(data))
    assert not read_coverage(path, "b" * 64, "a" * 64, max_age_hours=24, now=now)[2]


@pytest.mark.parametrize("profile", ("full", "mechanical", "fast", "offline"))
@isolated_cli_logging()
def test_profiles_match_their_plan(tmp_path, capsys, profile):
    assert cli.main([str(tmp_path), "--profile", profile, "--explain-plan"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["llm_review"] == (profile == "full")
    assert plan["native_resolution"] == (profile in {"full", "mechanical"})
    assert plan["network_enabled"] == (profile != "offline")


def test_run_context_restores_settings_on_exception(tmp_path, monkeypatch):
    from core.json import JsonCache
    from packages.sca.resolvers import pip
    monkeypatch.setattr(pip, "_ALLOW_SDIST_BUILDS_DEFAULT", ContextVar("test_run_sdist", default=False))
    monkeypatch.setattr(pipeline, "sca_cache_root", lambda: tmp_path / "cache")
    cleaned = []
    def fail(*args, resource_stack, **kwargs):
        resource_stack.callback(cleaned.append, "closed")
        pip.set_allow_sdist_builds(True)
        raise RuntimeError("owned failure")
    monkeypatch.setattr(pipeline, "_run_sca", fail)
    with pytest.raises(RuntimeError, match="owned failure"):
        pipeline.run_sca(tmp_path, tmp_path / "out", cache=JsonCache(root=tmp_path / "cache"))
    assert not pip.PipResolver().allow_sdist_builds
    assert cleaned == ["closed"]
    report = json.loads((tmp_path / "out" / "scan-summary.json").read_text())
    assert report["status"] == "failed" and report["error_type"] == "RuntimeError"


def test_sbom_only_plan_does_not_claim_source_reachability(tmp_path, capsys):
    with isolated_cli_logging():
        assert cli.main([str(tmp_path), "--sbom", "release.json", "--explain-plan"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert not plan["reachability"] and not plan["native_resolution"] and not plan["image_scanning"]


def test_supply_chain_can_check_packages_without_walking_source(tmp_path, monkeypatch):
    from packages.sca import supply_chain
    def unexpected(*args, **kwargs):
        pytest.fail("SBOM-only operation walked unrelated source")
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, supply_chain, "_artefacts", "scan_target", unexpected)
    patch_module_attribute(monkeypatch, supply_chain, "_gha_drift", "scan_target", unexpected)
    assert supply_chain.evaluate(tmp_path, [], [], source_checks=False) == []


@isolated_cli_logging()
def test_stats_and_selected_exports_public_cli(tmp_path, capsys):
    source = tmp_path / "sbom.json"
    source.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [{"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1", "licenses": [{"license": {"id": "MIT"}}]},
                       {"type": "library", "name": "b", "version": "1", "purl": "pkg:npm/b@1"}]}))
    assert cli.main(["sbom", "stats", str(source), "--scope", "packages"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["selection_scopes"]["packages"]["unresolved_declarations"] == 1
    assert cli.main(["sbom", "inspect", str(source), "--unresolved", "--format", "jsonl"]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["record"]["name"] == "b" and exported["selection_only"]
    assert cli.main(["sbom", "inspect", str(source), "--license", "MIT", "--format", "json", "--records-only"]) == 0
    assert len(json.loads(capsys.readouterr().out)["records"]) == 1



def test_cache_context_ignores_launch_state_but_tracks_registry_and_policy(tmp_path, monkeypatch):
    from packages.sca.resolvers import _cache
    class Resolver:
        ecosystem = "PyPI"
        MANIFEST_FILES = ("requirements.txt",)
        CACHE_ENV_KEYS = ("PIP_INDEX_URL",)
        @property
        def proxy_hosts(self):
            pytest.fail("cache identity triggered proxy calibration")
    source = tmp_path / "requirements.txt"
    source.write_text("example==1\n")
    resolver = Resolver()
    before = manifest_hash(resolver, tmp_path)
    monkeypatch.setenv("RAPTOR_SESSION_PID", "owned-session")
    assert manifest_hash(resolver, tmp_path) == before
    monkeypatch.setenv("PIP_INDEX_URL", "https://example.invalid/simple")
    changed = manifest_hash(resolver, tmp_path)
    assert changed != before
    _cache._OVERRIDE_CONFIG_PATH.write_text('{"pip": []}')
    assert manifest_hash(resolver, tmp_path) != changed



def test_streamed_snapshot_preserves_complete_inventory_and_selection():
    from packages.sca.sbom_inventory.output import inventory_chunks, inventory_document
    inv = Inventory("test", "a" * 64, records=[Record("a", "©", "1", "library"), Record("b", "b", "1", "library")])
    stream = "".join(inventory_chunks(inv, inv.records[:1]))
    assert json.loads(stream) == inventory_document(inv, inv.records[:1])
    assert len(json.loads(stream)["records"]) == 2
    inv.notice_verification = "verified"
    snapshot = inv.to_dict()
    assert "notice_verification" not in snapshot
    from packages.sca.sbom_inventory.model import from_snapshot
    assert from_snapshot(snapshot).notice_verification == "not_recorded"



def test_sarif_stream_matches_builder_and_rolls_back_late_failure(tmp_path):
    from datetime import datetime, timezone
    from packages.sca.sarif import build_sarif, write_sarif
    stamp = datetime(2026, 11, 7, tzinfo=timezone.utc)
    rows = [_vuln("high"), {"vuln_type": "sca:hygiene:lockfile_missing", "severity": "info", "description": "missing"}]
    out = tmp_path / "findings.sarif"
    assert write_sarif(out, target=tmp_path, rows=iter(rows), generated_at=stamp) == 2
    original = out.read_bytes()
    assert json.loads(original) == build_sarif(target=tmp_path, rows=rows, generated_at=stamp)
    def failing_rows():
        yield rows[0]
        raise ValueError("late failure")
    with pytest.raises(ValueError, match="late failure"):
        write_sarif(out, target=tmp_path, rows=failing_rows(), generated_at=stamp)
    assert out.read_bytes() == original


def test_report_bounds_details_but_counts_all_findings(tmp_path, monkeypatch):
    from packages.sca import reporting
    monkeypatch.setattr(reporting, "MAX_FINDINGS", 1)
    rows = [_vuln("high"), _vuln("high", kev=True)]
    context, document = reporting.build_sca_document(rows=iter(rows), target=tmp_path, output_dir=tmp_path, deps_analysed=2)
    assert context.extensions["raptor.accounting"] == {"recorded_rows": 2, "captured_rows": 1}
    assert document.summary["KEV matches"] == 1
    assert any("truncated" in message.lower() for message in context.diagnostics)



@pytest.mark.parametrize("module,cls,base,extra", (
    ("gomod", "GoResolver", "go.mod", "main.go"),
    ("nuget", "NugetResolver", "packages.lock.json", "example.csproj"),
))
def test_dynamic_resolver_inputs_invalidate_cache(tmp_path, module, cls, base, extra):
    resolver = getattr(import_module("packages.sca.resolvers." + module), cls)()
    (tmp_path / base).write_text("base")
    source = tmp_path / extra
    source.write_text("first")
    before = manifest_hash(resolver, tmp_path)
    source.write_text("changed")
    assert manifest_hash(resolver, tmp_path) != before


def test_pip_cache_bypasses_dynamic_and_included_inputs(tmp_path):
    from packages.sca.resolvers.pip import PipResolver
    req = tmp_path / "requirements.txt"
    req.write_text("example==1\n")
    assert manifest_hash(PipResolver(), tmp_path)
    req.write_text("-r requirements-base.txt\n")
    assert manifest_hash(PipResolver(), tmp_path) is None
    req.write_text("example==1\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='example'\n")
    assert manifest_hash(PipResolver(), tmp_path) is None



def test_cache_fingerprinting_has_a_total_byte_budget(tmp_path, monkeypatch):
    from packages.sca.resolvers import _cache
    class Resolver:
        ecosystem = "test"
        MANIFEST_FILES = ("a", "b")
    (tmp_path / "a").write_bytes(b"first")
    (tmp_path / "b").write_bytes(b"second")
    monkeypatch.setattr(_cache, "_MAX_INPUT_BYTES", 8)
    assert manifest_hash(Resolver(), tmp_path) is None


def test_actual_cascade_workers_receive_the_scan_context(tmp_path, monkeypatch):
    from packages.sca import transitive
    from packages.sca.resolvers import pip
    monkeypatch.setattr(pip, "_ALLOW_SDIST_BUILDS_DEFAULT", ContextVar("test_worker_sdist", default=True))
    def batch(ecosystem, items, cache):
        return [(project, manifest, [], str(pip.PipResolver().allow_sdist_builds)) for project, manifest in items]
    monkeypatch.setattr(transitive, "_try_cascade_batch", batch)
    result = transitive._run_cascades_parallel({"PyPI": [(tmp_path, tmp_path / "requirements.txt")]})
    assert result[("PyPI", tmp_path)] == ([], "True")



@isolated_cli_logging()
def test_statistics_cannot_replace_its_input(tmp_path, capsys):
    source = tmp_path / "sbom.json"
    original = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []})
    source.write_text(original)
    assert cli.main(["sbom", "stats", str(source), "--out", str(source)]) == 2
    assert source.read_text() == original
    assert "differ from the input" in capsys.readouterr().err
