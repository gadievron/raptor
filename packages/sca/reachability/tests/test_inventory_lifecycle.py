"""Exercise real reachability tiers while stubbing incidental inventory startup."""

import importlib
import logging
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.atomic_fs import rmtree_hardened
from core.inventory import builder
from core.run import scratch
from packages.sca import reachability
from packages.sca.models import Advisory, Confidence, Dependency, PinStyle, Reachability
from packages.sca.osv import OsvResult


TIERS = [
    ("python", "pypi", "PyPI"), ("npm", "npm", "npm"),
    ("go", "go", "Go"), ("java", "maven", "Maven"),
    ("cargo", "cargo", "Cargo"), ("rubygems", "rubygems", "RubyGems"),
    ("nuget", "nuget", "NuGet"), ("packagist", "packagist", "Packagist"),
]


def dependency(ecosystem="PyPI", name="fixture"):
    return Dependency(ecosystem=ecosystem, name=name, version="1.0", declared_in=Path("manifest"),
        scope="main", is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:generic/fixture@1.0", parser_confidence=Confidence("high"))


@pytest.fixture
def owned(tmp_path, monkeypatch, _owned_reachability_keepalive):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("import requests\n")
    (target / "app.js").write_text("require('lodash');\n")
    before = {p.name: p.read_bytes() for p in target.iterdir()}
    roots = []
    original = tempfile.mkdtemp

    def allocate(*args, **kwargs):
        root = Path(original(*args, **{**kwargs, "dir": runtime}))
        roots.append(root)
        return str(root)

    monkeypatch.setattr(scratch, "tempfile", SimpleNamespace(**{**vars(tempfile), "mkdtemp": allocate}))
    monkeypatch.setattr(scratch, "logger", logging.Logger("reachability-scratch-test"))
    from packages.sca.reachability import _walker
    from core.analysis import reachability as analysis
    # Restore the inherited cache objects after our joined scan thread exits;
    # do not clear entries that belong to earlier tests or the caller.
    with _walker._CACHE_LOCK:
        monkeypatch.setattr(_walker, "_CACHE", {})
    with analysis._INDEX_CACHE_LOCK:
        monkeypatch.setattr(analysis, "_INDEX_CACHE", type(analysis._INDEX_CACHE)())
    with analysis._FN_CALLED_INDEX_CACHE_LOCK:
        monkeypatch.setattr(analysis, "_FN_CALLED_INDEX_CACHE", type(analysis._FN_CALLED_INDEX_CACHE)())
    with analysis._BO_ITEM_INDEX_CACHE_LOCK:
        monkeypatch.setattr(analysis, "_BO_ITEM_INDEX_CACHE", type(analysis._BO_ITEM_INDEX_CACHE)())
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "registry"))
    monkeypatch.setattr(reachability, "_inventory_cache_dir", lambda target: tmp_path / "inventory-cache")
    try:
        yield SimpleNamespace(roots=roots, pins=_owned_reachability_keepalive, target=target)
        assert all(not p.exists() for p in roots), roots
        assert not _owned_reachability_keepalive
        assert {p.name: p.read_bytes() for p in target.iterdir()} == before
    finally:
        assert rmtree_hardened(runtime)


def invoke(owned, module, tier, ecosystem, *, inventory=None, verdict="imported", symbols=True):
    mod = importlib.import_module(f"packages.sca.reachability.{module}_function_level")
    dep = dependency(ecosystem)
    original = Reachability(verdict, Confidence("high"), ["module import"])
    output = {dep.key(): original}
    kwargs = {f"{tier}_symbol_map": {dep.key(): ["fixture.call"]} if symbols else {}}
    getattr(mod, f"refine_{tier}_verdicts")([dep], output, target=owned.target,
        inventory=inventory, **kwargs)
    return output[dep.key()], original


def dirty(owned, output):
    root = Path(output)
    assert root == owned.roots[-1] and str(root) in owned.pins
    child = root / "restricted" / "cache"
    child.mkdir(parents=True)
    (child / "payload").write_bytes(b"cache" * 1024)
    child.chmod(0)


@pytest.mark.parametrize("module,tier,ecosystem", TIERS, ids=[v[0] for v in TIERS])
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt, SystemExit], ids=["success", "error", "interrupt", "exit"])
def test_direct_inventory_lifecycle(owned, monkeypatch, module, tier, ecosystem, error):
    calls = []

    def build(target, output):
        calls.append(target)
        assert isinstance(output, str)
        dirty(owned, output)
        if error:
            raise error("primary build failure")
        return {"files": []}

    monkeypatch.setattr(builder, "build_inventory", build)
    if error in (KeyboardInterrupt, SystemExit):
        with pytest.raises(error, match="primary build failure"):
            invoke(owned, module, tier, ecosystem)
    else:
        refined, original = invoke(owned, module, tier, ecosystem)
        if error:
            assert refined is original
    assert len(calls) == len(owned.roots) == 1


@pytest.mark.parametrize("module,tier,ecosystem", TIERS, ids=[v[0] for v in TIERS])
@pytest.mark.parametrize("reason", ["no-symbols", "stronger-verdict", "provided-inventory"])
def test_inventory_work_is_skipped_when_unneeded(owned, monkeypatch, module, tier, ecosystem, reason):
    monkeypatch.setattr(builder, "build_inventory", lambda *a, **k: pytest.fail("unneeded inventory build"))
    invoke(owned, module, tier, ecosystem, symbols=reason != "no-symbols",
        verdict="likely_called" if reason == "stronger-verdict" else "imported",
        inventory={"files": []} if reason == "provided-inventory" else None)
    assert not owned.roots


@pytest.mark.parametrize("module,tier,ecosystem", TIERS, ids=[v[0] for v in TIERS])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_secondary_removal_failure_preserves_builder_error(owned, monkeypatch, module, tier, ecosystem, error):
    def build(target, output):
        dirty(owned, output)
        raise KeyboardInterrupt("primary build failure")

    def remove(*args, **kwargs):
        raise error("secondary removal failure")

    monkeypatch.setattr(builder, "build_inventory", build)
    with pytest.MonkeyPatch.context() as fault:
        fault.setattr(scratch, "rmtree_hardened", remove)
        with pytest.raises(KeyboardInterrupt, match="primary build failure"):
            invoke(owned, module, tier, ecosystem)
    assert not owned.pins
    for root in owned.roots:
        assert root.is_dir()
        assert rmtree_hardened(root)


@pytest.mark.parametrize("module,tier,ecosystem", TIERS, ids=[v[0] for v in TIERS])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_keepalive_setup_failure_drops_reservation(owned, monkeypatch, module, tier, ecosystem, error):
    register = scratch.keepalive_register

    def fail(path):
        register(path)
        raise error("registration failure")

    monkeypatch.setattr(scratch, "keepalive_register", fail)
    monkeypatch.setattr(builder, "build_inventory", lambda *a, **k: pytest.fail("builder started after failed setup"))
    if error in (KeyboardInterrupt, SystemExit):
        with pytest.raises(error, match="registration failure"):
            invoke(owned, module, tier, ecosystem)
    else:
        refined, original = invoke(owned, module, tier, ecosystem)
        assert refined is original
    assert len(owned.roots) == 1


def scan_inputs():
    deps = [dependency("PyPI", "requests"), dependency("npm", "lodash")]
    advisory = Advisory(osv_id="FIXTURE", aliases=[], summary="", details="", affected=[],
        severity=None, fixed_versions=[], references=[],
        ecosystem_specific={"imports": [{"path": "fixture", "symbols": ["call"]}]})
    return deps, [OsvResult(dep.key(), [advisory]) for dep in deps]


@pytest.mark.parametrize("recover", [False, True])
def test_failed_build_is_memoized_only_within_one_scan(owned, monkeypatch, recover):
    calls = []
    deps, osv = scan_inputs()

    def build(*args, **kwargs):
        calls.append(None)
        if len(calls) == 1 or not recover:
            raise RuntimeError("builder unavailable")
        return {"files": []}

    monkeypatch.setattr(builder, "build_inventory", build)
    for _ in range(2):
        reachability.scan(owned.target, deps, osv_results=osv)
    assert len(calls) == 2, "each scan must try once, regardless of the prior scan"


def test_concurrent_scan_cannot_reset_another_scans_failure_memo(owned, monkeypatch):
    from packages.sca.reachability import npm_function_level
    paused, completed = threading.Event(), threading.Event()
    calls = {"failed": 0, "healthy": 0}
    deps, osv = scan_inputs()
    failed_thread = []
    original_symbols = npm_function_level.build_npm_symbol_map

    def build(*args, **kwargs):
        if threading.current_thread() is failed_thread[0]:
            calls["failed"] += 1
            raise RuntimeError("first scan builder unavailable")
        calls["healthy"] += 1
        return {"files": []}

    def symbols(*args, **kwargs):
        if threading.current_thread() is failed_thread[0]:
            paused.set()
            assert completed.wait(10), "healthy scan was not completed"
        return original_symbols(*args, **kwargs)

    def failed_scan():
        failed_thread.append(threading.current_thread())
        return reachability.scan(owned.target, deps, osv_results=osv)

    monkeypatch.setattr(builder, "build_inventory", build)
    monkeypatch.setattr(npm_function_level, "build_npm_symbol_map", symbols)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(failed_scan)
        try:
            assert paused.wait(5), "failed scan did not reach its second tier"
            reachability.scan(owned.target, deps, osv_results=osv)
        finally:
            completed.set()
        pending.result(timeout=5)
    assert calls == {"failed": 1, "healthy": 1}
