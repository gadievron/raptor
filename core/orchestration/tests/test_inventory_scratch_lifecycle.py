"""Exercise orchestration inventory ownership without incidental parser startup."""

import logging
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.analysis import reachability as analysis
from core.atomic_fs import rmtree_hardened
from core.inventory import builder, save_checklist
from core.orchestration import agentic_passes, context_map_ast_view, context_map_callgraph
from core.orchestration import flow_trace_ast_view, reachability_enrichment
from core.run import scratch


OWNERS = ["context-ast", "context-calls", "flow-ast", "priority", "callers", "prepass"]


@pytest.fixture
def owned(tmp_path, monkeypatch, _owned_orchestration_keepalive):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def fixture():\n    return 1\n")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "registry"))
    out = tmp_path / "run"
    save_checklist(out, {"files": []})
    roots = []
    original = tempfile.mkdtemp

    def allocate(*args, **kwargs):
        root = Path(original(*args, **{**kwargs, "dir": runtime}))
        roots.append(root)
        return str(root)

    monkeypatch.setattr(scratch, "tempfile", SimpleNamespace(**{**vars(tempfile), "mkdtemp": allocate}))
    monkeypatch.setattr(scratch, "logger", logging.Logger("orchestration-scratch-test"))
    with analysis._INDEX_CACHE_LOCK:
        monkeypatch.setattr(analysis, "_INDEX_CACHE", type(analysis._INDEX_CACHE)())
    with analysis._FN_CALLED_INDEX_CACHE_LOCK:
        monkeypatch.setattr(analysis, "_FN_CALLED_INDEX_CACHE", type(analysis._FN_CALLED_INDEX_CACHE)())
    with analysis._BO_ITEM_INDEX_CACHE_LOCK:
        monkeypatch.setattr(analysis, "_BO_ITEM_INDEX_CACHE", type(analysis._BO_ITEM_INDEX_CACHE)())
    try:
        yield SimpleNamespace(roots=roots, pins=_owned_orchestration_keepalive, target=target, out=out)
        assert all(not path.exists() for path in roots), roots
        assert not _owned_orchestration_keepalive
        assert (target / "app.py").read_text() == "def fixture():\n    return 1\n"
    finally:
        assert rmtree_hardened(runtime)


def invoke(owned, owner, *, supplied=False, empty=False, allow_unreachable=False):
    kwargs = {"inventory": {"files": []}} if supplied else {}
    if owner == "prepass":
        return agentic_passes.run_reachability_prepass(owned.target,
            owned.out / "missing" if empty else owned.out,
            allow_unreachable=allow_unreachable, **kwargs)
    if owner in ("priority", "callers"):
        checklist = {} if empty else {"files": []}
        if owner == "priority":
            return reachability_enrichment.mark_unreachable_low_priority(checklist, owned.target,
                allow_unreachable=allow_unreachable, **kwargs)
        return reachability_enrichment.compute_caller_context(checklist, owned.target, **kwargs)
    if owner == "flow-ast":
        trace = {} if empty else {"steps": [{"definition": "app.py:1"}]}
        return flow_trace_ast_view.enrich_with_ast_view(trace, owned.target, **kwargs)
    context = {} if empty else {"entry_points": [{"file": "app.py", "line": 1}]}
    if owner == "context-ast":
        return context_map_ast_view.enrich_with_ast_view(context, owned.target, **kwargs)
    return context_map_callgraph.enrich_with_forward_reachable(context, owned.target, **kwargs)


def dirty(owned, output):
    root = Path(output)
    assert root == owned.roots[-1] and str(root) in owned.pins
    assert root.name.startswith("raptor-orchestration-inventory-")
    child = root / "restricted" / "cache"
    child.mkdir(parents=True)
    (child / "payload").write_bytes(b"cache" * 1024)
    child.chmod(0)


@pytest.mark.parametrize("owner", OWNERS)
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt, SystemExit], ids=["success", "error", "interrupt", "exit"])
def test_inventory_build_lifecycle(owned, monkeypatch, owner, error):
    calls = []

    def build(target, output, **kwargs):
        calls.append(target)
        assert isinstance(output, str)
        dirty(owned, output)
        if error:
            raise error("primary build failure")
        return {"files": []}

    monkeypatch.setattr(builder, "build_inventory", build)
    if error in (KeyboardInterrupt, SystemExit):
        with pytest.raises(error, match="primary build failure"):
            invoke(owned, owner)
    else:
        returned = invoke(owned, owner)
        if owner == "prepass":
            assert returned.ran == (error is None)
    assert len(calls) == len(owned.roots) == 1


@pytest.mark.parametrize("owner", OWNERS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_cleanup_preserves_build_error(owned, monkeypatch, owner, error):
    def build(target, output, **kwargs):
        dirty(owned, output)
        raise KeyboardInterrupt("primary build failure")

    def remove(*args, **kwargs):
        raise error("secondary removal failure")

    monkeypatch.setattr(builder, "build_inventory", build)
    with pytest.MonkeyPatch.context() as fault:
        fault.setattr(scratch, "rmtree_hardened", remove)
        with pytest.raises(KeyboardInterrupt, match="primary build failure"):
            invoke(owned, owner)
    assert not owned.pins
    for root in owned.roots:
        assert root.is_dir()
        assert rmtree_hardened(root)


@pytest.mark.parametrize("owner", OWNERS)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_keepalive_setup_failure_reclaims_root(owned, monkeypatch, owner, error):
    register = scratch.keepalive_register

    def fail(path):
        register(path)
        raise error("registration failure")

    monkeypatch.setattr(scratch, "keepalive_register", fail)
    monkeypatch.setattr(builder, "build_inventory", lambda *a, **k: pytest.fail("builder started after failed setup"))
    if error in (KeyboardInterrupt, SystemExit):
        with pytest.raises(error, match="registration failure"):
            invoke(owned, owner)
    else:
        invoke(owned, owner)
    assert len(owned.roots) == 1


@pytest.mark.parametrize("owner", OWNERS)
@pytest.mark.parametrize("reason", ["supplied", "empty"])
def test_no_scratch_when_inventory_is_unneeded(owned, monkeypatch, owner, reason):
    monkeypatch.setattr(builder, "build_inventory", lambda *a, **k: pytest.fail("unneeded inventory build"))
    invoke(owned, owner, supplied=reason == "supplied", empty=reason == "empty")
    assert not owned.roots


@pytest.mark.parametrize("owner", ["priority", "prepass"])
@pytest.mark.parametrize("allow_unreachable", [False, True])
def test_isolation_scope_reaches_inventory_builder(owned, monkeypatch, owner, allow_unreachable):
    observed = []

    def build(target, output, **kwargs):
        dirty(owned, output)
        observed.append(kwargs["allow_unreachable"])
        return {"files": []}

    monkeypatch.setattr(builder, "build_inventory", build)
    invoke(owned, owner, allow_unreachable=allow_unreachable)
    assert observed == [allow_unreachable]
