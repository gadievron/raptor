"""Exercise real resolver owners with incidental package-manager startup stubbed."""

import importlib
import logging
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.atomic_fs import rmtree_hardened
from core.run import scratch
from packages.sca import resolvers
from packages.sca.resolvers.pip import PipResolver


@pytest.fixture
def workspace(tmp_path, monkeypatch, _owned_resolver_keepalive):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    for name in ("Gemfile", "Cargo.toml", "composer.json", "go.mod", "package.json",
                 "example.csproj", "pyproject.toml", "requirements.in"):
        (project / name).write_text("fixture\n")
    before = {p.name: p.read_bytes() for p in project.iterdir()}
    allocated = []
    original = tempfile.mkdtemp

    def allocate(*args, **kwargs):
        path = Path(original(*args, **{**kwargs, "dir": runtime}))
        allocated.append(path)
        return str(path)

    monkeypatch.setattr(scratch, "tempfile", SimpleNamespace(**{**vars(tempfile), "mkdtemp": allocate}))
    monkeypatch.setattr(scratch, "logger", logging.Logger("resolver-scratch-test"))
    try:
        yield SimpleNamespace(project=project, allocated=allocated, pins=_owned_resolver_keepalive)
        assert allocated, "resolver never acquired its workspace"
        assert all(not p.exists() for p in allocated), allocated
        assert {p.name: p.read_bytes() for p in project.iterdir()} == before
        assert not _owned_resolver_keepalive
    finally:
        assert rmtree_hardened(runtime)


RESOLVERS = [
    ("bundler", "BundlerResolver"), ("cargo", "CargoResolver"),
    ("composer", "ComposerResolver"), ("gomod", "GoResolver"),
    ("npm", "NpmResolver"), ("nuget", "NugetResolver"),
    ("pnpm", "PnpmResolver"), ("poetry", "PoetryResolver"), ("yarn", "YarnResolver"),
]


def native_owner(monkeypatch, name, cls):
    module = importlib.import_module(f"packages.sca.resolvers.{name}")
    owner = getattr(module, cls)()
    monkeypatch.setattr(type(owner), "is_available", lambda self: True)
    monkeypatch.setattr(type(owner), "proxy_hosts", property(lambda self: []))
    return module, owner


def dirty(workspace):
    root = workspace.allocated[-1]
    assert str(root) in workspace.pins
    child = root / "cache" / "nested"
    child.mkdir(parents=True)
    (child / "payload").write_bytes(b"cache" * 1024)
    child.chmod(0)
    return root


def outcome(kind):
    if kind == "timeout":
        raise subprocess.TimeoutExpired("package-manager", 1)
    if kind in ("error", "interrupt", "exit"):
        raise {"error": RuntimeError, "interrupt": KeyboardInterrupt, "exit": SystemExit}[kind]("primary")
    return subprocess.CompletedProcess([], int(kind == "nonzero"), "", "")


@pytest.mark.parametrize("name,cls", RESOLVERS, ids=[v[0] for v in RESOLVERS])
@pytest.mark.parametrize("kind", ["success", "missing-lock", "nonzero", "timeout", "error", "interrupt", "exit"])
def test_native_workspace_covers_run(workspace, monkeypatch, name, cls, kind):
    module, owner = native_owner(monkeypatch, name, cls)

    def run(*args, **kwargs):
        root = dirty(workspace)
        assert kwargs["cwd"] == root
        if kind == "success":
            # Successful package managers must actually produce a regular lock.
            for filename in ("Gemfile.lock", "Cargo.lock", "composer.lock", "go.sum", "package-lock.json",
                             "packages.lock.json", "pnpm-lock.yaml", "poetry.lock", "yarn.lock"):
                (root / filename).write_bytes(b"fixture lock")
        return outcome(kind)

    monkeypatch.setattr(module, "_run", run)
    if kind in ("error", "interrupt", "exit"):
        with pytest.raises({"error": RuntimeError, "interrupt": KeyboardInterrupt, "exit": SystemExit}[kind], match="primary"):
            owner.dry_run(workspace.project)
    else:
        result = owner.dry_run(workspace.project)
        assert result.success == (kind == "success" or kind == "missing-lock" and name == "gomod")
        if kind == "missing-lock" and name != "gomod":
            assert result.proposed_lockfile is None and "readable regular lockfile" in result.error


@pytest.mark.parametrize("name,cls", RESOLVERS, ids=[v[0] for v in RESOLVERS])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_workspace_covers_manifest_copy(workspace, monkeypatch, name, cls, error):
    module, owner = native_owner(monkeypatch, name, cls)

    def fail(*args, **kwargs):
        dirty(workspace)
        raise error("copy failed")

    monkeypatch.setattr(module, "copy_regular_file", fail)
    with pytest.raises(error, match="copy failed"):
        owner.dry_run(workspace.project)


def pip_call(workspace, monkeypatch, batch):
    owner = PipResolver()
    monkeypatch.setattr(owner, "is_available", lambda: True)
    monkeypatch.setattr(type(owner), "proxy_hosts", property(lambda self: []))
    if batch:
        second = workspace.project.parent / "second"
        second.mkdir()
        (second / "requirements.in").write_text("fixture\n")
        return owner, lambda: owner.dry_run_batch([workspace.project, second], common_root=workspace.project.parent)
    return owner, lambda: owner._run_pip_compile_in_venv(workspace.project, "requirements.in", 1)


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_pip_script_setup_is_inside_workspace(workspace, monkeypatch, batch, error):
    owner, call = pip_call(workspace, monkeypatch, batch)

    def fail(*args, **kwargs):
        dirty(workspace)
        raise error("script failed")

    monkeypatch.setattr(owner, "_build_batch_script" if batch else "_venv_setup_script", fail)
    with pytest.raises(error, match="script failed"):
        call()


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
@pytest.mark.parametrize("kind", ["success", "nonzero", "error", "interrupt", "exit"])
def test_pip_run_reclaims_workspace(workspace, monkeypatch, batch, kind):
    from packages.sca.resolvers import pip
    owner, call = pip_call(workspace, monkeypatch, batch)

    def run(*args, **kwargs):
        dirty(workspace)
        return outcome(kind)

    monkeypatch.setattr(pip, "_run", run)
    if kind in ("error", "interrupt", "exit"):
        with pytest.raises({"error": RuntimeError, "interrupt": KeyboardInterrupt, "exit": SystemExit}[kind], match="primary"):
            call()
    else:
        call()


@pytest.mark.parametrize("networked", [False, True])
@pytest.mark.parametrize("kind", ["success", "nonzero", "timeout", "error", "interrupt", "exit"])
def test_dispatch_output_workspace(workspace, monkeypatch, networked, kind):
    from core.sandbox import context

    def run(*args, **kwargs):
        assert kwargs["output"] == str(dirty(workspace))
        return outcome(kind)

    # Startup is incidental here; sandbox policy has real dedicated contracts.
    monkeypatch.setattr(context, "run_untrusted", run)
    monkeypatch.setattr(context, "run_untrusted_networked", run)
    if kind in ("timeout", "error", "interrupt", "exit"):
        with pytest.raises({"timeout": subprocess.TimeoutExpired, "error": RuntimeError,
                            "interrupt": KeyboardInterrupt, "exit": SystemExit}[kind]):
            resolvers._run(["fixture"], cwd=workspace.project, timeout=1,
                           proxy_hosts=["example.invalid"] if networked else [])
    else:
        resolvers._run(["fixture"], cwd=workspace.project, timeout=1,
                       proxy_hosts=["example.invalid"] if networked else [])


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
def test_pip_timeout_releases_before_fallback(workspace, monkeypatch, batch):
    from packages.sca.resolvers import pip
    owner, call = pip_call(workspace, monkeypatch, batch)

    def run(*args, **kwargs):
        dirty(workspace)
        raise subprocess.TimeoutExpired("pip", 1)

    def fallback(*args, **kwargs):
        assert all(not path.exists() for path in workspace.allocated)
        assert not workspace.pins
        return resolvers.ResolverResult(ecosystem="PyPI", success=True, available=True)

    monkeypatch.setattr(pip, "_run", run)
    monkeypatch.setattr(owner, "dry_run", fallback)
    result = call()
    if batch:
        assert len(result) == 2 and all(r.success for r in result)
    else:
        assert not result.success and "timed out" in result.error


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("owner_kind", ["native", "pip-single", "pip-batch", "dispatch"])
def test_secondary_cleanup_failure_preserves_primary(workspace, monkeypatch, error, owner_kind):
    def fail(*args, **kwargs):
        dirty(workspace)
        raise RuntimeError("primary work failure")

    if owner_kind == "native":
        module, owner = native_owner(monkeypatch, "npm", "NpmResolver")
        monkeypatch.setattr(module, "_run", fail)
        call = lambda: owner.dry_run(workspace.project)
    elif owner_kind.startswith("pip"):
        owner, call = pip_call(workspace, monkeypatch, owner_kind == "pip-batch")
        monkeypatch.setattr(owner, "_venv_setup_script", fail)
    else:
        from core.sandbox import context
        monkeypatch.setattr(context, "run_untrusted", fail)
        call = lambda: resolvers._run(["fixture"], cwd=workspace.project, timeout=1, proxy_hosts=[])

    def remove(*args, **kwargs):
        raise error("secondary removal failure")

    with pytest.MonkeyPatch.context() as fault:
        fault.setattr(scratch, "rmtree_hardened", remove)
        with pytest.raises(RuntimeError, match="primary work failure"):
            call()
    assert not workspace.pins
    assert all(path.exists() for path in workspace.allocated)
    for path in workspace.allocated:
        assert rmtree_hardened(path)
