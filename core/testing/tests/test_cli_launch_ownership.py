"""Standalone shell routers retain native assertions under borrowed state."""

import ast
import importlib.util
import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from core.security import launch_scratch
from core.testing.standalone_cli import run_standalone_cli

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX launcher and shell routes")


@pytest.mark.parametrize("mode", ["clean", "stale", "missing-tmp", "unset-tmp", "retired-metadata"])
@pytest.mark.parametrize("method", [
    "test_show_routes_to_project_threat_model",
    "test_build_help_routes_to_agentic_help",
])
def test_transitive_router_owns_launch_state(tmp_path, monkeypatch, mode, method):
    path = ROOT / "core/threat_model/tests/test_raptor_threat_model_wrapper.py"
    spec = importlib.util.spec_from_file_location("owned_threat_router", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    for name in ("_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    if mode == "stale":
        monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "retired-authorization")
        monkeypatch.setenv("RAPTOR_SESSION_PID", "99999999")
        monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "retired-session")
    elif mode == "missing-tmp":
        monkeypatch.setenv("TMPDIR", str(tmp_path / "missing-scratch"))
    elif mode == "unset-tmp":
        monkeypatch.delenv("TMPDIR", raising=False)
    elif mode == "retired-metadata":
        root = tmp_path / f"raptor-{os.geteuid()}" / f"session-{os.getpid()}-123"
        root.mkdir(parents=True, mode=0o700)
        metadata = launch_scratch.create(root)
        token = launch_scratch.issue(tmp_path / "authorities", metadata, os.getpid())
        monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", token)
        shutil.rmtree(root)
    before = dict(os.environ)
    case = module.RaptorThreatModelWrapperTests(method)
    getattr(case, method)()
    unchanged = dict(os.environ) == before
    assert unchanged, "standalone router changed its caller's launch state"


@pytest.mark.parametrize("method", [
    "test_stop_runs_in_claudecode", "test_tool_failure_runs_in_claudecode",
    "test_session_end_runs_in_claudecode",
])
def test_copied_lifecycle_hook_owns_stale_parent_launch(tmp_path, monkeypatch, method):
    path = ROOT / "core/run/tests/test_lifecycle_hook.py"
    # Compile the actual subprocess class and its payload, without executing
    # the unrelated in-process hook loader at module collection. The copied
    # script still runs its real bootstrap in the owned child.
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body
             if isinstance(node, ast.ClassDef) and node.name == "TestE2EHookScript"
             or isinstance(node, ast.Assign) and any(
                 isinstance(target, ast.Name) and target.id == "RAPTOR_BASH_FAILURE"
                 for target in node.targets)]
    namespace = dict(__name__=__name__, unittest=unittest, json=json,
                     TemporaryDirectory=TemporaryDirectory, Path=Path, os=os,
                     sys=sys, run_standalone_cli=run_standalone_cli,
                     REPO_ROOT=ROOT, HOOK_SCRIPT=ROOT / "libexec/raptor-lifecycle-hook")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "retired-authorization")
    monkeypatch.setenv("TMPDIR", str(tmp_path / "retired-scratch"))
    before = dict(os.environ)
    # Keep the actual copied-script dispatch and its native assertions.
    case = namespace["TestE2EHookScript"](method)
    getattr(case, method)()
    unchanged = dict(os.environ) == before
    assert unchanged, "copied hook changed its caller's launch state"


@pytest.fixture
def stdin_budget_native(monkeypatch):
    path = ROOT / "packages/exploit_feasibility/tests/test_smt_path.py"
    spec = importlib.util.spec_from_file_location("owned_stdin_budget", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module.TestStdinBudget()


@pytest.mark.parametrize("cached", [False, True], ids=["cold-bootstrap", "cached-bootstrap"])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_stdin_loader_restores_launch_owner(stdin_budget_native, tmp_path, monkeypatch, cached, outcome):
    from contextlib import ExitStack, redirect_stderr
    import io

    from core.security import env_sanitisation
    from core.testing.module_registry import fresh_module_tree

    # The bootstrap's documented no-fileno path avoids registering a process
    # signal handler while retaining its real scratch admission/restore call.
    with fresh_module_tree("core.startup.process_init"), redirect_stderr(io.StringIO()), \
            ExitStack() as warmth, pytest.MonkeyPatch.context() as parent:
        if cached:
            # The outer launch and its metadata stay alive while the inner
            # loader borrows the already-imported bootstrap module.
            warmth.enter_context(stdin_budget_native._load_module())
        else:
            parent.setattr(launch_scratch, "_restored", False)
        parent.setenv("_RAPTOR_SCRATCH_AUTH", "retired-authorization")
        parent.setenv("TMPDIR", str(tmp_path / "retired-scratch"))
        before = dict(os.environ)
        scratch = (launch_scratch._restored, launch_scratch._metadata_path,
                   env_sanitisation._subprocess_tmpdir)
        failure = KeyboardInterrupt("owned stdin interruption") if outcome == "interrupt" else RuntimeError("owned stdin error")

        def body():
            with stdin_budget_native._load_module() as module:
                assert Path(os.environ["TMPDIR"]).is_dir()
                assert "_RAPTOR_SCRATCH_AUTH" not in os.environ
                assert callable(module.main)
                if not cached:
                    assert launch_scratch._restored is True
                if outcome != "normal":
                    raise failure

        if outcome == "normal":
            body()
        else:
            with pytest.raises(type(failure)) as caught:
                body()
            assert caught.value is failure
        unchanged = dict(os.environ) == before
        assert unchanged, "stdin loader changed borrowed launch credentials"
        assert launch_scratch._restored is scratch[0]
        assert launch_scratch._metadata_path is scratch[1]
        assert env_sanitisation._subprocess_tmpdir is scratch[2]


@pytest.mark.parametrize("subject", ["test_e2e_orchestrator_signals", "test_fail_open_census"])
@pytest.mark.parametrize("stale", [False, True], ids=["clean", "stale-parent"])
def test_module_preparation_and_later_consumer_share_signing_identity(
    tmp_path, tmp_path_factory, monkeypatch, request, subject, stale,
):
    import json

    from core.inventory import checklist_frame_mac as frame

    path = ROOT / "core/audit/tests" / f"{subject}.py"
    spec = importlib.util.spec_from_file_location(f"owned_{subject}", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    keys = tmp_path / "module-keys"
    keys.mkdir()
    # The module producer precedes function key fixtures. Its later consumer
    # must explicitly re-pin the same directory after a default-key override.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "wrong-default-keys"))
    if stale:
        monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "retired-authorization")
        monkeypatch.setenv("TMPDIR", str(tmp_path / "missing-scratch"))
    before = dict(os.environ)
    if subject == "test_e2e_orchestrator_signals":
        target = tmp_path / "source"
        target.mkdir()
        (target / "tiny.c").write_text("int add(int a, int b) { return a + b; }\n")
        out = module.out_dir.__wrapped__(target, tmp_path_factory, keys)
    else:
        # Tool discovery is incidental to the launch/signing contract. Keep
        # the real checklist/prep path without probing a host JVM/toolchain.
        from core.audit import capabilities
        monkeypatch.setattr(
            capabilities, "probe_capabilities",
            lambda *args, **kwargs: capabilities.AuditCapabilities(),
        )
        prep, out = module.census_prep.__wrapped__(tmp_path_factory, keys)
        assert prep is not None
    restored = dict(os.environ) == before
    assert restored, "module preparation left caller launch/signing state changed"
    with pytest.MonkeyPatch.context() as consumer:
        module._shared_launch_signing_keys.__wrapped__(request, consumer, keys)
        doc = json.loads((out / "checklist.json").read_text())
        provenance = frame.frame_provenance(doc, frame.frame_binding(out), frame.FORM_SINGLE)
        assert provenance == frame.FRAME_VERIFIED, "parent could not authenticate the actual child's checklist"
    restored = dict(os.environ) == before
    assert restored, "later consumer left borrowed signing state changed"


@pytest.mark.parametrize("stale", [False, True], ids=["clean", "stale-parent"])
def test_agent_runner_owns_live_launch_state_without_entering_kernel_profiles(
    tmp_path, monkeypatch, stale,
):
    import subprocess

    from core.testing import standalone_cli
    from core.testing.module_bindings import patch_module_attribute

    path = ROOT / "packages/sca/tests/test_sandbox_full_e2e.py"
    spec = importlib.util.spec_from_file_location("owned_sca_agent_runner", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    if stale:
        monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", "retired-authorization")
        monkeypatch.setenv("RAPTOR_SESSION_PID", "99999999")
        monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "retired-session")
        monkeypatch.setenv("TMPDIR", str(tmp_path / "retired-scratch"))
    before = dict(os.environ)
    real_run = subprocess.run
    observed = []

    def capture(args, **kwargs):
        env = kwargs.get("env")
        explicit = isinstance(env, dict)
        assert explicit, "standalone agent inherited its caller's environment"
        independent = not any(name in env for name in (
            "_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN",
        ))
        assert independent, "standalone agent retained borrowed authority"
        home, scratch = Path(env["HOME"]), Path(env["TMPDIR"])
        assert home.is_dir() and scratch.is_dir()
        assert str(home) != before.get("HOME")
        observed.append((home, scratch))
        return real_run(args, **kwargs)

    # Observe either transport at its actual process boundary, then execute
    # the real parser. No sandbox-floor, compiler or model workflow is run.
    patch_module_attribute(monkeypatch, module, "subprocess", "run", capture)
    patch_module_attribute(monkeypatch, standalone_cli, "subprocess", "run", capture)
    reply = module._run_agent(["--help"], timeout=30)
    assert reply.returncode == 0, reply.stderr
    assert "--sandbox" in reply.stdout
    assert len(observed) == 1
    assert all(not path.exists() for paths in observed for path in paths)
    unchanged = dict(os.environ) == before
    assert unchanged, "agent runner changed its caller's launch state"
