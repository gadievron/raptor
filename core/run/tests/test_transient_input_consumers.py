"""Temporary tool inputs share ownership across independent consumers."""

from pathlib import Path
import subprocess
import tempfile
from types import ModuleType

import pytest

from core.run import scratch


CONSUMERS = ["build", "coverage", "history", "flow", "expanded", "semgrep", "coccinelle"]


@pytest.fixture
def pool(tmp_path, monkeypatch):
    parent = tmp_path / "inputs"
    parent.mkdir()
    created = []
    fault = {"stage": None, "error": OSError, "unlink": None}
    original = tempfile.NamedTemporaryFile

    def allocate(**kwargs):
        if fault["stage"] == "allocate":
            raise fault["error"]("allocation failure")
        # All test artifacts are owned, regardless of the host's TMPDIR.
        kwargs["dir"] = parent
        assert kwargs["encoding"] == "utf-8"
        stream = original(**kwargs)
        close, write = stream.close, stream.write
        created.append((stream, close, Path(stream.name)))

        def fail_write(text):
            write(text[:2])
            raise fault["error"]("input write failure")

        def fail_close():
            close()
            raise fault["error"]("input close failure")

        if fault["stage"] == "write":
            stream.write = fail_write
        elif fault["stage"] == "close":
            stream.close = fail_close
        return stream

    class ScopedPath(type(parent)):
        def unlink(self, *args, **kwargs):
            if fault["unlink"] is not None:
                raise fault["unlink"]("input cleanup failure")
            return super().unlink(*args, **kwargs)

    proxy = ModuleType("owned_input_tempfile")
    proxy.__dict__.update(vars(tempfile))
    proxy.NamedTemporaryFile = allocate
    monkeypatch.setattr(scratch, "tempfile", proxy)
    monkeypatch.setattr(scratch, "Path", ScopedPath)
    try:
        yield fault, created
    finally:
        for stream, close, path in created:
            close()
            path.unlink(missing_ok=True)


@pytest.fixture(params=CONSUMERS)
def case(request, tmp_path, monkeypatch, pool):
    from packages.semgrep.models import SemgrepFinding, SemgrepResult
    from packages.coccinelle.models import SpatchResult
    from core.container.proc import RunOutcome

    root = tmp_path / "target"
    root.mkdir()
    source = root / "source.c"
    source.write_text("void handler(void) { foo(); }\n", encoding="utf-8")
    state = {"error": None, "seen": []}

    def consume(path):
        path = Path(path)
        assert all(stream.file.closed for stream, _, _ in pool[1])
        assert path.stat().st_mode & 0o077 == 0
        state["seen"].append(path.read_bytes())
        if state["error"] is not None:
            raise state["error"]("consumer primary failure")

    kind = request.param
    if kind == "build":
        from core.container import build
        def run(cmd, **kwargs):
            consume(cmd[cmd.index("-f") + 1])
            return RunOutcome(returncode=0, stdout="ok", stderr="", timed_out=False)
        monkeypatch.setattr(build, "run_cli", run)
        invoke = lambda: build.build_image(context_dir=str(root), tag="scope:1", dockerfile_text="FROM scratch\n# café\n").ok
    elif kind == "coverage":
        from core.coverage import collect, parsers
        monkeypatch.setattr(collect, "_sandboxed_run", lambda *a, **kw: subprocess.CompletedProcess(a, 0, b"TN:caf\xc3\xa9\n", b""))
        def parse(path):
            consume(path)
            return {"source.c": {1}}
        monkeypatch.setattr(parsers, "parse_lcov", parse)
        invoke = lambda: bool(collect.collect_llvm(root / "app", root / "data.prof", env={}))
    elif kind == "history":
        from core.audit import fix_history
        def run(target, rule, **kwargs):
            consume(rule)
            return SemgrepResult(findings=[SemgrepFinding(file="source.c", line=1)])
        invoke = lambda: bool(fix_history._sweep_callee_sites(root, "foo", {"files": []}, run_rule_fn=run))
    elif kind == "flow":
        from core.audit import cocci_flow
        from packages.coccinelle import runner
        monkeypatch.setattr(runner, "is_available", lambda: True)
        def run(target, rule, **kwargs):
            consume(rule)
            return SpatchResult(rule="scope")
        monkeypatch.setattr(runner, "run_rule", run)
        invoke = lambda: cocci_flow.run_flow_cocci_sweep(target_path=root, file_path="source.c", function_name="handler", hypothesis="use-after-free of `buf` after free(buf)", language="c").outcome == "refuted"
    elif kind == "expanded":
        from core.audit import expanded_semgrep
        from core.audit.preprocessor_view import ExpandedView
        from packages.semgrep import runner
        budget = expanded_semgrep.ExpansionBudget()
        view = ExpandedView(ok=True, file_path="source.c", text="// café\nvoid handler(void) {}\n")
        monkeypatch.setattr(budget, "view_for", lambda *a, **kw: view)
        monkeypatch.setattr(runner, "is_available", lambda: True)
        def run(target, config, **kwargs):
            consume(target)
            return SemgrepResult()
        monkeypatch.setattr(runner, "run_rule", run)
        invoke = lambda: expanded_semgrep.run_expanded_semgrep_rule(target_path=root, file_path="source.c", rule_config="scope.yaml", budget=budget).ok
    else:
        if kind == "semgrep":
            from packages.hypothesis_validation.adapters import semgrep as adapter_module
            adapter = adapter_module.SemgrepAdapter()
            package_name = "semgrep_pkg"
            rule = "rules: [] # café\n"
        else:
            from packages.hypothesis_validation.adapters import coccinelle as adapter_module
            adapter = adapter_module.CoccinelleAdapter()
            package_name = "coccinelle_pkg"
            rule = "@x@\nexpression E;\n@@\n* foo(E);\n// café\n"
        monkeypatch.setattr(adapter, "is_available", lambda: True)
        package = ModuleType("owned_rule_package")
        package.__dict__.update(vars(getattr(adapter_module, package_name)))
        def run(*args, **kwargs):
            # The adapter's real sandbox policy stays engaged; only the
            # incidental external tool invocation is replaced.
            assert kwargs["subprocess_runner"] is not None
            if kind == "semgrep":
                assert kwargs["unsandboxed"] is False
                consume(kwargs["config"])
                return SemgrepResult()
            consume(kwargs["rule"])
            return SpatchResult(rule="scope")
        package.run_rule = run
        monkeypatch.setattr(adapter_module, package_name, package)
        invoke = lambda: adapter.run(rule, root, env={}).success
    return invoke, state


def _invoke_failure(invoke):
    try:
        assert not invoke()
    except OSError:
        pass  # Some callers expose I/O errors; others return structured errors.


@pytest.mark.parametrize("stage", ["allocate", "write", "close"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_setup_failure_never_reaches_consumer_or_leaks_input(case, pool, stage, error):
    invoke, state = case
    fault, created = pool
    fault.update(stage=stage, error=error)
    if error is KeyboardInterrupt:
        with pytest.raises(error):
            invoke()
    else:
        _invoke_failure(invoke)
    assert state["seen"] == []
    assert bool(created) == (stage != "allocate")
    assert all(stream.file.closed and not path.exists() for stream, _, path in created)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_consumer_failure_reclaims_complete_input(case, pool, error):
    invoke, state = case
    state["error"] = error
    if error is KeyboardInterrupt:
        with pytest.raises(error, match="consumer primary failure"):
            invoke()
    else:
        _invoke_failure(invoke)
    assert state["seen"]
    assert all(stream.file.closed and not path.exists() for stream, _, path in pool[1])


def test_success_uses_closed_utf8_input_and_reclaims_it(case, pool):
    invoke, state = case
    assert invoke()
    assert state["seen"]
    for payload in state["seen"]:
        payload.decode("utf-8")
    assert all(stream.file.closed and not path.exists() for stream, _, path in pool[1])


def test_cleanup_io_error_cannot_discard_successful_result(case, pool):
    invoke, state = case
    pool[0]["unlink"] = OSError
    assert invoke()
    assert state["seen"]
    assert all(stream.file.closed for stream, _, _ in pool[1])


def test_cleanup_cancellation_cannot_mask_primary_cancellation(case, pool):
    invoke, state = case
    state["error"] = KeyboardInterrupt
    pool[0]["unlink"] = KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt, match="consumer primary failure"):
        invoke()
    assert state["seen"]
    assert all(stream.file.closed for stream, _, _ in pool[1])
