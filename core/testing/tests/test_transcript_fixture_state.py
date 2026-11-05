"""Transcript fixture scopes preserve borrowed session identity and state."""

import ast
from contextlib import contextmanager
from copy import deepcopy
from importlib import import_module
from inspect import signature
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest

from core.llm import transcript
from core.llm.providers import LLMResponse


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("core/llm/tests/test_transcript.py", "_fresh_session"),
    ("packages/llm_analysis/tests/test_transcript_fence.py", "_fresh_session"),
    ("packages/llm_analysis/tests/test_transcript_replay_e2e.py", "_fresh_session"),
    ("packages/llm_analysis/tests/test_context_toolloop_agent.py", "TestTranscriptRoundTrip._fresh_session"),
]


def _view(module):
    view = ModuleType(module.__name__)
    view.__dict__.update(vars(module))
    return view


def _fixture(case, owner, fail_at=None):
    """Run the native fixture against private module bindings, including faults."""
    path, name = case
    calls = 0

    class Patch(pytest.MonkeyPatch):
        def setattr(self, target, field, value, **kwargs):
            nonlocal calls
            super().setattr(target, field, value, **kwargs)
            if target is owner:
                calls += 1
                if calls == fail_at:
                    raise RuntimeError("injected setup failure")

    helper = import_module("core.testing.module_state")
    raw = helper.isolated_module_state.__wrapped__
    pytest_view = _view(pytest)
    pytest_view.MonkeyPatch = Patch
    clone = FunctionType(raw.__code__, dict(raw.__globals__, pytest=pytest_view))
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper_view = _view(helper)
    helper_view.isolated_module_state = contextmanager(clone)
    llm_view = _view(import_module("core.llm"))
    llm_view.transcript = owner

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.llm":
            return llm_view
        if name == "core.llm.transcript":
            return owner
        if name == "core.testing.module_state":
            return helper_view
        return __import__(name, globals, locals, fromlist, level)

    namespace = {
        "reset_active_transcript": owner.reset_active_transcript,
        "__builtins__": dict(vars(import_module("builtins")), __import__=private_import),
    }
    node = ast.parse((ROOT / path).read_text())
    for part in name.split("."):
        node = next(n for n in node.body if getattr(n, "name", None) == part)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return namespace[node.name]


def _owner(tmp_path, state):
    owner = _view(transcript)
    owner._active_lock = threading.Lock()
    owner._active = None
    if state in ("record", "replay"):
        recorder = transcript.TranscriptRecorder(tmp_path / "borrowed.jsonl")
        recorder.record_generate(
            "caller prompt", None, "analyse", {},
            LLMResponse(content="caller answer", model="m", provider="anthropic",
                        tokens_used=1, cost=0.0, finish_reason="stop"),
        )
        owner._active = recorder
        if state == "replay":
            owner._active = transcript.TranscriptReplayer(recorder.path)
            owner._active.match("generate", "caller prompt", None, "analyse", {})
    owner._active_resolved = state != "unresolved"
    raw = transcript.reset_active_transcript
    owner.reset_active_transcript = FunctionType(raw.__code__, owner.__dict__)
    return owner


def _start(function, patch, tmp_path_factory):
    available = {"self": object(), "monkeypatch": patch, "tmp_path_factory": tmp_path_factory}
    generator = function(**{name: available[name] for name in signature(function).parameters})
    next(generator)
    return generator


@pytest.mark.parametrize("case", CASES, ids=[Path(c[0]).stem for c in CASES])
@pytest.mark.parametrize("state", ["unresolved", "resolved-none", "record", "replay"])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_transcript_fixture_preserves_session(case, state, mode, tmp_path, tmp_path_factory):
    owner = _owner(tmp_path, state)
    borrowed, resolved, lock = owner._active, owner._active_resolved, owner._active_lock
    snapshot = vars(borrowed).copy() if borrowed is not None else None
    contents = {name: deepcopy(value) for name, value in (snapshot or {}).items()
                if isinstance(value, (dict, list, set))}
    journal = tmp_path / "borrowed.jsonl"
    journal_before = journal.read_bytes() if journal.exists() else None
    generator = None
    try:
        with pytest.MonkeyPatch.context() as patch:
            generator = _start(_fixture(case, owner), patch, tmp_path_factory)
            assert owner._active is None
            assert owner._active_resolved is False
            assert owner._active_lock is lock
            owner._active = transcript.TranscriptRecorder(tmp_path / "owned.jsonl")
            owner._active_resolved = True
            if mode == "close":
                generator.close()
            elif mode == "throw":
                with pytest.raises(KeyboardInterrupt):
                    generator.throw(KeyboardInterrupt)
            else:
                with pytest.raises(StopIteration):
                    next(generator)
    finally:
        if generator is not None:
            generator.close()
    assert owner._active is borrowed
    assert owner._active_resolved is resolved
    assert owner._active_lock is lock
    if borrowed is not None:
        assert vars(borrowed) == snapshot
        for name, value in snapshot.items():
            assert getattr(borrowed, name) is value
        for name, value in contents.items():
            assert getattr(borrowed, name) == value
    assert (journal.read_bytes() if journal.exists() else None) == journal_before


@pytest.mark.parametrize("case", CASES, ids=[Path(c[0]).stem for c in CASES])
@pytest.mark.parametrize("fail_at", [1, 2])
def test_transcript_fixture_restores_partial_setup(case, fail_at, tmp_path, tmp_path_factory):
    owner = _owner(tmp_path, "record")
    borrowed, lock = owner._active, owner._active_lock
    with pytest.MonkeyPatch.context() as patch:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            _start(_fixture(case, owner, fail_at), patch, tmp_path_factory)
    assert owner._active is borrowed
    assert owner._active_resolved is True
    assert owner._active_lock is lock


@pytest.mark.parametrize("case", CASES[1:], ids=[Path(c[0]).stem for c in CASES[1:]])
def test_transcript_test_imports_do_not_insert_sys_path(case):
    tree = ast.parse((ROOT / case[0]).read_text())
    # Inspect only module-level execution, not legitimate entry-point scripts.
    for node in tree.body:
        assert not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == "sys.path.insert"
        )
