"""Borrowed trust and signal handlers survive native fixture unwinding."""

import ast
from importlib import import_module
from pathlib import Path
import signal
from types import FunctionType, ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("packages/sca/tests/test_scan_args.py", "_restore_trust_overrides"),
    ("packages/joern/tests/test_pidns_forwarder.py", "restore_signal_handlers"),
    ("packages/joern/tests/test_pidns_contract.py", "restore_signal_handlers"),
]


def _view(name):
    owner = ModuleType(name)
    owner.__dict__.update(vars(import_module(name)))
    return owner


def _native(case, request, seed):
    if case[1] == "_restore_trust_overrides":
        cc, ql = _view("core.security.cc_trust"), _view("core.security.codeql_trust")
        cc._trust_override_set, ql._trust_override_set = seed, not seed
        for owner in (cc, ql):
            for name in ("set_trust_override", "is_trust_overridden"):
                if hasattr(owner, name):
                    raw = getattr(owner, name)
                    setattr(owner, name, FunctionType(raw.__code__, owner.__dict__))
        security = _view("core.security")
        security.cc_trust, security.codeql_trust = cc, ql

        def private_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "core.security":
                return security
            return __import__(name, globals, locals, fromlist, level)

        namespace = {"__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}
        original = (cc._trust_override_set, ql._trust_override_set)

        def change(patch):
            for owner in (cc, ql):
                value = not owner._trust_override_set
                if patch:
                    patch.setattr(owner, "_trust_override_set", value)
                else:
                    owner.set_trust_override(value)

        def read():
            return cc._trust_override_set, ql._trust_override_set

        def fail_restore(error):
            raw = ql.set_trust_override

            def fail(value):
                raw(value)
                if value is original[1]:
                    raise error("restore interrupted")

            ql.set_trust_override = fail
    else:
        view = _view("signal")

        def first(signum, frame):
            pass

        def second(signum, frame):
            pass

        original = (first, second) if seed else (second, first)
        saved = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        def cleanup():
            for sig, handler in saved.items():
                signal.signal(sig, handler)

        request.addfinalizer(cleanup)
        for sig, handler in zip(saved, original):
            signal.signal(sig, handler)
        namespace = {"signal": view}

        def change(patch):
            # Body monkeypatches replace the consumer's signal API while
            # handler changes still reach the real process boundary.
            if patch:
                patch.setattr(view, "signal", signal.signal)
            for sig in saved:
                view.signal(sig, signal.SIG_IGN)

        def read():
            return signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)

        def fail_restore(error):
            def fail(sig, handler):
                signal.signal(sig, handler)
                if sig == signal.SIGINT and handler is original[1]:
                    raise error("restore interrupted")

            view.signal = fail


    node = next(n for n in ast.parse((ROOT / case[0]).read_text()).body if getattr(n, "name", None) == case[1])
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), case[0], "exec"), namespace)
    return namespace[case[1]], original, change, read, fail_restore, cleanup if case[1] != "_restore_trust_overrides" else lambda: None


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("finish", ["resume", "close", "interrupt", "error"])
@pytest.mark.parametrize("body_patch", [False, True])
def test_borrowed_state_restored_on_exit(case, seed, finish, body_patch, request):
    fixture, original, change, read, _, cleanup = _native(case, request, seed)
    patch = pytest.MonkeyPatch()
    generator = fixture(monkeypatch=patch)
    try:
        next(generator)
        assert read() == original
        change(patch if body_patch else None)
        assert read() != original
        if finish == "resume":
            with pytest.raises(StopIteration):
                next(generator)
        elif finish == "close":
            generator.close()
        else:
            error = KeyboardInterrupt if finish == "interrupt" else RuntimeError
            with pytest.raises(error):
                generator.throw(error("body interrupted"))
        patch.undo()
        assert read() == original
    finally:
        generator.close()
        patch.undo()
        cleanup()


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_all_restorations_attempted_after_cleanup_error(case, error, request):
    fixture, original, change, read, fail_restore, cleanup = _native(case, request, True)
    patch = pytest.MonkeyPatch()
    generator = fixture(monkeypatch=patch)
    try:
        fail_restore(error)
        next(generator)
        change(None)
        with pytest.raises(error, match="restore interrupted"):
            generator.close()
        assert read() == original
    finally:
        generator.close()
        patch.undo()
        cleanup()
