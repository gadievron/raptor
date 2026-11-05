"""Fixture lifecycle checks with real jail owners, sockets and benign children.

Startup is replaced only to inject lifecycle faults after resource acquisition;
these checks make no claim about confinement. Native boundary checks run the
real workers separately.
"""

import ast
from contextlib import ExitStack
from pathlib import Path
import socket
import subprocess
import sys
from types import FunctionType, ModuleType

import pytest

from core.testing.processes import reap_on_exit


CASES = [
    ("core/sandbox/tests/test_parser_jail.py", "parser_jail", "ParserJail"),
    ("core/llm/dispatcher/tests/test_usage_scan_jail.py", "usage_scan_jail", "UsageScanJail"),
]
ROOT = Path(__file__).resolve().parents[3]


def _fixture(path, name, namespace):
    tree = ast.parse((ROOT / path).read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    module = ModuleType("fixture_under_test")
    module.__dict__.update(namespace)
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), vars(module))
    return getattr(module, name)


def _view(original):
    view = ModuleType(original.__name__)
    view.__dict__.update(vars(original))
    # Getter and reset must act on this real module view, not production globals.
    for name in ("get_usage_scan_jail", "get_parser_jail", "_reset_for_tests"):
        if hasattr(original, name):
            function = getattr(original, name)
            clone = FunctionType(function.__code__, vars(view), name, function.__defaults__)
            clone.__kwdefaults__ = function.__kwdefaults__
            setattr(view, name, clone)
    return view


def _attach_resources(jail, resources):
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    resources.enter_context(reap_on_exit(process))
    local, peer = socket.socketpair()
    resources.callback(local.close)
    resources.callback(peer.close)
    jail._proc = process
    jail._sock = local
    return process, local


@pytest.mark.parametrize("path,owner,class_name", CASES)
@pytest.mark.parametrize("finish", ["resume", "close", "interrupt", "startup_error", "startup_interrupt"])
def test_fresh_fixture_always_finishes_owned_resources(path, owner, class_name, finish):
    from core.llm.dispatcher import usage_scan_jail
    from core.sandbox import parser_jail

    original = {"parser_jail": parser_jail, "usage_scan_jail": usage_scan_jail}[owner]
    view = _view(original)
    jail = getattr(original, class_name)()
    setattr(view, class_name, lambda: jail)
    fixture = _fixture(path, "fresh_jail", {owner: view})
    with ExitStack() as resources:
        process, stream = _attach_resources(jail, resources)

        def start():
            # Resource acquisition has already occurred; the fixture must own it
            # even when readiness never succeeds.
            if finish == "startup_error":
                raise RuntimeError("startup failed")
            if finish == "startup_interrupt":
                raise KeyboardInterrupt

        jail.start = start
        generator = fixture()
        try:
            if finish.startswith("startup"):
                error = RuntimeError if finish == "startup_error" else KeyboardInterrupt
                with pytest.raises(error):
                    next(generator)
            else:
                assert next(generator) is jail
                assert process.poll() is None
                if finish == "resume":
                    with pytest.raises(StopIteration):
                        next(generator)
                elif finish == "interrupt":
                    with pytest.raises(KeyboardInterrupt):
                        generator.throw(KeyboardInterrupt)
                else:
                    generator.close()
            assert jail._stopped is True
            assert jail._proc is None
            assert jail._sock is None
            assert stream.fileno() == -1
            assert process.returncode is not None
        finally:
            generator.close()
            jail.stop()


@pytest.mark.parametrize("path,owner,class_name", CASES)
@pytest.mark.parametrize("finish", ["resume", "close", "interrupt"])
@pytest.mark.parametrize("replace_owned", [False, True])
def test_singleton_fixture_preserves_live_borrowed_worker(path, owner, class_name, finish, replace_owned):
    from core.llm.dispatcher import usage_scan_jail
    from core.sandbox import parser_jail

    original = {"parser_jail": parser_jail, "usage_scan_jail": usage_scan_jail}[owner]
    view = _view(original)
    borrowed = getattr(original, class_name)()
    view._jail = borrowed
    name = "isolated_parser_singleton" if owner == "parser_jail" else "reset_singleton"
    # The parser scope is newly introduced. On the baseline, exercise the
    # original singleton test itself so the failure proves it stops its caller.
    if not any(isinstance(n, ast.FunctionDef) and n.name == name
               for n in ast.parse((ROOT / path).read_text()).body):
        import importlib
        native = importlib.import_module("core.sandbox.tests.test_parser_jail")
        method = native.TestSingleton.test_get_returns_same_jail_and_reset_tears_down
        run = FunctionType(method.__code__, {**method.__globals__, "parser_jail": view})
        with ExitStack() as resources:
            process, _stream = _attach_resources(borrowed, resources)
            resources.callback(borrowed.stop)
            run(None)
            assert view._jail is borrowed
            assert process.poll() is None
        return
    fixture = _fixture(path, name, {owner: view})
    # Singleton ownership is independent of eager parser startup. Retain real
    # ParserJail owners, but attach benign owned resources below.
    if owner == "parser_jail":
        def make_parser():
            jail = parser_jail.ParserJail()
            jail.start = lambda: None
            return jail
        view.ParserJail = make_parser
    get_jail = view.get_parser_jail if owner == "parser_jail" else view.get_usage_scan_jail
    lock = view._jail_lock
    with ExitStack() as resources:
        process, stream = _attach_resources(borrowed, resources)
        resources.callback(borrowed.stop)
        generator = fixture()
        owned = []
        try:
            next(generator)
            assert process.poll() is None
            assert borrowed._stopped is False
            assert view._jail is None
            first = get_jail()
            owned.append(first)
            first_process, first_stream = _attach_resources(first, resources)
            if replace_owned:
                view._reset_for_tests()
                assert first_process.returncode is not None
                replacement = get_jail()
                owned.append(replacement)
                last_process, last_stream = _attach_resources(replacement, resources)
            else:
                last_process, last_stream = first_process, first_stream
            if finish == "resume":
                with pytest.raises(StopIteration):
                    next(generator)
            elif finish == "interrupt":
                with pytest.raises(KeyboardInterrupt):
                    generator.throw(KeyboardInterrupt)
            else:
                generator.close()
            assert view._jail is borrowed
            assert view._jail_lock is lock
            assert not lock.locked()
            assert process.poll() is None
            assert stream.fileno() != -1
            assert borrowed._stopped is False
            assert first_process.returncode is not None
            assert last_process.returncode is not None
            assert last_stream.fileno() == -1
            assert all(jail._stopped for jail in owned)
        finally:
            generator.close()
            for jail in owned:
                view.atexit.unregister(jail.stop)
                jail.stop()
