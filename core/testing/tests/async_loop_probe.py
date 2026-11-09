"""Execute one real test runner expression in an owned child interpreter."""

import ast
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
import threading


ROOT = Path(__file__).resolve().parents[3]
FILES = (
    "core/sandbox/tests/test_proxy_sock_diag.py",
    "core/llm/tests/test_throttle.py",
    "core/sage/tests/test_sage_scripts_common.py",
    "core/sage/tests/test_seed_sage_knowledge.py",
    "core/sandbox/tests/test_proxy_progress_cap.py",
    "core/sandbox/tests/test_proxy_submission_cleanup.py",
)
THREAD_ONLY = (
    "core/llm/tests/test_throttle.py",
    "TestAcquireLivelockAndMixedWakeups._run_bounded.runner",
)


def runner_sites(source):
    tree = ast.parse(source)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return name(node.value) + "." + node.attr
        return ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            target = name(node.value)
            if target in ("asyncio.run", "asyncio.runners.run"):
                for item in node.targets:
                    if isinstance(item, ast.Name):
                        aliases[item.id] = target
    rows, scopes = [], []

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node):
            scopes.append(node.name)
            self.generic_visit(node)
            scopes.pop()

        def visit_FunctionDef(self, node):
            scopes.append(node.name)
            self.generic_visit(node)
            scopes.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            if name(node.func) in ("asyncio.run", "asyncio.runners.run"):
                rows.append((".".join(scopes), node))
            self.generic_visit(node)

    Visitor().visit(tree)
    return rows, aliases


def exercise(case, finish):
    assert case["path"] in FILES
    source = (ROOT / case["path"]).read_bytes()
    assert hashlib.sha256(source).hexdigest() == case["sha256"]
    rows, aliases = runner_sites(source.decode())
    scope, original = next((scope, node) for scope, node in rows
                           if node.lineno == case["line"] and node.col_offset == case["column"])
    assert (case["path"], scope) != THREAD_ONLY
    call = copy.deepcopy(original)
    # Exercise the real runner/factory expression with controlled work. The
    # original native coroutine bodies are validated separately by their tests.
    call.args = [ast.Name(id="coroutine", ctx=ast.Load())]
    expression = ast.fix_missing_locations(ast.Expression(call))
    borrowed = asyncio.new_event_loop()
    asyncio.set_event_loop(borrowed)
    owned, streams, retired = [], [], []
    before_threads = set(threading.enumerate())
    failure = (LookupError("owned coroutine failed") if finish == "error" else
               asyncio.CancelledError("owned coroutine cancelled") if finish == "cancel" else None)

    async def pending():
        try:
            await asyncio.Event().wait()
        finally:
            retired.append("task")

    async def stream():
        try:
            yield "open"
        finally:
            retired.append("generator")

    async def work():
        owned.append(asyncio.get_running_loop())
        asyncio.create_task(pending())
        await asyncio.sleep(0)
        generator = stream()
        streams.append(generator)
        assert await anext(generator) == "open"
        assert await asyncio.to_thread(lambda: "executor") == "executor"
        if failure is not None:
            raise failure
        return "completed"

    coroutine = work()
    namespace = {"asyncio": asyncio, "coroutine": coroutine}
    for alias, target in aliases.items():
        if target == "asyncio":
            namespace[alias] = asyncio
        elif target in ("asyncio.run", "asyncio.runners.run"):
            namespace[alias] = asyncio.run
        elif target == "asyncio.new_event_loop":
            namespace[alias] = asyncio.new_event_loop
    try:
        try:
            result = eval(compile(expression, str(ROOT / case["path"]), "eval"), namespace)
        except BaseException as caught:
            assert caught is failure
        else:
            assert failure is None
            assert result == "completed"
        try:
            observed = asyncio.get_event_loop()
        except RuntimeError:
            observed = None
        assert observed is borrowed, "runner discarded the caller's installed loop"
        assert not borrowed.is_closed()
        assert len(owned) == 1 and owned[0] is not borrowed
        assert owned[0].is_closed() and not owned[0].is_running()
        assert sorted(retired) == ["generator", "task"]
        assert set(threading.enumerate()) == before_threads, "owned executor thread survived runner cleanup"
    finally:
        coroutine.close()
        asyncio.set_event_loop(None)
        borrowed.close()


if __name__ == "__main__":
    exercise(json.loads(sys.argv[1]), sys.argv[2])
