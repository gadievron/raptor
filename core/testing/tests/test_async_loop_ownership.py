"""Parent-thread coroutine probes retain an installed caller event loop."""

import hashlib
import json
from pathlib import Path
import sys

import pytest

from core.testing.standalone_cli import run_standalone_cli
from core.testing.tests.async_loop_probe import FILES, THREAD_ONLY, runner_sites


ROOT = Path(__file__).resolve().parents[3]
PROBE = Path(__file__).with_name("async_loop_probe.py")


def cases():
    result = []
    for path in FILES:
        source = (ROOT / path).read_bytes()
        rows, _ = runner_sites(source.decode())
        for scope, node in rows:
            if (path, scope) != THREAD_ONLY:
                case = dict(path=path, line=node.lineno, column=node.col_offset,
                            sha256=hashlib.sha256(source).hexdigest())
                result.append(pytest.param(case, id=f"{path}:{scope}"))
    return result


@pytest.mark.parametrize("case", cases())
@pytest.mark.parametrize("finish", ["normal", "error", "cancel"])
def test_actual_runner_expression_keeps_caller_and_retires_owned_work(case, finish):
    result = run_standalone_cli(
        [sys.executable, str(PROBE), json.dumps(case), finish],
        cwd=str(ROOT), capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_native_sage_case_preserves_borrowed_loop():
    script = """
import asyncio
from core.sage.tests.test_sage_scripts_common import TestAsyncMemoryExists
borrowed = asyncio.new_event_loop()
asyncio.set_event_loop(borrowed)
try:
    case = TestAsyncMemoryExists('test_returns_false_when_empty')
    case.test_returns_false_when_empty()
    try:
        observed = asyncio.get_event_loop()
    except RuntimeError:
        observed = None
    assert observed is borrowed, 'native test discarded the caller event loop'
    assert not borrowed.is_closed()
finally:
    asyncio.set_event_loop(None)
    borrowed.close()
"""
    result = run_standalone_cli(
        [sys.executable, "-c", script], cwd=str(ROOT),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
