"""Native thread fault hooks preserve the shared threading namespace."""

import ast
from pathlib import Path
import threading

import pytest

from core.run import scratch
from core.sandbox.tests import socket_server
from core.testing.module_bindings import patch_module_attribute


_ROOT = Path(__file__).resolve().parents[3]
_SITES = [
    ('core/run/tests/test_scratch.py', 'test_ticker_start_failure_discards_registration'),
    ('core/llm/dispatcher/tests/test_raw_upstream_cleanup.py', 'test_raw_upstream_startup_closes_listener'),
    ('core/llm/dispatcher/tests/test_raw_upstream_cleanup.py', 'test_raw_upstream_handler_failure_releases_connection'),
    ('core/llm/dispatcher/tests/test_raw_upstream_cleanup.py', 'test_wedged_upstream_shutdown_retires_threads'),
    ('core/llm/dispatcher/tests/test_raw_upstream_cleanup.py', 'test_watchdog_setup_failure_reclaims_upstream'),
]


@pytest.mark.parametrize('path,name', _SITES)
@pytest.mark.parametrize('exit_kind', ['normal', 'error', 'interrupt'])
def test_native_constructor_hook_is_private(path, name, exit_kind):
    tree = ast.parse((_ROOT / path).read_text())
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)
             and any(isinstance(a, ast.Constant) and a.value == 'Thread' for a in n.args)]
    assert len(calls) == 1
    call = calls[0]
    consumer = scratch if path.endswith('test_scratch.py') else socket_server
    borrowed = consumer.threading
    original = threading.Thread
    seen = []

    def replacement(*args, **kwargs):
        seen.append((args, kwargs))
        return 'owned constructor'

    failure = {'normal': None, 'error': RuntimeError, 'interrupt': KeyboardInterrupt}[exit_kind]
    try:
        with pytest.MonkeyPatch.context() as scope:
            namespace = dict(patch_module_attribute=patch_module_attribute,
                             monkeypatch=scope, patcher=scope, threading=threading,
                             scratch_mod=scratch, socket_server=socket_server,
                             _BoomThread=replacement, create_thread=replacement,
                             thread=replacement)
            exec(compile(ast.Expression(call), path, 'eval'), namespace)
            assert threading.Thread is original
            assert consumer.threading is not borrowed
            assert consumer.threading.Thread('sentinel', daemon=True) == 'owned constructor'
            assert seen == [(('sentinel',), {'daemon': True})]
            assert consumer.threading.Event is threading.Event
            if failure:
                raise failure('injected unwind')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert failure is type(error)
    finally:
        assert consumer.threading is borrowed
        assert threading.Thread is original
