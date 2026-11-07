"""Native thread fault hooks preserve the shared threading namespace."""

import ast
from pathlib import Path
import threading

import pytest

from core.llm.dispatcher import server
from core.llm.tests import mock_upstream
from packages.web.tests import http_server as http_support
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
    ('core/http/tests/test_backend_fixture_cleanup.py', 'test_http_fixture_failure_retires_listener_and_worker'),
    ('core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py', 'tracked_listeners'),
    ('core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py', 'test_partial_constructor_retires_all_acquired_listeners'),
    ('core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py', 'test_failed_optional_tcp_setup_is_retired_and_can_be_retried'),
    ('core/llm/dispatcher/tests/test_http_teardown_cleanup.py', '_record_servers'),
    ('core/llm/dispatcher/tests/test_proxy_gateway_fixture_cleanup.py', 'test_gateway_fixture_retires_resources_and_unread_token'),
    ('core/llm/dispatcher/tests/test_proxy_gateway_fixture_cleanup.py', 'test_proxy_http_startup_and_shutdown_own_listener_and_thread'),
    ('core/llm/dispatcher/tests/test_setup_ownership.py', 'test_dispatcher_failure_reclaims_started_upstream'),
    ('core/llm/dispatcher/tests/test_web_http_fixture_cleanup.py', 'test_http_fixture_owns_listener'),
]


@pytest.mark.parametrize('path,name', _SITES)
@pytest.mark.parametrize('exit_kind', ['normal', 'error', 'interrupt'])
def test_native_constructor_hook_is_private(path, name, exit_kind):
    tree = ast.parse((_ROOT / path).read_text())
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)
             and any(isinstance(a, ast.Constant) and a.value == 'Thread' for a in n.args)]
    assert len(calls) == (3 if path.endswith('test_setup_ownership.py') else 1)
    if path.endswith('test_scratch.py'):
        consumers = (scratch,)
    elif path.endswith('test_raw_upstream_cleanup.py'):
        consumers = (socket_server,)
    elif path.endswith('test_dispatcher_lifecycle_cleanup.py'):
        consumers = (server,)
    elif path.endswith('test_setup_ownership.py'):
        consumers = (http_support, socket_server, mock_upstream)
    else:
        consumers = (http_support,)
    borrowed = [consumer.threading for consumer in consumers]
    original = threading.Thread
    seen = []

    def replacement(*args, **kwargs):
        seen.append((args, kwargs))
        return 'owned constructor'

    failure = {'normal': None, 'error': RuntimeError, 'interrupt': KeyboardInterrupt}[exit_kind]
    try:
        with pytest.MonkeyPatch.context() as scope:
            namespace = dict(patch_module_attribute=patch_module_attribute,
                             monkeypatch=scope, patcher=scope, fault=scope, threading=threading,
                             http_support=http_support, server=server, mock_upstream=mock_upstream,
                             scratch_mod=scratch, socket_server=socket_server,
                             _BoomThread=replacement, create_thread=replacement,
                             thread=replacement, failed_thread=replacement)
            for call in calls:
                exec(compile(ast.Expression(call), path, 'eval'), namespace)
            assert threading.Thread is original
            for consumer, previous in zip(consumers, borrowed, strict=True):
                assert consumer.threading is not previous
                assert consumer.threading.Thread('sentinel', daemon=True) == 'owned constructor'
                assert consumer.threading.Event is threading.Event
            assert seen == [(('sentinel',), {'daemon': True})] * len(consumers)
            if failure:
                raise failure('injected unwind')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert failure is type(error)
    finally:
        for consumer, previous in zip(consumers, borrowed, strict=True):
            assert consumer.threading is previous
        assert threading.Thread is original


@pytest.mark.parametrize('name,target', [
    ('test_partial_constructor_retires_all_acquired_listeners', 'real_thread'),
    ('test_failed_optional_tcp_setup_is_retired_and_can_be_retried', 'thread'),
])
def test_nested_dispatcher_fault_keeps_outer_tracking(name, target):
    path = _ROOT / 'core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py'
    tree = ast.parse(path.read_text())
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    assignment = next(n for n in ast.walk(function) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == target for t in n.targets)
                      and isinstance(n.value, ast.Attribute) and n.value.attr == 'Thread')
    outer_tracker = object()
    with pytest.MonkeyPatch.context() as scope:
        patch_module_attribute(scope, server, 'threading', 'Thread', outer_tracker)
        namespace = dict(server=server, threading=threading)
        exec(compile(ast.Module(body=[assignment], type_ignores=[]), str(path), 'exec'), namespace)
        assert namespace[target] is outer_tracker
