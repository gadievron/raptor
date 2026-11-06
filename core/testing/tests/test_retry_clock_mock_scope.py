"""Observe each native clock mock without starting its worker or timer."""
from functools import lru_cache
import ast
import copy
from pathlib import Path
import time
from types import ModuleType

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [('core/llm/scorecard/tests/test_integrity.py',
  {'mac_key': 'core.security.mac_key', 'sc_mod': 'core.llm.scorecard.scorecard'}),
 ('core/llm/tests/test_cache_integrity_key_race.py', {'mac_key': 'core.security.mac_key'}),
 ('core/llm/tests/test_consumed_attempt_e2e.py', {'client_mod': 'core.llm.client'}),
 ('core/llm/tests/test_consumed_attempt_gate.py', {'client_mod': 'core.llm.client'}),
 ('core/llm/tests/test_max_retries_zero.py', {'client_mod': 'core.llm.client'}),
 ('core/llm/tests/test_retry_log_dedup.py', {'client_mod': 'core.llm.client'}),
 ('core/llm/tests/test_telemetry.py', {'client_mod': 'core.llm.client'}),
 ('core/llm/tests/test_timeout_retry_cap.py', {'client_mod': 'core.llm.client'}),
 ('core/llm/tests/test_truncation_matrix.py', {'client_mod': 'core.llm.client'}),
 ('core/llm/tool_use/tests/test_anthropic.py', {'providers_mod': 'core.llm.providers'}),
 ('core/llm/tool_use/tests/test_loop.py', {'_loop_mod': 'core.llm.tool_use.loop'}),
 ('core/sandbox/tests/test_limits_cache_clock.py', {'preexec': 'core.sandbox.preexec'}),
 ('packages/cve_env/tests/unit/test_docker_run_bounded.py', {'cc': 'core.container.containers'}),
 ('packages/frida/tests/test_follow_children.py', {'runner': 'packages.frida.runner'}),
 ('packages/sca/bump/tests/test_cli.py', {'cache_mod': 'core.json.cache'}),
 ('packages/web/tests/test_client_hardening.py', {'client_module': 'packages.web.client'})]


@lru_cache(maxsize=None)
def _calls(file):
    tree = ast.parse((_REPO / file).read_text())
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "patch_module_attribute":
            if len(node.args) == 5 and isinstance(node.args[2], ast.Constant) and node.args[2].value == "time":
                calls.append(node)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "setattr" and len(node.args) == 3:
            if isinstance(node.args[0], ast.Attribute) and node.args[0].attr == "time" and isinstance(node.args[1], ast.Constant):
                calls.append(node)
    return sorted(calls, key=lambda node: node.lineno)


def _cases():
    cases = []
    for file, aliases in _SPECS:
        for index, call in enumerate(_calls(file)):
            private = isinstance(call.func, ast.Name)
            alias = call.args[1].id if private else call.args[0].value.id
            name = call.args[3].value if private else call.args[1].value
            cases.append(pytest.param(file, index, aliases[alias], name,
                                      id=Path(file).stem + "-" + name + "-" + str(index)))
    return cases


def _consumer(module, borrowed):
    # Execute the real test's patch statement against an owned consumer. It
    # only reads/writes this time binding; importing production modules here
    # starts unrelated SDK imports without exercising their runtime code.
    # The native tests retain that real behavior and import coverage.
    consumer = ModuleType(module)
    consumer.time = time
    if borrowed:
        view = ModuleType(time.__name__)
        vars(view).update(vars(time))
        consumer.time = view
    return consumer


def _assert_namespace(owner, before):
    changed = [name for name, value in before.items() if vars(owner).get(name) is not value]
    added = sorted(set(vars(owner)) - set(before))
    assert changed == [] and added == [], (changed, added)


@pytest.mark.parametrize("file,index,module,name", _cases())
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_clock_statement_owns_its_binding(file, index, module, name, borrowed, exit_mode):
    consumer = _consumer(module, borrowed)
    original = consumer.time
    raw = dict(vars(consumer))
    inherited = dict(vars(original))
    shared_clock = getattr(time, name)

    def fake_clock(*args, **kwargs):
        return 0.0

    statement = copy.deepcopy(_calls(file)[index])
    private = isinstance(statement.func, ast.Name)
    alias = statement.args[1].id if private else statement.args[0].value.id
    patcher = statement.args[0].id if private else statement.func.value.id
    # Native tests exercise the original clock values. This probe retains the
    # actual binding statement but never calls its clock or starts a worker.
    statement.args[-1] = ast.Name(id="fake_clock", ctx=ast.Load())
    code = compile(ast.fix_missing_locations(ast.Module(body=[ast.Expr(value=statement)], type_ignores=[])), file, "exec")
    caught = None
    try:
        with pytest.MonkeyPatch.context() as scope:
            namespace = {alias: consumer, patcher: scope, "fake_clock": fake_clock,
                         "patch_module_attribute": patch_module_attribute}
            exec(code, namespace)
            assert getattr(time, name) is shared_clock, "native mock changed the shared clock"
            _assert_namespace(original, inherited)
            assert getattr(consumer.time, name) is fake_clock
            if exit_mode != "normal":
                raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
    except BaseException as error:
        caught = error
    assert getattr(time, name) is shared_clock
    assert consumer.time is original
    _assert_namespace(consumer, raw)
    _assert_namespace(original, inherited)
    if exit_mode == "normal":
        assert caught is None, repr(caught)
    else:
        assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
        assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
def test_unmodified_clock_is_a_passing_control(borrowed):
    consumer = _consumer("core.audit.prep_profile", borrowed)
    shared_clock = time.perf_counter
    original = consumer.time
    inherited = dict(vars(original))
    assert consumer.time.perf_counter is shared_clock
    _assert_namespace(original, inherited)
