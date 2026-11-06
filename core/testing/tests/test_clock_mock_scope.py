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
_SPECS = [('core/analysis/tests/test_sanitizer_cut_postpass.py',
  {'scp': 'core.analysis.sanitizer_cut_postpass'}),
 ('core/audit/tests/test_cost_tracker.py', {'ct_mod': 'core.audit.cost_tracker'}),
 ('core/audit/tests/test_heartbeat.py', {'hb_mod': 'core.audit.heartbeat'}),
 ('core/audit/tests/test_joern_backend.py', {'jb': 'core.audit.joern_backend'}),
 ('core/audit/tests/test_prep_profile.py', {'prep_profile': 'core.audit.prep_profile'}),
 ('core/audit/tests/test_resource_bounds.py', {'rb': 'core.audit.resource_bounds'}),
 ('core/audit/tests/test_zero_dispatch_resweep.py',
  {'orch': 'core.audit.orchestrator'}),
 ('core/coverage/tests/test_journal_mac.py', {'mac_key': 'core.security.mac_key'}),
 ('core/http/tests/test_urllib_backend.py', {'ub': 'core.http.urllib_backend'}),
 ('core/iris/tests/test_store_integrity.py', {'mac_key': 'core.security.mac_key'}),
 ('core/sandbox/tests/test_landlock_audit_reap.py',
  {'audit': 'core.sandbox._landlock_audit'}),
 ('core/sandbox/tests/test_landlock_probe_lifecycle.py',
  {'probes': 'core.sandbox.probes'}),
 ('core/sandbox/tests/test_mount_ns_etc_copy.py', {'mns': 'core.sandbox.mount_ns'}),
 ('core/sandbox/tests/test_namespace_probe_lifecycle.py',
  {'probes': 'core.sandbox.probes'}),
 ('core/sandbox/tests/test_parser_jail_io_reliability.py',
  {'jail_mod': 'core.sandbox.parser_jail'}),
 ('core/sandbox/tests/test_parser_jail_startup_cleanup.py',
  {'jail_mod': 'core.sandbox.parser_jail'}),
 ('core/sandbox/tests/test_parser_worker_poll_failure.py',
  {'jail': 'core.sandbox.parser_jail'}),
 ('core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  {'probe': 'core.sandbox.ptrace_probe'}),
 ('core/sandbox/tests/test_ptrace_probe_deadline.py',
  {'probe': 'core.sandbox.ptrace_probe'}),
 ('core/sandbox/tests/test_spawn_pidfd_fallback.py', {'spawn': 'core.sandbox._spawn'}),
 ('core/sandbox/tests/test_spawn_startup_poll.py', {'spawn': 'core.sandbox._spawn'}),
 ('core/sandbox/tests/test_telemetry_creator_disappears.py',
  {'mac': 'core.sandbox.telemetry_mac'}),
 ('core/sandbox/tests/test_telemetry_mac.py', {'tmac': 'core.sandbox.telemetry_mac'}),
 ('core/testing/tests/test_expected_crash.py',
  {'helper': 'core.testing.expected_crash'}),
 ('core/witness/tests/test_provenance.py', {'mac_key': 'core.security.mac_key'})]


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
