"""Execute native discovery mock statements without starting their tools."""
from functools import lru_cache
import ast
import copy
from pathlib import Path
import shutil
import sys
from types import ModuleType

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [('core/analysis/tests/test_binary_oracle.py', {'bo_mod': 'core.analysis.binary_oracle'}),
 ('core/analysis/tests/test_binary_oracle_edges.py',
  {'_edges': 'core.analysis.binary_oracle_edges',
   'edges_mod': 'core.analysis.binary_oracle_edges'}),
 ('core/analysis/tests/test_binary_oracle_fold_and_decode.py',
  {'bo_mod': 'core.analysis.binary_oracle'}),
 ('core/analysis/tests/test_binary_oracle_output.py', {'oracle': 'core.analysis.binary_oracle'}),
 ('core/build/tests/test_has_libasan.py', {'toolchain': 'core.build.toolchain'}),
 ('core/inventory/tests/test_perlasm.py', {'perlasm': 'core.inventory.perlasm'}),
 ('core/run/tests/test_toolprobe_adoption_driftguard.py', {'toolprobe': 'core.run.toolprobe'}),
 ('core/binary/tests/test_inspection_boundaries_native.py',
  {'oracle': 'core.analysis.binary_oracle'}),
 ('core/binary/tests/test_inspection_policy.py', {'oracle': 'core.analysis.binary_oracle'}),
 ('core/audit/tests/test_dark_verify.py', {'ex': 'core.audit.dark_verify._execute'}),
 ('core/audit/tests/test_witness_oracle_dispatch.py',
  {'dispatch': 'core.audit.dark_verify._dispatch'}),
 ('core/audit/corpus/tests/test_rule_eval.py', {'rule_eval': 'core.audit.corpus.rule_eval'}),
 ('core/startup/tests/test_check_tools.py', {'startup_init': 'core.startup.init', 'consumer_0': 'core.startup.init'}),
 ('core/startup/tests/test_install_guard.py', {'guard': 'core.startup.install_guard'}),
 ('packages/joern/tests/test_prereqs.py', {'prereqs': 'packages.joern.prereqs'}),
 ('packages/zkpox/tests/test_proving_deps.py', {'pd': 'packages.zkpox.proving_deps'}),
 ('packages/binary_analysis/tests/test_probe_env_hygiene.py',
  {'r2u': 'packages.binary_analysis.radare2_understand'}),
 ('packages/binary_analysis/tests/test_rr_record.py',
  {'runtime': 'packages.binary_analysis.rr_replay'}),
 ('packages/binary_analysis/tests/test_rr_replay.py',
  {'module': 'packages.binary_analysis.rr_replay'}),
 ('packages/coccinelle/tests/test_runner.py', {'runner_mod': 'packages.coccinelle.runner'}),
 ('packages/semgrep/tests/test_version_probe_home.py',
  {'runner': 'packages.semgrep.runner', 'toolprobe': 'core.run.toolprobe'}),
 ('packages/exploit_feasibility/tests/test_loader_execution_policy.py',
  {'toolexec': 'packages.exploit_feasibility.toolexec'}),
 ('packages/exploit_feasibility/tests/test_toolexec_posture.py',
  {'toolexec_mod': 'packages.exploit_feasibility.toolexec'}),
 ('packages/fuzzing/tests/test_afl_runner.py', {'mod': 'packages.fuzzing.afl_runner'}),
 ('packages/fuzzing/tests/test_binary_only_mode.py',
  {'afl_runner_mod': 'packages.fuzzing.afl_runner',
   'capability': 'packages.fuzzing.capability',
   'orch_mod': 'packages.fuzzing.orchestrator'})]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


@lru_cache(maxsize=None)
def _calls(file):
    tree = _tree(file)
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "patch_module_attribute":
            if len(node.args) == 5 and isinstance(node.args[2], ast.Constant) and node.args[2].value == "shutil" and isinstance(node.args[3], ast.Constant) and node.args[3].value == "which":
                calls.append(node)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "setattr" and len(node.args) == 3:
            if isinstance(node.args[0], ast.Attribute) and node.args[0].attr == "shutil" and isinstance(node.args[1], ast.Constant) and node.args[1].value == "which":
                calls.append(node)
    return sorted(calls, key=lambda node: node.lineno)


def _imported_consumer(tree, call, alias, approved):
    """Resolve a new local import alias only to an already reviewed consumer.

    Prefer the innermost enclosing scope. Do not borrow imports from sibling
    functions or silently accept an ambiguous/new module target.
    """
    scopes = [tree, *(node for node in ast.walk(tree)
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                     and node.lineno <= call.lineno <= node.end_lineno)]
    scopes.sort(key=lambda node: getattr(node, "end_lineno", float("inf"))
                - getattr(node, "lineno", 0))
    for scope in scopes:
        modules = set()
        pending = list(scope.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, ast.Import):
                modules.update((name.name if name.asname else name.name.split(".")[0]) for name in node.names
                               if (name.asname or name.name.split(".")[0]) == alias
                               and node.lineno < call.lineno)
            elif isinstance(node, ast.ImportFrom) and not node.level:
                modules.update(f"{node.module}.{name.name}" for name in node.names
                               if (name.asname or name.name) == alias
                               and node.lineno < call.lineno)
            pending.extend(ast.iter_child_nodes(node))
        if modules:
            assert len(modules) == 1, f"ambiguous consumer import for {alias}: {sorted(modules)}"
            module = modules.pop()
            assert module in approved, f"register newly discovered consumer module: {module}"
            return module
    raise AssertionError(f"consumer alias {alias!r} has no enclosing import; register it explicitly")


def _cases():
    cases = []
    approved = {module for _, aliases in _SPECS for module in aliases.values()}
    for file, aliases in _SPECS:
        for index, call in enumerate(_calls(file)):
            alias = call.args[1].id if isinstance(call.func, ast.Name) else call.args[0].value.id
            module = aliases.get(alias)
            if module is None:
                module = _imported_consumer(_tree(file), call, alias, approved)
            cases.append(pytest.param(file, index, module, id=Path(file).stem + "-" + str(index)))
    return cases


def _consumer(module, borrowed):
    # Execute the actual patch statement against its only required binding.
    # Importing production modules here starts incidental tool/SDK setup;
    # native tests retain the production behavior and discovery return values.
    consumer = ModuleType(module)
    consumer.shutil = shutil
    if borrowed:
        view = ModuleType(shutil.__name__)
        vars(view).update(vars(shutil))
        consumer.shutil = view
    return consumer


def _assert_namespace(owner, before):
    changed = [name for name, value in before.items() if vars(owner).get(name) is not value]
    added = sorted(set(vars(owner)) - set(before))
    assert changed == [] and added == [], (changed, added)


@pytest.mark.parametrize("file,index,module", _cases())
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_discovery_statement_owns_its_binding(file, index, module, borrowed, exit_mode):
    consumer = _consumer(module, borrowed)
    original = consumer.shutil
    raw = dict(vars(consumer))
    inherited = dict(vars(original))
    shared_which = shutil.which

    def fake_which(*args, **kwargs):
        return "/owned/discovery-probe"

    statement = copy.deepcopy(_calls(file)[index])
    private = isinstance(statement.func, ast.Name)
    alias = statement.args[1].id if private else statement.args[0].value.id
    patcher = statement.args[0].id if private else statement.func.value.id
    # Retain the exact native binding target. Its discovery return values are
    # covered by native tests; this probe owns a deterministic lookup result.
    statement.args[-1] = ast.Name(id="fake_which", ctx=ast.Load())
    code = compile(ast.fix_missing_locations(ast.Module(body=[ast.Expr(value=statement)], type_ignores=[])), file, "exec")
    caught = None
    try:
        with pytest.MonkeyPatch.context() as scope:
            namespace = {alias: consumer, patcher: scope, "fake_which": fake_which,
                         "patch_module_attribute": patch_module_attribute}
            exec(code, namespace)
            assert shutil.which is shared_which, "native mock changed shared discovery"
            _assert_namespace(original, inherited)
            assert consumer.shutil.which is fake_which
            assert consumer.shutil.which("owned-tool") == "/owned/discovery-probe"
            if exit_mode != "normal":
                raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
    except BaseException as error:
        caught = error
    assert shutil.which is shared_which
    assert consumer.shutil is original
    _assert_namespace(consumer, raw)
    _assert_namespace(original, inherited)
    if exit_mode == "normal":
        assert caught is None, repr(caught)
    else:
        assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
        assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
def test_unmodified_lookup_is_a_passing_control(borrowed):
    consumer = _consumer("_owned_discovery_consumer", borrowed)
    shared_which = shutil.which
    original = consumer.shutil
    inherited = dict(vars(original))
    assert consumer.shutil.which(sys.executable) is not None
    assert shutil.which is shared_which
    _assert_namespace(original, inherited)


@pytest.mark.parametrize("form", ["import {module} as consumer", "from core import {leaf} as consumer"])
def test_new_alias_respects_function_local_imports(form):
    source = "\n".join(
        f"def case_{leaf}():\n    " + form.format(module=f"core.{leaf}", leaf=leaf)
        + "\n    patch(consumer)"
        for leaf in ("first", "second")
    )
    tree = ast.parse(source)
    calls = sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)),
                   key=lambda node: node.lineno)
    approved = {"core.first", "core.second"}
    assert [_imported_consumer(tree, call, "consumer", approved) for call in calls] == [
        "core.first", "core.second",
    ]


@pytest.mark.parametrize("source,match", [
    ("import core.new as consumer\npatch(consumer)", "register newly discovered"),
    ("def sibling():\n    import core.known as consumer\npatch(consumer)", "no enclosing import"),
    ("if flag:\n    import core.known as consumer\nelse:\n    import core.other as consumer\npatch(consumer)", "ambiguous consumer"),
])
def test_unreviewed_or_unresolvable_consumer_still_fails(source, match):
    tree = ast.parse(source)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    with pytest.raises(AssertionError, match=match):
        _imported_consumer(tree, call, "consumer", {"core.known", "core.other"})


def test_dotted_import_without_alias_binds_only_its_root_package():
    tree = ast.parse("import core.known\npatch(core)")
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    with pytest.raises(AssertionError, match=r"(?m)^register newly discovered consumer module: core$"):
        _imported_consumer(tree, call, "core", {"core.known"})
