"""Exercise native deferred prerequisites without invoking installed tools."""
import ast
import copy
from functools import lru_cache
import itertools
import importlib
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from packages.coccinelle.runner import MIN_SPATCH_VERSION

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'condition': 'not is_available()',
  'file': 'packages/semgrep/tests/test_runner.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 822,
  'old_marker': "pytest.mark.skipif(not is_available(), reason='semgrep not "
                "installed')",
  'reason': "'semgrep not installed'"},
 {'condition': 'not is_available()',
  'file': 'packages/semgrep/tests/test_runner.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 854,
  'old_marker': "pytest.mark.skipif(not is_available(), reason='semgrep not "
                "installed')",
  'reason': "'semgrep not installed'"},
 {'condition': 'is_available() and (not scope_isolation_available())',
  'file': 'packages/semgrep/tests/test_runner.py',
  'fixture': '_live_tool_prerequisite_1',
  'line': 855,
  'old_marker': 'pytest.mark.skipif(is_available() and (not '
                "scope_isolation_available()), reason='semgrep below scope-isolation "
                "floor')",
  'reason': "'semgrep below scope-isolation floor'"},
 {'condition': 'not is_available()',
  'file': 'packages/semgrep/tests/test_runner.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 960,
  'old_marker': "pytest.mark.skipif(not is_available(), reason='semgrep not "
                "installed')",
  'reason': "'semgrep not installed'"},
 {'condition': 'not is_available()',
  'file': 'packages/semgrep/tests/test_runner.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 1228,
  'old_marker': "pytest.mark.skipif(not is_available(), reason='semgrep not "
                "installed')",
  'reason': "'semgrep not installed'"},
 {'condition': "shutil.which('git') is None",
  'file': 'packages/semgrep/tests/test_runner.py',
  'fixture': '_live_tool_prerequisite_2',
  'line': 897,
  'old_marker': "pytest.mark.skipif(shutil.which('git') is None, reason='git not "
                "installed')",
  'reason': "'git not installed'"},
 {'condition': 'not _compose_available()',
  'file': 'core/container/tests/test_compose_sanitize.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 412,
  'old_marker': "pytest.mark.skipif(not _compose_available(), reason='docker compose "
                "unavailable')",
  'reason': "'docker compose unavailable'"},
 {'condition': 'not _live_ready()',
  'file': 'packages/joern/tests/test_server_uds.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 483,
  'old_marker': "pytest.mark.skipif(not _live_ready(), reason='needs a joern install "
                "and user namespaces')",
  'reason': "'needs a joern install and user namespaces'"},
 {'condition': 'not _toolchain_ready()',
  'file': 'packages/ghidra/tests/test_match_precision.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 38,
  'old_marker': "pytest.mark.skipif(not _toolchain_ready(), reason='needs cc, strip, "
                "and radare2')",
  'reason': "'needs cc, strip, and radare2'"},
 {'condition': 'not _docker_reachable()',
  'file': 'packages/cve_env/tests/unit/test_label_cleanup_e2e.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 42,
  'old_marker': "pytest.mark.skipif(not _docker_reachable(), reason='real Docker "
                "daemon required (Colima up)')",
  'reason': "'real Docker daemon required (Colima up)'"},
 {'condition': "not shutil.which('spatch')",
  'file': 'packages/source_intel/tests/test_rule_integrity.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 145,
  'old_marker': "pytest.mark.skipif(not shutil.which('spatch'), reason='spatch not "
                "installed')",
  'reason': "'spatch not installed'"},
 {'condition': "shutil.which('spatch') is not None and (not _meets_min_spatch())",
  'file': 'packages/source_intel/tests/test_rule_integrity.py',
  'fixture': '_live_tool_prerequisite_1',
  'line': 149,
  'old_marker': "pytest.mark.skipif(shutil.which('spatch') is not None and (not "
                '_meets_min_spatch()), reason=f"spatch < {\'.\'.join(map(str, '
                'MIN_SPATCH_VERSION))} cannot parse the prefix-attribute rules RAPTOR '
                'ships against (apt builds on Ubuntu 22.04/24.04 and Debian bookworm '
                'are 1.1.1); the run-time runner degrades per-rule on these. Re-runs '
                'in CI once the runner image carries spatch >= the floor.")',
  'reason': 'f"spatch < {\'.\'.join(map(str, MIN_SPATCH_VERSION))} cannot parse the '
            'prefix-attribute rules RAPTOR ships against (apt builds on Ubuntu '
            '22.04/24.04 and Debian bookworm are 1.1.1); the run-time runner degrades '
            'per-rule on these. Re-runs in CI once the runner image carries spatch >= '
            'the floor."'},
 {'condition': 'not _spatch_meets_min()',
  'file': 'packages/source_intel/tests/test_function_intel_status.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 22,
  'old_marker': "pytest.mark.skipif(not _spatch_meets_min(), reason='spatch >= 1.3 "
                "required for prereqs E2E')",
  'reason': "'spatch >= 1.3 required for prereqs E2E'"},
 {'condition': 'not _spatch_meets_min()',
  'file': 'packages/source_intel/tests/test_function_intel_status.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 38,
  'old_marker': "pytest.mark.skipif(not _spatch_meets_min(), reason='spatch >= 1.3 "
                "required for prereqs E2E')",
  'reason': "'spatch >= 1.3 required for prereqs E2E'"},
 {'condition': 'not _spatch_meets_min()',
  'file': 'packages/source_intel/tests/test_dead_code.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 173,
  'old_marker': "pytest.mark.skipif(not _spatch_meets_min(), reason='spatch >= 1.3 "
                "required for prereqs E2E')",
  'reason': "'spatch >= 1.3 required for prereqs E2E'"},
 {'condition': 'not _spatch_meets_min()',
  'file': 'packages/source_intel/tests/test_dead_code.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 192,
  'old_marker': "pytest.mark.skipif(not _spatch_meets_min(), reason='spatch >= 1.3 "
                "required for prereqs E2E')",
  'reason': "'spatch >= 1.3 required for prereqs E2E'"},
 {'condition': 'not _spatch_meets_min()',
  'file': 'packages/source_intel/tests/test_dead_code.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 212,
  'old_marker': "pytest.mark.skipif(not _spatch_meets_min(), reason='spatch >= 1.3 "
                "required for prereqs E2E')",
  'reason': "'spatch >= 1.3 required for prereqs E2E'"},
 {'condition': 'not _spatch_meets_min()',
  'file': 'packages/source_intel/tests/test_dead_code.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 238,
  'old_marker': "pytest.mark.skipif(not _spatch_meets_min(), reason='spatch >= 1.3 "
                "required for prereqs E2E')",
  'reason': "'spatch >= 1.3 required for prereqs E2E'"},
 {'condition': 'not _spatch_meets_min()',
  'file': 'packages/source_intel/tests/test_dead_code.py',
  'fixture': '_live_tool_prerequisite_0',
  'line': 260,
  'old_marker': "pytest.mark.skipif(not _spatch_meets_min(), reason='spatch >= 1.3 "
                "required for prereqs E2E')",
  'reason': "'spatch >= 1.3 required for prereqs E2E'"}]
_SPECS = {'core/container/tests/test_compose_sanitize.py': [{'condition': 'not '
                                                                 '_compose_available()',
                                                    'fixture': '_live_tool_prerequisite_0',
                                                    'reason': "'docker compose "
                                                              "unavailable'"}],
 'packages/cve_env/tests/unit/test_label_cleanup_e2e.py': [{'condition': 'not '
                                                                         '_docker_reachable()',
                                                            'fixture': '_live_tool_prerequisite_0',
                                                            'reason': "'real Docker "
                                                                      'daemon required '
                                                                      "(Colima up)'"}],
 'packages/ghidra/tests/test_match_precision.py': [{'condition': 'not '
                                                                 '_toolchain_ready()',
                                                    'fixture': '_live_tool_prerequisite_0',
                                                    'reason': "'needs cc, strip, and "
                                                              "radare2'"}],
 'packages/joern/tests/test_server_uds.py': [{'condition': 'not _live_ready()',
                                              'fixture': '_live_tool_prerequisite_0',
                                              'reason': "'needs a joern install and "
                                                        "user namespaces'"}],
 'packages/semgrep/tests/test_runner.py': [{'condition': 'not is_available()',
                                            'fixture': '_live_tool_prerequisite_0',
                                            'reason': "'semgrep not installed'"},
                                           {'condition': 'is_available() and (not '
                                                         'scope_isolation_available())',
                                            'fixture': '_live_tool_prerequisite_1',
                                            'reason': "'semgrep below scope-isolation "
                                                      "floor'"},
                                           {'condition': "shutil.which('git') is None",
                                            'fixture': '_live_tool_prerequisite_2',
                                            'reason': "'git not installed'"}],
 'packages/source_intel/tests/test_dead_code.py': [{'condition': 'not '
                                                                 '_spatch_meets_min()',
                                                    'fixture': '_live_tool_prerequisite_0',
                                                    'reason': "'spatch >= 1.3 required "
                                                              "for prereqs E2E'"}],
 'packages/source_intel/tests/test_function_intel_status.py': [{'condition': 'not '
                                                                             '_spatch_meets_min()',
                                                                'fixture': '_live_tool_prerequisite_0',
                                                                'reason': "'spatch >= "
                                                                          '1.3 '
                                                                          'required '
                                                                          'for prereqs '
                                                                          "E2E'"}],
 'packages/source_intel/tests/test_rule_integrity.py': [{'condition': 'not '
                                                                      "shutil.which('spatch')",
                                                         'fixture': '_live_tool_prerequisite_0',
                                                         'reason': "'spatch not "
                                                                   "installed'"},
                                                        {'condition': "shutil.which('spatch') "
                                                                      'is not None and '
                                                                      '(not '
                                                                      '_meets_min_spatch())',
                                                         'fixture': '_live_tool_prerequisite_1',
                                                         'reason': 'f"spatch < '
                                                                   "{'.'.join(map(str, "
                                                                   'MIN_SPATCH_VERSION))} '
                                                                   'cannot parse the '
                                                                   'prefix-attribute '
                                                                   'rules RAPTOR ships '
                                                                   'against (apt '
                                                                   'builds on Ubuntu '
                                                                   '22.04/24.04 and '
                                                                   'Debian bookworm '
                                                                   'are 1.1.1); the '
                                                                   'run-time runner '
                                                                   'degrades per-rule '
                                                                   'on these. Re-runs '
                                                                   'in CI once the '
                                                                   'runner image '
                                                                   'carries spatch >= '
                                                                   'the floor."'}]}
_CACHE_SPECS = {'core/container/tests/test_compose_sanitize.py': {'fields': ['_compose_invocation'],
                                                   'kind': 'lru',
                                                   'module': 'core.container.compose'},
 'packages/joern/tests/test_server_uds.py': {'fields': ['_resolved_joern',
                                                        '_joern_resolved',
                                                        '_resolved_joern_parse',
                                                        '_joern_parse_resolved',
                                                        '_resolved_java',
                                                        '_java_resolved'],
                                             'kind': 'fields',
                                             'module': 'packages.joern.prereqs'},
 'packages/source_intel/tests/test_dead_code.py': {'fields': ['_spatch_resolved',
                                                              '_resolved_spatch'],
                                                   'kind': 'fields',
                                                   'module': 'packages.coccinelle.runner'},
 'packages/source_intel/tests/test_function_intel_status.py': {'fields': ['_spatch_resolved',
                                                                          '_resolved_spatch'],
                                                               'kind': 'fields',
                                                               'module': 'packages.coccinelle.runner'},
 'packages/source_intel/tests/test_rule_integrity.py': {'fields': ['_spatch_resolved',
                                                                   '_resolved_spatch'],
                                                        'kind': 'fields',
                                                        'module': 'packages.coccinelle.runner'}}
_KEYS = ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _fixture(file, name, namespace):
    node = next((n for n in _tree(file).body if isinstance(n, ast.FunctionDef) and n.name == name), None)
    if node is None:
        return None
    node = copy.deepcopy(node)
    node.decorator_list = []
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), file, "exec"), namespace)
    return namespace[name]


def _calls(spec):
    return list(dict.fromkeys(ast.unparse(n.func) for n in ast.walk(ast.parse(spec["condition"], mode="eval")) if isinstance(n, ast.Call)))


def _namespace(spec, values, fault=None):
    namespace = {"pytest": pytest, "MIN_SPATCH_VERSION": MIN_SPATCH_VERSION}
    which_view = ModuleType(shutil.__name__)
    vars(which_view).update(vars(shutil))
    namespace["shutil"] = which_view
    mocks = {}
    for name, present in zip(_calls(spec), values):
        value = ("/owned/tool" if present else None) if name == "shutil.which" else present
        mock = MagicMock(name=name, return_value=value)
        if fault is not None and name == fault[0]:
            mock.side_effect = fault[1]("owned probe failure")
        if name == "shutil.which":
            which_view.which = mock
        else:
            namespace[name] = mock
        mocks[name] = mock
    return namespace, mocks


def _policy_cases():
    return [pytest.param(file, spec, values, id=file + "-" + spec["fixture"] + "-" + str(values))
            for file, specs in _SPECS.items() for spec in specs
            for values in itertools.product((False, True), repeat=len(_calls(spec)))]


def _fault_cases():
    return [pytest.param(file, spec, name, error, id=file + "-" + spec["fixture"] + "-" + name + "-" + error.__name__)
            for file, specs in _SPECS.items() for spec in specs for name in _calls(spec)
            for error in (RuntimeError, KeyboardInterrupt)]


@pytest.mark.parametrize("index", range(len(_SITES)), ids=[row["file"] + "-" + str(i) for i, row in enumerate(_SITES)])
@pytest.mark.parametrize("available", [False, True])
def test_native_marker_does_not_probe_during_collection(index, available):
    row = _SITES[index]
    ordinal = sum(old["file"] == row["file"] and old["fixture"] == row["fixture"] for old in _SITES[:index])
    old_marker = ast.parse(row["old_marker"], mode="eval").body
    candidates = []
    for node in ast.walk(_tree(row["file"])):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == "usefixtures" and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and node.args[0].value == row["fixture"]:
            candidates.append(node)
        elif node.func.attr == "skipif" and ast.dump(node, include_attributes=False) == ast.dump(old_marker, include_attributes=False):
            candidates.append(node)
    assert len(candidates) > ordinal
    namespace, mocks = _namespace(row, (available,) * len(_calls(row)))
    eval(compile(ast.fix_missing_locations(ast.Expression(copy.deepcopy(candidates[ordinal]))), row["file"], "eval"), namespace)
    assert all(mock.call_count == 0 for mock in mocks.values()), {name: mock.call_count for name, mock in mocks.items()}


@pytest.mark.parametrize("file,spec,values", _policy_cases())
def test_native_fixture_keeps_predicate_and_skip_reason(file, spec, values):
    namespace, _ = _namespace(spec, values)
    expected_skip = bool(eval(spec["condition"], namespace))
    reason = eval(spec["reason"], namespace)
    namespace, _ = _namespace(spec, values)
    fixture = _fixture(file, spec["fixture"], namespace)
    assert fixture is not None, "prerequisite must run in fixture setup"
    node = next(n for n in _tree(file).body if isinstance(n, ast.FunctionDef) and n.name == spec["fixture"])
    assert [a.arg for a in node.args.args] == (["_live_tool_home", "_live_tool_probe_state"] if file in _CACHE_SPECS else ["_live_tool_home"])
    if expected_skip:
        with pytest.raises(pytest.skip.Exception) as caught:
            fixture(*([None, None] if file in _CACHE_SPECS else [None]))
        assert str(caught.value) == reason
    else:
        assert fixture(*([None, None] if file in _CACHE_SPECS else [None])) is None


@pytest.mark.parametrize("file,spec,name,error", _fault_cases())
def test_native_fixture_does_not_hide_probe_failures(file, spec, name, error):
    namespace, _ = _namespace(spec, (True,) * len(_calls(spec)), fault=(name, error))
    fixture = _fixture(file, spec["fixture"], namespace)
    assert fixture is not None
    with pytest.raises(error, match="owned probe failure"):
        fixture(*([None, None] if file in _CACHE_SPECS else [None]))


@pytest.mark.parametrize("file", list(_SPECS))
@pytest.mark.parametrize("inherited", ["absent", "empty", "present"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "skip", "interrupt"])
def test_native_probe_home_restores_inherited_state(file, inherited, exit_mode, tmp_path):
    spec = _SPECS[file][0]
    operator = tmp_path / "operator"
    operator.mkdir()
    sentinel = operator / "keep"
    sentinel.write_text("operator state")
    with pytest.MonkeyPatch.context() as outer:
        for key in _KEYS:
            if inherited == "absent":
                outer.delenv(key, raising=False)
            else:
                outer.setenv(key, "" if inherited == "empty" else str(operator))
        before = dict(os.environ)
        fault = (RuntimeError if exit_mode == "error" else KeyboardInterrupt) if exit_mode in ("error", "interrupt") else None
        namespace, _ = _namespace(spec, (exit_mode != "skip",) * len(_calls(spec)), fault=(_calls(spec)[0], fault) if fault else None)
        home = _fixture(file, "_live_tool_home", namespace)
        gate = _fixture(file, spec["fixture"], namespace)
        assert home is not None and gate is not None
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                home(tmp_path, scope)
                for key in _KEYS:
                    directory = Path(os.environ[key])
                    assert directory.is_dir() and directory.is_relative_to(tmp_path / "live-tool-state")
                gate(*([None, None] if file in _CACHE_SPECS else [None]))
        except BaseException as error:
            caught = error
        assert dict(os.environ) == before
        assert sentinel.read_text() == "operator state"
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            expected = {"error": RuntimeError, "skip": pytest.skip.Exception, "interrupt": KeyboardInterrupt}[exit_mode]
            assert isinstance(caught, expected), repr(caught)


@pytest.mark.parametrize("file", list(_SPECS))
def test_unmodified_environment_control(file):
    before = dict(os.environ)
    namespace, _ = _namespace(_SPECS[file][0], (True,) * len(_calls(_SPECS[file][0])))
    assert bool(eval(_SPECS[file][0]["condition"], namespace)) is False
    assert dict(os.environ) == before


@pytest.mark.parametrize("file", list(_CACHE_SPECS))
@pytest.mark.parametrize("warm", [False, True], ids=["cold", "borrowed-warm"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "skip", "interrupt"])
def test_native_probe_cache_restores_borrowed_state(file, warm, exit_mode):
    spec = _CACHE_SPECS[file]
    consumer = importlib.import_module(spec["module"])
    canonical = {field: getattr(consumer, field) for field in spec["fields"]}
    namespace = {}
    fixture = _fixture(file, "_live_tool_probe_state", namespace)
    assert fixture is not None
    with pytest.MonkeyPatch.context() as outer:
        if spec["kind"] == "lru":
            calls = []
            def lookup():
                calls.append("owned lookup")
                return ("owned-compose",)
            borrowed = lru_cache(maxsize=3 if warm else 1, typed=warm)(lookup)
            borrowed()
            outer.setattr(consumer, "_compose_invocation", borrowed)
            old_info = borrowed.cache_info()
            old_parameters = borrowed.cache_parameters()
        else:
            for field in spec["fields"]:
                value = warm if field.endswith("_resolved") else ("/owned/borrowed/" + field if warm else None)
                outer.setattr(consumer, field, value)
            borrowed_fields = {field: getattr(consumer, field) for field in spec["fields"]}
        caught = None
        try:
            with contextmanager(fixture)():
                if spec["kind"] == "lru":
                    active = consumer._compose_invocation
                    assert active is not borrowed and active.cache_info().currsize == 0
                    assert active.cache_parameters() == old_parameters
                    assert active() == ("owned-compose",)
                    assert borrowed.cache_info() == old_info
                else:
                    for field in spec["fields"]:
                        assert getattr(consumer, field) is (False if field.endswith("_resolved") else None)
                        setattr(consumer, field, True if field.endswith("_resolved") else "/owned/probed/" + field)
                if exit_mode == "skip":
                    pytest.skip("owned cache skip")
                if exit_mode != "normal":
                    raise RuntimeError("owned cache failure") if exit_mode == "error" else KeyboardInterrupt("owned cache failure")
        except BaseException as error:
            caught = error
        if spec["kind"] == "lru":
            assert consumer._compose_invocation is borrowed
            assert borrowed.cache_info() == old_info
        else:
            for field, value in borrowed_fields.items():
                assert getattr(consumer, field) is value
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, {"error": RuntimeError, "skip": pytest.skip.Exception, "interrupt": KeyboardInterrupt}[exit_mode]), repr(caught)
    for field, value in canonical.items():
        assert getattr(consumer, field) is value
