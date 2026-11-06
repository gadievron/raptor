"""Real native mock targets must leave shared and borrowed modules untouched."""
import ast
import copy
from contextlib import ExitStack, contextmanager
from functools import lru_cache
import importlib.machinery
import importlib.util
import inspect
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 131,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 158,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 193,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 223,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 273,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 305,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 338,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 361,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup.py',
  'kind': 'object',
  'line': 434,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_startup.py',
  'kind': 'monkey',
  'line': 17,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_startup.py',
  'kind': 'monkey',
  'line': 99,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_malformed.py',
  'kind': 'monkey',
  'line': 67,
  'receiver': 'seatbelt_audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup_cleanup.py',
  'kind': 'monkey',
  'line': 28,
  'receiver': 'audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_seatbelt_audit_warmup_io.py',
  'kind': 'monkey',
  'line': 25,
  'receiver': 'audit'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_parser_jail_startup_cleanup.py',
  'kind': 'monkey',
  'line': 96,
  'receiver': 'jail_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'core/sandbox/tests/test_parser_jail_teardown.py',
  'kind': 'monkey',
  'line': 90,
  'receiver': 'parser'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/dataflow/tests/test_cvefix_bridge.py',
  'kind': 'monkey',
  'line': 322,
  'receiver': 'cvefix_bridge'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/dataflow/tests/test_cvefix_bridge.py',
  'kind': 'monkey',
  'line': 380,
  'receiver': 'cvefix_bridge'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/dataflow/tests/test_cvefix_walk.py',
  'kind': 'monkey',
  'line': 202,
  'receiver': 'cvefix_walk'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/dataflow/tests/test_cvefix_walk.py',
  'kind': 'monkey',
  'line': 523,
  'receiver': 'cvefix_walk'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/dataflow/tests/test_ghsa_harvester.py',
  'kind': 'monkey',
  'line': 286,
  'receiver': 'gh'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/dataflow/tests/test_ghsa_harvester.py',
  'kind': 'monkey',
  'line': 323,
  'receiver': 'gh'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_env/tests/unit/test_cvefix_envs.py',
  'kind': 'monkey',
  'line': 229,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_env/tests/unit/test_cvefix_envs.py',
  'kind': 'monkey',
  'line': 249,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_env/tests/unit/test_cvefix_envs.py',
  'kind': 'monkey',
  'line': 266,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_env/tests/unit/test_cvefix_envs.py',
  'kind': 'monkey',
  'line': 279,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_env/tests/unit/test_cvefix_envs.py',
  'kind': 'monkey',
  'line': 312,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_env/tests/unit/test_subprocess_env_hygiene.py',
  'kind': 'monkey',
  'line': 188,
  'receiver': '_proc_mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_env/tests/unit/test_subprocess_env_hygiene.py',
  'kind': 'monkey',
  'line': 220,
  'receiver': '_proc_mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_diff/tests/unit/infra/test_service_health.py',
  'kind': 'monkey',
  'line': 415,
  'receiver': 'service_health'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_diff/tests/unit/infra/test_service_health.py',
  'kind': 'monkey',
  'line': 353,
  'receiver': 'service_health'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/cve_diff/tests/unit/infra/test_service_health.py',
  'kind': 'monkey',
  'line': 357,
  'receiver': 'service_health'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/frida/tests/test_patch_oracle.py',
  'kind': 'monkey',
  'line': 274,
  'receiver': 'patch_oracle'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/frida/tests/test_patch_oracle.py',
  'kind': 'monkey',
  'line': 309,
  'receiver': 'patch_oracle'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/frida/tests/test_patch_oracle.py',
  'kind': 'monkey',
  'line': 351,
  'receiver': 'patch_oracle'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/frida/tests/test_patch_oracle.py',
  'kind': 'monkey',
  'line': 413,
  'receiver': 'patch_oracle'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/frida/tests/test_patch_oracle.py',
  'kind': 'monkey',
  'line': 474,
  'receiver': 'po'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 224,
  'receiver': 'fo'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 243,
  'receiver': 'fo'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 258,
  'receiver': 'fo'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 277,
  'receiver': 'fo'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 307,
  'receiver': 'fo'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 334,
  'receiver': 'fo'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 351,
  'receiver': 'fo'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'monkey',
  'line': 188,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'monkey',
  'line': 206,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'monkey',
  'line': 225,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'monkey',
  'line': 242,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'monkey',
  'line': 259,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'monkey',
  'line': 320,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'object',
  'line': 70,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/joern/tests/test_prereqs.py',
  'kind': 'object',
  'line': 89,
  'receiver': 'prereqs'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/llm/tests/test_cc_probe.py',
  'kind': 'monkey',
  'line': 99,
  'receiver': 'cc_probe'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/llm/tests/test_cc_probe.py',
  'kind': 'monkey',
  'line': 237,
  'receiver': 'cc_probe'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/llm/tests/test_cc_probe.py',
  'kind': 'monkey',
  'line': 251,
  'receiver': 'cc_probe'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_fix_diff.py',
  'kind': 'monkey',
  'line': 233,
  'receiver': 'fix_diff'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_fix_diff.py',
  'kind': 'monkey',
  'line': 92,
  'receiver': 'fix_diff'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_fix_diff.py',
  'kind': 'monkey',
  'line': 110,
  'receiver': 'fix_diff'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_fix_diff.py',
  'kind': 'monkey',
  'line': 116,
  'receiver': 'fix_diff'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_playwright_source_evidence.py',
  'kind': 'monkey',
  'line': 68,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_playwright_source_evidence.py',
  'kind': 'monkey',
  'line': 126,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_node_release_evidence.py',
  'kind': 'monkey',
  'line': 78,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/tests/test_node_release_evidence.py',
  'kind': 'monkey',
  'line': 91,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/sca/parsers/tests/test_gitmodules.py',
  'kind': 'monkey',
  'line': 382,
  'receiver': 'gm'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/binary_analysis/tests/test_cli.py',
  'kind': 'object',
  'line': 598,
  'receiver': 'cli_mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/binary_analysis/tests/test_cli.py',
  'kind': 'object',
  'line': 618,
  'receiver': 'cli_mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'packages/binary_analysis/tests/test_cli.py',
  'kind': 'object',
  'line': 665,
  'receiver': 'cli_mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/concepts/tests/test_study_loop.py',
  'kind': 'monkey',
  'line': 530,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/concepts/tests/test_study_loop.py',
  'kind': 'monkey',
  'line': 558,
  'receiver': 'mod'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/concepts/tests/test_study_prep_scoping.py',
  'kind': 'monkey',
  'line': 232,
  'receiver': 'prep'},
 {'attribute': 'run',
  'binding': 'subprocess',
  'file': 'core/audit/corpus/tests/test_sources.py',
  'kind': 'monkey',
  'line': 198,
  'receiver': 'sources_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 48,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 57,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 58,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 67,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 68,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 88,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 89,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 101,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 102,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 116,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 117,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 127,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 128,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 151,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 152,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 169,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 170,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 190,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 191,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 217,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 218,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 229,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 230,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 492,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 493,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 518,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 519,
  'receiver': '_scanner_mod'},
 {'attribute': 'which',
  'binding': 'shutil',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'scanner_string',
  'line': 595,
  'receiver': '_scanner_mod'},
 {'attribute': 'Popen',
  'binding': 'subprocess',
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 596,
  'receiver': '_scanner_mod'}]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


@lru_cache(maxsize=None)
def _native(file):
    name = "owned_process_native_" + file.replace("/", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(_REPO / file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()), pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, name, module)
        scope.setenv("_RAPTOR_TRUSTED", "1")
        loader.exec_module(module)
    return module


@lru_cache(maxsize=None)
def _consumer(file, expression):
    namespace = dict(vars(_native(file)))
    names = {node.id for node in ast.walk(ast.parse(expression, mode="eval")) if isinstance(node, ast.Name)}
    with patch.object(sys, "path", sys.path.copy()):
        for name in names:
            if name not in namespace:
                imports = [node for node in ast.walk(_tree(file)) if isinstance(node, (ast.Import, ast.ImportFrom))
                           and any((alias.asname or alias.name.split(".")[0]) == name for alias in node.names)]
                if not imports:
                    aliases = [node.value.id for node in ast.walk(_tree(file))
                               if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)
                               and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
                               and isinstance(namespace.get(node.value.id), ModuleType)]
                    assert aliases, (file, name)
                    namespace[name] = namespace[aliases[0]]
                    continue
                assert imports, (file, name)
                exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(imports[0])], type_ignores=[])), file, "exec"), namespace)
            value = namespace[name]
            if not isinstance(value, ModuleType) and hasattr(value, "__wrapped__"):
                factory = value.__wrapped__
                assert not inspect.signature(factory).parameters, (file, name)
                namespace[name] = factory()
        owner = eval(expression, namespace)
    assert isinstance(owner, ModuleType), (file, expression, owner)
    return owner


def _selected(node, file):
    if not isinstance(node, ast.Call) or not node.args:
        return False
    name = getattr(node.func, "id", "")
    if name in ("patch_module_attribute", "mock_module_attribute"):
        index = 2 if name == "patch_module_attribute" else 1
        return len(node.args) > index + 1 and isinstance(node.args[index], ast.Constant) and (
            node.args[index].value == "subprocess" and node.args[index + 1].value in ("run", "Popen")
            or file.endswith("static-analysis/tests/test_scanner.py") and node.args[index].value == "shutil" and node.args[index + 1].value == "which")
    if getattr(node.func, "attr", "") in ("setattr", "object") and len(node.args) > 1:
        return isinstance(node.args[0], ast.Attribute) and node.args[0].attr == "subprocess" and isinstance(node.args[1], ast.Constant) and node.args[1].value in ("run", "Popen")
    return name == "patch" and isinstance(node.args[0], ast.Constant) and node.args[0].value == "shutil.which" and file.endswith("static-analysis/tests/test_scanner.py")


@lru_cache(maxsize=None)
def _nodes(file):
    return sorted((node for node in ast.walk(_tree(file)) if _selected(node, file)), key=lambda node: (node.lineno, node.col_offset))


def _assert_namespace(owner, before):
    current = vars(owner)
    changed = [name for name, value in before.items() if name not in current or current[name] is not value]
    added = sorted(current.keys() - before.keys())
    assert changed == [] and added == [], (owner.__name__, changed, added)


@contextmanager
def _snapshots(row, borrowed):
    owner = _consumer(row["file"], row["receiver"])
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            original = getattr(owner, row["binding"])
            view = ModuleType(original.__name__)
            vars(view).update(vars(original))
            inherited.setitem(vars(owner), row["binding"], view)
        raw = [(owner, dict(vars(owner)))]
        values = [subprocess, shutil, getattr(owner, row["binding"])]
        snapshots = [(value, dict(vars(value))) for value in values]
        yield owner, raw, snapshots


def _exercise(row, index, borrowed, exit_mode, mock=True):
    with _snapshots(row, borrowed) as (owner, raw, snapshots):
        fake = MagicMock(name="owned_native_mock")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope, ExitStack() as contexts:
                if mock:
                    node = copy.deepcopy(_nodes(row["file"])[index])
                    namespace = {"_owner": owner, "_scope": scope, "_fake": fake,
                                 "patch_module_attribute": patch_module_attribute,
                                 "mock_module_attribute": mock_module_attribute, "patch": patch,
                                 "subprocess": subprocess, "shutil": shutil}
                    if getattr(node.func, "id", "") == "patch_module_attribute":
                        node.args[0] = ast.Name(id="_scope", ctx=ast.Load())
                        node.args[1] = ast.Name(id="_owner", ctx=ast.Load())
                        node.args[-1] = ast.Name(id="_fake", ctx=ast.Load())
                        eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace)
                    elif getattr(node.func, "id", "") == "mock_module_attribute":
                        node.args = [ast.Name(id="_owner", ctx=ast.Load()), *node.args[1:3], ast.Name(id="_fake", ctx=ast.Load())]
                        node.keywords = []
                        contexts.enter_context(eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace))
                    elif row["kind"] == "monkey":
                        target = eval(ast.unparse(node.args[0]).replace(row["receiver"], "_owner", 1), namespace)
                        scope.setattr(target, node.args[1].value, fake)
                    elif row["kind"] == "object":
                        target = eval(ast.unparse(node.args[0]).replace(row["receiver"], "_owner", 1), namespace)
                        contexts.enter_context(patch.object(target, node.args[1].value, fake))
                    else:
                        contexts.enter_context(patch(node.args[0].value, fake))
                    for shared, before in snapshots:
                        _assert_namespace(shared, before)
                    assert getattr(getattr(owner, row["binding"]), row["attribute"]) is fake
                else:
                    for shared, before in snapshots:
                        _assert_namespace(shared, before)
                if exit_mode != "normal":
                    raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        for shared, before in raw + snapshots:
            _assert_namespace(shared, before)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "owned scope exit"


def _cases():
    counts = {}
    for row in sorted(_SITES, key=lambda row: (row["file"], row["line"])):
        index = counts.get(row["file"], 0)
        counts[row["file"]] = index + 1
        yield pytest.param(row, index, id=row["file"] + ":" + str(row["line"]))


@pytest.mark.parametrize("row,index", list(_cases()))
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_process_mock_is_owned(row, index, borrowed, exit_mode):
    _exercise(row, index, borrowed, exit_mode)


@pytest.mark.parametrize("row", list({row["file"]: row for row in _SITES}.values()), ids=lambda row: row["file"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_process_control(row, borrowed):
    _exercise(row, 0, borrowed, "normal", mock=False)


@pytest.mark.parametrize("config", ["explicit", "return_value", "side_effect", "autospec", "spec_set"])
@pytest.mark.parametrize("binding", ["stored", "borrowed", "lazy"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_mock_context_preserves_configuration_and_borrowed_binding(config, binding, exit_mode):
    owner = ModuleType("owned_mock_consumer")
    module = ModuleType("borrowed_calls")
    token = object()
    def call(value):
        return value
    module.call = call
    if binding == "lazy":
        owner.__getattr__ = lambda name: module if name == "calls" else None
    elif binding == "borrowed":
        original = ModuleType("original_calls")
        vars(original).update(vars(module))
        module = original
        owner.calls = module
    else:
        owner.calls = module
    raw = dict(vars(owner))
    shared = dict(vars(module))
    kwargs = {"return_value": token} if config == "return_value" else {"side_effect": lambda value: token} if config == "side_effect" else {"autospec": True, "return_value": token} if config == "autospec" else {"spec_set": call, "return_value": token} if config == "spec_set" else {}
    args = [lambda value: token] if config == "explicit" else []
    caught = None
    try:
        with mock_module_attribute(owner, "calls", "call", *args, **kwargs) as mocked:
            assert owner.calls.call is mocked
            assert mocked(token) is token
            if config != "explicit":
                mocked.assert_called_once_with(token)
            _assert_namespace(module, shared)
            if exit_mode != "normal":
                raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
    except BaseException as error:
        caught = error
    _assert_namespace(owner, raw)
    _assert_namespace(module, shared)
    if exit_mode == "normal":
        assert caught is None, repr(caught)
    else:
        assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)


def test_mock_configuration_failure_restores_original_binding():
    owner = ModuleType("owned_mock_consumer")
    module = ModuleType("borrowed_calls")
    module.call = lambda value: value
    owner.calls = module
    raw = dict(vars(owner))
    with pytest.raises(TypeError):
        with mock_module_attribute(owner, "calls", "call", object(), autospec=True):
            pytest.fail("invalid patch configuration must refuse before entering")
    _assert_namespace(owner, raw)


@pytest.mark.parametrize("lazy", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_nested_contexts_restore_earlier_mock_and_original_binding(lazy, exit_mode):
    owner = ModuleType("owned_nested_consumer")
    module = ModuleType("borrowed_calls")
    module.first, module.second = lambda: None, lambda: None
    if lazy:
        owner.__getattr__ = lambda name: module if name == "calls" else None
    else:
        owner.calls = module
    raw, shared = dict(vars(owner)), dict(vars(module))
    with mock_module_attribute(owner, "calls", "first") as first:
        earlier = owner.calls
        caught = None
        try:
            with mock_module_attribute(owner, "calls", "second") as second:
                assert owner.calls.first is first and owner.calls.second is second
                _assert_namespace(module, shared)
                if exit_mode != "normal":
                    raise RuntimeError("nested exit") if exit_mode == "error" else KeyboardInterrupt("nested exit")
        except BaseException as error:
            caught = error
        assert owner.calls is earlier and owner.calls.first is first
        assert owner.calls.second is module.second
        assert caught is None if exit_mode == "normal" else isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt)
    _assert_namespace(owner, raw)
    _assert_namespace(module, shared)


@pytest.mark.parametrize("lazy", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_create_option_stays_on_private_binding(lazy, exit_mode):
    owner, module = ModuleType("owned_create_consumer"), ModuleType("borrowed_calls")
    if lazy:
        owner.__getattr__ = lambda name: module if name == "calls" else None
    else:
        owner.calls = module
    raw, shared = dict(vars(owner)), dict(vars(module))
    caught = None
    try:
        with mock_module_attribute(owner, "calls", "missing", create=True) as mocked:
            assert owner.calls.missing is mocked
            _assert_namespace(module, shared)
            if exit_mode != "normal":
                raise RuntimeError("owned create exit") if exit_mode == "error" else KeyboardInterrupt("owned create exit")
    except BaseException as error:
        caught = error
    _assert_namespace(owner, raw)
    _assert_namespace(module, shared)
    assert caught is None if exit_mode == "normal" else isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt)


def test_missing_attribute_refusal_restores_original_binding():
    owner, module = ModuleType("owned_missing_consumer"), ModuleType("borrowed_calls")
    owner.calls = module
    raw = dict(vars(owner))
    with pytest.raises(AttributeError):
        with mock_module_attribute(owner, "calls", "missing"):
            pytest.fail("missing attributes require explicit create=True")
    _assert_namespace(owner, raw)
