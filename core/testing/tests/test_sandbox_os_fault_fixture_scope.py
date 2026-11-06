"""Native OS fault mocks must leave shared and borrowed namespaces untouched."""
import ast
import copy
from contextlib import ExitStack, contextmanager
from functools import lru_cache
import importlib
import os
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [{'file': 'core/sandbox/tests/test_evidence_append_resync.py',
  'kind': 'monkey',
  'line': 36,
  'module': 'core.sandbox.evidence',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_evidence_append_resync.py',
  'kind': 'monkey',
  'line': 68,
  'module': 'core.sandbox.evidence',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_evidence_append_resync.py',
  'kind': 'monkey',
  'line': 98,
  'module': 'core.sandbox.evidence',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_evidence_cancel_state.py',
  'kind': 'monkey',
  'line': 36,
  'module': 'core.sandbox.evidence',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_evidence_open_cleanup.py',
  'kind': 'monkey',
  'line': 54,
  'module': 'core.sandbox.evidence',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_evidence_open_cleanup.py',
  'kind': 'monkey',
  'line': 55,
  'module': 'core.sandbox.evidence',
  'target': 'os.close'},
 {'file': 'core/sandbox/tests/test_evidence_open_cleanup.py',
  'kind': 'monkey',
  'line': 56,
  'module': 'core.sandbox.evidence',
  'target': 'os.fstat'},
 {'file': 'core/sandbox/tests/test_evidence_short_write.py',
  'kind': 'monkey',
  'line': 25,
  'module': 'core.sandbox.evidence',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_denial_io_recovery.py',
  'kind': 'monkey',
  'line': 126,
  'module': 'core.sandbox.evidence',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_creator_disappears.py',
  'kind': 'monkey',
  'line': 42,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_creator_disappears.py',
  'kind': 'monkey',
  'line': 70,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_telemetry_creator_disappears.py',
  'kind': 'monkey',
  'line': 112,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_telemetry_key_close.py',
  'kind': 'monkey',
  'line': 30,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.close'},
 {'file': 'core/sandbox/tests/test_telemetry_key_close.py',
  'kind': 'monkey',
  'line': 63,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_telemetry_key_close.py',
  'kind': 'monkey',
  'line': 80,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_key_create_recovery.py',
  'kind': 'monkey',
  'line': 95,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_key_create_recovery.py',
  'kind': 'monkey',
  'line': 38,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_key_create_recovery.py',
  'kind': 'monkey',
  'line': 56,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_key_create_recovery.py',
  'kind': 'monkey',
  'line': 77,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_mac.py',
  'kind': 'monkey',
  'line': 44,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.geteuid'},
 {'file': 'core/sandbox/tests/test_telemetry_mac.py',
  'kind': 'monkey',
  'line': 74,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_telemetry_mac.py',
  'kind': 'monkey',
  'line': 88,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_telemetry_marker_resync.py',
  'kind': 'monkey',
  'line': 52,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_telemetry_marker_resync.py',
  'kind': 'monkey',
  'line': 29,
  'module': 'core.sandbox.telemetry_mac',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_proxy_count_reader_io.py',
  'kind': 'monkey',
  'line': 30,
  'module': 'core.sandbox.context',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_proxy_count_reader_io.py',
  'kind': 'monkey',
  'line': 46,
  'module': 'core.sandbox.context',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_proxy_count_reader_io.py',
  'kind': 'monkey',
  'line': 89,
  'module': 'core.sandbox.context',
  'target': 'os.close'},
 {'file': 'core/sandbox/tests/test_proxy_count_reader_io.py',
  'kind': 'monkey',
  'line': 88,
  'module': 'core.sandbox.context',
  'target': 'os.read'},
 {'delegate': 'core.atomic_fs',
  'file': 'core/sandbox/tests/test_proxy_event_durability.py',
  'kind': 'monkey',
  'line': 41,
  'module': 'core.sandbox.context',
  'target': 'os.fsync'},
 {'delegate': 'core.atomic_fs',
  'file': 'core/sandbox/tests/test_proxy_event_durability.py',
  'kind': 'monkey',
  'line': 96,
  'module': 'core.sandbox.context',
  'target': 'os.fstat'},
 {'delegate': 'core.atomic_fs',
  'file': 'core/sandbox/tests/test_proxy_event_durability.py',
  'kind': 'monkey',
  'line': 144,
  'module': 'core.sandbox.context',
  'target': 'os.fstat'},
 {'delegate': 'core.atomic_fs',
  'file': 'core/sandbox/tests/test_proxy_event_durability.py',
  'kind': 'monkey',
  'line': 145,
  'module': 'core.sandbox.context',
  'target': 'os.close'},
 {'delegate': 'core.atomic_fs',
  'file': 'core/sandbox/tests/test_proxy_event_durability.py',
  'kind': 'monkey',
  'line': 59,
  'module': 'core.sandbox.context',
  'target': 'os.fsync'},
 {'file': 'core/sandbox/tests/test_proxy_recount_io.py',
  'kind': 'monkey',
  'line': 22,
  'module': 'core.sandbox.context',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_proxy_recount_io.py',
  'kind': 'monkey',
  'line': 50,
  'module': 'core.sandbox.context',
  'target': 'os.close'},
 {'file': 'core/sandbox/tests/test_proxy_recount_io.py',
  'kind': 'monkey',
  'line': 49,
  'module': 'core.sandbox.context',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_proxy_refusal_state.py',
  'kind': 'monkey',
  'line': 39,
  'module': 'core.sandbox.context',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_proxy_refusal_state.py',
  'kind': 'monkey',
  'line': 51,
  'module': 'core.sandbox.context',
  'target': 'os.fstat'},
 {'file': 'core/sandbox/tests/test_proxy_sidecar_key_io.py',
  'kind': 'monkey',
  'line': 47,
  'module': 'core.sandbox.context',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_triage_zero_count_failure.py',
  'kind': 'monkey',
  'line': 51,
  'module': 'core.sandbox.context',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_proxy_count_sidecar_io.py',
  'kind': 'monkey',
  'line': 33,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_proxy_count_sidecar_io.py',
  'kind': 'monkey',
  'line': 45,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_proxy_count_sidecar_io.py',
  'kind': 'monkey',
  'line': 75,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_summary.py',
  'kind': 'monkey',
  'line': 325,
  'module': 'core.sandbox.summary',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_summary.py',
  'kind': 'monkey',
  'line': 326,
  'module': 'core.sandbox.summary',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_summary.py',
  'kind': 'monkey',
  'line': 327,
  'module': 'core.sandbox.summary',
  'target': 'os.close'},
 {'file': 'core/sandbox/tests/test_summary_evidence_retention.py',
  'kind': 'monkey',
  'line': 72,
  'module': 'core.sandbox.summary',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_summary_evidence_retention.py',
  'kind': 'monkey',
  'line': 73,
  'module': 'core.sandbox.summary',
  'target': 'os.fstat'},
 {'file': 'core/sandbox/tests/test_summary_evidence_retention.py',
  'kind': 'monkey',
  'line': 74,
  'module': 'core.sandbox.summary',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_triage.py',
  'kind': 'monkey',
  'line': 1238,
  'module': 'core.security.capped_read',
  'target': 'os.fstat'},
 {'file': 'core/sandbox/tests/test_landlock_audit_drain_deadline.py',
  'kind': 'monkey',
  'line': 32,
  'module': 'core.sandbox._landlock_audit',
  'target': 'os.read'},
 {'file': 'core/sandbox/tests/test_landlock_audit_drain_deadline.py',
  'kind': 'monkey',
  'line': 37,
  'module': 'core.sandbox._landlock_audit',
  'target': 'os.waitid'},
 {'file': 'core/atomic_fs/tests/test_anchored_atomic.py',
  'kind': 'monkey',
  'line': 39,
  'module': 'core.atomic_fs',
  'target': 'os.replace'},
 {'delegate': 'core.source.beneath',
  'file': 'core/atomic_fs/tests/test_anchored_atomic.py',
  'kind': 'monkey',
  'line': 60,
  'module': 'core.atomic_fs',
  'target': 'os.open'},
 {'file': 'core/atomic_fs/tests/test_anchored_atomic.py',
  'kind': 'monkey',
  'line': 68,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'file': 'core/atomic_fs/tests/test_anchored_atomic.py',
  'kind': 'monkey',
  'line': 83,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'delegate': 'core.source.beneath',
  'file': 'core/atomic_fs/tests/test_writer_consumers.py',
  'kind': 'monkey',
  'line': 84,
  'module': 'core.atomic_fs',
  'target': 'os.open'},
 {'file': 'core/atomic_fs/tests/test_writer_consumers.py',
  'kind': 'monkey',
  'line': 107,
  'module': 'core.atomic_fs',
  'target': 'os.fdopen'},
 {'file': 'core/atomic_fs/tests/test_writer_consumers.py',
  'kind': 'monkey',
  'line': 122,
  'module': 'core.atomic_fs',
  'target': 'os.fchmod'},
 {'file': 'core/atomic_fs/tests/test_writer_consumers.py',
  'kind': 'monkey',
  'line': 141,
  'module': 'core.atomic_fs',
  'target': 'os.replace'},
 {'file': 'core/atomic_fs/tests/test_writer_consumers.py',
  'kind': 'monkey',
  'line': 182,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'file': 'core/atomic_fs/tests/test_writer_consumers.py',
  'kind': 'monkey',
  'line': 214,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'file': 'packages/joern/tests/test_owned_artifact_cleanup.py',
  'kind': 'monkey',
  'line': 143,
  'module': 'core.source.gated',
  'target': 'os.open'},
 {'file': 'packages/joern/tests/test_owned_artifact_cleanup.py',
  'kind': 'monkey',
  'line': 144,
  'module': 'core.source.gated',
  'target': 'os.fdopen'},
 {'file': 'core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py',
  'kind': 'monkey',
  'line': 168,
  'module': 'core.llm.dispatcher.server',
  'target': 'os.open'},
 {'file': 'core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py',
  'kind': 'monkey',
  'line': 213,
  'module': 'core.llm.dispatcher.server',
  'target': 'os.chmod'},
 {'file': 'core/build/tests/test_build_artifact_lifecycle.py',
  'kind': 'monkey',
  'line': 51,
  'module': 'core.build.build_detector',
  'target': 'os.close'},
 {'file': 'core/concepts/tests/test_library_cache_cleanup.py',
  'kind': 'monkey',
  'line': 232,
  'module': 'core.concepts.library_detect',
  'target': 'os.rename'},
 {'file': 'core/concepts/tests/test_library_cache_cleanup.py',
  'kind': 'monkey',
  'line': 207,
  'module': 'core.concepts.library_detect',
  'target': 'os.rename'},
 {'file': 'core/coverage/tests/test_journal_checkpoint.py',
  'kind': 'monkey',
  'line': 638,
  'module': 'core.coverage.journal_compact',
  'target': 'os.rename'},
 {'file': 'core/coverage/tests/test_store_budget.py',
  'kind': 'monkey',
  'line': 247,
  'module': 'core.coverage.store',
  'target': 'os.link'},
 {'file': 'core/audit/tests/test_prep_cache.py',
  'kind': 'monkey',
  'line': 107,
  'module': 'core.atomic_fs',
  'target': 'os.replace'},
 {'file': 'core/container/tests/test_compose_staging_lifecycle.py',
  'kind': 'monkey',
  'line': 284,
  'module': 'core.container.compose',
  'target': 'os.scandir'},
 {'file': 'packages/sca/tests/test_verify_overlay_lifecycle.py',
  'kind': 'monkey',
  'line': 211,
  'module': 'packages.sca.verify',
  'target': 'os.rename'},
 {'file': 'packages/sca/tests/test_verify_overlay_lifecycle.py',
  'kind': 'monkey',
  'line': 238,
  'module': 'packages.sca.verify',
  'target': 'os.rename'},
 {'file': 'packages/ghidra/tests/test_project_copy_lifecycle.py',
  'kind': 'monkey',
  'line': 134,
  'module': 'packages.ghidra.project_util',
  'target': 'os.rename'},
 {'file': 'packages/ghidra/tests/test_project_copy_lifecycle.py',
  'kind': 'monkey',
  'line': 162,
  'module': 'packages.ghidra.project_util',
  'target': 'os.rename'},
 {'file': 'core/startup/tests/test_tighten_perms.py',
  'kind': 'string',
  'line': 60,
  'module': 'core.startup.init',
  'target': 'os.getuid'},
 {'file': 'core/startup/tests/test_tighten_perms.py',
  'kind': 'string',
  'line': 87,
  'module': 'core.startup.init',
  'target': 'os.fchmod'},
 {'file': 'core/project/tests/test_cli.py',
  'kind': 'object',
  'line': 475,
  'module': 'core.project.cli',
  'target': 'os.isatty'},
 {'file': 'core/sandbox/tests/test_supervised_invariants.py',
  'kind': 'monkey',
  'line': 267,
  'module': 'core.sandbox.supervised',
  'target': 'os.listdir'},
 {'file': 'core/sandbox/tests/test_supervised_invariants.py',
  'kind': 'monkey',
  'line': 278,
  'module': 'core.sandbox.supervised',
  'target': 'os.listdir'},
 {'file': 'core/sandbox/tests/test_supervised_invariants.py',
  'kind': 'monkey',
  'line': 325,
  'module': 'core.sandbox.supervised',
  'target': 'os.listdir'},
 {'file': 'core/sandbox/tests/test_supervised_invariants.py',
  'kind': 'monkey',
  'line': 349,
  'module': 'core.sandbox.supervised',
  'target': 'os.listdir'},
 {'file': 'core/sandbox/tests/test_supervised_invariants.py',
  'kind': 'monkey',
  'line': 366,
  'module': 'core.sandbox.supervised',
  'target': 'os.listdir'},
 {'file': 'core/sandbox/tests/test_supervised_invariants.py',
  'kind': 'monkey',
  'line': 223,
  'module': 'core.sandbox.supervised',
  'target': 'os.getpgrp'},
 {'file': 'core/sandbox/tests/test_supervised_invariants.py',
  'kind': 'monkey',
  'line': 224,
  'module': 'core.sandbox.supervised',
  'target': 'os.killpg'},
 {'file': 'core/sandbox/tests/test_idmap_nested_userns_hint.py',
  'kind': 'monkey',
  'line': 38,
  'module': 'core.sandbox._spawn',
  'target': 'os.getuid'},
 {'file': 'core/sandbox/tests/test_idmap_nested_userns_hint.py',
  'kind': 'monkey',
  'line': 48,
  'module': 'core.sandbox._spawn',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_idmap_nested_userns_hint.py',
  'kind': 'monkey',
  'line': 70,
  'module': 'core.sandbox._spawn',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_rr_capabilities.py',
  'kind': 'monkey',
  'line': 64,
  'module': 'core.sandbox._rr_caps',
  'target': 'os.geteuid'},
 {'file': 'core/sandbox/tests/test_rr_capabilities.py',
  'kind': 'monkey',
  'line': 78,
  'module': 'core.sandbox._rr_caps',
  'target': 'os._exit'},
 {'file': 'core/sandbox/tests/test_rr_capabilities.py',
  'kind': 'monkey',
  'line': 79,
  'module': 'core.sandbox._rr_caps',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_tracer.py',
  'kind': 'monkey',
  'line': 941,
  'module': 'core.sandbox.tracer',
  'target': 'os.write'},
 {'file': 'core/sandbox/tests/test_tracer.py',
  'kind': 'monkey',
  'line': 942,
  'module': 'core.sandbox.tracer',
  'target': 'os.close'},
 {'file': 'core/sandbox/tests/test_mount_ns_etc_copy.py',
  'kind': 'monkey',
  'line': 406,
  'module': 'core.sandbox.mount_ns',
  'target': 'os.link'},
 {'file': 'core/sandbox/tests/test_mount_ns_etc_copy.py',
  'kind': 'monkey',
  'line': 427,
  'module': 'core.sandbox.mount_ns',
  'target': 'os.listdir'},
 {'file': 'core/sandbox/tests/test_mount_ns_etc_copy.py',
  'kind': 'monkey',
  'line': 59,
  'module': 'core.sandbox.mount_ns',
  'target': 'os.link'},
 {'file': 'core/sandbox/tests/test_observe_profile_malformed.py',
  'kind': 'monkey',
  'line': 106,
  'module': 'core.security.capped_read',
  'target': 'os.open'},
 {'file': 'core/sandbox/tests/test_observe_profile_malformed.py',
  'kind': 'monkey',
  'line': 107,
  'module': 'core.security.capped_read',
  'target': 'os.fstat'}]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


@lru_cache(maxsize=None)
def _nodes(file):
    result = []
    for node in ast.walk(_tree(file)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if getattr(node.func, "id", "") == "patch_module_attribute" and len(node.args) >= 5:
            if isinstance(node.args[1], ast.Name) and node.args[1].id.startswith("_os_fault_consumer"):
                result.append(node)
        elif getattr(node.func, "attr", "") == "object" and len(node.args) >= 3 and (ast.unparse(node.args[0]) == "os" or ast.unparse(node.args[0]).startswith("_os_fault_consumer")):
            result.append(node)
        elif getattr(node.func, "attr", "") == "setattr" and len(node.args) >= 3 and ast.unparse(node.args[0]) == "os":
            result.append(node)
        elif (getattr(node.func, "id", "") == "patch" or getattr(node.func, "attr", "") == "patch") and isinstance(node.args[0], ast.Constant):
            target = node.args[0].value
            if isinstance(target, str) and (any(target == row["target"] for row in _SPECS if row["file"] == file) or any(target == row["module"] + "." + row["target"] for row in _SPECS if row["file"] == file)):
                result.append(node)
    return sorted(result, key=lambda node: (node.lineno, node.col_offset))


@lru_cache(maxsize=None)
def _namespace(file):
    namespace = {"patch_module_attribute": patch_module_attribute, "os": os, "patch": patch}
    for node in _tree(file).body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.asname.startswith("_os_fault_consumer"):
                    namespace[alias.asname] = importlib.import_module(alias.name)
    for original in _tree(file).body:
        if not isinstance(original, ast.FunctionDef) or original.name not in ("_isolate_os_fault_patches", "_isolate_delegated_os_faults"):
            continue
        node = copy.deepcopy(original)
        node.decorator_list = []
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), file, "exec"), namespace)
    return namespace


def _assert_namespace(owner, before):
    current = vars(owner)
    assert current.keys() == before.keys()
    assert all(current[key] is value for key, value in before.items())


@contextmanager
def _snapshot(row, borrowed):
    owner = importlib.import_module(row["module"])
    owners = [owner]
    if row.get("delegate"):
        owners.append(importlib.import_module(row["delegate"]))
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            for current in owners:
                view = ModuleType(current.os.__name__)
                vars(view).update(vars(current.os))
                inherited.setitem(vars(current), "os", view)
        raw = [(current, dict(vars(current))) for current in owners]
        values = [os, os.path] + [current.os for current in owners]
        namespaces = [(value, dict(vars(value))) for value in values]
        yield owner, raw, namespaces


def _exercise(row, index, borrowed, exit_mode, mock=True):
    with _snapshot(row, borrowed) as (owner, raw, namespaces):
        namespace = dict(_namespace(row["file"]))
        token = object()
        fake = MagicMock(name="owned_os_fault", return_value=token)
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope, ExitStack() as patches:
                namespace.update(monkeypatch=scope, fault=scope, faults=scope, _owned_fake=fake)
                for name in ("_isolate_os_fault_patches", "_isolate_delegated_os_faults"):
                    fixture = namespace.get(name)
                    if fixture:
                        fixture(scope)
                if mock:
                    node = copy.deepcopy(_nodes(row["file"])[index])
                    if row["kind"] == "object":
                        node.args = node.args[:2] + [ast.Name(id="_owned_fake", ctx=ast.Load())]
                        node.keywords = []
                        patches.enter_context(eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace))
                    elif row["kind"] == "string":
                        target = node.args[0].value
                        patches.enter_context(patch(target, new=fake))
                    else:
                        # Execute the actual native target/scope/attribute expression,
                        # substituting only the fault value; no syscall is executed.
                        scope_name = node.args[0] if getattr(node.func, "id", "") == "patch_module_attribute" else node.func.value
                        assert isinstance(scope_name, ast.Name), ast.unparse(scope_name)
                        namespace[scope_name.id] = scope
                        node.args[-1] = ast.Name(id="_owned_fake", ctx=ast.Load())
                        eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace)
                    for namespace_owner, before in namespaces:
                        _assert_namespace(namespace_owner, before)
                    actual = owner
                    for part in row["target"].split("."):
                        actual = getattr(actual, part)
                    assert actual is fake
                    if row.get("delegate"):
                        delegated = importlib.import_module(row["delegate"])
                        forwarded = getattr(delegated.os, row["target"].split(".")[-1])
                        assert forwarded(token, owned=token) is token
                        fake.assert_called_once_with(token, owned=token)
                else:
                    for namespace_owner, before in namespaces:
                        _assert_namespace(namespace_owner, before)
                if exit_mode != "normal":
                    raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        for namespace_owner, before in raw + namespaces:
            _assert_namespace(namespace_owner, before)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            expected = RuntimeError if exit_mode == "error" else KeyboardInterrupt
            assert isinstance(caught, expected), repr(caught)
            assert str(caught) == "owned scope exit"


def _cases():
    seen = {}
    for row in sorted(_SPECS, key=lambda row: (row["file"], row["line"])):
        index = seen.get(row["file"], 0)
        seen[row["file"]] = index + 1
        yield pytest.param(row, index, id=row["file"] + ":" + str(row["line"]))


@pytest.mark.parametrize("row,index", list(_cases()))
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_os_fault_is_consumer_owned(row, index, borrowed, exit_mode):
    _exercise(row, index, borrowed, exit_mode)


@pytest.mark.parametrize("row", list({row["file"]: row for row in _SPECS}.values()), ids=lambda row: row["file"])
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
def test_unmodified_os_control(row, borrowed):
    _exercise(row, 0, borrowed, "normal", mock=False)
