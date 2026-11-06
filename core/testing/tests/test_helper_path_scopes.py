"""Helper bootstrap and runtime paths restore caller objects on every exit."""

import ast
import importlib.util
from contextlib import nullcontext
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import patch

import pytest


ROOT = Path(__file__).resolve().parents[3]
FILES = (
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_client_timeouts.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_clients.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_collect_events_unsupported.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_commit_file_statuses.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_deleted_claim_failclosed.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_gharchive_recovery.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_gharchive_row_cap.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_gharchive_type_verification.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_git_client.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_github_lane_fail_closed.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_helpers.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_ingest_bq_events.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_integration.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_parsers.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_store.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_url_canonical_identity.py',
    '.claude/skills/oss-forensics/github-evidence-kit/tests/test_verifier_skips.py',
    '.github/tests/test_audit_transcript_adoption_census.py',
    '.github/tests/test_check_miswiring.py',
    '.github/tests/test_check_run_dir_reads.py',
    '.github/tests/test_check_tracked_file_census.py',
    '.github/tests/test_checklist_read_closure.py',
    '.github/tests/test_codeql_scope.py',
    '.github/tests/test_compute_filters.py',
    '.github/tests/test_crlf_line_model_census.py',
    '.github/tests/test_junit_durations.py',
    '.github/tests/test_load_json_budget_closure.py',
    '.github/tests/test_redos_idiom_census.py',
    '.github/tests/test_runtime_file_universe.py',
    '.github/tests/test_safe_read_closure.py',
    '.github/tests/test_sarif_known_fp_suppressions.py',
    '.github/tests/test_splitlines_line_model_census.py',
    '.github/tests/test_tier_counter_registry_closure.py',
    '.github/tests/test_writeside_hardening_census.py',
)


def _evidence_dependencies_available():
    try:
        return all(importlib.util.find_spec(name) is not None for name in (
            "google.auth", "google.cloud.bigquery", "waybackpy",
        ))
    except (ModuleNotFoundError, ValueError):
        return False


CASES = [pytest.param(path, marks=pytest.mark.skipif(
    path.startswith(".claude/") and not _evidence_dependencies_available(),
    reason="evidence-kit optional test dependencies are not installed",
)) for path in FILES]


def _path_call(node):
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) in {"sys.path.insert", "sys.path.append"}


def _prefix(path, mode="normal"):
    tree = ast.parse((ROOT / path).read_text())
    body = []
    started = False
    for node in tree.body:
        if started and isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            break
        body.append(node)
        if _path_call(node) or (isinstance(node, ast.With) and any(_path_call(item) for item in node.body)):
            started = True
    assert started, path
    error = "ImportError" if mode == "import_error" else "KeyboardInterrupt"
    if mode != "normal":
        class Fault(ast.NodeTransformer):
            def visit_Expr(self, node):
                if _path_call(node):
                    return [node, ast.Raise(exc=ast.Call(func=ast.Name(id=error, ctx=ast.Load()), args=[], keywords=[]), cause=None)]
                return node
        body = Fault().visit(ast.Module(body=body, type_ignores=[])).body
    return ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))


def _namespace(path, guard):
    module = ModuleType("owned_helper_test")
    module.__file__ = str(ROOT / path)
    guard.setitem(sys.modules, module.__name__, module)
    return vars(module)


@pytest.mark.parametrize("path", CASES)
@pytest.mark.parametrize("mode", ["normal", "import_error", "interrupt"])
def test_bootstrap_restores_exact_caller_path(path, mode):
    with patch.object(sys, "path", sys.path.copy()), pytest.MonkeyPatch.context() as guard:
        caller, contents = sys.path, sys.path.copy()
        namespace = _namespace(path, guard)
        error = ImportError if mode == "import_error" else KeyboardInterrupt
        with pytest.raises(error) if mode != "normal" else nullcontext():
            exec(compile(_prefix(path, mode), str(ROOT / path), "exec"), namespace)
        assert sys.path is caller
        assert sys.path == contents


@pytest.mark.parametrize("path", CASES)
@pytest.mark.parametrize("mode", ["normal", "error", "interrupt", "publication_error"])
def test_runtime_fixture_restores_path_after_body_or_setup_failure(path, mode):
    class Failure(Exception):
        pass

    class FailingPatch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            if mode == "publication_error":
                raise Failure

    with patch.object(sys, "path", sys.path.copy()), pytest.MonkeyPatch.context() as guard:
        caller, contents = sys.path, sys.path.copy()
        namespace = _namespace(path, guard)
        tree = ast.parse((ROOT / path).read_text())
        fixture = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_scoped_helper_import_path"), None)
        owned = FailingPatch()
        if fixture is None:
            # Exercise the original import bootstrap, not a missing-fixture
            # error. Its installed helper path remains on the borrowed list.
            exec(compile(_prefix(path), str(ROOT / path), "exec"), namespace)
        else:
            exec(compile(_prefix(path), str(ROOT / path), "exec"), namespace)
            fixture.decorator_list = []
            exec(compile(ast.Module(body=[fixture], type_ignores=[]), str(ROOT / path), "exec"), namespace)
            error = Failure if mode in {"error", "publication_error"} else KeyboardInterrupt
            with pytest.raises(error) if mode != "normal" else nullcontext():
                try:
                    namespace[fixture.name](owned)
                    assert sys.path is not caller
                    sys.path.append("owned-body-path")
                    if mode in {"error", "interrupt"}:
                        raise error
                finally:
                    owned.undo()
        assert sys.path is caller
        assert sys.path == contents
