"""Collection admission and event policy without loading parsers or corpus drivers."""

import ast
import builtins
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
CONSUMER = ROOT / "core/audit/tests/test_cpp_macro_cfg_availability.py"


def _collection_preamble(importer):
    tree = ast.parse(CONSUMER.read_bytes(), filename=str(CONSUMER))
    prefix = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            break
        prefix.append(node)
    namespace = {"__builtins__": dict(vars(builtins), __import__=importer)}
    exec(compile(ast.Module(body=prefix, type_ignores=[]), str(CONSUMER), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("missing", ["tree_sitter_c", "tree_sitter_cpp"])
@pytest.mark.parametrize("retained_helper", [False, True])
def test_missing_grammar_skips_before_importing_test_helpers(missing, retained_helper):
    # importlib-mode collection can retain a module whose importorskip stopped
    # execution before its helper definitions. Model that namespace explicitly.
    helper = ModuleType("core.analysis.tests.test_cpp_macro_fidelity")
    if not retained_helper:
        helper._source = object()
        helper.gap_transport = object()
    visited = []
    imported = []

    def importorskip(name):
        visited.append(name)
        if name == missing:
            pytest.skip("owned absent grammar: " + name)

    def owned_import(name, globals=None, locals=None, fromlist=(), level=0):
        imported.append(name)
        if name == "pytest":
            return SimpleNamespace(importorskip=importorskip)
        if name == helper.__name__:
            return helper
        if name in {"core.analysis.finding_resolver", "core.audit", "core.audit.block_review"}:
            return SimpleNamespace(**{symbol: object() for symbol in fromlist})
        raise AssertionError("product import before optional-dependency admission: " + name)

    with pytest.raises(pytest.skip.Exception, match="owned absent grammar"):
        _collection_preamble(owned_import)
    assert visited == (["tree_sitter_c"] if missing == "tree_sitter_c"
                       else ["tree_sitter_c", "tree_sitter_cpp"])
    assert imported == ["pytest"]


def test_available_grammars_retain_helper_and_product_imports():
    checked = []
    modules = {}

    def owned_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pytest":
            return SimpleNamespace(importorskip=checked.append)
        assert checked == ["tree_sitter_c", "tree_sitter_cpp"]
        assert name in {"core.analysis.finding_resolver", "core.audit",
                        "core.audit.block_review", "core.analysis.tests.test_cpp_macro_fidelity"}
        module = SimpleNamespace(**{symbol: object() for symbol in fromlist})
        modules[name] = module
        return module

    namespace = _collection_preamble(owned_import)
    assert len(modules) == 4
    helper = modules["core.analysis.tests.test_cpp_macro_fidelity"]
    assert namespace["_source"] is helper._source
    assert namespace["gap_transport"] is helper.gap_transport
    assert namespace["try_build_cfg"] is modules["core.audit.block_review"].try_build_cfg


@pytest.mark.parametrize("repository,event,expected", [
    ("gadievron/raptor", "schedule", True),
    ("contributor/raptor", "schedule", False),
    ("grokjc/raptor", "schedule", False),
    ("gadievron/raptor", "workflow_dispatch", True),
    ("contributor/raptor", "workflow_dispatch", True),
    ("contributor/raptor", "push", False),
])
def test_corpus_job_event_policy(repository, event, expected):
    workflow = yaml.safe_load((ROOT / ".github/workflows/weekly_corpus.yml").read_text())
    condition = workflow["jobs"]["corpus-drivers"].get("if", "true")
    assert condition == ("github.event_name == 'workflow_dispatch' || "
                         "(github.event_name == 'schedule' && "
                         "github.repository == 'gadievron/raptor')")
    expression = condition.replace("github.event_name", repr(event))
    expression = expression.replace("github.repository", repr(repository))
    expression = expression.replace("||", "or").replace("&&", "and")
    assert eval(expression, {"__builtins__": {}}) is expected
