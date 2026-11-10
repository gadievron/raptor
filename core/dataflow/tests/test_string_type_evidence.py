"""Curated escapers need exact primitive input and default-call evidence."""
from pathlib import Path
import ast
import json

import pytest

from core.dataflow import smt_barrier as sb
from core.dataflow import tier1_llm as t1


def _review(tmp_path: Path, prefix="", argument="raw", parameters="raw", claimed_variable="raw"):
    line = f"    safe = html.escape({argument})"
    source = "import html\ndef handle(" + parameters + "):\n" + prefix + line + "\n    return render(safe)\n"
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": claimed_variable, "charset": "", "forbidden": "",
                        "library_call": "html.escape", "exact_type": "str"})
    result = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path, sink_uri="app.py",
        sink_line=len(source.splitlines()), sink_class="xss", language="python",
        complete=lambda _system, _user: reply,
    )
    return result


def test_untyped_input_cannot_certify_an_overridable_escaper(tmp_path: Path):
    result = _review(tmp_path)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "exact builtin" in result.reasoning


@pytest.mark.parametrize("prefix,argument,claim", [
    ("    if type(raw) is not str: return\n", "raw", "raw"),
    ("    raw = '<literal>'\n", "raw", "raw"),
    ("", "'<literal>'", "safe"),
], ids=["guard", "literal-binding", "literal-argument"])
def test_exact_primitive_inputs_keep_real_curated_certificates(tmp_path: Path, prefix, argument, claim):
    result = _review(tmp_path, prefix=prefix, argument=argument, claimed_variable=claim)
    assert result.status is sb.Tier0Status.SOUND
    evidence = result.extras["input_type_evidence"]
    assert evidence["source_digest"]
    assert evidence["scope"] == "primitive-input-type-and-default-call-form"
    assert evidence["call_span"][0] > 0
    assert evidence["assumptions"]


@pytest.mark.parametrize("prefix,parameters", [
    ("", "raw: str"),
    ("    if not isinstance(raw, str): return\n", "raw"),
    ("    if type(raw) is not str: pass\n", "raw"),
    ("    if type(raw) is not str: return\n", "raw, type"),
    ("    if type(raw) is not str: return\n", "raw, str"),
    ("    if type(raw) is not str: return\n    raw = replacement\n", "raw"),
], ids=["annotation", "isinstance", "fallthrough", "shadow-type", "shadow-str", "rebound"])
def test_missing_or_invalid_primitive_facts_do_not_certify(tmp_path: Path, prefix, parameters):
    result = _review(tmp_path, prefix=prefix, parameters=parameters)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert "input_type_evidence" not in result.extras


def test_nondefault_library_options_are_not_an_implicit_contract(tmp_path: Path):
    result = _review(tmp_path, prefix="    if type(raw) is not str: return\n",
                     argument="raw, quote=False")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None


@pytest.mark.parametrize("body", [
    "    if type(raw) is not str: return\n    while flag:\n        safe = html.escape(raw)\n",
    "    if type(raw) is not str: return\n    safe = [html.escape(raw) for raw in values]\n",
    "    if type(raw) is not str: return\n    try:\n        raw = replacement\n        safe = html.escape(raw)\n    except Error: pass\n",
    "    if type(raw) is not str: return\n    safe = (raw := replacement, html.escape(raw))[1]\n",
    "    def change():\n        nonlocal raw\n        raw = replacement\n    if type(raw) is not str: return\n    safe = html.escape(raw)\n",
    "    __import__('builtins').type = replacement\n    if type(raw) is not str: return\n    safe = html.escape(raw)\n",
    "    if type(raw) is not str: return\n    class Scope(metaclass=Factory):\n        safe = html.escape(raw)\n",
], ids=["loop", "comprehension", "try-rebind", "same-line-rebind", "closure-rebind", "dynamic-builtins", "class-namespace"])
def test_primitive_factory_refuses_unsupported_value_epochs(body):
    from core.dataflow.string_type_evidence import exact_str_default_call_evidence

    source = "import html\ndef handle(raw):\n" + body
    ast.parse(source)  # refusal must not be a syntax-error artefact
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "html.escape" in text)
    assert exact_str_default_call_evidence(source, line, "raw", "html.escape") is None


@pytest.mark.parametrize("definition", [
    "def callback(arg=(raw := replacement)): pass",
    "def callback(*, arg=(raw := replacement)): pass",
    "class Scope((raw := replacement)): pass",
    "class Scope:\n            nonlocal raw\n            raw = replacement",
    "def callback(arg: Annotation): pass",
], ids=["default", "kw-default", "class-base", "class-nonlocal", "annotation-profile"])
def test_header_execution_cannot_keep_a_stale_primitive_fact(definition):
    from core.dataflow.string_type_evidence import exact_str_default_call_evidence

    source = ("import html\ndef handle(raw):\n"
              "    if type(raw) is not str: return\n    try:\n        " + definition + "\n"
              "        safe = html.escape(raw)\n    except Error: pass\n")
    ast.parse(source)  # refusal must not be a syntax-error artefact
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "html.escape" in text)
    assert exact_str_default_call_evidence(source, line, "raw", "html.escape") is None


@pytest.mark.parametrize("definition", [
    "def callback(arg='literal'): return arg",
    "def callback(*, arg='literal'): return arg",
], ids=["default", "kw-default"])
def test_pure_definition_headers_preserve_the_primitive_fact(definition):
    from core.dataflow.string_type_evidence import exact_str_default_call_evidence

    source = ("import html\ndef handle(raw):\n"
              "    if type(raw) is not str: return\n    try:\n        " + definition + "\n"
              "        safe = html.escape(raw)\n    except Error: return\n")
    ast.parse(source)
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "html.escape" in text)
    evidence = exact_str_default_call_evidence(source, line, "raw", "html.escape")
    assert evidence is not None and evidence.origin == "adjacent-exact-type-guard"
