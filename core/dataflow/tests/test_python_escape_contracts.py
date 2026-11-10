"""Input protocols cannot silently satisfy primitive escaping contracts."""
from pathlib import Path
import json

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding
from core.analysis.tests.test_interproc import _bindings_for
from core.dataflow import tier1_llm as t1
from core.dataflow.smt_barrier import Tier0Status


@pytest.mark.parametrize("library,sink_class", [("markupsafe.escape", "xss"), ("shlex.quote", "cmdi"), ("django.utils.html.escape", "xss")])
def test_untyped_protocol_inputs_cannot_earn_library_certificates(tmp_path: Path, library, sink_class):
    module = library.rsplit(".", 1)[0]
    line = f"    safe = {library}(raw)"
    source = f"import {module}\ndef handle(raw):\n" + line + "\n    return consume(safe)\n"
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": library, "exact_type": "str"})
    def review():
        return t1.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                            sink_uri="app.py", sink_line=len(source.splitlines()),
                            sink_class=sink_class, language="python",
                            complete=lambda _system, _user: reply)
    result = review()
    assert result.status is Tier0Status.NOT_APPLICABLE
    assert result.extras["unverified_source_contracts"] == ["exact_builtin_str_default_call"]
    assert result.artifact is None
    source = source.replace(line, "    if type(raw) is not str: return\n" + line)
    (tmp_path / "app.py").write_text(source)
    result = review()
    assert result.status is Tier0Status.SOUND
    assert result.extras["input_type_evidence"]["origin"] == "adjacent-exact-type-guard"


@pytest.mark.parametrize("library,cwe", [("markupsafe.escape", "CWE-79"), ("shlex.quote", "CWE-78"), ("django.utils.html.escape", "CWE-79")])
def test_graph_and_wrapper_candidates_keep_the_same_unverified_contract(library, cwe):
    module = library.rsplit(".", 1)[0]
    source = (f"import {module}\ndef clean(value):\n    return {library}(value)\n"
              "def handle(raw):\n    safe = clean(raw)\n    consume(safe)\n")
    graph, bindings = _bindings_for(source, "handle", cwe)
    binding, = bindings
    assert binding.callable == "clean"
    assert binding.unverified_source_contracts == frozenset({"exact_builtin_str_default_call"})
    sink = next(node for node in graph.nodes() if "consume" in node.calls)
    result = evaluate_finding(graph, [graph.entry_node], sink, cwe=cwe, language="python",
                              source_symbols={"raw"}, sink_arg="safe", extra_bindings=bindings)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and result.suppress is False
    assert result.value_bound_bindings
    direct = f"import {module}\ndef handle(raw):\n    safe = {library}(raw)\n    consume(safe)\n"
    graph = build_python_cfg(direct, "handle")
    assert graph is not None
    sink = next(node for node in graph.nodes() if "consume" in node.calls)
    result = evaluate_finding(graph, [graph.entry_node], sink, cwe=cwe, language="python",
                              source_symbols={"raw"}, sink_arg="safe")
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    assert result.value_bound_bindings
