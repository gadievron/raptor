"""A joined return value alone does not establish trusted path containment."""
import json
from pathlib import Path

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding
from core.analysis.tests.test_interproc import _bindings_for
from core.dataflow import tier1_llm as t1

REQUIREMENT = "trusted_path_base_components_and_containment"


@pytest.mark.parametrize("arguments", ["raw", "raw, 'leaf'", "raw, component", "'/srv/data', raw"])
def test_joined_value_needs_source_containment_premises(tmp_path: Path, arguments):
    line = f"    safe = werkzeug.security.safe_join({arguments})"
    source = f"import werkzeug.security\ndef handle(raw, component):\n{line}\n    return open(safe)\n"
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "werkzeug.security.safe_join"})
    result = t1.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                          sink_uri="app.py", sink_line=4, sink_class="pathtrav",
                          language="python", complete=lambda _system, _user: reply)
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [REQUIREMENT]


@pytest.mark.parametrize("wrapper", [False, True])
def test_join_candidates_cannot_erase_argument_role_requirements(wrapper):
    preamble = "import werkzeug.security\n"
    if wrapper:
        source = (preamble + "def clean(value):\n    return werkzeug.security.safe_join(value)\n"
                  "def handle(raw):\n    safe = clean(raw)\n    open(safe)\n")
        graph, bindings = _bindings_for(source, "handle", "CWE-22")
    else:
        source = (preamble + "def handle(raw):\n"
                  "    safe = werkzeug.security.safe_join(raw)\n    open(safe)\n")
        graph = build_python_cfg(source, "handle")
        bindings = []
    assert graph is not None
    sink = next(node for node in graph.nodes() if "open" in node.calls)
    result = evaluate_finding(graph, [graph.entry_node], sink, cwe="CWE-22",
                              language="python", source_symbols={"raw"}, sink_arg="safe",
                              extra_bindings=bindings)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    assert result.value_bound_bindings
    assert all(REQUIREMENT in binding.unverified_source_contracts
               for binding in result.value_bound_bindings)
