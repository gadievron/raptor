"""Return-effect names cannot refute constraints on original parameters."""
import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import TaintSummary, build_taint_summaries
from core.audit.constraints import Constraint
from core.audit.propagation import PropagationConfig, _try_taint_summary_resolve
from core.evidence import EvidenceRecord


def _resolve(summary, cwe):
    constraint = Constraint(function="clean", file="app.py", kind="parameter", target="raw",
                            rule="raw must satisfy the caller input constraint",
                            violation="unvalidated input", cwe=cwe)
    record = EvidenceRecord(file="app.py", function="clean", taint_summary=summary)
    config = PropagationConfig(evidence_index={"app.py:clean": record})
    return _try_taint_summary_resolve(constraint, config)


@pytest.mark.parametrize("library,cwe", [
    ("html.escape", "CWE-79"), ("werkzeug.utils.secure_filename", "CWE-22"),
    ("unknown.clean", ""),
])
def test_return_effect_only_cannot_discharge_original_parameter(library, cwe):
    # Production summary shape: return effects can be supplied independently
    # of the optional call-argument field; this is not a whole-source proof.
    summary = TaintSummary(function="clean", params=("raw",),
                           return_effects=frozenset({(0, library, 0)}))
    assert summary.return_sanitizers_for_param(0)
    assert _resolve(summary, cwe) is None


def test_generated_call_argument_flow_keeps_existing_confirmation_path():
    source = "import html\ndef clean(raw):\n    return html.escape(raw)\n"
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summary = build_taint_summaries(graph, source)["clean"]
    assert summary.call_arg_taint == frozenset({("html.escape", 0, 0)})
    result = _resolve(summary, "CWE-79")
    assert result is not None
    assert result.resolved and result.resolution == "confirmed"
    assert result.resolver_used == "taint_summary"
