"""Curated default-only claims must bind the actual source call form."""
import json
from pathlib import Path

import pytest

from core.dataflow import tier1_llm as t1

REQUIREMENT = "single_positional_default_call"


def _review(tmp_path: Path, arguments: str):
    line = f"    safe = bleach.clean({arguments})"
    source = f"import bleach\ndef handle(raw, options):\n{line}\n    return render(safe)\n"
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "bleach.clean", "uses_defaults": True})
    result = t1.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                          sink_uri="app.py", sink_line=4, sink_class="xss", language="python",
                          complete=lambda _system, _user: reply)
    return source, result


@pytest.mark.parametrize("arguments", ["raw, tags=['literal']", "raw, **options", "raw, ['literal']"])
def test_custom_configuration_cannot_earn_a_default_only_certificate(tmp_path: Path, arguments):
    _, result = _review(tmp_path, arguments)
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [REQUIREMENT]


def test_default_call_keeps_a_scoped_source_receipt(tmp_path: Path):
    source, result = _review(tmp_path, "raw")
    assert result.status is t1.Tier0Status.SOUND
    evidence = result.extras["call_form_evidence"]
    assert evidence["scope"] == "source-call-form-only"
    assert evidence["library_call"] == "bleach.clean"
    from hashlib import sha256
    assert evidence["source_digest"] == sha256(source.encode()).hexdigest()
    assert evidence["call_span"][0] == 3


@pytest.mark.parametrize("expression", [
    "bleach.clean(*raw)", "bleach.clean(raw, **options)", "bleach.clean(raw, tags=[])",
    "bleach.clean(raw, [])", "bleach.clean()", "other.clean(raw)",
    "bleach.clean(raw); bleach.clean(raw)",
])
def test_call_form_receipts_refuse_options_unpacking_and_ambiguous_calls(expression):
    from core.dataflow.string_type_evidence import default_positional_call_evidence

    source = f"import bleach\ndef handle(raw, options):\n    {expression}\n"
    assert default_positional_call_evidence(source, 3, "bleach.clean") is None


def test_call_form_receipt_does_not_claim_an_input_type_or_trust_an_alias():
    from dataclasses import asdict
    from core.dataflow.string_type_evidence import default_positional_call_evidence

    source = "import bleach\ndef handle(raw):\n    return bleach.clean(raw)\n"
    evidence = default_positional_call_evidence(source, 3, "bleach.clean")
    assert evidence is not None
    payload = json.loads(json.dumps(asdict(evidence)))
    assert payload["scope"] == "source-call-form-only"
    assert "variable" not in payload and "input_type" not in payload
    shadowed = source.replace("handle(raw)", "handle(raw, bleach)")
    assert default_positional_call_evidence(shadowed, 3, "bleach.clean") is None


@pytest.mark.parametrize("wrapper", [False, True])
def test_graph_candidates_keep_default_call_requirements_until_source_binding(wrapper):
    from core.analysis.cfg_builder import build_python_cfg
    from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding
    from core.analysis.tests.test_interproc import _bindings_for

    if wrapper:
        source = ("import bleach\ndef clean(value):\n    return bleach.clean(value)\n"
                  "def handle(raw):\n    safe = clean(raw)\n    render(safe)\n")
        graph, bindings = _bindings_for(source, "handle", "CWE-79")
    else:
        source = "import bleach\ndef handle(raw):\n    safe = bleach.clean(raw)\n    render(safe)\n"
        graph, bindings = build_python_cfg(source, "handle"), []
    assert graph is not None
    sink = next(node for node in graph.nodes() if "render" in node.calls)
    result = evaluate_finding(graph, [graph.entry_node], sink, cwe="CWE-79", language="python",
                              source_symbols={"raw"}, sink_arg="safe", extra_bindings=bindings)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    assert result.value_bound_bindings
    assert all(REQUIREMENT in item.unverified_source_contracts for item in result.value_bound_bindings)
