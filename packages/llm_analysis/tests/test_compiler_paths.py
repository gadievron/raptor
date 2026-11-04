"""Compiler control-flow context reaches both analysis entry paths as data."""
from packages.llm_analysis.prompts.analysis import (
    build_analysis_prompt_bundle, build_analysis_prompt_bundle_from_finding,
)


def evidence():
    return {"code_flows": [{"threadFlows": [{"locations": [{"location": {
        "physicalLocation": {"artifactLocation": {"uri": "a.c"}, "region": {"startLine": 3}},
        "message": {"text": "CONTROL_PATH_CANARY"}}, "nestingLevel": 1}]}]}]}


def test_control_path_reaches_both_prompt_builders_as_untrusted_data():
    finding = {"rule_id": "-Wanalyzer-null-dereference", "file_path": "a.c", "start_line": 3,
               "end_line": 3, "level": "warning", "message": "possible null", "compiler_evidence": evidence()}
    sequential = build_analysis_prompt_bundle(rule_id=finding["rule_id"], file_path="a.c", start_line=3,
        end_line=3, level="warning", message="possible null", compiler_evidence=evidence())
    orchestrated = build_analysis_prompt_bundle_from_finding(finding)
    for bundle in (sequential, orchestrated):
        user = "\n".join(m.content for m in bundle.messages if m.role == "user")
        system = "\n".join(m.content for m in bundle.messages if m.role == "system")
        assert "CONTROL_PATH_CANARY" in user and "CONTROL_PATH_CANARY" not in system
        assert "not a taint trace" in user


def test_context_serialization_preserves_bounded_compiler_evidence(tmp_path):
    from packages.llm_analysis.agent import VulnerabilityContext
    context = VulnerabilityContext({"rule_id": "test", "file_path": "a.c", "start_line": 3,
        "level": "warning", "message": "possible null", "compiler_evidence": evidence()}, tmp_path)
    carried = context.to_dict()
    event = carried["compiler_evidence"]["code_flows"][0]["threadFlows"][0]["locations"][0]
    assert event["location"]["message"]["text"] == "CONTROL_PATH_CANARY"
    assert event["nestingLevel"] == 1
