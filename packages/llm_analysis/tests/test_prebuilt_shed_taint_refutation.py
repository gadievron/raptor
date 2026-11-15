"""Prebuilt absence cannot refute a shed path with positive approximation evidence."""

import copy
import zipfile

from core.config import RaptorConfig
from core.taint.emission import EmissionLimits, PRODUCER, _Emitter
from core.taint.packs import PackSet
from packages.hypothesis_validation import Hypothesis
from packages.hypothesis_validation.adapters import CodeQLAdapter
from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.llm_analysis import dataflow_validation as dv


def test_prebuilt_zero_does_not_refute_shed_sub_static_candidate(tmp_path, monkeypatch):
    finding = {"finding_id": "owned", "tool": PRODUCER, "file_path": "a.c",
               "start_line": 1, "cwe_id": "CWE-78", "has_dataflow": True,
               "dataflow_path": {"steps": [], "alternative_paths": []},
               "metadata": {"path_tier": "heuristic_dynamic"}}
    analysis = {"is_exploitable": True, "dataflow_summary": "input reaches command"}
    assert not dv._eligible_for_validation(finding, analysis)
    packs = PackSet(packs=(), sources=(), sinks=(), sanitizers=(), propagators=())
    emitter = _Emitter(packs, "cpp", EmissionLimits(max_record_bytes=1))
    record = {"properties": {}, "codeFlows": [{"threadFlows": [{"locations": []}]}]}
    emitter._shed_to_cap(record, finding)
    assert emitter.stats["record_codeflows_shed"] == 1
    assert finding["dataflow_path"] is None
    assert finding["has_dataflow"] is False
    assert dv._eligible_for_validation(finding, analysis)
    assert dv._taint_sub_static_exemption(finding)

    db = tmp_path / "db"
    db.mkdir()
    with zipfile.ZipFile(db / "src.zip", "w") as archive:
        archive.writestr("repo/a.c", "int main(void) { return 0; }\n")
    pack = tmp_path / "pack"
    pack.mkdir()
    query = pack / "flow.ql"
    query.write_text("import cpp\nselect 1\n")
    monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [pack])
    monkeypatch.setattr(dv, "discover_prebuilt_query", lambda *args: query)
    zero = ToolEvidence(tool="codeql", rule=str(query), success=True, matches=[])
    monkeypatch.setattr(CodeQLAdapter, "run_prebuilt_query", lambda *args: zero)
    adapter = CodeQLAdapter(database_path=db, codeql_bin="owned-codeql", sandbox=False)
    hypothesis = Hypothesis(claim="input reaches command", target=tmp_path, cwe="CWE-78")
    result, tier = dv._validate_one_hypothesis(hypothesis, finding, adapter, None)
    assert result.verdict == "inconclusive"
    assert tier == "prebuilt-inconclusive"
    # Independently generated template predicates retain their existing verdict path.
    assert dv._verdict_from_template(zero, finding, codeql_db=db) == "refuted"
    for control in (
        {**copy.deepcopy(finding), "metadata": {"path_tier": "resolved_static"}},
        {**copy.deepcopy(finding), "tool": "semgrep"},
    ):
        result, tier = dv._validate_one_hypothesis(hypothesis, control, adapter, None)
        assert result.verdict == "refuted"
        assert tier == "prebuilt"
    hit = ToolEvidence(tool="codeql", rule=str(query), success=True,
                       matches=[{"file": "a.c", "line": 1}])
    assert dv._verdict_from_prebuilt(hit, finding, query, db) == "confirmed"
