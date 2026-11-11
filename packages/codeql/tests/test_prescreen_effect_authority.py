"""A typed charset-model flag cannot establish source-effect refutation."""
import ast
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

from core.dataflow import injection_prescreen as ip
from core.smt_solver.path_feasibility import PathSMTResult
from packages.codeql import dataflow_validator as module
from packages.codeql.tests.test_dataflow_validator import _FULL_RESPONSE, _validator
from packages.codeql.tests.test_injection_prescreen_hook import _dataflow


def test_typed_charset_receipt_cannot_replace_source_review(tmp_path, monkeypatch):
    source = (
        "import re\n\n\ndef handle(value):\n"
        "    # Parsed fixture only; no application call is executed.\n"
        "    original = value\n"
        "    if not re.fullmatch(r'[A-Za-z0-9]+', value):\n"
        "        return\n"
        "    alias = value\n"
        "    return consume(alias)\n"
    )
    (tmp_path / "app.py").write_text(source)
    tree = ast.parse(source)
    sink_call = tree.body[1].body[-1].value
    assert isinstance(sink_call, ast.Call) and len(sink_call.args) == 1
    assert isinstance(sink_call.func, ast.Name) and sink_call.func.id == "consume"
    model = {
        "path_index": 0, "validator_file": "app.py", "validator_line": 7,
        "kind": "charset", "pattern": "A-Za-z0-9", "sink_classes": ["pathtrav"],
        "reasoning": "conditional finite charset exclusion only",
        "source_input_sha256": sha256(source.encode()).hexdigest(),
    }
    # This is an inert typed model receipt, not a source-effect certificate.
    receipt = ip.PrescreenVerdict(
        refuted=True, paths_checked=1, evidence=[deepcopy(model)],
        reason="conditional finite charset exclusion only",
    )
    monkeypatch.setattr(ip, "prescreen_finding", lambda **kwargs: receipt)
    monkeypatch.setattr(module, "check_path_feasibility_dual", lambda *a, **k: PathSMTResult(
        feasible=None, reasoning="owned diagnostic", satisfied=[], unknown=[],
        unsatisfied=[], smt_available=False, model={},
    ))
    monkeypatch.setattr("core.llm.scorecard.prefilter_decision",
                        lambda *a, **k: SimpleNamespace(short_circuit=False))
    monkeypatch.setattr("core.llm.scorecard.record_prefilter_outcome", lambda *a, **k: None)
    monkeypatch.setattr(module, "load_methodology", lambda *a, **k: "")
    observations = []

    def record_observation(*args, **kwargs):
        observations.append(kwargs)

    monkeypatch.setattr("core.audit.check_trace.record_check_observation", record_observation)
    for claimed_refutation in (True, False):
        receipt.refuted = claimed_refutation
        validator = _validator()
        assert validator._injection_prescreen(
            _dataflow(), tmp_path, observation_out_dir=tmp_path,
        ) is None
        result = validator.validate_dataflow_path(
            _dataflow(), tmp_path, observation_out_dir=tmp_path,
        )
        assert result.error is None
        assert result.is_exploitable is _FULL_RESPONSE["is_exploitable"]
        assert result.reasoning == _FULL_RESPONSE["reasoning"]
        assert result.sanitizers_effective is _FULL_RESPONSE["sanitizers_effective"]
        validator.llm.generate_structured.assert_called_once()
        observation = observations[-1]
        details = observation["result"].details
        assert observation["verdict"] == "inconclusive"
        assert details["source_bound"] is False
        assert details["producer_claimed_refutation"] is claimed_refutation
        assert details["producer_reason"] == receipt.reason
        assert observation["result"].raw_output == model
        assert "producer_claimed_refutation" not in observation["request"]
        assert "producer_reason" not in details["assumptions"]["accepted_charset_model"]

    def unavailable_writer(*args, **kwargs):
        raise OSError("inert observation writer unavailable")

    receipt.refuted = True
    monkeypatch.setattr("core.audit.check_trace.record_check_observation", unavailable_writer)
    validator = _validator()
    result = validator.validate_dataflow_path(_dataflow(), tmp_path, observation_out_dir=tmp_path)
    assert result.is_exploitable is True
    assert result.reasoning == _FULL_RESPONSE["reasoning"]
    validator.llm.generate_structured.assert_called_once()
