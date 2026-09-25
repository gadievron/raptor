"""Probe synthesis and output parsing/authentication.

Hermetic above the execution boundary: probe TEXT is asserted
directly; parsing is fed synthetic probe outputs. No interpreter.
"""

from __future__ import annotations

import base64
import json

from core.audit.sanwit._extract import ChainStep
from core.audit.sanwit._probe import (
    MAX_OUTPUT_CHARS,
    ProbeRun,
    generate_probe,
    parse_probe_output,
    payloads_document,
)

_STEP = ChainStep(
    callable_name="htmlspecialchars",
    before="htmlspecialchars(", after=",ENT_COMPAT)", line=3,
)
_TOKEN = "cafe0123deadbeef"


def _doc(**overrides):
    doc = {
        "sanwit_token": _TOKEN,
        "php_version": "8.3.0",
        "outputs": {"p1": base64.b64encode(b"a&#039;b").decode()},
        "errors": {},
        "truncated": {},
    }
    doc.update(overrides)
    return json.dumps(doc)


class TestGenerateProbe:
    def test_chain_steps_emitted_as_written(self):
        probe = generate_probe((_STEP,), _TOKEN)
        assert "$x = htmlspecialchars($x,ENT_COMPAT);" in probe
        assert f'"sanwit_token" => "{_TOKEN}"' in probe

    def test_no_payload_bytes_in_probe_code(self):
        # Payloads travel ONLY in the JSON data file.
        probe = generate_probe((_STEP,), _TOKEN)
        assert "onerror" not in probe
        assert "--flag" not in probe

    def test_step_errors_are_recorded_not_swallowed(self):
        probe = generate_probe((_STEP,), _TOKEN)
        assert "set_error_handler" in probe
        assert "ErrorException" in probe
        assert "chain produced" in probe  # non-string chain result

    def test_truncation_marked(self):
        probe = generate_probe((_STEP,), _TOKEN)
        assert f"strlen($x) > {MAX_OUTPUT_CHARS}" in probe
        assert "__truncated" in probe

    def test_payloads_document_shape(self):
        doc = json.loads(payloads_document((("p1", "x' y"),)))
        assert doc == {"payloads": {"p1": "x' y"}}


class TestParseProbeOutput:
    def test_roundtrip(self):
        run = parse_probe_output(_doc(), _TOKEN)
        assert isinstance(run, ProbeRun)
        assert run.php_version == "8.3.0"
        assert run.outputs == {"p1": "a&#039;b"}

    def test_wrong_token_refused(self):
        result = parse_probe_output(
            _doc(sanwit_token="0000000000000000"), _TOKEN,
        )
        assert isinstance(result, str)
        assert "token" in result

    def test_missing_token_refused(self):
        doc = json.loads(_doc())
        del doc["sanwit_token"]
        result = parse_probe_output(json.dumps(doc), _TOKEN)
        assert isinstance(result, str)

    def test_non_json_refused(self):
        result = parse_probe_output("PHP Warning: something", _TOKEN)
        assert isinstance(result, str)
        assert "no JSON" in result

    def test_json_on_last_line_survives_leading_noise(self):
        result = parse_probe_output(
            "Deprecated: something\n" + _doc(), _TOKEN,
        )
        assert isinstance(result, ProbeRun)

    def test_bad_base64_marks_payload_errored(self):
        run = parse_probe_output(
            _doc(outputs={"p1": "!!not-base64!!"}), _TOKEN,
        )
        assert isinstance(run, ProbeRun)
        assert "p1" not in run.outputs
        assert "base64" in run.errors["p1"]

    def test_errors_and_truncation_carried(self):
        run = parse_probe_output(
            _doc(
                outputs={},
                errors={"p1": "chain produced NULL"},
                truncated={"p2": True},
            ),
            _TOKEN,
        )
        assert isinstance(run, ProbeRun)
        assert run.errors["p1"] == "chain produced NULL"
        assert run.truncated["p2"] is True

    def test_outputs_map_required(self):
        doc = json.loads(_doc())
        doc["outputs"] = "nope"
        result = parse_probe_output(json.dumps(doc), _TOKEN)
        assert isinstance(result, str)
        assert "outputs" in result
