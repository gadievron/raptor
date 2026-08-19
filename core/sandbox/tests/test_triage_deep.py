"""Tests for core.sandbox.triage_deep — the optional LLM pass over a
sandbox-triage verdict. Hermetic: a fake client, no real LLM."""

import json

import pytest

from core.sandbox import triage as triage_mod
from core.sandbox import triage_deep as deep_mod


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    yield


class _FakeClient:
    model_name = "fake-model"

    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def generate(self, user, *, system_prompt="", **kwargs):
        self.calls.append({"user": user, "system": system_prompt,
                           **kwargs})
        return self.reply


def _suspicious_run(tmp_path):
    """A run dir whose rules triage yields a suspicious verdict with
    one escape-primitive signal (lifecycle-realistic: written via the
    real triage entry point so the report is self-stamped)."""
    from core.sandbox import summary as summary_mod
    payload = {
        "run_dir": str(tmp_path),
        "generated_at": "2026-07-23T00:00:00Z",
        "total_denials": 1,
        "by_type": {},
        "denials": [{"type": "seccomp", "syscall": "ptrace",
                     "profile": "full",
                     "cmd": "<sandbox audit: traced PID 42>"}],
    }
    (tmp_path / summary_mod.SUMMARY_FILE).write_text(json.dumps(payload))
    report = triage_mod.triage_run(tmp_path)
    assert report["verdict"] == "suspicious"
    return report


def _reply(signal_type="escape_primitive_denied",
           judgement="attack_attempt", extra=""):
    return json.dumps({
        "assessments": [{
            "signal_type": signal_type,
            "judgement": judgement,
            "confidence": 0.9,
            "rationale": "ptrace from a build tool is not normal" + extra,
        }],
        "overall_note": "looks deliberate",
    })


class TestDeepAnalyse:
    def test_happy_path_writes_advisory_report(self, tmp_path):
        _suspicious_run(tmp_path)
        client = _FakeClient(_reply())
        deep = deep_mod.deep_analyse(tmp_path, client=client)
        assert deep["rules_verdict"] == "suspicious"
        assert deep["rules_verdict_immutable"] is True
        assert deep["assessments"][0]["judgement"] == "attack_attempt"
        on_disk = json.loads((tmp_path / deep_mod.DEEP_FILE).read_text())
        assert on_disk["model"] == "fake-model"
        assert "mac" in on_disk

    def test_rules_verdict_never_recomputed_from_model(self, tmp_path):
        # Even a model insisting everything is noise cannot move the
        # verdict: the deep report restates the rules verdict verbatim.
        _suspicious_run(tmp_path)
        client = _FakeClient(_reply(judgement="tool_noise"))
        deep = deep_mod.deep_analyse(tmp_path, client=client)
        assert deep["rules_verdict"] == "suspicious"
        rules = json.loads(
            (tmp_path / triage_mod.TRIAGE_FILE).read_text())
        assert rules["verdict"] == "suspicious", "rules file untouched"

    def test_invented_signal_types_dropped(self, tmp_path):
        _suspicious_run(tmp_path)
        client = _FakeClient(json.dumps({
            "assessments": [
                {"signal_type": "escape_primitive_denied",
                 "judgement": "unclear", "confidence": 0.5,
                 "rationale": "ok"},
                {"signal_type": "totally_invented_signal",
                 "judgement": "attack_attempt", "confidence": 1.0,
                 "rationale": "model hallucination"},
            ],
            "overall_note": "",
        }))
        deep = deep_mod.deep_analyse(tmp_path, client=client)
        assert [a["signal_type"] for a in deep["assessments"]] == [
            "escape_primitive_denied"]
        assert deep["ungrounded_dropped"] == 1

    def test_model_output_sanitised_and_coerced(self, tmp_path):
        _suspicious_run(tmp_path)
        client = _FakeClient(json.dumps({
            "assessments": [{
                "signal_type": "escape_primitive_denied",
                "judgement": "DEFINITELY-EVIL",       # not in the enum
                "confidence": "lots",                  # not a float
                "rationale": "x\x1b]0;pwn\x07" + "y" * 2000,
            }],
            "overall_note": "n",
        }))
        deep = deep_mod.deep_analyse(tmp_path, client=client)
        a = deep["assessments"][0]
        assert a["judgement"] == "unclear"
        assert a["confidence"] == 0.0
        assert "\x1b" not in a["rationale"]
        assert len(a["rationale"]) <= deep_mod._MAX_RATIONALE_CHARS

    def test_garbage_model_output_yields_empty_assessments(self, tmp_path):
        _suspicious_run(tmp_path)
        client = _FakeClient("I cannot help with that.")
        deep = deep_mod.deep_analyse(tmp_path, client=client)
        assert deep["assessments"] == []

    def test_tampered_triage_report_refused(self, tmp_path):
        _suspicious_run(tmp_path)
        report_path = tmp_path / triage_mod.TRIAGE_FILE
        on_disk = json.loads(report_path.read_text())
        on_disk["verdict"] = "clean"  # forged downgrade
        report_path.write_text(json.dumps(on_disk))
        client = _FakeClient(_reply())
        assert deep_mod.deep_analyse(tmp_path, client=client) is None
        assert client.calls == [], "no LLM call over forged telemetry"
        assert not (tmp_path / deep_mod.DEEP_FILE).exists()

    def test_unstamped_triage_report_refused_by_default(self, tmp_path):
        report_path = tmp_path / triage_mod.TRIAGE_FILE
        report_path.write_text(json.dumps({
            "run_dir": str(tmp_path),
            "verdict": "suspicious",
            "signals": [{"type": "escape_primitive_denied",
                         "severity": "high", "count": 1,
                         "evidence": ["ptrace"]}],
        }))
        client = _FakeClient(_reply())
        assert deep_mod.deep_analyse(tmp_path, client=client) is None
        assert client.calls == [], "no LLM call over unstamped telemetry"
        assert not (tmp_path / deep_mod.DEEP_FILE).exists()

    def test_missing_report_and_no_client_return_none(
            self, tmp_path, monkeypatch):
        assert deep_mod.deep_analyse(tmp_path,
                                     client=_FakeClient("{}")) is None
        _suspicious_run(tmp_path)
        import core.llm.factory as factory
        monkeypatch.setattr(factory, "get_client", lambda *a, **k: None)
        assert deep_mod.deep_analyse(tmp_path) is None


class TestPromptConstruction:
    def test_untrusted_content_enveloped_not_in_system(self, tmp_path):
        report = _suspicious_run(tmp_path)
        client = _FakeClient(_reply())
        deep_mod.deep_analyse(tmp_path, client=client)
        call = client.calls[0]
        # Attacker-influenced strings ride in the user message's
        # untrusted envelope; the system prompt stays pure instruction.
        assert "ptrace" in call["user"]
        assert "ptrace" not in call["system"].replace(
            deep_mod._SYSTEM_PROMPT, "")
        assert call["call_class"] == "sandbox-triage-deep"
        assert report["signals"], "precondition"
