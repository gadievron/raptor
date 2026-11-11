"""Conditional models identify their actual text input without freshness claims."""
from hashlib import sha256

from core.dataflow import injection_prescreen as ip
from core.dataflow.tests.test_injection_prescreen import _path


def test_model_digest_uses_captured_input_not_post_query_file(tmp_path, monkeypatch):
    source = ("import re\ndef handle(value):\n"
              "    if not re.fullmatch(r'[A-Za-z0-9]+', value):\n"
              "        return\n    return consume(value)\n")
    path = tmp_path / "app.py"
    path.write_text(source)
    monkeypatch.setattr(ip, "_z3_available", lambda: True)
    monkeypatch.setattr(ip, "_STATS", ip.PrescreenStats())

    def model_only(spec, classes):
        path.write_text("changed after captured model input\n")
        return True, "owned conditional exclusion", 0.0

    monkeypatch.setattr(ip, "_spec_neutralizes_all", model_only)
    verdict = ip.prescreen_finding(
        paths=[_path("app.py", 2, [3], 5)], repo_root=tmp_path, rule_id="py/path-injection",
    )
    assert verdict is not None and verdict.refuted is False
    model, = verdict.evidence
    assert model["source_input_sha256"] == sha256(source.encode()).hexdigest()
    assert model["source_input_sha256"] != sha256(path.read_bytes()).hexdigest()
    assert "sink interpretation" in verdict.reason
