"""Tests for core.orchestration.joern_binary_scan (ghidra2cpg bridge)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from core.orchestration.joern_binary_scan import (
    ARTIFACT_NAME,
    MAX_ARTIFACT_HITS,
    run_joern_binary_scan,
)


def _hit(query, line, function="fn", code="call()"):
    return ('JOERN_SCANHIT:{"query":"%s","file":"/t/bin","line":%d,'
            '"function":"%s","code":"%s"}' % (query, line, function, code))


def _done(queries=14, failed=0):
    return 'JOERN_SCAN_DONE:{"queries":%d,"failed":%d}' % (queries, failed)


class FakeFlow:
    def __init__(self, steps):
        self.steps = steps


class FakeClient:
    def __init__(self, *, bind_ok=True, flows=None, taint_errors=None,
                 script_output="", script_errors=None,
                 method_count_raw="val res0: Int = 91"):
        self.bind_ok = bind_ok
        self.flows = flows or []
        self.taint_errors = taint_errors or []
        self.script_output = script_output
        self.script_errors = script_errors or []
        self.method_count_raw = method_count_raw
        self.stopped = False
        self.bound = None

    def import_cpg(self, cpg_path, *, timeout=None):
        self.bound = Path(cpg_path)
        return self.bind_ok

    def query(self, cpgql, *, timeout=None):
        return SimpleNamespace(raw_output=self.method_count_raw)

    def run_tiered_sweep(self, *, timeout=None, lang_profile=None):
        self.lang_profile = lang_profile
        return SimpleNamespace(errors=self.taint_errors, flows=self.flows)

    def query_script(self, script, *, timeout=None):
        self.script = Path(script)
        return SimpleNamespace(errors=self.script_errors,
                               raw_output=self.script_output)

    def stop(self):
        self.stopped = True


def _build_ok(tmp_path):
    def build(binary, out_dir, *, timeout, errors_out=None):
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cpg = out_dir / "cpg.bin"
        cpg.write_bytes(b"CPG")
        return cpg
    return build


def _run(tmp_path, client, binary_bytes=b"\x7fELF"):
    binary = tmp_path / "target"
    binary.write_bytes(binary_bytes)
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    outcome = run_joern_binary_scan(
        binary, out_dir,
        build_fn=_build_ok(tmp_path),
        client_factory=lambda: client,
    )
    return outcome, out_dir


class TestHappyPath:
    def test_artifact_written_with_hint_tier_hits(self, tmp_path):
        output = "\n".join([
            _hit("call-to-gets", 1054000, "read_line", "gets"),
            _hit("setuid-without-setgid", 1054601, "drop_user", "setuid"),
            _done(),
        ])
        client = FakeClient(
            flows=[FakeFlow([
                {"function": "f", "line": 1053929, "code": "RDI"},
                {"function": "f", "line": 1053950, "code": "RSI"},
            ])],
            script_output=output)
        outcome, out_dir = _run(tmp_path, client)
        assert outcome.method_count == 91
        assert outcome.taint_flow_count == 1
        assert outcome.structural_hit_count == 2
        assert outcome.degraded is False
        assert client.stopped is True
        assert outcome.artifact_path == out_dir / ARTIFACT_NAME
        doc = json.loads(outcome.artifact_path.read_text())
        assert doc["engine"] == "joern-ghidra2cpg"
        assert doc["evidence_tier"] == "hint"
        assert "virtual addresses" in doc["precision"]
        assert doc["binary_sha256"]
        hits = doc["structural_hits"]
        # Addresses surface as hex, never as source lines.
        assert {h["address"] for h in hits} == {"0x101530", "0x101789"}
        assert all(h["cwe"] for h in hits)
        flow = doc["taint_flows"][0]["steps"]
        assert flow[0]["address"] == "0x1014e9"

    def test_ansi_coloured_count_echo_parsed(self, tmp_path):
        # Live regression: the REPL echo is SGR-coloured and a naive
        # digit scrape concatenated the colour-code digits (91 became
        # 330366032091).
        raw = ("\x1b[33mval\x1b[0m \x1b[36mres6\x1b[0m: "
               "\x1b[32mInt\x1b[0m = 91\n")
        client = FakeClient(script_output=_done(), method_count_raw=raw)
        outcome, _ = _run(tmp_path, client)
        assert outcome.method_count == 91

    def test_unparseable_count_is_none(self, tmp_path):
        client = FakeClient(script_output=_done(), method_count_raw="?!")
        outcome, _ = _run(tmp_path, client)
        assert outcome.method_count is None

    def test_c_profile_selected(self, tmp_path):
        client = FakeClient(script_output=_done())
        _run(tmp_path, client)
        assert client.lang_profile is not None

    def test_duplicate_hits_deduplicated(self, tmp_path):
        output = "\n".join([
            _hit("call-to-gets", 1054000, "read_line"),
            _hit("call-to-gets", 1054000, "read_line"),
            _done(),
        ])
        outcome, _ = _run(tmp_path, FakeClient(script_output=output))
        assert outcome.structural_hit_count == 1

    def test_hit_cap_bounds_artifact(self, tmp_path):
        lines = [_hit("call-to-gets", 1054000 + i) for i in
                 range(MAX_ARTIFACT_HITS + 50)]
        lines.append(_done())
        outcome, _ = _run(tmp_path,
                          FakeClient(script_output="\n".join(lines)))
        assert outcome.structural_hit_count == MAX_ARTIFACT_HITS


class TestSentinelDiscipline:
    def test_missing_sentinel_is_not_clean(self, tmp_path):
        outcome, _ = _run(tmp_path, FakeClient(script_output=""))
        assert outcome.degraded is True
        assert any("did not complete" in e for e in outcome.errors)

    def test_query_count_drift_surfaces(self, tmp_path):
        outcome, _ = _run(tmp_path,
                          FakeClient(script_output=_done(queries=6)))
        assert outcome.degraded is True
        assert any("drift" in e for e in outcome.errors)

    def test_scanerr_records_fail_queries(self, tmp_path):
        output = "\n".join([
            'JOERN_SCANERR:{"query":"call-to-gets","error":"boom"}',
            _done(failed=1),
        ])
        outcome, _ = _run(tmp_path, FakeClient(script_output=output))
        assert outcome.queries_failed == ["call-to-gets"]
        assert outcome.degraded is True

    def test_unknown_query_name_surfaces_once(self, tmp_path):
        output = "\n".join([
            _hit("made-up-query", 1054000),
            _hit("made-up-query", 1054001),
            _done(),
        ])
        outcome, _ = _run(tmp_path, FakeClient(script_output=output))
        assert outcome.structural_hit_count == 0
        unknown = [e for e in outcome.errors if "unknown structural" in e]
        assert len(unknown) == 1


class TestFailurePaths:
    def test_build_failure_degrades_without_artifact(self, tmp_path):
        binary = tmp_path / "target"
        binary.write_bytes(b"\x7fELF")
        out_dir = tmp_path / "run"
        out_dir.mkdir()

        def build_fail(binary, out, *, timeout, errors_out=None):
            if errors_out is not None:
                errors_out.append("ghidra2cpg exited 1")
            return None

        outcome = run_joern_binary_scan(
            binary, out_dir, build_fn=build_fail,
            client_factory=lambda: FakeClient())
        assert outcome.degraded is True
        assert outcome.artifact_path is None
        assert not (out_dir / ARTIFACT_NAME).exists()

    def test_bind_failure_degrades_without_artifact(self, tmp_path):
        client = FakeClient(bind_ok=False)
        outcome, out_dir = _run(tmp_path, client)
        assert outcome.degraded is True
        assert outcome.artifact_path is None
        assert client.stopped is True

    def test_taint_errors_degrade_but_artifact_stands(self, tmp_path):
        client = FakeClient(taint_errors=["tier 2 timed out"],
                            script_output=_done())
        outcome, _ = _run(tmp_path, client)
        assert outcome.degraded is True
        assert outcome.artifact_path is not None
        doc = json.loads(outcome.artifact_path.read_text())
        assert doc["degraded"] is True
        assert any("timed out" in e for e in doc["errors"])

    def test_client_exception_never_raises(self, tmp_path):
        class Exploding(FakeClient):
            def run_tiered_sweep(self, **kwargs):
                raise RuntimeError("worker died")

        client = Exploding(script_output=_done())
        outcome, _ = _run(tmp_path, client)
        assert outcome.degraded is True
        assert client.stopped is True
        assert any("worker died" in e for e in outcome.errors)
