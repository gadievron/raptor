"""Tests for the shared run-digest reader + renderers."""

import json
import os
import time
import types
from pathlib import Path

from core.run.digest import (
    last_activity_age_s,
    read_run_digest,
    render_run_digest,
    render_run_status,
)


def _meta(run: Path, **over):
    meta = {
        "command": "agentic",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "status": "completed",
    }
    meta.update(over)
    (run / ".raptor-run.json").write_text(json.dumps(meta),
                                          encoding="utf-8")


def _jsonl(path: Path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n",
                    encoding="utf-8")


class TestReader:
    def test_empty_dir_degrades_everywhere(self, tmp_path):
        d = read_run_digest(tmp_path)
        assert d.status == "unknown"
        assert d.spend_usd is None
        assert d.findings_total is None
        assert d.coverage_percent is None
        # Renderers still produce output.
        assert "Unknown" in render_run_status(d)
        assert "What matters" in render_run_digest(d)

    def test_lifecycle_fields(self, tmp_path):
        _meta(tmp_path, status="failed", duration_seconds=42.0,
              extra={"error": "boom", "findings_count": 7})
        d = read_run_digest(tmp_path)
        assert d.status == "failed"
        assert d.duration_seconds == 42.0
        assert d.error == "boom"
        assert d.findings_total == 7
        assert d.heartbeat_age_s is None  # terminal runs: no heartbeat

    def test_running_run_reports_heartbeat_age(self, tmp_path):
        _meta(tmp_path, status="running")
        d = read_run_digest(tmp_path)
        assert d.heartbeat_age_s is not None
        assert d.heartbeat_age_s < 60

    def test_heartbeat_uses_freshest_child(self, tmp_path):
        old = time.time() - 7200
        os.utime(tmp_path, (old, old))
        (tmp_path / "llm-telemetry.jsonl").write_text("",
                                                      encoding="utf-8")
        age = last_activity_age_s(tmp_path)
        assert age is not None and age < 60

    def test_telemetry_counters_and_live_spend(self, tmp_path):
        _meta(tmp_path)
        _jsonl(tmp_path / "llm-telemetry.jsonl", [
            {"event": "call", "disposition": "ok",
             "call_class": "review", "cost_usd": 0.5,
             "ts": 1767225600.0},
            {"event": "attempt_failed", "disposition": "timeout",
             "call_class": "review", "cost_usd": 0.25,
             "ts": 1767225601.5},
            # The sink stamps ts as an epoch FLOAT (time.time()) —
            # the reader must render it, not drop it.
            {"event": "attempt_failed", "disposition": "blocked",
             "call_class": "sweep", "cost_usd": 0.0,
             "ts": 1767225700.0},
            {"event": "breaker_tripped", "call_class": "run_breaker",
             "cost_usd": 0.0},
            {"event": "resume_marker", "call_class": "resume_marker"},
        ])
        d = read_run_digest(tmp_path)
        assert d.llm_calls == 1
        assert d.llm_failed_attempts == 2
        assert d.llm_timeouts == 1
        assert d.breaker_trips == 1
        assert d.spend_usd == 0.75
        # Phase hint is the newest CALL-shaped record, not the breaker.
        assert d.last_call_class == "sweep"
        assert d.last_call_ts == "2026-01-01T00:01:40+00:00"

    def test_string_ts_passes_through(self, tmp_path):
        _meta(tmp_path)
        _jsonl(tmp_path / "llm-telemetry.jsonl", [
            {"event": "call", "disposition": "ok",
             "call_class": "review", "cost_usd": 0.1,
             "ts": "2026-01-02T03:04:05+00:00"},
        ])
        d = read_run_digest(tmp_path)
        assert d.last_call_ts == "2026-01-02T03:04:05+00:00"

    def test_terminal_run_keeps_reconciled_ledger(self, tmp_path):
        # A completed run's reconciled ledger is authoritative — the
        # naive per-record telemetry sum must not override it.
        _meta(tmp_path, status="completed")
        (tmp_path / "spend-floor.json").write_text(
            json.dumps({"spend_usd": 1.0}), encoding="utf-8")
        _jsonl(tmp_path / "llm-telemetry.jsonl", [
            {"event": "call", "disposition": "ok",
             "call_class": "review", "cost_usd": 5.0},
        ])
        d = read_run_digest(tmp_path)
        assert d.spend_usd == 1.0

    def test_running_run_takes_live_sum_when_ahead(self, tmp_path):
        _meta(tmp_path, status="running")
        (tmp_path / "spend-floor.json").write_text(
            json.dumps({"spend_usd": 1.0}), encoding="utf-8")
        _jsonl(tmp_path / "llm-telemetry.jsonl", [
            {"event": "call", "disposition": "ok",
             "call_class": "review", "cost_usd": 5.0},
        ])
        d = read_run_digest(tmp_path)
        assert d.spend_usd == 5.0

    def test_spend_cap_from_run_config(self, tmp_path):
        _meta(tmp_path)
        (tmp_path / "audit-run-config.json").write_text(
            json.dumps({"max_cost_usd": 50.0}), encoding="utf-8")
        (tmp_path / "spend-floor.json").write_text(
            json.dumps({"spend_usd": 12.5}), encoding="utf-8")
        d = read_run_digest(tmp_path)
        assert d.max_cost_usd == 50.0
        assert d.spend_usd == 12.5

    def test_exploitable_split_by_verification(self, tmp_path,
                                               monkeypatch):
        _meta(tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps([
            {"id": "f1", "file": "a.c", "line": 3,
             "vuln_type": "overflow", "is_exploitable": True},
            {"id": "f2", "file": "b.c",
             "analysis": {"is_exploitable": True}},
            {"id": "f3", "file": "c.c", "is_exploitable": False},
            {"id": "f4", "file": "d.c", "final_status": "exploitable"},
        ]), encoding="utf-8")
        import core.labeled_attempts.view as view_mod
        monkeypatch.setattr(
            view_mod, "collect_outcomes",
            lambda run_dir, project_root=None: [types.SimpleNamespace(
                status="verified", finding_id="f1", oracle="sandbox",
                cwe_id="CWE-787", file="a.c")])
        d = read_run_digest(tmp_path)
        assert [v["finding_id"] for v in d.verified] == ["f1"]
        assert {r["finding_id"] for r in d.exploitable_unverified} \
            == {"f2", "f4"}
        assert d.findings_total == 4

    def test_orchestrated_results_feed_the_digest(self, tmp_path):
        # /agentic runs have no top-level findings.json — per-finding
        # verdicts live in orchestrated_report.json.
        _meta(tmp_path)
        (tmp_path / "orchestrated_report.json").write_text(json.dumps({
            "mode": "orchestrated",
            "results": [
                {"finding_id": "o1", "status": "analysed",
                 "file_path": "a.c", "line": 5,
                 "vuln_type": "overflow", "is_exploitable": True},
                {"finding_id": "o2", "status": "analysed",
                 "file_path": "b.c", "is_exploitable": False},
            ],
        }), encoding="utf-8")
        d = read_run_digest(tmp_path)
        assert [r["finding_id"] for r in d.exploitable_unverified] \
            == ["o1"]
        assert d.findings_total == 2

    def test_confirm_direction_vocabulary(self, tmp_path):
        # The digest classifies with the repo's verdict vocabulary:
        # every confirm-direction status lands in the exploitable
        # bucket; explicit negatives suppress. A status the project
        # views show as confirmed must never read as an all-clear.
        _meta(tmp_path)
        vdir = tmp_path / "validation"
        vdir.mkdir()
        shown = ["confirmed", "confirmed_unverified",
                 "likely_exploitable", "confirmed_constrained",
                 "confirmed_blocked"]
        hidden = ["ruled_out", "disproven", "false_positive"]
        (vdir / "findings.json").write_text(json.dumps(
            [{"finding_id": f"s-{v}", "file": "a.c",
              "final_status": v} for v in shown]
            + [{"finding_id": f"h-{v}", "file": "a.c",
                "final_status": v, "is_exploitable": True}
               for v in hidden],
        ), encoding="utf-8")
        d = read_run_digest(tmp_path)
        got = {r["finding_id"] for r in d.exploitable_unverified}
        assert got == {f"s-{v}" for v in shown}

    def test_lifecycle_status_enum_never_counts_positive(self,
                                                         tmp_path):
        _meta(tmp_path)
        (tmp_path / "orchestrated_report.json").write_text(json.dumps({
            "mode": "orchestrated",
            "results": [
                {"finding_id": "o1", "status": "analysed",
                 "file_path": "a.c"},
                {"finding_id": "o2", "status": "skipped",
                 "file_path": "b.c"},
            ],
        }), encoding="utf-8")
        d = read_run_digest(tmp_path)
        assert d.exploitable_unverified == []

    def test_validation_ruling_overrides_earlier_claim(self, tmp_path):
        _meta(tmp_path)
        (tmp_path / "orchestrated_report.json").write_text(json.dumps({
            "mode": "orchestrated",
            "results": [
                {"finding_id": "o1", "status": "analysed",
                 "file_path": "a.c", "is_exploitable": True},
            ],
        }), encoding="utf-8")
        vdir = tmp_path / "validation"
        vdir.mkdir()
        (vdir / "findings.json").write_text(json.dumps([
            {"finding_id": "o1", "file": "a.c",
             "is_exploitable": True, "final_status": "ruled_out"},
        ]), encoding="utf-8")
        d = read_run_digest(tmp_path)
        assert d.exploitable_unverified == []

    def test_idless_verified_outcome_dedupes_by_file(self, tmp_path,
                                                     monkeypatch):
        _meta(tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps([
            {"file": "a.c", "is_exploitable": True},  # no id
        ]), encoding="utf-8")
        import core.labeled_attempts.view as view_mod
        monkeypatch.setattr(
            view_mod, "collect_outcomes",
            lambda run_dir, project_root=None: [types.SimpleNamespace(
                status="verified", finding_id="", oracle="sandbox",
                cwe_id="", file="a.c")])
        d = read_run_digest(tmp_path)
        # Same defect must never count under BOTH headings.
        assert len(d.verified) == 1
        assert d.exploitable_unverified == []

    def test_abstained_verdict_is_not_exploitable(self, tmp_path):
        _meta(tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps([
            {"id": "f1", "file": "a.c", "is_exploitable": None},
            {"id": "f2", "file": "b.c",
             "is_exploitable": "true"},  # junk shape — abstained
        ]), encoding="utf-8")
        d = read_run_digest(tmp_path)
        assert d.exploitable_unverified == []

    def test_suppression_counts(self, tmp_path):
        _meta(tmp_path)
        _jsonl(tmp_path / "suppressions.jsonl", [
            {"finding_id": "x", "verdict": "binary_oracle_absent",
             "dropped": True},
            {"finding_id": "y", "verdict": "binary_oracle_absent"},
            {"finding_id": "z", "verdict": "candidate_only",
             "dropped": False},
        ])
        d = read_run_digest(tmp_path)
        assert d.suppressed_dropped == 2
        assert d.suppression_verdicts == {"binary_oracle_absent": 2}

    def test_next_steps_name_validate_and_review(self, tmp_path):
        _meta(tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps([
            {"id": "f1", "file": "a.c", "is_exploitable": True},
        ]), encoding="utf-8")
        _jsonl(tmp_path / "suppressions.jsonl", [
            {"finding_id": "x", "verdict": "binary_oracle_absent"},
        ])
        d = read_run_digest(tmp_path)
        joined = "\n".join(d.next_steps)
        assert "/validate" in joined
        assert "raptor-review verdict" in joined


class TestRendering:
    def test_status_values_title_case_never_all_caps(self, tmp_path):
        _meta(tmp_path, status="running")
        out = render_run_status(read_run_digest(tmp_path))
        assert "Running" in out
        assert "RUNNING" not in out

    def test_foreign_bytes_escaped_at_render(self, tmp_path):
        _meta(tmp_path, status="failed",
              extra={"error": "boom \x1b]0;evil\x07 done"})
        (tmp_path / "findings.json").write_text(json.dumps([
            {"id": "f\x1b[31m1", "file": "a\x1b[2Jb.c",
             "is_exploitable": True},
        ]), encoding="utf-8")
        d = read_run_digest(tmp_path)
        for out in (render_run_status(d), render_run_digest(d)):
            assert "\x1b" not in out
            assert "\x07" not in out
        assert "\\x1b" in render_run_status(d)

    def test_digest_ranks_verified_first(self, tmp_path, monkeypatch):
        _meta(tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps([
            {"id": "f1", "file": "a.c", "is_exploitable": True},
            {"id": "f2", "file": "b.c", "is_exploitable": True},
        ]), encoding="utf-8")
        import core.labeled_attempts.view as view_mod
        monkeypatch.setattr(
            view_mod, "collect_outcomes",
            lambda run_dir, project_root=None: [types.SimpleNamespace(
                status="verified", finding_id="f1", oracle="sandbox",
                cwe_id="", file="a.c")])
        out = render_run_digest(read_run_digest(tmp_path))
        assert out.index("Verified") < out.index("Exploitable, unverified")

    def test_spend_vs_cap_line(self, tmp_path):
        _meta(tmp_path)
        (tmp_path / "audit-run-config.json").write_text(
            json.dumps({"max_cost_usd": 10.0}), encoding="utf-8")
        (tmp_path / "spend-floor.json").write_text(
            json.dumps({"spend_usd": 2.5}), encoding="utf-8")
        out = render_run_status(read_run_digest(tmp_path))
        assert "$2.50 of $10.00 cap (25%)" in out

    def test_to_dict_round_trips_json(self, tmp_path):
        _meta(tmp_path)
        d = read_run_digest(tmp_path)
        payload = json.dumps(d.to_dict(), ensure_ascii=True)
        assert json.loads(payload)["command"] == "agentic"


class TestFuzzHarnessLine:
    """Shipped fuzz-harness surfacing — one line, terminal runs
    only, never able to degrade the digest."""

    @staticmethod
    def _target_with_harnesses(base: Path) -> Path:
        target = base / "target-repo"
        fuzz = target / "fuzz" / "fuzz_targets"
        fuzz.mkdir(parents=True)
        (target / "fuzz" / "Cargo.toml").write_text("[package]\n")
        (fuzz / "roundtrip.rs").write_text(
            "fuzz_target!(|data: &[u8]| {});\n")
        c_dir = target / "tests" / "fuzz"
        c_dir.mkdir(parents=True)
        (c_dir / "fuzz_decode.c").write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)"
            " { return 0; }\n")
        return target

    def test_digest_line_renders_counts(self, tmp_path):
        target = self._target_with_harnesses(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        _meta(run, target_path=str(target))
        d = read_run_digest(run)
        assert d.fuzz_harness_counts == {"cargo-fuzz": 1, "libfuzzer": 1}
        out = render_run_digest(d)
        assert "Target ships 2 fuzz harnesses: " in out
        assert "1 cargo-fuzz, 1 libfuzzer" in out
        assert "/fuzz can drive them" in out

    def test_singular_harness_line(self, tmp_path):
        target = tmp_path / "t"
        fuzz = target / "fuzz" / "fuzz_targets"
        fuzz.mkdir(parents=True)
        (target / "fuzz" / "Cargo.toml").write_text("[package]\n")
        (fuzz / "one.rs").write_text("fn main() {}\n")
        run = tmp_path / "run"
        run.mkdir()
        _meta(run, target_path=str(target))
        out = render_run_digest(read_run_digest(run))
        assert "Target ships 1 fuzz harness: 1 cargo-fuzz" in out

    def test_truncated_census_marks_counts_partial(
            self, tmp_path, monkeypatch):
        import packages.fuzzing.harness_census as hc
        target = self._target_with_harnesses(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        _meta(run, target_path=str(target))
        monkeypatch.setattr(hc, "_MAX_SNIFF_FILES", 0)
        d = read_run_digest(run)
        assert d.fuzz_harness_counts_partial is True
        out = render_run_digest(d)
        assert "fuzz harness (counts partial): 1 cargo-fuzz" in out

    def test_no_harnesses_no_line(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        run = tmp_path / "run"
        run.mkdir()
        _meta(run, target_path=str(target))
        d = read_run_digest(run)
        assert d.fuzz_harness_counts == {}
        assert "fuzz harness" not in render_run_digest(d)

    def test_running_run_skips_census(self, tmp_path, monkeypatch):
        target = self._target_with_harnesses(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        _meta(run, status="running", target_path=str(target))
        import packages.fuzzing.harness_census as hc

        def _explode(_path):  # pragma: no cover - trap
            raise AssertionError("census must not run on a live run")

        monkeypatch.setattr(hc, "census_fuzz_harnesses", _explode)
        d = read_run_digest(run)
        assert d.fuzz_harness_counts == {}

    def test_census_failure_digest_intact(self, tmp_path, monkeypatch):
        target = self._target_with_harnesses(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        _meta(run, target_path=str(target),
              extra={"findings_count": 3})
        import packages.fuzzing.harness_census as hc

        def _boom(_path):
            raise RuntimeError("census exploded")

        monkeypatch.setattr(hc, "census_fuzz_harnesses", _boom)
        d = read_run_digest(run)
        assert d.fuzz_harness_counts == {}
        assert d.findings_total == 3  # other layers untouched
        out = render_run_digest(d)
        assert "What matters" in out
        assert "fuzz harness" not in out

    def test_absent_or_bogus_target_path_skips(self, tmp_path):
        run = tmp_path / "run"
        run.mkdir()
        _meta(run)  # no target_path at all
        assert read_run_digest(run).fuzz_harness_counts == {}
        _meta(run, target_path=str(tmp_path / "nope"))
        assert read_run_digest(run).fuzz_harness_counts == {}

    def test_to_dict_carries_counts(self, tmp_path):
        target = self._target_with_harnesses(tmp_path)
        run = tmp_path / "run"
        run.mkdir()
        _meta(run, target_path=str(target))
        doc = json.loads(json.dumps(read_run_digest(run).to_dict()))
        assert doc["fuzz_harness_counts"]["cargo-fuzz"] == 1
        assert doc["target_path"] == str(target)
