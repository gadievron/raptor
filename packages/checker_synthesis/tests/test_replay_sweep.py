"""Tests for the cross-target proven-rule replay sweep."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.checker_synthesis import replay_sweep as rs
from packages.checker_synthesis.library import RuleLibrary
from packages.coccinelle.models import SpatchMatch, SpatchResult
from packages.semgrep.models import SemgrepFinding, SemgrepResult


def _manifest_entry(
    rule_id: str,
    *,
    engine: str = "semgrep",
    cwe: str = "CWE-787",
    tp_rate: float = 0.9,
    dual_control: bool = True,
    n_targets: int = 1,
    archived: bool = False,
) -> dict:
    ext = ".yml" if engine == "semgrep" else ".cocci"
    return {
        "rule_id": rule_id,
        "engine": engine,
        "cwe": cwe,
        "body_hash": f"hash-{rule_id}",
        "rule_path": f"{engine}/{rule_id}{ext}",
        "rationale": "",
        "seed_file": "",
        "seed_function": "",
        "dual_control": dual_control,
        "promoted_at": "2026-01-01T00:00:00Z",
        "tp_rate": tp_rate,
        "fp_rate": 1.0 - tp_rate,
        "total_variants": 3,
        "total_matches": 4,
        "targets": [
            {
                "target_hash": f"t{i}",
                "ts": "2026-01-01T00:00:00Z",
                "matches": 2,
                "variants": 1,
                "tp_rate": tp_rate,
            }
            for i in range(n_targets)
        ],
        "archived": archived,
    }


def _write_library(tmp_path: Path, entries: list[dict]) -> Path:
    lib_dir = tmp_path / "rule-library"
    (lib_dir / "semgrep").mkdir(parents=True)
    (lib_dir / "coccinelle").mkdir(parents=True)
    (lib_dir / "manifest.json").write_text(
        json.dumps({"rules": entries}), encoding="utf-8",
    )
    for e in entries:
        (lib_dir / e["rule_path"]).parent.mkdir(exist_ok=True)
        (lib_dir / e["rule_path"]).write_text(
            "rules: []\n" if e["engine"] == "semgrep" else "@r@\n@@\n",
            encoding="utf-8",
        )
    return lib_dir


def _semgrep_result(findings: int, rule_id: str = "r") -> SemgrepResult:
    return SemgrepResult(
        name=rule_id,
        findings=[
            SemgrepFinding(file="src/a.c", line=i + 1, rule_id=rule_id)
            for i in range(findings)
        ],
    )


def _spatch_result(matches: int, rule: str = "r") -> SpatchResult:
    return SpatchResult(
        rule=rule,
        matches=[
            SpatchMatch(file="src/a.c", line=i + 1, rule=rule)
            for i in range(matches)
        ],
    )


class TestReplayableEntries:
    def test_gates_mirror_find_replayable(self, tmp_path):
        entries = [
            _manifest_entry("good-semgrep"),
            _manifest_entry("good-cocci", engine="coccinelle"),
            _manifest_entry("low-tp", tp_rate=0.5),
            _manifest_entry("no-dual", dual_control=False),
            _manifest_entry("no-targets", n_targets=0),
            _manifest_entry("archived", archived=True),
            _manifest_entry("odd-engine", engine="codeql"),
        ]
        lib = RuleLibrary(_write_library(tmp_path, entries))
        sg, cc, unsupported = rs.replayable_entries(lib)
        assert [e.rule_id for e in sg] == ["good-semgrep"]
        assert [e.rule_id for e in cc] == ["good-cocci"]
        assert unsupported == ["odd-engine (engine=codeql)"]

    def test_gates_match_library_constants(self, tmp_path):
        # An entry exactly at the replay threshold passes here iff
        # find_replayable would pass it — pin against drift.
        entry = _manifest_entry("edge", cwe="CWE-89")
        entry["tp_rate"] = rs._REPLAY_TP_THRESHOLD
        lib = RuleLibrary(_write_library(tmp_path, [entry]))
        sg, _, _ = rs.replayable_entries(lib)
        assert [e.rule_id for e in sg] == ["edge"]
        assert [e.rule_id for e in lib.find_replayable("CWE-89", "semgrep")] \
            == ["edge"]


class TestDispatch:
    def test_cocci_skipped_without_c_sources(self, tmp_path, monkeypatch):
        lib_dir = _write_library(
            tmp_path, [_manifest_entry("cc", engine="coccinelle")],
        )
        target = tmp_path / "pyproj"
        target.mkdir()
        (target / "app.py").write_text("x = 1\n")
        called = []
        monkeypatch.setattr(
            rs.cocci_runner, "run_rule",
            lambda *a, **k: called.append(a) or _spatch_result(0),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=False)
        assert not called
        assert report.cocci_skipped_targets == [str(target)]

    def test_cocci_runs_on_c_target(self, tmp_path, monkeypatch):
        lib_dir = _write_library(
            tmp_path, [_manifest_entry("cc", engine="coccinelle")],
        )
        target = tmp_path / "cproj"
        target.mkdir()
        (target / "main.c").write_text("int main(void){return 0;}\n")
        monkeypatch.setattr(
            rs.cocci_runner, "run_rule",
            lambda *a, **k: _spatch_result(2, rule="cc"),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=False)
        assert len(report.matches) == 2
        assert {m.engine for m in report.matches} == {"coccinelle"}
        assert report.cocci_skipped_targets == []

    def test_semgrep_runs_on_any_target(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        target = tmp_path / "pyproj"
        target.mkdir()
        (target / "app.py").write_text("x = 1\n")
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(1, rule_id="sg"),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=False)
        assert len(report.matches) == 1
        m = report.matches[0]
        assert m.provenance == "rule-library"
        assert m.tier == "library"
        assert m.tp_rate == pytest.approx(0.9)


class TestGraduated:
    def test_graduated_rules_join_sweep(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("grad")])
        engine_rules = tmp_path / "engine-rules"
        (engine_rules / "semgrep" / "rules").mkdir(parents=True)
        (engine_rules / "semgrep" / "rules" / "grad.yaml").write_text(
            "rules: []\n",
        )
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(1, rule_id="grad"),
        )
        report = rs.run_sweep(
            [target], library_dir=lib_dir,
            engine_rules_dir=engine_rules, record=False,
        )
        assert report.rules_graduated == 1
        provs = sorted(m.provenance for m in report.matches)
        assert provs == ["graduated", "rule-library"]


class TestRecording:
    def test_matches_recorded_without_precision_change(
        self, tmp_path, monkeypatch,
    ):
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(3, rule_id="sg"),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=True)
        assert report.recorded_updates == 1
        entry = RuleLibrary(lib_dir).all_entries()[0]
        assert len(entry.targets) == 2  # original + sweep target
        sweep_rec = entry.targets[-1]
        assert sweep_rec.matches == 3
        assert sweep_rec.tp_rate is None  # no triage → no verdict
        assert entry.tp_rate == pytest.approx(0.9)  # precision untouched

    def test_no_record_leaves_library_untouched(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        before = (lib_dir / "manifest.json").read_text()
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(3, rule_id="sg"),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=False)
        assert report.recorded_updates == 0
        assert (lib_dir / "manifest.json").read_text() == before

    def test_zero_matches_not_recorded(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        before = (lib_dir / "manifest.json").read_text()
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(0, rule_id="sg"),
        )
        rs.run_sweep([target], library_dir=lib_dir, record=True)
        assert (lib_dir / "manifest.json").read_text() == before


class TestCap:
    def test_match_cap_applied_and_counted(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("loose")])
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(rs.MATCH_CAP + 50,
                                            rule_id="loose"),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=False)
        assert len(report.matches) == rs.MATCH_CAP
        assert report.capped == {f"loose@{target}": 50}


class TestOutput:
    def test_jsonl_shape(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(2, rule_id="sg"),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=False)
        out = tmp_path / "out"
        matches_path = rs.write_report(report, out)
        lines = [
            json.loads(line)
            for line in matches_path.read_text().splitlines()
        ]
        assert len(lines) == 2
        for rec in lines:
            assert set(rec) == {
                "rule_id", "engine", "cwe", "target", "file", "line",
                "message", "provenance", "tier", "tp_rate",
                "targets_tested",
            }
        summary = json.loads((out / "summary.json").read_text())
        assert summary["total_matches"] == 2
        assert summary["rules_semgrep"] == 1

    def test_runner_errors_survive_into_report(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: SemgrepResult(
                name="sg", errors=["sandbox unavailable"], returncode=-1,
            ),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=False)
        assert report.matches == []
        assert report.errors == ["semgrep sg @ %s: sandbox unavailable"
                                 % target]


class TestCli:
    def test_missing_target_exits_2(self, tmp_path, capsys):
        rc = rs.main([str(tmp_path / "nope")])
        assert rc == 2
        assert "do not exist" in capsys.readouterr().err

    def test_empty_library_happy_path(self, tmp_path, capsys):
        target = tmp_path / "t"
        target.mkdir()
        out = tmp_path / "out"
        rc = rs.main([
            str(target),
            "--library-dir", str(tmp_path / "no-library"),
            "--out", str(out),
            "--no-record",
        ])
        assert rc == 0
        assert (out / "matches.jsonl").exists()
        assert (out / "summary.json").exists()
        assert "0 match(es)" in capsys.readouterr().out
