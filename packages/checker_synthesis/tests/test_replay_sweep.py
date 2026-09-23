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
    rule_tier: str | None = None,
) -> dict:
    ext = ".yml" if engine == "semgrep" else ".cocci"
    d = {
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
    if rule_tier is not None:
        d["rule_tier"] = rule_tier
    return d


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
            # dual passed, fix-mutant failed: never proved it
            # distinguishes fixed from unfixed code — not replayable.
            _manifest_entry("dual-no-mutant", rule_tier="sweep_once"),
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


class TestTargetHashConvention:
    def test_public_spelling_resolves_and_joins(self, tmp_path):
        # Relative / symlinked spellings of one physical target must
        # produce ONE TargetRecord identity — the public spelling for
        # out-of-package recorders joins the private convention.
        real = tmp_path / "repo"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        assert rs.target_hash_for(link) == rs._target_hash(real)

    def test_followup_recorder_uses_the_convention(self):
        # The per-run replay recorder hashed str(repo_root) as passed
        # (no resolve), minting a second TargetRecord for the same
        # target off a non-canonical spelling. Pin that the module
        # routes target hashing through target_hash_for and carries
        # no inline hashing of its own.
        import inspect

        import packages.llm_analysis.checker_followup as cf
        src = inspect.getsource(cf)
        assert "target_hash_for" in src
        assert "hashlib" not in src


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
        # A rule that is both a replayable library entry and a
        # graduated file runs ONCE (in the library loop) — sweeping
        # the graduated copy too duplicated every match and, with
        # record=True, double-counted total_matches.
        provs = sorted(m.provenance for m in report.matches)
        assert provs == ["rule-library"]

    def test_graduated_only_rule_still_swept(self, tmp_path, monkeypatch):
        # A graduated file with no replayable library twin must still
        # join the sweep (dedup must not drop it).
        lib_dir = _write_library(tmp_path, [])
        engine_rules = tmp_path / "engine-rules"
        (engine_rules / "semgrep" / "rules").mkdir(parents=True)
        (engine_rules / "semgrep" / "rules" / "solo.yaml").write_text(
            "rules: []\n",
        )
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(1, rule_id="solo"),
        )
        report = rs.run_sweep(
            [target], library_dir=lib_dir,
            engine_rules_dir=engine_rules, record=False,
        )
        assert [m.provenance for m in report.matches] == ["graduated"]

    def test_graduated_cocci_rules_join_sweep(self, tmp_path, monkeypatch):
        # graduate() writes coccinelle rules to coccinelle/*.cocci —
        # the sweep must pick those up, not just semgrep/rules.
        lib_dir = _write_library(tmp_path, [])
        engine_rules = tmp_path / "engine-rules"
        (engine_rules / "coccinelle").mkdir(parents=True)
        (engine_rules / "coccinelle" / "gradc.cocci").write_text(
            "@@\n@@\n- x\n",
        )
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text("int main(void){return 0;}\n")

        class _CocciResult:
            errors: list = []
            matches = [
                type("M", (), {"file": "a.c", "line": 1, "message": "hit"})(),
            ]

        monkeypatch.setattr(
            rs.cocci_runner, "run_rule", lambda *a, **k: _CocciResult(),
        )
        report = rs.run_sweep(
            [target], library_dir=lib_dir,
            engine_rules_dir=engine_rules, record=False,
        )
        assert report.rules_graduated == 1
        assert [
            (m.rule_id, m.engine, m.provenance) for m in report.matches
        ] == [("gradc", "coccinelle", "graduated")]


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

    def test_zero_matches_recorded_as_coverage(self, tmp_path, monkeypatch):
        # A target where the rule fired nowhere is negative evidence:
        # the TargetRecord must accrue (matches=0, no verdict) so
        # stale rules can eventually be auto-archived and per-target
        # confidence counts misses, not just hits.
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(0, rule_id="sg"),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=True)
        assert report.recorded_updates == 1
        entry = RuleLibrary(lib_dir).all_entries()[0]
        assert len(entry.targets) == 2  # original + zero-match sweep target
        sweep_rec = entry.targets[-1]
        assert sweep_rec.matches == 0
        assert sweep_rec.tp_rate is None  # no triage → no verdict
        assert entry.tp_rate == pytest.approx(0.9)  # precision untouched

    def test_engine_errored_run_records_no_coverage(
        self, tmp_path, monkeypatch,
    ):
        # A target the engine could NOT scan proves nothing: it must
        # not become a zero-match TargetRecord (negative coverage
        # evidence that inflates targets_tested and feeds
        # auto-archive). The failure surfaces on report.errors only.
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        before = (lib_dir / "manifest.json").read_text()
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: SemgrepResult(
                name="sg", errors=["sandbox unavailable"], returncode=-1,
            ),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=True)
        assert report.recorded_updates == 0
        assert report.matches == []
        assert len(report.errors) == 1
        entry = RuleLibrary(lib_dir).all_entries()[0]
        assert len(entry.targets) == 1  # original only — no sweep record
        assert (lib_dir / "manifest.json").read_text() == before

    def test_errored_run_keeps_matches_but_records_no_coverage(
        self, tmp_path, monkeypatch,
    ):
        # One fatal per-file failure on a large target must not
        # discard every match the rule DID produce: the matches stay
        # in the report (flagged partial), only the coverage
        # recording is skipped — an errored run is not evidence.
        lib_dir = _write_library(tmp_path, [_manifest_entry("sg")])
        before = (lib_dir / "manifest.json").read_text()
        target = tmp_path / "t"
        target.mkdir()
        partial = _semgrep_result(2, rule_id="sg")
        partial.errors = ["fatal: src/broken.c parse failure"]
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule", lambda *a, **k: partial,
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=True)
        assert len(report.matches) == 2
        assert report.partial == [f"sg@{target}"]
        assert len(report.errors) == 1
        # No coverage: no recorded update, manifest untouched.
        assert report.recorded_updates == 0
        assert (lib_dir / "manifest.json").read_text() == before

    def test_cocci_errored_run_records_no_coverage(
        self, tmp_path, monkeypatch,
    ):
        lib_dir = _write_library(
            tmp_path, [_manifest_entry("cc", engine="coccinelle")],
        )
        target = tmp_path / "t"
        target.mkdir()
        (target / "a.c").write_text("int main(void){return 0;}\n")
        monkeypatch.setattr(
            rs.cocci_runner, "run_rule",
            lambda *a, **k: SpatchResult(
                rule="cc", errors=["spatch crashed"], returncode=2,
            ),
        )
        report = rs.run_sweep([target], library_dir=lib_dir, record=True)
        assert report.recorded_updates == 0
        assert report.matches == []
        assert len(report.errors) == 1
        entry = RuleLibrary(lib_dir).all_entries()[0]
        assert len(entry.targets) == 1

    def test_errored_rule_does_not_feed_auto_archive(
        self, tmp_path, monkeypatch,
    ):
        # Counterpart to test_zero_match_sweeps_can_auto_archive:
        # three ERRORED runs (vs three genuine zero-match runs) must
        # NOT retire the rule — failed scans are not evidence the
        # rule never fires.
        lib_dir = _write_library(
            tmp_path, [_manifest_entry("dud", n_targets=1)],
        )
        manifest = json.loads((lib_dir / "manifest.json").read_text())
        manifest["rules"][0]["total_variants"] = 0
        (lib_dir / "manifest.json").write_text(json.dumps(manifest))
        targets = []
        for i in range(3):
            t = tmp_path / f"t{i}"
            t.mkdir()
            targets.append(t)
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: SemgrepResult(
                name="dud", errors=["engine failure"], returncode=-1,
            ),
        )
        rs.run_sweep(targets, library_dir=lib_dir, record=True)
        entry = RuleLibrary(lib_dir).all_entries()[0]
        assert entry.archived is False

    def test_zero_match_sweeps_can_auto_archive(self, tmp_path, monkeypatch):
        # Enough zero-match targets push a never-firing rule over the
        # prune threshold — sweep evidence alone can retire it.
        lib_dir = _write_library(
            tmp_path, [_manifest_entry("dud", n_targets=1)],
        )
        # Strip prior variant evidence so the rule counts as never
        # having fired.
        manifest = json.loads((lib_dir / "manifest.json").read_text())
        manifest["rules"][0]["total_variants"] = 0
        (lib_dir / "manifest.json").write_text(json.dumps(manifest))
        targets = []
        for i in range(3):
            t = tmp_path / f"t{i}"
            t.mkdir()
            targets.append(t)
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(0, rule_id="dud"),
        )
        rs.run_sweep(targets, library_dir=lib_dir, record=True)
        entry = RuleLibrary(lib_dir).all_entries()[0]
        assert entry.archived is True


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


class TestGraduatedStemJoin:
    """Graduated file stems are SANITISED rule ids — the sweep's joins
    back to the library must compare through graduated_stem, or an
    unsafe original id double-sweeps and never accrues coverage."""

    def test_unsafe_id_graduated_twin_runs_once(self, tmp_path, monkeypatch):
        lib_dir = _write_library(tmp_path, [_manifest_entry("weird id")])
        engine_rules = tmp_path / "engine-rules"
        (engine_rules / "semgrep" / "rules").mkdir(parents=True)
        # graduate() names the file with the sanitised stem.
        from packages.checker_synthesis.library import graduated_stem
        stem = graduated_stem("weird id")
        assert stem != "weird id"
        (engine_rules / "semgrep" / "rules" / f"{stem}.yaml").write_text(
            "rules: []\n",
        )
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(1, rule_id="weird id"),
        )
        report = rs.run_sweep(
            [target], library_dir=lib_dir,
            engine_rules_dir=engine_rules, record=False,
        )
        assert sorted(m.provenance for m in report.matches) == [
            "rule-library",
        ]

    def test_unsafe_id_graduated_only_rule_records_coverage(
        self, tmp_path, monkeypatch,
    ):
        # Non-replayable entry (sweep_once tier): only its graduated
        # copy runs — coverage must still land on the library entry.
        lib_dir = _write_library(
            tmp_path,
            [_manifest_entry("weird id", dual_control=False,
                             rule_tier="sweep_once")],
        )
        engine_rules = tmp_path / "engine-rules"
        (engine_rules / "semgrep" / "rules").mkdir(parents=True)
        from packages.checker_synthesis.library import graduated_stem
        stem = graduated_stem("weird id")
        (engine_rules / "semgrep" / "rules" / f"{stem}.yaml").write_text(
            "rules: []\n",
        )
        target = tmp_path / "t"
        target.mkdir()
        monkeypatch.setattr(
            rs.semgrep_runner, "run_rule",
            lambda *a, **k: _semgrep_result(2, rule_id=stem),
        )
        report = rs.run_sweep(
            [target], library_dir=lib_dir,
            engine_rules_dir=engine_rules, record=True,
        )
        assert report.recorded_updates == 1
        entry = RuleLibrary(lib_dir).all_entries()[0]
        assert any(t.matches == 2 for t in entry.targets)


class TestGraduatedSkipAccounting:
    def test_graduated_only_non_c_target_records_skip(
        self, tmp_path, monkeypatch,
    ):
        """A graduated-only sweep on a non-C target skips its cocci
        rules the same way library entries do — the skip must land in
        cocci_skipped_targets, not vanish from the accounting."""
        lib_dir = _write_library(tmp_path, [])
        engine_rules = tmp_path / "engine-rules"
        (engine_rules / "coccinelle").mkdir(parents=True)
        (engine_rules / "coccinelle" / "gradc.cocci").write_text(
            "@@\n@@\n- x\n",
        )
        target = tmp_path / "pyproj"
        target.mkdir()
        (target / "app.py").write_text("x = 1\n")
        called = []
        monkeypatch.setattr(
            rs.cocci_runner, "run_rule",
            lambda *a, **k: called.append(a) or _spatch_result(0),
        )
        report = rs.run_sweep(
            [target], library_dir=lib_dir,
            engine_rules_dir=engine_rules, record=False,
        )
        assert not called
        assert report.cocci_skipped_targets == [str(target)]
