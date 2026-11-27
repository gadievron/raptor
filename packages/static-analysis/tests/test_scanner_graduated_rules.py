"""Tests for the graduated synthesized-rules /scan stage (P7).

Same hyphenated-package importlib pattern as the other scanner tests.
The semgrep runner is faked throughout — no semgrep binary required.
"""

from __future__ import annotations

import importlib.util
import json

import pytest
import sys
from dataclasses import dataclass
from pathlib import Path

# parents[3]: tests/ → static-analysis/ → packages/ → repo root
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if __name__ == "__main__":
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)

_SCANNER_PATH = Path(_REPO_ROOT) / "packages/static-analysis/scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_graduated", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scanner)


@dataclass
class FakeFinding:
    line: int
    rule_id: str = "no-strcpy"
    message: str = "strcpy is dangerous"
    file: str = "src/a.c"
    level: str = "warning"

    def to_dict(self):
        return {
            "file": self.file, "line": self.line, "rule_id": self.rule_id,
            "message": self.message, "level": self.level,
        }


class FakeSemgrepResult:
    def __init__(self, findings=(), errors=()):
        self.findings = list(findings)
        self.errors = list(errors)


def _mk_rules_dir(base: Path, *stems: str) -> Path:
    rules_dir = base / "engine-rules" / "semgrep" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        (rules_dir / f"{stem}.yaml").write_text(
            f"rules:\n  - id: {stem}-inner\n    pattern: strcpy(...)\n"
            f"    message: x\n    languages: [c]\n    severity: WARNING\n",
            encoding="utf-8",
        )
    return rules_dir


def _fake_runner(monkeypatch, results):
    """results: dict config-path-stem → FakeSemgrepResult or Exception.

    Configs with no entry raise, so a batched (directory-config)
    invocation falls back to the per-rule loop unless the test
    provides an entry keyed on the rules dir's own stem ("rules" for
    ``_mk_rules_dir`` layouts).
    """
    calls = []

    def run_rule(target, config, *, name="", timeout=0, env=None, **kw):
        stem = Path(config).stem
        calls.append({"config": config, "name": name, "timeout": timeout,
                      "env": env})
        res = results.get(stem)
        if res is None:
            raise RuntimeError(f"no fake semgrep result for {stem!r}")
        if isinstance(res, Exception):
            raise res
        return res

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run_rule)
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)
    return calls


class TestFindEngineRulesDir:
    def test_resolves_run_dir_sibling(self, tmp_path):
        project = tmp_path / "project"
        run_dir = project / "run_001"
        run_dir.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, "rule-a")
        repo = tmp_path / "repo"
        repo.mkdir()
        assert _scanner.find_engine_rules_dir(run_dir, repo) == rules_dir

    def test_resolves_agentic_scan_subdir(self, tmp_path):
        project = tmp_path / "project"
        scan_out = project / "run_001" / "scan"
        scan_out.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, "rule-a")
        repo = tmp_path / "repo"
        repo.mkdir()
        assert _scanner.find_engine_rules_dir(scan_out, repo) == rules_dir

    def test_none_when_no_rules(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        repo = tmp_path / "repo"
        repo.mkdir()
        assert _scanner.find_engine_rules_dir(run_dir, repo) is None

    def test_refuses_rules_inside_repo(self, tmp_path):
        # A hostile target shipping engine-rules must never load as
        # scanner config.
        repo = tmp_path / "repo"
        run_dir = repo / "out"
        run_dir.mkdir(parents=True)
        _mk_rules_dir(repo, "evil-rule")
        assert _scanner.find_engine_rules_dir(run_dir, repo) is None

    def test_refusal_emits_security_event(self, tmp_path, monkeypatch):
        # The refusal is the scanner's suspicious-input rejection path;
        # it must land on the security-event stream (observability
        # only — the refusal itself is asserted above).
        events = []
        monkeypatch.setattr(
            _scanner.logger, "log_security_event",
            lambda event_type, message, **kw: events.append(
                (event_type, message, kw),
            ),
        )
        repo = tmp_path / "repo"
        run_dir = repo / "out"
        run_dir.mkdir(parents=True)
        _mk_rules_dir(repo, "evil-rule")
        assert _scanner.find_engine_rules_dir(run_dir, repo) is None
        assert len(events) == 1
        event_type, _message, kw = events[0]
        assert event_type == "untrusted_rules_dir_rejected"
        assert kw["repo"] == str(repo.resolve())
        assert str(repo.resolve()) in kw["rules_dir"]

    def test_legitimate_rules_dir_emits_no_security_event(
        self, tmp_path, monkeypatch,
    ):
        events = []
        monkeypatch.setattr(
            _scanner.logger, "log_security_event",
            lambda event_type, message, **kw: events.append(event_type),
        )
        project = tmp_path / "project"
        run_dir = project / "run_001"
        run_dir.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, "rule-a")
        repo = tmp_path / "repo"
        repo.mkdir()
        assert _scanner.find_engine_rules_dir(run_dir, repo) == rules_dir
        assert events == []

    def test_refusal_survives_broken_logging_sink(self, tmp_path, monkeypatch):
        # No-raise-on-sink-failure: the guarded emitter must not turn
        # the refusal into a crash (the security event is a stream,
        # not a control). Only the security-event write fails so the
        # pre-existing refusal warning is unaffected.
        def _flaky_warning(message, *args, **kwargs):
            if str(message).startswith("SECURITY:"):
                raise OSError("sink down")

        monkeypatch.setattr(_scanner.logger, "warning", _flaky_warning)
        repo = tmp_path / "repo"
        run_dir = repo / "out"
        run_dir.mkdir(parents=True)
        _mk_rules_dir(repo, "evil-rule")
        assert _scanner.find_engine_rules_dir(run_dir, repo) is None


class TestRunGraduatedRulesStage:
    def test_emits_sarif_with_provenance(self, tmp_path, monkeypatch):
        project = tmp_path / "project"
        out_dir = project / "run_001"
        out_dir.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, "uaf-variant-3")
        repo = tmp_path / "repo"
        repo.mkdir()
        _fake_runner(monkeypatch, {
            "uaf-variant-3": FakeSemgrepResult(
                findings=[FakeFinding(line=12, rule_id="uaf-inner")],
            ),
        })

        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert len(sarifs) == 1
        doc = json.loads(Path(sarifs[0]).read_text())
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "raptor-graduated"
        result = run["results"][0]
        assert result["ruleId"] == "synthesized:uaf-variant-3"
        assert result["properties"]["provenance"] == "synthesized:uaf-variant-3"
        assert result["properties"]["semgrep_rule_id"] == "uaf-inner"
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/a.c"
        assert loc["region"]["startLine"] == 12

    def test_one_failing_rule_does_not_kill_stage(
        self, tmp_path, monkeypatch, capsys,
    ):
        project = tmp_path / "project"
        out_dir = project / "run_001"
        out_dir.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, "bad-rule", "good-rule")
        repo = tmp_path / "repo"
        repo.mkdir()
        _fake_runner(monkeypatch, {
            "bad-rule": RuntimeError("boom"),
            "good-rule": FakeSemgrepResult(findings=[FakeFinding(line=3)]),
        })

        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert len(sarifs) == 1
        doc = json.loads(Path(sarifs[0]).read_text())
        assert len(doc["runs"][0]["results"]) == 1
        assert "failed to run" in capsys.readouterr().err

    def test_all_rules_failed_retains_diagnostic_sarif(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Persist failed invocations so zero findings cannot imply success."""
        project = tmp_path / "project"
        out_dir = project / "run_001"
        out_dir.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, "rule-a", "rule-b")
        repo = tmp_path / "repo"
        repo.mkdir()
        _fake_runner(monkeypatch, {
            "rule-a": RuntimeError("boom"),
            "rule-b": RuntimeError("boom"),
        })

        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert sarifs == [str(out_dir / "graduated.sarif")]
        run = json.loads(Path(sarifs[0]).read_text())["runs"][0]
        assert run["results"] == []
        assert len(run["invocations"]) == 2
        assert all(inv["executionSuccessful"] is False for inv in run["invocations"])
        assert "FAILED" in capsys.readouterr().err

    def test_no_rules_dir_silently_skips(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "project" / "run_001"
        out_dir.mkdir(parents=True)
        repo = tmp_path / "repo"
        repo.mkdir()
        calls = _fake_runner(monkeypatch, {})
        assert _scanner.run_graduated_rules_stage(repo, out_dir) == []
        assert calls == []

    def test_explicit_dir_inside_repo_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        repo = tmp_path / "repo"
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        rules_dir = _mk_rules_dir(repo, "evil")
        calls = _fake_runner(monkeypatch, {})
        assert _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        ) == []
        assert calls == []
        assert "refusing rules dir" in capsys.readouterr().err

    def test_semgrep_unavailable_reports_loudly(
        self, tmp_path, monkeypatch, capsys,
    ):
        project = tmp_path / "project"
        out_dir = project / "run_001"
        out_dir.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, "rule-a")
        repo = tmp_path / "repo"
        repo.mkdir()
        monkeypatch.setattr(
            "packages.semgrep.runner.is_available", lambda: False,
        )
        paths = _scanner.run_graduated_rules_stage(repo, out_dir, rules_dir=rules_dir)
        assert paths == [str(out_dir / "graduated.sarif")]
        assert json.loads(Path(paths[0]).read_text())["runs"][0]["invocations"][0]["executionSuccessful"] is False
        assert "semgrep not installed" in capsys.readouterr().err


class TestGraduatedBatchPath:
    """The stage runs the whole graduated set as ONE Semgrep
    invocation when batched findings can be attributed to exactly the
    same per-rule provenance the serial loop produces, and falls back
    to the per-rule loop otherwise. Semgrep emits check ids of the
    form ``<dotted config path>.<in-file id>`` in BOTH modes (the rule
    file stem never appears), so attribution goes through the in-file
    ids."""

    def _setup(self, tmp_path, *stems):
        pytest.importorskip("yaml")
        project = tmp_path / "project"
        out_dir = project / "run_001"
        out_dir.mkdir(parents=True)
        rules_dir = _mk_rules_dir(project, *stems)
        repo = tmp_path / "repo"
        repo.mkdir()
        return out_dir, rules_dir, repo

    def test_batched_single_invocation_with_provenance(
        self, tmp_path, monkeypatch,
    ):
        out_dir, rules_dir, repo = self._setup(tmp_path, "uaf-variant-3")
        calls = _fake_runner(monkeypatch, {
            "rules": FakeSemgrepResult(findings=[FakeFinding(
                line=12, rule_id="semgrep.rules.uaf-variant-3-inner",
            )]),
        })
        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert [c["config"] for c in calls] == [str(rules_dir)]
        doc = json.loads(Path(sarifs[0]).read_text())
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "raptor-graduated"
        result = run["results"][0]
        assert result["ruleId"] == "synthesized:uaf-variant-3"
        assert result["properties"]["provenance"] == "synthesized:uaf-variant-3"
        assert result["properties"]["semgrep_rule_id"] == (
            "semgrep.rules.uaf-variant-3-inner"
        )

    def test_batched_output_equals_serial_output(self, tmp_path, monkeypatch):
        """The equivalence bar: identical findings served through the
        batched dir config and through the per-rule loop must produce
        an identical SARIF document (check ids are identical in both
        Semgrep modes)."""
        pytest.importorskip("yaml")
        per_rule = {
            "rule-a": [FakeFinding(
                line=3, rule_id="x.rule-a-inner", file="src/a.c",
            )],
            "rule-b": [
                FakeFinding(line=9, rule_id="x.rule-b-inner", file="src/b.c"),
                FakeFinding(line=11, rule_id="x.rule-b-inner", file="src/b.c"),
            ],
        }
        # Interleaved batch order — grouping must restore the serial
        # rule-file order.
        batched = [
            per_rule["rule-b"][0], per_rule["rule-a"][0], per_rule["rule-b"][1],
        ]
        docs = {}
        for mode in ("batched", "serial"):
            project = tmp_path / mode
            out_dir = project / "run"
            out_dir.mkdir(parents=True)
            rules_dir = _mk_rules_dir(project, "rule-a", "rule-b")
            repo = tmp_path / f"repo-{mode}"
            repo.mkdir()
            fakes = (
                {"rules": FakeSemgrepResult(findings=batched)}
                if mode == "batched" else
                {stem: FakeSemgrepResult(findings=f)
                 for stem, f in per_rule.items()}
            )
            calls = _fake_runner(monkeypatch, fakes)
            paths = _scanner.run_graduated_rules_stage(
                repo, out_dir, rules_dir=rules_dir,
            )
            # Serial mode = the dir-config batch attempt (raises in
            # this fake) followed by the historical per-rule calls.
            expected = (["rules"] if mode == "batched"
                        else ["rules", "rule-a", "rule-b"])
            assert [Path(c["config"]).stem for c in calls] == expected
            docs[mode] = json.loads(Path(paths[0]).read_text())
        assert docs["batched"] == docs["serial"]

    def test_batch_falls_back_when_inner_ids_ambiguous(
        self, tmp_path, monkeypatch,
    ):
        """One in-file id is a dot-suffix of another: a batched check
        id could then match two rules, so the stage must run per-rule
        rather than risk mis-keyed provenance."""
        out_dir, rules_dir, repo = self._setup(tmp_path, "alpha")
        (rules_dir / "beta.yaml").write_text(
            "rules:\n  - id: evil.alpha-inner\n    pattern: strcpy(...)\n"
            "    message: x\n    languages: [c]\n    severity: WARNING\n",
            encoding="utf-8",
        )
        calls = _fake_runner(monkeypatch, {
            "alpha": FakeSemgrepResult(), "beta": FakeSemgrepResult(),
        })
        _scanner.run_graduated_rules_stage(repo, out_dir, rules_dir=rules_dir)
        assert [Path(c["config"]).stem for c in calls] == ["alpha", "beta"]

    def test_batch_falls_back_on_unmappable_finding(
        self, tmp_path, monkeypatch,
    ):
        """A batched finding whose check id matches no graduated rule
        means attribution failed — rerun per-rule, whose provenance is
        structural."""
        out_dir, rules_dir, repo = self._setup(tmp_path, "only-rule")
        calls = _fake_runner(monkeypatch, {
            "rules": FakeSemgrepResult(findings=[FakeFinding(
                line=1, rule_id="something.unrelated",
            )]),
            "only-rule": FakeSemgrepResult(findings=[FakeFinding(
                line=5, rule_id="x.only-rule-inner",
            )]),
        })
        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert [Path(c["config"]).stem for c in calls] == ["rules", "only-rule"]
        results = json.loads(Path(sarifs[0]).read_text())["runs"][0]["results"]
        assert [r["ruleId"] for r in results] == ["synthesized:only-rule"]

    @pytest.mark.parametrize("extra", ["subdir", "yml"])
    def test_batch_falls_back_when_dir_has_extra_config(
        self, tmp_path, monkeypatch, extra,
    ):
        """A subdirectory or *.yml file would load under a dir config
        but is never part of the serial *.yaml enumeration — the batch
        would scan MORE than serial, so it must not run."""
        out_dir, rules_dir, repo = self._setup(tmp_path, "only-rule")
        if extra == "subdir":
            (rules_dir / "nested").mkdir()
        else:
            (rules_dir / "stray.yml").write_text("rules: []\n")
        calls = _fake_runner(monkeypatch, {
            "only-rule": FakeSemgrepResult(),
        })
        _scanner.run_graduated_rules_stage(repo, out_dir, rules_dir=rules_dir)
        assert [Path(c["config"]).stem for c in calls] == ["only-rule"]

    @pytest.mark.parametrize("damage", [
        {"errors": ["rule failed to compile"]},
        {"returncode": 2},
        {"skipped_rules": ["incompatible"]},
    ])
    def test_batch_result_damage_falls_back_to_serial(
        self, tmp_path, monkeypatch, damage,
    ):
        """Errors, a bad exit, or rule-side skips in the batch cannot
        be attributed to a specific graduated rule — the per-rule loop
        (which isolates the offender) must run instead."""
        from packages.semgrep.models import SemgrepResult

        out_dir, rules_dir, repo = self._setup(tmp_path, "only-rule")
        calls = _fake_runner(monkeypatch, {
            "rules": SemgrepResult(**damage),
            "only-rule": FakeSemgrepResult(findings=[FakeFinding(
                line=5, rule_id="x.only-rule-inner",
            )]),
        })
        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert [Path(c["config"]).stem for c in calls] == ["rules", "only-rule"]
        results = json.loads(Path(sarifs[0]).read_text())["runs"][0]["results"]
        assert [r["ruleId"] for r in results] == ["synthesized:only-rule"]

    @pytest.mark.parametrize("damage", [
        {"errors": ["rule failed to compile"]},
        {"returncode": 2},
        {"skipped_rules": ["incompatible"]},
    ])
    def test_batch_non_timeout_damage_never_bisects(
        self, tmp_path, monkeypatch, damage,
    ):
        """A non-timeout refusal is an attribution problem a smaller
        batch would reproduce — the whole set goes straight to the
        per-rule loop, with no bisection slices attempted."""
        from packages.semgrep.models import SemgrepResult

        out_dir, rules_dir, repo = self._setup(
            tmp_path, "rule-a", "rule-b", "rule-c", "rule-d",
        )
        calls = _fake_runner(monkeypatch, {
            "rules": SemgrepResult(**damage),
            "rule-a": FakeSemgrepResult(),
            "rule-b": FakeSemgrepResult(),
            "rule-c": FakeSemgrepResult(),
            "rule-d": FakeSemgrepResult(),
        })
        _scanner.run_graduated_rules_stage(repo, out_dir, rules_dir=rules_dir)
        assert [Path(c["config"]).stem for c in calls] == [
            "rules", "rule-a", "rule-b", "rule-c", "rule-d",
        ]

    def _timeout_result(self):
        from packages.semgrep.models import SemgrepResult

        return SemgrepResult(
            errors=["Timeout after 600s"], returncode=-1, timed_out=True,
        )

    def test_batch_timeout_bisects_and_isolates_slow_half(
        self, tmp_path, monkeypatch,
    ):
        """A whole-set timeout halves the batch: the clean half lands
        its findings batched (never serialized), the timing-out half
        recurses to singletons which run through the per-rule loop."""
        out_dir, rules_dir, repo = self._setup(
            tmp_path, "rule-a", "rule-b", "rule-c", "rule-d",
        )
        calls = _fake_runner(monkeypatch, {
            "rules": self._timeout_result(),
            "graduated-slice-0-2": FakeSemgrepResult(findings=[
                FakeFinding(line=3, rule_id="x.rule-a-inner", file="src/a.c"),
                FakeFinding(line=9, rule_id="x.rule-b-inner", file="src/b.c"),
            ]),
            "graduated-slice-2-4": self._timeout_result(),
            "rule-c": FakeSemgrepResult(findings=[FakeFinding(
                line=5, rule_id="x.rule-c-inner", file="src/c.c",
            )]),
            "rule-d": FakeSemgrepResult(),
        })
        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        # The clean half never runs serially; the slow half's
        # singletons go straight to the per-rule loop.
        assert [Path(c["config"]).stem for c in calls] == [
            "rules", "graduated-slice-0-2", "graduated-slice-2-4",
            "rule-c", "rule-d",
        ]
        # Timeout/env parity: every leg runs under the same per-attempt
        # budget and sanitized environment as the whole-set batch.
        assert len({c["timeout"] for c in calls}) == 1
        assert all(c["env"] is not None for c in calls)
        results = json.loads(Path(sarifs[0]).read_text())["runs"][0]["results"]
        assert [r["ruleId"] for r in results] == [
            "synthesized:rule-a", "synthesized:rule-b", "synthesized:rule-c",
        ]

    def test_bisected_findings_never_carry_the_scratch_config_path(
        self, tmp_path, monkeypatch,
    ):
        """A bisect slice runs from a private mkdtemp copy of its rule
        files, so Semgrep prefixes slice check ids with the dotted
        scratch path — a random per-run name. The emitted SARIF must
        rewrite those onto the original rules dir: a scratch prefix
        would leak the scratch layout and make the forensics property
        nondeterministic run-to-run."""
        import os

        out_dir, rules_dir, repo = self._setup(
            tmp_path, "rule-a", "rule-b", "rule-c", "rule-d",
        )
        scratch_id = (
            "tmp.raptor-graduated-bisect-k3xq9z.graduated-slice-0-2"
            ".rule-a-inner"
        )
        _fake_runner(monkeypatch, {
            "rules": self._timeout_result(),
            "graduated-slice-0-2": FakeSemgrepResult(findings=[
                FakeFinding(line=3, rule_id=scratch_id, file="src/a.c"),
                # Bare in-file id (no config prefix) rewrites too — the
                # bisect leg emits ONE canonical shape.
                FakeFinding(line=9, rule_id="rule-b-inner", file="src/b.c"),
            ]),
            "graduated-slice-2-4": self._timeout_result(),
            "rule-c": FakeSemgrepResult(findings=[FakeFinding(
                line=5, rule_id="x.rule-c-inner", file="src/c.c",
            )]),
            "rule-d": FakeSemgrepResult(),
        })
        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        text = Path(sarifs[0]).read_text()
        assert "graduated-bisect" not in text
        assert "graduated-slice" not in text
        results = json.loads(text)["runs"][0]["results"]
        dotted = str(rules_dir).replace(os.sep, ".").lstrip(".")
        assert [r["properties"]["semgrep_rule_id"] for r in results] == [
            f"{dotted}.rule-a-inner",
            f"{dotted}.rule-b-inner",
            # The per-rule loop keeps Semgrep's own id untouched.
            "x.rule-c-inner",
        ]
        assert [r["ruleId"] for r in results] == [
            "synthesized:rule-a", "synthesized:rule-b", "synthesized:rule-c",
        ]

    def test_batch_timeout_everywhere_stops_bisecting(
        self, tmp_path, monkeypatch,
    ):
        """When BOTH halves of a split time out the slowness is
        target-wide, not one bad rule — further splits would pay a full
        timeout each before reaching the serial loop, so the slices go
        serial directly."""
        out_dir, rules_dir, repo = self._setup(
            tmp_path, "rule-a", "rule-b", "rule-c", "rule-d",
        )
        serial = {stem: FakeSemgrepResult()
                  for stem in ("rule-a", "rule-b", "rule-c", "rule-d")}
        calls = _fake_runner(monkeypatch, {
            "rules": self._timeout_result(),
            "graduated-slice-0-2": self._timeout_result(),
            "graduated-slice-2-4": self._timeout_result(),
            **serial,
        })
        _scanner.run_graduated_rules_stage(repo, out_dir, rules_dir=rules_dir)
        assert [Path(c["config"]).stem for c in calls] == [
            "rules", "graduated-slice-0-2", "graduated-slice-2-4",
            "rule-a", "rule-b", "rule-c", "rule-d",
        ]

    def test_bisect_half_refusal_goes_direct_serial(
        self, tmp_path, monkeypatch,
    ):
        """A NON-timeout refusal inside a half during bisection routes
        that half to the per-rule loop without further splitting."""
        from packages.semgrep.models import SemgrepResult

        out_dir, rules_dir, repo = self._setup(
            tmp_path, "rule-a", "rule-b", "rule-c", "rule-d",
        )
        calls = _fake_runner(monkeypatch, {
            "rules": self._timeout_result(),
            "graduated-slice-0-2": SemgrepResult(
                errors=["rule failed to compile"],
            ),
            "graduated-slice-2-4": FakeSemgrepResult(findings=[FakeFinding(
                line=7, rule_id="x.rule-d-inner", file="src/d.c",
            )]),
            "rule-a": FakeSemgrepResult(),
            "rule-b": FakeSemgrepResult(),
        })
        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert [Path(c["config"]).stem for c in calls] == [
            "rules", "graduated-slice-0-2", "graduated-slice-2-4",
            "rule-a", "rule-b",
        ]
        results = json.loads(Path(sarifs[0]).read_text())["runs"][0]["results"]
        assert [r["ruleId"] for r in results] == ["synthesized:rule-d"]

    def test_single_rule_timeout_goes_straight_serial(
        self, tmp_path, monkeypatch,
    ):
        """A one-rule set has nothing to bisect — the serial loop IS
        the retry."""
        out_dir, rules_dir, repo = self._setup(tmp_path, "only-rule")
        calls = _fake_runner(monkeypatch, {
            "rules": self._timeout_result(),
            "only-rule": FakeSemgrepResult(findings=[FakeFinding(
                line=5, rule_id="x.only-rule-inner",
            )]),
        })
        sarifs = _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        )
        assert [Path(c["config"]).stem for c in calls] == ["rules", "only-rule"]
        results = json.loads(Path(sarifs[0]).read_text())["runs"][0]["results"]
        assert [r["ruleId"] for r in results] == ["synthesized:only-rule"]


# ---------------------------------------------------------------------
# CLI flag surface — default-on, opt-out
# ---------------------------------------------------------------------


def test_scanner_flag_default_on_opt_out():
    src = _SCANNER_PATH.read_text(encoding="utf-8")
    assert '"--no-graduated-rules"' in src
    # The opt-out is internalised in the stage lane: the lane runs by
    # default and returns [] when the flag is set.
    assert "if args.no_graduated_rules:" in src
    assert "graduated_sarifs" in src


def test_agentic_forwards_opt_out():
    src = (Path(_REPO_ROOT) / "raptor_agentic.py").read_text(encoding="utf-8")
    assert '"--no-graduated-rules"' in src
    assert 'semgrep_cmd.append("--no-graduated-rules")' in src


@pytest.mark.parametrize('damage', [
    {'errors': ['another file failed']},
    {'files_failed': [{'path': 'other.c', 'reason': 'parse error'}]},
    {'skipped_rules': ['incompatible']},
    {'returncode': 2},
])
def test_graduated_partial_findings_retain_saved_execution_diagnostics(tmp_path, monkeypatch, damage):
    from core.reporting.scan_coverage import scan_execution_status
    from core.sarif.parser import generate_scan_metrics
    from packages.semgrep.models import SemgrepFinding, SemgrepResult

    project = tmp_path / 'project'
    out = project / 'run'
    out.mkdir(parents=True)
    rules = _mk_rules_dir(project, 'partial')
    repo = tmp_path / 'repo'
    repo.mkdir()
    _fake_runner(monkeypatch, {'partial': SemgrepResult(
        findings=[SemgrepFinding('a.c', 1, rule_id='inner')], **damage,
    )})
    paths = _scanner.run_graduated_rules_stage(repo, out, rules_dir=rules)
    metrics = generate_scan_metrics(paths)
    assert metrics['total_findings'] == 1
    assert scan_execution_status(metrics) == 'partial'
    assert metrics['tool_execution_failures'] or metrics['tool_coverage_limitations']



def test_graduated_diagnostic_escapes_rule_names_and_tool_error_controls(tmp_path, monkeypatch):
    from packages.semgrep.models import SemgrepResult

    project = tmp_path / 'project'
    out = project / 'run'
    out.mkdir(parents=True)
    rule_name = 'bad\nrule'
    rules = _mk_rules_dir(project, rule_name)
    repo = tmp_path / 'repo'
    repo.mkdir()
    _fake_runner(monkeypatch, {rule_name: SemgrepResult(errors=['parse error\x1b[2J'])})
    paths = _scanner.run_graduated_rules_stage(repo, out, rules_dir=rules)
    note = json.loads(Path(paths[0]).read_text())['runs'][0]['invocations'][0]['toolExecutionNotifications'][0]
    text = note['message']['text']
    assert 'parse error' in text
    assert '\n' not in text and '\x1b' not in text
    assert len(text) < 1000



def test_graduated_export_retains_two_distinct_direct_source_spans(tmp_path, monkeypatch):
    from core.sarif.parser import merge_sarif
    from packages.semgrep.models import SemgrepFinding, SemgrepResult

    project = tmp_path / 'project'
    out = project / 'run'
    out.mkdir(parents=True)
    rules = _mk_rules_dir(project, 'spans')
    repo = tmp_path / 'repo'
    repo.mkdir()
    _fake_runner(monkeypatch, {'spans': SemgrepResult(findings=[
        SemgrepFinding('a.c', 7, rule_id='inner', column=2, line_end=7, column_end=5),
        SemgrepFinding('a.c', 7, rule_id='inner', column=8, line_end=7, column_end=11),
    ])})
    paths = _scanner.run_graduated_rules_stage(repo, out, rules_dir=rules)
    results = merge_sarif(paths)['runs'][0]['results']
    assert [row['locations'][0]['physicalLocation']['region'] for row in results] == [
        {'startLine': 7, 'endLine': 7, 'startColumn': 2, 'endColumn': 5},
        {'startLine': 7, 'endLine': 7, 'startColumn': 8, 'endColumn': 11},
    ]


def test_graduated_enumeration_refusal_is_failed_invocation(tmp_path, monkeypatch):
    import os
    from packages.semgrep import runner
    from core.reporting.scan_coverage import scan_execution_status
    from core.sarif.parser import generate_scan_metrics

    repo, out, rules = (tmp_path / name for name in ('repo', 'out', 'rules'))
    for directory in (repo, out, rules):
        directory.mkdir()
    (rules / 'owned.yaml').write_text('rules: []\n')
    original = os.scandir
    calls = []

    def refused(path):
        if os.path.normpath(os.fspath(path)) == str(rules):
            calls.append(str(path))
            raise PermissionError('owned enumeration refusal')
        return original(path)

    def forbidden(*args, **kwargs):
        raise AssertionError('enumeration refusal reached a Semgrep probe or runner')

    monkeypatch.setattr(os, 'scandir', refused)
    monkeypatch.setattr(runner, 'is_available', forbidden)
    monkeypatch.setattr(runner, 'run_rule', forbidden)
    paths = _scanner.run_graduated_rules_stage(repo, out, rules_dir=rules)
    assert calls
    assert paths
    metrics = generate_scan_metrics(paths)
    assert metrics['total_findings'] == 0
    assert metrics['tool_execution_failures']
    assert scan_execution_status(metrics) == 'partial'


def test_automatic_graduated_locator_preserves_enumeration_failure(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    from core.audit import rules_dirs
    from core.run import pin
    from packages.semgrep import runner
    from core.sarif.parser import generate_scan_metrics

    project, repo = tmp_path / 'project', tmp_path / 'repo'
    out = project / 'run'
    out.mkdir(parents=True)
    repo.mkdir()
    rules = _mk_rules_dir(project, 'owned')
    monkeypatch.setattr(pin, 'resolve_run_pin', lambda path: SimpleNamespace(run_dir=out, authoritative=True))
    monkeypatch.setattr(pin, 'pin_project_dir', lambda path: project)
    monkeypatch.setattr(pin, '_marker_trustworthy', lambda path: True)
    monkeypatch.setattr(rules_dirs, 'standalone_read_candidates', lambda path: [])
    original = os.scandir
    calls = []

    def refused(path):
        if os.path.normpath(os.fspath(path)) == str(rules):
            calls.append(str(path))
            raise PermissionError('owned automatic discovery refusal')
        return original(path)

    def forbidden(*args, **kwargs):
        raise AssertionError('automatic discovery refusal reached Semgrep')

    monkeypatch.setattr(os, 'scandir', refused)
    monkeypatch.setattr(runner, 'is_available', forbidden)
    monkeypatch.setattr(runner, 'run_rule', forbidden)
    paths = _scanner.run_graduated_rules_stage(repo, out)
    assert calls
    assert paths
    metrics = generate_scan_metrics(paths)
    assert metrics['total_findings'] == 0
    assert metrics['tool_execution_failures']
