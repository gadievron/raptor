"""Tests for the graduated synthesized-rules /scan stage (P7).

Same hyphenated-package importlib pattern as the other scanner tests.
The semgrep runner is faked throughout — no semgrep binary required.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path

# parents[3]: tests/ → static-analysis/ → packages/ → repo root
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
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
    """results: dict config-path-stem → FakeSemgrepResult or Exception."""
    calls = []

    def run_rule(target, config, *, name="", timeout=0, env=None, **kw):
        stem = Path(config).stem
        calls.append({"config": config, "name": name})
        res = results.get(stem, FakeSemgrepResult())
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
        assert _scanner.run_graduated_rules_stage(
            repo, out_dir, rules_dir=rules_dir,
        ) == []
        assert "semgrep not installed" in capsys.readouterr().err


# ---------------------------------------------------------------------
# CLI flag surface — default-on, opt-out
# ---------------------------------------------------------------------


def test_scanner_flag_default_on_opt_out():
    src = _SCANNER_PATH.read_text(encoding="utf-8")
    assert '"--no-graduated-rules"' in src
    assert "if not args.no_graduated_rules:" in src
    assert "graduated_sarifs" in src


def test_agentic_forwards_opt_out():
    src = (Path(_REPO_ROOT) / "raptor_agentic.py").read_text(encoding="utf-8")
    assert '"--no-graduated-rules"' in src
    assert 'semgrep_cmd.append("--no-graduated-rules")' in src
