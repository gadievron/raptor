"""Tests for the ``--expanded-semgrep`` /scan stage wiring.

Same hyphenated-package importlib pattern as the other scanner tests.
The corpus build + translation machinery has its own suite in
core/audit/tests/test_expanded_semgrep.py; here we exercise the
scanner-side stage: skip paths, SARIF emission with the marker,
cross-pack dedup, loud budget reporting, and CLI flag surface.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# parents[3]: tests/ → static-analysis/ → packages/ → repo root
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_SCANNER_PATH = Path(_REPO_ROOT) / "packages/static-analysis/scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_expanded", _SCANNER_PATH,
)
_scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scanner)

from core.audit import expanded_semgrep as es  # noqa: E402 — after the sys.path/importlib bootstrap above


@dataclass
class FakeFinding:
    line: int
    rule_id: str = "no-strcpy"
    message: str = "strcpy is dangerous"
    file: str = ""


class FakeSemgrepResult:
    def __init__(self, findings=(), errors=()):
        self.findings = list(findings)
        self.errors = list(errors)


@dataclass
class FakeCorpus:
    root: Path
    tus: dict = field(default_factory=dict)
    candidates_total: int = 0
    expanded: int = 0
    skipped_budget: int = 0
    failed: int = 0

    def summary_line(self):
        line = (
            f"expanded-semgrep: {self.expanded}/{self.candidates_total} "
            f"macro-heavy TU(s) expanded"
        )
        if self.skipped_budget:
            line += f"; ⚠️  {self.skipped_budget} TU(s) SKIPPED"
        return line


def _c_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "main.c").write_text(
        "void f(char *d, const char *s) { UNSAFE_COPY(d, s); }\n",
    )
    return repo


# ---------------------------------------------------------------------
# run_expanded_semgrep_stage
# ---------------------------------------------------------------------


def test_stage_skips_non_c_target(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    out = tmp_path / "out"
    out.mkdir()

    def boom(*a, **k):
        raise AssertionError("corpus built for a non-C repo")

    monkeypatch.setattr(es, "build_expanded_corpus", boom)
    assert _scanner.run_expanded_semgrep_stage(repo, out, [], []) == []


def test_stage_empty_corpus_returns_nothing(tmp_path, monkeypatch):
    repo = _c_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(
        es, "build_expanded_corpus",
        lambda target, scratch, **kw: FakeCorpus(root=Path(scratch)),
    )
    assert _scanner.run_expanded_semgrep_stage(repo, out, [], []) == []
    assert not (out / "expanded_semgrep.sarif").exists()


def test_stage_emits_marked_sarif_and_dedups(tmp_path, monkeypatch):
    repo = _c_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()

    monkeypatch.setattr(
        es, "build_expanded_corpus",
        lambda target, scratch, **kw: FakeCorpus(
            root=Path(scratch), candidates_total=1, expanded=1,
            tus={"main.c": object()},
        ),
    )
    finding = {
        "file": "main.c", "line": 1, "expanded_line": 90,
        "rule_id": "no-strcpy", "message": "strcpy is dangerous",
        "expanded_view": True,
    }
    monkeypatch.setattr(
        es, "translate_corpus_findings",
        lambda corpus, findings: ([dict(finding)], 2),
    )
    monkeypatch.setattr(
        "packages.semgrep.runner.run_rule",
        lambda target, config, **kw: FakeSemgrepResult(
            findings=[FakeFinding(line=90)],
        ),
    )
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    # Two configs producing the SAME translated finding — cross-pack
    # dedup must collapse them to one result.
    rules_a = tmp_path / "rules_a"
    rules_a.mkdir()
    rules_b = tmp_path / "rules_b"
    rules_b.mkdir()
    paths = _scanner.run_expanded_semgrep_stage(
        repo, out, [str(rules_a), str(rules_b)], [],
    )
    assert paths == [str(out / "expanded_semgrep.sarif")]

    sarif = json.loads(
        (out / "expanded_semgrep.sarif").read_text(encoding="utf-8"),
    )
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "semgrep-expanded"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["properties"]["expanded_view"] is True
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "main.c"
    assert loc["region"]["startLine"] == 1

    # Scratch corpus dir cleaned up.
    assert not any(
        p.name.startswith("expanded_semgrep_") for p in out.iterdir()
    )


def test_stage_reports_budget_skips_on_stderr(tmp_path, monkeypatch, capsys):
    repo = _c_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    # Hermetic availability (same stub the sibling tests use): without
    # it, a semgrep-less host early-returns with the 'not installed'
    # message before the budget-skip branch this test pins.
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)
    monkeypatch.setattr(
        es, "build_expanded_corpus",
        lambda target, scratch, **kw: FakeCorpus(
            root=Path(scratch), candidates_total=3, expanded=0,
            skipped_budget=3,
        ),
    )
    assert _scanner.run_expanded_semgrep_stage(repo, out, [], []) == []
    assert "SKIPPED" in capsys.readouterr().err


def test_stage_one_pack_failure_is_not_fatal(tmp_path, monkeypatch, capsys):
    """One failing pack degrades that pack only; the stage still emits
    SARIF and tallies the failure on stderr."""
    repo = _c_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(
        es, "build_expanded_corpus",
        lambda target, scratch, **kw: FakeCorpus(
            root=Path(scratch), candidates_total=1, expanded=1,
            tus={"main.c": object()},
        ),
    )
    monkeypatch.setattr(
        es, "translate_corpus_findings",
        lambda corpus, findings: (list(findings), 0),
    )

    calls = []

    def run_rule(target, config, **kw):
        calls.append(config)
        if len(calls) == 1:
            raise RuntimeError("pack exploded")
        return FakeSemgrepResult()

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run_rule)
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    rules_a = tmp_path / "rules_a"
    rules_a.mkdir()
    rules_b = tmp_path / "rules_b"
    rules_b.mkdir()
    paths = _scanner.run_expanded_semgrep_stage(
        repo, out, [str(rules_a), str(rules_b)], [],
    )
    assert len(paths) == 1
    sarif = json.loads(Path(paths[0]).read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"] == []
    assert "1/2 pack(s) failed" in capsys.readouterr().err


def test_stage_all_packs_failed_surfaces_error_no_sarif(
    tmp_path, monkeypatch, capsys,
):
    """All packs failing must not silently write a zero-finding SARIF —
    that reads downstream as a clean scan."""
    repo = _c_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(
        es, "build_expanded_corpus",
        lambda target, scratch, **kw: FakeCorpus(
            root=Path(scratch), candidates_total=1, expanded=1,
            tus={"main.c": object()},
        ),
    )

    def raising_run_rule(target, config, **kw):
        raise RuntimeError("pack exploded")

    monkeypatch.setattr("packages.semgrep.runner.run_rule", raising_run_rule)
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)

    rules = tmp_path / "rules"
    rules.mkdir()
    paths = _scanner.run_expanded_semgrep_stage(repo, out, [str(rules)], [])
    assert paths == []
    assert not (out / "expanded_semgrep.sarif").exists()
    err = capsys.readouterr().err
    assert "FAILED" in err
    assert "no SARIF emitted" in err


def test_stage_requires_semgrep(tmp_path, monkeypatch, capsys):
    repo = _c_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: False)
    assert _scanner.run_expanded_semgrep_stage(repo, out, [], []) == []
    assert "semgrep not installed" in capsys.readouterr().err


# ---------------------------------------------------------------------
# CLI flag surface
# ---------------------------------------------------------------------


def test_scanner_flag_default_off():
    src = _SCANNER_PATH.read_text(encoding="utf-8")
    assert '"--expanded-semgrep"' in src
    # Stage gated on the opt-in flag.
    assert "if args.expanded_semgrep:" in src
    # SARIF from the stage joins the merge inputs.
    assert "expanded_sarifs" in src


def test_agentic_forwards_expanded_semgrep():
    src = (Path(_REPO_ROOT) / "raptor_agentic.py").read_text(encoding="utf-8")
    assert '"--expanded-semgrep"' in src
    assert 'semgrep_cmd.append("--expanded-semgrep")' in src
