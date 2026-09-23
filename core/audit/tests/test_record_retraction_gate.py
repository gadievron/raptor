"""G3 retraction lane: downgrading a verdict needs EXECUTED evidence.

Retraction is the suppression-critical direction of the audit
doctrine ("the LLM never directly classifies — tool output is the
verdict"): a finding/suspicious verdict served to reports, gap folds,
and cross-run reuse must not be retractable to clean on the strength
of the agent's own assertion. The sweep producer already tags
attested outcomes (``rule_source: manual-attestation``) and G2
excludes them from finding receipts; the G3 freshness gate must
apply the same discrimination when the re-record downgrades.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CLI_PATH = _REPO_ROOT / "libexec" / "raptor-audit"


@pytest.fixture(scope="module")
def cli():
    loader = SourceFileLoader(
        "raptor_audit_cli_retraction", str(_CLI_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture()
def scratch(tmp_path, monkeypatch):
    # Never resolve this host's live project/sandbox state.
    import core.project.trust as trust
    monkeypatch.setattr(
        trust, "apply_project_sandbox_floor", lambda *a, **k: None)
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def f(x):\n    return eval(x)\n")
    out = tmp_path / "out"
    out.mkdir()
    return target, out


def _run(cli, monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["raptor-audit", *argv])
    return cli.main()


def _record(cli, monkeypatch, target, out, status, **extra):
    argv = ["record", "--out", str(out), "--target", str(target),
            "--file", "app.py", "--function", "f",
            "--status", status, "--body", "probe"]
    if status in ("suspicious", "finding", "dormant"):
        argv += ["--hypothesis", "eval of user input"]
    for k, v in extra.items():
        argv += [f"--{k.replace('_', '-')}", v]
    return _run(cli, monkeypatch, *argv)


def _seed_suspicious(cli, monkeypatch, target, out):
    assert _run(cli, monkeypatch, "context", "--target", str(target),
                "--file", "app.py", "--function", "f",
                "--out", str(out)) == 0
    assert _record(cli, monkeypatch, target, out, "suspicious") == 0


def _plant_executed_sweep(out, outcome="refuted"):
    """Append the row shape the semgrep auto-run branch writes."""
    from core.audit.record import append_audit_log
    append_audit_log(out, {
        "action": "sweep", "key": "app.py:f", "file": "app.py",
        "function": "f", "tool": "semgrep", "outcome": outcome,
        "rule_id": "probe-rule",
        "rule_source": str(out / "rule.yaml"),
    })


class TestRetractionNeedsExecutedSweep:
    def test_attested_sweep_does_not_unlock_clean(
            self, cli, scratch, monkeypatch, capsys):
        target, out = scratch
        _seed_suspicious(cli, monkeypatch, target, out)
        # Fresh re-record refused outright (no sweep at all).
        assert _record(cli, monkeypatch, target, out, "clean") == 1
        # Manual attestation: nothing executed.
        assert _run(cli, monkeypatch, "sweep", "--out", str(out),
                    "--target", str(target), "--file", "app.py",
                    "--function", "f", "--tool", "semgrep",
                    "--outcome", "refuted") == 0
        capsys.readouterr()
        assert _record(cli, monkeypatch, target, out, "clean") == 1
        err = capsys.readouterr().err
        assert "G3 NO-SELF-CRITIQUE" in err
        assert "EXECUTED" in err
        # The refusal must prescribe execution, not the bypass.
        assert "--outcome <confirmed|refuted>" not in err

    def test_outcomeless_logged_sweep_does_not_unlock_clean(
            self, cli, scratch, monkeypatch, capsys):
        # Adjacent retraction route: a bare logged sweep row (no
        # --outcome, so the producer never tags it) is not execution
        # evidence either.
        target, out = scratch
        _seed_suspicious(cli, monkeypatch, target, out)
        assert _run(cli, monkeypatch, "sweep", "--out", str(out),
                    "--target", str(target), "--file", "app.py",
                    "--function", "f", "--tool", "semgrep") == 0
        capsys.readouterr()
        assert _record(cli, monkeypatch, target, out, "clean") == 1
        assert "EXECUTED" in capsys.readouterr().err

    def test_error_outcome_sweep_does_not_unlock_clean(
            self, cli, scratch, monkeypatch, capsys):
        # A tool that never completed is not execution evidence.
        target, out = scratch
        _seed_suspicious(cli, monkeypatch, target, out)
        _plant_executed_sweep(out, outcome="error")
        capsys.readouterr()
        assert _record(cli, monkeypatch, target, out, "clean") == 1
        assert "EXECUTED" in capsys.readouterr().err

    def test_executed_sweep_unlocks_clean(
            self, cli, scratch, monkeypatch):
        target, out = scratch
        _seed_suspicious(cli, monkeypatch, target, out)
        _plant_executed_sweep(out)
        assert _record(cli, monkeypatch, target, out, "clean") == 0

    def test_dormant_downgrade_also_gated(
            self, cli, scratch, monkeypatch, capsys):
        # dormant suppresses the same way clean does.
        target, out = scratch
        _seed_suspicious(cli, monkeypatch, target, out)
        assert _run(cli, monkeypatch, "sweep", "--out", str(out),
                    "--target", str(target), "--file", "app.py",
                    "--function", "f", "--tool", "semgrep",
                    "--outcome", "refuted") == 0
        capsys.readouterr()
        assert _record(cli, monkeypatch, target, out, "dormant") == 1
        assert "EXECUTED" in capsys.readouterr().err


class TestNonDowngradePathsKeepPlainFreshness:
    def test_escalation_still_passes_on_attested_sweep(
            self, cli, scratch, monkeypatch):
        # clean -> suspicious is the condemn direction — the plain
        # freshness rule (any sweep since last record) still applies.
        target, out = scratch
        assert _run(cli, monkeypatch, "context", "--target",
                    str(target), "--file", "app.py", "--function",
                    "f", "--out", str(out)) == 0
        assert _record(cli, monkeypatch, target, out, "clean") == 0
        assert _run(cli, monkeypatch, "sweep", "--out", str(out),
                    "--target", str(target), "--file", "app.py",
                    "--function", "f", "--tool", "semgrep",
                    "--outcome", "confirmed") == 0
        assert _record(cli, monkeypatch, target, out, "suspicious") == 0

    def test_first_record_always_allowed(
            self, cli, scratch, monkeypatch):
        target, out = scratch
        assert _run(cli, monkeypatch, "context", "--target",
                    str(target), "--file", "app.py", "--function",
                    "f", "--out", str(out)) == 0
        assert _record(cli, monkeypatch, target, out, "clean") == 0


class TestConfirmOnlySilenceStillUnlocksRetraction:
    """Interaction pin: confirm-only sweep silence vs the G3 unlock.

    Two doctrines meet on one journal row, and the composed behavior
    is deliberate — assert it so any future change to either side is
    made knowingly:

    - G3's retraction unlock keys on EXECUTION, not refutation: any
      tool-produced outcome other than "error" (and never a
      manual-attestation row) proves a tool actually ran since the
      last record. The gate forbids retraction on the agent's bare
      word — not retraction informed by a run.
    - A confirm-only rule's zero-match is capped at "inconclusive" by
      the sweep layer: silence adjudicates only the rule's sub-shape,
      never the dispatched class, so the row's CONTENT can never be
      cited as a class refutation.

    An inconclusive row from an executed confirm-only rule therefore
    DOES unlock the retraction lane: it is execution evidence, while
    the verdict itself remains the operator's judgment. If retraction
    should ever require a mechanically refuting outcome instead, that
    is a G3 policy change — not a sweep-layer one.
    """

    def test_confirm_only_inconclusive_row_unlocks_clean(
            self, cli, scratch, monkeypatch):
        target, out = scratch
        _seed_suspicious(cli, monkeypatch, target, out)
        # The row shape the semgrep auto-run branch writes when a
        # curated `# raptor: confirm-only` rule scans zero matches:
        # executed (tool-produced rule_source, not an attestation),
        # outcome capped at "inconclusive" — never "refuted".
        _plant_executed_sweep(out, outcome="inconclusive")
        assert _record(cli, monkeypatch, target, out, "clean") == 0
