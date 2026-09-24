"""Receipt-policy honesty and in-session plumbing for content-probed
foreign-extension sweep targets.

Two surfaces:

* engine: when semgrep cannot witness a foreign-extension file (no
  language key for the probed language, or the rule's ``languages:``
  does not name it), the inevitable no-witness inconclusive must
  RECORD the capability gap instead of the generic silent-skip
  message — a silent cap read as a rule failure and hid that no
  executed receipt was possible on the target/rule pair at all;
* CLI: ``raptor-audit sweep`` (the in-session receipt path) resolves
  the inventory-stamped language from the checklist and threads it to
  the engine — without it, in-session sweeps on probed files could
  never earn an executed receipt in either direction and
  finding-grade results stayed capped at suspicious.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from core.audit.sweep import SweepResult, run_semgrep_sweep

REPO_ROOT = Path(__file__).resolve().parents[3]
AUDIT_CLI = REPO_ROOT / "libexec" / "raptor-audit"

_PHP_RULE = (
    "rules:\n  - id: x\n    pattern-regex: 'exec'\n"
    "    message: m\n    languages: [php]\n    severity: WARNING\n"
)


def _run_sweep(tmp_path, monkeypatch, *, file_name, language,
               rule_text=_PHP_RULE, examined=False):
    import packages.semgrep.runner as runner_mod
    from packages.semgrep.models import SemgrepResult

    target = tmp_path / file_name
    target.write_text("<?php\nexec($_POST['c']);\n")
    rule = tmp_path / "rule.yaml"
    rule.write_text(rule_text)

    def _fake_run_rule(tgt, config, **kw):
        res = SemgrepResult(
            name="x", config=config, target=str(tgt), returncode=0,
        )
        if examined:
            res.files_examined = [str(target)]
        return res

    monkeypatch.setattr(runner_mod, "is_available", lambda: True)
    monkeypatch.setattr(runner_mod, "run_rule", _fake_run_rule)
    return run_semgrep_sweep(
        target_path=tmp_path,
        file_path=file_name,
        function_name="f",
        rule_config=str(rule),
        language=language,
    )


class TestCapabilityNote:
    def test_unscannable_probed_language_records_capability_absent(
            self, tmp_path, monkeypatch):
        # perl has no semgrep language key: the receipt policy must
        # say the ENGINE cannot scan this file, not imply a rule bug.
        result = _run_sweep(
            tmp_path, monkeypatch, file_name="form.mod", language="perl",
        )
        assert result.outcome == "inconclusive"
        assert "engine capability absent" in result.details["reason"]
        assert "perl" in result.details["reason"]

    def test_rule_language_mismatch_records_actionable_reason(
            self, tmp_path, monkeypatch):
        c_rule = (
            "rules:\n  - id: x\n    pattern-regex: 'exec'\n"
            "    message: m\n    languages: [c]\n    severity: WARNING\n"
        )
        result = _run_sweep(
            tmp_path, monkeypatch, file_name="check.mod", language="php",
            rule_text=c_rule,
        )
        assert result.outcome == "inconclusive"
        assert "rule languages do not include" in result.details["reason"]
        assert "languages: [php]" in result.details["reason"]

    def test_witnessed_probed_scan_still_refutes(
            self, tmp_path, monkeypatch):
        # The other direction: probe + rule agreement earns the
        # executed receipt as before — the note never interferes.
        result = _run_sweep(
            tmp_path, monkeypatch, file_name="check.mod", language="php",
            examined=True,
        )
        assert result.outcome == "refuted"

    def test_mapped_extension_keeps_generic_message(
            self, tmp_path, monkeypatch):
        # Ordinary target silently skipped by the engine: not a
        # capability gap — the generic no-witness message stands.
        result = _run_sweep(
            tmp_path, monkeypatch, file_name="index.php", language="php",
        )
        assert result.outcome == "inconclusive"
        assert "no scanned-target witness" in result.details["reason"]


@pytest.fixture(scope="module")
def audit_cli():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader("raptor_audit_cli", str(AUDIT_CLI))
    spec = importlib.util.spec_from_loader("raptor_audit_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestCmdSweepLanguagePlumbing:
    def _args(self, out_dir, target, file_name):
        return argparse.Namespace(
            out=str(out_dir), target=str(target), tool="semgrep",
            file=file_name, function="f",
            rule_file=None, rule=_PHP_RULE,
            line_start=1, line_end=2,
            outcome=None, result_file=None, codeql_db=None,
            smt_verb=None, smt_args=None, cwe=None, query=None,
        )

    def _setup(self, tmp_path, *, language):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        target = tmp_path / "target"
        target.mkdir()
        (target / "check.mod").write_text("<?php\nexec($_POST['c']);\n")
        (out_dir / "checklist.json").write_text(json.dumps({
            "target_path": str(target),
            "files": [{
                "path": "check.mod", "language": language,
                "items": [{"name": "f", "kind": "function",
                           "line_start": 1, "line_end": 2}],
            }],
        }))
        return out_dir, target

    def test_checklist_language_reaches_engine(
            self, tmp_path, monkeypatch, audit_cli):
        out_dir, target = self._setup(tmp_path, language="php")
        seen: dict = {}

        import core.audit.sweep as sweep_mod

        def _fake(**kw):
            seen.update(kw)
            return SweepResult(
                tool="semgrep", file_path=kw["file_path"],
                function_name=kw["function_name"], outcome="refuted",
            )

        monkeypatch.setattr(sweep_mod, "run_semgrep_sweep", _fake)
        rc = audit_cli.cmd_sweep(self._args(out_dir, target, "check.mod"))
        assert rc == 0
        assert seen["language"] == "php"

    def test_unstamped_file_degrades_to_no_hint(
            self, tmp_path, monkeypatch, audit_cli):
        out_dir, target = self._setup(tmp_path, language=None)
        seen: dict = {}

        import core.audit.sweep as sweep_mod

        def _fake(**kw):
            seen.update(kw)
            return SweepResult(
                tool="semgrep", file_path=kw["file_path"],
                function_name=kw["function_name"], outcome="refuted",
            )

        monkeypatch.setattr(sweep_mod, "run_semgrep_sweep", _fake)
        rc = audit_cli.cmd_sweep(self._args(out_dir, target, "check.mod"))
        assert rc == 0
        assert seen["language"] is None
