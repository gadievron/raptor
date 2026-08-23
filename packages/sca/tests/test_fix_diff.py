"""Tests for ``raptor-sca fix-diff`` (packages/sca/fix_diff.py).

The /cve-diff subprocess is always stubbed — these tests cover CVE
collection from findings rows, summary parsing, the invocation
contract, the cap, and exit codes.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from packages.sca import fix_diff
from packages.sca.cli import SUBCOMMANDS, _dispatch


def _row(adv_id="GHSA-xxxx-yyyy-zzzz", aliases=("CVE-2021-44228",),
         suppressed=False):
    row = {
        "severity": "high",
        "sca": {
            "ecosystem": "Maven",
            "name": "log4j-core",
            "version": "2.14.0",
            "advisory": {"id": adv_id, "aliases": list(aliases)},
        },
    }
    if suppressed:
        row["suppressed"] = True
    return row


class TestCollectCveIds:
    def test_collects_from_aliases_and_id_deduplicated(self):
        rows = [
            _row(aliases=("CVE-2021-44228", "CVE-2021-45046")),
            _row(adv_id="CVE-2021-44228", aliases=()),
            _row(aliases=("cve-2024-12345",)),  # case-normalised
        ]
        assert fix_diff.collect_cve_ids(rows) == [
            "CVE-2021-44228", "CVE-2021-45046", "CVE-2024-12345",
        ]

    def test_skips_suppressed_and_non_cve_aliases(self):
        rows = [
            _row(suppressed=True),
            _row(aliases=("GHSA-only-alias", "PYSEC-2024-1")),
        ]
        assert fix_diff.collect_cve_ids(rows) == []

    def test_tolerates_malformed_rows(self):
        rows = ["not a dict", {}, {"sca": None}, {"sca": {"advisory": "x"}}]
        assert fix_diff.collect_cve_ids(rows) == []


class TestParseSummary:
    def test_finds_last_json_object_after_noise(self):
        stdout = (
            "OUTPUT_DIR=/tmp/run\n"
            "progress line\n"
            '{\n  "ok": true,\n  "cve_id": "CVE-2024-1",\n'
            '  "bundle": {"fix_commit": "abc"}\n}\n'
        )
        parsed = fix_diff._parse_summary(stdout)
        assert parsed["ok"] is True
        assert parsed["bundle"]["fix_commit"] == "abc"

    def test_garbage_returns_none(self):
        assert fix_diff._parse_summary("no json here") is None
        assert fix_diff._parse_summary("{broken\n") is None


class TestRunOne:
    def test_invocation_contract_and_result_row(self, tmp_path, monkeypatch):
        seen = {}

        def _fake_run(cmd, **kw):
            seen["cmd"] = cmd
            seen["env_trusted"] = kw["env"].get("_RAPTOR_TRUSTED")
            stdout = json.dumps({
                "ok": True, "cve_id": "CVE-2024-12345",
                "output_dir": str(tmp_path / "cve-2024-12345"),
                "bundle": {
                    "repository_url": "https://github.com/e/p",
                    "fix_commit": "a" * 40, "files_changed": 2,
                },
            })
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

        monkeypatch.setattr(fix_diff.subprocess, "run", _fake_run)
        row = fix_diff.run_one(
            "CVE-2024-12345", tmp_path,
            budget_multiplier=2.0, model="gemini-2.5-pro",
        )
        assert row["ok"] is True
        assert row["fix_commit"] == "a" * 40
        assert seen["env_trusted"] == "1"
        cmd = seen["cmd"]
        assert cmd[1].endswith("libexec/raptor-cve-diff")
        assert cmd[2:4] == ["run", "CVE-2024-12345"]
        assert "--budget-multiplier" in cmd and "2.0" in cmd
        assert "--model" in cmd and "gemini-2.5-pro" in cmd

    def test_timeout_yields_failure_row(self, tmp_path, monkeypatch):
        def _boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 1)

        monkeypatch.setattr(fix_diff.subprocess, "run", _boom)
        row = fix_diff.run_one("CVE-2024-12345", tmp_path)
        assert row["ok"] is False
        assert row["error_class"] == "TimeoutExpired"

    def test_unparseable_output_yields_failure_row(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            fix_diff.subprocess, "run",
            lambda cmd, **kw: subprocess.CompletedProcess(
                cmd, 5, stdout="garbage", stderr="agent surrendered"),
        )
        row = fix_diff.run_one("CVE-2024-12345", tmp_path)
        assert row["ok"] is False
        assert row["error_class"] == "NoSummary"
        assert row["exit_code"] == 5


class TestMain:
    def _findings(self, tmp_path, rows):
        path = tmp_path / "findings.json"
        path.write_text(json.dumps(rows), encoding="utf-8")
        return path

    def test_runs_each_cve_and_writes_summary(self, tmp_path, monkeypatch):
        ran = []
        monkeypatch.setattr(
            fix_diff, "run_one",
            lambda cve, out, **kw: ran.append(cve) or
            {"ok": True, "cve_id": cve},
        )
        findings = self._findings(
            tmp_path, [_row(aliases=("CVE-2021-44228",))])
        rc = fix_diff.main([str(findings)])
        assert rc == 0
        assert ran == ["CVE-2021-44228"]
        summary = json.loads(
            (tmp_path / "fix-diffs" / "summary.json").read_text())
        assert summary["results"][0]["ok"] is True
        assert summary["dropped_over_cap"] == 0

    def test_cap_is_enforced_and_reported(self, tmp_path, monkeypatch, capsys):
        ran = []
        monkeypatch.setattr(
            fix_diff, "run_one",
            lambda cve, out, **kw: ran.append(cve) or
            {"ok": True, "cve_id": cve},
        )
        rows = [_row(aliases=(f"CVE-2024-{10000 + i}",)) for i in range(8)]
        findings = self._findings(tmp_path, rows)
        rc = fix_diff.main([str(findings), "--max-cves", "3"])
        assert rc == 0
        assert len(ran) == 3
        summary = json.loads(
            (tmp_path / "fix-diffs" / "summary.json").read_text())
        assert summary["dropped_over_cap"] == 5
        assert "5 CVE(s) beyond --max-cves" in capsys.readouterr().err

    def test_partial_failure_exits_1(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            fix_diff, "run_one",
            lambda cve, out, **kw: {
                "ok": cve.endswith("44228"), "cve_id": cve,
            },
        )
        findings = self._findings(tmp_path, [
            _row(aliases=("CVE-2021-44228", "CVE-2021-45046")),
        ])
        assert fix_diff.main([str(findings)]) == 1

    def test_explicit_cve_skips_findings(self, tmp_path, monkeypatch):
        ran = []
        monkeypatch.setattr(
            fix_diff, "run_one",
            lambda cve, out, **kw: ran.append(cve) or
            {"ok": True, "cve_id": cve},
        )
        rc = fix_diff.main([
            "--cve", "CVE-2024-12345", "--output-dir", str(tmp_path / "o"),
        ])
        assert rc == 0
        assert ran == ["CVE-2024-12345"]

    def test_bad_inputs_exit_2(self, tmp_path):
        assert fix_diff.main(["--cve", "not-a-cve"]) == 2
        assert fix_diff.main([str(tmp_path / "missing.json")]) == 2
        assert fix_diff.main([]) == 2

    def test_no_cves_found_is_success_noop(self, tmp_path):
        findings = self._findings(tmp_path, [_row(aliases=("GHSA-x",))])
        assert fix_diff.main([str(findings)]) == 0
        assert not (tmp_path / "fix-diffs").exists()


def test_subcommand_registered():
    assert "fix-diff" in SUBCOMMANDS
    # Unknown-arg parse error inside the module exits via argparse; a
    # smoke dispatch with bad args must reach fix_diff (exit 2), not
    # the unknown-subcommand branch.
    with pytest.raises(SystemExit):
        _dispatch("fix-diff", ["--definitely-not-a-flag"])
