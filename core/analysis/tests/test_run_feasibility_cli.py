"""Argument parsing and malformed-finding tolerance for
``libexec/raptor-run-feasibility``.

The CLI hand-rolls its argv handling; a flag token must never stand in
for a forgotten positional, trailing valueless flags must error rather
than silently skip an analysis mode, and a finding carrying
``"feasibility": null`` must not abort the group filter.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-run-feasibility"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.fixture(scope="module")
def feasibility_mod():
    """Import the script as a module for unit-level checks."""
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_run_feasibility", str(CLI),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        yield mod
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


class TestArgvParsing:
    def test_flag_cannot_stand_in_for_positional(self, tmp_path: Path):
        # output_dir forgotten: "--vuln-type" must not become the
        # output directory.
        res = _run(
            ["bin.elf", "findings.json", "--vuln-type", "overflow"],
            tmp_path,
        )
        assert res.returncode == 1
        assert "Usage:" in res.stderr
        assert not (tmp_path / "--vuln-type").exists()

    def test_trailing_valueless_flag_errors(self, tmp_path: Path):
        binary = tmp_path / "bin.elf"
        binary.write_bytes(b"\x7fELF")
        findings = tmp_path / "findings.json"
        findings.write_text('{"findings": []}', encoding="utf-8")
        res = _run(
            [str(binary), str(findings), str(tmp_path / "out"), "--target"],
            tmp_path,
        )
        assert res.returncode == 1
        assert "requires a value" in res.stderr

    def test_unknown_flag_errors(self, tmp_path: Path):
        res = _run(
            ["bin.elf", "f.json", "out", "--bogus"],
            tmp_path,
        )
        assert res.returncode == 1
        assert "unknown flag" in res.stderr

    def test_valid_argv_reaches_binary_check(self, tmp_path: Path):
        # Good direction: full argv parses; the run proceeds to the
        # binary-existence check (and fails there, not at parse time).
        res = _run(
            ["/nonexistent/bin.elf", "f.json", "out",
             "--vuln-type", "overflow"],
            tmp_path,
        )
        assert res.returncode == 1
        assert "binary not found" in res.stderr
        assert "Usage:" not in res.stderr


class TestNullFeasibilityFinding:
    def test_null_feasibility_does_not_crash(self, tmp_path: Path):
        binary = tmp_path / "bin.elf"
        binary.write_bytes(b"\x7fELF")
        findings = tmp_path / "findings.json"
        findings.write_text(
            json.dumps({
                "findings": [
                    {"id": "a", "feasibility": None},
                    {"id": "b", "ruling": None},
                    {"id": "c", "feasibility": "bogus-shape"},
                ],
            }),
            encoding="utf-8",
        )
        res = _run(
            [str(binary), str(findings), str(tmp_path / "out")],
            tmp_path,
        )
        # No finding references the binary — clean early return, not
        # an AttributeError traceback.
        assert res.returncode == 0
        assert "Traceback" not in res.stderr
        assert "No findings reference binary" in res.stderr


class TestMapFilename:
    def test_distinct_ids_get_distinct_files(self, feasibility_mod):
        a = feasibility_mod._map_filename("vuln:1")
        b = feasibility_mod._map_filename("vuln_1")
        assert a != b

    def test_already_safe_id_unchanged(self, feasibility_mod):
        assert feasibility_mod._map_filename("plain-id_1") == "plain-id_1"

    def test_sanitised_id_is_deterministic(self, feasibility_mod):
        assert (
            feasibility_mod._map_filename("f#2")
            == feasibility_mod._map_filename("f#2")
        )

    def test_empty_id_named(self, feasibility_mod):
        assert feasibility_mod._map_filename("").startswith("unnamed")


class TestDismissedFindingsAndRulingForwarding:
    """Two directions: dismissed findings never reach analysis, and
    the mapper receives each surviving finding's ruling/status.

    The old group filter matched exactly two literals (status
    "disproven", dict-ruling "ruled_out") and then stripped findings
    down to id+vuln_type — false_positive rows and string-shaped
    rulings entered the analysis flow, and the mapper's own dismissal
    gate could never fire because rulings never reached it.
    """

    def _drive(self, feasibility_mod, monkeypatch, tmp_path: Path,
               findings: list[dict]) -> tuple[list, dict]:
        """Run main() with the analysis seam stubbed; returns
        (mapper_input, saved findings.json)."""
        from types import SimpleNamespace

        binary = tmp_path / "bin.elf"
        binary.write_bytes(b"\x7fELF")
        for f in findings:
            f.setdefault("feasibility", {})["binary_path"] = str(binary)
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(
            json.dumps({"findings": findings}), encoding="utf-8")
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        import packages.exploit_feasibility as pef
        context_file = tmp_path / "context.json"
        context_file.write_text("{}", encoding="utf-8")
        received: list = []

        def fake_map(findings_arg, constraints, **kwargs):
            received.extend(findings_arg)
            return [
                SimpleNamespace(
                    finding_id=f["id"], verdict="Difficult",
                    impact="", blockers=[], notes="",
                    exploitation_paths=[],
                )
                for f in findings_arg
            ]

        monkeypatch.setattr(
            pef, "save_exploit_context",
            lambda *a, **k: context_file)
        monkeypatch.setattr(
            pef, "load_exploit_context",
            lambda *a, **k: {"verdict": "difficult"})
        monkeypatch.setattr(pef, "map_findings_to_constraints", fake_map)
        import core.witness.provenance as prov
        monkeypatch.setattr(
            prov, "stamp_feasibility", lambda *a, **k: None)

        monkeypatch.setattr(sys, "argv", [
            "raptor-run-feasibility", str(binary), str(findings_path),
            str(out_dir),
        ])
        feasibility_mod.main()
        saved = json.loads(findings_path.read_text())
        return received, saved

    def test_dismissed_spellings_never_reach_analysis(
            self, feasibility_mod, monkeypatch, tmp_path: Path):
        received, saved = self._drive(feasibility_mod, monkeypatch,
                                      tmp_path, [
            {"id": "fp", "vuln_type": "overflow",
             "ruling": {"status": "false_positive"}},
            {"id": "fp-hyphen", "vuln_type": "overflow",
             "ruling": {"status": "False-Positive"}},
            {"id": "string-ruled", "vuln_type": "overflow",
             "ruling": "ruled_out"},
            {"id": "string-disproven", "vuln_type": "overflow",
             "ruling": "disproven"},
            {"id": "status-fp", "vuln_type": "overflow",
             "status": "false_positive"},
            {"id": "live", "vuln_type": "overflow",
             "ruling": {"status": "confirmed"}},
        ])
        assert [f["id"] for f in received] == ["live"]
        by_id = {f["id"]: f for f in saved["findings"]}
        assert by_id["live"]["feasibility"].get("verdict") == "Difficult"
        for fid in ("fp", "fp-hyphen", "string-ruled",
                    "string-disproven", "status-fp"):
            assert "verdict" not in by_id[fid]["feasibility"], fid

    def test_surviving_findings_forward_ruling_and_status(
            self, feasibility_mod, monkeypatch, tmp_path: Path):
        received, saved = self._drive(feasibility_mod, monkeypatch,
                                      tmp_path, [
            {"id": "dicted", "vuln_type": "overflow",
             "status": "confirmed",
             "ruling": {"status": "confirmed", "rationale": "r"}},
            {"id": "stringed", "vuln_type": "overflow",
             "ruling": "confirmed"},
            {"id": "bare", "vuln_type": "overflow"},
        ])
        by_id = {f["id"]: f for f in received}
        assert set(by_id) == {"dicted", "stringed", "bare"}
        # The mapper sees the ruling — dict shape passed through,
        # string shape dict-normalised, absence forwarded as None.
        assert by_id["dicted"]["ruling"]["status"] == "confirmed"
        assert by_id["dicted"]["status"] == "confirmed"
        assert by_id["stringed"]["ruling"] == {"status": "confirmed"}
        assert by_id["bare"]["ruling"] is None
        # No over-suppression: all three were analysed.
        saved_by_id = {f["id"]: f for f in saved["findings"]}
        for fid in ("dicted", "stringed", "bare"):
            assert saved_by_id[fid]["feasibility"]["verdict"] == "Difficult"
