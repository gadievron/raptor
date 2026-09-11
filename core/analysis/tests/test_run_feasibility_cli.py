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
