"""Tests for the learned-models wiring around the PR2a emitter:
``codeql_augmented_run.run_learned_models_measurement`` and the
``raptor-emit-extension-pack`` libexec shim. CodeQL is never invoked;
the fake runner writes minimal SARIF where ``--output=`` points."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow.extension_pack import ModelRow


def _row(**kw) -> ModelRow:
    base = dict(
        role="sink",
        provenance="study",
        name="do_exec",
        access_input="Argument[*0]",
        model_kind="command-injection",
    )
    base.update(kw)
    return ModelRow(**base)


# ---------------------------------------------------------------------
# End-to-end wiring (mocked CodeQL)
# ---------------------------------------------------------------------


_MINIMAL_SARIF = {
    "runs": [{"tool": {"driver": {"name": "codeql"}}, "results": []}],
}


def _sarif_writing_runner(args, *, capture_output=True, text=True,
                          timeout=None, check=False, env=None):
    out = next(a.split("=", 1)[1] for a in args if a.startswith("--output="))
    Path(out).write_text(json.dumps(_MINIMAL_SARIF), encoding="utf-8")
    return SimpleNamespace(returncode=0, stdout="", stderr="")


class TestRunLearnedModelsMeasurement:
    def test_end_to_end(self, tmp_path: Path):
        from core.dataflow.codeql_augmented_run import (
            run_learned_models_measurement,
        )
        m = run_learned_models_measurement(
            tmp_path / "db",
            ["codeql/cpp-queries:some-suite"],
            [_row()],
            language="cpp",
            out_dir=tmp_path / "out",
            runner=_sarif_writing_runner,
        )
        assert m.pack.rows_written == 1
        assert m.baseline.extension_pack is None
        assert m.augmented.extension_pack == m.pack.pack_dir
        assert m.diff.baseline_count == 0
        assert (m.pack.pack_dir / "codeql-pack.yml").exists()

    def test_all_rejected_raises(self, tmp_path: Path):
        from core.dataflow.codeql_augmented_run import (
            run_learned_models_measurement,
        )
        with pytest.raises(ValueError, match="no model rows survived"):
            run_learned_models_measurement(
                tmp_path / "db",
                ["suite"],
                [_row(provenance="llm_prior")],
                language="cpp",
                out_dir=tmp_path / "out",
                runner=_sarif_writing_runner,
            )


# ---------------------------------------------------------------------
# Shim smoke (argparse level)
# ---------------------------------------------------------------------


_SHIM = Path(__file__).resolve().parents[3] / "libexec" / "raptor-emit-extension-pack"


def _run_shim(*args):
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(_SHIM), *args],
        capture_output=True, text=True, timeout=60, env=env, check=False,
    )


class TestShim:
    def test_specs_to_pack(self, tmp_path: Path):
        specs = [{
            "role": "sink",
            "function": "proj::db::run_q",
            "taint_classes": ["sql_injection"],
            "params_affected": [0],
            "confidence": 0.9,
            "evidence_tier": "xref_backed",
        }]
        specs_file = tmp_path / "specs.json"
        specs_file.write_text(json.dumps(specs), encoding="utf-8")
        proc = _run_shim("--specs", str(specs_file), "--language", "cpp",
                         "--out", str(tmp_path / "out"))
        assert proc.returncode == 0, proc.stderr
        report = json.loads(proc.stdout)
        assert report["counts"] == {"sinkModel": 1}
        assert Path(report["model_file"]).exists()

    def test_no_inputs_is_usage_error(self, tmp_path: Path):
        proc = _run_shim("--language", "cpp", "--out", str(tmp_path))
        assert proc.returncode == 2

    def test_empty_specs_exit_2(self, tmp_path: Path):
        f = tmp_path / "specs.json"
        f.write_text("[]", encoding="utf-8")
        proc = _run_shim("--specs", str(f), "--language", "cpp",
                         "--out", str(tmp_path / "out"))
        assert proc.returncode == 2
        assert "no records" in proc.stderr
