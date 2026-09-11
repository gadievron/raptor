"""Lifecycle handling for a runtime ``SystemExit`` escaping the
``raptor-cve-diff`` pipeline after ``start_run``.

A library calling ``sys.exit`` (or a nested CLI) with a nonzero code
must mark the run record failed before re-raising — otherwise the
``.raptor-run.json`` is stranded in ``running``. ``SystemExit(0)`` is
success and must NOT be recorded as a failure.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-cve-diff"


@pytest.fixture(scope="module")
def cve_diff_mod():
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_cve_diff", str(SCRIPT),
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


def _run_with_pipeline_exit(cve_diff_mod, monkeypatch, tmp_path, code):
    """Drive cmd_run with a stubbed pipeline that raises SystemExit."""
    output_dir = tmp_path / "run"

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("RAPTOR_TRAJECTORY_DIR", "")

    opts = {
        "cve_id": "CVE-2024-12345",
        "budget_multiplier": 1.0,
        "model": "stub-model",
        "output_dir": str(output_dir),
    }
    monkeypatch.setattr(cve_diff_mod, "_parse_run_args", lambda argv: opts)
    monkeypatch.setattr(
        cve_diff_mod, "_resolve_output_dir",
        lambda explicit, cve_id: output_dir,
    )

    def _pipeline(*args, **kwargs):
        raise SystemExit(code)

    monkeypatch.setattr(cve_diff_mod, "_run_pipeline", _pipeline)

    with pytest.raises(SystemExit) as excinfo:
        cve_diff_mod.cmd_run(["CVE-2024-12345"])
    assert excinfo.value.code == code

    from core.json import load_json
    record = load_json(output_dir / ".raptor-run.json")
    assert record is not None, "run record missing"
    return record


class TestSystemExitFailRun:
    def test_nonzero_systemexit_marks_run_failed(
        self, cve_diff_mod, monkeypatch, tmp_path: Path,
    ):
        record = _run_with_pipeline_exit(
            cve_diff_mod, monkeypatch, tmp_path, code=3,
        )
        assert record.get("status") == "failed"
        # fail_run folds the error text into the record's extra dict.
        assert "SystemExit" in ((record.get("extra") or {}).get("error")
                                or record.get("error") or "")

    def test_zero_systemexit_is_not_a_failure(
        self, cve_diff_mod, monkeypatch, tmp_path: Path,
    ):
        record = _run_with_pipeline_exit(
            cve_diff_mod, monkeypatch, tmp_path, code=0,
        )
        assert record.get("status") != "failed"
