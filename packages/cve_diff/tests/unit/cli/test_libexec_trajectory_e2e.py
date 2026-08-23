"""End-to-end test for trajectory env-var wiring through the
``libexec/raptor-cve-diff`` shim.

Loads the shim as a module and drives ``main()`` with the Pipeline
mocked. Asserts that by the time the Pipeline is invoked,
``RAPTOR_TRAJECTORY_DIR`` is set to the resolved output directory —
which is the contract the agent loop relies on for trajectory
persistence (see ``core.trajectories.auto.persist_from_loop_result``).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[5]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-cve-diff"


def _load_shim():
    """Import libexec/raptor-cve-diff as a module. The session-wide
    ``_RAPTOR_TRUSTED=1`` env var lets the trust-marker check pass."""
    loader = SourceFileLoader("raptor_cve_diff_e2e", str(LIBEXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_cve_diff_shim_sets_trajectory_env_var_before_pipeline_runs(
    tmp_path, monkeypatch,
):
    """The shim must set RAPTOR_TRAJECTORY_DIR to the resolved
    --output-dir BEFORE Pipeline.run is invoked. The agent loop
    inside the pipeline reads this env var; if the assignment
    happens too late (after Pipeline initialisation, in a different
    function, etc.) operators get no trajectories.

    We assert it from inside the patched Pipeline.run — that's the
    exact moment the loop will later read the env var.
    """
    out_dir = tmp_path / "out"
    # Defensive: the shim sets RAPTOR_TRAJECTORY_DIR via os.environ.
    # Register the existing value (or absence) with monkeypatch so the
    # mutation is undone at teardown instead of leaking forward.
    monkeypatch.delenv("RAPTOR_TRAJECTORY_DIR", raising=False)

    seen = {}

    class _FakePipeline:
        def __init__(self, **_kw):
            self.agent = type("A", (), {"last_telemetry": None})()

        def run(self, cve_id, work_dir):
            # Capture state at the moment the pipeline runs — which
            # is also when the agent loop would read the env var.
            seen["trajectory_dir"] = os.environ.get("RAPTOR_TRAJECTORY_DIR")
            seen["cve_id"] = cve_id
            # Raise a known error so the shim returns cleanly without
            # needing real GitHub / OSV / disk artefacts.
            from cve_diff.core.exceptions import UnsupportedSource
            raise UnsupportedSource("test stub: pipeline mocked")

    mod = _load_shim()

    argv = [
        "raptor-cve-diff",
        "run",
        "CVE-2024-12345",
        "--output-dir", str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", argv)

    # Patch Pipeline at the import site. The shim imports inside the
    # `main()` body so we patch the source module.
    with patch("cve_diff.pipeline.Pipeline", _FakePipeline):
        rc = mod.main()

    # UnsupportedSource → exit code 4 (per the shim's error_map).
    assert rc == 4, f"unexpected rc {rc}"

    # The contract: env var was set to the resolved output dir BEFORE
    # the pipeline began. If the assignment moved after or got
    # dropped, this fails.
    assert seen.get("cve_id") == "CVE-2024-12345"
    assert seen.get("trajectory_dir") == str(out_dir), (
        f"RAPTOR_TRAJECTORY_DIR not set to output_dir when Pipeline "
        f"ran. Got {seen.get('trajectory_dir')!r} expected {str(out_dir)!r}"
    )


def test_cve_diff_shim_overrides_pre_set_trajectory_env_var(
    tmp_path, monkeypatch,
):
    """If the operator already exported RAPTOR_TRAJECTORY_DIR, the
    shim overrides it to --output-dir so trajectories land with the
    rest of the run's artefacts."""
    out_dir = tmp_path / "out"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    monkeypatch.setenv("RAPTOR_TRAJECTORY_DIR", str(foreign))

    seen = {}

    class _FakePipeline:
        def __init__(self, **_kw):
            self.agent = type("A", (), {"last_telemetry": None})()

        def run(self, cve_id, work_dir):
            seen["trajectory_dir"] = os.environ.get("RAPTOR_TRAJECTORY_DIR")
            from cve_diff.core.exceptions import UnsupportedSource
            raise UnsupportedSource("test stub")

    mod = _load_shim()

    argv = [
        "raptor-cve-diff", "run", "CVE-2024-99999",
        "--output-dir", str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", argv)

    with patch("cve_diff.pipeline.Pipeline", _FakePipeline):
        mod.main()

    # Override: env var points at --output-dir, NOT the operator's
    # pre-set foreign value.
    assert seen.get("trajectory_dir") == str(out_dir), (
        f"shim did not override pre-set RAPTOR_TRAJECTORY_DIR. "
        f"Got {seen.get('trajectory_dir')!r}"
    )
