"""The symbolic sweep's replay gate resolves the RUN PIN's project.

``raptor-audit sweep --tool symbolic`` gates witness REPLAY (which
executes the target) on dynamic trust. That resolution must carry
``run_dir=out_dir`` — the audit run's pin — so the marker lookup
answers from the project the run is pinned to, never the launching
session's ambient project.
"""

from __future__ import annotations

import argparse
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_replaygate", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_replaygate", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestSymbolicSweepReplayGateRunDir:

    def test_symbolic_sweep_gate_passes_out_dir_as_run_dir(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mod = _load_cli()
        import core.audit.sweep as sweep_mod
        import core.project.trust as trust

        seen: dict = {}

        def fake_gate(explicit, *, banner=True, target_path=None,
                      run_dir=None):
            seen["run_dir"] = run_dir
            return False

        class _Stop(RuntimeError):
            pass

        def fake_symbolic_sweep(**kwargs):
            seen["replay"] = kwargs.get("replay")
            raise _Stop  # capture done; skip the log-append tail

        monkeypatch.setattr(trust, "resolve_dynamic_validation", fake_gate)
        monkeypatch.setattr(sweep_mod, "run_symbolic_sweep",
                            fake_symbolic_sweep)

        out_dir = tmp_path / "audit-out"
        out_dir.mkdir()
        target = tmp_path / "code"
        target.mkdir()
        args = argparse.Namespace(
            out=str(out_dir), target=str(target), tool="symbolic",
            file="bin:app", function="f", rule=None, rule_file=None,
            cwe="", line_start=None, line_end=None, codeql_db=None)
        with pytest.raises(_Stop):
            mod.cmd_sweep(args)
        # The gate ran, refused (replay=False rode through), AND
        # received the audit run dir — the kwarg that routes the
        # marker lookup through the (witnessed) run pin.
        assert seen["replay"] is False
        assert seen["run_dir"] is not None
        assert Path(seen["run_dir"]) == out_dir
