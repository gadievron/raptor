"""The validation helper's workdir reads pay the shared default budget.

``libexec/raptor-validation-helper`` reads findings.json (and the
other working documents) through ``core.json.load_json`` with no
site-specific budget, so it must inherit the loader's
capped-by-default contract: an oversized findings.json is refused
(the reader returns ``None``, the missing-file shape every stage
already tolerates), a normal one still loads. The budget is
tightened via the module constant (resolved per call) so the probe
costs kilobytes, not the real cap.
"""

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_helper():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = str(REPO_ROOT / "libexec" / "raptor-validation-helper")
    loader = SourceFileLoader("raptor_validation_helper", script)
    spec = importlib.util.spec_from_loader("raptor_validation_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _tighten(monkeypatch, helper, budget: int = 1024) -> None:
    # Patch the constant in the loader module the helper actually
    # bound (via the function's own globals): suites that reset
    # core.json in sys.modules can leave a static import here
    # pointing at a different module object than the one the
    # freshly-executed script re-imported.
    monkeypatch.setitem(
        helper.load_json.__globals__, "DEFAULT_JSON_MAX_BYTES", budget,
    )


def test_oversized_findings_refused(tmp_path, monkeypatch):
    helper = _load_helper()
    _tighten(monkeypatch, helper)
    (tmp_path / "findings.json").write_text(
        json.dumps({"findings": [], "pad": "x" * 4096}), encoding="utf-8",
    )
    assert helper._findings(str(tmp_path)) is None


def test_normal_findings_flow(tmp_path, monkeypatch):
    helper = _load_helper()
    _tighten(monkeypatch, helper)
    (tmp_path / "findings.json").write_text(
        json.dumps({"findings": []}), encoding="utf-8",
    )
    assert helper._findings(str(tmp_path)) == {"findings": []}
