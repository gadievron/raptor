"""Preset writes in libexec/raptor-tune.

Loads the script as a module (SourceFileLoader precedent) and points
its _TUNING_PATH at a tmp file so no real repo state is touched.
Preset rewrites must apply the profile values AND preserve valid
operator-set passthrough keys (max_llm_workers, throttle_cooldown_s)
that no preset produces.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

from core.json import load_json_with_comments

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-tune"


@pytest.fixture
def tune_mod(monkeypatch, tmp_path):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    loader = importlib.machinery.SourceFileLoader(
        "raptor_tune_under_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    mod._TUNING_PATH = tmp_path / "tuning.json"
    return mod


def test_preset_applies_values_and_preserves_passthrough(tune_mod):
    path = tune_mod._TUNING_PATH
    path.write_text(json.dumps({
        "codeql_ram_mb": 1234,
        "max_llm_workers": 4,
        "throttle_cooldown_s": 7,
    }))

    tune_mod._write_tuning(tune_mod._default_values())

    raw = load_json_with_comments(path)
    # Direction 1: the preset value replaced the operator's override.
    assert raw["codeql_ram_mb"] == "auto"
    # Direction 2: valid passthrough keys the preset never produces survive.
    assert raw["max_llm_workers"] == 4
    assert raw["throttle_cooldown_s"] == 7
    # Every shipped-default key is present.
    for key in tune_mod._DEFAULTS:
        assert key in raw


def test_preset_write_from_scratch_has_all_default_keys(tune_mod):
    path = tune_mod._TUNING_PATH
    assert not path.exists()
    tune_mod._write_tuning(tune_mod._default_values())
    raw = load_json_with_comments(path)
    assert set(tune_mod._DEFAULTS) <= set(raw)
    # No stray tmp file left behind (the writer is atomic tmp+rename).
    leftovers = [p for p in path.parent.iterdir() if p.name != path.name]
    assert leftovers == []


def test_preset_drops_unknown_keys(tune_mod):
    # Unknown keys are not valid tuning config; the canonical writer's
    # contract keeps only _VALID_KEYS, so a typo'd key does not persist.
    path = tune_mod._TUNING_PATH
    path.write_text(json.dumps({"not_a_real_key": 1, "max_llm_workers": 2}))
    tune_mod._write_tuning(tune_mod._default_values())
    raw = load_json_with_comments(path)
    assert "not_a_real_key" not in raw
    assert raw["max_llm_workers"] == 2


def test_written_file_loads_through_core_tuning(tune_mod):
    from core.tuning import load_tuning
    path = tune_mod._TUNING_PATH
    path.write_text(json.dumps({"joern_cpg_timeout_s": 42}))
    values = dict(tune_mod._default_values())
    values["joern_cpg_timeout_s"] = 99
    tune_mod._write_tuning(values)
    t = load_tuning(path)
    assert t.joern_cpg_timeout_s == 99


def test_main_help_and_unknown_profile(tune_mod, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["raptor-tune", "--help"])
    assert tune_mod.main() == 0
    monkeypatch.setattr("sys.argv", ["raptor-tune", "bogus"])
    assert tune_mod.main() == 1
    err = capsys.readouterr().err
    assert "Unknown profile" in err
