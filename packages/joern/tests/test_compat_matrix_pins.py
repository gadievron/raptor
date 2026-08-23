"""sha256 pin helpers of the compat-matrix dev tool.

The matrix downloads release archives and EXECUTES the extracted
launcher, so pin verification is the only integrity gate between a
release asset and code execution on the dev host. These tests drive
the pure helpers directly — no network, no downloads.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compat_matrix.py"


@pytest.fixture(scope="module")
def cm():
    spec = importlib.util.spec_from_file_location("compat_matrix", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verify_pin_mismatch_raises(cm):
    pins = {"v1.0.0/joern-cli.zip": "a" * 64}
    with pytest.raises(RuntimeError, match="sha256 mismatch"):
        cm._verify_pin(pins, "v1.0.0", "joern-cli.zip", "b" * 64)


def test_verify_pin_match_is_case_insensitive(cm):
    pins = {"v1.0.0/joern-cli.zip": "AB" * 32}
    assert cm._verify_pin(pins, "v1.0.0", "joern-cli.zip", "ab" * 32)


def test_verify_pin_absent_returns_false(cm):
    assert not cm._verify_pin({}, "v1.0.0", "joern-cli.zip", "a" * 64)


def test_tag_has_pin_checks_all_candidate_assets(cm):
    # Either the per-platform archive or the platform-independent
    # joern-cli.zip pin satisfies the pre-download gate.
    assert cm._tag_has_pin({"v1.0.0/joern-cli.zip": "a" * 64}, "v1.0.0")
    assert not cm._tag_has_pin({"v9.9.9/joern-cli.zip": "a" * 64}, "v1.0.0")


def test_save_and_load_pins_round_trip(cm, tmp_path):
    path = tmp_path / "pins.json"
    pins = {
        "v2.0.0/joern-cli.zip": "b" * 64,
        "v1.0.0/joern-cli.zip": "a" * 64,
    }
    cm._save_pins(pins, path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    # Documentation key present on disk, stripped on load.
    assert raw["_comment"]
    assert path.read_text(encoding="utf-8").endswith("\n")
    assert cm._load_pins(path) == pins
    # Keys are sorted for stable diffs.
    data_keys = [k for k in raw if not k.startswith("_")]
    assert data_keys == sorted(data_keys)


def test_load_pins_tolerates_missing_and_garbage(cm, tmp_path):
    assert cm._load_pins(tmp_path / "absent.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert cm._load_pins(bad) == {}
    wrong_shape = tmp_path / "list.json"
    wrong_shape.write_text("[1, 2]", encoding="utf-8")
    assert cm._load_pins(wrong_shape) == {}


def test_repo_pins_file_parses(cm):
    # The checked-in sidecar must always load (an unparseable file
    # silently disables every pin).
    assert isinstance(cm._load_pins(), dict)
