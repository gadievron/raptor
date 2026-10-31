"""Unsafe reflection follows callable selectors, not ordinary object data."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_RULE = _ROOT / "rules/php/unsafe-reflection.yaml"
_FIXTURES = _ROOT / "tests/fixtures"
_RULE_ID = "raptor.php.unsafe-reflection.tainted-callable"


@pytest.mark.slow  # Real Semgrep startup can approach the default-tier budget.
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_only_attacker_controlled_selectors_are_reflection_sinks(tmp_path):
    source = """<?php
function fixed_method_on_tainted_object() {
    $obj = new Controller($_POST['arg']);
    $obj->handle();
    $obj->handle($_GET['payload']);
}
function dynamic_method_on_tainted_object() {
    $obj = new Controller($_POST['arg']);
    $method = $_GET['method'];
    $obj->$method(); // reflection
}
function dynamic_method_on_parameter($obj) {
    $method = $_GET['method'];
    $obj->$method('fixed payload'); // reflection
}
function fixed_function_with_tainted_argument() {
    handle($_POST['arg']);
}
function dynamic_function() {
    $fn = $_GET['fn'];
    $fn('fixed payload'); // reflection
}
function fixed_class_with_tainted_argument() {
    return new Controller($_POST['arg']);
}
function dynamic_class() {
    $cls = $_GET['class'];
    return new $cls('fixed payload'); // reflection
}
"""
    target = tmp_path / "selectors.php"
    target.write_text(source)
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--json", str(target),
         str(_FIXTURES / "unsafe_reflection_pos.php"),
         str(_FIXTURES / "unsafe_reflection_neg.php")],
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    expected = {
        "selectors.php": {i for i, line in enumerate(source.splitlines(), 1)
                          if "// reflection" in line},
        "unsafe_reflection_pos.php": {
            i for i, line in enumerate(
                (_FIXTURES / "unsafe_reflection_pos.php").read_text().splitlines(), 1,
            ) if "// reflection" in line
        },
        "unsafe_reflection_neg.php": set(),
    }
    assert expected["unsafe_reflection_pos.php"], "positive fixture needs reflection markers"
    actual = {name: set() for name in expected}
    for result in data["results"]:
        assert result["check_id"].endswith(_RULE_ID), result["check_id"]
        actual[Path(result["path"]).name].add(result["start"]["line"])
    assert actual == expected
