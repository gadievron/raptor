"""Run each real-caplog ownership check in a fresh one-case pytest child."""

import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[3]
PROBE = Path(__file__).with_name("_osv_caplog_fixture_probe.py")
EXPECTED_CLOSED = True
CASES = [
    "test_unmapped_ecosystem_warns_visibly",
    "test_known_no_coverage_ecosystem_stays_silent",
]


def run_child(tmp_path, case, deny):
    output = tmp_path / "child"
    output.mkdir()
    for directory in ["home", "tmp", "config", "cache", "data"]:
        (output / directory).mkdir()
    environment = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT")
        if key in os.environ
    }
    environment.update(
        HOME=str(output / "home"),
        TMPDIR=str(output / "tmp"),
        XDG_CONFIG_HOME=str(output / "config"),
        XDG_CACHE_HOME=str(output / "cache"),
        XDG_DATA_HOME=str(output / "data"),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
    )
    mode = "schema-refusal" if deny else "setup-boundary"
    node = str(PROBE) + "::test_caplog_child[" + mode + "-" + case + "]"
    argv = [
        sys.executable,
        "-I",
        "-m",
        "pytest",
        "--noconftest",
        "-o",
        "addopts=",
        "-p",
        "no:cacheprovider",
        "-p",
        "no:faulthandler",
        node,
        "--basetemp=" + str(output / "pytest-tmp"),
        "--junitxml=" + str(output / "results.xml"),
        "-q",
    ]
    try:
        result = subprocess.run(
            argv,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        for name, value in [("stdout", exc.stdout), ("stderr", exc.stderr)]:
            if isinstance(value, bytes):
                value = value.decode(errors="replace")
            (output / name).write_text(value or "")
        (output / "receipt.json").write_text(
            json.dumps({"argv": argv, "cwd": str(ROOT), "timed_out": True}) + "\n"
        )
        pytest.fail("owned one-case pytest child timed out")
    (output / "stdout").write_text(result.stdout)
    (output / "stderr").write_text(result.stderr)
    (output / "receipt.json").write_text(
        json.dumps(
            {
                "argv": argv,
                "cwd": str(ROOT),
                "exit": result.returncode,
                "timed_out": False,
            }
        )
        + "\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    xml = ET.parse(output / "results.xml")
    cases = xml.findall(".//testcase")
    assert len(cases) == 1
    assert cases[0].attrib["name"] == "test_caplog_child[" + mode + "-" + case + "]"
    assert not any(
        xml.findall(".//" + name) for name in ["failure", "error", "skipped"]
    )
    observations = list(
        (output / "pytest-tmp").rglob("caplog-ownership-observation.json")
    )
    assert len(observations) == 1
    observation = json.loads(observations[0].read_text())
    assert observation["case"] == case and observation["deny"] is deny
    assert observation["closed_before_rescue"] is EXPECTED_CLOSED
    assert observation["owner_cleared"] is EXPECTED_CLOSED
    assert observation["http_calls"] == []
    assert observation["before_logging"] == observation["after_logging"]
    assert len(observation["close_states"]) == int(EXPECTED_CLOSED)
    assert all(
        state == observation["before_logging"] for state in observation["close_states"]
    )
    assert len(observation["seams"]) == 1
    assert (
        observation["seams"][0]["target_level"]
        == observation["seams"][0]["capture_level"]
        == 30
    )
    assert observation["real_caplog_type"] == "LogCaptureFixture"
    (tmp_path / "qualified-child-observation.json").write_text(
        json.dumps(observation) + "\n"
    )


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize(
    "deny", [False, True], ids=["setup-boundary", "schema-refusal"]
)
def test_caplog_fixture_owns_schema_connection(tmp_path, case, deny):
    run_child(tmp_path, case, deny)
