"""Relay fixture streams close before unittest removes their paths after IO failure."""

import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

CHILD = 'import ast\nimport builtins\nimport errno\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport tempfile\nfrom types import SimpleNamespace\nimport unittest\nimport weakref\n\nROOT = Path(os.environ["RELAY_ROOT"])\nSOURCE = ROOT / "packages/autonomous/tests/test_relay_handler_scoping.py"\nMETHOD = os.environ["RELAY_METHOD"]\nTEXT = SOURCE.read_text()\nassert hashlib.sha256(TEXT.encode()).hexdigest() == "87e3af13e2c7eeb80cee089b5d088f7b5bdd39488c5a0629ddafa4f6c98cdb72"\nCLS = next(n for n in ast.parse(TEXT).body if isinstance(n, ast.ClassDef) and n.name == "RelayHandlerLiveTests")\nNODE = next(n for n in CLS.body if isinstance(n, ast.FunctionDef) and n.name == METHOD)\nPINS = {\'_fake_binary\': \'1f61a964cbef8ab3019acb907f4ff0ab89cb5c3e336f95464598943fd07b7904\', \'_one_finding_sarif\': \'b501ba54034b9e95deb65067775e99773714ece9775653ec7be534472482a6c1\'}\nassert hashlib.sha256(ast.get_source_segment(TEXT, NODE).encode()).hexdigest() == PINS[METHOD]\nassert not NODE.decorator_list\nMETA = {}\n\ndef refuse(*args, **kwargs):\n    raise OSError(errno.ENOSPC, "owned relay first write refusal")\n\ndef factory(*args, **kwargs):\n    assert "dir" not in kwargs\n    handle = tempfile.NamedTemporaryFile(*args, dir=os.environ["RELAY_DATA"], **kwargs)\n    st = os.fstat(handle.fileno())\n    META.update(ref=weakref.ref(handle), fd=handle.fileno(), name=handle.name, identity=(st.st_dev, st.st_ino))\n    handle.write = refuse\n    return handle\n\nIMPORT = builtins.__import__\ndef private_import(name, *args, **kwargs):\n    if name == "tempfile":\n        return SimpleNamespace(NamedTemporaryFile=factory)\n    return IMPORT(name, *args, **kwargs)\n\nNS = {"__builtins__": dict(vars(builtins), __import__=private_import), "Path": Path, "os": os}\nexec(compile(ast.Module(body=[NODE], type_ignores=[]), str(SOURCE), "exec"), NS)\nNATIVE = NS[METHOD]\n\nclass TestNativeFailure(unittest.TestCase):\n    def test_first_write(self):\n        self.addCleanup(self.observe_after_path_cleanup)\n        NATIVE(self)\n\n    def observe_after_path_cleanup(self):\n        result = self._outcome.result\n        exact = [entry for info in result._excinfo for entry in info.traceback if entry.frame.code.raw is NATIVE.__code__]\n        retained = len(exact) == 1 and exact[0].frame.f_locals["handle"] is META["ref"]()\n        try:\n            os.fstat(META["fd"])\n        except OSError as exc:\n            consumed = exc.errno == errno.EBADF\n        else:\n            consumed = False\n        record = {"method": METHOD, "native_traceback_retains_handle": retained, "fd_consumed": consumed, "stream_closed": META["ref"]().closed, "pathname_removed": not Path(META["name"]).exists(), "result_type": type(result).__module__ + "." + type(result).__qualname__}\n        Path(os.environ["RELAY_OBSERVATION"]).write_text(json.dumps(record, indent=2) + "\\n")\n        META["ref"]().close()\n'


@pytest.mark.parametrize("method", ["_fake_binary", "_one_finding_sarif"])
def test_relay_descriptor_closes_before_path_cleanup(method, tmp_path):
    root = Path(__file__).resolve().parents[3]
    child = tmp_path / "test_native_failure.py"
    child.write_text(CHILD)
    for name in ("data", "home", "tmp"):
        (tmp_path / name).mkdir()
    observation = tmp_path / "observation.json"
    report = tmp_path / "result.xml"
    env = dict(
        os.environ,
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        HOME=str(tmp_path / "home"),
        TMPDIR=str(tmp_path / "tmp"),
        RELAY_METHOD=method,
        RELAY_ROOT=str(root),
        RELAY_DATA=str(tmp_path / "data"),
        RELAY_OBSERVATION=str(observation),
    )
    result = subprocess.run(
        [
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
            str(child) + "::TestNativeFailure::test_first_write",
            "--basetemp=" + str(tmp_path / "pytest-tmp"),
            "--junitxml=" + str(report),
            "-q",
        ],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    cases = ET.parse(report).findall(".//testcase")
    assert len(cases) == 1 and len(cases[0].findall("failure")) == 1
    assert not cases[0].findall("error") and not cases[0].findall("skipped")
    assert "owned relay first write refusal" in cases[0].find("failure").text
    assert json.loads(observation.read_text()) == {
        "method": method,
        "native_traceback_retains_handle": True,
        "fd_consumed": True,
        "stream_closed": True,
        "pathname_removed": True,
        "result_type": "_pytest.unittest.TestCaseFunction",
    }
    assert not list((tmp_path / "data").iterdir())
