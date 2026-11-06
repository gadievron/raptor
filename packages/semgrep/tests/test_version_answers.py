"""Only successful, unambiguous stable releases establish CLI support."""
from unittest.mock import Mock

import pytest

from core.run.toolprobe import ToolInfo
from packages.semgrep import runner


@pytest.mark.parametrize("stdout,stderr,expected", [
    ("1.177.0\n", "", (1, 177, 0)),
    ("", "1.177.0\n", (1, 177, 0)),
    ("Python 3.14.9\n1.177.0\n", "", (1, 177, 0)),
    ("Python 3.14.9\n", "", None),
    ("1.177.0-rc1\n", "", None),
    ("1.177.0-rc1\n", "1.177.0\n", None),
    ("1.177.0\n", "1.79.0\n", None),
    ("1.177.0\n", "v1.177.0\n", (1, 177, 0)),
    ("x" * (64 * 1024), "1.177.0", None),
])
def test_capability_requires_stable_release(monkeypatch, stdout, stderr, expected):
    info = ToolInfo(name="semgrep", path="/unused", returncode=0,
                    stdout=stdout, stderr=stderr)
    monkeypatch.setattr(runner, "_version_probe", lambda: info)
    assert runner._probe_scope_version(None) == expected


@pytest.mark.parametrize("returncode", [1, -11, None])
def test_failed_version_output_is_not_a_diagnostic_answer(monkeypatch, returncode):
    info = ToolInfo(name="semgrep", path="/unused", returncode=returncode,
                    stdout="1.177.0\n")
    probe = Mock(side_effect=[info, ToolInfo(name="semgrep", path="/unused",
                                          returncode=0, stdout="1.177.0\n")])
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.version() is None
    assert runner.version() == "1.177.0"
