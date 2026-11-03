"""Readable IDs retain payloads, explicit labels, and pytest selection."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

import pytest

from core.testing.param_ids import pytest_make_parametrize_id as case_id

pytest_plugins = "pytester"


@pytest.mark.parametrize("value", ["linux", "clang++", "CWE-787", "src/file.c", 3, None, False],
                         ids=["platform", "compiler", "cwe", "path", "integer", "none", "boolean"])
def test_ordinary_values_use_pytest_defaults(value):
    assert case_id(value, "value") is None


@pytest.mark.parametrize("value", ["[" * 10000 + "]" * 10000, b"\xff", "x\nforged", "x\0y",
                                  "\ud800.c", "café.py", "00" * 33, "int f(void) { return 0; }",
                                  re.compile(r"x\ny"), "", b"", "[" * 40 + "]" * 40,
                                  "return redirect(request.args['next'])"],
                         ids=["deep-json", "invalid-utf8", "newline", "nul", "surrogate",
                              "unicode", "long-digest", "source", "regex", "empty-text", "empty-bytes", "brackets", "return-fragment"])
def test_payload_ids_are_short_ascii_and_stable(value):
    result = case_id(value, "payload")
    assert result == case_id(value, "payload")
    assert result is not None and len(result) <= 80 and result.isascii()
    assert re.fullmatch(r"[A-Za-z0-9_-]+", result)
    assert "\\" not in result and "[" not in result


def test_distinct_payloads_and_types_have_distinct_suffixes():
    ids = {case_id(value, "payload") for value in ("a" * 500, "b" * 500, b"a" * 500)}
    assert len(ids) == 3


def test_control_characters_have_readable_names():
    assert case_id("\n", "separator") == "separator-line-feed"
    assert case_id("\u2028", "separator") == "separator-line-separator"
    assert case_id(b"\xff", "payload") == "payload-byte-ff"


def test_real_pytest_preserves_data_explicit_ids_and_selection(pytester, monkeypatch):
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    monkeypatch.delenv("PYTEST_ADDOPTS", raising=False)
    helper = Path(__file__).resolve().parents[1] / "param_ids.py"
    pytester.makepyfile(param_ids=helper.read_text())
    pytester.makepyfile(test_cases='''
import pytest
VALUES = ["[" * 10000 + "]" * 10000, b"\\xff", "a\\nb", "linux"]
@pytest.mark.parametrize("payload", VALUES + [pytest.param(VALUES[0], id="explicit-depth")])
def test_payload(payload):
    assert payload in VALUES
@pytest.mark.parametrize("left", ["int f(void) { return 0; }", "plain"])
@pytest.mark.parametrize("right", [b"\\xff", "ok"])
def test_stacked(left, right):
    assert isinstance(left, str) and right in (b"\\xff", "ok")
@pytest.mark.parametrize("payload", ["x\\ny"], ids=lambda value: "callback-label")
def test_callback(payload):
    assert payload == "x\\ny"
def pytest_generate_tests(metafunc):
    if "generated" in metafunc.fixturenames:
        metafunc.parametrize("generated", ["x\\ny", "z" * 200])
def test_generated(generated):
    assert generated in ("x\\ny", "z" * 200)
''')
    options = ["-c", str(pytester.makeini("[pytest]")), "--noconftest", "-p", "param_ids"]
    xml = pytester.path / "results.xml"
    result = pytester.runpytest_subprocess(*options, "-v", "--junitxml=" + str(xml))
    result.assert_outcomes(passed=12)
    names = [case.get("name") for case in ET.parse(xml).iter("testcase")]
    assert len(names) == 12 and all(len(name) < 160 and name.isascii() for name in names)
    assert "test_payload[explicit-depth]" in names
    output = result.stdout.str()
    assert "test_payload[explicit-depth]" in output
    assert "test_callback[callback-label]" in output
    assert "test_payload[linux]" in output
    assert "[[[[[[[[" not in output and "\\\\xff" not in output
    node = "test_cases.py::test_payload[" + case_id("a\nb", "payload") + "]"
    selected = pytester.runpytest_subprocess(*options, node, "-q")
    selected.assert_outcomes(passed=1)


def test_naming_does_not_invoke_payload_overrides():
    class Text(str):
        def encode(self, *args, **kwargs):
            pytest.fail("payload encode override was invoked")

    class Bytes(bytes):
        def decode(self, *args, **kwargs):
            pytest.fail("payload decode override was invoked")

    assert case_id(Text("x\ny"), "payload") == case_id("x\ny", "payload")
    assert case_id(Bytes(b"\xff\x00"), "payload") == case_id(b"\xff\x00", "payload")
