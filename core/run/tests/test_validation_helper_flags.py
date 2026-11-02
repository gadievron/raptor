"""Tests for libexec/raptor-validation-helper's flag parsing.

The helper bundles run-lifecycle management for /validate; its flag
walker bugs (ignored --target=PATH, --target consuming --out as its
value) were CI-invisible without a direct test. Colocated with the
run-lifecycle CLI tests.
"""

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_helper():
    script = str(REPO_ROOT / "libexec" / "raptor-validation-helper")
    loader = SourceFileLoader("raptor_validation_helper", script)
    spec = importlib.util.spec_from_loader(
        "raptor_validation_helper", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)
    return mod


class TestFlagValue:

    def test_space_form(self):
        mod = _load_helper()
        assert mod._flag_value(["0", "--target", "/x"], "--target") == "/x"

    def test_equals_form(self):
        mod = _load_helper()
        assert mod._flag_value(["0", "--target=/x"], "--target") == "/x"

    def test_absent_returns_none(self):
        mod = _load_helper()
        assert mod._flag_value(["0", "--out", "/d"], "--target") is None

    def test_last_occurrence_wins(self):
        mod = _load_helper()
        args = ["0", "--target", "/a", "--target=/b"]
        assert mod._flag_value(args, "--target") == "/b"

    def test_missing_value_errors(self):
        mod = _load_helper()
        with pytest.raises(SystemExit):
            mod._flag_value(["0", "--target"], "--target")

    def test_flag_as_value_errors(self):
        # `--target --out /d` must error, not consume --out.
        mod = _load_helper()
        with pytest.raises(SystemExit):
            mod._flag_value(["A", "wd", "--target", "--out", "/d"],
                            "--target")

    def test_empty_equals_value_errors(self):
        mod = _load_helper()
        with pytest.raises(SystemExit):
            mod._flag_value(["0", "--out="], "--out")

    def test_prefix_flag_not_confused(self):
        # --sanitizer-cut must not match --sanitizer-cut-parity-log.
        mod = _load_helper()
        args = ["0", "--sanitizer-cut-parity-log", "/log"]
        assert mod._flag_value(args, "--sanitizer-cut") is None
        assert mod._flag_value(args, "--sanitizer-cut-parity-log") == "/log"

    def test_project_name_space_form(self):
        mod = _load_helper()
        assert mod._flag_value(["0", "--project", "myapp"],
                               "--project") == "myapp"

    def test_project_bare_dash_space_form(self):
        # `--project -` = explicitly projectless (core/run/pin.py);
        # the usage string advertises `--project <name|->`.
        mod = _load_helper()
        assert mod._flag_value(["0", "--project", "-"],
                               "--project") == "-"

    def test_project_bare_dash_equals_form(self):
        mod = _load_helper()
        assert mod._flag_value(["0", "--project=-"], "--project") == "-"

    def test_flag_shaped_value_still_errors(self):
        # Bare `-` is legal; flag-shaped tokens are still a missing
        # value in both forms.
        mod = _load_helper()
        with pytest.raises(SystemExit):
            mod._flag_value(["0", "--project", "--out"], "--project")
        with pytest.raises(SystemExit):
            mod._flag_value(["0", "--project=--out"], "--project")
