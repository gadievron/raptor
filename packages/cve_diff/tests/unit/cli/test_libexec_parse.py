"""Argument-parsing contract for ``libexec/raptor-cve-diff run``.

The parser is argparse (libexec convention) but must keep the shim's
documented behaviours: exit 1 on usage errors (2 is the trust-marker
code), all historical option forms including ``--opt=value`` and
``-o=DIR``, and the budget-multiplier sanity range.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[5]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-cve-diff"


def _shim():
    loader = SourceFileLoader("raptor_cve_diff_parse", str(LIBEXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    # The shim's import-time path setup (sys.path.insert of the repo
    # root / its package dir) must not leak process-wide: a leaked
    # packages/<pkg> prepend shadows the sibling package's bare
    # 'tests' test-package for every LATER fresh import in this
    # process — including multiprocessing forkserver children, which
    # freeze sys.path at first pool use (an unpickle in the child then
    # fails with ModuleNotFoundError on the victim's test module).
    # The shim's own imports resolve during exec; nothing needs the
    # leaked entries afterwards (pytest.ini pythonpath + the root
    # conftest already pin the canonical entries).
    path_before = list(sys.path)
    try:
        loader.exec_module(mod)
    finally:
        sys.path[:] = path_before
    return mod


@pytest.fixture(scope="module")
def shim():
    return _shim()


def test_defaults(shim):
    opts = shim._parse_run_args(["CVE-2024-12345"])
    assert opts == {
        "cve_id": "CVE-2024-12345",
        "output_dir": None,
        "budget_multiplier": 1.0,
        "with_root_cause": False,
        "model": None,
    }


@pytest.mark.parametrize("argv", [
    ["CVE-2024-1", "--output-dir", "/tmp/x"],
    ["CVE-2024-1", "--output-dir=/tmp/x"],
    ["CVE-2024-1", "-o", "/tmp/x"],
    ["CVE-2024-1", "-o=/tmp/x"],
])
def test_output_dir_forms(shim, argv):
    assert shim._parse_run_args(argv)["output_dir"] == "/tmp/x"


def test_all_options_together(shim):
    opts = shim._parse_run_args([
        "CVE-2024-1", "--budget-multiplier=2.5", "--with-root-cause",
        "--model", "gemini-2.5-pro", "-o", "outdir",
    ])
    assert opts["budget_multiplier"] == 2.5
    assert opts["with_root_cause"] is True
    assert opts["model"] == "gemini-2.5-pro"
    assert opts["output_dir"] == "outdir"


@pytest.mark.parametrize("bad", ["nan", "inf", "-1", "0", "0.05", "101", "x"])
def test_budget_multiplier_rejects_unsane_values(shim, bad, capsys):
    with pytest.raises(SystemExit) as exc:
        shim._parse_run_args(["CVE-2024-1", "--budget-multiplier", bad])
    assert exc.value.code == 1


def test_unknown_option_exits_1(shim):
    with pytest.raises(SystemExit) as exc:
        shim._parse_run_args(["CVE-2024-1", "--frobnicate"])
    assert exc.value.code == 1


def test_missing_cve_id_exits_1(shim):
    with pytest.raises(SystemExit) as exc:
        shim._parse_run_args([])
    assert exc.value.code == 1
