"""The real review CLI child receives an owned interpreter environment."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys

import pytest


@pytest.mark.slow
@pytest.mark.parametrize("stale_launch", [False, True])
@pytest.mark.parametrize("key", ["PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE"])
@pytest.mark.parametrize("value", [None, "", "/owned/interpreter-override"],
                         ids=["missing", "empty", "borrowed"])
def test_review_parser_child_preserves_parent(tmp_path, monkeypatch, key, value, stale_launch):
    if value is None:
        monkeypatch.delenv(key, raising=False)
    else:
        monkeypatch.setenv(key, value)
    environment = dict(os.environ)
    path, values = sys.path, list(sys.path)
    source = Path(__file__).resolve().parents[3] / "core/audit/tests/test_review_cli_toolruns.py"
    loader = importlib.machinery.SourceFileLoader("owned_review_parser_probe", str(source))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    with monkeypatch.context() as child_patch:
        child_patch.setenv("XDG_DATA_HOME", str(tmp_path / "data-home"))
        module.TestToolsCommand().test_subcommand_registered_in_cli(
            tmp_path, child_patch, stale_launch,
        )
    assert dict(os.environ) == environment
    assert sys.path is path
    assert sys.path == values
