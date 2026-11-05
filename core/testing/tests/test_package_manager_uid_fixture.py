"""Install-advice fixtures model non-root operators without changing the host UID."""

import ast
import functools
from contextlib import nullcontext
import os
from pathlib import Path
from types import ModuleType

import pytest

from packages.describe import package_manager


ROOT = Path(__file__).resolve().parents[3]
FILES = ["packages/describe/tests/test_package_manager.py", "packages/describe/tests/test_tool_readiness.py"]


def _view(original):
    view = ModuleType(original.__name__)
    view.__dict__.update(vars(original))
    return view


@pytest.mark.parametrize("path", FILES)
@pytest.mark.parametrize("caller_uid", [0, 1000])
@pytest.mark.parametrize("finish", ["normal", "error", "interrupt", "root_override"])
def test_operator_uid_is_private_and_caller_state_is_restored(monkeypatch, path, caller_uid, finish):
    actual_geteuid = os.geteuid
    caller_os = _view(os)
    caller_os.geteuid = lambda: caller_uid
    caller_tools = _view(package_manager.shutil)
    caller_tools.which = lambda name: "/usr/bin/apt" if name == "apt" else None
    monkeypatch.setattr(package_manager, "os", caller_os)
    monkeypatch.setattr(package_manager, "shutil", caller_tools)
    original = package_manager.detect_package_manager
    borrowed = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    monkeypatch.setattr(package_manager, "detect_package_manager", borrowed)
    for _ in range(5):
        assert borrowed() == "apt"
    stats = borrowed.cache_info()
    namespace = {"__name__": "operator_fixture", "pytest": pytest, "functools": functools,
                 "detect_package_manager": borrowed}
    tree = ast.parse((ROOT / path).read_text())
    fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_isolated_package_manager_cache")
    fixture.decorator_list = []
    exec(compile(ast.Module(body=[fixture], type_ignores=[]), path, "exec"), namespace)
    patch = pytest.MonkeyPatch()

    class BodyFailure(Exception):
        pass

    error = BodyFailure if finish == "error" else KeyboardInterrupt
    expectation = pytest.raises(error) if finish in {"error", "interrupt"} else nullcontext()
    with expectation:
        try:
            namespace[fixture.name](patch)
            assert package_manager.os.geteuid() == 1000
            assert os.geteuid is actual_geteuid
            assert package_manager.format_install_hint(["libtool"]) == "sudo apt install libtool"
            if finish == "root_override":
                # An explicit root-branch test still replaces only its consumer.
                patch.setattr(package_manager.os, "geteuid", lambda: 0)
                assert package_manager.format_install_hint(["libtool"]) == "apt install libtool"
                assert os.geteuid is actual_geteuid
            elif finish in {"error", "interrupt"}:
                raise error
        finally:
            patch.undo()
    assert package_manager.os is caller_os
    assert caller_os.geteuid() == caller_uid
    assert os.geteuid is actual_geteuid
    assert package_manager.shutil is caller_tools
    assert package_manager.detect_package_manager is borrowed
    assert borrowed.cache_info() == stats
    assert namespace["detect_package_manager"] is borrowed
    assert package_manager._sudo_prefix() == ("" if caller_uid == 0 else "sudo ")
