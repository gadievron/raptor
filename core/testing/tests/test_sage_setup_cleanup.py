"""SAGE fixture setup owns its files before fallible IO, without running flows."""

import builtins
import importlib
import os
from pathlib import Path
import tempfile
from types import FunctionType, ModuleType
import unittest

import pytest


_CASES = [
    ("test_sage_client", "TestHardenIdentityKeyPerms", "mkdir"),
    ("test_sage_hooks", "TestFindingSourceHashes", "write_text"),
    ("test_sage_hooks", "TestComputeFindingSourceHash", "write_text"),
    ("test_sage_mcp_guard", "_GuardHarness", "write_text"),
    ("test_sage_mcp_wrapper_reexec", "TestSgReExec", "mkdir"),
    ("test_sage_setup_migration", "TestSageSetupMigration", "mkdir"),
    ("test_sage_setup_reauthorize", "_AuthorizeBootPayloadCase", "extract"),
    ("test_sage_setup_reexec_quoting", "TestSgReExecQuoting", "mkdir"),
]


@pytest.mark.parametrize("module,classname,operation", _CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before-io", "after-io"])
def test_setup_io_error_retires_owned_directory(module, classname, operation, error, after, tmp_path):
    _exercise(module, classname, operation, error, after, tmp_path)


@pytest.mark.parametrize("module,classname,operation", _CASES)
def test_native_setup_and_teardown_remain_usable(module, classname, operation, tmp_path):
    _exercise(module, classname, operation, None, False, tmp_path)


def _exercise(module, classname, operation, error, after, tmp_path):
    owner = importlib.import_module("core.sage.tests." + module)
    cls = getattr(owner, classname)
    names = unittest.TestLoader().getTestCaseNames(cls)
    case = cls(names[0] if names else "runTest")
    resources = []
    failure = error("owned native fixture setup IO failure") if error else None
    before_env = dict(os.environ)
    fired = False

    def temporary(*args, **kwargs):
        kwargs["dir"] = tmp_path
        resource = tempfile.TemporaryDirectory(*args, **kwargs)
        resources.append(resource)
        return resource

    class FaultPath(type(Path())):
        def mkdir(self, *args, **kwargs):
            nonlocal fired
            if operation == "mkdir" and not fired:
                fired = True
                if after:
                    super().mkdir(*args, **kwargs)
                raise failure
            return super().mkdir(*args, **kwargs)

        def write_text(self, *args, **kwargs):
            nonlocal fired
            if operation == "write_text" and not fired:
                fired = True
                if after:
                    super().write_text(*args, **kwargs)
                raise failure
            return super().write_text(*args, **kwargs)

    original_extract = getattr(owner, "_extract_function", None)

    def extract(*args, **kwargs):
        nonlocal fired
        fired = True
        if after:
            original_extract(*args, **kwargs)
        raise failure

    paths = ModuleType("pathlib")
    vars(paths).update(vars(importlib.import_module("pathlib")))
    paths.Path = FaultPath if failure else Path
    temps = ModuleType("tempfile")
    vars(temps).update(vars(tempfile))
    temps.TemporaryDirectory = temporary

    def importing(name, *args, **kwargs):
        if name == "tempfile":
            return temps
        if name == "pathlib":
            return paths
        return builtins.__import__(name, *args, **kwargs)

    original = cls.setUp
    namespace = dict(vars(owner), tempfile=temps, Path=paths.Path,
                     __builtins__=dict(vars(builtins), __import__=importing))
    if failure and operation == "extract":
        namespace["_extract_function"] = extract
    setup = FunctionType(original.__code__, namespace, original.__name__,
                         original.__defaults__, original.__closure__)
    setup.__kwdefaults__ = original.__kwdefaults__
    try:
        if failure:
            with pytest.raises(error) as caught:
                setup(case)
            assert caught.value is failure
            assert fired
        else:
            setup(case)
            assert len(resources) == 1 and Path(resources[0].name).is_dir()
            # Exercise the original fixture-only positive path, including
            # generated files and extracted driver text; execute no drivers.
            if hasattr(case, "key"):
                assert case.key.is_file()
            if hasattr(case, "path"):
                assert case.path.is_file()
            if hasattr(case, "fixture"):
                assert case.fixture.is_file()
            if hasattr(case, "bindir"):
                assert (case.bindir / "docker").is_file() and (case.bindir / "sg").is_file()
            if hasattr(case, "checkout"):
                assert (case.checkout / "libexec/raptor-sage-setup").is_file()
            if hasattr(case, "driver"):
                assert "authorize_boot_payload" in case.driver
            case.tearDown()
        # unittest invokes this even on failed setUp, when tearDown is
        # skipped. Retain the traceback and case until after checking it.
        case.doCleanups()
        assert len(resources) == 1
        assert not Path(resources[0].name).exists()
        assert cls.setUp is original
        restored = dict(os.environ) == before_env
        assert restored
    finally:
        case.doCleanups()
        for resource in resources:
            resource.cleanup()
