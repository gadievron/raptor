"""Failed native project setup retires its directory without tearDown."""

import importlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import FunctionType
import unittest

import pytest


_CASES = [
    ("core.project.tests.test_add", "TestAddDirectory"),
    ("core.project.tests.test_add", "TestRemoveRun"),
    ("core.project.tests.test_add", "TestAdoptionProjections"),
    ("core.project.tests.test_binary_witness", "BinaryWitnessCliTest"),
    ("core.project.tests.test_binary_witness_mint_race", "MintSwapWindowTest"),
    ("core.project.tests.test_project", "TestProjectManager"),
]


@pytest.mark.parametrize("module,classname", _CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before-construction", "after-construction"])
def test_setup_error_retires_directory_and_restores_patches(module, classname, error, after, tmp_path):
    import core.project.project as model

    owner = importlib.import_module(module)
    cls = getattr(owner, classname)
    case = cls(unittest.TestLoader().getTestCaseNames(cls)[0])
    resources = []
    failure = error("owned project setup constructor failure")
    constructor = owner.ProjectManager
    borrowed_output = model.DEFAULT_OUTPUT_BASE
    before_env = dict(os.environ)

    def temporary(*args, **kwargs):
        kwargs["dir"] = tmp_path
        resource = TemporaryDirectory(*args, **kwargs)
        resources.append(resource)
        return resource

    def manager(*args, **kwargs):
        if after:
            constructor(*args, **kwargs)
        raise failure

    original = cls.setUp
    namespace = dict(vars(owner), TemporaryDirectory=temporary, ProjectManager=manager)
    setup = FunctionType(original.__code__, namespace, original.__name__,
                         original.__defaults__, original.__closure__)
    setup.__kwdefaults__ = original.__kwdefaults__
    try:
        with pytest.raises(error) as caught:
            setup(case)
        assert caught.value is failure
        # unittest runs this stack even when setUp fails; tearDown is not
        # called. Keep the case, resources and traceback alive for the check.
        case.doCleanups()
        assert len(resources) == 1
        assert not Path(resources[0].name).exists()
        assert model.DEFAULT_OUTPUT_BASE is borrowed_output
        assert owner.ProjectManager is constructor
        assert cls.setUp is original
        restored = dict(os.environ) == before_env
        assert restored
    finally:
        case.doCleanups()
        for resource in resources:
            resource.cleanup()
