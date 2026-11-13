"""Checklist timeout fixtures preserve inherited loaded CLI and override state."""
from contextlib import contextmanager, nullcontext
import os

import pytest

from core.audit.tests import test_checklist_build_timeout as native


@pytest.mark.parametrize("preloaded", [False, True], ids=["empty", "loaded"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_scaling_fixture_restores_inherited_cache(tmp_path, preloaded, failure):
    original = native._CLI_MOD
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "_CLI_MOD", None)
        inherited = native._load_cli() if preloaded else None
        snapshot = dict(vars(inherited)) if inherited is not None else None
        owner.setenv(native.ENV, "12000")
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                with contextmanager(native._no_override.__wrapped__)(patch):
                    assert native._CLI_MOD is None
                    assert native.ENV not in os.environ
                    native.TestScalingFunction().test_small_source_tree_keeps_the_floor(tmp_path)
                    assert native._CLI_MOD is not None
                    assert native._CLI_MOD is not inherited
                    if failure:
                        raise failure("owned body failure")
        assert native._CLI_MOD is inherited
        assert os.environ[native.ENV] == "12000"
        if snapshot is not None:
            assert vars(inherited).keys() == snapshot.keys()
            assert all(vars(inherited)[key] is value for key, value in snapshot.items())
    assert native._CLI_MOD is original
