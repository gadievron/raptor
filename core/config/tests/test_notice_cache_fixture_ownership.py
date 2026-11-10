"""Native RAPTOR_DIR tests own notice history without mutating caller caches."""

from contextlib import ExitStack

import pytest

import core.config as config
from core.config.tests import test_raptor_dir_pin as native
from core.testing.module_state import isolated_module_state

KEY = "_RAPTOR_DIR_OVERRIDE_NOTICED"


@pytest.mark.parametrize("mode", ["empty", "foreign", "matching"])
@pytest.mark.parametrize("error", [None, OSError, KeyboardInterrupt, SystemExit])
def test_notice_owner_restores_borrowed_cache_after_body_undo(tmp_path, caplog, mode, error):
    other = str(tmp_path / "other-checkout")
    borrowed = set() if mode == "empty" else {"caller-sentinel"}
    if mode == "matching":
        borrowed.add(other)
    before = set(borrowed)
    failure = error("owned notice body failure") if error else None
    with ExitStack() as scope:
        scope.enter_context(isolated_module_state(config, {KEY: borrowed}))
        if KEY in vars(native):
            # A reintroduced collection-time alias must not hide mutation of
            # the borrowed container when the producer owns a fresh cache.
            scope.enter_context(isolated_module_state(native, {KEY: borrowed}))
        generator = native._owned_override_notice_cache.__wrapped__()

        def invoke():
            try:
                next(generator)
                owned = getattr(config, KEY)
                assert owned is not borrowed and owned == set()
                with pytest.MonkeyPatch.context() as body:
                    body.setattr(config, KEY, {"body-owned"})
                    body.undo()
                    assert getattr(config, KEY) is owned
                    native.TestPinRaptorDir().test_override_notice_once_per_ambient_value(tmp_path, caplog)
                    assert other in owned
                    assert borrowed == before
                    if error:
                        raise failure
            finally:
                generator.close()

        if error:
            with pytest.raises(error) as caught:
                invoke()
            assert caught.value is failure
        else:
            invoke()
        assert getattr(config, KEY) is borrowed
        assert borrowed == before
