"""Temporary-grant scenarios do not redirect unrelated scratch users."""
from contextlib import contextmanager, nullcontext
import tempfile

import pytest

from core.sandbox.tests import test_tmp_writable_bind as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_tmp_grant_case_owns_tempfile_view(tmp_path, failure):
    tempdir = tempfile.tempdir
    drop = native._spawn._drop_host_tmpdir_grants
    scope = native.scoped_function_imports
    inherited = str(tmp_path / "borrowed-scratch")
    (tmp_path / "borrowed-scratch").mkdir()
    entered = []
    with contextmanager(native.paths.__wrapped__)() as paths:
        root, _, _ = paths

        @contextmanager
        def checked(module, functions, imports):
            assert module is native._spawn
            assert functions == ("_drop_host_tmpdir_grants",)
            assert imports["tempfile"] is not tempfile
            assert imports["tempfile"].gettempdir() == str(root)
            with scope(module, functions, imports) as private:
                entered.append(private)
                assert private.tempfile.gettempdir() == str(root)
                assert tempfile.tempdir is inherited
                assert tempfile.gettempdir() == inherited
                yield private
                assert tempfile.tempdir is inherited
                if failure:
                    raise failure("owned body failure")

        expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
        with pytest.MonkeyPatch.context() as owner:
            owner.setattr(tempfile, "tempdir", inherited)
            owner.setattr(native, "scoped_function_imports", checked)
            with expected:
                with pytest.MonkeyPatch.context() as patch:
                    native.test_host_tmpdir_baseline_is_not_reintroduced(paths, patch)
            assert len(entered) == 1
            assert native._spawn._drop_host_tmpdir_grants is drop
            assert tempfile.tempdir is inherited
        assert native.scoped_function_imports is scope
        assert tempfile.tempdir is tempdir
