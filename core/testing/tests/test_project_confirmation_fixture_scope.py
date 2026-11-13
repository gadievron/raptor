"""Confirmation fixtures restore module lookup without changing builtins."""
from contextlib import contextmanager, nullcontext
import builtins

import pytest

from core.project import cli
from core.project.tests import test_cli as native


@pytest.mark.parametrize("method", [
    "test_eof_means_no", "test_yes_and_no_answers",
    "test_merge_without_yes_cancels_on_closed_stdin",
])
@pytest.mark.parametrize("inherited", [False, True], ids=["absent", "present"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_confirmation_fixture_restores_input_lookup(tmp_path, method, inherited, failure):
    original = builtins.input
    missing = object()
    binding = vars(cli).get("input", missing)
    patcher = native.patch
    entered = []

    def borrowed(prompt=""):
        raise AssertionError("inherited input must be replaced for the owned test")

    @contextmanager
    def checked(target, *args, **kwargs):
        assert target == "core.project.cli.input"
        assert kwargs["create"] is True
        with patcher(target, *args, **kwargs) as fake:
            entered.append(fake)
            assert vars(cli)["input"] is fake
            assert builtins.input is original
            yield fake
            fake.assert_called_once()
            assert builtins.input is original
            if failure:
                raise failure("owned body failure")

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with contextmanager(native._user_state_in_tmp.__wrapped__)(tmp_path):
        with pytest.MonkeyPatch.context() as owner:
            native._isolate_os_fault_patches.__wrapped__(owner)
            if inherited:
                owner.setitem(vars(cli), "input", borrowed)
            else:
                owner.delitem(vars(cli), "input", raising=False)
            owner.setattr(native, "patch", checked)
            with expected:
                getattr(native.TestConfirmPrompt(), method)()
            count = 2 if method == "test_yes_and_no_answers" and failure is None else 1
            assert len(entered) == count
            assert vars(cli).get("input", missing) is (borrowed if inherited else missing)
            assert builtins.input is original
        assert vars(cli).get("input", missing) is binding
    assert native.patch is patcher
    assert builtins.input is original
