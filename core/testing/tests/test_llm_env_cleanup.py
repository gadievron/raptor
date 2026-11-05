"""Exercise cancellation and setup failure without starting an egress proxy."""

import pytest

from core.testing.llm_env import PROXY_ENV_VARS, reset_llm_egress_state


@pytest.fixture
def state(monkeypatch):
    from core.llm import egress

    private = {"enabled": True, "original": {"HTTPS_PROXY": "borrowed"}}

    def reset():
        private.update(enabled=False, original=None)

    monkeypatch.setattr(egress, "_reset_for_tests", reset)
    return private


@pytest.mark.parametrize("pin", [False, True])
@pytest.mark.parametrize("exit_kind", ["normal", "close", "error", "interrupt"])
def test_reset_on_generator_exit(monkeypatch, state, pin, exit_kind):
    scope = reset_llm_egress_state(monkeypatch, pin_ollama_host=pin)
    next(scope)
    state.update(enabled=True, original={"HTTPS_PROXY": "test proxy"})
    try:
        if exit_kind == "normal":
            with pytest.raises(StopIteration):
                next(scope)
        elif exit_kind == "close":
            scope.close()
        else:
            error = KeyboardInterrupt if exit_kind == "interrupt" else RuntimeError
            with pytest.raises(error):
                scope.throw(error("cancelled"))
        assert state == {"enabled": False, "original": None}
    finally:
        scope.close()


@pytest.mark.parametrize("var", [*PROXY_ENV_VARS, "OLLAMA_HOST"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_reset_after_setup_failure(monkeypatch, state, var, error):
    class InterruptedPatch:
        def setenv(self, key, value):
            if key == var:
                state.update(enabled=True, original={"HTTPS_PROXY": "partial setup"})
                raise error("setup interrupted")
            monkeypatch.setenv(key, value)

        def delenv(self, key):
            monkeypatch.delenv(key)

    scope = reset_llm_egress_state(InterruptedPatch())
    with pytest.raises(error):
        next(scope)
    assert state == {"enabled": False, "original": None}
