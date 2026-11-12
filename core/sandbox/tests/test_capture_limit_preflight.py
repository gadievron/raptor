"""Capture limits are validated before the native dispatch can execute work."""

import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.test_context_decision_pins import _Driver, _SpawnRecorder
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux dispatcher preparation")


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    recorder = _SpawnRecorder()
    _Driver(monkeypatch, recorder)

    def forbid_process(*args, **kwargs):
        pytest.fail("capture preflight must not launch a process")

    monkeypatch.setattr(context, "_run_teardown_first_timeout", forbid_process)
    patch_module_attribute(monkeypatch, context, "subprocess", "Popen", forbid_process)
    return recorder


@pytest.mark.parametrize("cap,kind", [("invalid", ValueError), (float("nan"), ValueError),
                                      (float("inf"), OverflowError)])
def test_invalid_limit_refuses_before_dispatch(prepared, tmp_path, cap, kind):
    with context.sandbox(profile="full", target=str(tmp_path)) as run:
        with pytest.raises(kind):
            run(["/bin/true"], max_capture_bytes=cap, capture_output=True, timeout=1)
    assert prepared.calls == []


@pytest.mark.parametrize("cap,expected", [(-1, 0), (0, 0), (4, 4), ("4", 4)])
def test_finite_limit_normalisation_reaches_dispatch(prepared, tmp_path, cap, expected):
    with context.sandbox(profile="full", target=str(tmp_path)) as run:
        result = run(["/bin/true"], max_capture_bytes=cap, capture_output=True, timeout=1)
    assert result.returncode == 0
    assert len(prepared.calls) == 1
    assert prepared.calls[0]["max_capture_bytes"] == expected
