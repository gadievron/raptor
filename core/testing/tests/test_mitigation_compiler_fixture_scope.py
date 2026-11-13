"""Compiler fixtures affect the mitigation consumer without changing caller PATH."""
from contextlib import nullcontext
import inspect
import shutil

import pytest

from packages.exploit_feasibility import under_mitigations
from packages.exploit_feasibility.tests import test_under_mitigations as native


@pytest.mark.parametrize("name", ['test_build_refusal_logs_structured_detail_and_raises', 'test_replay_refusal_logs_structured_detail_and_raises', 'test_plain_setup_error_still_propagates_unmapped', 'test_ordinary_build_exception_still_captured_per_profile'])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_mitigation_compiler_fixture_restores_its_consumer(tmp_path, caplog, name, outcome):
    namespace, lookup = under_mitigations.shutil, shutil.which
    empty = tmp_path / "empty-path"
    empty.mkdir()
    assert shutil.which("c++", path=str(empty)) is None
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            value = native._fake_cxx.__wrapped__(patch)
            body = getattr(native.TestFloorRefusalRecordThenRaise(), name)
            kwargs = {"tmp_path": tmp_path, "monkeypatch": patch, "caplog": caplog, "_fake_cxx": value}
            body(**{key: value for key, value in kwargs.items() if key in inspect.signature(body).parameters})
            assert shutil.which is lookup
            assert shutil.which("c++", path=str(empty)) is None
            assert under_mitigations.shutil is not namespace
            assert under_mitigations.shutil.which("c++", path=str(empty)) == "/usr/bin/c++"
            assert under_mitigations.shutil.which("unrelated-missing-tool", path=str(empty)) is None
            if outcome:
                raise outcome("owned body failure")
    assert under_mitigations.shutil is namespace
    assert shutil.which is lookup
