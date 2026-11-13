"""Sidecar decoder faults belong only to the actual reader."""
from contextlib import contextmanager, nullcontext
import json

import pytest

from core.sandbox.tests import test_proxy_count_reader_io as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_recursion_fault_preserves_other_decoders(tmp_path, failure):
    loads = json.loads
    reader = native.context._read_proxy_count_sidecar
    read = native.read
    scope = native.scoped_function_imports
    faults = []
    entered = []

    @contextmanager
    def checked(module, functions, imports):
        assert module is native.context
        assert functions == ("_read_proxy_count_sidecar",)
        with scope(module, functions, imports) as private:
            entered.append(private)

            def observed(path):
                assert json.loads is loads
                assert json.loads('{"unrelated": true}') == {"unrelated": True}
                fault = private.json.loads
                assert fault is not loads

                def counted(raw, **kwargs):
                    faults.append(raw)
                    assert loads(raw)["count"] == 4
                    return fault(raw, **kwargs)

                with pytest.MonkeyPatch.context() as patch:
                    patch.setattr(private.json, "loads", counted)
                    return read(path)

            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(native, "read", observed)
                yield private
                assert len(faults) == 1
                if failure:
                    raise failure("owned body failure")

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        sidecar = native.sidecar.__wrapped__(tmp_path, owner)
        owner.setattr(native, "scoped_function_imports", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.test_recursion_error_is_invalid_sidecar(sidecar, patch)
        assert len(entered) == len(faults) == 1
        assert native.context._read_proxy_count_sidecar is reader
        assert native.read is read
        assert json.loads is loads
    assert native.scoped_function_imports is scope
