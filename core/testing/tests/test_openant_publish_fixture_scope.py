"""Configuration publication faults do not break unrelated OS renames."""
from contextlib import nullcontext
import os
from pathlib import Path

import pytest

from packages.openant.tests import test_cleanup_transactions as native


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_publish_fault_restores_scanner_namespace(tmp_path, error, failure):
    rename = os.rename
    namespace = native.scanner.os
    helper = native.patch_module_attribute
    entered, faults = [], []
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        out = native.out.__wrapped__(tmp_path, owner)

        def checked(patch, module, binding, name, value):
            assert module is native.scanner
            assert (binding, name) == ("os", "rename")

            def observed(source, destination, *args, **kwargs):
                source, destination = Path(source), Path(destination)
                assert source.name == "xdg" and source.parent.parent == out
                assert destination == out / native.scanner._XDG_STAGE_DIRNAME
                config = source / "openant" / "config.json"
                assert config.is_file()
                assert config.stat().st_mode & 0o777 == 0o600
                faults.append((source, destination))
                return value(source, destination, *args, **kwargs)

            private = helper(patch, module, binding, name, observed)
            entered.append(private)
            assert os.rename is rename
            return private

        owner.setattr(native, "patch_module_attribute", checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                native.test_failed_credential_stage_leaves_no_partial_config(out, body, "publish", error)
                assert len(entered) == len(faults) == 1
                source, destination = tmp_path / "unrelated-source", tmp_path / "unrelated-destination"
                source.write_text("owned")
                os.rename(source, destination)
                assert not source.exists() and destination.read_text() == "owned"
                assert len(faults) == 1
                assert list(out.iterdir()) == []
                if failure:
                    raise failure("owned body failure")
        assert native.scanner.os is namespace
        assert os.rename is rename
    assert native.patch_module_attribute is helper
