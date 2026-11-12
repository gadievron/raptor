"""Parser adapter discovery fakes retain real lookup for unrelated consumers."""
from contextlib import nullcontext
import importlib
import shutil
import sys

import pytest

from core.binary.tests import test_additional_wrapper_contracts as native


@pytest.mark.parametrize("adapter", ["autodetect", "capabilities", "addr2line", "ebpf", "ghidra", "scanner", "objdump"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_adapter_discovery_restores_bindings(tmp_path, monkeypatch, adapter, outcome):
    monkeypatch.setattr(sys, "path", sys.path.copy())
    modules = {
        "capabilities": "core.audit.capabilities",
        "addr2line": "core.orchestration.frida_validation_bridge",
        "scanner": "packages.static-analysis.scanner",
    }
    consumer = importlib.import_module(modules[adapter]) if adapter in modules else None
    original_namespace = getattr(consumer, "shutil", None)
    original_function = getattr(consumer, "_addr2line_batch", None)
    lookup = shutil.which
    missing = str(tmp_path / "unrelated-missing-executable")
    assert shutil.which(missing) is None
    with pytest.MonkeyPatch.context() as patch:
        native.test_small_parser_adapter_reaches_sandbox(tmp_path, patch, adapter)
        assert shutil.which is lookup
        assert shutil.which(missing) is None
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with native._parser_discovery(adapter):
            assert shutil.which is lookup
            assert shutil.which(missing) is None
            if adapter in ("capabilities", "scanner"):
                assert consumer.shutil is not original_namespace
                assert consumer.shutil.which("owned-tool") == "/usr/bin/owned-tool"
            elif adapter == "addr2line":
                assert consumer._addr2line_batch is not original_function
            if outcome:
                raise outcome("owned body failure")
    assert shutil.which is lookup
    assert shutil.which(missing) is None
    assert getattr(consumer, "shutil", None) is original_namespace
    assert getattr(consumer, "_addr2line_batch", None) is original_function
