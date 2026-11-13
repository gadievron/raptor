"""Missing r2pipe fixtures rely on an owned negative module-cache entry."""
import builtins
from contextlib import contextmanager, nullcontext
import sys
from types import ModuleType

import pytest

from packages.binary_analysis.tests import test_radare2_understand as native


@pytest.mark.parametrize("inherited", ["absent", "negative", "loaded"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_missing_r2pipe_fixture_restores_registry(inherited, failure):
    importer = builtins.__import__
    table = sys.modules
    missing = object()
    binding = table.get("r2pipe", missing)
    registry = native.mock_module_registry
    probe = native.probe_capability
    module = native._mock_owner("packages.binary_analysis.radare2_understand")
    shutil = module.shutil
    selected = missing if inherited == "absent" else None if inherited == "negative" else ModuleType("r2pipe")
    entered = []
    results = []

    @contextmanager
    def checked(replacements):
        assert replacements == {"r2pipe": None}
        with registry(replacements) as active:
            entered.append(active)
            assert active is table
            assert table["r2pipe"] is None
            assert builtins.__import__ is importer
            with pytest.raises(ModuleNotFoundError, match="None in sys.modules"):
                importer("r2pipe")
            yield active
            assert builtins.__import__ is importer
            if failure:
                raise failure("owned body failure")

    def observed():
        assert builtins.__import__ is importer
        assert table["r2pipe"] is None
        result = probe()
        assert result["r2_bin"] == "/usr/bin/r2"
        assert result["has_r2pipe"] is result["available"] is False
        results.append(result)
        return result

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        native._isolated_defense_telemetry.__wrapped__(owner)
        if selected is missing:
            owner.delitem(table, "r2pipe", raising=False)
        else:
            owner.setitem(table, "r2pipe", selected)
        owner.setattr(native, "mock_module_registry", checked)
        owner.setattr(native, "probe_capability", observed)
        with expected:
            native.TestProbeCapability().test_radare2_without_r2pipe()
        assert len(entered) == len(results) == 1
        assert table.get("r2pipe", missing) is selected
        assert module.shutil is shutil
        assert builtins.__import__ is importer
    assert sys.modules is table
    assert table.get("r2pipe", missing) is binding
    assert native.probe_capability is probe
    assert native.mock_module_registry is registry
