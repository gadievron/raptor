"""Route fixtures own native CLI discovery without changing caller PATH lookups."""
from contextlib import contextmanager, nullcontext
import shutil

import pytest

from core.llm import config, detection
from core.llm.tests import test_transport_route_matrix as native


@pytest.mark.parametrize("name", [
    "test_no_bedrock_entry_resolves_claudecode_session_default",
    "test_ambient_routing_family_does_not_change_the_fallback",
])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_route_fixture_restores_discovery_dispatch(tmp_path, name, outcome):
    registry, entries = config._PROVIDER_BUILDERS, dict(config._PROVIDER_BUILDERS)
    builder, auth = config._build_claudecode_config, config._entry_auth_resolvable
    namespace, lookup = detection.shutil, shutil.which
    empty = tmp_path / "empty-path"
    empty.mkdir()
    assert shutil.which("claude", path=str(empty)) is None
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            with contextmanager(native._hermetic_resolution.__wrapped__)(patch, tmp_path) as imports:
                getattr(native.TestClaudecodeRoutePreserved(), name)(patch, imports)
                assert shutil.which is lookup
                assert shutil.which("claude", path=str(empty)) is None
                assert detection.shutil is not namespace
                assert detection.shutil.which("claude") == "/usr/local/bin/claude"
                assert config._PROVIDER_BUILDERS is not registry
                assert config._PROVIDER_BUILDERS["claudecode"] is config._build_claudecode_config
                assert config._build_claudecode_config is not builder
                assert config._entry_auth_resolvable is not auth
                if outcome:
                    raise outcome("owned body failure")
    assert config._PROVIDER_BUILDERS is registry
    assert registry == entries
    assert config._build_claudecode_config is builder
    assert config._entry_auth_resolvable is auth
    assert detection.shutil is namespace
    assert shutil.which is lookup
