"""Own scratch ticker resources used by CodeQL adapter tests."""

import pytest


@pytest.fixture(autouse=True)
def _owned_tool_scratch():
    from core.testing.scratch_state import isolated_scratch_keepalive

    with isolated_scratch_keepalive():
        yield


@pytest.fixture(autouse=True)
def _isolated_cache_mac_key(tmp_path_factory, monkeypatch):
    """Point XDG_DATA_HOME at a per-test tmp dir.

    Every ``DatabaseManager.save_metadata`` now mints an HMAC key
    under ``$XDG_DATA_HOME/raptor/codeql-cache-mac.key``
    (``packages.codeql.cache_integrity``); without this isolation, any
    test that saves or loads metadata would lazily create — or depend
    on — the developer's real key file. Same pattern as
    ``core/llm/tests/conftest.py``.
    """
    from core.testing.tempdirs import isolated_test_dir

    monkeypatch.setenv(
        "XDG_DATA_HOME", str(isolated_test_dir(tmp_path_factory, "xdg-data")),
    )
