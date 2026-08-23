"""Per-directory test infra for ``core.iris`` tests.

The store integrity layer (``core.iris.integrity``) mints its HMAC
key under ``$XDG_DATA_HOME/raptor/iris-store-mac.key``. Point
XDG_DATA_HOME at a per-test tmp dir so the suite never touches (or
depends on) the developer's real key, and every test starts from a
fresh-key state. Same pattern as
``core/llm/scorecard/tests/conftest.py``.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_iris_store_key(tmp_path_factory, monkeypatch):
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )
