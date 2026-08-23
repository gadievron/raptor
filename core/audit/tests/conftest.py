"""Per-directory test infra.

Journal appends stamp rows with an HMAC key under
``$XDG_DATA_HOME/raptor/journal-mac.key`` (``core.coverage.journal_mac``;
the witness/iris/scorecard integrity layers keep sibling keys in the
same directory). Point XDG_DATA_HOME at a per-test tmp dir so the
suite never touches (or depends on) the developer's real key files,
and every test starts from a fresh-key state. Same pattern as
``core/llm/scorecard/tests/conftest.py``. Tests that need a specific
key state set XDG_DATA_HOME themselves inside the test body, which
runs after this autouse fixture and wins.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_mac_keys(tmp_path_factory, monkeypatch):
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )
