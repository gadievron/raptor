"""Shared fixtures for core/witness tests.

Every test gets a private ``XDG_DATA_HOME``: ``WitnessStore.put``
stamps manifests with the witness-provenance MAC, whose key is
created lazily under the data dir — tests must never mint against
(or create) the operator's real key store.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_witness_mac_key(tmp_path_factory, monkeypatch):
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg")),
    )
