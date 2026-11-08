"""Shared fixtures for core/witness tests.

Every test gets a private ``XDG_DATA_HOME``: ``WitnessStore.put``
stamps manifests with the witness-provenance MAC, whose key is
created lazily under the data dir — tests must never mint against
(or create) the operator's real key store.
"""

from __future__ import annotations

import pytest

from core.testing.tempdirs import isolated_test_dir
from core.testing.module_state import isolated_module_state
from core.witness import provenance


@pytest.fixture(autouse=True)
def _isolated_witness_mac_key(tmp_path_factory, monkeypatch):
    with isolated_module_state(provenance, {"_warned_paths": set()}):
        try:
            monkeypatch.setenv(
                "XDG_DATA_HOME", str(isolated_test_dir(tmp_path_factory, "xdg")),
            )
            yield
        finally:
            monkeypatch.undo()
