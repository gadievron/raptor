"""Shared fixtures for packages.ghidra tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _stub_decomp_conformance(monkeypatch):
    """Keep unit tests hermetic at the tree-build seam.

    ``write_decomp_tree`` measures parse conformance by default,
    which spawns a sandboxed tree-sitter child and a sandboxed
    semgrep probe — host-tool- and sandbox-dependent work no unit
    test should pay or depend on. Stubbed for every test in this
    package; tests that exercise the seam re-monkeypatch with a
    recorder (a later ``setattr`` wins), and the conformance module's
    own tests call ``measure_conformance`` directly with injected
    legs, bypassing this module-attribute stub.
    """
    from packages.ghidra import decomp_conformance
    monkeypatch.setattr(
        decomp_conformance, "measure_conformance",
        lambda *args, **kwargs: {"stubbed": True},
    )
    yield
