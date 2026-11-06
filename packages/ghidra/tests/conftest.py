"""Shared fixtures for packages.ghidra tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home_state(tmp_path: Path,
                         monkeypatch: pytest.MonkeyPatch) -> None:
    """Two writers escape into the developer's real home on bare runs.

    The bookmarks-bridge checklist writes reach the stamping write
    chokepoint (``core.inventory.save_checklist``), whose integrity
    layer (``core.inventory.checklist_frame_mac``) keys off
    ``$XDG_DATA_HOME/raptor/checklist-frame-mac.key``. And the live
    gitignore-scope tests run real semgrep (``unsandboxed=True``),
    which unconditionally appends to ``~/.semgrep/semgrep.log`` and
    reads/writes ``~/.semgrep/settings.yml`` — keyed off HOME
    directly, which no XDG pin can cover. Point both at per-test tmp
    dirs so bare runs never mint keys or touch real user state (the
    explicit XDG pin also guards against a developer env whose
    XDG_DATA_HOME points at the real data dir).
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


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


@pytest.fixture(autouse=True)
def _owned_ghidra_keepalive():
    """Own ticker resources and fail if a database owner forgets its pin."""
    import threading
    from core.run import scratch

    with pytest.MonkeyPatch.context() as owner_patch:
        stop = threading.Event()
        paths = set()
        owner_patch.setattr(scratch, "_keepalive_paths", paths)
        owner_patch.setattr(scratch, "_keepalive_thread", None)
        owner_patch.setattr(scratch, "_keepalive_loop", lambda: stop.wait())
        try:
            yield paths
        finally:
            stop.set()
            thread = scratch._keepalive_thread
            if thread is not None:
                thread.join(timeout=5)
                assert not thread.is_alive(), "owned Ghidra keepalive did not stop"
            leaked = [path for path in paths if Path(path).name.startswith("raptor-ghidra-")]
            assert not leaked, f"Ghidra owner left working-copy keepalives registered: {leaked}"
