"""Identity-pin bracket at the edge-extraction seam.

The classify pass re-verifies a project-store binary's identity pin
bracketing its tool runs (``test_binary_oracle_identity_pins``); the
edge extractor (`extract_direct_call_edges`) reads the SAME path by
name — r2 inside its sandbox, plus content-keyed cache lookups whose
keys are themselves derived by name — so a swap landing after the
witness read would let unverified bytes plant positive-reachability
edges under the pinned path's authority. The bracket withholds edges
(empty index — the module's documented 'no binary evidence' shape)
on any pin failure; it never refuses the run and never touches
unpinned paths.

Swaps are driven deterministically at the seams (ordering hooks, not
timing races). The bracket-internal tests patch the extraction body
seam and skip on trees that predate it; the launch-refusal test runs
on any tree (red on BASE: the recorder observes the r2 launch the
gate should have withheld).
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import core.analysis.binary_oracle_edges as edges_mod
import core.sandbox as sandbox_mod
from core.config import RaptorConfig
from core.hash import sha256_file

_IMPL = "_extract_direct_call_edges_impl"


def _pin(path: Path) -> tuple[int, int, int, str]:
    import os
    st = os.stat(path)
    return (st.st_dev, st.st_ino, st.st_size, sha256_file(path))


@pytest.fixture()
def pins():
    """Save/seed/restore the identity-pin channel on RaptorConfig."""
    prev = getattr(RaptorConfig, "BINARY_ORACLE_IDENTITY_PINS", None)
    RaptorConfig.BINARY_ORACLE_IDENTITY_PINS = {}
    yield RaptorConfig.BINARY_ORACLE_IDENTITY_PINS
    if prev is None:
        try:
            delattr(RaptorConfig, "BINARY_ORACLE_IDENTITY_PINS")
        except AttributeError:
            pass
    else:
        RaptorConfig.BINARY_ORACLE_IDENTITY_PINS = prev


class _SandboxRecorder:
    """Stands in for core.sandbox.run: records launches, returns a
    clean fake completion — if it fires, r2 WOULD have parsed
    whatever the path denotes at that moment."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class TestLaunchGate:
    """Runs on any tree: does the extraction LAUNCH r2 over bytes
    whose identity pin is broken?"""

    def test_demoted_pin_withholds_the_launch(self, tmp_path, pins):
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\xff" * 28)
        pins[str(b)] = None  # demoted at witness load

        rec = _SandboxRecorder()
        # r2 presence must not decide the verdict — fake it available
        # so the only thing standing between the demotion and the
        # launch is the pin gate.
        with patch.object(sandbox_mod, "run", rec), \
             patch.object(edges_mod.shutil, "which",
                          lambda _name: "/usr/bin/r2"):
            idx = edges_mod.extract_direct_call_edges(
                b, use_cache=False)
        assert rec.calls == []
        assert idx.edges == []

    def test_stale_pin_withholds_the_launch(self, tmp_path, pins):
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pins[str(b)] = _pin(b)
        b.write_bytes(b"\x7fELF" + b"\xff" * 28)  # drift after witness

        rec = _SandboxRecorder()
        with patch.object(sandbox_mod, "run", rec), \
             patch.object(edges_mod.shutil, "which",
                          lambda _name: "/usr/bin/r2"):
            idx = edges_mod.extract_direct_call_edges(
                b, use_cache=False)
        assert rec.calls == []
        assert idx.edges == []

    def test_verified_pin_still_launches(self, tmp_path, pins):
        """No swap: the gate must not withhold the verified binary."""
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pins[str(b)] = _pin(b)

        rec = _SandboxRecorder()
        with patch.object(sandbox_mod, "run", rec), \
             patch.object(edges_mod.shutil, "which",
                          lambda _name: "/usr/bin/r2"):
            edges_mod.extract_direct_call_edges(b, use_cache=False)
        assert len(rec.calls) >= 1

    def test_unpinned_path_passes_through(self, tmp_path, pins):
        """Auto-detected / --binary paths are unpinned: the gate never
        widens withholding beyond witness-verified store entries."""
        b = tmp_path / "local.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)

        rec = _SandboxRecorder()
        with patch.object(sandbox_mod, "run", rec), \
             patch.object(edges_mod.shutil, "which",
                          lambda _name: "/usr/bin/r2"):
            edges_mod.extract_direct_call_edges(b, use_cache=False)
        assert len(rec.calls) >= 1


class TestBracket:
    """Bracket internals via the extraction-body seam (post-fix
    trees only — the seam is introduced with the bracket)."""

    @pytest.fixture(autouse=True)
    def _needs_seam(self):
        if not hasattr(edges_mod, _IMPL):
            pytest.skip("no extraction-body seam on this tree")

    def _sentinel(self, b: Path) -> "edges_mod.BinaryEdgeIndex":
        return edges_mod.BinaryEdgeIndex(
            binary_path=str(b),
            edges=[edges_mod.BinaryCallEdge(caller="main",
                                            callee="parse",
                                            binary_path=str(b))],
            callees={"parse"},
        )

    def test_verified_pin_returns_the_extraction(self, tmp_path, pins):
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pins[str(b)] = _pin(b)
        with patch.object(edges_mod, _IMPL,
                          lambda p, **kw: self._sentinel(p)):
            idx = edges_mod.extract_direct_call_edges(
                b, use_cache=False)
        assert [e.callee for e in idx.edges] == ["parse"]

    def test_demoted_pin_never_reaches_the_body(self, tmp_path, pins):
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pins[str(b)] = None
        calls: list[Path] = []

        def body(p, **kw):
            calls.append(p)
            return self._sentinel(p)

        with patch.object(edges_mod, _IMPL, body):
            idx = edges_mod.extract_direct_call_edges(
                b, use_cache=True)
        # Withheld BEFORE the body — before the content-keyed cache
        # lookups inside it could serve the swapped file's edges.
        assert calls == []
        assert idx.edges == []

    def test_swap_during_extraction_withholds(self, tmp_path, pins):
        """THE lingering-swap window: pre-check passes, the slot is
        swapped while r2 runs. The post-extraction by-name inode
        check catches it and the extracted edges are withheld."""
        import os
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pins[str(b)] = _pin(b)
        impostor = tmp_path / "impostor.debug"
        impostor.write_bytes(b"\x7fELF" + b"\xee" * 28)

        def swapping_body(p, **kw):
            os.replace(impostor, p)
            return self._sentinel(p)

        with patch.object(edges_mod, _IMPL, swapping_body):
            idx = edges_mod.extract_direct_call_edges(
                b, use_cache=False)
        assert idx.edges == []

    def test_inplace_rewrite_during_extraction_withholds(
            self, tmp_path, pins):
        """Same-inode variant: dev/ino unchanged, so only the held-fd
        re-hash can catch the rewrite."""
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pins[str(b)] = _pin(b)

        def rewriting_body(p, **kw):
            with open(p, "r+b") as f:
                f.write(b"\x7fELF" + b"\xee" * 28)  # same length
            return self._sentinel(p)

        with patch.object(edges_mod, _IMPL, rewriting_body):
            idx = edges_mod.extract_direct_call_edges(
                b, use_cache=False)
        assert idx.edges == []

    def test_withheld_index_has_no_callees_either(self, tmp_path,
                                                  pins):
        """The withhold must be COMPLETELY empty — cfg_builder
        consumes ``index.callees`` as
        positive-reachability signal (``build_cpp_callgraph``'s
        ``seen_functions.update(index.callees)``), so an edges-empty/
        callees-populated regression would still steer reachability
        off bytes the witness never verified."""
        import os
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pins[str(b)] = _pin(b)
        impostor = tmp_path / "i.debug"
        impostor.write_bytes(b"\x7fELF" + b"\xee" * 28)

        def swapping_body(p, **kw):
            os.replace(impostor, p)
            return self._sentinel(p)

        with patch.object(edges_mod, _IMPL, swapping_body):
            idx = edges_mod.extract_direct_call_edges(
                b, use_cache=False)
        assert idx.edges == []
        assert idx.callees == set()
