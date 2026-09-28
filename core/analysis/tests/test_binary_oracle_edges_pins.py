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


class TestEdgeCacheContentBinding:
    """The persistence leg of the same threat: the JSON edge cache
    outlives the run, so an extraction persisted while impostor bytes
    sat at the name (or a pre-poisoned cache file dropped under the
    shared cache dir with the RIGHT version and binary_path) would be
    served on the NEXT run — after the pin re-verifies against the
    restored honest binary. The payload must be bound to the binary's
    content sha at load, exactly as ``_try_graph_store`` already binds
    graph-store reuse."""

    @staticmethod
    def _cache_file(monkeypatch, tmp_path) -> Path:
        monkeypatch.setattr(RaptorConfig, "BASE_OUT_DIR", tmp_path)
        cache_file = edges_mod._cache_path_for("abcdef" * 7)
        assert cache_file is not None
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        return cache_file

    def test_stale_content_sha_is_a_miss(self, tmp_path, monkeypatch):
        """Attack direction: version and binary_path both match, but
        the recorded sha is of the IMPOSTOR bytes the entry was
        extracted from — the honest binary now at the name must not
        be served those edges."""
        import json
        cache_file = self._cache_file(monkeypatch, tmp_path)
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        payload = {
            "version": edges_mod._EDGE_CACHE_VERSION,
            "binary_path": str(b),
            "binary_sha256": "e" * 64,  # not the bytes at the name
            "edges": [{"caller": "main", "callee": "evil_free_pass",
                       "binary_path": str(b)}],
        }
        cache_file.write_text(json.dumps(payload), encoding="utf-8")
        assert edges_mod._load_cached_index(
            cache_file, str(b)) is None, (
            "a cache entry whose binary_sha256 does not match the "
            "bytes now at the name must be a miss")

    def test_missing_content_sha_is_a_miss(self, tmp_path,
                                           monkeypatch):
        """The binding must not be bypassable by OMITTING the field
        (crafted or legacy payload claiming the current version)."""
        import json
        cache_file = self._cache_file(monkeypatch, tmp_path)
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        for sha_field in ({}, {"binary_sha256": None},
                          {"binary_sha256": 7}):
            payload = {
                "version": edges_mod._EDGE_CACHE_VERSION,
                "binary_path": str(b),
                "edges": [{"caller": "main",
                           "callee": "evil_free_pass",
                           "binary_path": str(b)}],
                **sha_field,
            }
            cache_file.write_text(json.dumps(payload),
                                  encoding="utf-8")
            assert edges_mod._load_cached_index(
                cache_file, str(b)) is None, (
                "a cache entry without a valid binary_sha256 must "
                "be a miss, never a hit")

    def test_honest_round_trip_still_hits(self, tmp_path,
                                          monkeypatch):
        """Preservation direction: save-then-load on an unchanged
        binary is still a cache HIT with the edges intact."""
        cache_file = self._cache_file(monkeypatch, tmp_path)
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        idx = edges_mod.BinaryEdgeIndex(binary_path=str(b))
        idx.edges = [edges_mod.BinaryCallEdge(
            caller="main", callee="parse", binary_path=str(b))]
        idx.callees = {"parse"}
        edges_mod._save_cached_index(cache_file, idx)
        loaded = edges_mod._load_cached_index(cache_file, str(b))
        assert loaded is not None
        assert [(e.caller, e.callee) for e in loaded.edges] == [
            ("main", "parse")]
        assert loaded.callees == {"parse"}

    def test_save_skips_a_binary_it_cannot_hash(self, tmp_path,
                                                monkeypatch):
        """An entry the saver cannot bind (binary unreadable/gone at
        save time) is never persisted — an unbindable entry could
        only ever load as a miss, and writing it would leave a
        version-current, path-current payload one field short of the
        contract in a shared cache dir."""
        cache_file = self._cache_file(monkeypatch, tmp_path)
        idx = edges_mod.BinaryEdgeIndex(
            binary_path=str(tmp_path / "never-existed.debug"))
        idx.edges = [edges_mod.BinaryCallEdge(
            caller="main", callee="parse",
            binary_path=idx.binary_path)]
        edges_mod._save_cached_index(cache_file, idx)
        assert not cache_file.exists()

    def test_unhashable_binary_at_load_is_a_miss(
            self, tmp_path, monkeypatch):
        """A binary the loader cannot hash at cache-load time
        (transient EIO, permissions, replaced-by-unreadable) must not
        skip the content compare in the reader's favour: unbindable-
        at-load = miss, exactly as a missing/invalid payload
        ``binary_sha256`` is. Reachable without a bracket pre-verify
        in front of the cache (pinless / auto-detected binaries), so
        the gate itself must be fail-closed."""
        cache_file = self._cache_file(monkeypatch, tmp_path)
        b = tmp_path / "app.debug"
        b.write_bytes(b"\x7fELF" + b"\x00" * 28)
        idx = edges_mod.BinaryEdgeIndex(binary_path=str(b))
        idx.edges = [edges_mod.BinaryCallEdge(
            caller="main", callee="parse", binary_path=str(b))]
        edges_mod._save_cached_index(cache_file, idx)  # honest save
        assert cache_file.exists()
        real = edges_mod._content_hash

        def gone(path):
            if str(path) == str(b):
                return None
            return real(path)

        monkeypatch.setattr(edges_mod, "_content_hash", gone)
        assert edges_mod._load_cached_index(
            cache_file, str(b)) is None, (
            "an unbindable-at-load cache entry must be a miss, "
            "never served")
