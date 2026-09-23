"""Shared RE-database size ceiling across readers and write guards."""

import importlib
import importlib.util
import json
import logging
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestSharedCeilingIdentity:
    def test_sites_bind_the_one_core_constant(self, monkeypatch):
        """Reload-tolerant cross-site agreement. Two halves:

        - effective VALUES all match the core constant's current
          resolution (object identity is deliberately not asserted —
          the lazy-reexport tests' sys.modules reset legitimately
          recreates ``core.json.utils`` and its int object mid-suite);
        - each site textually BINDS the shared name (import
          provenance), so a hand-copied value that happens to be
          equal today still fails here.
        """
        import core.audit.binary_context as binary_context
        import packages.ghidra.context_inject as context_inject

        monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
        loader = SourceFileLoader(
            "raptor_binary_study_ceiling_test",
            str(REPO_ROOT / "libexec" / "raptor-binary-study"),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)

        utils = importlib.import_module("core.json.utils")
        effective = utils.RE_DATABASE_MAX_BYTES
        assert mod._MAX_DB_BYTES == effective
        assert context_inject._MAX_CACHE_BYTES == effective
        assert binary_context._MAX_REDB_BYTES == effective

        # Import provenance (drift fence): the binding must be the
        # imported shared name, never a literal. attach, decomp_tree,
        # parser, and raptor-study-prep bind the same import at call
        # time — no module attribute to assert for those.
        for module, needle in (
            (context_inject,
             "_MAX_CACHE_BYTES = RE_DATABASE_MAX_BYTES"),
            (binary_context,
             "RE_DATABASE_MAX_BYTES as _MAX_REDB_BYTES"),
            (mod, "RE_DATABASE_MAX_BYTES as _MAX_DB_BYTES"),
        ):
            source = Path(module.__file__).read_text()
            assert needle in source, module.__name__


class TestBigCacheReads:
    def _cache_with_pad(self, tmp_path: Path, pad_bytes: int) -> Path:
        cache = tmp_path / "re-database.json"
        # Composed textually: json.dumps on a 65MiB value doubles the
        # test's peak memory for no added coverage.
        cache.write_text(
            '{"source_tool": "ghidra", "functions": '
            '[{"name": "f", "address": 1, "size": 2, '
            '"source_tool": "ghidra"}], '
            '"metadata": {"pad": "' + "x" * pad_bytes + '"}}'
        )
        return cache

    def test_reader_accepts_over_the_old_64mib_bound(
            self, tmp_path, monkeypatch):
        """A --decompile-all import of a large binary legitimately
        writes past 64MiB — the previous bound made every capped
        reader refuse the importer's own artifact."""
        import packages.ghidra.roundtrip as roundtrip
        from packages.ghidra.context_inject import _load_cached_redb

        cache = self._cache_with_pad(tmp_path, 65 * 1024 * 1024)
        assert cache.stat().st_size > 64 * 1024 * 1024
        monkeypatch.setattr(
            roundtrip, "redb_cache_candidates", lambda gpr: [cache])
        db = _load_cached_redb(tmp_path / "fw.gpr")
        assert db is not None
        assert len(db.functions) == 1

    def test_reader_still_bounded_at_the_ceiling(
            self, tmp_path, monkeypatch):
        """Raised, not removed: past the effective ceiling the read
        is still refused (whole-document parsing of a corrupted or
        bloated cache is a memory-exhaustion primitive)."""
        import packages.ghidra.context_inject as context_inject
        import packages.ghidra.roundtrip as roundtrip

        cache = tmp_path / "re-database.json"
        cache.write_text(json.dumps(
            {"source_tool": "ghidra", "functions": [],
             "metadata": {"pad": "x" * 4096}}))
        monkeypatch.setattr(context_inject, "_MAX_CACHE_BYTES", 64)
        monkeypatch.setattr(
            roundtrip, "redb_cache_candidates", lambda gpr: [cache])
        assert context_inject._load_cached_redb(
            tmp_path / "fw.gpr") is None


class TestWriteSideParityWarning:
    @staticmethod
    def _bridge(tmp_path):
        from packages.ghidra.bridge import GhidraBridge

        gpr = tmp_path / "fw.gpr"
        rep = tmp_path / "fw.rep"
        rep.mkdir()
        (rep / "project.prp").write_text("<FILE_INFO/>")
        gpr.write_text("")
        return GhidraBridge(gpr)

    def test_bridge_warns_when_write_crosses_ceiling(
            self, tmp_path, monkeypatch, caplog):
        """The importer must not silently write an artifact every
        capped reader then refuses."""
        from packages.ghidra.model import REDatabase

        bridge = self._bridge(tmp_path)
        # The bridge resolves the ceiling at the shared-constant home
        # — an override there must reach the write-side check too.
        monkeypatch.setattr("core.json.utils.RE_DATABASE_MAX_BYTES", 16)
        with caplog.at_level(logging.WARNING,
                             logger="packages.ghidra.bridge"):
            bridge._write_re_database(
                REDatabase(source_tool="ghidra"), tmp_path)
        assert any("read ceiling" in r.getMessage()
                   for r in caplog.records)

    def test_bridge_silent_under_ceiling(
            self, tmp_path, monkeypatch, caplog):
        from packages.ghidra.model import REDatabase

        del monkeypatch  # signature parity with the warn case
        bridge = self._bridge(tmp_path)
        with caplog.at_level(logging.WARNING,
                             logger="packages.ghidra.bridge"):
            bridge._write_re_database(
                REDatabase(source_tool="ghidra"), tmp_path)
        assert not any("read ceiling" in r.getMessage()
                       for r in caplog.records)
