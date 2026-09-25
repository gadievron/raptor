"""I/O hygiene of ``libexec/raptor-build-checklist``'s binary route.

Run artifacts must be written atomically (a crash mid-write leaves a
torn checklist.json that every downstream stage half-reads or refuses)
and run-dir JSON reads must be bounded (the shared 64MB artifact
ceiling; an unbounded read is an OOM lever).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-build-checklist"


@pytest.fixture(scope="module")
def script_mod() -> ModuleType:
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_build_checklist", str(SCRIPT),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


class _FakeDb:
    metadata: dict = {}

    def to_dict(self) -> dict:
        return {"functions": []}


def _drive_binary_route(script_mod, monkeypatch, tmp_path: Path,
                        context_map_text: str | None = None) -> dict:
    """Run _build_binary_checklist with the import chain stubbed out."""
    import core.audit.binary_context as binary_context
    import core.inventory.binary_builder as binary_builder

    out = tmp_path / "out"
    out.mkdir(exist_ok=True)   # tests may pre-populate the out dir
    target = tmp_path / "prog"
    target.write_bytes(b"\x7fELF" + b"\0" * 12)

    if context_map_text is not None:
        (out / "context-map.json").write_text(
            context_map_text, encoding="utf-8")

    redb = out / "re-database.json"
    monkeypatch.setattr(binary_context, "find_redb", lambda o, t: redb)
    monkeypatch.setattr(binary_context, "load_redb", lambda p: _FakeDb())

    captured: dict = {}

    def fake_build(db, *, binary_path, include_auto_named, context_map):
        captured["context_map"] = context_map
        return {"total_items": 0, "binary_stats": {}}

    monkeypatch.setattr(
        binary_builder, "build_binary_checklist", fake_build)

    script_mod._build_binary_checklist(target, out)
    captured["out"] = out
    return captured


class TestChecklistWriteAtomic:
    def test_checklist_written_via_accessor(
            self, script_mod, monkeypatch, tmp_path: Path):
        # The binary route writes through save_checklist (atomic +
        # flocked + retires a superseded sharded layout) — pin the
        # accessor call and the on-disk result.
        import core.inventory as inv
        calls: list[Path] = []
        real = inv.save_checklist

        def recording_save(output_dir, data):
            calls.append(Path(output_dir))
            return real(output_dir, data)

        monkeypatch.setattr(inv, "save_checklist", recording_save)
        captured = _drive_binary_route(script_mod, monkeypatch, tmp_path)
        assert captured["out"] in calls
        loaded = json.loads(
            (captured["out"] / "checklist.json").read_text())
        assert loaded["total_items"] == 0

    def test_write_retires_stale_sharded_layout(
            self, script_mod, monkeypatch, tmp_path: Path):
        # A leftover sharded checklist/ dir must not shadow the fresh
        # binary inventory via the index.json discriminator.
        import hashlib
        out = tmp_path / "out"
        out.mkdir()
        shard_dir = out / "checklist"
        shard_dir.mkdir()
        content = b'{"files":[]}\n'
        (shard_dir / "shard-stale-000.json").write_bytes(content)
        (shard_dir / "index.json").write_text(json.dumps({
            "schema_version": 1, "meta": {"target_path": "/stale"},
            "shards": [{"path": "shard-stale-000.json",
                        "file_count": 0, "item_count": 0, "sloc": 0,
                        "bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest()}],
        }))
        _drive_binary_route(script_mod, monkeypatch, tmp_path)
        assert not (shard_dir / "index.json").exists()
        from core.inventory import read_checklist
        assert read_checklist(out)["total_items"] == 0


class TestContextMapRead:
    def test_read_is_bounded(self, script_mod, monkeypatch,
                             tmp_path: Path):
        seen: dict = {}
        real = script_mod.load_json

        def recording_load(path, *a, **kw):
            seen[Path(path).name] = kw.get("max_bytes")
            return real(path, *a, **kw)

        monkeypatch.setattr(script_mod, "load_json", recording_load)
        captured = _drive_binary_route(
            script_mod, monkeypatch, tmp_path,
            context_map_text=json.dumps({"entry_points": []}),
        )
        assert captured["context_map"] == {"entry_points": []}
        assert seen.get("context-map.json") == 64 * 1024 * 1024

    def test_torn_context_map_skipped(self, script_mod, monkeypatch,
                                      tmp_path: Path):
        captured = _drive_binary_route(
            script_mod, monkeypatch, tmp_path,
            context_map_text='{"entry_points": [',
        )
        assert captured["context_map"] is None
