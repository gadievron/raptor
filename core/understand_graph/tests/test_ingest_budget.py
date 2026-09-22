"""Ingest reader budget + out-of-transaction hashing pins."""

from __future__ import annotations

import sqlite3

from core.json import save_json

import core.understand_graph.ingest as ingest


def _write_min_run(run_dir, target):
    target.mkdir(parents=True, exist_ok=True)
    (target / "a.c").write_text("void f() {}\n")
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "files": [{"path": "a.c", "language": "c", "items": []}],
    })
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target)},
        "entry_points": [{"id": "EP-1", "name": "f", "file": "a.c", "line": 1}],
    })


def test_ingest_records_artifact_digests(tmp_path):
    run_dir, target = tmp_path / "run", tmp_path / "t"
    _write_min_run(run_dir, target)
    graph = ingest.ingest_run(run_dir, str(target))
    assert graph is not None
    conn = sqlite3.connect(graph)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT kind, sha256 FROM artifacts WHERE kind='context_map'"
    ).fetchall()
    conn.close()
    assert rows and all(len(r["sha256"]) == 64 for r in rows)


def test_oversized_artifact_degrades_to_skip(tmp_path, monkeypatch):
    """A run artifact past the shared budget must cost a skipped
    ingest of that artifact, not memory."""
    run_dir, target = tmp_path / "run", tmp_path / "t"
    _write_min_run(run_dir, target)
    # variants.json exceeds the (shrunk) budget → treated as missing;
    # the smaller checklist / context-map still ingest.
    save_json(run_dir / "variants.json",
              [{"id": f"variant-{i}", "file": "a.c", "pad": "x" * 64}
               for i in range(64)])
    monkeypatch.setattr(ingest, "_ARTIFACT_MAX_BYTES",
                        (run_dir / "context-map.json").stat().st_size + 1)
    graph = ingest.ingest_run(run_dir, str(target))
    assert graph is not None
    conn = sqlite3.connect(graph)
    conn.row_factory = sqlite3.Row
    kinds = {r["kind"] for r in conn.execute("SELECT kind FROM artifacts")}
    nodes = {r["kind"] for r in conn.execute("SELECT kind FROM nodes")}
    conn.close()
    assert "variants" not in kinds
    assert "variant" not in nodes      # oversized file never parsed
    assert "entry_point" in nodes      # context map still ingested


def test_journal_read_is_capped(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "review-journal.jsonl").write_text(
        '{"type": "hypothesis", "function": "f", "file": "a.c"}\n' * 10
    )
    monkeypatch.setattr(ingest, "_ARTIFACT_MAX_BYTES", 8)
    assert ingest.ingest_audit_hypotheses(run_dir, str(tmp_path)) is None
