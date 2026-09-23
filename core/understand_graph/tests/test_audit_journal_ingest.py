"""The audit-journal ingest speaks the REAL producer's vocabulary.

The only producer of review-journal.jsonl is
core.coverage.journal.append_entry (ReviewJournalEntry rows:
hypotheses in the nested ``hypotheses`` list, receipts in
``evidence_tools`` — no ``type``/``kind`` field anywhere). These
tests write rows through that producer and assert the graph lane
actually ingests them, tolerates a torn tail line, records MAC
provenance, and never commits a junk empty ``audit`` snapshot.
"""

import hashlib
import json

from core.coverage import journal_mac
from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso
from core.json import save_json
from core.understand_graph import graph_summary, ingest_audit_hypotheses, ingest_run
from core.understand_graph.store import open_graph


def _write_understand_run(run_dir, target):
    src = target / "server.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("void handle_request(char *i) { system(i); }\n",
                   encoding="utf-8")
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "total_files": 1,
        "total_items": 1,
        "files": [{
            "path": "server.c",
            "sha256": sha,
            "items": [{"name": "handle_request", "line_start": 1}],
        }],
    })
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target)},
        "entry_points": [{"id": "EP-1", "name": "handle_request",
                          "file": "server.c", "line": 1}],
        "sinks": [{"id": "SINK-1", "name": "system",
                   "file": "server.c", "line": 1}],
        "unchecked_flows": [{"id": "FLOW-1", "entry_point": "EP-1",
                             "sink": "SINK-1", "confidence": "high"}],
    })
    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None
    return graph_path


def _review_entry(**over):
    base = dict(
        ts=now_iso(),
        run_id="run-1",
        file="server.c",
        function="handle_request",
        verdict="suspicious",
        source_hash="ab" * 8,
        cwe="CWE-78",
        hypotheses=[{"mechanism": "unchecked system() call",
                     "confidence": "high"}],
        evidence_tools=["semgrep"],
        tools_dispatched=["semgrep", "joern"],
    )
    base.update(over)
    return ReviewJournalEntry(**base)


def test_real_producer_rows_mint_hypothesis_and_verdict_nodes(tmp_path):
    """A row written by the REAL producer ingests: hypothesis node
    from hypotheses[], tool_verdict from evidence_tools, AFFECTS to
    the function node, TESTED_BY between them."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)

    append_entry(run_dir, _review_entry())
    result = ingest_audit_hypotheses(run_dir, str(target))
    assert result is not None

    summary = graph_summary(result)
    assert summary["nodes"].get("hypothesis", 0) >= 1
    assert summary["nodes"].get("tool_verdict", 0) >= 1
    assert summary["edges"].get("TESTED_BY", 0) >= 1
    assert summary["edges"].get("AFFECTS", 0) >= 1

    with open_graph(graph_path) as conn:
        hyp = conn.execute(
            "SELECT props_json FROM nodes WHERE kind='hypothesis'"
        ).fetchone()
        props = json.loads(hyp["props_json"])
        assert "unchecked system() call" in props.get("description", "")
        assert props.get("cwe") == "CWE-78"


def test_rows_without_review_content_commit_no_snapshot(tmp_path):
    """A journal whose rows carry no hypotheses and no evidence
    receipts must NOT deposit an empty producer='audit' snapshot into
    the durable graph (the pre-fix behavior for EVERY real journal:
    the lane keyed on a type/kind field no producer writes, ingested
    0 nodes, and committed the junk snapshot at the end of every
    /audit run — polluting snapshot-ordered consumers)."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)

    append_entry(run_dir, _review_entry(
        verdict="clean", hypotheses=[], evidence_tools=[]))
    result = ingest_audit_hypotheses(run_dir, str(target))
    assert result is None

    with open_graph(graph_path) as conn:
        audit_snaps = conn.execute(
            "SELECT COUNT(*) AS c FROM snapshots WHERE producer='audit'"
        ).fetchone()["c"]
    assert audit_snaps == 0


def test_torn_tail_line_does_not_discard_valid_rows(tmp_path):
    """One torn tail (the shape an interrupted append leaves) must
    cost that line only — never the whole ingest."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    _write_understand_run(run_dir, target)

    for i in range(3):
        append_entry(run_dir, _review_entry(
            hypotheses=[{"mechanism": f"mechanism {i}", "confidence": "high"}]))
    journal = run_dir / "review-journal.jsonl"
    with journal.open("a", encoding="utf-8") as fh:
        fh.write('{"ts": "2026-')  # torn tail, no newline

    result = ingest_audit_hypotheses(run_dir, str(target))
    assert result is not None
    summary = graph_summary(result)
    assert summary["nodes"].get("hypothesis", 0) == 3


def test_mac_provenance_recorded_on_minted_nodes(tmp_path):
    """Rows stamped by the producer verify (mac_provenance=verified);
    a content-edited row demotes to tampered. The graph records the
    tri-state so authority-tier consumers can filter — hint-tier
    seeding keeps both."""
    assert journal_mac.key_usable()  # hermetic XDG key from conftest

    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    _write_understand_run(run_dir, target)

    append_entry(run_dir, _review_entry(
        hypotheses=[{"mechanism": "intact row", "confidence": "high"}]))
    append_entry(run_dir, _review_entry(
        hypotheses=[{"mechanism": "victim row", "confidence": "high"}]))

    journal = run_dir / "review-journal.jsonl"
    lines = journal.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["verdict"] = "clean"  # content edit, token kept
    lines[1] = json.dumps(tampered, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = ingest_audit_hypotheses(run_dir, str(target))
    assert result is not None
    with open_graph(result) as conn:
        rows = conn.execute(
            "SELECT props_json FROM nodes WHERE kind='hypothesis'"
        ).fetchall()
    provenance = {
        json.loads(r["props_json"])["description"]:
            json.loads(r["props_json"])["mac_provenance"]
        for r in rows
    }
    assert provenance["intact row"] == journal_mac.ROW_VERIFIED
    assert provenance["victim row"] == journal_mac.ROW_TAMPERED
