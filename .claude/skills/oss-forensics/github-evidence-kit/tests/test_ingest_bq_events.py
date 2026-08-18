"""
Robustness tests for scripts/ingest_bq_events.py.

The ingest script bridges libexec/raptor-bq-query output (JSON
envelope with a ``rows`` list) into the evidence store. Tests drive it
as a subprocess — the same way the gh-archive agent's Bash allowlist
invokes it — plus unit checks on the row loader.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).parents[1]
SCRIPT = SKILL_DIR / "scripts" / "ingest_bq_events.py"

sys.path.insert(0, str(SKILL_DIR))

from src.store import EvidenceStore


def _push_row(sha="a" * 40):
    return {
        "type": "PushEvent",
        "created_at": "2025-07-13T20:37:04Z",
        "actor_login": "testuser",
        "actor_id": 123,
        "repo_name": "owner/repo",
        "payload": json.dumps({
            "ref": "refs/heads/main",
            "before": "b" * 40,
            "head": sha,
            "size": 1,
            "commits": [{"sha": sha, "message": "test",
                         "author": {"name": "T", "email": "t@x.test"}}],
        }),
    }


def _run(args, stdin=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin, capture_output=True, text=True, timeout=30,
        check=False,
    )


class TestIngest:
    def test_envelope_rows_ingested(self, tmp_path):
        rows_file = tmp_path / "rows.json"
        rows_file.write_text(json.dumps({
            "rows": [_push_row()],
            "row_count": 1,
            "job": {"job_id": "j"},
            "dry_run": False,
        }))
        evidence = tmp_path / "evidence.json"
        proc = _run([str(evidence), "--table", "githubarchive.day.20250713",
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert summary["success"] is True
        assert summary["ingested"] == 1
        assert summary["skipped"] == []

        store = EvidenceStore.load(str(evidence))
        events = list(store)
        assert len(events) == 1
        assert events[0].verification.bigquery_table == \
            "githubarchive.day.20250713"

    def test_bare_list_accepted(self, tmp_path):
        rows_file = tmp_path / "rows.json"
        rows_file.write_text(json.dumps([_push_row()]))
        evidence = tmp_path / "evidence.json"
        proc = _run([str(evidence), "--table", "githubarchive.day.20250713",
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout)["ingested"] == 1

    def test_stdin_rows(self, tmp_path):
        evidence = tmp_path / "evidence.json"
        proc = _run(
            [str(evidence), "--table", "githubarchive.day.20250713",
             "--rows-file", "-"],
            stdin=json.dumps({"rows": [_push_row()]}))
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout)["ingested"] == 1

    def test_appends_to_existing_store(self, tmp_path):
        evidence = tmp_path / "evidence.json"
        rows_file = tmp_path / "rows.json"
        rows_file.write_text(json.dumps({"rows": [_push_row("c" * 40)]}))
        _run([str(evidence), "--table", "githubarchive.day.20250713",
              "--rows-file", str(rows_file)])
        rows_file.write_text(json.dumps({"rows": [_push_row("d" * 40)]}))
        proc = _run([str(evidence), "--table", "githubarchive.day.20250714",
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 0, proc.stderr
        store = EvidenceStore.load(str(evidence))
        assert len(list(store)) == 2

    def test_unsupported_event_type_skipped_not_fatal(self, tmp_path):
        rows_file = tmp_path / "rows.json"
        rows_file.write_text(json.dumps({"rows": [
            _push_row(),
            {"type": "MysteryEvent", "created_at": "2025-07-13T20:37:04Z",
             "actor_login": "x", "repo_name": "owner/repo", "payload": "{}"},
        ]}))
        evidence = tmp_path / "evidence.json"
        proc = _run([str(evidence), "--table", "githubarchive.day.20250713",
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert summary["ingested"] == 1
        assert len(summary["skipped"]) == 1
        assert "MysteryEvent" in summary["skipped"][0]["reason"]

    def test_non_object_row_skipped(self, tmp_path):
        rows_file = tmp_path / "rows.json"
        rows_file.write_text(json.dumps({"rows": ["not-a-row"]}))
        evidence = tmp_path / "evidence.json"
        proc = _run([str(evidence), "--table", "githubarchive.day.20250713",
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 0, proc.stderr
        summary = json.loads(proc.stdout)
        assert summary["ingested"] == 0
        assert summary["skipped"][0]["reason"] == "row is not an object"


class TestInputErrors:
    def test_missing_rows_file(self, tmp_path):
        proc = _run([str(tmp_path / "e.json"), "--table", "t",
                     "--rows-file", str(tmp_path / "absent.json")])
        assert proc.returncode == 1
        assert json.loads(proc.stdout)["success"] is False

    def test_malformed_rows_json(self, tmp_path):
        rows_file = tmp_path / "rows.json"
        rows_file.write_text("{not json")
        proc = _run([str(tmp_path / "e.json"), "--table", "t",
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 1

    def test_object_without_rows_key(self, tmp_path):
        rows_file = tmp_path / "rows.json"
        rows_file.write_text(json.dumps({"data": []}))
        proc = _run([str(tmp_path / "e.json"), "--table", "t",
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 1
        assert "rows" in json.loads(proc.stdout)["error"]

    def test_table_is_required(self, tmp_path):
        rows_file = tmp_path / "rows.json"
        rows_file.write_text("[]")
        proc = _run([str(tmp_path / "e.json"),
                     "--rows-file", str(rows_file)])
        assert proc.returncode == 2  # argparse usage error


class TestLoadRowsUnit:
    @pytest.fixture(autouse=True)
    def _import(self):
        sys.path.insert(0, str(SKILL_DIR / "scripts"))
        import ingest_bq_events
        self.mod = ingest_bq_events
        yield
        sys.path.remove(str(SKILL_DIR / "scripts"))

    def test_rejects_scalar_json(self, tmp_path):
        f = tmp_path / "rows.json"
        f.write_text("42")
        with pytest.raises(ValueError, match="object or list"):
            self.mod.load_rows(str(f))
