#!/usr/bin/env python3
"""
Ingest raptor-bq-query results into an evidence store.

Companion to ``libexec/raptor-bq-query``: the wrapper runs the
read-only BigQuery statement and writes a JSON envelope; this script
parses each returned row with ``parse_gharchive_event`` and appends the
resulting evidence objects to ``evidence.json``. Together they replace
the ad-hoc inline BigQuery Python the gh-archive agent used to run.

Usage:
    python3 ingest_bq_events.py <workdir>/evidence.json \
        --table githubarchive.day.20250713 --rows-file rows.json

``--rows-file`` accepts either the wrapper's envelope (object with a
``rows`` key) or a bare JSON list of rows; ``-`` reads stdin. Rows
must carry the columns the parsers expect — select at least ``type``,
``created_at``, ``payload``, and alias ``actor.login AS actor_login``,
``repo.name AS repo_name``.

``--table`` is REQUIRED and must be the exact table the query ran
against (e.g. ``githubarchive.day.20250713``) — verification metadata
depends on it; without the right table, ``store.verify_all()`` fails.

Output: one JSON summary object on stdout. Exit 0 on success (even if
some rows were skipped as unsupported event types — see ``skipped``),
exit 1 on input/store errors.
"""

import argparse
import json
import sys
from pathlib import Path

# Add skill dir to path for package imports
script_dir = Path(__file__).parent
skill_dir = script_dir.parent
sys.path.insert(0, str(skill_dir))

from src.parsers import parse_gharchive_event
from src.store import EvidenceStore


def _fail(message: str) -> int:
    print(json.dumps({"success": False, "error": message}))
    return 1


def load_rows(rows_file: str):
    """Load rows from the wrapper envelope or a bare JSON list."""
    if rows_file == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(rows_file).read_text(encoding="utf-8")
    data = json.loads(raw)
    if isinstance(data, dict):
        rows = data.get("rows")
        if isinstance(rows, list):
            return rows
        raise ValueError(
            "JSON object has no 'rows' list — expected raptor-bq-query "
            "envelope or a bare list of rows"
        )
    if isinstance(data, list):
        return data
    raise ValueError("rows input must be a JSON object or list")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest raptor-bq-query rows into an evidence store"
    )
    parser.add_argument(
        "evidence_path",
        help="Path to evidence.json (created if missing)",
    )
    parser.add_argument(
        "--table", required=True,
        help="Exact BigQuery table the rows came from "
             "(e.g. githubarchive.day.20250713)",
    )
    parser.add_argument(
        "--rows-file", required=True,
        help="raptor-bq-query JSON output ('-' for stdin)",
    )
    args = parser.parse_args()

    try:
        rows = load_rows(args.rows_file)
    except (OSError, ValueError) as exc:
        return _fail(f"could not load rows: {exc}")

    evidence_path = Path(args.evidence_path)
    try:
        if evidence_path.exists():
            store = EvidenceStore.load(str(evidence_path))
        else:
            store = EvidenceStore()
    except (OSError, ValueError, KeyError) as exc:
        return _fail(f"could not load evidence store: {exc}")

    ingested = 0
    skipped = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            skipped.append({"row": index, "reason": "row is not an object"})
            continue
        try:
            event = parse_gharchive_event(row, table=args.table)
        except (ValueError, KeyError, TypeError) as exc:
            skipped.append({"row": index, "reason": str(exc)})
            continue
        store.add(event)
        ingested += 1

    try:
        store.save(str(evidence_path))
    except OSError as exc:
        return _fail(f"could not save evidence store: {exc}")

    print(json.dumps({
        "success": True,
        "evidence_path": str(evidence_path),
        "table": args.table,
        "ingested": ingested,
        "skipped": skipped,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
