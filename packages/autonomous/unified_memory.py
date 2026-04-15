#!/usr/bin/env python3
"""
Unified memory backend for cross-tool RAPTOR learning.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

logger = get_logger()

SCHEMA_VERSION = 1
SECRET_REDACTION = "[REDACTED_SECRET]"


@dataclass
class SecretScanPolicy:
    enabled: bool = True
    run_trufflehog: bool = False
    max_snippet_length: int = 4096
    hash_only_mode: bool = False


class UnifiedMemory:
    """SQLite-backed memory for fuzzing, agentic, codeql, crash, and web workflows."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        policy: Optional[SecretScanPolicy] = None,
    ) -> None:
        self.db_path = Path(db_path or (Path.home() / ".raptor" / "memory.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.policy = policy or SecretScanPolicy()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL
                )
                """
            )
            current = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()["v"]
            if current is None:
                self._apply_v1(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, time.time()),
                )
            elif current < SCHEMA_VERSION:
                self._apply_v1(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, time.time()),
                )

    def _apply_v1(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS knowledge_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                knowledge_type TEXT NOT NULL,
                key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.5,
                success_count INTEGER NOT NULL DEFAULT 0,
                failure_count INTEGER NOT NULL DEFAULT 0,
                context_json TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                UNIQUE(domain, knowledge_type, key)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS run_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                reason_code TEXT,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS materialized_stats (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_domain ON knowledge_entries(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_type ON knowledge_entries(knowledge_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_tool ON run_events(tool)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON run_events(event_type)")

    def _scan_and_sanitize(self, value: Any) -> tuple[Any, Optional[str]]:
        if not self.policy.enabled:
            return value, None
        serialized = json.dumps(value, ensure_ascii=False)[: self.policy.max_snippet_length]
        reason = None
        if self._contains_secret(serialized):
            reason = "secret_pattern_detected"
            if self.policy.hash_only_mode:
                import hashlib

                return {"sha256": hashlib.sha256(serialized.encode()).hexdigest()}, reason
        if self.policy.run_trufflehog and self._trufflehog_matches(serialized):
            reason = "trufflehog_detected"
        if reason:
            return self._redact(value), reason
        return value, None

    def _contains_secret(self, text: str) -> bool:
        patterns = [
            r"AKIA[0-9A-Z]{16}",
            r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]",
            r"(?i)secret\s*[:=]\s*['\"][^'\"]+['\"]",
            r"(?i)token\s*[:=]\s*['\"][^'\"]+['\"]",
            r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
        ]
        return any(re.search(p, text) for p in patterns)

    def _trufflehog_matches(self, text: str) -> bool:
        try:
            proc = subprocess.run(
                ["trufflehog", "stdin", "--json"],
                input=text,
                text=True,
                capture_output=True,
                timeout=5,
                env={k: v for k, v in os.environ.items() if k not in {"TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"}},
            )
            return proc.returncode == 0 and bool(proc.stdout.strip())
        except Exception:
            return False

    def _redact(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._redact(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._redact(v) for v in obj]
        if isinstance(obj, str):
            return SECRET_REDACTION if self._contains_secret(obj) else obj[: self.policy.max_snippet_length]
        return obj

    def record_event(self, tool: str, event_type: str, payload: Dict[str, Any]) -> None:
        safe_payload, reason = self._scan_and_sanitize(payload)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO run_events (tool, event_type, payload_json, reason_code, created_at) VALUES (?, ?, ?, ?, ?)",
                (tool, event_type, json.dumps(safe_payload), reason, time.time()),
            )

    def upsert_knowledge(
        self,
        domain: str,
        knowledge_type: str,
        key: str,
        value: Any,
        confidence: float = 0.5,
        success_count: int = 0,
        failure_count: int = 0,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        safe_value, reason_value = self._scan_and_sanitize(value)
        safe_context, reason_ctx = self._scan_and_sanitize(context or {})
        reason = reason_value or reason_ctx
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO knowledge_entries (
                    domain, knowledge_type, key, value_json, confidence, success_count, failure_count, context_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, knowledge_type, key) DO UPDATE SET
                    value_json=excluded.value_json,
                    confidence=excluded.confidence,
                    success_count=excluded.success_count,
                    failure_count=excluded.failure_count,
                    context_json=excluded.context_json,
                    updated_at=excluded.updated_at
                """,
                (
                    domain,
                    knowledge_type,
                    key,
                    json.dumps(safe_value),
                    confidence,
                    success_count,
                    failure_count,
                    json.dumps(safe_context),
                    now,
                    now,
                ),
            )
            if reason:
                conn.execute(
                    "INSERT INTO run_events (tool, event_type, payload_json, reason_code, created_at) VALUES (?, ?, ?, ?, ?)",
                    (domain, "memory_redaction", json.dumps({"knowledge_type": knowledge_type, "key": key}), reason, now),
                )

    def query_knowledge(
        self,
        domain: Optional[str] = None,
        knowledge_type: Optional[str] = None,
        min_confidence: float = 0.0,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM knowledge_entries WHERE confidence >= ?"
        params: List[Any] = [min_confidence]
        if domain:
            sql += " AND domain = ?"
            params.append(domain)
        if knowledge_type:
            sql += " AND knowledge_type = ?"
            params.append(knowledge_type)
        sql += " ORDER BY confidence DESC, updated_at DESC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_knowledge(r) for r in rows]

    def aggregate_metrics(self) -> Dict[str, Any]:
        with self._connect() as conn:
            by_domain = conn.execute(
                "SELECT domain, COUNT(*) AS c FROM knowledge_entries GROUP BY domain"
            ).fetchall()
            by_tool = conn.execute("SELECT tool, COUNT(*) AS c FROM run_events GROUP BY tool").fetchall()
            top_noisy_rules = conn.execute(
                """
                SELECT key, failure_count, success_count
                FROM knowledge_entries
                WHERE knowledge_type = 'finding_quality'
                ORDER BY failure_count DESC
                LIMIT 10
                """
            ).fetchall()
        return {
            "knowledge_by_domain": {r["domain"]: r["c"] for r in by_domain},
            "events_by_tool": {r["tool"]: r["c"] for r in by_tool},
            "top_noisy_rules": [
                {"rule_id": r["key"], "failure_count": r["failure_count"], "success_count": r["success_count"]}
                for r in top_noisy_rules
            ],
        }

    def compact(self, max_event_rows: int = 50000, stale_days: int = 180) -> Dict[str, int]:
        cutoff = time.time() - stale_days * 86400
        with self._connect() as conn:
            removed_knowledge = conn.execute(
                "DELETE FROM knowledge_entries WHERE updated_at < ? AND confidence < 0.2",
                (cutoff,),
            ).rowcount
            total_events = conn.execute("SELECT COUNT(*) AS c FROM run_events").fetchone()["c"]
            removed_events = 0
            if total_events > max_event_rows:
                to_remove = total_events - max_event_rows
                removed_events = conn.execute(
                    "DELETE FROM run_events WHERE id IN (SELECT id FROM run_events ORDER BY created_at ASC LIMIT ?)",
                    (to_remove,),
                ).rowcount
        return {"knowledge_removed": removed_knowledge, "events_removed": removed_events}

    def health_status(self) -> Dict[str, Any]:
        with self._connect() as conn:
            schema = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()["v"]
            knowledge = conn.execute("SELECT COUNT(*) AS c FROM knowledge_entries").fetchone()["c"]
            events = conn.execute("SELECT COUNT(*) AS c FROM run_events").fetchone()["c"]
        return {
            "db_path": str(self.db_path),
            "schema_version": schema,
            "knowledge_entries": knowledge,
            "run_events": events,
        }

    def export_json(self, output_path: Path, domain: Optional[str] = None) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "exported_at": time.time(),
            "domain": domain or "all",
            "knowledge": self.query_knowledge(domain=domain),
            "metrics": self.aggregate_metrics(),
        }
        output_path.write_text(json.dumps(payload, indent=2))
        return output_path

    def _row_to_knowledge(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "domain": row["domain"],
            "knowledge_type": row["knowledge_type"],
            "key": row["key"],
            "value": json.loads(row["value_json"]),
            "confidence": row["confidence"],
            "success_count": row["success_count"],
            "failure_count": row["failure_count"],
            "context": json.loads(row["context_json"] or "{}"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
