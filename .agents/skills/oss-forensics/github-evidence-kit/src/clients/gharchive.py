"""
GH Archive Client for BigQuery.
"""
from __future__ import annotations

import json
import os
from typing import Any

import google.auth
from google.cloud import bigquery
from google.oauth2 import service_account

from ..schema.common import EvidenceSource


class GHArchiveClient:
    """Client for GH Archive BigQuery queries.

    Credentials via GOOGLE_APPLICATION_CREDENTIALS env var:
    - File path: /path/to/service-account.json
    - Inline JSON: {"type":"service_account","project_id":"..."}

    Falls back to Application Default Credentials (gcloud, metadata server).
    """

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id
        self._client: bigquery.Client | None = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GHARCHIVE

    def _get_client(self) -> bigquery.Client:
        if self._client is None:
            credentials, project = self._resolve_credentials()
            self._client = bigquery.Client(
                credentials=credentials,
                project=self.project_id or project,
            )
        return self._client

    def _resolve_credentials(self) -> tuple[Any, str | None]:
        """Resolve credentials - supports file path or inline JSON."""
        scopes = ["https://www.googleapis.com/auth/bigquery"]
        creds_value = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")

        # Inline JSON (starts with '{')
        if creds_value.startswith("{"):
            info = json.loads(creds_value)
            credentials = service_account.Credentials.from_service_account_info(
                info, scopes=scopes
            )
            return credentials, info.get("project_id")

        # File path or ADC fallback
        return google.auth.default(scopes=scopes)

    def query_events(
        self,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
        from_date: str = "",
        to_date: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query GH Archive for events using parameterized queries."""
        client = self._get_client()

        # Build table reference - use daily table
        # from_date is YYYYMMDDHHMM format (12 digits), extract day part
        day = from_date[:8]
        # Table names can't be parameterized, but day is validated format
        if not day.isdigit() or len(day) != 8:
            raise ValueError(f"Invalid date format: {from_date}")
        table = f"`githubarchive.day.{day}`"

        # Build WHERE clauses with parameterized values
        clauses = []
        params = []

        # Filter by hour and minute using created_at timestamp
        hour = int(from_date[8:10])
        minute = int(from_date[10:12])
        clauses.append("EXTRACT(HOUR FROM created_at) = @hour")
        clauses.append("EXTRACT(MINUTE FROM created_at) = @minute")
        params.append(bigquery.ScalarQueryParameter("hour", "INT64", hour))
        params.append(bigquery.ScalarQueryParameter("minute", "INT64", minute))

        if repo:
            clauses.append("repo.name = @repo")
            params.append(bigquery.ScalarQueryParameter("repo", "STRING", repo))
        if actor:
            clauses.append("actor.login = @actor")
            params.append(bigquery.ScalarQueryParameter("actor", "STRING", actor))
        if event_type:
            clauses.append("type = @event_type")
            params.append(bigquery.ScalarQueryParameter("event_type", "STRING", event_type))

        where = " AND ".join(clauses) if clauses else "1=1"

        query = f"""
        SELECT
            type,
            created_at,
            actor.login as actor_login,
            actor.id as actor_id,
            repo.name as repo_name,
            repo.id as repo_id,
            payload
        FROM {table}
        WHERE {where}
        ORDER BY created_at
        LIMIT 1000
        """

        job_config = bigquery.QueryJobConfig(query_parameters=params)
        results = client.query(query, job_config=job_config)
        return [dict(row) for row in results]
