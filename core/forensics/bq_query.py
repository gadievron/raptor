"""Typed BigQuery query execution for `libexec/raptor-bq-query`.

This module is BOTH:

  * a library — query-shape validation, proxy-host resolution, and the
    ``execute()`` entry point the wrapper calls in ``--no-sandbox``
    mode, and
  * the sandbox child — ``python3 core/forensics/bq_query.py`` reads a
    JSON request on stdin, runs the query, and prints the JSON result
    envelope on stdout. The wrapper spawns exactly that command under
    ``core.sandbox.run_untrusted_networked`` with the egress proxy
    pinned to the BigQuery hosts.

Because the child runs as a plain script (``sys.path[0]`` is this
directory, not the repo root), module-level imports here must be
stdlib-only. The Google client libraries are imported lazily inside
``execute()``.

Query-shape validation is MISUSE PREVENTION, not SQL sandboxing: it
stops the obvious wrong turns (DML/DDL, multi-statement scripts,
comment-smuggled keywords) so an agent driving this wrapper cannot
casually mutate state. The real security boundary is BigQuery's own
credential scoping — run the wrapper with a service account that only
holds the read-only ``BigQuery User`` role on the target project.

Exit-code contract (shared by wrapper and child):

  0  success
  2  trust-marker refusal / argparse usage error (wrapper only)
  3  query validation rejected (shape, size, statement type)
  4  input error (unreadable query file, malformed child request)
  5  dependency missing (google-cloud-bigquery not installed)
  6  credential resolution failed (GOOGLE_APPLICATION_CREDENTIALS)
  7  query execution failed (BigQuery API error, bytes-billed cap hit)
  8  timeout (query or sandboxed child)
  9  sandbox setup/launch failure (wrapper only)

Structured errors are a single JSON line on stderr:
``{"error": "<kind>", "message": "...", "exit_code": N}``.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# --- exit codes ---------------------------------------------------------

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_VALIDATION = 3
EXIT_INPUT = 4
EXIT_DEPENDENCY = 5
EXIT_CREDENTIALS = 6
EXIT_QUERY = 7
EXIT_TIMEOUT = 8
EXIT_SANDBOX = 9

# Default cap on bytes billed: 200 GB (~$1.14 at $6.25/TiB) — above the
# skill's documented "typical query" band ($0.10–$1.00) but far below
# the multi-TiB accidents unfiltered wildcard scans produce. Callers
# raise it explicitly with --max-bytes-billed when a broad scan is
# intentional.
DEFAULT_MAX_BYTES_BILLED = 200 * 1000**3

DEFAULT_TIMEOUT_S = 300.0

# BigQuery's own GoogleSQL query-length ceiling is 1024k characters;
# anything bigger is misuse regardless of content.
MAX_QUERY_BYTES = 1024 * 1024

# Statement keywords the wrapper accepts. Read-only surface: SELECT and
# WITH (CTE prologue). Everything else — DML (INSERT/UPDATE/DELETE/
# MERGE/TRUNCATE), DDL (CREATE/ALTER/DROP), scripting (DECLARE/BEGIN/
# CALL/EXECUTE), session statements (SET/EXPORT/GRANT) — is rejected.
ALLOWED_LEADING_KEYWORDS = frozenset({"SELECT", "WITH"})

# BigQuery pricing constant used for dry-run cost estimates.
_USD_PER_TIB = 6.25

# --- errors -------------------------------------------------------------


class BQQueryError(Exception):
    """Base class carrying the structured-error kind and exit code."""

    kind = "error"
    exit_code = EXIT_QUERY


class QueryValidationError(BQQueryError):
    kind = "validation"
    exit_code = EXIT_VALIDATION


class RequestInputError(BQQueryError):
    kind = "input"
    exit_code = EXIT_INPUT


class DependencyError(BQQueryError):
    kind = "dependency"
    exit_code = EXIT_DEPENDENCY


class CredentialsError(BQQueryError):
    kind = "credentials"
    exit_code = EXIT_CREDENTIALS


class QueryExecutionError(BQQueryError):
    kind = "query"
    exit_code = EXIT_QUERY


class QueryTimeoutError(BQQueryError):
    kind = "timeout"
    exit_code = EXIT_TIMEOUT


def write_error_json(stream, exc_or_kind, message: str | None = None,
                     exit_code: int | None = None) -> int:
    """Emit the single-line structured error and return its exit code."""
    if isinstance(exc_or_kind, BQQueryError):
        kind = exc_or_kind.kind
        message = str(exc_or_kind)
        exit_code = exc_or_kind.exit_code
    else:
        kind = str(exc_or_kind)
        if exit_code is None:
            exit_code = EXIT_QUERY
    stream.write(json.dumps({
        "error": kind,
        "message": message or "",
        "exit_code": exit_code,
    }) + "\n")
    return exit_code


# --- query-shape validation ----------------------------------------------


def strip_sql_noise(sql: str) -> str:
    """Return *sql* with comments removed and string bodies blanked.

    Handles ``--`` and ``#`` line comments, ``/* */`` block comments
    (GoogleSQL block comments do not nest), single/double-quoted and
    triple-quoted string literals with backslash escapes, and backtick
    identifiers. Best-effort lexing for misuse prevention — NOT a full
    GoogleSQL lexer; exotic literal forms may over- or under-blank, and
    the failure direction is a rejected query, never a smuggled one
    reaching a broader surface than the credential allows.
    """
    out: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        two = sql[i:i + 2]
        three = sql[i:i + 3]
        if two == "--" or ch == "#":
            j = sql.find("\n", i)
            i = n if j == -1 else j  # keep the newline itself
            continue
        if two == "/*":
            j = sql.find("*/", i + 2)
            out.append(" ")
            i = n if j == -1 else j + 2
            continue
        if three in ("'''", '"""'):
            quote = three
            j = i + 3
            while j < n:
                if sql[j] == "\\":
                    j += 2
                    continue
                if sql[j:j + 3] == quote:
                    j += 3
                    break
                j += 1
            out.append("''")
            i = min(j, n)
            continue
        if ch in ("'", '"', "`"):
            j = i + 1
            while j < n:
                if sql[j] == "\\":
                    j += 2
                    continue
                if sql[j] == ch:
                    j += 1
                    break
                j += 1
            out.append("''")
            i = min(j, n)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def validate_query(sql: str) -> str:
    """Validate the query shape; return the query or raise.

    Rules (misuse prevention, not SQL sandboxing — see module
    docstring):

      * non-empty after BOM/whitespace/comment stripping
      * at most :data:`MAX_QUERY_BYTES` long
      * leading keyword must be SELECT or WITH
      * single statement — a ``;`` outside strings/comments may only
        be trailing
    """
    if not isinstance(sql, str):
        raise QueryValidationError("query must be a string")
    sql = sql.lstrip("﻿")
    if len(sql.encode("utf-8", errors="replace")) > MAX_QUERY_BYTES:
        raise QueryValidationError(
            f"query exceeds {MAX_QUERY_BYTES} bytes — BigQuery's own "
            "query-length ceiling is 1024k characters"
        )
    stripped = strip_sql_noise(sql)
    if not stripped.strip():
        raise QueryValidationError("query is empty (after comment stripping)")

    match = re.match(r"\s*([A-Za-z_]+)", stripped)
    if not match:
        raise QueryValidationError(
            "query does not start with an SQL keyword"
        )
    keyword = match.group(1).upper()
    if keyword not in ALLOWED_LEADING_KEYWORDS:
        allowed = "/".join(sorted(ALLOWED_LEADING_KEYWORDS))
        raise QueryValidationError(
            f"leading keyword {keyword!r} is not allowed — this wrapper "
            f"only runs read-only queries ({allowed}). DML/DDL and "
            "scripting statements are rejected by design."
        )

    _head, sep, tail = stripped.partition(";")
    if sep and tail.strip():
        raise QueryValidationError(
            "multiple SQL statements detected — the wrapper runs exactly "
            "one statement per invocation"
        )
    return sql


# --- egress host resolution ----------------------------------------------

# Hosts the google-cloud-bigquery REST path dials:
#   bigquery.googleapis.com   — the BigQuery v2 API itself
#   oauth2.googleapis.com     — service-account token exchange
#                               (default token_uri in modern key files)
#   www.googleapis.com        — legacy token endpoint + discovery paths
# The BigQuery Storage read API (bigquerystorage.googleapis.com) is
# deliberately NOT listed: the wrapper never requests it, and adding it
# would widen egress for a path we do not use.
_DEFAULT_BQ_HOSTS: tuple[str, ...] = (
    "bigquery.googleapis.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
)

_OVERRIDE_CONFIG_PATH = (
    Path.home() / ".config" / "raptor" / "bq-proxy-hosts.json"
)

# Real service-account key files are <4 KB; refuse pathological inputs
# (same cap as the evidence-kit GHArchiveClient).
_CREDS_INLINE_MAX = 64 * 1024


def _load_override() -> list[str] | None:
    """Operator override list, or None. Same contract as the git
    proxy-hosts override: the override REPLACES the default so a shop
    with a locked-down mirror can also ban the public endpoints."""
    if not _OVERRIDE_CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(_OVERRIDE_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        return None
    seen: set[str] = set()
    result: list[str] = []
    for h in hosts:
        if isinstance(h, str) and h and h not in seen:
            seen.add(h)
            result.append(h)
    return result or None


def _token_uri_host() -> str | None:
    """Hostname of the ``token_uri`` in the configured credentials.

    Older service-account key files carry legacy token endpoints
    (``accounts.google.com``, ``www.googleapis.com``); pin whatever the
    key actually declares so token refresh is not denied by the proxy.
    Tolerant: any parse problem returns None (the static default hosts
    still cover modern key files).
    """
    creds_value = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not creds_value:
        return None
    try:
        if creds_value.lstrip().startswith("{"):
            if len(creds_value) > _CREDS_INLINE_MAX:
                return None
            info = json.loads(creds_value)
        else:
            path = Path(creds_value)
            if not path.is_file() or path.stat().st_size > _CREDS_INLINE_MAX:
                return None
            info = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(info, dict):
        return None
    token_uri = info.get("token_uri")
    if not isinstance(token_uri, str) or "://" not in token_uri:
        return None
    from urllib.parse import urlsplit
    try:
        host = urlsplit(token_uri).hostname
    except ValueError:
        return None
    return host or None


def proxy_hosts_for_bq() -> list[str]:
    """Egress-proxy hostname allowlist for the sandboxed BigQuery child.

    Resolution: operator override (total replace) → static default
    plus the host of the credential file's ``token_uri``.
    """
    override = _load_override()
    if override is not None:
        return override
    hosts = list(_DEFAULT_BQ_HOSTS)
    token_host = _token_uri_host()
    if token_host and token_host not in hosts:
        hosts.append(token_host)
    return hosts


# --- execution ------------------------------------------------------------


def _json_default(obj: Any) -> str:
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(bytes(obj)).decode("ascii")
    return str(obj)


def _resolve_credentials() -> tuple[Any, str | None]:
    """Resolve BigQuery credentials — file path, inline JSON, or ADC.

    Mirrors the evidence-kit ``GHArchiveClient`` contract:
    ``GOOGLE_APPLICATION_CREDENTIALS`` may be a key-file path or the
    inline service-account JSON itself; anything else falls through to
    Application Default Credentials.
    """
    scopes = ["https://www.googleapis.com/auth/bigquery"]
    creds_value = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")

    if creds_value.lstrip().startswith("{"):
        if len(creds_value) > _CREDS_INLINE_MAX:
            raise CredentialsError(
                "GOOGLE_APPLICATION_CREDENTIALS inline JSON exceeds "
                f"{_CREDS_INLINE_MAX} bytes — service-account keys are "
                "typically <4 KB; refusing pathological input"
            )
        from google.oauth2 import service_account
        try:
            info = json.loads(creds_value)
            credentials = service_account.Credentials.from_service_account_info(
                info, scopes=scopes
            )
        except (ValueError, KeyError) as exc:
            raise CredentialsError(
                f"could not parse inline service-account JSON: {exc}"
            ) from exc
        return credentials, info.get("project_id")

    import google.auth
    from google.auth import exceptions as auth_exceptions
    try:
        return google.auth.default(scopes=scopes)
    except auth_exceptions.GoogleAuthError as exc:
        raise CredentialsError(
            f"could not resolve BigQuery credentials: {exc} — set "
            "GOOGLE_APPLICATION_CREDENTIALS to a service-account key "
            "file (read-only BigQuery User role)"
        ) from exc


def execute(sql: str, *, project: str | None = None,
            max_bytes_billed: int = DEFAULT_MAX_BYTES_BILLED,
            timeout_s: float = DEFAULT_TIMEOUT_S,
            dry_run: bool = False) -> dict:
    """Validate and run one read-only query; return the result envelope.

    Raises the typed :class:`BQQueryError` subclasses documented in the
    module docstring.
    """
    sql = validate_query(sql)

    try:
        from google.cloud import bigquery
    except ImportError as exc:
        raise DependencyError(
            "google-cloud-bigquery is not installed — "
            "pip install google-cloud-bigquery google-auth"
        ) from exc

    credentials, default_project = _resolve_credentials()
    try:
        client = bigquery.Client(
            credentials=credentials,
            project=project or default_project,
        )
    except Exception as exc:  # classified below
        raise _classify_google_error(exc) from exc

    job_config = bigquery.QueryJobConfig(use_legacy_sql=False)
    if dry_run:
        job_config.dry_run = True
        job_config.use_query_cache = False
    else:
        job_config.maximum_bytes_billed = int(max_bytes_billed)

    import concurrent.futures
    try:
        job = client.query(sql, job_config=job_config)
        if dry_run:
            n = int(job.total_bytes_processed or 0)
            return {
                "dry_run": True,
                "total_bytes_processed": n,
                "gigabytes_processed": round(n / 1024**3, 4),
                "estimated_cost_usd": round(n / 1024**4 * _USD_PER_TIB, 4),
            }
        rows_iter = job.result(timeout=timeout_s)
        rows = [dict(row) for row in rows_iter]
    except (concurrent.futures.TimeoutError, TimeoutError) as exc:
        raise QueryTimeoutError(
            f"query did not complete within {timeout_s}s"
        ) from exc
    except BQQueryError:
        raise
    except Exception as exc:  # classified below
        raise _classify_google_error(exc) from exc

    return {
        "dry_run": False,
        "rows": rows,
        "row_count": len(rows),
        "job": {
            "job_id": job.job_id,
            "project": client.project,
            "total_bytes_processed": job.total_bytes_processed,
            "total_bytes_billed": job.total_bytes_billed,
            "cache_hit": job.cache_hit,
        },
    }


def _classify_google_error(exc: Exception) -> BQQueryError:
    """Map a Google-client exception onto the typed error taxonomy."""
    module = type(exc).__module__ or ""
    if module.startswith(("google.auth", "google.oauth2")):
        return CredentialsError(f"credential error: {exc}")
    return QueryExecutionError(f"query failed: {exc}")


# --- sandbox-child entry point --------------------------------------------


def _child_main() -> int:
    """Read a JSON request on stdin, execute, print the envelope."""
    raw = sys.stdin.read()
    try:
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise TypeError("request must be a JSON object")
        sql = request["sql"]
    except (TypeError, ValueError, KeyError) as exc:
        return write_error_json(
            sys.stderr, RequestInputError(f"malformed child request: {exc}")
        )

    try:
        result = execute(
            sql,
            project=request.get("project"),
            max_bytes_billed=int(
                request.get("max_bytes_billed", DEFAULT_MAX_BYTES_BILLED)
            ),
            timeout_s=float(request.get("timeout_s", DEFAULT_TIMEOUT_S)),
            dry_run=bool(request.get("dry_run", False)),
        )
    except BQQueryError as exc:
        return write_error_json(sys.stderr, exc)

    json.dump(result, sys.stdout, default=_json_default)
    sys.stdout.write("\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(_child_main())
