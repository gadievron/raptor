"""Dependency-Track push integration.

OWASP `Dependency-Track <https://dependencytrack.org/>`_ is a
self-hosted SBOM/VEX management platform. SCA already emits
CycloneDX 1.5 SBOMs; this module adds a one-shot upload path so
operators running DT can post each scan's SBOM into their portfolio
without copying files around.

## CLI

  ``raptor-sca dt-push --url https://dt.example.com \
                       --api-key $DT_API_KEY \
                       --bom out/sbom.cdx.json \
                       --project myapp --version 1.0``

## API surface used

DT 4.x exposes a single combined endpoint that handles project
lookup, conditional creation, and BOM upload in one call:

  ``POST /api/v1/bom``
  Body: ``{"projectName": str, "projectVersion": str,
          "autoCreate": bool, "bom": <base64-encoded BOM>}``
  Returns: ``{"token": str}`` — upload-progress token

The combined endpoint avoids multipart-form gymnastics and the
two-call lookup/create dance the older API required. Auth is
``X-Api-Key`` header.

## Egress

DT URLs are operator-supplied per-invocation, so they can't live
in :data:`SCA_ALLOWED_HOSTS`. The CLI constructs an
:class:`EgressClient` scoped to just the DT host for this one
call. The static SCA allowlist isn't extended.

## What this is NOT

* A live integration with DT's webhooks, policy engine, or
  notifications. We push BOMs; everything else is DT's
  responsibility.
* A BOM diff / dedup against the project's previous upload —
  DT's UI handles that on its side.
* Multi-target / batch uploads — one BOM per invocation. CI
  pipelines that scan multiple projects loop the dt-push
  invocation per target.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# DT's combined upload endpoint accepts BOMs up to ``bom.upload.size``
# (server-configurable; default 5 MB for typical setups). We cap our
# read at 50 MB to fail fast on truly large BOMs without making an
# unbounded request.
_MAX_BOM_BYTES = 50 * 1024 * 1024

# DT API timeout: BOM upload triggers indexing on the server side
# which can take seconds for large projects. Generous default; CI
# operators can override.
_DEFAULT_TIMEOUT = 60


def push_bom(
    *,
    url: str,
    api_key: str,
    bom_path: Path,
    project_name: str,
    project_version: str,
    auto_create: bool = True,
    timeout: int = _DEFAULT_TIMEOUT,
    http: Optional[Any] = None,
) -> Dict[str, Any]:
    """Push a CycloneDX BOM file to a Dependency-Track instance.

    ``url`` is the DT base URL (e.g. ``https://dt.example.com``) —
    NOT including the ``/api/v1/bom`` path; this function appends it.
    ``api_key`` goes into the ``X-Api-Key`` header.
    ``project_name`` + ``project_version`` identify the DT project.
    ``auto_create=True`` lets DT create a project if one with that
    name+version doesn't exist.

    ``http`` is an optional :class:`HttpClient` for testing /
    pre-built allowlists; the production CLI builds one scoped to
    the DT host.

    Returns ``{status, token, error}``:

      * ``status="uploaded"`` — BOM accepted, ``token`` is the
        DT upload-progress token (operators can poll
        ``/api/v1/event/token/<token>`` for completion).
      * ``status="error"`` — pre-flight or upload failure;
        ``error`` describes what went wrong.

    Idempotent w.r.t. DT's project state: re-uploading an
    identical BOM produces a new event but doesn't double-count
    components on the server side.
    """
    bom_bytes = _load_bom(bom_path)
    if isinstance(bom_bytes, dict):
        return bom_bytes              # pre-flight error

    if http is None:
        http = _build_egress_client(url)

    body = {
        "projectName": project_name,
        "projectVersion": project_version,
        "autoCreate": auto_create,
        "bom": base64.b64encode(bom_bytes).decode("ascii"),
    }
    endpoint = url.rstrip("/") + "/api/v1/bom"
    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
    }
    try:
        response = http.post_json(
            endpoint, body, timeout=timeout, headers=headers,
        )
    except Exception as e:                                  # noqa: BLE001
        logger.warning(
            "sca.dependency_track: upload to %s failed: %s",
            _redact_url(url), e,
        )
        return {
            "status": "error",
            "token": None,
            "error": f"DT upload failed: {e}",
        }

    token = response.get("token") if isinstance(response, dict) else None
    if not token:
        return {
            "status": "error",
            "token": None,
            "error": (
                f"DT response missing 'token' field — got "
                f"{response!r}; check API version + auth"
            ),
        }
    return {"status": "uploaded", "token": token, "error": None}


def _load_bom(bom_path: Path) -> Any:
    """Read the BOM file as bytes. Returns the bytes on success or a
    pre-flight error dict (``{status, error, token}``) on failure.

    Defensive against:
      * Path doesn't exist
      * File too large (bounded at ``_MAX_BOM_BYTES``)
      * Invalid JSON (we don't NEED to parse it — DT does — but a
        well-formed JSON check catches operator typos like
        passing the markdown report by mistake)
    """
    if not bom_path.is_file():
        return {
            "status": "error", "token": None,
            "error": f"BOM file not found: {bom_path}",
        }
    try:
        size = bom_path.stat().st_size
    except OSError as e:
        return {
            "status": "error", "token": None,
            "error": f"BOM stat failed for {bom_path}: {e}",
        }
    if size > _MAX_BOM_BYTES:
        return {
            "status": "error", "token": None,
            "error": (
                f"BOM file {bom_path} is {size} bytes; refusing to "
                f"upload >{_MAX_BOM_BYTES} bytes"
            ),
        }
    try:
        bom_bytes = bom_path.read_bytes()
    except OSError as e:
        return {
            "status": "error", "token": None,
            "error": f"BOM read failed for {bom_path}: {e}",
        }
    # Sanity: must be parseable JSON. DT will reject malformed
    # uploads server-side, but failing fast here saves a network
    # round-trip and gives the operator a clearer error.
    try:
        json.loads(bom_bytes)
    except json.JSONDecodeError as e:
        return {
            "status": "error", "token": None,
            "error": f"BOM file {bom_path} isn't valid JSON: {e}",
        }
    return bom_bytes


def _build_egress_client(url: str) -> Any:
    """Construct an :class:`EgressClient` allowlisted for the DT
    host.

    DT URLs are operator-supplied per invocation — not part of
    :data:`packages.sca.SCA_ALLOWED_HOSTS`. Building a client
    scoped to just this host means a misconfigured ``--url`` can't
    leak the SBOM to a wrong destination.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            f"DT URL must be http(s) with a hostname; got {url!r}"
        )
    from core.http.egress_backend import EgressClient
    from packages.sca import SCA_USER_AGENT
    return EgressClient(
        (parsed.hostname,), user_agent=SCA_USER_AGENT,
    )


def _redact_url(url: str) -> str:
    """Strip query string + fragment from a URL for logging.
    Operators sometimes pass auth via query (legacy DT setups);
    avoid leaking it into logs."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}{parsed.path}".rstrip("/")


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="raptor-sca dt-push",
        description=(
            "Push a CycloneDX SBOM to a Dependency-Track instance."
        ),
    )
    parser.add_argument(
        "--url", required=True,
        help="DT base URL (e.g. https://dt.example.com)",
    )
    parser.add_argument(
        "--api-key", required=False,
        help=(
            "DT API key (X-Api-Key header). Falls back to "
            "$DT_API_KEY env var if not supplied. Required either "
            "way."
        ),
    )
    parser.add_argument(
        "--bom", required=True, type=Path,
        help="Path to the CycloneDX BOM file (sbom.cdx.json)",
    )
    parser.add_argument(
        "--project", required=True,
        help="DT project name",
    )
    parser.add_argument(
        "--version", required=True,
        help="DT project version",
    )
    parser.add_argument(
        "--no-auto-create", action="store_true",
        help=(
            "Refuse to create the DT project if it doesn't exist. "
            "Default is to create on first push."
        ),
    )
    parser.add_argument(
        "--timeout", type=int, default=_DEFAULT_TIMEOUT,
        help=f"DT API timeout in seconds (default: {_DEFAULT_TIMEOUT})",
    )
    args = parser.parse_args(argv)

    import os
    api_key = args.api_key or os.environ.get("DT_API_KEY")
    if not api_key:
        print(
            "raptor-sca dt-push: --api-key not given and $DT_API_KEY "
            "is unset", file=sys.stderr,
        )
        return 2

    result = push_bom(
        url=args.url,
        api_key=api_key,
        bom_path=args.bom,
        project_name=args.project,
        project_version=args.version,
        auto_create=not args.no_auto_create,
        timeout=args.timeout,
    )
    if result["status"] == "uploaded":
        print(
            f"raptor-sca dt-push: SBOM uploaded to "
            f"{_redact_url(args.url)} for project "
            f"{args.project} {args.version}; token={result['token']}"
        )
        return 0
    print(
        f"raptor-sca dt-push: {result['error']}", file=sys.stderr,
    )
    return 1


__all__ = ["main", "push_bom"]
