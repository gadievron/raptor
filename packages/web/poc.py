"""Proof-of-concept artifacts for oracle-proven web findings.

Two portable artifacts per confirmed finding:

* a curl reproducer script — the finding's confirmation request plus
  the response evidence to look for;
* a RAPTOR-authored nuclei template whose matcher is generated FROM
  ``packages.web.markers`` (single source: the replay template can
  never drift from the oracle that confirmed the finding), so the
  verdict can be replayed by a genuinely independent implementation —
  different HTTP stack, different regex engine — and handed to the
  target owner as a regression check.

Both artifacts embed the confirmation payload, which may carry
credentials for authenticated findings: they are written 0600 via
fresh O_EXCL|O_NOFOLLOW inodes, and only findings passing the
oracle-proof gate (packages.web.verified_outcomes) get artifacts at
all.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.logging import get_logger
from core.security.redaction import redact_secrets
from packages.web.markers import MARKER_RES
from packages.web.verified_outcomes import has_exploit_oracle_evidence

if TYPE_CHECKING:
    from packages.web.models import WebFinding

logger = get_logger()


def _go_regex_for(vuln_type: str) -> str | None:
    """The class marker as a Go-compatible regex with inline flags.

    Our marker patterns deliberately avoid Python-only constructs
    (lookaround, conditional groups), so the pattern text ports to Go
    regexp verbatim; only the compile-time flags need translating to
    inline ``(?ims)`` prefixes.
    """
    pattern = MARKER_RES.get(vuln_type)
    if pattern is None:
        return None
    inline = ""
    if pattern.flags & re.IGNORECASE:
        inline += "i"
    if pattern.flags & re.MULTILINE:
        inline += "m"
    if pattern.flags & re.DOTALL:
        inline += "s"
    return (f"(?{inline})" if inline else "") + pattern.pattern


def _url_with_param(url: str, param: str, value: str) -> str:
    """URL with ``param`` replaced (not duplicated) in the query."""
    parsed = urlparse(url)
    query = [
        (name, existing)
        for name, existing in parse_qsl(parsed.query, keep_blank_values=True)
        if name != param
    ]
    query.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(query)))


def _confirmation_request(finding: WebFinding) -> tuple[str, str, str | None]:
    """(method, url, body) reproducing the finding's confirmation probe."""
    data = finding.to_dict()
    method = str(data.get("method") or "GET").upper()
    target = str(data.get("target_url") or data.get("url") or "")
    params = list(data.get("affected_parameters") or [])
    param = params[0] if params else None
    payload = str(data.get("confirmation_payload") or "")
    if method == "POST" and param:
        return method, target, urlencode({param: payload})
    if param:
        return method, _url_with_param(target, param, payload), None
    return method, target, None


def build_reproducer(finding: WebFinding) -> str | None:
    """A curl reproducer script for one oracle-proven finding."""
    data = finding.to_dict()
    if not has_exploit_oracle_evidence(data):
        return None
    method, url, body = _confirmation_request(finding)
    curl = ["curl", "-sk", "-X", method, json.dumps(url)]
    if body is not None:
        curl += ["--data", json.dumps(body)]
    signal = str(data.get("oracle_signal") or "")
    diff = str(data.get("diff_summary") or "")
    return (
        "#!/bin/sh\n"
        f"# RAPTOR reproducer — {data.get('finding_id')}: {data.get('title')}\n"
        f"# Class: {data.get('vuln_type')} ({data.get('cwe_id')})\n"
        f"# Oracle signal to expect in the response: {signal}\n"
        f"# Baseline/attack differential at confirmation: {diff}\n"
        "# Live-target replay requires fresh operator authorisation.\n"
        + " ".join(curl) + "\n"
    )


def build_nuclei_template(finding: WebFinding) -> str | None:
    """A nuclei replay template for one oracle-proven finding.

    All interpolated values are JSON-encoded — JSON is a YAML subset,
    so payload/URL content cannot break out of its YAML scalar.
    """
    data = finding.to_dict()
    if not has_exploit_oracle_evidence(data):
        return None
    vuln_type = str(data.get("vuln_type") or "")
    method, url, body = _confirmation_request(finding)
    parsed = urlparse(url)
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    finding_id = str(data.get("finding_id") or "web").lower()

    if vuln_type == "xss":
        matcher = (
            "      - type: word\n"
            "        part: body\n"
            "        words:\n"
            f"          - {json.dumps(str(data.get('confirmation_payload') or ''))}\n"
        )
    else:
        go_regex = _go_regex_for(vuln_type)
        if go_regex is None:
            return None
        matcher = (
            "      - type: regex\n"
            "        part: body\n"
            "        regex:\n"
            f"          - {json.dumps(go_regex)}\n"
        )

    lines = [
        f"id: raptor-replay-{re.sub(r'[^a-z0-9-]', '-', finding_id)}",
        "",
        "info:",
        f"  name: {json.dumps('RAPTOR replay — ' + str(data.get('title') or vuln_type))}",
        "  author: raptor",
        f"  severity: {data.get('severity') or 'high'}",
        f"  tags: {vuln_type},raptor-replay",
        "  description: >-",
        "    Replays the confirmation probe of an oracle-proven RAPTOR web",
        "    finding with the class marker as the matcher. A match replays",
        "    the verdict via an independent implementation; use as a",
        "    regression check after remediation.",
        "",
        "http:",
        f"  - method: {method}",
        "    path:",
        f"      - {json.dumps('{{BaseURL}}' + path)}",
    ]
    if body is not None:
        lines.append(f"    body: {json.dumps(body)}")
    lines += [
        "    matchers:",
        matcher.rstrip("\n"),
        "",
    ]
    return "\n".join(lines)


def write_web_pocs(
    findings: list[WebFinding],
    out_dir: Path,
    *,
    reveal_secrets: bool = False,
) -> list[Path]:
    """Write reproducer + replay-template artifacts; never raises."""
    poc_dir = out_dir / "pocs"
    written: list[Path] = []
    for finding in findings:
        try:
            reproducer = build_reproducer(finding)
            template = build_nuclei_template(finding)
        except Exception:
            logger.debug("poc build failed", exc_info=True)
            continue
        if reproducer is None and template is None:
            continue
        poc_dir.mkdir(parents=True, exist_ok=True)
        base = str(finding.id or "web").lower()
        if reproducer is not None:
            written.append(
                _write_private(poc_dir / f"{base}-reproducer.sh", reproducer)
            )
        if template is not None:
            written.append(
                _write_private(poc_dir / f"{base}-replay.yaml", template)
            )
    if written:
        logger.info(
            "Wrote %d PoC artifact(s) to %s: %s",
            len(written), poc_dir,
            ", ".join(
                redact_secrets(p.name, reveal_secrets=reveal_secrets)
                for p in written
            ),
        )
    return written


def _write_private(path: Path, content: str) -> Path:
    """Fresh 0600 inode; refuses to follow a pre-planted symlink."""
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path
