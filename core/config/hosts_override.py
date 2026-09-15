"""Operator hosts-override config loading.

Several egress-allowlist modules resolve their hostname list as
"operator override → static default", with the override stored as a
flat ``{"hosts": [...]}`` JSON file under ``~/.config/raptor/``
(``git-proxy-hosts.json``, ``semgrep-proxy-hosts.json``,
``cve-diff-forge-hosts.json``, ...). This module owns the one loader
they share; each consumer keeps its own config path and static
default.

Threat model: the override config is operator-trusted — anyone who
can write ``~/.config/raptor/`` already controls the RAPTOR install.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

#: Byte budget for the override file, checked via ``stat()`` before
#: any read. Trade-off at this bound: lower catches a fat-fingered
#: path (a log or SARIF dumped onto the config path) before it is
#: parsed, but risks rejecting a legitimately huge allowlist; higher
#: tolerates any plausible operator config but parses junk. 1 MiB is
#: orders of magnitude above any real host list (tens of thousands of
#: entries) while still refusing obviously-not-a-config files.
_MAX_OVERRIDE_BYTES = 1024 * 1024


def load_hosts_override(
    config_path: Path,
    key: str = "hosts",
    *,
    missing_key_ok: bool = False,
) -> list[str] | None:
    """Return the operator override host list, or None when no
    override is configured.

    A file that parses to the ``{"<key>": [...]}`` schema is an
    explicit operator statement and is honoured even when the list
    is empty (or every entry is dropped): the override REPLACES the
    consumer's permissive static default, so ``{"hosts": []}`` must
    mean "allow nothing", not "restore the public default" — the
    ban-public-hosts use case is exactly why overrides replace
    rather than extend.

    ``key`` selects the list inside the JSON object — ``"hosts"``
    for the flat single-list grammar, ``"proxy_hosts"`` for the
    cc/codeql dispatch grammar, or a tool name for the SCA per-tool
    grammar. With ``missing_key_ok=True`` an object WITHOUT the key
    returns None silently (per-tool files legitimately configure a
    subset of tools); otherwise the absence is warned like any other
    schema surprise.

    Malformed JSON, non-UTF-8 bytes, an oversize file (see
    ``_MAX_OVERRIDE_BYTES``), or an unexpected schema still
    degrade to None (consumers keep their static default) — but
    loudly, so a fat-fingered restrictive config never fails open in
    silence. Entries are whitespace-stripped (a hand-edited
    ``"host.example "`` passes validation but can never match the
    proxy's hostname comparison) and deduplicated preserving order;
    non-string and empty entries are dropped with a warning.
    """
    if not config_path.exists():
        return None
    try:
        size = config_path.stat().st_size
    except OSError as exc:
        logger.warning(
            "hosts override %s is unreadable (%s) — keeping the "
            "static default host list", config_path, exc,
        )
        return None
    if size > _MAX_OVERRIDE_BYTES:
        logger.warning(
            "hosts override %s is %d bytes (limit %d) — not a "
            "plausible host list; keeping the static default host "
            "list", config_path, size, _MAX_OVERRIDE_BYTES,
        )
        return None
    try:
        data = json.loads(
            config_path.read_text(encoding="utf-8"),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning(
            "hosts override %s is unreadable (%s) — keeping the "
            "static default host list", config_path, exc,
        )
        return None
    if missing_key_ok and isinstance(data, dict) and key not in data:
        return None
    hosts = data.get(key) if isinstance(data, dict) else None
    if not isinstance(hosts, list):
        logger.warning(
            'hosts override %s has an unexpected schema (expected '
            '{"%s": [...]}) — keeping the static default host '
            "list", config_path, key,
        )
        return None
    seen: set[str] = set()
    result: list[str] = []
    dropped = 0
    for entry in hosts:
        if not isinstance(entry, str):
            dropped += 1
            continue
        host = entry.strip()
        if not host:
            dropped += 1
            continue
        if host not in seen:
            seen.add(host)
            result.append(host)
    if dropped:
        logger.warning(
            "hosts override %s: dropped %d non-string or empty "
            "entry(ies)", config_path, dropped,
        )
    return result
