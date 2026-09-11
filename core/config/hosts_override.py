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


def load_hosts_override(config_path: Path) -> list[str] | None:
    """Return the operator override host list, or None when no
    override is configured.

    A file that parses to the ``{"hosts": [...]}`` schema is an
    explicit operator statement and is honoured even when the list
    is empty (or every entry is dropped): the override REPLACES the
    consumer's permissive static default, so ``{"hosts": []}`` must
    mean "allow nothing", not "restore the public default" — the
    ban-public-hosts use case is exactly why overrides replace
    rather than extend.

    Malformed JSON, non-UTF-8 bytes, or an unexpected schema still
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
        data = json.loads(
            config_path.read_text(encoding="utf-8"),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning(
            "hosts override %s is unreadable (%s) — keeping the "
            "static default host list", config_path, exc,
        )
        return None
    hosts = data.get("hosts") if isinstance(data, dict) else None
    if not isinstance(hosts, list):
        logger.warning(
            'hosts override %s has an unexpected schema (expected '
            '{"hosts": [...]}) — keeping the static default host '
            "list", config_path,
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
