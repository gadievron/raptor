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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def load_hosts_override(config_path: Path) -> list[str] | None:
    """Return the operator override host list, or None when no
    override is configured.

    Tolerant: malformed JSON, non-UTF-8 bytes, or an unexpected
    schema all degrade to None — the production failure mode is loud
    at the egress proxy ("host not in allowlist" from the consumer's
    subprocess), not silent at startup. Hosts are deduplicated
    preserving order; non-string and empty entries are dropped; an
    override that yields nothing usable is treated as absent.
    """
    if not config_path.exists():
        return None
    try:
        data = json.loads(
            config_path.read_text(encoding="utf-8"),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        return None
    seen: set = set()
    result: list = []
    for h in hosts:
        if isinstance(h, str) and h and h not in seen:
            seen.add(h)
            result.append(h)
    return result or None
