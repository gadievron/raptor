"""Egress-proxy hostname allowlist for ``core.git`` subprocesses.

Two-layer resolution: operator override → static default. There's no
calibrate layer here because git's network reach is URL-derived per
call (``git clone https://gitlab.example.com/...`` reaches
gitlab.example.com regardless of the binary), not binary-scoped.
``git --version`` doesn't network at all, so calibrating the binary
would only ever capture filesystem reads — useless for the
proxy_hosts decision.

Resolution layers (priority high → low):

  1. **Operator override** — ``~/.config/raptor/git-proxy-hosts.json``
     with a flat ``{"hosts": [...]}`` list. Required for shops on a
     private GitHub Enterprise / GitLab self-hosted / corporate git
     mirror — the public-host static default doesn't reach those.
  2. **Static default** — the documented set of public forge hosts
     RAPTOR commonly clones from (github.com + gitlab.com + the
     GitHub LFS / userassets / archive subdomains).

The override REPLACES the default rather than extending it. An
operator on a private mirror typically wants to ban public clones
(supply-chain hygiene, internal-only policy) — extending would
weaken that boundary.

The egress proxy enforces deny-by-default at runtime regardless of
what this module returns. If a clone reaches a host outside the
resolved allowlist, the proxy denies, the operator sees a clear
"host not in proxy_hosts" error from the clone subprocess, and
either updates the override config or routes around (e.g. cloning
via a known-allowed mirror URL).

Threat model: the override config is operator-trusted, same as
``cc_proxy_hosts`` / ``codeql_proxy_hosts``. An operator who can
write to ``~/.config/raptor/`` already controls the RAPTOR install.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


_OVERRIDE_CONFIG_PATH = (
    Path.home() / ".config" / "raptor" / "git-proxy-hosts.json"
)


# Static default — public forges + GitHub LFS / archive / userassets
# subdomains LFS-using clones redirect through. The set was empirically
# expanded after operators saw mid-checkout failures with "unable to
# access 'https://raw.githubusercontent.com/...'" — these hosts MUST
# stay together (LFS clone breaks if any are missing).
_DEFAULT_GIT_HOSTS: tuple[str, ...] = (
    "github.com",
    "gitlab.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "media.githubusercontent.com",
)


def _load_override() -> Optional[list[str]]:
    """Return the operator override list, or None when no override is
    configured. Tolerant: malformed JSON, non-UTF-8 bytes, or an
    unexpected schema all degrade to None — production failure mode
    is loud at the proxy (clone fails with "host not in
    proxy_hosts"), not silent at startup."""
    if not _OVERRIDE_CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(
            _OVERRIDE_CONFIG_PATH.read_text(encoding="utf-8"),
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


def proxy_hosts_for_git() -> list[str]:
    """Egress-proxy hostname allowlist for ``core.git`` subprocesses.

    Two-layer resolution: operator override → static default.

    Returns a fresh list each call so the caller can mutate /
    extend it (e.g. ``ls_remote`` callers add the URL's host on
    top) without affecting subsequent calls.
    """
    override = _load_override()
    if override is not None:
        return override
    return list(_DEFAULT_GIT_HOSTS)
