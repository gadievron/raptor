"""Shared docker-stderr failure classifier.

A misleading `give_up=no_image` can mask the real cause — e.g. Colima VM
disk exhaustion mid-pull (`no space left on device`). Without a categorical
signal the agent cannot distinguish "host can't store this right now" from
"image truly absent on the registry."

This module classifies docker subprocess stderr into one of:

* ``ok``               — succeeded
* ``disk_full``        — host or VM disk exhausted; retry-eligible after prune
* ``manifest_unknown`` — image truly absent (permanent for this ref/version)
* ``transport``        — timeout / connection error / HTTP 5xx (transient)
* ``auth``             — 401 / 403 / pull access denied (do not retry without creds)
* ``network``          — DNS / unreachable / network is down (transient)
* ``daemon_corruption``— containerd/daemon corrupted (disk-pressure); not retry-eligible
* ``gpg_signature``    — apt/yum GPG signature failure during build
* ``fatal_compose_config`` — malformed docker-compose config (permanent)
* ``rate_limited``     — registry pull rate-limit (retry-eligible after cooldown)
* ``unknown``          — stderr didn't match any known pattern; treat as transport

Used by ``docker_run.py``, ``docker_build.py``, ``docker_compose_up.py``,
and ``run_in_container.py`` to populate a ``reason_class`` field on their
result payloads.
"""

from __future__ import annotations

import re
from typing import Literal

DockerFailureClass = Literal[
    "ok",
    "daemon_corruption",
    "disk_full",
    "manifest_unknown",
    "transport",
    "auth",
    "network",
    "gpg_signature",
    "fatal_compose_config",
    "rate_limited",
    "unknown",
]

# Disk PRESSURE (host near full, qcow2 near its cap) can corrupt the colima
# containerd storage mid-run. Builds then fail with "corrupted containerd
# storage: persistent input/output error" / "failed to retrieve image list:
# rpc error". This is HOST INFRA corruption — NOT disk_full (prune+retry is
# futile; the daemon stays corrupted until restarted) and NOT the agent's
# build error. Checked FIRST so the corruption signature wins over disk_full's
# generic "input/output error" pattern. NOT retry-eligible in-run (the heal is
# a daemon restart at the bench layer); one corruption otherwise cascades into
# many futile-retry failures.
_DAEMON_CORRUPTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"corrupted containerd storage", re.IGNORECASE),
    re.compile(r"failed to retrieve image list", re.IGNORECASE),
    re.compile(r"rpc error: code = Unknown", re.IGNORECASE),
)

# Patterns ordered by specificity: more specific first.
_DISK_FULL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"no space left on device", re.IGNORECASE),
    re.compile(r"\bdisk full\b", re.IGNORECASE),
    re.compile(r"write.+: no space", re.IGNORECASE),
    re.compile(r"input/output error", re.IGNORECASE),  # often disk-related on Colima
)

# GPG / apt signature errors. mirror.gcr.io's bullseye base images can have
# stale GPG keyrings; `apt-get update` then fails with "At least one invalid
# signature was encountered". Recoverable via apt_unsafe=true flag in
# dockerfile_gen, OR a base-image pivot to bookworm/alpine.
_GPG_SIGNATURE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"At least one invalid signature was encountered", re.IGNORECASE),
    re.compile(r"GPG error.+invalid signature", re.IGNORECASE),
    re.compile(r"is not signed", re.IGNORECASE),
    re.compile(r"NO_PUBKEY", re.IGNORECASE),
)

# Permanent compose-config errors. Compose retries on OCI mount errors
# (host bind path missing) can cycle until the wall guard fires — never
# reaching verify even when the agent is making real progress. These are
# CONFIG bugs, not transient: retrying without changing inputs is futile.
_FATAL_COMPOSE_CONFIG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"cannot create subdirectories", re.IGNORECASE),
    re.compile(r"bind source path does not exist", re.IGNORECASE),
    re.compile(r"invalid mount config for type", re.IGNORECASE),
)

_MANIFEST_UNKNOWN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bmanifest unknown\b", re.IGNORECASE),
    re.compile(r"manifest for .+ not found", re.IGNORECASE),
    re.compile(r"repository .+ not found", re.IGNORECASE),
    re.compile(r"pull access denied for .+, repository does not exist", re.IGNORECASE),
    re.compile(r"image not found", re.IGNORECASE),
)

_AUTH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bunauthorized\b", re.IGNORECASE),
    re.compile(r"\bauthentication required\b", re.IGNORECASE),
    re.compile(r"\bdenied\b", re.IGNORECASE),
    re.compile(r"\b401\b"),
    re.compile(r"\b403\b"),
)

_TRANSPORT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"received unexpected HTTP status:?\s*(?:429|500|502|503|504)", re.IGNORECASE
    ),
    re.compile(r"\btoomanyrequests\b", re.IGNORECASE),
    re.compile(r"\bconnection reset\b", re.IGNORECASE),
    re.compile(r"i/o timeout", re.IGNORECASE),
    re.compile(r"server misbehaving", re.IGNORECASE),
    re.compile(r"\btimeout\b", re.IGNORECASE),
    re.compile(r"\beof\b", re.IGNORECASE),
)

_NETWORK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"network is unreachable", re.IGNORECASE),
    re.compile(r"network is down", re.IGNORECASE),
    re.compile(r"temporary failure in name resolution", re.IGNORECASE),
    re.compile(r"no route to host", re.IGNORECASE),
    re.compile(r"\bdns resolution\b", re.IGNORECASE),
    re.compile(r"could not resolve host", re.IGNORECASE),
)

# Docker Hub anonymous pull rate limit. Checked BEFORE auth because Docker
# Hub rate-limit messages use words like "unauthenticated" that would
# otherwise match the _AUTH_PATTERNS \bdenied\b / \bunauthorized\b. Without
# this, a rate-limited compose-pull is mislabeled as 'unknown' and the agent
# can give up as 'proprietary'.
_RATE_LIMIT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"unauthenticated pull rate limit", re.IGNORECASE),
)

# Ordered specific→general. Order is load-bearing — see classify_docker_stderr
# docstring for the rationale on each precedence pair.
# 1. disk_full first: often masks downstream errors when Colima VM is full.
# 2. gpg_signature: actionable (apt_unsafe=true / base-image pivot).
# 3. fatal_compose_config: OCI mount/bind errors are permanent; checked
#    before manifest_unknown to avoid mislabelling.
# 4. manifest_unknown: permanent, no retry.
# 5. rate_limited: BEFORE auth so "unauthenticated pull rate limit"
#    does not match \bunauthorized\b in _AUTH_PATTERNS.
# 6. auth: permanent without creds.
# 7. network then transport: both transient; transport is catch-all.
_CLASSIFIER_TABLE: tuple[
    tuple[tuple[re.Pattern[str], ...], DockerFailureClass], ...
] = (
    # daemon_corruption FIRST: its "corrupted containerd storage" co-occurs with
    # "input/output error", which would otherwise match disk_full and trigger a
    # futile prune+retry on a daemon that needs a restart, not a prune.
    (_DAEMON_CORRUPTION_PATTERNS, "daemon_corruption"),
    (_DISK_FULL_PATTERNS, "disk_full"),
    (_GPG_SIGNATURE_PATTERNS, "gpg_signature"),
    (_FATAL_COMPOSE_CONFIG_PATTERNS, "fatal_compose_config"),
    (_MANIFEST_UNKNOWN_PATTERNS, "manifest_unknown"),
    (_RATE_LIMIT_PATTERNS, "rate_limited"),
    (_AUTH_PATTERNS, "auth"),
    (_NETWORK_PATTERNS, "network"),
    (_TRANSPORT_PATTERNS, "transport"),
)


def classify_docker_stderr(stderr: str | bytes | None) -> DockerFailureClass:
    """Map a docker-subprocess stderr to a :class:`DockerFailureClass`.

    Pattern checks are ordered specific→general. `disk_full` is checked
    BEFORE `auth` because some pull-access-denied messages are downstream
    of an actual disk error (Colima VM full → registry timeout → vague
    error). Returns ``"unknown"`` only when no pattern matches, treating
    the failure as transport-class for retry purposes is the caller's
    decision.
    """
    if not stderr:
        return "unknown"  # subprocess died w/o stderr → no evidence to classify
    if isinstance(stderr, bytes):
        try:
            stderr = stderr.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            return "unknown"
    for patterns, reason_class in _CLASSIFIER_TABLE:
        if any(pat.search(stderr) for pat in patterns):
            return reason_class
    return "unknown"


def is_retry_eligible(reason_class: DockerFailureClass) -> bool:
    """True iff a failure with this class is worth retrying.

    ``disk_full`` is retry-eligible AFTER a prune. ``transport`` and
    ``network`` are retry-eligible after a short wait. ``manifest_unknown``
    and ``auth`` are permanent; retrying without changing inputs is futile.
    ``unknown`` is treated as transport (give it one chance).
    """
    return reason_class in {
        "disk_full",
        "transport",
        "network",
        "unknown",
        "rate_limited",
    }


__all__ = [
    "DockerFailureClass",
    "classify_docker_stderr",
    "is_retry_eligible",
]
