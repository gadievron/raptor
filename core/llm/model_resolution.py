"""Lazy Anthropic model alias resolution.

Anthropic publishes versioned snapshots (e.g. ``claude-haiku-4-5-20251001``)
but operators typically configure the unversioned alias
(``claude-haiku-4-5``) in ``~/.config/raptor/models.json``. The SDK then
sends the alias to ``/v1/messages`` and gets back ``404 not_found_error``
because Anthropic has no ``-latest`` alias for every model family.

This module resolves the alias to the most recent matching snapshot
from the live ``/v1/models`` inventory. Resolution is lazy and
per-process: the first call to :func:`resolve_anthropic` triggers one
inventory fetch; later calls hit an in-memory cache. Failure to fetch
(network, auth) falls through to verbatim — same failure mode as
today, the SDK still raises a clear 404 if the name is genuinely
unknown.

Scoped to Anthropic. Gemini and OpenAI IDs are stable enough that
operators pin them exactly; adding more providers is a one-line
conditional in the integration point at :func:`_read_config_models`.
"""

from __future__ import annotations

import threading
from typing import Optional

from core.logging import get_logger

logger = get_logger()


# Module-level cache. Populated on first :func:`resolve_anthropic` call;
# stays populated for the process lifetime. ``_INVENTORY_PROBED`` flips to
# ``True`` after the first fetch attempt regardless of outcome, so a
# transient network failure at startup doesn't trigger a retry on every
# subsequent read of ``models.json`` — the same posture as Anthropic's
# own SDK, which caches model lists between calls.
_INVENTORY: Optional[list[str]] = None
_INVENTORY_PROBED: bool = False
_INVENTORY_LOCK = threading.Lock()

# Per-process dedupe of resolution log lines. The inventory is cached
# but the resolver itself runs per-call: multiple readers of
# ``models.json`` within one process otherwise each emit their own
# "Resolved alias X -> Y" line, which is noisy and falsely implies
# repeated network calls. Track which (alias -> resolved) pairs we've
# already logged so each mapping logs exactly once.
_LOGGED_RESOLUTIONS: set[tuple[str, str]] = set()


def resolve_anthropic(name: str, api_key: Optional[str]) -> str:
    """Return the canonical Anthropic model ID for *name*.

    Resolution rules, in order:

      1. If *name* is an exact match for a published snapshot, return
         it verbatim — the operator pinned a specific version.
      2. If *name* is one date-suffix away from a canonical ID — i.e.
         every candidate of the form ``{name}-{next_segment}-...`` has
         ``next_segment`` an 8-digit ``YYYYMMDD`` — return the lex-max
         match. Lex-max == most-recent because the date is fixed-width.
      3. Otherwise, return *name* verbatim. This covers:
           - ambiguous aliases (``claude``, ``claude-opus``,
             ``claude-opus-4``) whose next segment is a family or
             version component, not a date — silent resolution would
             surprise the operator with a "random" model from the
             family. Better to 404 with the alias they typed.
           - typos and unknown families — same 404 they'd see without
             this resolver.

    Inventory is fetched lazily on first call per process. Failures
    (network, auth, malformed response) are absorbed silently and fall
    through to verbatim.
    """
    inventory = _get_inventory(api_key)
    if not inventory:
        return name

    if name in inventory:
        return name

    prefix = name + "-"
    candidates = [m for m in inventory if m.startswith(prefix)]
    if not candidates:
        return name

    # Guard against ambiguous aliases. The segment immediately after
    # ``{name}-`` must be a YYYYMMDD date in EVERY candidate; otherwise
    # the alias spans multiple families/versions and silent resolution
    # would be surprising. The ``all()`` semantics matter: if any
    # candidate has a non-date next segment, we refuse the whole batch
    # rather than picking the date-segmented subset — partial
    # resolution would be even more surprising than none.
    if not all(_next_segment_is_date(c, len(prefix)) for c in candidates):
        return name

    resolved = max(candidates)
    if resolved != name:
        pair = (name, resolved)
        # Lock around the set check + add so two concurrent
        # first-callers can't race past the membership test and
        # double-log the same mapping. Re-use the inventory lock —
        # the two pieces of dedupe state (cache + log set) move
        # together at startup and locking them as one ensures no
        # ordering window where one is populated and the other isn't.
        with _INVENTORY_LOCK:
            if pair not in _LOGGED_RESOLUTIONS:
                _LOGGED_RESOLUTIONS.add(pair)
                _emit = True
            else:
                _emit = False
        if _emit:
            logger.info(
                f"Resolved Anthropic model alias {name} -> {resolved} "
                f"(from /v1/models inventory)"
            )
    return resolved


def _next_segment_is_date(model_id: str, prefix_len: int) -> bool:
    """Is the segment at ``model_id[prefix_len:]`` an 8-digit date?

    A canonical Anthropic snapshot suffix is ``YYYYMMDD`` (e.g.
    ``20251001``). The segment ends at the next ``-`` or end-of-string.
    """
    rest = model_id[prefix_len:]
    seg = rest.split("-", 1)[0]
    return len(seg) == 8 and seg.isdigit()


def _get_inventory(api_key: Optional[str]) -> list[str]:
    """Return the cached inventory, fetching it on first call.

    Thread-safe: concurrent first-callers from multiple threads collapse
    to a single fetch via ``_INVENTORY_LOCK``.
    """
    global _INVENTORY, _INVENTORY_PROBED

    # Fast path — already probed. Reads of ``_INVENTORY_PROBED`` and
    # ``_INVENTORY`` are atomic in CPython (PEP 13), so the lockless
    # check is safe for the steady-state read pattern.
    if _INVENTORY_PROBED:
        return _INVENTORY or []

    with _INVENTORY_LOCK:
        if _INVENTORY_PROBED:
            return _INVENTORY or []
        try:
            _INVENTORY = _fetch_inventory(api_key) if api_key else []
        except Exception as exc:
            logger.debug(f"Anthropic model inventory fetch failed: {exc}")
            _INVENTORY = []
        _INVENTORY_PROBED = True
        return _INVENTORY


def _fetch_inventory(api_key: str) -> list[str]:
    """One-shot ``GET /v1/models`` returning each entry's ``id``.

    Returns an empty list on non-200 responses. Raises on transport
    errors — :func:`_get_inventory` absorbs those.
    """
    import requests

    # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
    # Hardcoded Anthropic API hostname — not SSRF.
    r = requests.get(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
        timeout=5,
    )
    if r.status_code != 200:
        return []
    data = r.json().get("data", [])
    return [
        entry["id"]
        for entry in data
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    ]


def _reset_cache_for_tests() -> None:
    """Test seam — clears the inventory cache between cases."""
    global _INVENTORY, _INVENTORY_PROBED
    with _INVENTORY_LOCK:
        _INVENTORY = None
        _INVENTORY_PROBED = False
        _LOGGED_RESOLUTIONS.clear()


def _seed_cache_for_tests(inventory: list[str]) -> None:
    """Test seam — injects an inventory without going to the network."""
    global _INVENTORY, _INVENTORY_PROBED
    with _INVENTORY_LOCK:
        _INVENTORY = list(inventory)
        _INVENTORY_PROBED = True
