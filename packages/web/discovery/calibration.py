"""Soft-404 filter derivation for ffuf runs.

ffuf's ``-ac`` auto-calibration handles targets whose wildcard
responses are stable, but a templated soft-404 — HTTP 200, body size
jittering around dynamic fragments — slips through and floods the
report. Probing a few paths that cannot exist and deriving explicit
``-fs``/``-fw`` filters from what comes back closes that gap. The
probes are first-party requests through the scan client, so scope,
rate limiting, and the execution policy all apply; derivation is
conservative and returns nothing rather than guessing (a wrong filter
silently hides real hits, no filter merely costs report noise).
"""

from __future__ import annotations

import secrets
from typing import Any

from core.logging import get_logger

logger = get_logger()

_PROBE_COUNT = 3


def derive_soft404_filters(client: Any, base_url: str) -> dict[str, int]:
    """ffuf filter overrides derived from wildcard-path probes.

    Returns ``{"filter_size": N}`` when the target answers unknown
    paths with a byte-identical body, ``{"filter_words": N}`` when the
    size jitters but the word count is stable, and ``{}`` when the
    target 404s honestly (the default status filter already covers it)
    or the wildcard responses are too unstable to characterize.
    """
    responses = []
    for _ in range(_PROBE_COUNT):
        path = f"/{secrets.token_hex(12)}"
        try:
            responses.append(client.get(base_url.rstrip("/") + path))
        except Exception as e:
            logger.debug("soft-404 probe failed: %s", e)
            return {}
    statuses = {r.status_code for r in responses}
    if statuses == {404}:
        return {}
    if len(statuses) != 1:
        logger.debug(
            "soft-404 probes returned mixed statuses %s — no filter derived",
            sorted(statuses),
        )
        return {}
    sizes = {len(r.content) for r in responses}
    if len(sizes) == 1:
        return {"filter_size": sizes.pop()}
    words = {len(r.text.split()) if isinstance(r.text, str) else -1
             for r in responses}
    if len(words) == 1 and -1 not in words:
        return {"filter_words": words.pop()}
    logger.debug(
        "soft-404 probes unstable (sizes %s) — no filter derived",
        sorted(sizes),
    )
    return {}
