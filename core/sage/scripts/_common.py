"""Shared helpers for SAGE setup scripts.

Both `register_agents.py` and `seed_sage_knowledge.py` propose a
deterministic set of memories on install. Running them twice (e.g. after
a SAGE volume reset, or when the setup script is re-invoked) creates
duplicates in the SAGE consensus store.

`async_memory_exists` lets callers skip the propose step for items
already stored, keyed by a stable per-memory tag that SAGE's 6.6.0
tags-as-first-class feature makes queryable.

Caveat: SAGE stores tags as **node-local metadata** (not part of the
on-chain consensus tx). On a single-node deployment — which is what
`libexec/raptor-sage-setup` spins up by default — submit and query
hit the same node, so tag-based existence checks are reliable. On a
distributed SAGE where submit and query can land on different nodes,
tags would not replicate and re-runs against a fresh node would
duplicate. Not a concern for current RAPTOR deployments.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def async_memory_exists(
    client: Any,
    domain_tag: str,
    tag: str,
) -> bool:
    """Return True if a memory tagged `tag` exists in `domain_tag`.

    Uses ``list_memories(domain, tag, limit=1)`` — exact-filter lookup
    with no embedding required. (``query()`` would need an embedding,
    and tag semantics there are looser.)

    On any error (SAGE unreachable, schema mismatch, timeout) logs at
    debug level and returns False so the caller re-proposes rather than
    silently skipping. A duplicate is cheap; a missing memory because of
    a transient query failure is not.
    """
    try:
        response = await client.list_memories(
            domain=domain_tag,
            tag=tag,
            limit=1,
        )
        return bool(response.memories)
    except Exception as e:
        logger.debug(f"SAGE tag existence check failed ({domain_tag}/{tag}): {e}")
        return False
