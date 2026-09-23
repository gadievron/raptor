"""Load curated lists as LLM exemplar blocks.

The mechanical layer ships curated JSON files (popular package names,
exfiltration destinations) for literal matching.  This module re-packages
them as ``UntrustedBlock`` instances so LLM stages can use them as
pattern-exemplars — the model extrapolates the same judgment to novel
inputs the lists don't cover literally.

The blocks are cached at module level (lists are static data files that
don't change during a run).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from core.json import load_json
from core.security.prompt_envelope import UntrustedBlock

_DATA_DIR = Path(__file__).resolve().parents[1] / "data"  # packages/sca/data


@lru_cache(maxsize=16)
def popular_names_block(ecosystem: str) -> UntrustedBlock | None:
    """Return an exemplar block of popular package names for *ecosystem*.

    Returns ``None`` when no list exists for the ecosystem.
    """
    path = _DATA_DIR / "popular" / f"{ecosystem}.json"
    if not path.is_file():
        return None
    # Repo-bundled data file; corrupt / oversize warn-and-None inside
    # load_json, and the emptiness guard below covers None.
    names = load_json(path, max_bytes=8 * 1024 * 1024)
    if not isinstance(names, list):
        return None
    # The list is machine-refreshed (refresh_typosquat_lists) and
    # unvalidated at load; one non-string element would TypeError the
    # join and lru_cache would pin the failure for the process.
    names = [n for n in names if isinstance(n, str)]
    if not names:
        return None
    text = (
        f"Popular {ecosystem} packages (used as typosquat anchor set — "
        f"a candidate name close to one of these is suspicious):\n\n"
        + ", ".join(names)
    )
    return UntrustedBlock(
        content=text,
        kind="EXEMPLAR_POPULAR_NAMES",
        origin=f"data/popular/{ecosystem}.json",
    )


@lru_cache(maxsize=1)
def exfil_destinations_block() -> UntrustedBlock | None:
    """Return an exemplar block of known exfiltration destination patterns."""
    path = _DATA_DIR / "exfil_destinations.json"
    if not path.is_file():
        return None
    # Repo-bundled data file; corrupt / oversize / non-dict shapes all
    # degrade to "no entries".
    data = load_json(path, max_bytes=8 * 1024 * 1024)
    entries = data.get("entries", []) if isinstance(data, dict) else []
    if not entries:
        return None

    by_category: dict[str, list[str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue  # malformed exfil-list entry — skip rather than crash
        cat = entry.get("category", "other")
        label = entry.get("host") or entry.get("tld") or entry.get("pattern", "?")
        by_category.setdefault(cat, []).append(label)

    if not by_category:
        return None

    lines = [
        "Known exfiltration / payload-staging patterns (URLs matching "
        "these categories in source code are suspicious):\n",
    ]
    for cat, hosts in sorted(by_category.items()):
        lines.append(f"  {cat}: {', '.join(hosts)}")

    return UntrustedBlock(
        content="\n".join(lines),
        kind="EXEMPLAR_EXFIL_DESTINATIONS",
        origin="data/exfil_destinations.json",
    )


def exemplar_blocks_for_supply_chain(
    ecosystem: str,
) -> tuple[UntrustedBlock, ...]:
    """All exemplar blocks relevant to supply-chain analysis.

    Returns a tuple suitable for appending to a stage's
    ``untrusted_blocks``.
    """
    blocks: list[UntrustedBlock] = []
    pop = popular_names_block(ecosystem)
    if pop is not None:
        blocks.append(pop)
    exfil = exfil_destinations_block()
    if exfil is not None:
        blocks.append(exfil)
    return tuple(blocks)
