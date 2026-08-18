"""Pack-driven crypto-inventory bootstrap for bare /audit runs (A9).

``crypto_inventory`` is produced by ``/understand --map``'s
source-intel phase (spatch-rendered ``crypto_calls.cocci`` with the
``@api-packs`` slot) and consumed by /audit per-function contexts and
strategy routing. A bare audit run — no /understand beforehand — has
no context map at all, so the crypto vocabulary packs never fed the
audit: an openssl-shaped target went through the final comparison
audit with ZERO crypto_inventory refs and only the path-derived
"crypto" strategy tag.

This module gives the audit prep a mechanical fallback: the same
per-library API packs (``engine/coccinelle/source_intel/crypto/
packs/*.json`` — resolved relative to THIS tree, never the invocation
cwd) plus the hardcoded libc RNG seed names drive a bounded regex scan
over the checklist's C-family files, emitting sites in the exact shape
``packages.code_understanding.context_map_sites.build_crypto_inventory``
produces (kind / file / line / function / api / fn). Enumeration only
— a call-site inventory, no misuse claim — matching the source-intel
contract. When a real ``/understand`` map already carries the section
the bootstrap never runs (the cocci-derived inventory is strictly more
precise).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# core/orchestration/context_map_crypto.py → repo root (parents[2]).
# Anchored to __file__ so the packs resolve regardless of the audit's
# invocation cwd (one of the A9 failure hypotheses).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_PACK_DIR = (
    _REPO_ROOT / "engine" / "coccinelle" / "source_intel" / "crypto" / "packs"
)

# libc RNG — universal vocabulary, hardcoded by operator policy
# (mirrors the ``libc_rng`` rule in crypto_calls.cocci; packs must not
# carry it, see packs/README.md).
_LIBC_RNG_NAMES = (
    "rand", "random", "srand", "srandom", "drand48", "lrand48", "mrand48",
)

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_C_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx")

_MAX_FILES = 2000
_MAX_FILE_BYTES = 2_000_000


def _load_packs() -> list[dict[str, Any]]:
    """Load every crypto API pack; malformed packs are skipped loudly."""
    packs: list[dict[str, Any]] = []
    try:
        pack_files = sorted(_PACK_DIR.glob("*.json"))
    except OSError:
        return packs
    for path in pack_files:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            logger.warning("crypto pack %s unreadable (%s) — skipped", path, e)
            continue
        api = raw.get("api", "")
        kinds = raw.get("kinds", {})
        if not (isinstance(api, str) and re.fullmatch(r"[a-z][a-z0-9_]*", api)
                and isinstance(kinds, dict)):
            logger.warning("crypto pack %s malformed — skipped", path)
            continue
        packs.append(raw)
    return packs


def _compile_matchers() -> list[tuple[str, str, re.Pattern]]:
    """One compiled call-site pattern per (api, kind).

    Prefixes match ``<prefix>\\w*`` and exact names match the bare
    identifier, both followed by ``(`` — the regex approximation of
    the cocci ``fn(...)`` call-expression match. Invalid identifiers
    are dropped (same tolerance as the pack renderer).
    """
    matchers: list[tuple[str, str, re.Pattern]] = []
    for pack in _load_packs():
        api = pack["api"]
        for kind, spec in pack.get("kinds", {}).items():
            if kind not in ("primitive_call", "rng_source"):
                continue
            if not isinstance(spec, dict):
                continue
            alts: list[str] = []
            for prefix in spec.get("prefixes", []):
                if isinstance(prefix, str) and _IDENT_RE.match(prefix):
                    alts.append(re.escape(prefix) + r"\w*")
            for name in spec.get("names", []):
                if isinstance(name, str) and _IDENT_RE.match(name):
                    alts.append(re.escape(name))
            if not alts:
                continue
            matchers.append((api, kind, re.compile(
                r"\b(" + "|".join(alts) + r")\s*\(",
            )))
    # libc RNG seeds (rng_source only, per the cocci rule).
    matchers.append(("libc", "rng_source", re.compile(
        r"\b(" + "|".join(_LIBC_RNG_NAMES) + r")\s*\(",
    )))
    return matchers


def _function_spans(
    checklist: dict[str, Any],
) -> dict[str, list[tuple[int, int, str]]]:
    """Per-file ``(line_start, line_end, name)`` spans for enclosing-
    function resolution."""
    spans: dict[str, list[tuple[int, int, str]]] = {}
    for file_info in checklist.get("files", []):
        fp = file_info.get("path", "")
        if not fp:
            continue
        rows = []
        for item in file_info.get("items", file_info.get("functions", [])):
            name = item.get("name", "")
            ls = item.get("line_start", 0) or 0
            le = item.get("line_end", 0) or ls
            if name and ls:
                rows.append((ls, le, name))
        if rows:
            spans[fp] = sorted(rows)
    return spans


def _enclosing(
    spans: list[tuple[int, int, str]] | None, line: int,
) -> str | None:
    if not spans:
        return None
    for ls, le, name in spans:
        if ls <= line <= le:
            return name
        if ls > line:
            break
    return None


def enrich_with_crypto_inventory(
    context_map: dict[str, Any],
    *,
    checklist: dict[str, Any] | None,
    target_path: Path | str,
) -> int:
    """Populate ``context_map['crypto_inventory']`` from the API packs.

    Best-effort and idempotent: an existing (non-empty) section is
    never overwritten; the section key is only written when sites were
    found. Returns the number of sites recorded.
    """
    if not isinstance(context_map, dict):
        return 0
    if context_map.get("crypto_inventory"):
        return 0
    if not checklist:
        return 0

    matchers = _compile_matchers()
    if not matchers:
        return 0

    root = Path(target_path)
    spans_by_file = _function_spans(checklist)

    sites: list[dict[str, Any]] = []
    scanned = 0
    for file_info in checklist.get("files", []):
        fp = file_info.get("path", "")
        if not fp or not fp.endswith(_C_SUFFIXES):
            continue
        if scanned >= _MAX_FILES:
            logger.info(
                "crypto inventory bootstrap: file cap (%d) reached — "
                "remaining files skipped", _MAX_FILES,
            )
            break
        full = root / fp
        try:
            if not full.is_file() or full.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        spans = spans_by_file.get(fp)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for api, kind, pattern in matchers:
                for m in pattern.finditer(line):
                    sites.append({
                        "kind": kind,
                        "file": fp,
                        "line": lineno,
                        "function": _enclosing(spans, lineno),
                        "api": api,
                        "fn": m.group(1),
                    })

    if sites:
        context_map["crypto_inventory"] = sites
    return len(sites)
