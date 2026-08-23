"""Substrate-derived ownership / privilege SITE enrichment for context maps.

Mechanical counterpart to the LLM-emitted map sections. ``source_intel``
already detects, via cocci, the sites these sections care about — allocation /
checked-allocation / paired-free / double-free (ownership) and
capability-check / LSM-hook (privilege) — each carrying a source location and
enclosing function. This projects those deterministically into
``context-map.json``'s ``ownership_model`` / ``privilege_model`` sections: no
LLM, idempotent, best-effort.

The LLM populator (``map.md``) later layers the *semantic* analysis on top —
refcount-protocol anomalies, ownership transfers, privilege bypass paths — the
parts that genuinely need a model. This module ships the deterministic site
inventory those analyses (and ``/audit``, annotation synthesis, ``/agentic``)
build on, with zero LLM-emit reliability risk.

Duck-typed on the ``SourceIntelResult`` (reads its tuple fields via
``getattr``) so importing this module never pulls source_intel's analysis
machinery — the producer-side shim hands in an already-computed result.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # type-only — no runtime dep on packages.source_intel
    from packages.source_intel import SourceIntelResult


def _relativize(path: str | None, repo_root: Path | None) -> str | None:
    """Make a site's file path relative to the run target.

    source_intel emits ABSOLUTE paths; the context-map convention (and the
    annotation substrate, which rejects absolute ``source_file``) is repo-
    relative. Best-effort: a path that isn't under ``repo_root`` (or any
    parse error) is left untouched rather than dropped.
    """
    if not path or repo_root is None:
        return path
    try:
        p = Path(path)
        if p.is_absolute():
            return str(p.relative_to(repo_root))
    except (ValueError, TypeError):
        return path
    return path


def _loc(ev: Any) -> tuple[str | None, int | None]:
    loc = getattr(ev, "location", None)
    if isinstance(loc, (tuple, list)) and len(loc) == 2:
        return loc[0], loc[1]
    return None, None


def _site(kind: str, ev: Any, **extra: Any) -> dict[str, Any]:
    file_, line = _loc(ev)
    site: dict[str, Any] = {
        "kind": kind,
        "file": file_,
        "line": line,
        "function": getattr(ev, "enclosing_function", None),
    }
    site.update({k: v for k, v in extra.items() if v is not None})
    return site


def build_ownership_model(si: SourceIntelResult) -> list[dict[str, Any]]:
    """Alloc / checked-alloc / paired-free / double-free sites, in order."""
    out: list[dict[str, Any]] = [_site("alloc", a, allocator=getattr(a, "allocator", None)) for a in getattr(si, "allocations", ()) or ()]
    out.extend(_site(
            "alloc_checked", a, allocator=getattr(a, "allocator", None),
        ) for a in getattr(si, "checked_allocations", ()) or ())
    out.extend(_site(
            "paired_free", p,
            allocator=getattr(p, "allocator", None),
            free_fn=getattr(p, "free_fn", None),
        ) for p in getattr(si, "paired_frees", ()) or ())
    out.extend(_site(
            "double_free", d,
            free_fn=getattr(d, "free_fn", None),
            role=getattr(d, "role", None),
        ) for d in getattr(si, "double_frees", ()) or ())
    return out


def build_privilege_model(si: SourceIntelResult) -> list[dict[str, Any]]:
    """Capability-check + LSM-hook sites."""
    out: list[dict[str, Any]] = [_site(
            "capability", c,
            name=getattr(c, "cap_function", None),
            grade=getattr(c, "grade", None),
        ) for c in getattr(si, "capabilities", ()) or ()]
    out.extend(_site("lsm_hook", h, name=getattr(h, "hook_name", None)) for h in getattr(si, "lsm_hooks", ()) or ())
    return out


def build_shared_state(si: SourceIntelResult) -> list[dict[str, Any]]:
    """Lock acquire / release sites — spin / mutex / rw / pthread.

    Site `kind` is `<lock_kind>_<op>` (e.g. `spin_acquire`, `mutex_release`)
    so consumers can filter on a single field. The concrete function
    (`fn`) and lock expression (`lock_var`) ride alongside.
    """
    out: list[dict[str, Any]] = []
    for ls in getattr(si, "lock_sites", ()) or ():
        kind = f"{getattr(ls, 'kind', '')}_{getattr(ls, 'op', '')}"
        out.append(_site(
            kind, ls,
            fn=getattr(ls, "fn", None),
            lock_var=getattr(ls, "lock_var", None),
        ))
    return out


def build_crypto_inventory(si: SourceIntelResult) -> list[dict[str, Any]]:
    """Cryptographic primitive call + RNG-source sites.

    Site `kind` is the call kind directly (`primitive_call` or
    `rng_source`); the originating library (`api`: openssl/kernel/
    libsodium/libc) and the concrete function (`fn`) ride alongside so
    consumers can filter without re-parsing the kind string.
    """
    out: list[dict[str, Any]] = [_site(
            getattr(cc, "kind", "crypto"), cc,
            api=getattr(cc, "api", None),
            fn=getattr(cc, "fn", None),
        ) for cc in getattr(si, "crypto_calls", ()) or ()]
    return out


def enrich_context_map_with_sites(
    cmap: dict[str, Any], si: SourceIntelResult,
    *, repo_root: str | Path | None = None,
) -> dict[str, int]:
    """Inject ``ownership_model`` / ``privilege_model`` into ``cmap`` from a
    SourceIntelResult.

    ``repo_root`` (the run target) relativises site file paths to match the
    context-map convention; pass it whenever the SourceIntelResult carries
    absolute paths (it always does in production).

    Idempotent — re-running overwrites a prior mechanical pass with fresh
    data. Best-effort — never raises; a malformed result just yields fewer
    sites. A section key is written only when it has entries, so an empty
    section doesn't clutter the map (and doesn't shadow an LLM-populated one
    with an empty list). Returns per-section site counts.

    NOTE (forward-compat): today the mechanical pass is the *only* producer of
    these sections, so overwrite-when-non-empty is correct. When the LLM
    semantic layer (map.md) lands and may populate the same keys, this needs a
    merge-vs-replace decision — resolve it then, against that layer's design
    (the intended flow is mechanical-sites-first, LLM-enriches-on-top).
    """
    counts = {
        "ownership_model": 0, "privilege_model": 0,
        "shared_state": 0, "crypto_inventory": 0,
    }
    if not isinstance(cmap, dict):
        return counts
    root = Path(repo_root) if repo_root is not None else None
    for key, builder in (
        ("ownership_model", build_ownership_model),
        ("privilege_model", build_privilege_model),
        ("shared_state", build_shared_state),
        ("crypto_inventory", build_crypto_inventory),
    ):
        try:
            sites = builder(si)
        except Exception:  # noqa: BLE001 — best-effort enrichment
            sites = []
        if root is not None:
            for s in sites:
                s["file"] = _relativize(s.get("file"), root)
        if sites:
            cmap[key] = sites
            counts[key] = len(sites)
    return counts
