"""Enrich ``context-map.json`` sinks with target-mitigation context.

Reads ``exploit_feasibility.analyze_binary`` output and enriches each
sink under ``context-map.json``'s ``sinks[]`` with a
``mitigation_context`` blob describing which classical exploitation
primitives (arbitrary write, `%n` write, GOT overwrite, `.fini_array`,
hook overwrite, stack smash) the target's build actually permits.

Design contract (co-authored with /audit; see
``/tmp/integration/exploit-feasibility-into-understand.md``):

* Opt-in — enrichment only runs when a binary path is supplied.
* Additive — the enricher NEVER removes sinks. Adding mitigation
  info must not filter the map; downstream renderers may re-order but
  must not hide.
* Namespaced — each substrate that enriches sinks emits under its own
  ``source`` field so /audit enrichments and this one can coexist.
* Tri-state honest — ``glibc_n_disabled=None`` (CONDITIONAL) maps to
  ``format_n_write: null`` here. Consumers MUST NOT collapse ``null``
  to ``false``.
* CWE join key — every ``mitigation_context`` carries ``cwe_class``
  matching the sink's CWE, so ``/audit``'s ``findings.json`` (which
  carries CWE) and this can be joined without another substrate call.
* One ``analyze_binary`` call per run — the cache is keyed on
  ``(binary_sha256, build_flags_source, schema_version)``.
* Immutable — a re-run produces a NEW enrichment with a new
  ``generated_at`` timestamp; enrichments are not edited in place.

Called from ``/understand --map`` post-processing when
``--binary <path>`` is supplied. Silent no-op when the binary is
absent.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # type-only — no runtime dep
    from core.build.build_flags import BuildFlagsContext


_LOG = logging.getLogger(__name__)

# Bumped when the ``mitigation_context`` field-set shape changes.
# Consumers keying by ``schema_version`` should refuse enrichments they
# don't understand rather than misinterpret.
SCHEMA_VERSION = 1

# CWE families this substrate has meaningful primitive-availability
# opinions about. Sinks with other CWEs still get a minimal
# mitigation_context (verdict + protections) but ``primitive_availability``
# stays sparse to avoid over-claiming.
_KNOWN_CWE_FAMILIES = frozenset({
    "CWE-134",   # format string
    "CWE-121", "CWE-122", "CWE-787",   # stack / heap / OOB write
    "CWE-125",   # OOB read
    "CWE-416", "CWE-415",   # UAF / double-free
    "CWE-190",   # integer overflow (often chains into write)
    "CWE-476",   # null deref
})


def _sha256_file(path: Path) -> Optional[str]:
    """Compute sha256 of ``path`` — used as part of the analysis cache key.

    Returns ``None`` on I/O error rather than raising; enrichment is
    best-effort and a broken read should downgrade to "no cache" not
    "abort /understand".
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        _LOG.debug("mitigation_enricher: sha256 read failed on %s: %s", path, e)
        return None


def _availability_for_cwe(
    cwe: str,
    result: Dict[str, Any],
) -> Dict[str, Optional[bool]]:
    """Project the substrate verdict into primitive-availability tri-state.

    Tri-state semantics (from PR #878):
    * ``True``  → primitive verified available on this build.
    * ``False`` → primitive verified blocked on this build.
    * ``None``  → CONDITIONAL — depends on the specific call site
                  (e.g. `%n` blocked for writable format strings,
                  works for `.rodata` format strings).

    Consumers MUST distinguish all three — a truthy check on ``None``
    silently mis-treats CONDITIONAL as blocked.
    """
    protections = result.get("protections") or {}
    glibc_n_disabled = result.get("glibc_n_disabled")

    # %n write tri-state, direct passthrough:
    if glibc_n_disabled is True:
        fmt_n = False
    elif glibc_n_disabled is False:
        fmt_n = True
    else:
        fmt_n = None  # CONDITIONAL

    # Arbitrary write via `%n`: same tri-state as fmt_n.
    # Other CWEs' arbitrary_write depends on their own primitive; we
    # only opine when the CWE's write mechanism is `%n`. For other
    # write-class CWEs (121/122/787) arbitrary write depends on chain
    # constraints the substrate can't decide statically — leave
    # ``arbitrary_write`` at ``None`` (conditional) unless the sink is
    # exclusively format-string.
    if cwe == "CWE-134":
        arbitrary_write = fmt_n
    else:
        arbitrary_write = None

    # GOT overwrite: blocked iff Full RELRO. .fini_array under Full
    # RELRO is also blocked; under partial RELRO both are writable.
    full_relro = bool(protections.get("full_relro"))
    got_overwrite = False if full_relro else True
    fini_array = False if full_relro else True

    # Hook overwrite: glibc 2.34+ removed __malloc_hook / __free_hook.
    # We only mark False when we KNOW glibc >= 2.34.
    glibc_ver_str = result.get("glibc_version") or ""
    hook_overwrite: Optional[bool] = None
    if glibc_ver_str:
        try:
            major_minor = ".".join(glibc_ver_str.split(".")[:2])
            major, minor = map(int, major_minor.split("."))
            if (major, minor) >= (2, 34):
                hook_overwrite = False
            else:
                hook_overwrite = True
        except (ValueError, IndexError):
            hook_overwrite = None

    # Stack smash primitives are gated on canary + PIE relative to the
    # attacker's leak posture — not statically decidable from the ELF
    # alone. Leave as None for CWE-121, False for non-stack CWEs.
    stack_smash: Optional[bool]
    if cwe == "CWE-121":
        stack_smash = None
    else:
        stack_smash = False

    return {
        "arbitrary_write": arbitrary_write,
        "format_n_write": fmt_n,
        "got_overwrite": got_overwrite,
        "fini_array": fini_array,
        "hook_overwrite": hook_overwrite,
        "stack_smash": stack_smash,
    }


def _availability_detail_for_cwe(
    cwe: str,
    result: Dict[str, Any],
) -> Dict[str, str]:
    """Human-readable detail strings for the primitives we opine on.

    Only populated for entries that carry substrate-provided prose
    (e.g. ``printf_n_availability_detail`` for `%n`). Empty otherwise —
    the tri-state value speaks for itself.
    """
    detail: Dict[str, str] = {}
    n_detail = result.get("printf_n_availability_detail")
    if isinstance(n_detail, str) and n_detail:
        detail["format_n_write"] = n_detail
    protections = result.get("protections") or {}
    if protections.get("full_relro"):
        detail["got_overwrite"] = (
            "Full RELRO — GOT and .fini_array are read-only after startup."
        )
        detail["fini_array"] = detail["got_overwrite"]
    return detail


def _priority_hint(
    availability: Dict[str, Optional[bool]],
    verdict: Optional[str],
) -> str:
    """Advisory hint for renderer sink-ordering. Not authoritative.

    Consumers MUST NOT hide sinks based on this — only re-order.
    """
    # Any confirmed-blocked primitive plus no confirmed-available
    # primitive → low. Any confirmed-available primitive → high.
    # Otherwise medium (default).
    has_available = any(v is True for v in availability.values())
    # ``all_blocked`` requires at least ONE False value AND no True/None
    # in the concrete-signal set. Otherwise ``all(...)`` on an empty
    # filter returns True and every all-None availability set would
    # misread as "everything blocked" (was: hard-priority-low bug on
    # CONDITIONAL-only sinks).
    concrete = [v for v in availability.values() if v is not None]
    all_blocked = bool(concrete) and all(v is False for v in concrete)
    if has_available:
        return "high"
    if all_blocked:
        return "low"
    if verdict in ("unlikely", "difficult"):
        return "low"
    if verdict in ("exploitable", "likely_exploitable"):
        return "high"
    return "medium"


def _priority_reason(
    availability: Dict[str, Optional[bool]],
    verdict: Optional[str],
    hint: str,
) -> str:
    """One-line reason for the priority_hint."""
    if hint == "high":
        avails = [k for k, v in availability.items() if v is True]
        if avails:
            return f"available primitives: {', '.join(sorted(avails))}"
        return f"verdict={verdict}"
    if hint == "low":
        blocked = [k for k, v in availability.items() if v is False]
        if blocked:
            return f"no viable write primitive on this build: {', '.join(sorted(blocked))} blocked"
        return f"verdict={verdict}"
    return "no strong-signal primitive availability"


def build_mitigation_context(
    result: Dict[str, Any],
    *,
    sink_cwe: str,
    binary_path: Path,
    build_flags_source: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a ``mitigation_context`` blob for ONE sink from an
    ``analyze_binary`` result and the sink's CWE.

    Callers usually invoke ``enrich_context_map`` which caches the
    result and iterates all sinks; this is exposed for callers who
    have their own iteration (e.g. attack-tree annotators).

    ``generated_at`` is required by contract but injected by the
    caller — leave ``None`` and the field is omitted, so tests that
    don't care about timestamps stay deterministic. Production
    callers pass an ISO8601 UTC string.
    """
    binary_sha = _sha256_file(binary_path) if binary_path else None
    verdict = result.get("verdict")
    availability = _availability_for_cwe(sink_cwe, result)
    detail = _availability_detail_for_cwe(sink_cwe, result)
    hint = _priority_hint(availability, verdict)
    reason = _priority_reason(availability, verdict, hint)

    blob: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": "exploit_feasibility.analyze_binary",
        "cwe_class": sink_cwe,
        "primitive_availability": availability,
        "priority_hint": hint,
        "priority_reason": reason,
        "verdict_for_downstream": {
            "verdict": verdict,
            "impact": result.get("impact") or "code_execution",
        },
    }
    if binary_sha:
        blob["target_binary_sha256"] = binary_sha
    if build_flags_source:
        blob["build_flags_source"] = build_flags_source
    if generated_at:
        blob["generated_at"] = generated_at
    if detail:
        blob["primitive_availability_detail"] = detail

    # Blockers/warnings pulled from the substrate as-is — the substrate
    # owns their phrasing.
    blockers = result.get("blockers") or []
    if blockers:
        blob["blockers"] = list(blockers)
    warnings = result.get("warnings") or []
    if warnings:
        blob["warnings"] = list(warnings)

    return blob


def _sink_cwe(sink: Dict[str, Any]) -> Optional[str]:
    """Best-effort CWE extraction from a context-map sink entry.

    context-map.json sinks carry CWE variously as ``cwe``, ``cwe_class``,
    ``category``, or under ``metadata.cwe``. Return the first hit
    normalized to ``CWE-N`` form; return ``None`` if no CWE surfaces.
    """
    for key in ("cwe", "cwe_class", "category"):
        val = sink.get(key)
        if isinstance(val, str) and val.upper().startswith("CWE-"):
            return val.upper()
    meta = sink.get("metadata") or {}
    if isinstance(meta, dict):
        val = meta.get("cwe")
        if isinstance(val, str) and val.upper().startswith("CWE-"):
            return val.upper()
    return None


def enrich_context_map(
    context_map: Dict[str, Any],
    *,
    binary_path: Path,
    build_flags: Optional["BuildFlagsContext"] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich every sink in ``context_map`` with ``mitigation_context``.

    Idempotent within a single run: ``analyze_binary`` is called once
    and the result reused across all sinks. Sinks whose CWE the
    substrate has no meaningful opinion on are enriched with the
    verdict + priority hint anyway (the LLM benefits from seeing
    "difficult" even when the primitives are ambiguous).

    Returns the mutated ``context_map`` dict (also modified in place).
    Never raises on substrate error — enrichment is best-effort and a
    failed ``analyze_binary`` returns the map unchanged.
    """
    from packages.exploit_feasibility.api import analyze_binary

    if not binary_path.exists():
        _LOG.warning(
            "mitigation_enricher: binary not found at %s — skipping",
            binary_path,
        )
        return context_map

    # ``build_flags`` was added to analyze_binary by PR #878 (on main).
    # Older substrate versions reject the keyword — pass it only when
    # actually supplied so the enricher stays compatible with any
    # branch predating that merge.
    kwargs: Dict[str, Any] = {}
    if build_flags is not None:
        kwargs["build_flags"] = build_flags
    try:
        result = analyze_binary(str(binary_path), **kwargs)
    except TypeError as e:
        if "build_flags" in str(e) and "build_flags" in kwargs:
            _LOG.warning(
                "mitigation_enricher: substrate predates PR #878 — "
                "retrying without build_flags (source_intel override "
                "unavailable on this codebase)",
            )
            kwargs.pop("build_flags")
            try:
                result = analyze_binary(str(binary_path), **kwargs)
            except Exception as e2:  # noqa: BLE001
                _LOG.warning(
                    "mitigation_enricher: analyze_binary raised on %s: %s",
                    binary_path, e2,
                )
                return context_map
        else:
            _LOG.warning(
                "mitigation_enricher: analyze_binary raised on %s: %s",
                binary_path, e,
            )
            return context_map
    except Exception as e:  # noqa: BLE001 — substrate failure must not abort /understand
        _LOG.warning(
            "mitigation_enricher: analyze_binary raised on %s: %s",
            binary_path, e,
        )
        return context_map

    build_flags_source = None
    if build_flags is not None:
        build_flags_source = getattr(build_flags, "source", None)

    sinks = context_map.get("sinks") or []
    if not isinstance(sinks, list):
        return context_map

    for sink in sinks:
        if not isinstance(sink, dict):
            continue
        cwe = _sink_cwe(sink)
        if cwe is None:
            # Substrate has no CWE-shaped opinion → still emit the
            # minimal verdict-only enrichment so the sink carries at
            # least the target's coarse exploitability posture.
            cwe = "UNKNOWN"
        sink["mitigation_context"] = build_mitigation_context(
            result,
            sink_cwe=cwe,
            binary_path=binary_path,
            build_flags_source=build_flags_source,
            generated_at=generated_at,
        )

    return context_map


def enrich_context_map_file(
    path: Path,
    *,
    binary_path: Path,
    build_flags: Optional["BuildFlagsContext"] = None,
    generated_at: Optional[str] = None,
) -> None:
    """Read ``path``, enrich, and write it back atomically.

    Convenience wrapper for the ``/understand --map`` post-processor.
    Uses ``core.atomic_fs`` for the write so a partial failure never
    leaves a truncated ``context-map.json``.
    """
    if not path.exists():
        _LOG.warning("mitigation_enricher: context-map at %s missing", path)
        return
    try:
        cm = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        _LOG.warning("mitigation_enricher: reading %s failed: %s", path, e)
        return

    enrich_context_map(
        cm,
        binary_path=binary_path,
        build_flags=build_flags,
        generated_at=generated_at,
    )

    from core.atomic_fs import atomic_write_text
    atomic_write_text(path, json.dumps(cm, indent=2, sort_keys=True) + "\n")


__all__ = [
    "SCHEMA_VERSION",
    "build_mitigation_context",
    "enrich_context_map",
    "enrich_context_map_file",
]
