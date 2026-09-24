"""Operator-steered hunt over a mapped binary.

The map substrate answers "what is in this binary?"; this module
answers the operator's directed questions about it:

- ``--anchor "<text>"``: which functions reference strings matching an
  operator-chosen anchor, and how do they cluster into FAMILIES
  (sibling handlers sharing vocabulary and helpers)? Substrate: the
  bounded string→xref machinery of the map's string-anchor pass
  (:meth:`packages.binary_analysis.radare2_understand.BinaryUnderstand
  .string_xref_scan` — same session sandbox, same scan bounds, same
  escape-at-capture discipline).

- ``--calls X [--and-not-calls Y]``: set algebra over a real call
  graph — callers(X), or the chokepoint residual callers(X) minus
  callers(Y). Substrate precedence: a co-located Ghidra re-database's
  call xrefs, else the map pass's whole-binary aflcj graph (via the
  shared adjacency fetch), else the binary-oracle cached edge index.

Claims discipline: everything here is xref-backed STRUCTURE. A shared
string or call edge is a review lead, never a finding and never taint
proof — every artifact, graph record and report line says so.

Flooding honesty: a hostile binary can plant thousands of matching
strings to bury the real family. Every truncation is surfaced in-band
("capped at N of M"), and truncation order prefers xref-weight over
discovery order so a flood of one-string decoys cannot silently
displace the anchor-dense members that motivated the hunt.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.artifacts.context_map_budget import CONTEXT_MAP_CONSUMER_MAX_BYTES
from core.artifacts.provenance import stamp_provenance
from core.atomic_fs import write_text_atomically
from core.binary.addrmap import (
    FidIndex,
    from_fid,
    make_fid,
    module_anchor,
    record_fid_misses,
)
from core.evidence import BinaryEvidenceRecord, EvidenceTier, make_evidence
from core.json import load_json, save_json
from core.security.log_sanitisation import escape_nonprintable
from core.security.markdown_render import md_inline

from ._artifact_lock import run_artifacts_lock
from ._symbols import symbol_base_name
from .graph_store import BinaryGraphStore, graph_path_for_run
from .manifest import BinaryManifest
from .radare2_understand import BinaryUnderstand

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------
# Bounds. Scan-side bounds (strings scanned, xref lookups) are the
# map's string-anchor constants — verified class attrs on
# BinaryUnderstand — so the hunt can never out-spend the pass it
# extends. The bounds below govern the clustering/reporting side.
# --------------------------------------------------------------------

# Operator anchors per invocation. Both directions: more anchors share
# the same global xref-lookup budget, so each anchor sees less of the
# binary; fewer refuses legitimate multi-vocabulary hunts (a format
# family often needs 3-4 spellings). 16 covers real hunts without
# letting a scripted caller turn the scan into a full string dump.
MAX_ANCHORS = 16

# Operator-typed pattern size/complexity bounds. The pattern is
# operator-authored but RUNS OVER HOSTILE STRINGS, so a catastrophic-
# backtracking regex is a self-DoS the binary can trigger by shaping
# its strings. Both directions: tighter bounds refuse legitimate
# alternation-heavy patterns; looser ones re-open the superlinear
# blow-up the bound exists to prevent. 256 chars / 16 quantifiers
# cover every realistic hunt pattern.
MAX_ANCHOR_PATTERN_CHARS = 256
MAX_ANCHOR_REGEX_QUANTIFIERS = 16

# Per-string match subject clip. r2 emits strings of arbitrary length;
# clipping the regex/substring subject bounds per-string match cost.
# Both directions: shorter clips can miss anchors deep inside huge
# blobs (rare — real diagnostic strings are short); longer clips
# multiply worst-case regex cost per string.
MAX_MATCH_SUBJECT_CHARS = 4096

# Family co-occurrence threshold K: two functions must share at least
# this many DISTINCT anchor strings to be joined into one family.
# Both directions: K=1 merges everything that touches one common
# string ("out of memory" would glue the whole binary together);
# K=3+ splits real sibling-handler families whose members share only
# a pair of format strings. K=2 is the smallest value that requires
# corroboration.
MIN_SHARED_ANCHOR_STRINGS = 2

# Stem-join fanout ceiling: a token stem shared by more functions than
# this is vocabulary, not family evidence, and must not merge
# clusters. Both directions: higher fanout lets common stems ("error",
# "failed") build mega-families; lower refuses genuinely rare stems
# that mark true siblings. 4 keeps stem joins to near-unique
# vocabulary.
STEM_JOIN_MAX_FANOUT = 4

# Minimum stem length considered at all — shorter alphabetic runs
# ("get", "set", "not") are ubiquitous and only add noise joins.
MIN_STEM_CHARS = 4

# Referencing functions considered per matched string. A hostile
# binary can xref one planted string from thousands of functions to
# explode the pairwise co-occurrence work. Both directions: lower
# caps can miss real members of very wide dispatch families; higher
# caps make the pair count quadratic in the flood. Truncation is
# surfaced on the payload.
MAX_FUNCS_PER_STRING = 64

# Emission caps — every one surfaced in-band when hit, and member
# truncation keeps the highest xref-weight members (see module
# docstring: flooding must not silently bury the real family).
# Both directions on each: larger values turn the artifact into a
# string dump on flooded binaries; smaller ones hide real structure.
MAX_FAMILY_MEMBERS = 32
MAX_FAMILIES = 16
MAX_SHARED_CALLEES = 24
MAX_INTER_MEMBER_EDGES = 128
MAX_FAMILY_STEMS = 8

# Sample strings shown per family — the map's per-function sample
# bound, reused so the two anchor surfaces render consistently.
FAMILY_SAMPLE_STRINGS = BinaryUnderstand._ANCHOR_SAMPLE_STRINGS  # noqa: SLF001 — deliberate constant reuse, single home


_HUNT_NOT_A_FINDING = (
    "Anchor families are xref-backed structure: shared strings, "
    "shared helpers and call edges are review leads, not findings "
    "and not taint proof."
)

_SLUG_RE = re.compile(r"[a-z0-9]+")
_STEM_RE = re.compile(rf"[a-z]{{{MIN_STEM_CHARS},}}")


class HuntError(ValueError):
    """Operator-facing hunt refusal (bad flags, missing artifacts,
    unusable substrate). The CLI prints the message and exits 2."""


# --------------------------------------------------------------------
# Anchor matcher
# --------------------------------------------------------------------

def _tokenize_regex(pattern: str) -> list[tuple[str, str]]:
    """Shallow regex token stream for the complexity guard.

    ``('atom', text)`` (literal / escape / whole char class),
    ``('open', '(')`` (group-construct markers like ``(?:`` are folded
    into the open so their ``?`` never counts as a quantifier),
    ``('close', ')')``, ``('quant', text)`` (``*``, ``+``, ``?``,
    ``{m[,n]}`` — lazy ``?`` suffixes surface as their own quant
    token), ``('alt', '|')``.
    """
    tokens: list[tuple[str, str]] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            tokens.append(("atom", pattern[i:i + 2]))
            i += 2
            continue
        if ch == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            j = min(j + 1, n)
            tokens.append(("atom", pattern[i:j]))
            i = j
            continue
        if ch == "(":
            tokens.append(("open", "("))
            i += 1
            if i < n and pattern[i] == "?":
                i += 1
                if i < n and pattern[i] in ":=!<aiLmsuxP-":
                    i += 1
            continue
        if ch == ")":
            tokens.append(("close", ")"))
            i += 1
            continue
        if ch == "|":
            tokens.append(("alt", "|"))
            i += 1
            continue
        if ch in "*+?":
            tokens.append(("quant", ch))
            i += 1
            continue
        if ch == "{" and i + 1 < n and (pattern[i + 1].isdigit()
                                        or pattern[i + 1] == ","):
            j = pattern.find("}", i)
            if j != -1:
                tokens.append(("quant", pattern[i:j + 1]))
                i = j + 1
                continue
        tokens.append(("atom", ch))
        i += 1
    return tokens


def _regex_complexity_guard(pattern: str) -> None:
    """Compile-time complexity bound for operator-typed regexes.

    Refuses, on top of the length cap:

    - too many quantifiers — where ``?`` and lazy suffixes COUNT (an
      uncounted ``?`` let ``(a?)+`` and ``a?``-chains through);
    - a ``*``/``+``/``{`` quantifier applied to a group that contains
      a quantifier OR an alternation — alternation-overlap bombs
      (``(a|a)+``, ``(a|aa)+``) backtrack exactly like nested
      repetition, so ``|`` inside a group is quantifier-equivalent;
      risk propagates outward through nested groups. ``?`` on such a
      group stays allowed (0-1 repetition cannot amplify);
    - adjacent same-atom quantifier stacking (``a*a*``, ``a?a?``…) —
      the classic exponential-alternatives shape without any group.

    The guard is deliberately conservative: refusing a safe pattern
    costs the operator a rewrite; accepting an unsafe one hands the
    scanned binary a CPU primitive. The per-string match budget below
    is the defense-in-depth for anything a future shape sneaks past.
    """
    if len(pattern) > MAX_ANCHOR_PATTERN_CHARS:
        msg = (
            f"anchor pattern too long ({len(pattern)} chars; "
            f"max {MAX_ANCHOR_PATTERN_CHARS})"
        )
        raise HuntError(msg)
    tokens = _tokenize_regex(pattern)
    quantifiers = sum(1 for kind, _ in tokens if kind == "quant")
    if quantifiers > MAX_ANCHOR_REGEX_QUANTIFIERS:
        msg = (
            f"anchor pattern has {quantifiers} quantifiers "
            f"(max {MAX_ANCHOR_REGEX_QUANTIFIERS}; ? and lazy "
            f"suffixes count)"
        )
        raise HuntError(msg)
    # Per-group repetition-risk flags. stack[0] is the (never-closed)
    # top level; a closed group's risk propagates to its parent so
    # ((a+)b)+ refuses like (a+)+.
    stack: list[bool] = [False]
    last_closed_risky = False
    for idx, (kind, text) in enumerate(tokens):
        if kind == "open":
            stack.append(False)
        elif kind == "close":
            if len(stack) > 1:
                last_closed_risky = stack.pop()
                if last_closed_risky:
                    stack[-1] = True
        elif kind == "alt":
            if len(stack) > 1:
                # Alternation inside a group: quantifier-equivalent
                # risk (overlapping branches under repetition
                # backtrack superlinearly).
                stack[-1] = True
        elif kind == "quant":
            prev_kind, prev_text = tokens[idx - 1] if idx else ("", "")
            if (prev_kind == "close" and last_closed_risky
                    and text[0] in "*+{"):
                msg = (
                    "anchor pattern repeats a group that contains a "
                    "quantifier or alternation (nested repetition / "
                    "alternation-overlap — superlinear on hostile "
                    "strings); rewrite the pattern"
                )
                raise HuntError(msg)
            if len(stack) > 1:
                stack[-1] = True
            if prev_kind == "atom":
                # Adjacent same-atom stacking: walk back through the
                # preceding quantifier run; landing on the same atom
                # means (atom X)(quant)(atom X)(this quant).
                k = idx - 2
                while k >= 0 and tokens[k][0] == "quant":
                    k -= 1
                if k < idx - 2 and k >= 0 and tokens[k] == ("atom", prev_text):
                    msg = (
                        "anchor pattern stacks quantifiers on the "
                        "same adjacent atom (e.g. a*a* / a?a? — "
                        "exponential alternatives on hostile "
                        "strings); rewrite the pattern"
                    )
                    raise HuntError(msg)


# Per-string regex match wall-clock budget — defense-in-depth under
# the compile-time guard: any repetition shape a future guard miss
# lets through degrades ONE string (skipped, counted, surfaced
# in-band), never the run. Both directions: a tighter budget starts
# skipping legitimately slow matches on very long strings; a looser
# one lets each planted string burn seconds. 1s is ~6 orders of
# magnitude above a benign match on a clipped subject.
REGEX_MATCH_BUDGET_SECONDS = 1.0

# Budget overruns tolerated before regex matching is disabled for the
# rest of the scan. Each overrun strands one watchdog worker thread
# (daemon — it cannot block exit, but it burns a core until the match
# finishes), so the breaker also bounds leaked threads. Both
# directions: higher tolerates more planted bombs at a core each;
# lower gives up recall after a single pathological string.
REGEX_MATCH_TIMEOUT_BREAKER = 3

_MATCH_TIMED_OUT = object()


def _search_with_budget(
    patterns: list[Any],
    subject: str,
    budget_s: float,
) -> Any:
    """any-of ``search`` under a wall-clock budget.

    The match runs in a daemon worker thread; an overrun returns
    :data:`_MATCH_TIMED_OUT` and strands the worker (bounded by the
    caller's breaker) instead of hanging the scan. Module-level so
    tests can exercise/patch the budget path directly.
    """
    result: dict[str, bool] = {}

    def _work() -> None:
        result["hit"] = any(p.search(subject) for p in patterns)

    worker = threading.Thread(
        target=_work, daemon=True, name="hunt-regex-budget",
    )
    worker.start()
    worker.join(budget_s)
    if worker.is_alive():
        return _MATCH_TIMED_OUT
    return bool(result.get("hit"))


def compile_anchor_matcher(
    anchors: list[str],
    *,
    regex: bool = False,
) -> "Callable[[str], bool]":
    """Build the string-selection predicate for the scan.

    Substring by default (case-insensitive — anchors are recall
    tools); ``regex=True`` compiles each anchor as a bounded regex
    (see :func:`_regex_complexity_guard`). Raises :class:`HuntError`
    on empty/over-long/over-complex/malformed anchors.
    """
    if not anchors:
        msg = "at least one --anchor is required"
        raise HuntError(msg)
    if len(anchors) > MAX_ANCHORS:
        msg = f"too many anchors ({len(anchors)}; max {MAX_ANCHORS})"
        raise HuntError(msg)
    cleaned: list[str] = []
    for anchor in anchors:
        if not isinstance(anchor, str) or not anchor.strip():
            msg = "empty anchor"
            raise HuntError(msg)
        if len(anchor) > MAX_ANCHOR_PATTERN_CHARS:
            msg = (
                f"anchor too long ({len(anchor)} chars; "
                f"max {MAX_ANCHOR_PATTERN_CHARS})"
            )
            raise HuntError(msg)
        cleaned.append(anchor)
    if regex:
        compiled = []
        for pattern in cleaned:
            _regex_complexity_guard(pattern)
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as exc:
                msg = f"invalid anchor regex: {exc}"
                raise HuntError(msg) from exc

        match_stats: dict[str, Any] = {
            "budget_timeouts": 0,
            "disabled": False,
        }

        def _match_re(text: str) -> bool:
            if match_stats["disabled"]:
                return False
            subject = text[:MAX_MATCH_SUBJECT_CHARS]
            outcome = _search_with_budget(
                compiled, subject, REGEX_MATCH_BUDGET_SECONDS,
            )
            if outcome is _MATCH_TIMED_OUT:
                match_stats["budget_timeouts"] += 1
                if (match_stats["budget_timeouts"]
                        >= REGEX_MATCH_TIMEOUT_BREAKER):
                    match_stats["disabled"] = True
                return False
            return bool(outcome)

        _match_re.match_stats = match_stats  # type: ignore[attr-defined]
        return _match_re

    needles = [anchor.casefold() for anchor in cleaned]

    def _match_sub(text: str) -> bool:
        subject = text[:MAX_MATCH_SUBJECT_CHARS].casefold()
        return any(needle in subject for needle in needles)

    return _match_sub


# --------------------------------------------------------------------
# Family clustering (pure — deterministic under shuffled emission)
# --------------------------------------------------------------------

class _UnionFind:
    def __init__(self) -> None:
        self._parent: dict[int, int] = {}

    def find(self, item: int) -> int:
        parent = self._parent.setdefault(item, item)
        while parent != item:
            self._parent[item] = self._parent.setdefault(parent, parent)
            item = self._parent[item]
            parent = self._parent.setdefault(item, item)
        return item

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic root choice: smaller address wins, so
            # component identity never depends on emission order.
            lo, hi = min(ra, rb), max(ra, rb)
            self._parent[hi] = lo


def _stems(text: str) -> set[str]:
    """Alphabetic token stems of one (already-escaped) anchor string."""
    return set(_STEM_RE.findall(text.casefold()))


def cluster_anchor_families(
    records: list[dict[str, Any]],
    *,
    min_shared: int = MIN_SHARED_ANCHOR_STRINGS,
    stem_fanout: int = STEM_JOIN_MAX_FANOUT,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Cluster string-xref records into anchor families.

    ``records`` is the scanner's shape: one entry per matched string
    with its referencing functions. Join rules:

    - CO-OCCURRENCE: two functions sharing >= ``min_shared`` distinct
      anchor strings join one family (the primary signal).
    - RARE STEM: functions sharing an alphabetic token stem held by at
      most ``stem_fanout`` functions join (near-unique vocabulary —
      "kdcc", "recblob" — marks siblings that never co-reference the
      exact same string).

    Deterministic under shuffled input: all grouping keys are sorted
    and union roots are address-ordered. Returns ``(families,
    cluster_stats)``; each family carries members sorted by
    xref-weight (matched-string count) then address, with truncation
    surfaced in-band.
    """
    # Aggregate function sets PER STRING TEXT first: duplicate izj
    # entries for the same text (or the same text at many vaddrs) are
    # ONE string downstream, and a per-record cap alone lets N
    # duplicate records smuggle N x cap functions into the pairwise
    # join — quadratic in the flood. The fanout cap applies to the
    # per-text UNION, before any pairwise work.
    funcs_by_text: dict[str, set[int]] = {}
    names_by_addr: dict[int, set[str]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        text = str(record.get("text") or "")
        functions = record.get("functions")
        if not text or not isinstance(functions, list):
            continue
        for item in functions:
            if not isinstance(item, dict):
                continue
            addr = item.get("address")
            if isinstance(addr, bool) or not isinstance(addr, int):
                continue
            funcs_by_text.setdefault(text, set()).add(addr)
            name = str(item.get("name") or "")
            if name:
                names_by_addr.setdefault(addr, set()).add(name)

    string_funcs_truncated = 0
    capped_by_text: dict[str, list[int]] = {}
    for text in sorted(funcs_by_text):
        addrs = sorted(funcs_by_text[text])
        if len(addrs) > MAX_FUNCS_PER_STRING:
            string_funcs_truncated += 1
            # Address-ordered keep: never emission-order dependent.
            addrs = addrs[:MAX_FUNCS_PER_STRING]
        capped_by_text[text] = addrs

    per_func_strings: dict[int, set[str]] = {}
    for text, addrs in capped_by_text.items():
        for addr in addrs:
            per_func_strings.setdefault(addr, set()).add(text)
    # Deterministic name choice (lexicographic min) — the same
    # function can surface under variant names across records and the
    # pick must not depend on emission order.
    per_func_name: dict[int, str] = {
        addr: min(names) for addr, names in names_by_addr.items()
    }

    uf = _UnionFind()
    for addr in per_func_strings:
        uf.find(addr)

    # Co-occurrence joins over the CAPPED per-text sets.
    pair_shared: dict[tuple[int, int], int] = {}
    for text in sorted(capped_by_text):
        addrs = capped_by_text[text]
        for i, a in enumerate(addrs):
            for b in addrs[i + 1:]:
                pair_shared[(a, b)] = pair_shared.get((a, b), 0) + 1
    for (a, b), shared in sorted(pair_shared.items()):
        if shared >= min_shared:
            uf.union(a, b)

    # Rare-stem joins. A stem only corroborates a pair when it is
    # witnessed by DIFFERENT strings on the two sides ("kdcc open
    # failed" vs "kdcc close failed") — a stem inside one single
    # shared string is the same one-string evidence the K threshold
    # already refused, not independent corroboration.
    by_stem: dict[str, dict[int, set[str]]] = {}
    for addr, texts in per_func_strings.items():
        for text in texts:
            for stem in _stems(text):
                by_stem.setdefault(stem, {}).setdefault(addr, set()).add(text)
    for stem in sorted(by_stem):
        witnesses = by_stem[stem]
        addrs = sorted(witnesses)
        if not (2 <= len(addrs) <= stem_fanout):
            continue
        for i, a in enumerate(addrs):
            for b in addrs[i + 1:]:
                if witnesses[a] - witnesses[b] and witnesses[b] - witnesses[a]:
                    uf.union(a, b)

    components: dict[int, list[int]] = {}
    for addr in per_func_strings:
        components.setdefault(uf.find(addr), []).append(addr)

    families: list[dict[str, Any]] = []
    for root in sorted(components):
        addrs = sorted(
            components[root],
            key=lambda a: (-len(per_func_strings[a]), a),
        )
        total = len(addrs)
        kept = addrs[:MAX_FAMILY_MEMBERS]
        members = [
            {
                "address": addr,
                "name": per_func_name.get(addr, ""),
                "anchor_string_count": len(per_func_strings[addr]),
                "anchor_strings": sorted(per_func_strings[addr]),
            }
            for addr in kept
        ]
        family_strings = sorted(
            {text for addr in kept for text in per_func_strings[addr]},
        )
        # Sample selection: strings referenced by the MOST kept
        # members first (the family's shared vocabulary), then
        # lexicographic — deterministic and flood-resistant.
        member_count_by_string = {
            text: sum(1 for addr in kept
                      if text in per_func_strings[addr])
            for text in family_strings
        }
        samples = sorted(
            family_strings,
            key=lambda text: (-member_count_by_string[text], text),
        )[:FAMILY_SAMPLE_STRINGS]
        stem_members: dict[str, int] = {}
        for addr in kept:
            seen: set[str] = set()
            for text in per_func_strings[addr]:
                seen |= _stems(text)
            for stem in seen:
                stem_members[stem] = stem_members.get(stem, 0) + 1
        shared_stems = sorted(
            (stem for stem, count in stem_members.items() if count >= 2),
            key=lambda stem: (-stem_members[stem], stem),
        )[:MAX_FAMILY_STEMS]
        family: dict[str, Any] = {
            "members": members,
            "member_count": total,
            "shared_stems": shared_stems,
            "sample_strings": samples,
            "total_anchor_weight": sum(
                len(per_func_strings[a]) for a in addrs
            ),
        }
        if total > MAX_FAMILY_MEMBERS:
            family["truncation"] = (
                f"family capped at {len(kept)} of {total} members; "
                "kept by xref-weight, not discovery order"
            )
        families.append(family)

    families.sort(
        key=lambda fam: (
            -fam["total_anchor_weight"],
            fam["members"][0]["address"] if fam["members"] else 0,
        ),
    )
    stats: dict[str, Any] = {
        "families_total": len(families),
        "string_fanout_truncated": string_funcs_truncated,
    }
    if len(families) > MAX_FAMILIES:
        stats["families_truncation"] = (
            f"families capped at {MAX_FAMILIES} of {len(families)}; "
            "kept by total xref-weight, not discovery order"
        )
        families = families[:MAX_FAMILIES]
    return families, stats


# --------------------------------------------------------------------
# Run-dir enrichment (fids, sizes, shared callees, inter-member edges)
# --------------------------------------------------------------------

def _load_manifest(run_dir: Path) -> BinaryManifest:
    payload = load_json(run_dir / "binary-manifest.json")
    if not isinstance(payload, dict):
        msg = f"missing binary-manifest.json in {run_dir}"
        raise HuntError(msg)
    manifest = BinaryManifest.from_dict(payload)
    if not manifest.binary_path:
        msg = f"invalid binary manifest in {run_dir}"
        raise HuntError(msg)
    return manifest


def _load_context_map(run_dir: Path) -> dict[str, Any]:
    payload = load_json(
        run_dir / "binary-context-map.json",
        # The consumer-side read cap every bounded context-map reader
        # imports — one home, so read bound and producer budget can
        # never drift apart silently.
        max_bytes=CONTEXT_MAP_CONSUMER_MAX_BYTES,
    )
    if not isinstance(payload, dict):
        msg = f"missing binary-context-map.json in {run_dir}"
        raise HuntError(msg)
    return payload


def _parse_addr(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value:
        try:
            return int(value, 16) if value.lower().startswith("0x") \
                else int(value)
        except ValueError:
            return None
    return None


def _inventory_by_address(
    context_map: dict[str, Any],
) -> dict[int, dict[str, Any]]:
    index: dict[int, dict[str, Any]] = {}
    for key in ("interesting_functions", "runtime_support_functions"):
        for item in context_map.get(key) or []:
            if not isinstance(item, dict):
                continue
            addr = _parse_addr(item.get("address"))
            if addr is not None:
                index.setdefault(addr, item)
    return index


def _fid_for(manifest: BinaryManifest, address: int) -> str | None:
    """Mint a fid from the manifest's recorded identity legs.

    Fail-closed per core.binary.addrmap: no recorded image base or no
    module anchor means NO fid — consumers fall back to names.
    """
    if manifest.image_base is None:
        return None
    anchor = module_anchor(
        build_id=manifest.build_id or None,
        binary_sha256=manifest.binary_sha256 or None,
    )
    return make_fid(anchor, address, manifest.image_base)


def _enrich_members(
    families: list[dict[str, Any]],
    manifest: BinaryManifest,
    inventory: dict[int, dict[str, Any]],
) -> None:
    """Bind members to the run's inventory: fid + name + size.

    Inventory values win over scan-time names (they were bound to the
    map's recovered functions); functions outside the inventory keep
    the scan-time escaped name and mint a fid from the manifest legs
    when possible.
    """
    for family in families:
        for member in family["members"]:
            addr = member["address"]
            record = inventory.get(addr)
            if record is not None:
                if record.get("name"):
                    member["name"] = str(record["name"])
                member["size"] = int(record.get("size") or 0)
                fid = record.get("fid") or _fid_for(manifest, addr)
            else:
                member["size"] = 0
                fid = _fid_for(manifest, addr)
            if fid:
                member["fid"] = fid
            member["address"] = hex(addr)


def _callee_index(
    context_map: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """name (full + base) -> inventory records, for callee resolution.

    Only the map's ingress-rooted call subgraph persists per-function
    edges, so callee EDGES come from ``call_graph_edges``; this index
    resolves the names those edges carry.
    """
    index: dict[str, list[dict[str, Any]]] = {}
    for item in context_map.get("interesting_functions") or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        name = str(item["name"])
        index.setdefault(name, []).append(item)
        base = symbol_base_name(name)
        if base != name:
            index.setdefault(base, []).append(item)
    return index


def _member_call_structure(
    families: list[dict[str, Any]],
    context_map: dict[str, Any],
    manifest: BinaryManifest,
) -> list[dict[str, Any]]:
    """Shared callees + inter-member edges from the persisted map
    call subgraph.

    HONESTY: the map persists only the ingress-rooted bounded call
    subgraph, so absence of an edge here means "not in the persisted
    subgraph", never "no call". Each family's records say which
    substrate produced them. Returns fid-resolution misses for the
    caller to record.
    """
    edges = [
        item for item in context_map.get("call_graph_edges") or []
        if isinstance(item, dict) and item.get("source_name")
    ]
    callees_by_source: dict[str, set[str]] = {}
    for edge in edges:
        target = str(edge.get("target_name") or "")
        if target:
            callees_by_source.setdefault(
                str(edge["source_name"]), set()).add(target)
    callee_index = _callee_index(context_map)
    misses: list[dict[str, Any]] = []
    for family in families:
        member_names = {m["name"] for m in family["members"]}
        member_bases = {symbol_base_name(n) for n in member_names}
        callee_members: dict[str, list[str]] = {}
        inter_edges: list[dict[str, str]] = []
        for member in family["members"]:
            for callee in sorted(
                callees_by_source.get(member["name"], ()),
            ):
                base = symbol_base_name(callee)
                if callee in member_names or base in member_bases:
                    inter_edges.append(
                        {"caller": member["name"], "callee": callee},
                    )
                else:
                    callee_members.setdefault(callee, []).append(
                        member["name"],
                    )
        shared: list[dict[str, Any]] = []
        for callee in sorted(callee_members):
            callers = sorted(set(callee_members[callee]))
            if len(callers) < 2:
                continue
            entry: dict[str, Any] = {
                "name": callee,
                "called_by": callers,
            }
            resolved = callee_index.get(callee) or []
            if len(resolved) == 1:
                record = resolved[0]
                fid = record.get("fid")
                if not fid:
                    addr = _parse_addr(record.get("address"))
                    if addr is not None:
                        fid = _fid_for(manifest, addr)
                if fid:
                    entry["fid"] = fid
            else:
                # Unresolvable (import, ambiguous duplicate, or
                # outside the inventory) — recorded, never silently
                # dropped: a fid-less shared helper is exactly what
                # the miss log exists to make visible.
                misses.append({
                    "operation_detail": "shared_callee",
                    "name": callee,
                    "reason": ("ambiguous_name" if len(resolved) > 1
                               else "not_in_inventory"),
                })
            shared.append(entry)
        total_shared = len(shared)
        if total_shared > MAX_SHARED_CALLEES:
            family["shared_callees_truncation"] = (
                f"shared callees capped at {MAX_SHARED_CALLEES} of "
                f"{total_shared}"
            )
            shared = shared[:MAX_SHARED_CALLEES]
        family["shared_callees"] = shared
        total_edges = len(inter_edges)
        if total_edges > MAX_INTER_MEMBER_EDGES:
            family["inter_member_edges_truncation"] = (
                f"inter-member edges capped at {MAX_INTER_MEMBER_EDGES} "
                f"of {total_edges}"
            )
            inter_edges = inter_edges[:MAX_INTER_MEMBER_EDGES]
        family["inter_member_edges"] = inter_edges
        family["call_structure_note"] = (
            "Callee data comes from the map's persisted ingress-rooted "
            "call subgraph; absence of an edge here does not mean the "
            "call does not exist."
        )
    return misses


def _escape_family_text(families: list[dict[str, Any]]) -> None:
    """Escape backstop for every hostile-text slot in the family
    payload: names adopted from the run's context map (the map's
    inventory stores raw r2 names; escaping is a render-site concern
    there), plus the string slots (sample_strings, per-member
    anchor_strings) in case a scanner did NOT escape at capture — raw
    ESC and raw bidi code points otherwise ride to disk (save_json
    preserves raw code points). THIS artifact is a jq-to-terminal
    surface; the evidence records are built AFTER this pass so they
    inherit the escaped values. Idempotent on already-escaped text.
    """
    for family in families:
        family["sample_strings"] = [
            escape_nonprintable(str(text))
            for text in family.get("sample_strings") or []
        ]
        for member in family.get("members") or []:
            member["name"] = escape_nonprintable(str(member.get("name") or ""))
            member["anchor_strings"] = [
                escape_nonprintable(str(text))
                for text in member.get("anchor_strings") or []
            ]
        for callee in family.get("shared_callees") or []:
            callee["name"] = escape_nonprintable(str(callee.get("name") or ""))
            callee["called_by"] = [
                escape_nonprintable(str(name))
                for name in callee.get("called_by") or []
            ]
        for edge in family.get("inter_member_edges") or []:
            edge["caller"] = escape_nonprintable(str(edge.get("caller") or ""))
            edge["callee"] = escape_nonprintable(str(edge.get("callee") or ""))


def _family_id(family: dict[str, Any], anchors: list[str]) -> str:
    raw = "::".join([
        *sorted(str(m["address"]) for m in family["members"]),
        *sorted(anchors),
    ])
    digest = hashlib.sha256(
        raw.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return f"BHUNTFAM-{digest}"


# --------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------

def _verified_binary(manifest: BinaryManifest) -> Path:
    """Content-identity gate before any live scan.

    The hunt joins its results onto the run's fids and inventory, so
    a swapped binary at the manifest path must refuse rather than mint
    joins against the wrong module. (r2 only reads the file — the
    gate protects evidence integrity, not execution safety.)
    """
    from core.hash import sha256_file
    binary = Path(manifest.binary_path)
    if not binary.is_file():
        msg = f"mapped binary no longer exists: {binary}"
        raise HuntError(msg)
    try:
        current_sha = sha256_file(binary)
    except OSError as exc:
        msg = f"cannot hash mapped binary {binary}: {exc}"
        raise HuntError(msg) from exc
    if manifest.binary_sha256 and current_sha != manifest.binary_sha256:
        msg = (
            f"mapped binary has changed since the map run (sha256 "
            f"{current_sha} != manifest {manifest.binary_sha256}); "
            f"re-run the map on the current binary"
        )
        raise HuntError(msg)
    return binary


def _default_scanner(
    manifest: BinaryManifest,
    select_fn: "Callable[[str], bool]",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Live bounded r2 string scan against the run's mapped binary."""
    understand = BinaryUnderstand(_verified_binary(manifest))
    return understand.string_xref_scan(select_fn)


def run_anchor_hunt(
    run_dir: Path,
    anchors: list[str],
    *,
    regex: bool = False,
    scanner: "Callable[..., tuple[list[dict[str, Any]], dict[str, Any]]] | None" = None,
) -> dict[str, Any]:
    """Anchor-family hunt over an existing binary run directory.

    Returns the artifact payload (already written to
    ``binary-hunt-<slug>.json`` beside a ``.md`` report, and ingested
    into the run's graph store). ``scanner`` is injectable for tests;
    the default is the live bounded r2 scan.
    """
    run_dir = Path(run_dir)
    matcher = compile_anchor_matcher(anchors, regex=regex)
    manifest = _load_manifest(run_dir)
    context_map = _load_context_map(run_dir)

    scan = scanner or _default_scanner
    records, scan_meta = scan(manifest, matcher)

    families, cluster_stats = cluster_anchor_families(records)
    inventory = _inventory_by_address(context_map)
    _enrich_members(families, manifest, inventory)
    misses = _member_call_structure(families, context_map, manifest)
    _escape_family_text(families)

    evidence: list[BinaryEvidenceRecord] = []
    for family in families:
        family["id"] = _family_id(family, anchors)
        family["confidence"] = "candidate"
        family["evidence_tier"] = EvidenceTier.XREF_BACKED.value
        family["evidence_note"] = _HUNT_NOT_A_FINDING
        record = make_evidence(
            manifest.binary_sha256,
            kind="hunt_anchor_family",
            source="radare2_axtj",
            summary=(
                f"{len(family['members'])} function(s) clustered on "
                f"operator anchor strings"
            ),
            tier=EvidenceTier.XREF_BACKED,
            confidence="candidate",
            reproducible=True,
            tool="radare2",
            location=manifest.binary_path,
            data={
                "family_id": family["id"],
                "members": [m["name"] for m in family["members"]],
                "sample_strings": family["sample_strings"],
            },
        )
        evidence.append(record)
        family["evidence_ids"] = [record.id]

    # Operator anchors are echoed ESCAPED: they are operator-typed,
    # but this artifact is a jq-to-terminal and report surface and the
    # echo convention must not depend on who typed the value.
    payload: dict[str, Any] = {
        "schema_version": 1,
        "mode": "anchor",
        "binary": manifest.binary_path,
        "binary_sha256": manifest.binary_sha256,
        "anchors": [escape_nonprintable(a) for a in anchors],
        "anchor_regex": bool(regex),
        "scan": {
            "substrate": "radare2 string-xref scan (izj + axtj, bounded)",
            **(scan_meta.get("stats") or {}),
            # The collector's documented contract: EMPTY stats means
            # the scan itself degraded (izj unreadable / session
            # lost) — 0 families then reflects the failure, not the
            # binary, and must be said in-band.
            "degraded": not (scan_meta.get("stats") or {}),
            # Notes quote r2 degradation text — escape like every
            # other externally-influenced string in this artifact.
            "notes": [
                escape_nonprintable(str(note))
                for note in scan_meta.get("notes") or []
            ],
            **_regex_budget_stats(matcher),
        },
        "cluster_stats": cluster_stats,
        "families": families,
        "claim": "structural_lead_only",
        "evidence_note": _HUNT_NOT_A_FINDING,
        "evidence": [record.to_dict() for record in evidence],
    }
    _surface_scan_truncation(payload)

    if misses:
        record_fid_misses(run_dir, "binary-hunt-anchor", misses)

    slug_source = anchors[0] if anchors else "anchor"
    artifact = _write_hunt_artifacts(
        run_dir, payload, slug_hint=f"anchor-{_slug(slug_source)}",
    )
    _ingest_anchor_graph(run_dir, manifest, payload, evidence)
    payload["artifacts"] = artifact
    return payload


def _regex_budget_stats(matcher: Any) -> dict[str, Any]:
    """Additive scan fields for the regex match-budget breaker."""
    stats = getattr(matcher, "match_stats", None)
    if not isinstance(stats, dict) or not stats.get("budget_timeouts"):
        return {}
    return {
        "regex_budget_timeouts": int(stats["budget_timeouts"]),
        "regex_matching_disabled": bool(stats.get("disabled")),
    }


def _surface_scan_truncation(payload: dict[str, Any]) -> None:
    """Fold every truncation / degradation fact into one in-band line
    list — the report and the terminal summary both render it, so a
    partial scan can never present as a clean empty result."""
    lines: list[str] = []
    scan = payload.get("scan") or {}
    if scan.get("degraded"):
        lines.append(
            "string scan degraded (izj unreadable or session lost) — "
            "an empty family list may reflect the failure, not the "
            "binary"
        )
    for note in scan.get("notes") or []:
        lines.append(str(note))
    if scan.get("regex_budget_timeouts"):
        suffix = ("; regex matching disabled for the rest of the scan"
                  if scan.get("regex_matching_disabled") else "")
        lines.append(
            f"{scan['regex_budget_timeouts']} string(s) exceeded the "
            f"per-string regex match budget and were skipped{suffix}"
        )
    if scan.get("scan_truncated"):
        lines.append(
            f"string scan examined {scan.get('strings_scanned')} of "
            f"{scan.get('strings_total')} strings (scan bound)"
        )
    if scan.get("selection_truncated"):
        lines.append(
            "matched strings exceeded the xref-lookup budget; later "
            "matches were not resolved"
        )
    cluster = payload.get("cluster_stats") or {}
    if cluster.get("string_fanout_truncated"):
        lines.append(
            f"{cluster['string_fanout_truncated']} string(s) had their "
            f"referencing-function fanout capped at "
            f"{MAX_FUNCS_PER_STRING}"
        )
    if cluster.get("families_truncation"):
        lines.append(str(cluster["families_truncation"]))
    for family in payload.get("families") or []:
        for key in ("truncation", "shared_callees_truncation",
                    "inter_member_edges_truncation"):
            if family.get(key):
                lines.append(str(family[key]))
    payload["truncation_lines"] = lines


# --------------------------------------------------------------------
# Artifact + report + graph
# --------------------------------------------------------------------

def _slug(text: str) -> str:
    runs = _SLUG_RE.findall(str(text).casefold())
    slug = "-".join(runs)[:32].strip("-")
    return slug or "hunt"


def _write_hunt_artifacts(
    run_dir: Path,
    payload: dict[str, Any],
    *,
    slug_hint: str,
) -> dict[str, str]:
    """Write ``binary-hunt-<slug>.json`` + the companion report.

    Collision-suffixed under the run-artifact lock so two concurrent
    hunts with the same anchor never clobber each other's artifacts.
    """
    stamp_provenance(payload, "binary-hunt", untrusted=True)
    with run_artifacts_lock(run_dir):
        slug = slug_hint
        suffix = 1
        while (run_dir / f"binary-hunt-{slug}.json").exists():
            suffix += 1
            slug = f"{slug_hint}-{suffix}"
            if suffix > 100:
                msg = f"too many hunt artifacts named {slug_hint} in {run_dir}"
                raise HuntError(msg)
        json_path = run_dir / f"binary-hunt-{slug}.json"
        report_path = run_dir / f"binary-hunt-{slug}.md"
        save_json(json_path, payload)
        # Atomic like the save_json beside it: the collision loop's
        # exists() probe shares exists()'s dangling-symlink blind
        # spot, and a plain write_text would follow whatever occupies
        # the name; os.replace replaces a planted symlink itself.
        write_text_atomically(report_path, _render_report(payload))
    return {"json": str(json_path), "report": str(report_path)}


def _md_escape(value: Any) -> str:
    # Report slots carry hostile-binary strings (already escaped at
    # capture, but printable markdown metacharacters survive that) —
    # md_inline is the writer-discipline home: control/bidi escaping,
    # newline flattening, in-slot | and backtick entity-escaping,
    # autofetch stripping.
    return md_inline(value)


def _render_report(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    mode = str(payload.get("mode") or "hunt")
    lines.append(f"# Binary hunt — {_md_escape(mode)}")
    lines.append("")
    lines.append(f"Target: `{_md_escape(payload.get('binary'))}`")
    lines.append("")
    if payload.get("evidence_note"):
        lines.append(
            "**Not findings.** " + _md_escape(payload.get("evidence_note")),
        )
        lines.append("")
    for honesty in payload.get("honesty") or []:
        lines.append(f"**Honesty.** {_md_escape(honesty)}")
        lines.append("")
    if payload.get("anchors"):
        anchors = ", ".join(
            f"`{_md_escape(anchor)}`" for anchor in payload["anchors"]
        )
        lines.append(
            f"Anchors ({'regex' if payload.get('anchor_regex') else 'substring'}): {anchors}",
        )
        lines.append("")
    for line in payload.get("truncation_lines") or []:
        lines.append(f"- ⚠️ {_md_escape(line)}")
    if payload.get("truncation_lines"):
        lines.append("")
    families = payload.get("families") or []
    if payload.get("mode") == "anchor":
        lines.append(f"## Anchor families ({len(families)})")
        lines.append("")
        for index, family in enumerate(families, start=1):
            lines.append(
                f"### Family {index} — {_md_escape(family.get('id'))}"
            )
            lines.append("")
            if family.get("shared_stems"):
                stems = ", ".join(
                    f"`{_md_escape(stem)}`" for stem in family["shared_stems"]
                )
                lines.append(f"Shared stems: {stems}")
                lines.append("")
            if family.get("truncation"):
                lines.append(f"⚠️ {_md_escape(family['truncation'])}")
                lines.append("")
            lines.append("| # | Function | Address | Size | Anchor strings | fid |")
            lines.append("|---|----------|---------|------|----------------|-----|")
            for m_index, member in enumerate(
                family.get("members") or [], start=1,
            ):
                lines.append(
                    f"| {m_index} | `{_md_escape(member.get('name'))}` | "
                    f"`{_md_escape(member.get('address'))}` | "
                    f"{int(member.get('size') or 0)} | "
                    f"{int(member.get('anchor_string_count') or 0)} | "
                    f"`{_md_escape(member.get('fid') or '-')}` |"
                )
            lines.append("")
            if family.get("sample_strings"):
                lines.append("Sample strings:")
                for sample in family["sample_strings"]:
                    lines.append(f"- `{_md_escape(sample)}`")
                lines.append("")
            shared = family.get("shared_callees") or []
            if shared:
                lines.append("Shared callees (how common helpers surface):")
                for callee in shared:
                    called_by = ", ".join(
                        f"`{_md_escape(n)}`" for n in callee.get("called_by") or []
                    )
                    fid = callee.get("fid")
                    fid_part = f" (fid `{_md_escape(fid)}`)" if fid else ""
                    lines.append(
                        f"- `{_md_escape(callee.get('name'))}`{fid_part} — "
                        f"called by {called_by}"
                    )
                lines.append("")
            edges = family.get("inter_member_edges") or []
            if edges:
                lines.append("Inter-member call edges:")
                for edge in edges:
                    lines.append(
                        f"- `{_md_escape(edge.get('caller'))}` → "
                        f"`{_md_escape(edge.get('callee'))}`"
                    )
                lines.append("")
            if family.get("call_structure_note"):
                lines.append(f"_{_md_escape(family['call_structure_note'])}_")
                lines.append("")
    if payload.get("mode") == "calls":
        query = payload.get("query") or {}
        lines.append(
            f"Substrate: {_md_escape(payload.get('substrate'))}",
        )
        lines.append("")
        for note in payload.get("substrate_notes") or []:
            lines.append(f"- ⚠️ {_md_escape(note)}")
        if payload.get("substrate_notes"):
            lines.append("")
        scope = ("transitive, depth "
                 f"{int(query.get('max_depth') or 1)}"
                 if query.get("transitive") else "direct")
        lines.append(
            f"## Callers of `{_md_escape(query.get('resolved_calls'))}` "
            f"({scope}) — {int(payload.get('caller_count') or 0)}",
        )
        lines.append("")
        lines.append("| # | Caller | Depth | Address | fid |")
        lines.append("|---|--------|-------|---------|-----|")
        for index, entry in enumerate(
            payload.get("callers") or [], start=1,
        ):
            lines.append(
                f"| {index} | `{_md_escape(entry.get('name'))}` | "
                f"{int(entry.get('depth') or 0)} | "
                f"`{_md_escape(entry.get('address') or '-')}` | "
                f"`{_md_escape(entry.get('fid') or '-')}` |"
            )
        lines.append("")
        residual = payload.get("residual")
        if isinstance(residual, dict):
            lines.append(
                f"## Chokepoint residual — callers with no edge to "
                f"`{_md_escape(query.get('resolved_and_not_calls'))}` "
                f"({int(residual.get('count') or 0)})",
            )
            lines.append("")
            lines.append(
                "**Hypothesis tier.** "
                + _md_escape(residual.get("evidence_note")),
            )
            lines.append("")
            if residual.get("empty_note"):
                lines.append(_md_escape(residual["empty_note"]))
                lines.append("")
            for entry in residual.get("entries") or []:
                fid = entry.get("fid")
                fid_part = f" (fid `{_md_escape(fid)}`)" if fid else ""
                lines.append(
                    f"- `{_md_escape(entry.get('name'))}`{fid_part} — "
                    f"depth {int(entry.get('depth') or 0)}"
                )
            if residual.get("entries"):
                lines.append("")
    return "\n".join(lines) + "\n"


def _hunt_snapshot(
    store: BinaryGraphStore,
    manifest: BinaryManifest,
    run_dir: Path,
) -> str:
    """Snapshot to attach hunt records to.

    Reuse the latest snapshot when one exists: ``begin_snapshot`` is
    keyed by (sha, run_dir) and INSERT OR REPLACE would CASCADE-delete
    every node/edge the map ingested for this run — the hunt must
    never wipe the map's graph.
    """
    snapshot_id = store.latest_snapshot_id()
    if snapshot_id:
        return snapshot_id
    return store.begin_snapshot(
        manifest.binary_sha256, manifest.binary_path, run_dir,
        props={"producer": "binary-hunt"},
    )


def _ingest_anchor_graph(
    run_dir: Path,
    manifest: BinaryManifest,
    payload: dict[str, Any],
    evidence: list[BinaryEvidenceRecord],
) -> None:
    graph_path = graph_path_for_run(run_dir)
    with BinaryGraphStore(graph_path) as store, store.batch():
        snapshot_id = _hunt_snapshot(store, manifest, run_dir)
        for record in evidence:
            store.add_evidence(snapshot_id, record)
        for family in payload.get("families") or []:
            family_node = store.add_node(
                snapshot_id,
                manifest.binary_sha256,
                "hunt_anchor_family",
                family["id"],
                name=family["id"],
                props={
                    key: value for key, value in family.items()
                    if key != "members"
                },
                evidence_ids=family.get("evidence_ids") or [],
            )
            for member in family.get("members") or []:
                addr = _parse_addr(member.get("address"))
                # Function-node key matches the map ingest's
                # ("function", BFN-<addr:x>) so the stable ids join
                # across snapshots — and add-if-absent, because the
                # hunt attaches to the MAP's snapshot: a REPLACE here
                # wiped the map's function props (calls_dangerous,
                # transitive_distance) for every family member.
                key = (f"BFN-{addr:x}" if addr is not None
                       else str(member.get("name") or ""))
                fn_node = store.add_node_if_absent(
                    snapshot_id,
                    manifest.binary_sha256,
                    "function",
                    key,
                    name=str(member.get("name") or ""),
                    address=str(member.get("address") or ""),
                    props=member,
                )
                store.add_edge(
                    snapshot_id,
                    manifest.binary_sha256,
                    "HUNT_ANCHOR_FAMILY_MEMBER",
                    family_node,
                    fn_node,
                    confidence="candidate",
                    evidence_ids=family.get("evidence_ids") or [],
                )


# --------------------------------------------------------------------
# --calls / --and-not-calls: set algebra over a real call graph
# --------------------------------------------------------------------

# Transitive-caller BFS depth for the calls algebra. Mirrors the map
# pass's transitive rationale: real CVE chains commonly span 4-5 hops.
# Both directions: deeper walks explode on dense/cyclic call graphs
# and drown the residual in far-away callers; shallower ones miss the
# parse → helpers → chokepoint chains the question exists to find.
# --max-depth may move it, but never past the hard cap — past ~12
# hops the answer is the whole binary, which is noise wearing a
# number.
CALLS_MAX_DEPTH_DEFAULT = 5
CALLS_MAX_DEPTH_CAP = 12

# Callers reported per query. Both directions: uncapped, a dispatch
# hub's caller set turns the artifact into a whole-program listing;
# too tight hides real review queues. Truncation is surfaced in-band
# and keeps depth order (nearest callers are the actionable ones).
MAX_CALLERS_REPORTED = 200

_CALLS_ABSENCE_NOTE = (
    "Absence of a call edge is not dataflow proof: residual entries "
    "are a review queue, not findings — the target may be reached "
    "through function pointers, wrappers, edges outside this "
    "substrate, or call chains deeper than the transitive depth "
    "bound."
)
_CALLS_PRESENCE_NOTE = (
    "Presence of a call edge is not protection: a planted or "
    "dominated call empties this residual without sanitising "
    "anything. An empty residual list is never reported as coverage."
)


@dataclass
class CallGraph:
    """One substrate's caller→callee adjacency plus node metadata."""

    substrate: str
    callees: dict[str, set[str]] = field(default_factory=dict)
    # name -> {"address": int | None, "fid": str | None, "size": int}
    meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _graph_from_redb(
    run_dir: Path,
    manifest: BinaryManifest,
    notes: list[str] | None = None,
) -> CallGraph | None:
    """Substrate 1: a co-located Ghidra re-database's call xrefs.

    ``notes`` (caller-owned) collects the honesty trail: a REJECTED
    higher-precedence substrate must be visible to artifact consumers,
    not just stderr — a later reader cannot otherwise tell that better
    evidence existed and was refused.
    """
    if notes is None:
        notes = []
    redb_path = run_dir / "re-database.json"
    if not redb_path.is_file():
        return None
    try:
        from core.json.utils import RE_DATABASE_MAX_BYTES
        from packages.ghidra.model import REDatabase
    except ImportError:  # pragma: no cover - ghidra package absent
        return None
    payload = load_json(redb_path, max_bytes=RE_DATABASE_MAX_BYTES)
    if not isinstance(payload, dict):
        note = (
            "re-database.json is present but unreadable (malformed or "
            "over the read bound) — its call xrefs were not used"
        )
        logger.warning("hunt: %s (%s)", note, run_dir)
        notes.append(note)
        return None
    db = REDatabase.from_dict(payload)
    # Wrong-binary evidence must not drive the algebra: the database
    # stamps the analysed binary's content hash; when both sides carry
    # one and they disagree, skip this substrate loudly AND on the
    # record.
    db_sha = db.metadata.get("binary_sha256")
    if (isinstance(db_sha, str) and db_sha and manifest.binary_sha256
            and db_sha != manifest.binary_sha256):
        note = (
            "re-database.json is present but stamped for a DIFFERENT "
            "binary (sha mismatch) — its call xrefs were rejected; "
            "results come from a lower-precedence substrate"
        )
        logger.warning("hunt: %s", note)
        notes.append(note)
        return None
    callees: dict[str, set[str]] = {}
    for xref in db.xrefs:
        if xref.kind != "call":
            continue
        caller = db.function_containing_address(xref.from_addr)
        callee = (db.function_by_address(xref.to_addr)
                  or db.function_containing_address(xref.to_addr))
        if caller is None or callee is None or not caller.name \
                or not callee.name:
            continue
        callees.setdefault(caller.name, set()).add(callee.name)
    if not callees:
        return None
    graph_notes: list[str] = []
    if not (isinstance(db_sha, str) and db_sha):
        # Legacy artifact: usable, but the identity check could not
        # run — say so instead of implying a verified join.
        graph_notes.append(
            "re-database.json carries no binary_sha256 stamp (legacy "
            "artifact) — its identity against the mapped binary was "
            "not verified"
        )
    meta = {
        fn.name: {
            "address": fn.address,
            "fid": fn.fid,
            "size": fn.size,
        }
        for fn in db.functions
        if fn.name
    }
    return CallGraph(
        substrate="ghidra re-database call xrefs",
        callees=callees,
        meta=meta,
        notes=graph_notes,
    )


def _graph_from_map_scan(manifest: BinaryManifest) -> CallGraph | None:
    """Substrate 2: the map pass's whole-binary aflcj graph, fetched
    live through the parameterized machinery (one graph builder —
    ``BinaryUnderstand._fetch_call_adjacency`` — shared with the
    map's transitive-caller tagging)."""
    try:
        binary = _verified_binary(manifest)
        understand = BinaryUnderstand(binary)
    except (HuntError, RuntimeError, FileNotFoundError, ValueError) as exc:
        logger.info("hunt: aflcj substrate unavailable: %s", exc)
        return None
    callees, addr_by_name, notes = understand.call_adjacency_scan()
    if not callees:
        return None
    meta = {
        name: {
            "address": addr,
            "fid": _fid_for(manifest, addr),
            "size": 0,
        }
        for name, addr in addr_by_name.items()
    }
    return CallGraph(
        substrate="radare2 whole-binary call graph (aflcj)",
        callees=callees,
        meta=meta,
        notes=notes,
    )


def _graph_from_edge_cache(manifest: BinaryManifest) -> CallGraph | None:
    """Substrate 3: the binary-oracle cached call-edge index."""
    try:
        binary = _verified_binary(manifest)
    except HuntError as exc:
        logger.info("hunt: edge-cache substrate unavailable: %s", exc)
        return None
    try:
        from core.analysis.binary_oracle_edges import (
            extract_direct_call_edges,
        )
    except ImportError:  # pragma: no cover - analysis package absent
        return None
    index = extract_direct_call_edges(binary, use_cache=True)
    if not index.edges:
        return None
    callees: dict[str, set[str]] = {}
    for edge in index.edges:
        if edge.caller and edge.callee:
            callees.setdefault(edge.caller, set()).add(edge.callee)
    if not callees:
        return None
    # Name-only substrate: the edge index carries no addresses, so
    # entries stay fid-less (name fallback — honest, never minted).
    return CallGraph(
        substrate="binary-oracle call-edge index",
        callees=callees,
        meta={},
    )


def load_call_graph(run_dir: Path, manifest: BinaryManifest) -> CallGraph:
    """Best available call substrate, in documented precedence order:
    re-database xrefs → live aflcj graph → binary-oracle edge cache.

    Rejection notes from skipped higher-precedence substrates ride on
    the returned graph (and thence into the artifact) — a consumer
    must be able to tell "no better evidence existed" from "better
    evidence existed and was rejected". Raises :class:`HuntError` when
    none is usable — "no substrate" must be a refusal (naming what was
    rejected, e.g. a present-but-mismatched re-database), never an
    empty caller list wearing a verdict.
    """
    rejection_notes: list[str] = []
    for builder in (
        lambda: _graph_from_redb(run_dir, manifest, rejection_notes),
        lambda: _graph_from_map_scan(manifest),
        lambda: _graph_from_edge_cache(manifest),
    ):
        graph = builder()
        if graph is not None:
            graph.notes = [*rejection_notes, *graph.notes]
            return graph
    detail = ("; ".join(rejection_notes) if rejection_notes else
              "no re-database.json in the run dir")
    msg = (
        f"no usable call-graph substrate: {detail}; no scannable "
        f"binary for the whole-binary call graph, and no cached edge "
        f"index"
    )
    raise HuntError(msg)


def _resolve_call_query(
    query: str,
    graph: CallGraph,
    misses: list[dict[str, Any]],
) -> str | None:
    """Resolve one operator <fid|name> to a graph node name.

    fid resolution goes through the FidIndex join policy (exact →
    bounded fuzzy → unique name); plain names also match graph nodes
    directly, full or base form. A miss is RECORDED (the caller
    persists via record_fid_misses) and returns None.
    """
    index = FidIndex()
    for name, info in graph.meta.items():
        index.add(name, fid=info.get("fid"), name=name)
    if from_fid(query) is not None:
        match = index.resolve(fid=query)
        if match is not None:
            return str(match.payload)
        misses.append({
            "operation_detail": "calls_query",
            "query": query,
            "reason": "fid_not_resolved",
        })
        return None
    # Name path: graph node names first (full, then base-name match
    # when unambiguous), then the FidIndex name fallback.
    names = set(graph.callees)
    for callee_set in graph.callees.values():
        names.update(callee_set)
    names.update(graph.meta)
    if query in names:
        return query
    base_matches = sorted(
        name for name in names if symbol_base_name(name) == query
    )
    if len(base_matches) == 1:
        return base_matches[0]
    match = index.resolve(name=query)
    if match is not None:
        return str(match.payload)
    misses.append({
        "operation_detail": "calls_query",
        "query": query,
        "reason": ("ambiguous_base_name" if len(base_matches) > 1
                   else "name_not_in_graph"),
    })
    return None


def callers_of(
    graph: CallGraph,
    target: str,
    *,
    transitive: bool = False,
    max_depth: int = CALLS_MAX_DEPTH_DEFAULT,
) -> dict[str, int]:
    """caller name -> min hop distance to ``target``.

    Reverse BFS with the same full-plus-base-name indexing the map's
    transitive tagging uses (a call site recorded as ``strcpy`` must
    match a node stored as ``sym.imp.strcpy``). Cycle-safe: min-depth
    per node, each node expanded once. ``transitive=False`` stops at
    depth 1 (direct callers).
    """
    depth_cap = 1 if not transitive else max(1, min(
        max_depth, CALLS_MAX_DEPTH_CAP,
    ))
    reverse: dict[str, set[str]] = {}
    for caller, callee_set in graph.callees.items():
        for callee in callee_set:
            reverse.setdefault(callee, set()).add(caller)
            base = symbol_base_name(callee)
            if base != callee:
                reverse.setdefault(base, set()).add(caller)
    result: dict[str, int] = {}
    skip = {target, symbol_base_name(target)}
    frontier = [target]
    depth = 0
    while frontier and depth < depth_cap:
        depth += 1
        next_frontier: list[str] = []
        for current in frontier:
            for cand in {current, symbol_base_name(current)}:
                for caller in reverse.get(cand, ()):
                    if caller in skip or caller in result:
                        continue
                    result[caller] = depth
                    next_frontier.append(caller)
        frontier = next_frontier
    return result


def run_calls_hunt(
    run_dir: Path,
    calls: str,
    *,
    and_not_calls: str | None = None,
    transitive: bool = False,
    max_depth: int | None = None,
    graph_loader: "Callable[[Path, BinaryManifest], CallGraph] | None" = None,
) -> dict[str, Any]:
    """callers(X), optionally minus callers(Y), over the best
    available substrate.

    ``--calls X --and-not-calls Y`` answers the chokepoint question:
    which callers of X never (transitively) reach Y — e.g. which
    parser entry points skip the shared validator. The residual is a
    HYPOTHESIS-tier review queue; honesty lines ride both directions
    (see _CALLS_ABSENCE_NOTE / _CALLS_PRESENCE_NOTE).
    """
    run_dir = Path(run_dir)
    manifest = _load_manifest(run_dir)
    loader = graph_loader or load_call_graph
    graph = loader(run_dir, manifest)

    depth = (CALLS_MAX_DEPTH_DEFAULT if max_depth is None
             else max(1, min(max_depth, CALLS_MAX_DEPTH_CAP)))
    depth_clamped = max_depth is not None and max_depth != depth
    misses: list[dict[str, Any]] = []
    target = _resolve_call_query(calls, graph, misses)
    exclude_target: str | None = None
    if target is not None and and_not_calls is not None:
        exclude_target = _resolve_call_query(and_not_calls, graph, misses)
    if misses:
        record_fid_misses(run_dir, "binary-hunt-calls", misses)
    if target is None:
        msg = (
            f"--calls target not found in the "
            f"{graph.substrate}: {escape_nonprintable(calls)}"
        )
        raise HuntError(msg)
    if and_not_calls is not None and exclude_target is None:
        msg = (
            f"--and-not-calls target not found in the "
            f"{graph.substrate}: {escape_nonprintable(and_not_calls)}"
        )
        raise HuntError(msg)

    callers_x = callers_of(
        graph, target, transitive=transitive, max_depth=depth,
    )
    residual: dict[str, int] | None = None
    degenerate_note: str | None = None
    if exclude_target is not None:
        if exclude_target == target:
            residual = {}
            degenerate_note = (
                "--calls and --and-not-calls resolve to the same "
                "function; the residual is empty by construction and "
                "says nothing about the binary."
            )
        else:
            callers_y = callers_of(
                graph, exclude_target,
                transitive=transitive, max_depth=depth,
            )
            residual = {
                name: hops for name, hops in callers_x.items()
                if name not in callers_y
            }

    def _entries(caller_map: dict[str, int]) -> list[dict[str, Any]]:
        ordered = sorted(
            caller_map.items(), key=lambda item: (item[1], item[0]),
        )
        entries: list[dict[str, Any]] = []
        for name, hops in ordered[:MAX_CALLERS_REPORTED]:
            info = graph.meta.get(name) or {}
            entry: dict[str, Any] = {
                "name": escape_nonprintable(name),
                "depth": hops,
            }
            address = info.get("address")
            if isinstance(address, int):
                entry["address"] = hex(address)
            if info.get("fid"):
                entry["fid"] = info["fid"]
            if info.get("size"):
                entry["size"] = int(info["size"])
            entries.append(entry)
        return entries

    evidence: list[BinaryEvidenceRecord] = []
    callers_record = make_evidence(
        manifest.binary_sha256,
        kind="hunt_callers",
        source=graph.substrate,
        summary=(
            f"{len(callers_x)} caller(s) of "
            f"{escape_nonprintable(target)} within {depth} hop(s)"
            if transitive else
            f"{len(callers_x)} direct caller(s) of "
            f"{escape_nonprintable(target)}"
        ),
        tier=EvidenceTier.XREF_BACKED,
        confidence="candidate",
        reproducible=True,
        tool="binary-hunt",
        location=manifest.binary_path,
        data={"target": escape_nonprintable(target)},
    )
    evidence.append(callers_record)

    payload: dict[str, Any] = {
        "schema_version": 1,
        "mode": "calls",
        "binary": manifest.binary_path,
        "binary_sha256": manifest.binary_sha256,
        "query": {
            # Operator-typed, echoed escaped — the echo convention
            # must not depend on who typed the value.
            "calls": escape_nonprintable(calls),
            "and_not_calls": (escape_nonprintable(and_not_calls)
                              if and_not_calls is not None else None),
            "resolved_calls": escape_nonprintable(target),
            "resolved_and_not_calls": (
                escape_nonprintable(exclude_target)
                if exclude_target is not None else None
            ),
            "transitive": bool(transitive),
            "max_depth": depth if transitive else 1,
        },
        "substrate": graph.substrate,
        # Substrate notes quote tool/degradation text — escaped like
        # every externally-influenced string in this artifact.
        "substrate_notes": [
            escape_nonprintable(str(note)) for note in graph.notes
        ],
        "callers": _entries(callers_x),
        "caller_count": len(callers_x),
        "claim": "structural_lead_only",
        "honesty": [_CALLS_ABSENCE_NOTE, _CALLS_PRESENCE_NOTE],
        "evidence": [],
    }
    truncation_lines: list[str] = []
    if depth_clamped:
        truncation_lines.append(
            f"--max-depth {max_depth} clamped to the transitive depth "
            f"bound ({depth})",
        )
    if len(callers_x) > MAX_CALLERS_REPORTED:
        truncation_lines.append(
            f"callers capped at {MAX_CALLERS_REPORTED} of "
            f"{len(callers_x)}; kept nearest-first",
        )
    if residual is not None:
        residual_record = make_evidence(
            manifest.binary_sha256,
            kind="hunt_chokepoint_residual",
            source=graph.substrate,
            summary=(
                f"{len(residual)} caller(s) of "
                f"{escape_nonprintable(target)} with no "
                f"{'transitive ' if transitive else ''}call edge to "
                f"{escape_nonprintable(exclude_target or '')}"
            ),
            # Hypothesis tier: the residual CLAIM rests on edge
            # absence, which the substrate cannot prove.
            tier=EvidenceTier.HEURISTIC,
            confidence="hypothesis",
            reproducible=True,
            tool="binary-hunt",
            location=manifest.binary_path,
            data={
                "target": escape_nonprintable(target),
                "exclude": escape_nonprintable(exclude_target or ""),
            },
        )
        evidence.append(residual_record)
        payload["residual"] = {
            "kind": "HUNT_CHOKEPOINT_RESIDUAL",
            "entries": _entries(residual),
            "count": len(residual),
            "confidence": "hypothesis",
            "evidence_tier": EvidenceTier.HEURISTIC.value,
            "evidence_note": _CALLS_ABSENCE_NOTE,
            "evidence_ids": [residual_record.id],
        }
        if len(residual) > MAX_CALLERS_REPORTED:
            truncation_lines.append(
                f"residual capped at {MAX_CALLERS_REPORTED} of "
                f"{len(residual)}; kept nearest-first",
            )
        if not residual:
            payload["residual"]["empty_note"] = (
                ("Empty residual: " + degenerate_note)
                if degenerate_note else
                "Empty residual: every observed caller has an edge "
                "to the excluded function. " + _CALLS_PRESENCE_NOTE
            )
    payload["truncation_lines"] = truncation_lines
    payload["evidence"] = [record.to_dict() for record in evidence]

    slug_target = symbol_base_name(target)
    slug = f"calls-{_slug(slug_target)}"
    if exclude_target is not None:
        slug += f"-not-{_slug(symbol_base_name(exclude_target))}"
    artifact = _write_hunt_artifacts(run_dir, payload, slug_hint=slug)
    _ingest_calls_graph(run_dir, manifest, payload, evidence)
    payload["artifacts"] = artifact
    return payload


def _ingest_calls_graph(
    run_dir: Path,
    manifest: BinaryManifest,
    payload: dict[str, Any],
    evidence: list[BinaryEvidenceRecord],
) -> None:
    residual = payload.get("residual")
    if not isinstance(residual, dict):
        return
    graph_path = graph_path_for_run(run_dir)
    with BinaryGraphStore(graph_path) as store, store.batch():
        snapshot_id = _hunt_snapshot(store, manifest, run_dir)
        for record in evidence:
            store.add_evidence(snapshot_id, record)
        query = payload.get("query") or {}
        key = (
            f"{query.get('resolved_calls')}::"
            f"{query.get('resolved_and_not_calls')}::"
            f"{query.get('max_depth')}"
        )
        residual_node = store.add_node(
            snapshot_id,
            manifest.binary_sha256,
            "hunt_chokepoint_residual",
            key,
            name=(
                f"callers({query.get('resolved_calls')}) minus "
                f"callers({query.get('resolved_and_not_calls')})"
            ),
            props={k: v for k, v in residual.items() if k != "entries"},
            evidence_ids=residual.get("evidence_ids") or [],
        )
        for entry in residual.get("entries") or []:
            addr = _parse_addr(entry.get("address"))
            node_key = (f"BFN-{addr:x}" if addr is not None
                        else str(entry.get("name") or ""))
            # add-if-absent: the residual references the MAP's
            # function nodes in the map's snapshot — a REPLACE here
            # wiped their map-owned props (see the anchor ingest).
            fn_node = store.add_node_if_absent(
                snapshot_id,
                manifest.binary_sha256,
                "function",
                node_key,
                name=str(entry.get("name") or ""),
                address=str(entry.get("address") or ""),
                props=entry,
            )
            store.add_edge(
                snapshot_id,
                manifest.binary_sha256,
                "HUNT_CHOKEPOINT_RESIDUAL",
                residual_node,
                fn_node,
                confidence="hypothesis",
                evidence_ids=residual.get("evidence_ids") or [],
            )
