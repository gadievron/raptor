"""Resource-bounds verification channel (CWE-770/400/772).

Adjudicates hypotheses of the shape *"peer-driven allocation or
collection insert with no bound check"* — the unbounded-accumulation
class (session caches that grow per connection, half-open lists with a
TODO admitting missing accounting). The LLM forms these hypotheses
readily; before this channel nothing adjudicated them and they died
suspicious-without-receipts.

A confirmation is the conjunction of three mechanically demonstrable
facts:

1. **Accumulation site** — an insert/append verb (merged vocabulary:
   channel-local seeds < linux_kernel pack ``collection_inserts`` <
   study-learned ``paired_operations`` entries of kind ``collection``)
   or an allocator called inside a loop.
2. **No bound witness** — no dominating guard at the site compares a
   count/size-classified identifier against a constant, a resolvable
   named limit (:mod:`core.audit.constant_resolution`), or a learned
   ``resource_limits`` entry; and no such guard dominates the call in
   any caller within the bounded reverse walk (depth ≤ 3).
3. **Grade** — vocabulary provenance splits the rule-id exactly like
   fail_open's ``-naming`` pattern: learned/pack/operator vocabulary
   AND entry-reachability ⇒ registry-grade
   ``resource_bounds:unbounded-accumulation`` (promote-capable);
   seed/name-stem-only vocabulary OR unknown reachability ⇒ the
   ``-naming`` detection variant (aggregation-only — unknown
   reachability never blocks, it caps; the escalator rule).

Honesty note: "no bound anywhere" is a negative claim — admission
control can live further up than the depth-3 caller walk. The receipt
therefore always records the searched caller set, and registry grade
additionally requires the entry-reachability escalator.

Verdicts: ``confirmed`` / ``refuted`` (bound witness receipt) /
``inconclusive`` with an enumerated reason. No LLM calls, no
subprocesses.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

RULE_UNBOUNDED = "resource_bounds:unbounded-accumulation"

# Detection-grade vocabulary (seed/name-stem only) or unknown
# reachability selects the -naming rule-id variant (may not promote
# alone; participates in channel aggregation).
DETECTION_VARIANT_SUFFIX = "-naming"

# CWE families the channel joins via the fallback chain.
RESOURCE_BOUNDS_CWES = frozenset({"CWE-770", "CWE-400", "CWE-772"})

# Enumerated inconclusive reasons (each a distinct tested string).
REASON_VOCAB_UNBOUND = "vocab-unbound"
REASON_GUARD_UNDECIDED = "guard-undecided"
REASON_CENSUS_DEGRADED = "census-degraded"
REASON_LANGUAGE_UNSUPPORTED = "language-unsupported"
REASON_HYPOTHESIS_UNBINDABLE = "hypothesis-unbindable"

INCONCLUSIVE_REASONS = frozenset({
    REASON_VOCAB_UNBOUND,
    REASON_GUARD_UNDECIDED,
    REASON_CENSUS_DEGRADED,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_HYPOTHESIS_UNBINDABLE,
})

# SEED SETS — canonical exemplars only (SEED_SET_CAP discipline, the
# callback_lifetime rule verbatim). The kernel bulk lives in the
# linux_kernel vocab pack's collection_inserts / collection_removes
# keys; project insert/remove verbs arrive via study-learned
# paired_operations entries of kind "collection". Do not grow these
# tuples — teach the study loop / pack instead.
_SEED_INSERT_NAMES = (
    "list_add", "list_add_tail", "sk_push", "queue", "enqueue",
    "append", "insert", "push_back",
)

_SEED_ALLOC_NAMES = (
    "malloc", "calloc", "realloc", "kmalloc", "kzalloc",
    "OPENSSL_malloc",
)

# Reverse caller walk bounds (the api_boundary call-site pattern).
_CALLER_MAX_DEPTH = 3
_CALLER_MAX_VISITED = 200
_MAX_SCAN_FILES = 40
_MAX_FILE_BYTES = 400_000
_SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp")

# Prepass caps (§1.6): CFG+dominators built only for candidates.
MAX_PREPASS_CANDIDATES = 150
PREPASS_BUDGET_S = 30.0
MAX_PREPASS_FINDINGS = 50

# Hypothesis shapes asserting an unbounded allocation / accumulation.
_RESOURCE_BOUNDS_HYPOTHESIS_RE = re.compile(
    r"(?:\bunbounded"
    r"|without\s+(?:a\s+)?(?:bound|limit|cap)"
    r"|no\s+(?:upper\s+)?(?:bound|limit|cap)"
    r"|grows?\s+without"
    r"|memory\s+exhaustion"
    r"|resource\s+exhaustion"
    r"|backpressure"
    r"|unlimited.{0,20}(?:alloc|insert|append|queue|list|connections?))",
    re.IGNORECASE | re.DOTALL,
)

# Count/size-classified identifier stems (the condition_binding
# name-stem convention) — one side of a bound witness.
_COUNTISH_RE = re.compile(
    r"(?:^|_)(?:count|cnt|num|n|len|length|size|sz|depth|used|"
    r"entries|total|pending|queued|sessions|active|outstanding)"
    r"(?:_|$)",
    re.IGNORECASE,
)

# Named-limit stems — the other side of a bound witness when the
# constant table cannot resolve the name.
_LIMITISH_RE = re.compile(
    r"(?:^|_)(?:max|limit|cap|quota|thresh|threshold|bound|budget)"
    r"(?:_|$)|^MAX_|_MAX$",
    re.IGNORECASE,
)

_BACKTICK_IDENT_RE = re.compile(r"`([A-Za-z_][\w.]*)\s*(?:\(\s*\))?`")
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w{2,})\b")
_CMP_RE = re.compile(
    r"([A-Za-z_]\w*(?:(?:->|\.)\w+)*)\s*(<=|>=|==|<|>)\s*"
    r"([A-Za-z_]\w*(?:(?:->|\.)\w+)*|\d+)",
)
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(")

_HYPOTHESIS_STOPWORDS = frozenset({
    "the", "and", "for", "not", "with", "when", "without", "bound",
    "limit", "cap", "check", "grows", "into", "list", "queue",
    "unbounded", "memory", "resource", "exhaustion", "attacker",
    "peer", "int", "void", "char", "this", "that", "insert",
    "inserted", "append", "appended", "alloc", "allocation",
    "allocated", "each", "every", "connection", "connections",
    "request", "backpressure", "unlimited", "upper", "session",
    "sessions", "entry", "added",
})


def is_resource_bounds_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts an unbounded allocation /
    accumulation shape (grows without limit, memory exhaustion, no
    backpressure)."""
    return bool(text) and bool(_RESOURCE_BOUNDS_HYPOTHESIS_RE.search(text))


def resource_bounds_applicable(cwe: str) -> bool:
    """True when the CWE belongs to the resource-bounds family."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in RESOURCE_BOUNDS_CWES


def is_detection_rule_id(rule_id: str) -> bool:
    """True for the detection-grade rule-id variants: they may not
    promote alone, only aggregate across independent namespaces."""
    return rule_id.startswith("resource_bounds:") and rule_id.endswith(
        DETECTION_VARIANT_SUFFIX,
    )


def seed_budget_violations() -> list[str]:
    """Vocabulary-policy lint (mirrors
    ``fail_open_roles.registry_budget_violations``): channel seed
    tuples stay within ``SEED_SET_CAP``."""
    from .fail_open_roles import SEED_SET_CAP
    violations: list[str] = []
    for name, seeds in (
        ("_SEED_INSERT_NAMES", _SEED_INSERT_NAMES),
        ("_SEED_ALLOC_NAMES", _SEED_ALLOC_NAMES),
    ):
        if len(seeds) > SEED_SET_CAP:
            violations.append(
                f"resource_bounds.{name} has {len(seeds)} entries "
                f"(cap {SEED_SET_CAP}) — teach the study loop / pack "
                "instead",
            )
    return violations


@dataclass
class BoundEvidence:
    """Aggregate channel verdict for one resource-bounds hypothesis."""

    outcome: str                 # confirmed | refuted | inconclusive
    reason: str
    rule_id: str = RULE_UNBOUNDED
    resource: dict[str, Any] | None = None
    site: dict[str, Any] | None = None
    bound_search: dict[str, Any] | None = None
    reachability: dict[str, Any] | None = None
    # Structured receipt dicts (PeerEvidence.to_dict()) and plain tool
    # stamps both slot in — the fail_open corroboration convention.
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
        }
        if self.resource is not None:
            d["resource"] = self.resource
        if self.site is not None:
            d["site"] = self.site
        if self.bound_search is not None:
            d["bound_search"] = self.bound_search
        if self.reachability is not None:
            d["reachability"] = self.reachability
        if self.corroboration:
            d["corroboration"] = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in self.corroboration
            ]
        return d


def _inconclusive(reason: str, detail: str = "") -> BoundEvidence:
    return BoundEvidence(
        outcome="inconclusive",
        reason=f"{reason}: {detail}" if detail else reason,
    )


# ── vocabulary (seeds < pack < learned) ─────────────────────────────


def _pack_collection_verbs(
    target_path: Path | None,
) -> tuple[frozenset[str], frozenset[str]]:
    """Channel-local read of the vocab pack's ``collection_inserts`` /
    ``collection_removes`` keys (data-file-only extension — the pack
    loader tolerates unknown keys and DomainVocabulary carries no
    collection classes by design)."""
    if target_path is None:
        return frozenset(), frozenset()
    try:
        from .vocab_packs import _PACK_DIR, is_kernel_tree
        if not is_kernel_tree(target_path):
            return frozenset(), frozenset()
        raw = json.loads(
            (_PACK_DIR / "linux_kernel.json").read_text(encoding="utf-8"),
        )
    except Exception:
        return frozenset(), frozenset()

    def _names(key: str) -> frozenset[str]:
        vals = raw.get(key) or []
        return frozenset(n for n in vals if isinstance(n, str) and n)

    return _names("collection_inserts"), _names("collection_removes")


def learned_collection_pairs(
    domain_model: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Insert/remove pairs from study-learned ``paired_operations``
    entries of kind ``collection`` (acquire = insert verb, release =
    remove verb), parsed channel-locally — the
    ``consistency_dimensions.learned_cleanup_pairs`` precedent, no
    DomainVocabulary schema edit. ``llm_prior`` provenance is excluded
    (the DomainVocabulary anti-laundering rule)."""
    pairs: list[dict[str, str]] = []
    for entry in (domain_model or {}).get("paired_operations") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("kind") or "").lower() != "collection":
            continue
        if str(entry.get("provenance") or "") == "llm_prior":
            continue
        insert = str(entry.get("acquire") or "").split("(")[0].strip()
        remove = str(entry.get("release") or "").split("(")[0].strip()
        if not insert:
            continue
        pairs.append({
            "insert": insert,
            "remove": remove,
            "provenance": str(entry.get("provenance") or "domain_model"),
        })
    return pairs


def learned_resource_limits(
    domain_model: dict[str, Any] | None,
) -> frozenset[str]:
    """Names from the optional ``resource_limits`` domain-model key
    ({field_or_macro, applies_to, provenance}) — strengthen
    bound-witness classification. Parsed channel-locally."""
    names: set[str] = set()
    for entry in (domain_model or {}).get("resource_limits") or []:
        if isinstance(entry, dict):
            name = str(entry.get("field_or_macro") or "").strip()
            if name and str(entry.get("provenance") or "") != "llm_prior":
                names.add(name)
        elif isinstance(entry, str) and entry:
            names.add(entry)
    return frozenset(names)


def _insert_vocabulary(
    domain_model: dict[str, Any] | None,
    target_path: Path | None,
) -> dict[str, tuple[str, str]]:
    """Merged insert verbs → ``(vocab_source, provenance)``.
    Precedence learned > pack > seed on collision (registry sources
    win the grade)."""
    vocab: dict[str, tuple[str, str]] = dict.fromkeys(_SEED_INSERT_NAMES, ("seed", "seed"))
    pack_inserts, _ = _pack_collection_verbs(target_path)
    for name in pack_inserts:
        vocab[name] = ("pack", "linux_kernel")
    for pair in learned_collection_pairs(domain_model):
        vocab[pair["insert"]] = ("learned", pair["provenance"])
    return vocab


def _alloc_vocabulary(
    domain_model: dict[str, Any] | None,
) -> dict[str, tuple[str, str]]:
    """Merged allocator verbs: seeds plus learned ``alloc`` pairs."""
    vocab: dict[str, tuple[str, str]] = dict.fromkeys(_SEED_ALLOC_NAMES, ("seed", "seed"))
    for entry in (domain_model or {}).get("paired_operations") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("kind") or "").lower() != "alloc":
            continue
        if str(entry.get("provenance") or "") == "llm_prior":
            continue
        name = str(entry.get("acquire") or "").split("(")[0].strip()
        if name:
            vocab[name] = (
                "learned", str(entry.get("provenance") or "domain_model"),
            )
    return vocab


# Registry-grade vocabulary sources (the fail_open grade rule:
# learned pair / pack / operator annotation; seeds and name stems are
# detection-grade).
_REGISTRY_VOCAB_SOURCES = frozenset({"learned", "pack", "annotation"})


# ── site enumeration ────────────────────────────────────────────────


@dataclass(frozen=True)
class _Site:
    line: int              # 1-based, file-absolute
    code: str
    verb: str
    kind: str               # "insert" | "alloc_in_loop"
    vocab_source: str
    provenance: str


def _call_re(names: tuple[str, ...] | frozenset[str]) -> re.Pattern:
    alts = "|".join(
        re.escape(n) for n in sorted(names, key=len, reverse=True)
    )
    return re.compile(r"\b(" + alts + r")\s*\(")


# Naming-stem insert matching (detection grade only). Project
# collection APIs routinely embed the insert verb inside a longer
# identifier — OpenSSL's macro-generated
# ``ossl_list_<name>_insert_tail`` (DEFINE_LIST_OF_IMPL: the function
# has NO definition anywhere, so the study loop can never index it),
# glib's ``g_queue_push_tail``, etc. The exact-name vocabulary match
# cannot see these (the verb is word-internal), which left a real
# unbounded-accumulation site unbindable ("no accumulation site
# found") even though the channel dispatched fine. Same policy as
# lock_region's ``_STEM_LOCK_RE``: structural naming evidence binds a
# site at detection grade — ``_apply_grade`` routes non-registry
# sources to the ``-naming`` variant — never at registry grade. No
# target-specific names.
#
# Two tiers: strong verbs (insert/enqueue) bind on the verb alone;
# weak verbs (add/push/append) bind only when the identifier also
# names a collection — ``BN_add``-style arithmetic must not bind.
# The collection noun must be a whole snake_case segment: pre-fix the
# ``\w*`` wrappers matched SUBSTRINGS, so ``string_append`` bound via
# "ring", ``task_add``/``mask_add`` via "sk" and ``offset_add`` via
# "set" — exactly the arithmetic/bookkeeping class the weak-verb tier
# exists to exclude. Segment atoms are ``[A-Za-z0-9]+`` (no ``_``), so
# the quantifiers cannot backtrack across segment boundaries.
_STEM_INSERT_RE = re.compile(
    r"\b("
    r"\w+_(?:insert|enqueue)(?:_\w+)?"
    r"|(?:[A-Za-z0-9]+_)*"
    r"(?:list|queue|stack|ring|table|hash|set|vec|array|buf|heap|sk)"
    r"(?:_[A-Za-z0-9]+)*?_(?:add|push|append)(?:_\w+)?"
    r")\s*\(",
)

_STEM_VOCAB_SOURCE = "naming"
_STEM_PROVENANCE = "naming-stem"


def _loop_lines(lines: list[str], start: int) -> set[int]:
    """1-based (relative to *start*) line numbers inside a loop body —
    a brace-depth scan sufficient for the alloc-in-loop candidate
    filter (false negatives degrade to fewer candidates, never to a
    wrong verdict: the bound search still runs per site)."""
    in_loop: set[int] = set()
    loop_depths: list[int] = []
    depth = 0
    pending_loop = False
    for idx, raw in enumerate(lines):
        code = raw.split("//", 1)[0]
        if _LOOP_RE.search(code):
            pending_loop = True
        for ch in code:
            if ch == "{":
                depth += 1
                if pending_loop:
                    loop_depths.append(depth)
                    pending_loop = False
            elif ch == "}":
                if loop_depths and loop_depths[-1] == depth:
                    loop_depths.pop()
                depth -= 1
        if loop_depths:
            in_loop.add(start + idx)
    return in_loop


def _enumerate_sites(
    segment_lines: list[str],
    span_start: int,
    insert_vocab: dict[str, tuple[str, str]],
    alloc_vocab: dict[str, tuple[str, str]],
) -> list[_Site]:
    sites: list[_Site] = []
    insert_re = _call_re(tuple(insert_vocab)) if insert_vocab else None
    alloc_re = _call_re(tuple(alloc_vocab)) if alloc_vocab else None
    loop_set = _loop_lines(segment_lines, span_start)
    for idx, raw in enumerate(segment_lines):
        code = raw.split("//", 1)[0]
        line_no = span_start + idx
        if insert_re is not None:
            m = insert_re.search(code)
            if m:
                src, prov = insert_vocab[m.group(1)]
                sites.append(_Site(
                    line=line_no, code=raw.strip()[:200],
                    verb=m.group(1), kind="insert",
                    vocab_source=src, provenance=prov,
                ))
                continue
        sm = _STEM_INSERT_RE.search(code)
        if sm:
            sites.append(_Site(
                line=line_no, code=raw.strip()[:200],
                verb=sm.group(1), kind="insert",
                vocab_source=_STEM_VOCAB_SOURCE,
                provenance=_STEM_PROVENANCE,
            ))
            continue
        if alloc_re is not None and line_no in loop_set:
            m = alloc_re.search(code)
            if m:
                src, prov = alloc_vocab[m.group(1)]
                sites.append(_Site(
                    line=line_no, code=raw.strip()[:200],
                    verb=m.group(1), kind="alloc_in_loop",
                    vocab_source=src, provenance=prov,
                ))
    return sites


# ── bound-witness comparator ────────────────────────────────────────


def _name_tail(name: str) -> str:
    return re.split(r"->|\.", name)[-1]


def _classify_bound_guard(
    condition: str,
    constants: dict[str, int] | None,
    limit_names: frozenset[str],
) -> dict[str, Any] | None:
    """Classify one guard condition as a bound witness.

    A bound witness compares a count/size/len-classified identifier
    against a constant, a resolvable named limit, a limit-stem name,
    or a learned ``resource_limits`` entry. Returns the witness
    receipt, ``{"undecided": True, ...}`` when a count comparison
    exists but the bound side cannot be classified, or ``None`` when
    the condition is unrelated."""
    undecided: dict[str, Any] | None = None
    for m in _CMP_RE.finditer(condition):
        lhs, _op, rhs = m.group(1), m.group(2), m.group(3)
        for count_side, bound_side in ((lhs, rhs), (rhs, lhs)):
            tail = _name_tail(count_side)
            if not (
                _COUNTISH_RE.search(tail)
                or count_side in limit_names
                or tail in limit_names
            ):
                continue
            bound_tail = _name_tail(bound_side)
            if not bound_side.isdigit() and len(bound_tail) <= 2:
                # Loop-induction shape (`i < len`): not a bound and
                # not evidence of a bound attempt — skip entirely.
                continue
            if bound_side.isdigit():
                source = "integer-literal"
            elif bound_side in limit_names or bound_tail in limit_names:
                source = "resource_limits"
            elif constants and (
                bound_side in constants or bound_tail in constants
            ):
                source = "resolved-constant"
            elif _LIMITISH_RE.search(bound_tail):
                source = "limit-stem"
            else:
                undecided = {
                    "undecided": True,
                    "condition": condition[:200],
                    "count": count_side,
                }
                continue
            return {
                "condition": condition[:200],
                "count": count_side,
                "bound": bound_side,
                "bound_source": source,
            }
    return undecided


_CLAMP_RE = re.compile(
    r"\b(\w+)\s*=\s*(?:min|MIN)\s*\(\s*([^,()]+?)\s*,\s*([^()]+?)\s*\)",
)


def _clamp_witness(
    segment_lines: list[str],
    span_start: int,
    site_line: int,
    constants: dict[str, int] | None,
    limit_names: frozenset[str],
) -> dict[str, Any] | None:
    """``min(count, MAX)``-style clamp witness for alloc-in-loop
    sites: a loop header before the site iterates over a variable that
    was clamped against a classifiable limit. The receipt records both
    the clamp line and the loop header."""
    def _is_limit(expr: str) -> bool:
        expr = expr.strip()
        tail = _name_tail(expr)
        return bool(
            expr.isdigit()
            or expr in limit_names or tail in limit_names
            or (constants and (expr in constants or tail in constants))
            or _LIMITISH_RE.search(tail),
        )

    clamp_map: dict[str, dict[str, Any]] = {}
    for idx, raw in enumerate(segment_lines):
        line_no = span_start + idx
        if line_no >= site_line:
            break
        for m in _CLAMP_RE.finditer(raw.split("//", 1)[0]):
            var, a, b = m.group(1), m.group(2), m.group(3)
            for bound in (a, b):
                if _is_limit(bound):
                    clamp_map[var] = {
                        "clamp_line": line_no,
                        "bound": bound.strip(),
                        "code": raw.strip()[:200],
                    }
    if not clamp_map:
        return None
    # Nearest loop header before the site that mentions a clamped var.
    for idx in range(site_line - span_start - 1, -1, -1):
        code = segment_lines[idx].split("//", 1)[0]
        if not _LOOP_RE.search(code):
            continue
        for var, info in clamp_map.items():
            if re.search(rf"\b{re.escape(var)}\b", code):
                return {
                    "condition": code.strip()[:200],
                    "count": var,
                    "bound": info["bound"],
                    "bound_source": "clamp-min",
                    "clamp_line": info["clamp_line"],
                }
        break
    return None


@lru_cache(maxsize=128)
def _cfg_dom_cached(source: str, tail: str, language: str):
    """(cfg, dominator tree) per (source, function, language) —
    ``None`` when the function cannot be parsed into a CFG.

    _caller_bound_search asks for guards at many call sites inside
    the same caller, and the prepass adjudicates several sites per
    function: without this cache every site rebuilt the full CFG and
    dominator tree from scratch."""
    from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
    from core.analysis.dominators import build_dom_tree
    cfg = build_cpp_intraproc_cfg(source, tail, language=language)
    if cfg is None:
        return None
    return cfg, build_dom_tree(cfg)


def _guards_at(
    source: str,
    function_name: str,
    line: int,
    file_path: str,
    language: str,
) -> list[str] | None:
    """Dominating guard conditions at *line* via CFG + dominators
    (the lifecycle_collector path). ``None`` = CFG unavailable
    (tree-sitter grammar missing / function unparseable)."""
    try:
        from core.analysis.lifecycle_collector import collect_guards_at_site
    except ImportError:
        return None
    tail = function_name.rsplit(".", 1)[-1]
    try:
        pair = _cfg_dom_cached(source, tail, language)
    except ImportError:
        return None
    except Exception:
        logger.debug("resource_bounds: CFG build failed", exc_info=True)
        return None
    if pair is None:
        return None
    cfg, dom = pair
    try:
        guards = collect_guards_at_site(cfg, dom, line, file_path)
    except Exception:
        logger.debug("resource_bounds: guard collection failed",
                     exc_info=True)
        return None
    return [g.condition for g in guards]


def _c_function_spans(source: str) -> list[tuple[str, int, int]]:
    """Rough (name, start_line, end_line) spans of C function
    definitions — used only to attribute caller call sites to their
    enclosing function; misses degrade to a smaller searched set,
    which the receipt reports honestly."""
    spans: list[tuple[str, int, int]] = []
    lines = source.splitlines()
    header_re = re.compile(r"^[A-Za-z_][\w\s\*]*?\b(\w+)\s*\([^;{}]*\)\s*\{?\s*$")
    i = 0
    while i < len(lines):
        m = header_re.match(lines[i])
        if not m or lines[i].rstrip().endswith(";"):
            i += 1
            continue
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "return", "sizeof"):
            i += 1
            continue
        # Find the opening brace (same line or one of the next two).
        start = i
        depth = 0
        opened = False
        j = i
        while j < len(lines) and j <= i + 2 and not opened:
            if "{" in lines[j]:
                opened = True
                break
            j += 1
        if not opened:
            i += 1
            continue
        while j < len(lines):
            depth += lines[j].count("{") - lines[j].count("}")
            if opened and depth <= 0:
                break
            j += 1
        spans.append((name, start + 1, min(j + 1, len(lines))))
        i = j + 1
    return spans


def _gather_source_texts(
    target_path: Path, primary_file: str,
) -> dict[str, str]:
    texts: dict[str, str] = {}
    primary = target_path / primary_file
    if primary.is_file():
        try:
            texts[primary_file] = primary.read_text(errors="replace")
        except OSError:
            pass
    try:
        candidates = [
            p for p in sorted(target_path.rglob("*"))
            if p.is_file() and p.suffix in _SOURCE_SUFFIXES
        ]
    except OSError:
        return texts
    for p in candidates:
        if len(texts) >= _MAX_SCAN_FILES:
            break
        rel = str(p.relative_to(target_path))
        if rel in texts:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
            texts[rel] = p.read_text(errors="replace")
        except OSError:
            continue
    return texts


def _caller_bound_search(
    function_name: str,
    source_texts: dict[str, str],
    defining_file: str,
    constants: dict[str, int] | None,
    limit_names: frozenset[str],
    language: str,
    deadline: float | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Depth-bounded reverse walk: a dominating count guard in a
    caller before the call refutes (``bound-in-caller``). Returns
    ``(witness_receipt | None, per_caller_receipts)`` — the receipt
    list records how far the search went (the honesty requirement).
    *deadline* (``time.monotonic()`` epoch, ``None`` = unbounded)
    stops the walk early; the receipts stay honest about the smaller
    searched set."""
    per_caller: list[dict[str, Any]] = []
    spans_cache: dict[str, list[tuple[str, int, int]]] = {}

    def _spans(fp: str) -> list[tuple[str, int, int]]:
        if fp not in spans_cache:
            spans_cache[fp] = _c_function_spans(source_texts.get(fp, ""))
        return spans_cache[fp]

    frontier = {function_name.rsplit(".", 1)[-1]}
    visited: set[str] = set(frontier)
    for depth in range(1, _CALLER_MAX_DEPTH + 1):
        next_frontier: set[str] = set()
        for callee in sorted(frontier):
            call_re = re.compile(rf"\b{re.escape(callee)}\s*\(")
            for fp, source in source_texts.items():
                if deadline is not None and \
                        time.monotonic() > deadline:
                    return None, per_caller
                if callee not in source:
                    continue
                for m_line, raw in enumerate(
                    source.splitlines(), start=1,
                ):
                    if not call_re.search(raw.split("//", 1)[0]):
                        continue
                    enclosing = next(
                        (
                            (n, s, e) for n, s, e in _spans(fp)
                            if s <= m_line <= e and n != callee
                        ),
                        None,
                    )
                    if enclosing is None:
                        continue
                    caller_name = enclosing[0]
                    if (
                        fp == defining_file
                        and caller_name == callee
                    ):
                        continue
                    guards = _guards_at(
                        source, caller_name, m_line, fp, language,
                    )
                    receipt: dict[str, Any] = {
                        "caller": caller_name,
                        "file": fp,
                        "line": m_line,
                        "depth": depth,
                        "guards_scanned": len(guards or []),
                    }
                    if guards:
                        for cond in guards:
                            witness = _classify_bound_guard(
                                cond, constants, limit_names,
                            )
                            if witness and not witness.get("undecided"):
                                receipt["bound"] = witness
                                per_caller.append(receipt)
                                return witness, per_caller
                    per_caller.append(receipt)
                    if (
                        caller_name not in visited
                        and len(visited) < _CALLER_MAX_VISITED
                    ):
                        visited.add(caller_name)
                        next_frontier.add(caller_name)
        frontier = next_frontier
        if not frontier:
            break
    return None, per_caller


# ── verdict assembly ────────────────────────────────────────────────


def _entry_reachability(
    context: Any,
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    """Outcome-gated escalator, identical to the fail-open channel's
    (imported read-only, the consistency_verify precedent)."""
    try:
        from .fail_open_verify import _entry_reachability as _fo_reach
    except ImportError:
        return None
    try:
        return _fo_reach(context, inventory, file_path, function_name)
    except Exception:
        logger.debug("resource_bounds: reachability escalator failed",
                     exc_info=True)
        return None


def _apply_grade(
    vocab_source: str, reachability: dict[str, Any] | None,
) -> str:
    """Grade split (§1.3): registry rule-id only for registry-grade
    vocabulary AND demonstrated entry reachability; everything else
    confirms under the -naming detection variant (absence never
    blocks — it caps)."""
    registry_vocab = vocab_source in _REGISTRY_VOCAB_SOURCES
    entry_reachable = (
        (reachability or {}).get("status") == "entry_reachable"
    )
    if registry_vocab and entry_reachable:
        return RULE_UNBOUNDED
    return RULE_UNBOUNDED + DETECTION_VARIANT_SUFFIX


def _adjudicate_site(
    site: _Site,
    source: str,
    file_path: str,
    function_name: str,
    language: str,
    *,
    segment_lines: list[str] | None = None,
    span_start: int = 1,
    source_texts: dict[str, str] | None,
    constants: dict[str, int] | None,
    limit_names: frozenset[str],
    collection_pairs: list[dict[str, str]],
    context: Any,
    inventory: dict[str, Any] | None,
    deadline: float | None = None,
) -> BoundEvidence:
    """The bound-witness comparator for one accumulation site."""
    resource = {
        "verb": site.verb,
        "kind": site.kind,
        "vocab_source": site.vocab_source,
        "provenance": site.provenance,
    }
    site_receipt = {
        "file": file_path,
        "line": site.line,
        "function": function_name,
        "code": site.code,
    }

    # 1. Local dominating bound.
    guards = _guards_at(source, function_name, site.line, file_path,
                        language)
    if guards is None:
        return _inconclusive(
            REASON_CENSUS_DEGRADED,
            "CFG/dominators unavailable for the insert site — a "
            "no-bound claim must not confirm without the guard walk",
        )
    undecided_guard: dict[str, Any] | None = None
    local_witness: dict[str, Any] | None = None
    for cond in guards:
        witness = _classify_bound_guard(cond, constants, limit_names)
        if witness is None:
            continue
        if witness.get("undecided"):
            undecided_guard = witness
            continue
        local_witness = witness
        break

    bound_search: dict[str, Any] = {
        "local": local_witness,
        "local_guards_scanned": len(guards),
        "callers": [],
        "removal_pair": None,
    }

    if local_witness is None and site.kind == "alloc_in_loop" \
            and segment_lines is not None:
        clamp = _clamp_witness(
            segment_lines, span_start, site.line, constants,
            limit_names,
        )
        if clamp is not None:
            bound_search["local"] = clamp
            local_witness = clamp

    if local_witness is not None:
        return BoundEvidence(
            outcome="refuted",
            reason=(
                f"dominating bound witness at {file_path}:{site.line} "
                f"— `{local_witness['condition']}` compares "
                f"{local_witness['count']} against "
                f"{local_witness['bound']} "
                f"({local_witness['bound_source']})"
            ),
            resource=resource,
            site=site_receipt,
            bound_search=bound_search,
        )

    # 2. Caller-side bound (bounded reverse walk, depth ≤ 3).
    texts = source_texts or {file_path: source}
    caller_witness, per_caller = _caller_bound_search(
        function_name, texts, file_path, constants, limit_names,
        language, deadline=deadline,
    )
    bound_search["callers"] = per_caller
    if caller_witness is not None:
        return BoundEvidence(
            outcome="refuted",
            reason=(
                f"bound-in-caller: `{caller_witness['condition']}` "
                f"dominates the call chain to {function_name} "
                f"({caller_witness['bound_source']}); searched "
                f"{len(per_caller)} caller site(s), depth ≤ "
                f"{_CALLER_MAX_DEPTH}"
            ),
            resource=resource,
            site=site_receipt,
            bound_search=bound_search,
        )

    if undecided_guard is not None:
        return BoundEvidence(
            outcome="inconclusive",
            reason=(
                f"{REASON_GUARD_UNDECIDED}: a dominating guard "
                f"compares {undecided_guard['count']} but the bound "
                f"side could not be classified "
                f"(`{undecided_guard['condition']}`)"
            ),
            resource=resource,
            site=site_receipt,
            bound_search=bound_search,
        )

    # 3. Removal-path parity — corroboration only, never standalone.
    for pair in collection_pairs:
        if pair["insert"] != site.verb or not pair["remove"]:
            continue
        remove_re = _call_re((pair["remove"],))
        removed_somewhere = any(
            remove_re.search(text) for text in texts.values()
        )
        bound_search["removal_pair"] = {
            "insert": pair["insert"],
            "remove": pair["remove"],
            "remove_present": removed_somewhere,
        }
        if not removed_somewhere:
            site_note = {
                "kind": "removal-parity",
                "detail": (
                    f"paired remove verb {pair['remove']} absent from "
                    f"the scanned source set"
                ),
            }
        else:
            site_note = None
        if site_note:
            # Attach as corroboration on the eventual confirmation.
            bound_search["removal_pair"]["corroborates"] = True
        break

    # 4. Neither bound found ⇒ confirmed; grade via the escalator.
    reachability = _entry_reachability(
        context, inventory, file_path, function_name,
    )
    rule_id = _apply_grade(site.vocab_source, reachability)
    searched = sorted({c["caller"] for c in per_caller}) or ["<none>"]
    result = BoundEvidence(
        outcome="confirmed",
        reason=(
            f"{site.verb} at {file_path}:{site.line} accumulates with "
            f"no dominating bound witness in {function_name} "
            f"({len(guards)} local guard(s) scanned) and none in the "
            f"searched callers ({', '.join(searched[:6])}; depth ≤ "
            f"{_CALLER_MAX_DEPTH}) — admission control above that "
            "scope would not be seen"
        ),
        rule_id=rule_id,
        resource=resource,
        site=site_receipt,
        bound_search=bound_search,
        reachability=reachability,
    )
    removal = bound_search.get("removal_pair") or {}
    if removal.get("corroborates"):
        result.corroboration.append({
            "kind": "removal-parity",
            "detail": (
                f"insert verb {removal['insert']} has learned remove "
                f"pair {removal['remove']} absent from every scanned "
                "path"
            ),
        })
    return result


# ── channel entry points ────────────────────────────────────────────


def _candidate_verbs_from_hypothesis(
    hypothesis: str, segment: str,
) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for m in _BACKTICK_IDENT_RE.finditer(hypothesis):
        name = m.group(1).rstrip("(")
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    for m in _IDENT_RE.finditer(hypothesis):
        name = m.group(1)
        if name.lower() in _HYPOTHESIS_STOPWORDS or name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return [
        n for n in ordered
        if re.search(
            rf"\b{re.escape(n.rsplit('.', 1)[-1])}\s*\(", segment,
        )
    ]


def run_resource_bounds_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    domain_model: dict[str, Any] | None = None,
    source_texts: dict[str, str] | None = None,
    budget_s: float | None = None,
) -> BoundEvidence:
    """Adjudicate one resource-bounds hypothesis. See module docstring
    for verdict semantics. ``budget_s`` is accepted for signature
    stability (the phase-2 Joern cross-file leg's clamp)."""
    del budget_s  # phase-2 Joern leg parameter
    try:
        from .fail_open_lang import language_for_path
        language = language_for_path(file_path)
    except ImportError:
        language = None
    if language not in ("c", "cpp"):
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            f"no phase-1 resource-bounds analyzer for "
            f"{language or Path(file_path).suffix or 'unknown'}",
        )

    if source_texts is None:
        source_texts = _gather_source_texts(Path(target_path), file_path)
    source = source_texts.get(file_path)
    if source is None:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE, f"could not read {file_path}",
        )

    try:
        from .fail_open_lang import c_function_span
        span = c_function_span(source, function_name, language=language)
    except ImportError:
        span = None
    lines = source.splitlines()
    if span:
        segment_lines = lines[span[0] - 1:span[1]]
        span_start = span[0]
    else:
        segment_lines = lines
        span_start = 1
    segment = "\n".join(segment_lines)

    insert_vocab = _insert_vocabulary(domain_model, Path(target_path))
    alloc_vocab = _alloc_vocabulary(domain_model)
    sites = _enumerate_sites(
        segment_lines, span_start, insert_vocab, alloc_vocab,
    )

    if not sites:
        named = _candidate_verbs_from_hypothesis(hypothesis, segment)
        if named:
            return _inconclusive(
                REASON_VOCAB_UNBOUND,
                f"hypothesis names {', '.join(named[:4])} but no "
                "insert/alloc vocabulary (seed, pack, or learned "
                "collection pair) binds to it — teach the study loop",
            )
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no accumulation site found in {function_name}",
        )

    constants: dict[str, int] | None = None
    try:
        if Path(target_path).is_dir():
            from .constant_resolution import build_unique_constants
            constants = build_unique_constants(
                Path(target_path),
            ).as_int_dict()
    except Exception:
        logger.debug("resource_bounds: constant table failed",
                     exc_info=True)
    limit_names = learned_resource_limits(domain_model)
    collection_pairs = learned_collection_pairs(domain_model)

    best: BoundEvidence | None = None
    for site in sites:
        res = _adjudicate_site(
            site, source, file_path, function_name, language,
            segment_lines=segment_lines,
            span_start=span_start,
            source_texts=source_texts,
            constants=constants,
            limit_names=limit_names,
            collection_pairs=collection_pairs,
            context=context,
            inventory=inventory,
        )
        if res.outcome == "confirmed":
            return res
        if best is None or (
            best.outcome == "inconclusive" and res.outcome == "refuted"
        ):
            best = res
    return best if best is not None else _inconclusive(
        REASON_HYPOTHESIS_UNBINDABLE,
        f"no adjudicable site in {function_name}",
    )


def run_resource_bounds_prepass(
    source_texts: dict[str, str],
    *,
    target_path: Path | None = None,
    out_dir: Path | None = None,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    domain_model: dict[str, Any] | None = None,
    budget_s: float = PREPASS_BUDGET_S,
) -> dict[str, Any]:
    """Standing pre-pass (dual mode, the consistency pattern): sweep
    the source set for accumulation sites, adjudicate each through the
    bound-witness comparator, and return ``{findings, leads,
    mechanical, telemetry}``. Budget/candidate caps per §1.6."""
    t0 = time.monotonic()
    telemetry: dict[str, Any] = {
        "channel": "resource_bounds",
        "confirmed": 0, "refuted": 0, "inconclusive": 0,
        "candidates": 0, "budget_exceeded": False,
        "inconclusive_reasons": {},
    }
    findings: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    mechanical: list[dict[str, Any]] = []

    insert_vocab = _insert_vocabulary(domain_model, target_path)
    alloc_vocab = _alloc_vocabulary(domain_model)
    constants: dict[str, int] | None = None
    try:
        if target_path is not None and Path(target_path).is_dir():
            from .constant_resolution import build_unique_constants
            constants = build_unique_constants(
                Path(target_path),
            ).as_int_dict()
    except Exception:
        logger.debug("resource_bounds prepass: constant table failed",
                     exc_info=True)
    limit_names = learned_resource_limits(domain_model)
    collection_pairs = learned_collection_pairs(domain_model)
    insert_re = _call_re(tuple(insert_vocab)) if insert_vocab else None

    def _has_insert(text: str) -> bool:
        # Exact vocabulary OR naming-stem structural match — the stem
        # tier is what binds macro-generated project insert APIs the
        # study loop can never learn (no definition to index).
        if insert_re is not None and insert_re.search(text):
            return True
        return bool(_STEM_INSERT_RE.search(text))

    candidates: list[tuple[str, str, int, int]] = []
    lines_cache: dict[str, list[str]] = {}
    for fp, source in sorted(source_texts.items()):
        if not fp.endswith(_SOURCE_SUFFIXES):
            continue
        if not _has_insert(source):
            continue
        lines = lines_cache.setdefault(fp, source.splitlines())
        for name, start, end in _c_function_spans(source):
            segment = "\n".join(lines[start - 1:end])
            if _has_insert(segment):
                candidates.append((fp, name, start, end))
            if len(candidates) >= MAX_PREPASS_CANDIDATES:
                break
        if len(candidates) >= MAX_PREPASS_CANDIDATES:
            break
    telemetry["candidates"] = len(candidates)

    for fp, name, start, end in candidates:
        if time.monotonic() - t0 > budget_s:
            telemetry["budget_exceeded"] = True
            break
        source = source_texts[fp]
        lines = lines_cache.setdefault(fp, source.splitlines())
        segment_lines = lines[start - 1:end]
        sites = _enumerate_sites(
            segment_lines, start, insert_vocab, alloc_vocab,
        )
        # Language from the file's extension, not a hardcoded "c":
        # _SOURCE_SUFFIXES admits C++ files, and the C guard walk on
        # a .cpp file used to fail into census-degraded inconclusive.
        try:
            from .fail_open_lang import language_for_path
            lang = language_for_path(fp) or "c"
        except Exception:
            lang = "c"
        for site in sites[:2]:
            if time.monotonic() - t0 > budget_s:
                telemetry["budget_exceeded"] = True
                break
            res = _adjudicate_site(
                site, source, fp, name, lang,
                segment_lines=segment_lines,
                span_start=start,
                source_texts=source_texts,
                constants=constants,
                limit_names=limit_names,
                collection_pairs=collection_pairs,
                context=context,
                inventory=inventory,
                deadline=t0 + budget_s,
            )
            telemetry[res.outcome] = telemetry.get(res.outcome, 0) + 1
            if res.outcome == "inconclusive":
                key = res.reason.split(":", 1)[0]
                telemetry["inconclusive_reasons"][key] = (
                    telemetry["inconclusive_reasons"].get(key, 0) + 1
                )
                continue
            if res.outcome != "confirmed":
                continue
            detection = is_detection_rule_id(res.rule_id)
            status = (
                "finding"
                if not detection
                and (res.reachability or {}).get("status")
                == "entry_reachable"
                else "suspicious"
            )
            if len(findings) < MAX_PREPASS_FINDINGS:
                findings.append({
                    "file": fp,
                    "function": name,
                    "line": site.line,
                    "rule_id": res.rule_id,
                    "evidence_tool": res.rule_id,
                    "status": status,
                    "detection_grade": detection,
                    "cwe": "CWE-770",
                    "hypothesis": (
                        f"{site.verb} at {fp}:{site.line} accumulates "
                        f"per request with no bound check in scope"
                    ),
                    "description": res.reason,
                    "receipts": res.to_dict(),
                })
            mechanical.append({
                "file": fp,
                "function": name,
                "detector": "resource_bounds",
                "line": site.line,
                "description": res.reason,
                "callee": site.verb,
                "rule_id": res.rule_id,
                "cwe": "CWE-770",
            })
            leads.append({
                "channel": "resource_bounds",
                "file": fp,
                "function": name,
                "line": site.line,
                "rule_id": res.rule_id,
                "description": res.reason[:300],
                "mechanism": (
                    f"{site.verb} at {fp}:{site.line} inserts into a "
                    f"collection with no bound witness in "
                    f"{name} or its searched callers — unbounded "
                    "accumulation (CWE-770)"
                ),
            })

    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)
    if out_dir is not None and (findings or leads):
        try:
            path = Path(out_dir) / "resource-bounds.json"
            path.write_text(json.dumps(
                {"findings": findings, "leads": leads,
                 "telemetry": telemetry}, indent=1,
            ))
        except Exception:
            logger.debug("resource-bounds.json write failed",
                         exc_info=True)
    return {
        "findings": findings,
        "leads": leads,
        "mechanical": mechanical,
        "telemetry": telemetry,
    }
