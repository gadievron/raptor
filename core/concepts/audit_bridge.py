"""Bridge between /understand --study domain model and /audit.

Provides functions for /audit to consume domain-model.json:
- Load and cache the domain model
- Extract relevant concepts/invariants/contracts for a given function
- Format as a prompt block for LLM context injection
- Queue items to the reading list when audit encounters unknown constructs

Usage in audit context assembly:
    from core.concepts.audit_bridge import domain_model_context
    block = domain_model_context(out_dir, file_path, function_name, source)
    if block:
        ctx["domain_model"] = block
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from collections import OrderedDict
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

logger = logging.getLogger(__name__)

# Byte budget for domain-model / study-list documents.
_MAX_MODEL_BYTES = 64 * 1024 * 1024

# Cache bounds for the string-keyed derivation caches below. Every
# cached function is a pure function of its (hashable, content-bearing)
# arguments, so eviction can only cost recompute time, never
# correctness — the bounds are working-set caps in both directions:
# larger pins more dead strings/patterns for the process lifetime
# (grep hints and file paths ride LLM/target-derived domain models, so
# the bound also caps how much memory a hostile model can pin);
# smaller falls back toward the per-call recompute cost the caches
# exist to kill (a study model carries thousands of distinct paths and
# hints, ALL re-derived for EVERY function whose prompt slice is
# scored — the warm domain-slice fingerprint cost was ~0.27 s/function
# at a 7 MB model before these caches).
#
# The path bound must clear the model's DISTINCT path count, not just
# be "large": scoring cycles through every item's evidence/contract
# path per function, and an LRU cycled by a working set even slightly
# over its bound evicts each entry just before its next use (~0% hit
# rate — measured: a representative 7 MB model carries ~9.5k distinct
# paths, and a 4096 bound profiled the same as no cache at all).
_PATH_PARTS_CACHE_MAX = 16384
_PATTERN_CACHE_MAX = 2048
_NAME_VARIANTS_CACHE_MAX = 1024

_STOPWORDS = frozenset((
    "causes", "which", "would", "could", "should", "their",
    "these", "those", "where", "while", "after", "before",
    "about", "above", "below", "between", "through", "during",
    "other", "there", "every", "being", "having", "never",
))


@lru_cache(maxsize=_NAME_VARIANTS_CACHE_MAX)
def _name_variants(function_name: str) -> "tuple[str, ...]":
    """The function name plus its r2-undecorated form, when distinct.

    Binary audits key functions with r2 decoration (sym.main,
    sym.imp.strcpy, fcn.00401000) while binary-study models carry the
    bare Ghidra names. Matching considers BOTH forms — rewriting the
    name in place regressed source audits whose inventories
    legitimately produce dotted names (Lua Class.method, a source
    object named `sym`).

    Cached (pure function of the name): relevance scoring re-derives
    the variants once per (model item × function) pass.
    """
    for _pfx in ("sym.imp.", "sym.", "fcn.", "imp."):
        if (function_name.startswith(_pfx)
                and len(function_name) > len(_pfx)):
            # a name that IS a bare prefix would yield an empty
            # variant — and "" is a substring of everything (spurious
            # +5 on every item) and matches a contract with no
            # function key (KeyError swallowed into silent primer
            # loss)
            return (function_name, function_name[len(_pfx):])
    return (function_name,)


def _file_gate_applies(file_path: str) -> bool:
    """Whether the contract file-agreement gate can be evaluated.

    Binary audits key review items by the ``binary:`` pseudo-path
    (core.inventory.binary_builder.BINARY_PATH_PREFIX) while binary
    study models carry decompile-unit file names — the two shapes are
    incomparable, so the qualified-identity gate falls back to the
    name match there instead of dropping every contract.
    """
    from core.inventory.binary_builder import BINARY_PATH_PREFIX
    return bool(file_path) and not file_path.startswith(BINARY_PATH_PREFIX)


@lru_cache(maxsize=_PATH_PARTS_CACHE_MAX)
def _pp_parts(path: str) -> tuple[str, frozenset[str]]:
    """(basename, parent components) of *path*, POSIX semantics.

    Pure function of the path string — cached because relevance
    scoring compares every model item's file field against the
    function under review, constructing thousands of PurePosixPath
    objects per pass over a small set of distinct strings.
    """
    p = PurePosixPath(path)
    return p.name, frozenset(p.parts[:-1])


def _paths_match(a: str, b: str) -> bool:
    """Check if two paths refer to the same file (suffix-match on components).

    Handles relative vs absolute and different prefix depths:
    "crypto/algif_aead.c" matches "src/crypto/algif_aead.c".
    """
    if a == b:
        return True
    if a.endswith("/" + b) or b.endswith("/" + a):
        return True
    # Same basename + at least one shared parent component
    a_name, a_parents = _pp_parts(a)
    b_name, b_parents = _pp_parts(b)
    if a_name != b_name:
        return False
    return bool(a_parents & b_parents)


@lru_cache(maxsize=4)
def _load_cached(path: str) -> dict[str, Any] | None:
    """Load domain-model.json with caching (path as string for hashability).

    Cached for the process lifetime — safe because audit is single-shot
    and domain-model.json is not rewritten mid-run.
    """
    p = Path(path)
    if not p.is_file():
        return None
    from core.json import load_json
    return load_json(p, max_bytes=_MAX_MODEL_BYTES)


_per_run_warned: set[str] = set()


def _warn_per_run_once(path: str, *, in_project: bool) -> None:
    if path in _per_run_warned:
        return
    _per_run_warned.add(path)
    if in_project:
        logger.warning(
            "domain-model.json found at per-run location %s — cross-run "
            "staleness is disabled. Move to <project>/concepts/domain-"
            "model.json for cross-run hash comparison.",
            path,
        )
    else:
        # Standalone run (no project container): the per-run location
        # IS the documented fallback and there is no <project>/concepts/
        # to move it to — the "move it" advice is inapplicable, so
        # don't page the operator about working-as-designed behaviour.
        logger.info(
            "domain-model.json at per-run location %s (standalone run "
            "— cross-run staleness not applicable)",
            path,
        )


def _find_domain_model(out_dir: Path) -> dict[str, Any] | None:
    """Search for domain-model.json — amendment §3 canonical order.

    Search order (project-scoped canonical first, per-run last):
      1. ``<project>/concepts/domain-model.json`` — canonical.
         ``domain_model_hash`` in journal entries hashes this file
         so cross-run staleness works.
      2. ``<project>/domain-model.json`` — legacy compat.
      3. ``<out_dir>/domain-model.json`` — per-run fallback for
         standalone runs. **Disables cross-run staleness** — logs
         a WARNING so operators know.

    Removed under this amendment: sibling-run scan (previously
    ``find_sibling_run`` walked adjacent ``understand_*`` dirs). It
    undermined the stable-hash invariant Phase-5 depends on — the
    domain model hash could come from any random sibling.
    """
    project_concepts = out_dir.parent / "concepts" / "domain-model.json"
    project_root = out_dir.parent / "domain-model.json"
    per_run = out_dir / "domain-model.json"

    if project_concepts.is_file():
        return _load_cached(str(project_concepts.resolve()))
    if project_root.is_file():
        return _load_cached(str(project_root.resolve()))
    if per_run.is_file():
        # Project detection matches cmd_run's legacy-state check: a
        # project container carries raptor-project.json alongside its
        # runs. Standalone out/ dirs don't — for those the per-run
        # location is the documented fallback, not operator error.
        _warn_per_run_once(
            str(per_run),
            in_project=(out_dir.parent / "raptor-project.json").is_file(),
        )
        return _load_cached(str(per_run.resolve()))
    return None


# Confidence acts as a tiebreaker, not a promotion — scaled down.
_CONF_BONUS = {
    "tested": 0.5, "documented": 0.4, "corroborated": 0.3,
    "traced": 0.2, "inferred": 0.0,
}


class _ItemStatics:
    """Function-independent scoring inputs derived from one model item.

    Everything :func:`_relevance_score` computes from the ITEM alone —
    joined/lowered prose, identifier tokens, the cleaned file field,
    the confidence bonus. Deriving these per (item × function) pass is
    what made the per-function slice fingerprint linear in model size;
    a :class:`_DomainSliceMemo` computes them once per model content.
    The equivalence suite pins every field against a frozen reference
    copy of the historical inline derivation, drifted shapes included.
    """

    __slots__ = ("desc", "item_id", "item_file", "id_parts",
                 "named_idents", "conf_bonus")

    def __init__(self, item: dict[str, Any]) -> None:
        # Statement and negation join the text: derived invariants
        # keep their identifiers in the statement while the
        # description is a provenance note — description-only scoring
        # made them invisible.
        self.desc: str = " ".join(
            s for s in (
                item.get("description"), item.get("statement"),
                item.get("negation"),
            ) if s
        ).lower()
        self.item_id: str = (
            item.get("id") or item.get("concept")
            or item.get("name") or ""
        ).lower()
        item_file = item.get("file") or item.get("source") or ""
        self.item_file: str = re.split(r":\d", item_file, maxsplit=1)[0]
        # ID parts pre-filtered to the scoreable length (>4 chars);
        # shorter parts never contribute.
        self.id_parts: tuple[str, ...] = tuple(
            p for p in re.split(r"[_\-.]", self.item_id) if len(p) > 4
        )
        # Code identifiers in the item text, underscore required,
        # deduplicated exactly like the historical set(findall(...)).
        self.named_idents: tuple[str, ...] = tuple(
            tok
            for tok in set(re.findall(r"[a-z_][a-z0-9_]{5,}", self.desc))
            if "_" in tok
        )
        self.conf_bonus: float = _CONF_BONUS.get(
            item.get("confidence", "inferred"), 0.0)


def _relevance_score(
    item: dict[str, Any],
    file_path: str,
    function_name: str,
    source: str,
    *,
    statics: _ItemStatics | None = None,
) -> float:
    """Score how relevant a concept/invariant/contract is to a function.

    ``statics`` (optional): the item's precomputed function-independent
    inputs, passed by memo-backed callers. Omitted, they are derived
    fresh — same values either way (the derivation is a pure function
    of the item).
    """
    st = statics if statics is not None else _ItemStatics(item)
    score = 0.0
    variants = _name_variants(function_name)
    fn_lowers = tuple(v.lower() for v in variants)
    source_lower = source.lower() if source else ""

    # Direct naming match (case-insensitive, no double-count) —
    # either name form counts, once.
    if any(v in st.desc or v in st.item_id for v in fn_lowers):
        score += 5.0

    # Evidence references this file or function.
    # File-level match is a weak signal (same file, possibly unrelated
    # function); function-level match is strong.
    for ev in item.get("evidence", []):
        if isinstance(ev, dict):
            ev_file = ev.get("file", "")
            if ev_file and _paths_match(file_path, ev_file):
                ev_item = ev.get("item", "")
                if ev_item and ev_item in variants:
                    score += 6.0
                else:
                    score += 1.5
                break

    # Contract is FOR this function specifically
    if item.get("function") in variants:
        score += 8.0
    if st.item_file and _paths_match(file_path, st.item_file):
        score += 2.0

    # Concept ID parts appear in the source body (weak signal)
    for part in st.id_parts:
        if part in source_lower:
            score += 0.5

    # Code identifiers named in the item's text that appear in the
    # reviewed function's body. This is the ONLY routing signal
    # available to derived invariants (threat-frame class): they carry
    # no receipts, evidence anchors, or file field — an invariant
    # whose statement names af_alg_pull_tsgl must reach the review of
    # every function whose body calls it. Underscore required so the
    # match means a code identifier, not prose; capped so a laundry
    # list of identifiers cannot outrank an exact-function anchor.
    if source_lower and st.desc:
        hits = sum(
            1 for tok in st.named_idents if tok in source_lower
        )
        score += min(3.0, 1.5 * hits)

    score += st.conf_bonus

    return score


def _add_derived_slots(
    selected: list[dict[str, Any]],
    scored: list[tuple[dict[str, Any], float]],
    *,
    max_extra: int = 2,
) -> list[dict[str, Any]]:
    """Reserve up to ``max_extra`` slots for derived (llm_prior)
    invariants that anchored to the function but missed the top-N cut.

    The threat-frame class carries no receipts, evidence anchors, or
    file fields, so extracted invariants systematically outscore it in
    a large model even when it names the exact functions under review
    — and it is precisely the knowledge aliasing-class detection needs
    (the CVE-2026-31431 A/B: extraction alone missed; the derived
    frame is the difference). Score > 1.0 still required: the anchor
    must be real, an unanchored derived invariant stays out.
    """
    chosen = {id(i) for i in selected}
    extra = [
        i for i, s in scored
        if s > 1.0 and id(i) not in chosen
        and str(i.get("provenance") or "") == "llm_prior"
    ]
    return list(selected) + extra[:max_extra]


def _security_context_lines(model: dict[str, Any]) -> list[str]:
    """Prompt lines for the model's ``security_context`` section.

    Returns an empty list when the model carries no usable security
    context (no privilege level).
    """
    sc = model.get("security_context")
    if not isinstance(sc, dict) or not sc.get("privilege_level"):
        return []
    parts = ["### Target Security Context\n"]
    parts.append(f"- **Privilege level:** {sc['privilege_level']}")
    if sc.get("attack_surface"):
        parts.append(f"- **Attack surface:** {sc['attack_surface']}")
    if sc.get("isolation"):
        parts.append(f"- **Isolation:** {sc['isolation']}")
    parts.append(
        "\nUse this context when assessing severity. "
        "Memory corruption in kernel code reachable from "
        "unprivileged userspace is high or critical severity. "
        "Adjust severity relative to the privilege boundary "
        "the attacker crosses.\n"
    )
    return parts


def _render_security_context(model: dict[str, Any]) -> str | None:
    """The security-context block for *model* (None when it has none)."""
    lines = _security_context_lines(model)
    if not lines:
        return None
    if isinstance(model.get("security_context"), dict):
        trust = model["security_context"].get("trust_summary")
        if trust:
            # Keep the guidance sentence last.
            lines.insert(len(lines) - 1, f"- **Trust boundary:** {trust}")
    return "\n".join(lines)


def domain_security_context(
    out_dir: Path,
    *,
    _memo: _DomainSliceMemo | None = None,
) -> str | None:
    """Standalone security-context prompt block.

    Consumed by ``core.audit.context`` (always-on prompt section,
    independent of primer relevance) and by the security classifier.
    Returns None when no domain model exists or it carries no
    security context.

    ``_memo`` (private): a prebuilt slice memo for the discovered
    model — the fingerprint path passes it so this model-wide render
    happens once per model content instead of once per function.
    """
    if _memo is not None:
        return _memo.security_block()
    model = _find_domain_model(out_dir)
    if not model:
        return None
    return _render_security_context(model)


@lru_cache(maxsize=4)
def _token_map_for_run(out_dir_s: str, target_s: str) -> dict[str, Any] | None:
    """Load — or mechanically project — the run's token-enforcement map.

    A per-run ``token-map.json`` wins (written by the study pipeline,
    or by a previous call here). Otherwise, when the discoverable
    domain model carries learned ``token_checks`` and this run has an
    entry-point source co-located (``checklist.json`` /
    ``context-map.json``), the map is projected on the fly and
    persisted for the rest of the run. Purely mechanical — no LLM
    call. Cached per (run, target) so per-function context assembly
    pays the projection at most once.
    """
    from .token_map import load_token_map, project_token_map_for_run

    out_dir = Path(out_dir_s)
    existing = load_token_map(out_dir)
    if existing is not None:
        return existing
    if not target_s:
        return None
    model = _find_domain_model(out_dir)
    if not isinstance(model, dict) or not model.get("token_checks"):
        return None
    written = project_token_map_for_run(model, out_dir, Path(target_s))
    return load_token_map(out_dir) if written else None


def ensure_token_map(
    out_dir: Path, target_path: str | Path,
) -> dict[str, Any] | None:
    """Public load-or-project entry (CLI + tests) for the run's map."""
    return _token_map_for_run(str(out_dir), str(target_path))


_MAX_TOKEN_TEXT_CHARS = 300


def _token_source_drift(
    record: dict[str, Any], target_path: str | Path | None,
) -> str:
    """Drift marker when the entry's source changed since projection.

    Compares the record's ``source_sha256`` stamp (content digest at
    projection time — the map carries no timestamp, staying
    deterministic) against the file's current content. Returns a
    suffix for the fact line, or "". Fail-quiet: a legacy record
    without a stamp, an unavailable target, or a read error produces
    no marker (the hint block already says verify-against-source).
    """
    import hashlib

    stamp = str(record.get("source_sha256") or "")
    if not stamp or not target_path:
        return ""
    rel = str(record.get("file") or "").replace("\\", "/")
    parts = PurePosixPath(rel)
    if not rel or parts.is_absolute() or ".." in parts.parts:
        return ""  # map content is untrusted — no traversal reads
    try:
        p = Path(target_path) / rel
        if not p.is_file():
            return " [source missing since projection]"
        text = p.read_text(encoding="utf-8", errors="replace")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    except OSError:
        return ""
    if digest == stamp:
        return ""
    return " [source drifted since projection — re-project before use]"


def token_enforcement_context(
    out_dir: Path,
    file_path: str,
    target_path: str | Path | None = None,
) -> str | None:
    """Per-entry token-enforcement hint block for an audit review.

    Returns a rendered block only when *file_path* is a mapped entry
    point in the run's token-enforcement map
    (:mod:`core.concepts.token_map`); library files and unmapped
    targets get None. Hint-tier by contract (same framing as the
    include-graph facts): the block says verify-against-source and is
    never a verdict input — in particular, an "enforced" line must
    never be read as refuting a request-forgery hypothesis, because
    the map records call PRESENCE, not bypass-freedom (conditional
    checks and skip paths still project as enforced).
    """
    from core.security.log_sanitisation import escape_nonprintable

    def _defend(value: Any, cap: int = _MAX_TOKEN_TEXT_CHARS) -> str:
        text = escape_nonprintable(str(value or ""))
        return text[:cap] + ("…" if len(text) > cap else "")

    try:
        payload = _token_map_for_run(str(out_dir), str(target_path or ""))
    except Exception:  # noqa: BLE001 — enrichment, never a review gate
        logger.debug("token map lookup failed", exc_info=True)
        return None
    if not payload:
        return None

    rel = str(file_path or "").replace("\\", "/").lstrip("./")
    record = None
    for r in payload.get("entries") or []:
        if not isinstance(r, dict):
            continue
        rf = str(r.get("file") or "")
        if rf == rel or rf.endswith("/" + rel) or rel.endswith("/" + rf):
            record = r
            break
    if record is None:
        return None

    checks = [
        c for c in (payload.get("check_functions") or [])
        if isinstance(c, dict)
    ]
    check_desc = ", ".join(
        f"{_defend(c.get('name'), 120)}() {_tier_tag(c)}"
        for c in checks[:4]
    ) or "(none)"

    status = str(record.get("status") or "unknown")
    via = _defend(record.get("via"), 120)
    cond = " (on a CONDITIONAL branch)" if record.get("conditional") else ""
    if status == "enforced":
        fact = (
            f"token-enforcement: enforced-via {via}(){cond} — direct "
            "call in the pre-output prefix (call-presence witness only)"
        )
    elif status == "indirect":
        chain = " -> ".join(
            _defend(hop, 120) for hop in (record.get("call_path") or [])[:8]
        )
        fact = (
            f"token-enforcement: enforced-via {via}() INDIRECTLY"
            f"{cond} ({chain}); intermediate branch conditions not "
            "analysed"
        )
    elif status == "not_enforced":
        fact = (
            "token-enforcement: NOT enforced — "
            f"{_defend(record.get('evidence'))}"
        )
    else:
        fact = (
            "token-enforcement: unknown — "
            f"{_defend(record.get('reason') or record.get('evidence'))}"
        )
    fact += _token_source_drift(record, target_path)

    return "\n".join([
        "### Token enforcement (mechanical projection of the "
        "study-learned check idiom)",
        f"- This file is a mapped entry point: {fact}.",
        f"- Learned check idiom: {check_desc}.",
        "Hint-tier steering context — verify against source; never "
        "treat as a verdict input. \"Enforced\" is call presence, not "
        "bypass-freedom (conditional checks and skip paths still map "
        "as enforced), so it must never rule out a request-forgery or "
        "state-change finding; \"NOT enforced\" is a static absence "
        "census over resolved calls, not proof of exploitability.",
    ])


# Complexity cap for LLM-derived grep hints compiled as regexes.
# Both directions matter: too low and legitimate multi-alternative
# hints ("memcpy|memmove|strcpy...(dozens of sinks)") silently lose
# regex semantics and stop selecting their pattern; too high and a
# pathological hint (steerable by hostile repo content through the
# study LLM) gets more room for slow constructs before the substring
# fallback catches it. 256 covers every hint shape study emits today
# with headroom, while keeping worst-case scan cost per function
# bounded.
_MAX_GREP_HINT_CHARS = 256

# Super-linear shapes ``looks_redos`` does not see. Same guard idiom
# as the log-check pattern gate in ``core/env/verify.py``
# (``_dangerous_re``): consecutive quantifiers, possessive-looking
# ``(?...+`` forms, any quantified group whose body carries an
# alternation or its own quantifier (incl. bounded ``{m,n}`` —
# ``(a|a)+`` and ``(a{1,9}){1,9}`` both blow up), and nested
# quantified groups. Group spans are bounded at the hint length cap
# (the length gate runs FIRST, so on every input this scan can see
# an unbounded ``[^)]*`` span would change no verdict — the bound
# only keeps the scan itself linear).
_HINT_SUPERLINEAR_RE = re.compile(
    r"[+*]{2,}"
    rf"|\(\?[^)]{{0,{_MAX_GREP_HINT_CHARS}}}\+"
    rf"|\([^)|+*{{]{{0,{_MAX_GREP_HINT_CHARS}}}[|+*{{]"
    rf"[^)]{{0,{_MAX_GREP_HINT_CHARS}}}\)\s*[+*{{]"
    rf"|\([^)]{{0,{_MAX_GREP_HINT_CHARS}}}\)[+*{{]"
    rf"[^)]{{0,{_MAX_GREP_HINT_CHARS}}}\)\s*[+*{{]"
)

# Any repeat applied to a GROUP — a repeat token after a close paren,
# regardless of the group body. The two group forms above inspect the
# body (alternation / inner quantifier); a quantified group whose
# body is a plain literal or class passes them, yet every iteration
# boundary is still a backtrack point, and at the source clamp below
# such shapes measure an order above the leading-literal baseline.
# Measurement venue for every figure in this guard block unless
# stated otherwise: bare ``re.search(pattern, source, re.IGNORECASE)``
# on a FAILING search over a saturated source at the 16384-char
# clamp, best-of-5 single-threaded wall clock on one development
# host — order-of-magnitude figures for ranking shapes, not portable
# constants. In that venue: "(ab)*c" 0.79 s, "([ab][ba])*x" 1.8 s,
# "(..)*xy" 1.5 s, counted forms like "(a){60000}" in the same
# regime, vs "memcpy.*len" 0.11 s. The body-inspecting forms above
# stay (their pins hold independently); this rule subsumes them
# body-blind. ``\s*`` slack matches their idiom, and ``?`` after a
# group — bounded on its own — is refused with the rest: over-refusal
# only demotes to the substring fallback, in keeping with the
# counted-not-parsed stance of the repeat-token budget below.
_HINT_QUANTIFIED_GROUP_RE = re.compile(r"\)\s*[+*?{]")

# Backreferences re-match a variable-length captured span, so
# ``(a*)\1b`` carries ONE repeat token and no quantified-group shape
# yet backtracks super-linearly (measured cubic-order: every split of
# the captured span is retried against the tail) — a clean bypass of
# every rule above. Numeric (``\1``..``\9``) and named (``(?P=name``)
# forms are refused alike. Conditional groups (``(?(id)yes|no)``,
# matched by ``\(\?\(``) are refused with them: the conditional test
# itself does not re-consume text, but it exists only alongside the
# same capture/backref machinery, no legitimate hint uses it, and
# refusal costs only the substring fallback. Over-refusal is safe
# (``\1`` inside a character class is an octal escape, not a backref
# — it still demotes): demotion loses selection power, never
# soundness. No shipped or schema-suggested hint uses any of these
# forms. The ``\g<1>`` / ``\g{1}`` spellings are deliberately not
# matched: they are replacement-template syntax, ``re.error`` inside
# a PATTERN on every interpreter, so the ``re.error`` arm demotes
# them to the same substring fallback — a spelling gap, not a bypass.
_HINT_BACKREF_RE = re.compile(r"\\[1-9]|\(\?P=|\(\?\(")

# Repeat tokens for the budget below. Counted, not parsed: every
# ``*``, ``+``, ``?``, or ``{`` occurrence counts, including escaped
# (``\*``) and class-member (``[+*]``) uses — over-counting only ever
# demotes a hint to the substring fallback (less selection power); a
# parser-accurate count could under-count a live repeat and is not
# worth the machinery for hint-sized inputs.
_HINT_REPEAT_TOKEN_RE = re.compile(r"[*+?{]")

# Repeat budget for compiled hints. The shape scans above are blind
# to UNGROUPED repeat chains — ``a*a*a*...b`` and ``a?a?...a{n}``
# backtrack combinatorially with no group or alternation for any
# shape rule to anchor on — so the only static bound on them is how
# many repeat tokens a hint may carry at all. Both directions:
# higher admits multi-repeat regex hints, but every additional
# repeat that can overlap its neighbour ahead of a failable
# continuation multiplies the split space the engine explores over
# target-derived source (two overlapping spans are already quadratic
# per attempt, and the source under the fold's slice recompute is
# attacker-authored); zero would demote the common single-span hint
# ("memcpy.*len"). One repeat admits exactly that single-span class —
# which is NOT free: a failing search is quadratic in the source when
# the leading literal recurs ("memcpy.*len" against "memcpy"*k
# restarts a full scan-and-backtrack at every occurrence), so
# admitted hints are additionally cost-bounded by the source-length
# clamp below (``_MAX_REGEX_SOURCE_CHARS``). The budget bounds the
# blow-up CLASS (no chains, no stacked repeats); the clamp bounds
# what the admitted class may cost. Both directions pinned by
# ``test_repeat_budget_two_directions``.
_MAX_GREP_HINT_REPEATS = 1

# Unbounded-capable repeat tokens for the prefix-period rule below:
# ``*``, ``+``, and ``{`` (counted repeats reach ``{60000}``-scale).
# ``?`` is excluded — it repeats its atom at most once, and the
# budget above already limits the whole hint to one repeat token.
_HINT_UNBOUNDED_REPEAT_RE = re.compile(r"[*+{]")

# Leading literal run of an alternation branch: everything up to the
# first regex metacharacter. Counted, not parsed (the stance of the
# repeat-token scan above): a ``\``-escape or class ends the run even
# when it would match a fixed character — under-counting the prefix
# only ever demotes.
_HINT_LITERAL_PREFIX_RE = re.compile(r"[^\\.\[\](){}*+?|^$]*")

# Minimum self-overlap period of the literal prefix required in front
# of any unbounded repeat, per top-level alternation branch. A
# failing search restarts the span once per occurrence of the
# mandatory leading literal, and occurrences can sit no closer than
# the prefix's period, so the period caps restart density — the
# multiplier on the quadratic floor the clamp below bounds. Measured
# (venue as above): density-1 shapes ("x.*y" 0.68 s, "aa.*z" 0.88 s,
# ".*z" 0.62 s — empty, 1-char, or self-overlapping prefixes) vs
# period-2 ("ab.*z") 0.35 s, period-3 ("aab.*z" 0.22 s,
# "len.*memcpy" 0.20 s), and the plain leading-literal baseline
# ("memcpy.*len", period 6) 0.11 s. The period is computed under the
# ENGINE's IGNORECASE character equivalence (``_engine_fold`` below)
# — matching is IGNORECASE, so the restart density that matters is
# the engine's, not any particular string fold's ("sSsS" folds to
# period-1 "ssss"; so do the cross-codepoint orbits the fold
# closes). Both directions: higher demotes real short-identifier
# hints (period 3 is the shortest common C-name shape — "len",
# "buf", "ptr", which must keep regex power); lower divides the
# restart spacing in the cost model's dominant n^2*W/p term at the
# source clamp (2 re-admits the 0.35 s period-2 tail-free class, 1
# the 0.6-0.9 s density-1 class — and at the full continuation walk
# a lower p scales the admitted-worst ceiling by the same factor).
# Both directions pinned by
# ``test_span_prefix_period_two_directions``; the admitted-worst
# ceiling itself is wall-clock-pinned by
# ``test_worst_admitted_shape_cost_bounded``.
_MIN_HINT_PREFIX_PERIOD = 3

# Per-backtrack walk budget for the repeat-bearing branch: the raw
# character count of the branch CONTINUATION (everything after the
# sole unbounded repeat token, to the end of the branch), weighted by
# the alternation bars anywhere in the WHOLE branch — walk =
# (1 + branch bars) * continuation chars. The period rule above
# bounds how OFTEN a failing search restarts the span; this bounds
# what each backtracked span position may COST: every backtrack
# attempt walks at most the continuation's elements once per
# alternation path through the branch, and sre memoises nothing, so
# a grouped bar multiplies that walk WHEREVER it sits — after the
# token ("aab.*(aabaabaaz|q)": 13 continuation chars whose bar
# doubles the per-position walk, 1.05 s measured, well above the
# 0.59 s no-bar "aab.*" + 13-char tail; unweighted it would ADMIT)
# or BEFORE it ("aab(a|a)[a-z0-9]*aabaabaabaabz": 1.77 s measured,
# exactly 2.0x its bar-free twin "aab[a-z0-9]*aabaabaabaabz" at
# 0.88 s — sre re-runs the whole span and its full backtrack once
# per group alternative; venue as above). A continuation-only bar
# weight would let the one admitted bar ride in FRONT of a
# full-budget tail at bare weight — an unpriced, clean 2x of its
# bar-free twin (1.77 s, inside the sampled spread of the family's
# admitted spellings — the weight bounds the cost class, not a
# total ordering of shapes; figures at the clamp constant);
# counting bars over the whole branch
# prices the path factor on both sides of the token. Unbounded, the
# continuation is a bypass of the whole cost model — a long
# self-overlapping literal tail ("aab.*" + "aab"*80 + "z": 246
# chars, ONE repeat token, period-3 prefix) measured 7.4 s at the
# source clamp (venue as above), ~35x the tail-free "aab.*z" at
# 0.20 s, scaling linearly in tail length (L30 1.0 s, L90 3.0 s).
# Counted, not parsed (the repeat-token scan's stance): brace
# digits, close-parens, escapes, and class-member or escaped bars
# all count — over-counting only ever demotes, and counting brace
# digits keeps a counted repeat from smuggling extra continuation
# mass past the budget. Deliberate asymmetry with the bar BUDGET
# below: the budget's counter is structure-aware (escaped and
# class-member bars are literal members, never path splits), while
# this WEIGHT uses the raw branch bar count — raw can only
# over-count, i.e. demote; a structure-aware weight would only
# re-admit shapes, so do not "fix" the asymmetry in that direction.
# Both directions: lower demotes the longest continuation in the
# legit corpus ("kfree(.*) double free" — ") double free" is
# exactly 13 chars, bars 0; admission pinned by
# ``test_group_hint_without_group_repeat_stays_admitted``); higher
# admits linearly costlier tails (~0.04-0.05 s per admitted
# continuation char at the clamp — the measured slope of the tail
# family, same venue). Both directions pinned by
# ``test_repeat_continuation_walk_two_directions``; the refusal of
# the literal-tail family is separately pinned red-if-neutralized
# by ``test_literal_tail_continuation_refused``, and the
# pre-token-bar family (bar spent before the token, walk
# saturated) by
# ``test_pre_token_grouped_bar_saturated_walk_refused``.
_MAX_HINT_REPEAT_CONTINUATION_WALK = 13

# Spelled length of the atom the unbounded repeat applies to (the
# span atom): a character class's per-span-char test cost is engine-
# and spelling-dependent, not O(1) — figures recorded under an
# earlier venue on this host had an escape-spelled member zoo
# ("aab[ab\x63\x64...]*" + 13-char tail) at 1.9-2.1 s at the clamp
# with the two-member "[ab]" spelling at 1.3-1.5 s, growth not even
# monotone in member count; in the current venue (as above) the
# same pair measures ~0.86 s in BOTH spellings ("[ab]" and the 4-
# and 8-member escape zoos alike), and within ONE admitted
# pre-token-bar family at the same clamp the negation spelling
# splits at the engine's compiler: the single-literal negation
# "aab(a|a)[^c]*aabaaz" compiles to the cheap single-op path and
# measures ~0.87 s where the two-member negation "[^cd]" spelling
# of the same shape measures ~1.63 s — the spelling-cost spread
# itself comes and
# goes with the engine's charset compilation and the host, which is
# exactly why the model refuses to carry an unbounded spelling
# rather than characterise it. The
# hint length cap alone bounds the spelling only at ~240 chars, too
# weak for a stated per-span-char constant. The span is located by
# the branch splitter's own escape/class scan rules, run forward
# (``_hint_repeat_atom_chars``): a nearest-"[" backward scan would
# let a class-member "[" understate an escape-heavy spelling
# ("aab[<escape zoo>[ab]*…" scans back to the inner "["). Both
# directions: lower refuses the golden class-atom shapes ("abc[)]*x"
# spells 3, "[ab]" 4, the common "[a-z0-9]" range spelling exactly
# 8); higher re-admits spellings whose walk constant the model
# cannot state. Both directions pinned by
# ``test_repeat_atom_spelling_two_directions``.
_MAX_HINT_REPEAT_ATOM_CHARS = 8

# Alternation bars INSIDE groups, whole-hint budget. Top-level bars
# are additive (the engine tries each top-level branch per start
# position; the total walk is bounded by the hint length), but every
# grouped alternation MULTIPLIES the paths one attempt explores
# through the pattern suffix after it, and sre memoises nothing: the
# repeat-free "(a|a)(a|a)...(a|a)b" stack doubles per group —
# measured 0.93 s at 22 groups over a 32-CHAR source, x~1.9 per
# added group (bare re.search IGNORECASE, single-threaded wall
# clock, one development host) — an exponential family fully inside
# the length cap with ZERO repeat tokens, invisible to every
# repeat-anchored rule above. One grouped bar caps the path factor
# of a match attempt at 2 (times 2 more for the sole ``?`` the
# repeat budget can admit), keeping one attempt's walk linear in the
# hint. On a repeat-BEARING branch the same factor multiplies the
# span walk and its backtrack too — priced there by the branch-wide
# bar weight of the continuation-walk budget above, so the budget
# here bounds the factor and the walk budget charges for it.
# Structure-aware, never failing
# (``_hint_grouped_alternation_bars``): a paren-depth-only count is
# bypassable — an escaped or class-member ")" silently closes the
# depth and hides every later real bar — so the count runs the
# branch splitter's escape/class scan; escaped and class-member bars
# are literal members, not path splits, and do not count. Unlike the
# splitter it never refuses on unbalance: a stray ")" clamps at
# depth zero and unterminated structure still yields a defined count
# (refusal-on-unbalance belongs to the splitter, which runs only on
# repeat-bearing hints — repeat-free unbalanced goldens like
# "(frame_checksum" keep their historical ADMIT, and the truly
# malformed are re.error and demote at compile). Both directions:
# zero refuses the legit group-alternation-after-admissible-prefix
# class ("memcpy(a|b.*z)", pinned by
# ``test_group_after_admissible_prefix_stays_admitted``); every
# extra allowed bar doubles the worst per-position path count —
# exponential in the allowance, the measured stack above. Both
# directions pinned by
# ``test_grouped_alternation_bar_budget_two_directions``; the stack
# family is pinned red-if-neutralized by
# ``test_alternation_stack_refused``.
_MAX_HINT_GROUPED_ALTERNATION_BARS = 1

# --- Engine-equivalence fold for the prefix-period rule ---
# The period must be computed under the same character equivalence
# the regex engine applies when matching IGNORECASE, or a prefix can
# look non-self-overlapping to the rule while every character of it
# matches every other at match time. CPython's sre matches literal
# characters 1:1 by SIMPLE lowercase and widens that with the
# extra-case orbits in ``re._casefix._EXTRA_CASES``;
# ``str.casefold()`` — the previous fold here — diverges from that
# equivalence in both directions, and each direction broke the rule
# (venue as above):
#
# * casefold SPLITS an engine orbit: "ı" (U+0131) casefolds to
#   itself while the engine matches i <-> ı, so "iıı.*z" showed a
#   casefold period of 3 (admitted) with a true engine restart
#   density of 1 — 0.81 s, vs the 0.22 s admitted worst.
# * casefold EXPANDS some single characters to multi-character
#   strings the engine still matches 1:1: "ﬃ" (U+FB03 -> "ffi",
#   fake period 3 over the expansion; "ﬃﬃﬃ.*z" 0.92 s) and "İ"
#   (U+0130 -> "i" + combining dot; the engine's simple lowercase
#   is plain "i", so "İii.*z" is engine-density-1, 0.76 s).
#
# The fold therefore maps each character to a canonical
# representative of its ENGINE orbit: İ first (the one character
# whose full lowercase via ``str.lower`` expands to two characters,
# while the engine's simple lowercase is "i"), then ``str.lower``
# (the engine's 1:1 simple-lowercase table for everything else —
# unlike casefold it never expands another character), then one
# representative per ``re._casefix._EXTRA_CASES`` orbit (dropping
# casefold loses its ς/σ-style unifications, which lower() does not
# perform but the engine does — the table restores every one). The
# orbit table is HARDCODED, not imported from ``re._casefix`` at
# runtime: the verdict feeds ``domain_slice_hash`` and must be
# identical on every interpreter, and ``re._casefix`` is a private
# stdlib module whose content (or importability) may drift. Drift is
# pinned instead by ``test_engine_fold_covers_interpreter_orbits``,
# which re-derives the pairs from the RUNNING interpreter's
# ``re._casefix`` and fails loudly if the fold misses any (a
# mechanical re-verify on interpreter bumps — never a silent verdict
# split; a fold that over-unifies only over-refuses, so the pinned
# direction is the admission-risk one). Source: CPython 3.14
# ``re/_casefix.py`` — 24 orbits over 50 codepoints.
_HINT_FOLD_DOTTED_I = str.maketrans({0x0130: "i"})
_HINT_FOLD_ORBIT_REPS = str.maketrans({
    0x0131: "\u0069",  # dotless i -> i
    0x017F: "\u0073",  # long s -> s
    0x00B5: "\u03BC",  # micro sign -> greek mu
    0x0345: "\u03B9",  # combining iota subscript -> iota
    0x1FBE: "\u03B9",  # prosgegrammeni -> iota
    0x1FD3: "\u0390",  # iota dialytika oxia -> iota dialytika tonos
    0x1FE3: "\u03B0",  # upsilon dialytika oxia -> dialytika tonos
    0x03D0: "\u03B2",  # beta symbol -> beta
    0x03F5: "\u03B5",  # lunate epsilon -> epsilon
    0x03D1: "\u03B8",  # theta symbol -> theta
    0x03F0: "\u03BA",  # kappa symbol -> kappa
    0x03D6: "\u03C0",  # pi symbol -> pi
    0x03F1: "\u03C1",  # rho symbol -> rho
    0x03C2: "\u03C3",  # final sigma -> sigma
    0x03D5: "\u03C6",  # phi symbol -> phi
    0x1C80: "\u0432",  # cyrillic small rounded ve -> ve
    0x1C81: "\u0434",  # long-legged de -> de
    0x1C82: "\u043E",  # narrow o -> o
    0x1C83: "\u0441",  # wide es -> es
    0x1C84: "\u0442",  # tall te -> te
    0x1C85: "\u0442",  # three-legged te -> te
    0x1C86: "\u044A",  # tall hard sign -> hard sign
    0x1C87: "\u0463",  # tall yat -> yat
    0x1C88: "\uA64B",  # unblended uk -> monograph uk
    0x1E9B: "\u1E61",  # long s with dot above -> s with dot above
    0xFB05: "\uFB06",  # st (long s-t) ligature -> st ligature
})


def _engine_fold(text: str) -> str:
    """Fold ``text`` by the engine's IGNORECASE character equivalence.

    Two characters fold equal here exactly when CPython's sre matches
    one against the other under ``re.IGNORECASE`` (simple lowercase
    plus the ``re._casefix`` extra-case orbits — rationale and drift
    pin at the tables above). Unlike ``str.casefold`` the result is
    1:1 per character, so self-overlap periods computed on it equal
    the engine's restart periods.
    """
    return (
        text.translate(_HINT_FOLD_DOTTED_I)
        .lower()
        .translate(_HINT_FOLD_ORBIT_REPS)
    )


# Source-length clamp for the regex path. The shape rules above
# decide WHICH hints compile, not what they cost: the admitted
# single-span class is quadratic in ``len(source)`` on a failing
# search, and source reaching this point is target-derived with no
# per-function bound upstream (the only upstream limit is the 64 MB
# per-file read cap in ``core/audit/context.py``). Measured quadratic
# curve ("memcpy.*len" over saturated failing source, bare
# ``re.search`` IGNORECASE, best-of-3 single-threaded wall clock on
# one development host — order-of-magnitude, host-dependent):
# 16 KiB ~ 0.11 s, 32 KiB ~ 0.42 s, 64 KiB ~ 2.1 s, 117 KiB ~ 7.1 s
# per hint evaluation. Both directions: higher keeps regex semantics
# on bigger functions, but the clamp value bounds the worst-case
# per-hint match cost quadratically (doubling the clamp quadruples
# the ceiling); lower demotes more big-function hints to the
# substring fallback (less selection power, never less soundness);
# both directions of the constant pinned by
# ``test_source_clamp_two_directions``.
#
# COST MODEL for one failing search of an ADMITTED hint over a
# clamped source (n = 16384). Every admitted hint obeys, by
# construction of the refusal layers: hint length H <= 256; at most
# ONE repeat token, never on a group, no backreference; at most ONE
# grouped alternation bar — a span-path factor g <= 1, because each
# grouped bar multiplies the paths one match attempt explores
# through its branch and sre memoises nothing; and when the sole
# token is unbounded, a mandatory branch prefix of engine-folded
# period p >= _MIN_HINT_PREFIX_PERIOD, a span atom spelled
# <= _MAX_HINT_REPEAT_ATOM_CHARS, and a WEIGHTED continuation walk
# W = (1 + branch bars) * continuation chars
# <= _MAX_HINT_REPEAT_CONTINUATION_WALK. The weight counts bars over
# the WHOLE branch, so branch bars >= g and W already prices the
# (1+g) path factor no matter which side of the token the bar sits
# (a continuation-only weight would omit g for a pre-token bar:
# the walk figure it stated would then be 1/(1+g) of the true
# weighted cost, a clean 2x hole).
# Repeat-free hints cost <= n starts x <= 4 paths x <= H elements —
# linear in n (worst constructed shapes measure ~ms at the clamp).
# The 4 is DERIVED from the budgets, not assumed: the only path
# multipliers a repeat-free admitted hint can carry are the sole
# "?" the repeat-token budget admits (x2) and the sole grouped bar
# the bar budget admits (x2) — top-level bars are additive, not
# multiplicative — so paths <= 2 x 2 = 4.
# Repeat-bearing hints cost
# <= c * [ n*H + (1+g) * (n/p) * n + (n/p) * n * W ]: prefix
# scanning is the n*H term; at most n/p positions carry the
# mandatory prefix, and each restarts the span once per path — the
# (1+g) span re-runs of <= n span chars each are the middle term,
# itself capped at 2 * (n/p) * n by g <= 1, i.e. at most 2/13 of
# the dominant term's cap IN ELEMENT COUNTS (its measured
# wall-clock share is far larger — see the ranking note below) —
# and each restarted span
# backtracks <= n positions whose continuation attempts walk, over
# ALL (1+g) paths together, <= W weighted elements. Every variable
# in the dominant n^2*W/p term is bounded by a named constant — W
# (which internally prices g) binds the ceiling, p divides it — and
# the constant c is the engine's per-element step with the span
# atom's test folded in (why the atom spelling is bounded too).
# The element-count arithmetic orders admitted repeat-bearing
# shapes by W at fixed p and atom spelling, but W alone is NOT a
# strict cost ranking at the top: in units of the (n/p)*n restart
# floor, the middle (span re-run) term contributes (1+g) and the
# dominant term W. Among shapes whose ONLY weight-counted bars are
# path-splitting ones, the best bar-carrying weight is
# (1+1) x 6 = 12 and the full-walk admitted maxima TIE at 14 units
# — the bar-free walk-13 shape (1 + 13), the pre-token-bar walk-12
# family (2 + 12), and the post-token-bar walk-12 runner-up
# (2 + 12). Raw (escaped or class-member) bars are weight-counted
# yet split no paths, and they MIX with the one grouped bar in the
# raw branch count, so mixed-bar admitted shapes reach weight 13
# with a path-splitting bar present — one grouped bar + 11 raw
# bars over a 1-char continuation, (1+12) x 1 = 13 (the bar BUDGET
# counts only the grouped bar) — scoring 2 + 13 = 15 units. That
# needs continuation <= 1 char, and both raw spellings measure
# below the measured-worst family stated next (venue as at
# ``_HINT_QUANTIFIED_GROUP_RE``): the escaped spelling
# ("aab(a|a)" + "\|"x11 + "[ab]*z") ~0.000 s — its mandatory
# literal bars kill every match attempt immediately, as they do
# for the pure raw-bar weight-13 shapes
# ("aab" + "\|"x12 + "[ab]*z", also ~0.000 s) — and the
# class-member spelling
# ("aab(a|a)" + "[a|b]"x11 + "[a-z0-9]*z") 1.00 s at n = 16384:
# its "[a|b]" prefix classes MATCH the aab-saturated source, so
# the (1+g)-doubled span-and-backtrack work is real, yet it
# measures below the measured-worst family.
# Measurement discriminates where the tie arithmetic cannot: the
# element counts under-weight the walk-INDEPENDENT cost each
# restart carries (the span run plus per-restart overhead —
# empirically ~60% of the bar-free wall clock at the clamp:
# in-venue, walk-13 bar-free 0.88 s vs walk-6 bar-free 0.69 s
# gives ~0.03 s per continuation char over a ~0.5 s base), and a
# pre-token bar multiplies that WHOLE base by (1+g). The MEASURED
# admitted ceiling therefore belongs to the matching-alternative
# pre-token family — its "[a-z0-9]" representative
# "aab(a|a)[a-z0-9]*aabaaz" (weight (1+1) x 6 = 12) measures
# (venue as at ``_HINT_QUANTIFIED_GROUP_RE``)
# 0.09 s / 0.35 s / 1.38 s at n = 4096 / 8192 / 16384 — ~1.4 s at
# the clamp light-load, higher under host load as across the
# recorded figure history — 2.0x its bar-free twin
# "aab[a-z0-9]*aabaaz" (0.69 s). WITHIN the family the cost is
# atom-spelling-dependent and every stated figure is a SAMPLE, not
# a supremum: sampled range spellings ("[a-b0-9]", "[a-c0-9]",
# "[0-9a-b]") measure 1.45-1.47 s at the clamp, and the sampled
# multi-member negated-class axis measures ~1.6-1.65 s in its
# single-range and enumerated spellings ("[^c-z]", "[^cde]",
# "[^C-Z]", "[^cd]") and ~1.8 s in its range+literal-mix
# spellings ("[^c-e9]", "[^9c-e]", "[^c-e0]", "[^cd-e9]") — the
# axis's sampled top: the mix defeats the single-RANGE charset
# compilation that holds "[^c-z]" at ~1.63 s (same venue, stable
# across passes; the single-literal negation "[^c]" compiles to
# the engine's cheap single-op path, ~0.87 s — the atom-cap note
# above shows the same split) — the negated-class samples beat the
# range-spelling samples ON THIS HOST in this same venue, so no
# measured constant is stated as the family's ceiling: the ceiling
# is spelling-dependent with no stated supremum, and the
# atom-spelling cap, not a measured figure, is the bound — the
# model's own "spelling-dependent, not O(1)" stance showing up
# inside one admitted family. The group
# alternatives must MATCH the saturated source: non-matching ones
# ("(x|y)" over aab-saturation) fail at the group before any span
# work and measure ~0.000 s, hiding the family's true cost. The
# bar-free arithmetic maximum "aab[a-z0-9]*aabaabaabaabz" measures
# 0.05 s / 0.22 s / 0.88 s (x~4 per doubling — quadratic) and the
# post-token runner-up "aab[a-z0-9]*(az|q)" (W = 12)
# 0.07 s / 0.28 s / 1.11 s in the same venue: the raw char-count
# walk over-prices a literal continuation (it usually fails at its
# first char) relative to a grouped one (both alternatives are
# always tried), a conservative-direction gap between the element
# counts and the engine, consistent with the three-way tie. For
# scale: the pre-token-bar shape at the SATURATED walk, which the
# branch-wide weight refuses ("aab(a|a)[a-z0-9]*aabaabaabaabz",
# weighted walk 26), measured 1.77 s — 2.0x its admitted bar-free
# twin, right where (1+g) arithmetic puts it, and INSIDE the
# family's sampled spread: the admitted range+literal-mix negated
# samples above measure ~1.8 s, ABOVE this refused shape. An
# admitted spelling out-measuring a refused shape is the model
# working as stated — the walk weight bounds the cost CLASS
# (bounded quadratic at the clamp), not a total ordering of
# shapes. Baselines: ~0.1 s
# for the common leading-literal hint ("memcpy.*len"), ~0.2 s for
# the tail-free minimum-period span ("aab.*z"). The ceiling is PER
# HINT EVALUATION: the recompute runs every bug-pattern hint
# against each fold row, so a hostile model's pattern list
# multiplies it by the list length — a 40-pattern list built
# entirely from atom-varied admitted-worst shapes through ONE
# ``domain_slice_hash`` call is bounded and LINEAR in list length,
# not sub-second (each run tracks 40 x the concurrently measured
# per-hint figure: the measured-worst pre-token family sampled
# ~56 s at its ~1.4 s per-hint figure, the runner-up family's
# recorded samples span ~45-75 s as host load varied, the
# arithmetic-worst family ~36 s at its lower ~0.9 s per-hint
# figure; the patterns-per-model cap that would bound the
# multiplier is a deliberate non-goal here).
# The single-hint ceiling is wall-clock-pinned with CI margin by
# ``test_worst_admitted_shape_cost_bounded`` (which CONSTRUCTS the
# three tying shapes — the measured-worst pre-token family, the
# bar-free arithmetic maximum, and the post-token runner-up — from
# the constants above, asserts each weight as arithmetic over
# those constants, and pins all three through one real pipeline
# call); the list-length multiplier stays prose (a 40x
# admitted-worst wall test would dominate the battery);
# ``test_hostile_pattern_list_slice_hash_bounded``
# pins the other side — a 40-list of REFUSED shapes stays prompt.
# Past the clamp the hint is evaluated as a plain substring over
# the FULL source (linear two-way search — it does not share the
# quadratic floor). The decision depends only on ``len(source)``:
# deterministic, interpreter-independent.
_MAX_REGEX_SOURCE_CHARS = 16384

# Once-per-hint demotion log, bounded. A hostile model can mint
# unlimited DISTINCT hostile hints, and the guard runs per function
# x per bug pattern (prompt assembly AND every fold-row slice
# recompute), so an unbounded seen-set — or per-call logging — hands
# that model a memory / log-volume lever. Both directions: higher
# keeps more distinct offenders operator-visible per process; lower
# silences later distinct offenders sooner. The cap gates ONLY the
# log line — the guard's refusal decision never depends on it. 64
# covers every observed model's bug-pattern count (study emits tens
# of patterns) with headroom. (The lru cache on the guard already
# keeps repeat calls for a cached hint from re-reaching the logger;
# this set is what keeps the dedupe across cache evictions, and the
# cap is what bounds the set itself.)
_MAX_DEMOTED_HINTS_LOGGED = 64
_demoted_hints_logged: set[str] = set()

# Log-excerpt bound for a demoted hint. Both directions: higher shows
# more of a long offender per warning line; lower keeps the line
# short. Hints reaching the log are already <= _MAX_GREP_HINT_CHARS
# raw (the length gate refuses silently before any shape check), so
# this only trims escape-expanded text. 120 keeps the whole warning
# within a single conventional log line.
_MAX_DEMOTED_HINT_EXCERPT_CHARS = 120

# A trailing PARTIAL escape at the excerpt cut point: "\", "\x" or
# "\u"/"\U" with fewer hex digits than escape_nonprintable emits
# (\xHH, \uHHHH, \UHHHHHHHH — lowercase hex). A complete escape does
# not match (the anchor requires end-of-string right after the short
# hex run).
_PARTIAL_ESCAPE_AT_CUT_RE = re.compile(
    r"\\(?:x[0-9a-f]?|u[0-9a-f]{0,3}|U[0-9a-f]{0,7})?\Z",
)


def _log_hint_demotion(grep_hint: str) -> None:
    """Warn once per distinct refused hint.

    Repeat refusals of the same hint are silent (the first line
    already names it), and distinct offenders beyond the cap drop to
    debug — the fold recompute re-checks every hint per journal row,
    so anything louder is a log flood on a single planted model.
    Hint text is target-derived LLM output: escape before logging.
    """
    from core.security.log_sanitisation import escape_nonprintable

    if grep_hint in _demoted_hints_logged:
        return
    if len(_demoted_hints_logged) >= _MAX_DEMOTED_HINTS_LOGGED:
        logger.debug(
            "domain-model grep hint demoted to substring matching "
            "(demotion-log cap reached; hint not recorded)",
        )
        return
    _demoted_hints_logged.add(grep_hint)
    excerpt = escape_nonprintable(grep_hint)
    if len(excerpt) > _MAX_DEMOTED_HINT_EXCERPT_CHARS:
        # Cutting the ESCAPED text can split a \xHH / \uHHHH /
        # \UHHHHHHHH sequence mid-escape; drop any trailing partial
        # escape after the cut and mark the elision. (A printable
        # literal that merely LOOKS like a partial escape at the cut
        # point is over-trimmed — cosmetic, on an already-elided log
        # excerpt.)
        excerpt = _PARTIAL_ESCAPE_AT_CUT_RE.sub(
            "", excerpt[:_MAX_DEMOTED_HINT_EXCERPT_CHARS],
        ) + "…"
    logger.warning(
        "domain-model grep hint refused as a regex (super-linear "
        "risk) — demoted to substring matching: %s",
        excerpt,
    )


def _string_period(text: str) -> int:
    """Smallest shift at which ``text`` overlaps itself.

    ``len(text)`` when there is no proper self-overlap ("abc" -> 3),
    smaller when there is ("abab" -> 2, "aaa" -> 1), 0 for the empty
    string. Quadratic scan — fine at hint scale (the length cap runs
    before any caller).
    """
    for shift in range(1, len(text) + 1):
        if text[shift:] == text[: len(text) - shift]:
            return shift
    return 0


def _hint_top_level_branches(grep_hint: str) -> list[str] | None:
    """Split a hint on TOP-LEVEL alternation bars only.

    A raw ``str.split("|")`` mis-attributed group-internal
    alternation: "(a|aab).*z" donated the strong-prefix fragment
    "aab).*z" to the period rule while the pattern's real single
    branch has no literal prefix at all — flipping a refusal into an
    admission (0.95 s in the measurement venue at
    ``_HINT_QUANTIFIED_GROUP_RE``; exactly the density-1 class the
    restart-density rule exists to refuse). Prepending a benign
    literal branch or moving the alternation into a character class
    rebuilds the same bypass around any narrower fix
    ("aabX|(a|aab).*z" 0.72 s, "aab|[]|aab]*z" 1.7 s, "[q|aab]*z"
    1.8 s — same venue), so the split itself must be
    structure-aware: this scanner tracks ``\\``-escapes, group
    depth, and character classes (including the leading
    "]"-as-member rule) so a bar inside any of them never splits a
    branch. One linear pass, no recursion, no compile probe — the
    verdict stays deterministic and interpreter-independent.

    Returns None when the scan sees unbalanced structure (a stray
    ")" at depth 0, an unclosed group, or an unterminated class):
    the caller refuses — fail toward the substring fallback, which
    is also where ``re.error`` would send such a pattern had it been
    compiled.
    """
    branches: list[str] = []
    start = 0
    depth = 0
    in_class = False
    class_body_start = -1
    i = 0
    n = len(grep_hint)
    while i < n:
        ch = grep_hint[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]" and i != class_body_start:
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            class_body_start = i + 1
            if grep_hint[class_body_start : class_body_start + 1] == "^":
                class_body_start += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return None
            depth -= 1
        elif ch == "|" and depth == 0:
            branches.append(grep_hint[start:i])
            start = i + 1
        i += 1
    if depth != 0 or in_class:
        return None
    branches.append(grep_hint[start:])
    return branches


def _hint_grouped_alternation_bars(grep_hint: str) -> int:
    """Count alternation bars that sit INSIDE a group.

    Same linear escape/class scan as ``_hint_top_level_branches`` —
    a paren-depth-only count is bypassable (an escaped or
    class-member ")" silently closes the depth, hiding every later
    real bar behind it), so depth moves only on true group parens.
    Escaped and class-member bars are literal members, not path
    splits, and do not count. Unlike the splitter this never fails:
    a stray ")" clamps at depth zero and unterminated structure
    still yields a defined count — refusal on unbalance belongs to
    the splitter, which runs only on repeat-bearing hints, so
    repeat-free unbalanced goldens ("(frame_checksum") keep their
    historical ADMIT (the truly malformed are ``re.error`` and
    demote at compile regardless).
    """
    bars = 0
    depth = 0
    in_class = False
    class_body_start = -1
    i = 0
    n = len(grep_hint)
    while i < n:
        ch = grep_hint[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]" and i != class_body_start:
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            class_body_start = i + 1
            if grep_hint[class_body_start : class_body_start + 1] == "^":
                class_body_start += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
        elif ch == "|" and depth > 0:
            bars += 1
        i += 1
    return bars


def _hint_repeat_atom_chars(branch: str, token_start: int) -> int:
    """Spelled length of the atom a repeat token at ``token_start`` repeats.

    The branch splitter's escape/class scan, run forward up to the
    token: a class atom spans from its true "[" opener to the "]"
    that closes it (a nearest-"[" backward scan would let a
    class-member "[" understate an escape-heavy spelling), an escape
    atom spells 2, anything else 1 — and 0 when nothing precedes the
    token (the period rule refuses such a branch regardless).
    A multi-character escape ("\\x63") scans as the two-char escape
    pair plus ordinary literals, so 2 is returned only when the
    escape pair itself ends directly at the token ("\\D*"); a token
    right after the trailing literals ("\\x63*") sees the last
    literal and spells 1. Either way the repeated atom is a single
    codepoint whose per-span-char test cost is a literal's — exactly
    what the spelling bound exists to pin. A token that is itself a class
    member never reaches a repeat semantically; whatever this
    returns for it can only demote.
    """
    closed_class_start = -1
    closed_class_end = -1
    escape_end = -1
    in_class = False
    class_start = -1
    class_body_start = -1
    i = 0
    while i < token_start:
        ch = branch[i]
        if ch == "\\":
            escape_end = i + 1
            i += 2
            continue
        if in_class:
            if ch == "]" and i != class_body_start:
                in_class = False
                closed_class_start = class_start
                closed_class_end = i
            i += 1
            continue
        if ch == "[":
            in_class = True
            class_start = i
            class_body_start = i + 1
            if branch[class_body_start : class_body_start + 1] == "^":
                class_body_start += 1
        i += 1
    if token_start == 0:
        return 0
    if closed_class_end == token_start - 1:
        return token_start - closed_class_start
    if escape_end == token_start - 1:
        return 2
    return 1


def _hint_repeat_prefix_admissible(grep_hint: str) -> bool:
    """Restart-density and per-backtrack-cost gate for unbounded repeats.

    Every top-level alternation branch that carries an unbounded
    repeat token must satisfy all three repeat-path bounds of the
    cost model (stated in full at ``_MAX_REGEX_SOURCE_CHARS``):

    * open with a literal run whose engine-folded period is at least
      ``_MIN_HINT_PREFIX_PERIOD`` — the mandatory literal is what
      keeps a failing search from restarting the span at every
      source position (the model's n/p restart term);
    * carry a continuation walk (character count of everything
      after the token, weighted by the bars in the WHOLE branch) of
      at most ``_MAX_HINT_REPEAT_CONTINUATION_WALK`` — the walk is
      what each backtracked span position may cost across every
      alternation path through the branch (the model's W factor,
      which prices the grouped-bar path multiplier on either side
      of the token; a long self-overlapping literal tail multiplies
      the quadratic term ~linearly in its length — the constants
      carry the measurements);
    * spell the repeated atom in at most
      ``_MAX_HINT_REPEAT_ATOM_CHARS`` characters — the atom's
      spelling bounds the per-span-char test constant.

    Branches come from the structure-aware top-level split
    (``_hint_top_level_branches``): a branch here is a real
    alternative of the whole pattern, so its leading literal run is
    genuinely mandatory for any match through that branch — a raw
    ``"|"`` split instead donated group-internal fragments whose
    prefixes the engine never requires (the bypass documented on the
    scanner). Unbalanced structure refuses (None from the scanner).
    Hints with no unbounded repeat anywhere are exempt without any
    structure scan, so alternations of plain literals — and
    unbalanced parens in repeat-free hints — stay regexes, exactly
    as before.
    """
    if _HINT_UNBOUNDED_REPEAT_RE.search(grep_hint) is None:
        return True
    branches = _hint_top_level_branches(grep_hint)
    if branches is None:
        return False
    for branch in branches:
        repeat = _HINT_UNBOUNDED_REPEAT_RE.search(branch)
        if repeat is None:
            # Includes the EMPTY top-level branch ("|aab.*w"): an
            # empty alternative matches at every position, so every
            # search through it succeeds immediately — safe by
            # construction, nothing to bound.
            continue
        prefix_match = _HINT_LITERAL_PREFIX_RE.match(branch)
        prefix = prefix_match.group() if prefix_match else ""
        if _string_period(_engine_fold(prefix)) < _MIN_HINT_PREFIX_PERIOD:
            return False
        # Walk and atom are anchored on the FIRST unbounded-capable
        # token: the repeat budget already caps the hint at one
        # repeat token in total, so the first is the only live one
        # (a second occurrence means the budget refused the hint
        # before this gate ran).
        continuation = branch[repeat.end():]
        # Weighted by bars in the WHOLE branch, not just the
        # continuation: a grouped bar BEFORE the token makes sre
        # re-run the span AND its backtrack walk once per
        # alternative, exactly like a bar after it — weighting only
        # the continuation's own bars let the one admitted bar ride
        # in front of a full-budget tail at bare weight, an
        # unpriced 2x of its bar-free twin — the weight bounds the
        # cost class, not a total ordering of shapes (figures at
        # the constant). Raw
        # count (asymmetry note at the constant): over-counts only,
        # i.e. demote-only.
        if (
            (1 + branch.count("|")) * len(continuation)
            > _MAX_HINT_REPEAT_CONTINUATION_WALK
        ):
            return False
        if (
            _hint_repeat_atom_chars(branch, repeat.start())
            > _MAX_HINT_REPEAT_ATOM_CHARS
        ):
            return False
    return True


@lru_cache(maxsize=_PATTERN_CACHE_MAX)
def _grep_hint_compilable(grep_hint: str) -> bool:
    """Whether an LLM-derived grep hint may be compiled as a regex.

    ``what_to_grep`` is LLM output derived from the untrusted target,
    and it runs per-function over source text — at prompt assembly
    AND per journal row in the gap fold's slice recompute
    (``domain_slice_hash`` → ``domain_bug_patterns``) — so a
    catastrophic-backtracking pattern can pin a review worker or the
    whole fold, and only ``re.error`` was caught originally.
    Refusal layers: the length cap, the shared ``looks_redos``
    shapes, the wider super-linear shape scan
    (``_HINT_SUPERLINEAR_RE``), the body-blind quantified-group
    refusal (``_HINT_QUANTIFIED_GROUP_RE``), the backreference
    refusal (``_HINT_BACKREF_RE`` — one repeat token, no quantified
    group, still super-linear), the repeat budget
    (``_MAX_GREP_HINT_REPEATS``) for the ungrouped chains no shape
    rule can see, the grouped-alternation bar budget
    (``_MAX_HINT_GROUPED_ALTERNATION_BARS``) that caps one match
    attempt's path count (the repeat-free alternation stack is
    exponential with ZERO repeat tokens — invisible to every
    repeat-anchored rule), and the restart-density gate
    (``_hint_repeat_prefix_admissible``) requiring a low-self-overlap
    literal prefix — under the engine's own IGNORECASE character
    equivalence, per TRUE top-level alternation branch — in front of
    any unbounded repeat, plus a bounded continuation walk and span-
    atom spelling behind it: the shapes the other rules admit are
    quadratic on a failing search; the prefix bounds how OFTEN the
    engine restarts the span, the walk and atom bound what each
    backtracked position may COST, and the source clamp bounds each
    restart (the full cost model is stated at
    ``_MAX_REGEX_SOURCE_CHARS``). Refused hints fall back to the plain substring
    match (the same degradation already used for non-compiling
    hints): fail toward less selection power, never toward unbounded
    matching cost. Dangerous-shape refusals log a demotion
    (``_log_hint_demotion``); the length-cap refusal stays silent as
    before (long literal phrases are a producer-verbosity signal,
    not a hostility signal). Refusal is shape-based only — no
    compile probe — so the decision AND the log line are identical
    on every supported interpreter.

    Cached (pure function of the hint): the shape scans re-ran for
    every hint on every function scored. The cache means the
    demotion log fires on cache MISSES only — correct for the log's
    once-per-distinct-hint contract — and neither the decision nor
    its slice-hash consumers ever depend on cache state.
    """
    from core.security.prompt_input_preflight import looks_redos

    if len(grep_hint) > _MAX_GREP_HINT_CHARS:
        return False
    if (
        looks_redos(grep_hint)
        or _HINT_SUPERLINEAR_RE.search(grep_hint) is not None
        or _HINT_QUANTIFIED_GROUP_RE.search(grep_hint) is not None
        or _HINT_BACKREF_RE.search(grep_hint) is not None
        or len(_HINT_REPEAT_TOKEN_RE.findall(grep_hint))
        > _MAX_GREP_HINT_REPEATS
        or _hint_grouped_alternation_bars(grep_hint)
        > _MAX_HINT_GROUPED_ALTERNATION_BARS
        or not _hint_repeat_prefix_admissible(grep_hint)
    ):
        # Deliberately NOT compile-gated: whether a refused shape
        # would even have compiled is Python-version-dependent
        # ("sg++" is re.error on 3.10 but a possessive quantifier on
        # 3.11+), and the guard's observable behaviour must not vary
        # by interpreter. Every dangerous-shape refusal logs.
        _log_hint_demotion(grep_hint)
        return False
    return True


@lru_cache(maxsize=_PATTERN_CACHE_MAX)
def _grep_hint_pattern(grep_hint: str) -> re.Pattern[str] | None:
    """Compiled ``what_to_grep`` matcher, or None when it won't compile.

    Byte-equivalent to the historical inline
    ``re.search(grep_hint, source, re.IGNORECASE)``: ``re.search``
    compiles then searches, and ``re.error`` is a compile-time
    failure, so mapping it to None here preserves the exact substring
    fallback at the call site. Cached because the interpreter's own
    regex cache (512 patterns) is evicted wholesale by a model with
    thousands of distinct hints, recompiling all of them for every
    function scored.
    """
    try:
        return re.compile(grep_hint, re.IGNORECASE)
    except re.error:
        return None


@lru_cache(maxsize=_PATTERN_CACHE_MAX)
def _word_boundary_pattern(word: str) -> re.Pattern[str]:
    """``\\b<literal>\\b`` matcher for a paired-operation name.

    Same interpreter-cache-thrash rationale as
    :func:`_grep_hint_pattern` — paired-operation names are model
    content, re-matched against every function's source.
    """
    return re.compile(r"\b" + re.escape(word) + r"\b")


def domain_bug_patterns(
    out_dir: Path,
    file_path: str,
    function_name: str,
    source: str = "",
    *,
    _memo: _DomainSliceMemo | None = None,
) -> str | None:
    """Bug-pattern prompt block filtered to the function under review.

    A pattern is included when its ``what_to_grep`` hint matches the
    function source (strong signal) or its relevance score clears the
    same >1.0 threshold the other bridge functions use.  With no
    source text available every pattern is included (nothing to
    filter on).  Returns None when nothing selects.

    ``_memo`` (private): a prebuilt slice memo for the discovered
    model — the fingerprint path passes it so per-item scoring
    statics are derived once per model content.
    """
    model = _memo.model if _memo is not None else _find_domain_model(out_dir)
    if not model:
        return None
    memo = _memo if _memo is not None else _DomainSliceMemo(model)
    bug_patterns = model.get("bug_patterns") or []
    if not isinstance(bug_patterns, list) or not bug_patterns:
        return None

    selected: list[dict[str, Any]] = []
    for bp in bug_patterns:
        if not isinstance(bp, dict):
            continue
        hit = False
        raw_hint = bp.get("what_to_grep")
        # Model JSON is external input: a non-str hint (int, list,
        # dict, bool) is schema drift, not a matchable pattern — treat
        # it as an absent hint (fail toward no-hint; the relevance
        # fallback below still applies) instead of crashing pattern
        # selection on .strip().
        grep_hint = raw_hint.strip() if isinstance(raw_hint, str) else ""
        if source and grep_hint:
            # The guard runs FIRST so a dangerous shape logs its
            # demotion regardless of source size; the source clamp
            # then bounds what the admitted shapes may cost (both
            # rationales at the constants).
            pattern = (
                _grep_hint_pattern(grep_hint)
                if (
                    _grep_hint_compilable(grep_hint)
                    and len(source) <= _MAX_REGEX_SOURCE_CHARS
                )
                else None
            )
            if pattern is None:
                # Refused (shape/length/source-clamp) or
                # non-compiling hint: the plain substring fallback,
                # exactly as before.
                hit = grep_hint.lower() in source.lower()
            else:
                hit = pattern.search(source) is not None
        if not hit and source:
            hit = memo.score(bp, file_path, function_name, source) > 1.0
        if hit or not source:
            selected.append(bp)
    if not selected:
        return None

    parts = ["### Bug Patterns (from study)\n"]
    parts.append(
        "These are common mistake classes for this subsystem. "
        "Check whether the function under review matches any:\n",
    )
    for bp in selected:
        desc = bp.get("description", bp.get("id", ""))
        parts.append(f"- {desc}")
        grep_hint = bp.get("what_to_grep", "")
        # Same non-str drift gate as selection: never render a
        # non-str value as a grep suggestion.
        if isinstance(grep_hint, str) and grep_hint:
            parts.append(f"  - Grep: `{grep_hint}`")
    return "\n".join(parts)


def domain_key_files(out_dir: Path) -> set[str]:
    """Paths the domain model marks as key files.

    Consumed by the audit orchestrator's priority boost (a gap whose
    file is a key file gets ``_KEY_FILE_PRIORITY_BOOST``).  Entries
    may be dicts (``{"path": ..., "reason": ...}``) or bare strings.
    Returns an empty set when no model or no key files.
    """
    model = _find_domain_model(out_dir)
    if not model:
        return set()
    out: set[str] = set()
    for kf in model.get("key_files") or []:
        if isinstance(kf, dict):
            p = kf.get("path") or kf.get("file") or ""
        elif isinstance(kf, str):
            p = kf
        else:
            continue
        if p:
            out.add(str(p))
    return out


def _guard_in_scope(inv: dict[str, Any], file_path: str) -> bool:
    """Whether a guard-role invariant applies to *file_path*.

    Scope evidence, in order: explicit ``files``/``scope`` lists, a
    ``file`` field, and file paths inside ``evidence`` entries.  An
    invariant with no scope information is treated as global (fail
    open) — matching the ``role`` default of "boost" in consumers.
    """
    scopes: list[str] = []
    for key in ("files", "scope"):
        v = inv.get(key)
        if isinstance(v, (list, tuple)):
            scopes.extend(str(x) for x in v if x)
        elif isinstance(v, str) and v:
            scopes.append(v)
    if inv.get("file"):
        scopes.append(str(inv["file"]))
    for ev in inv.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("file"):
            scopes.append(str(ev["file"]))
        elif isinstance(ev, str) and ev.strip():
            # strip() guard: a whitespace-only evidence string (a
            # supported schema shape from LLM-authored models) makes
            # split() return [] and the [0] index raise.
            head = ev.split()[0].split(":")[0]
            if "/" in head or "." in PurePosixPath(head).name:
                scopes.append(head)
    if not scopes:
        return True
    return any(_paths_match(file_path, s) for s in scopes)



def _tier_tag(entry: dict) -> str:
    """Render an entry's provenance tier for prompt injection.

    ``verbatim`` / ``mechanical`` carry verified receipts; everything
    else — including entries with no provenance stamp at all (fail
    closed) — is an unverified LLM summary and must read as a hint to
    check, never as established fact.
    """
    if str(entry.get("state") or "") == "stale":
        # Quarantined by the staleness check — evidence drifted since
        # the receipt was stamped.
        return "[stale-unverified]"
    tier = str(entry.get("provenance") or "")
    if tier in ("verbatim", "mechanical"):
        return f"[{tier}]"
    return "[unverified]"


def _drifted_entries(model: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Dict-shaped entries of ``model[key]``, WARN-skipping the rest.

    Raw domain-model JSON is loaded without the DomainModel drift
    loader, so schema-drifted records (strings, partial dicts) reach
    the prompt renderers. One bad record must degrade to a logged gap,
    never kill the whole domain-knowledge block: the consumers wrap
    this module in ``except Exception`` at DEBUG, so an escaped
    KeyError silently costs every receipt-backed study fact for the
    function under review.
    """
    raw = model.get(key) or []
    if not isinstance(raw, list):
        logger.warning(
            "domain-model %r is not a list — treated as empty "
            "(schema drift; domain knowledge for this key is lost "
            "until the model is regenerated)", key,
        )
        return []
    entries = [e for e in raw if isinstance(e, dict)]
    dropped = len(raw) - len(entries)
    if dropped:
        logger.warning(
            "domain-model %r: %d non-dict entr(y/ies) skipped from "
            "prompt injection (schema drift); %d remaining still "
            "render", key, dropped, len(entries),
        )
    return entries


def _entry_gap(kind: str, entry: dict[str, Any], missing: str) -> None:
    """Record one skipped drifted entry — a visible gap, never silence."""
    logger.warning(
        "domain-model %s entry missing %r — skipped from prompt "
        "injection (schema drift; the rest of the block still "
        "renders): %.120s", kind, missing, str(entry),
    )


_MEMO_UNSET = object()  # security block legitimately memoises to None


class _DomainSliceMemo:
    """Model-wide (function-independent) slice-render precomputation.

    One instance per domain-model CONTENT (:func:`_slice_memo_for`):
    the drift-filtered section lists, per-item scoring statics, the
    concept→invariants join, and the security-context render depend
    only on the model, yet were re-derived for every function whose
    prompt slice the journal writer or the gap fold fingerprinted —
    ~0.27 s per function at a 7 MB model, all of it model-side work.

    ``model`` is whatever dict the constructor received. The two
    construction sites differ deliberately:

    * the renderers' per-call fallback (``_memo`` omitted) wraps the
      caller's own model dict — single call, no lifetime beyond it;
    * the shared store (:func:`_slice_memo_for`) constructs the memo
      over a PRIVATE snapshot it parses itself, so no caller-held
      object is ever pinned here and later in-place mutation of any
      caller's model cannot reach a stored memo. Renderers that read
      ``_memo.model`` directly (bug patterns, security-context lines)
      therefore read insert-time content on a store hit, never a live
      object.

    Everything here is lazy: fields are built on first use, so a
    derivation that raises on a drifted model raises at the same call
    site as the uncached path (the fingerprint's callers map any
    exception to "no stamp" / "no match" — fail toward re-review,
    never toward a fingerprint of content that never rendered).
    Laziness is sound on the store path because the snapshot never
    mutates: first-use derivations see the same bytes construction
    did.

    Concurrency: plain dict/attribute fills — racing fillers can
    duplicate work but always store equal values, because every
    derivation is a pure function of the model content.
    """

    __slots__ = ("model", "_drifted", "_statics", "_invs_by_concept",
                 "_security_block")

    def __init__(self, model: dict[str, Any]) -> None:
        self.model = model
        self._drifted: dict[str, list[dict[str, Any]]] = {}
        self._statics: dict[int, tuple[dict[str, Any], _ItemStatics]] = {}
        self._invs_by_concept: (
            dict[str, list[dict[str, Any]]] | None) = None
        self._security_block: Any = _MEMO_UNSET

    def drifted(self, key: str) -> list[dict[str, Any]]:
        """``_drifted_entries(model, key)``, computed once per key.

        Callers treat the returned list as read-only — it is shared
        by every fingerprint pass over this model content.
        """
        entries = self._drifted.get(key)
        if entries is None:
            entries = _drifted_entries(self.model, key)
            self._drifted[key] = entries
        return entries

    def statics_for(self, item: dict[str, Any]) -> _ItemStatics:
        """The item's scoring statics, computed once per item.

        Keyed by id(item), made sound BY CONSTRUCTION rather than by
        reachability reasoning: each entry stores the ``(item,
        statics)`` PAIR, so the cache itself holds a strong reference
        to the exact dict it keyed — that object can never be
        collected while its entry lives, so its id can never be
        recycled onto a different dict. A hit is served only after
        the identity check ``stored is item`` confirms the key still
        names the same object; anything else recomputes and re-pins.
        (id alone was NOT sufficient: an item reachable only through
        a live model — never through memo-held structures — could be
        replaced in place, freed, and its id handed to a new dict.)
        """
        entry = self._statics.get(id(item))
        if entry is not None and entry[0] is item:
            return entry[1]
        st = _ItemStatics(item)
        self._statics[id(item)] = (item, st)
        return st

    def score(
        self,
        item: dict[str, Any],
        file_path: str,
        function_name: str,
        source: str,
    ) -> float:
        """:func:`_relevance_score` with memoised statics."""
        return _relevance_score(
            item, file_path, function_name, source,
            statics=self.statics_for(item),
        )

    def invs_by_concept(self) -> dict[str, list[dict[str, Any]]]:
        """Top-level invariants joined by concept id, computed once."""
        joined = self._invs_by_concept
        if joined is None:
            joined = {}
            for inv in self.drifted("invariants"):
                cid = str(inv.get("concept") or "")
                if cid:
                    joined.setdefault(cid, []).append(inv)
            self._invs_by_concept = joined
        return joined

    def security_block(self) -> str | None:
        """:func:`_render_security_context`, computed once."""
        if self._security_block is _MEMO_UNSET:
            self._security_block = _render_security_context(self.model)
        return self._security_block


# Memo store: domain-model content digest → memo. Keyed by CONTENT,
# never object identity: the parsed model dict is not provably
# immutable (the loader's lru can evict and re-parse, and nothing
# enforces read-only on consumers), so an id()-keyed store could
# serve derivations for content the object no longer holds — and a
# stale slice fingerprint silently reuses review verdicts whose
# prompt briefing changed. The digest costs one canonical dumps per
# fingerprint call (~30 ms at a 7 MB model): the price of
# unconditional byte-fidelity. Keying by object identity would save
# that, but only under an immutability guarantee no current contract
# provides.
#
# Content keying alone is NOT enough: a stored memo must also never
# hold the caller's dict. Two content-equal objects can exist at once
# (the same bytes parsed for two run dirs, or the parse lru evicting
# and re-parsing a path the memo outlives), and once the FIRST object
# mutates in place, a later lookup through the OTHER object still
# digests to the stored key — a memo pinning the first object would
# then mix its mutated fields into a hit that the key says is the
# original content. So a miss parses the memo's model back out of the
# exact canonical bytes the key digests (one loads per NEW content;
# hits never pay it): the stored memo is a pure function of its key,
# and a hit renders byte-identically to a cold compute of the
# looked-up content no matter what any caller-held object did since.
# (Renderers were verified key-order-insensitive: every model access
# is by explicit key, so the canonical form renders identically to
# the loader's parse of the same bytes.)
#
# Bound: the number of distinct model CONTENTS plausibly interleaving
# in one process — not coupled to _load_cached's maxsize (the two
# evict independently; parse-only consumers such as domain_key_files
# advance the parse lru without ever touching this store, and since
# the memo owns a private snapshot, a parse-lru eviction can never
# invalidate it). Larger holds model-scale snapshots plus derived
# data (statics roughly mirror the model's text) for contents no
# longer in play; smaller rebuilds the memo when fingerprint passes
# alternate across more contents than the bound (correctness
# unaffected either way — a miss only recomputes). Two-direction
# regression tests ride the equivalence suite.
_SLICE_MEMO_MAX = 4
_slice_memos: OrderedDict[str, _DomainSliceMemo] = OrderedDict()
_slice_memo_lock = threading.Lock()


def _model_content_canonical(model: dict[str, Any]) -> str:
    """Canonical byte form of a parsed domain model (key material)."""
    from core.json.utils import dumps_canonical
    return dumps_canonical(model)


def _slice_memo_for(model: dict[str, Any]) -> _DomainSliceMemo:
    """The shared slice memo for *model*'s current content.

    On a miss the memo is built over ``json.loads`` of the canonical
    bytes — a private snapshot; the caller's *model* object is never
    stored (see the store comment above for why). Faithful because
    *model* is itself parsed JSON here (:func:`_find_domain_model` is
    the only route in), so the canonical form re-parses to equal
    content.
    """
    # Outside the lock: the dumps+digest is the dominant per-call cost.
    canonical = _model_content_canonical(model)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    with _slice_memo_lock:
        memo = _slice_memos.get(digest)
        if memo is None:
            memo = _DomainSliceMemo(json.loads(canonical))
            _slice_memos[digest] = memo
            while len(_slice_memos) > _SLICE_MEMO_MAX:
                _slice_memos.popitem(last=False)
        else:
            _slice_memos.move_to_end(digest)
    return memo


def domain_model_context(
    out_dir: Path,
    file_path: str,
    function_name: str,
    source: str = "",
    *,
    max_concepts: int = 5,
    max_invariants: int = 5,
    max_contracts: int = 3,
    include_sage: bool = True,
    _memo: _DomainSliceMemo | None = None,
) -> str | None:
    """Build a prompt block with relevant domain-model knowledge.

    Returns a formatted string ready for injection into the audit LLM
    prompt, or None if no relevant domain knowledge is available.

    ``include_sage=False`` renders the block from the domain model
    alone, skipping the SAGE cross-session recall section. Used by
    :func:`domain_slice_hash`, which must fingerprint only the
    deterministic domain-model-derived content — SAGE recall varies
    with session history, so hashing it would churn the fingerprint
    without the model changing.

    ``_memo`` (private): a prebuilt slice memo for the discovered
    model — the fingerprint path passes it so drift filtering and
    per-item scoring statics are derived once per model content.
    """
    model = _memo.model if _memo is not None else _find_domain_model(out_dir)
    if not model:
        return None
    memo = _memo if _memo is not None else _DomainSliceMemo(model)

    concepts = memo.drifted("concepts")
    invariants = memo.drifted("invariants")
    contracts = memo.drifted("contracts")

    sage_block = (
        _sage_recall_for_context(out_dir, file_path, function_name)
        if include_sage else None
    )

    if not concepts and not invariants and not contracts and not sage_block:
        return None

    scored_concepts = sorted(
        [(c, memo.score(c, file_path, function_name, source)) for c in concepts],
        key=lambda x: x[1],
        reverse=True,
    )
    scored_invariants = sorted(
        [(i, memo.score(i, file_path, function_name, source)) for i in invariants],
        key=lambda x: x[1],
        reverse=True,
    )
    scored_contracts = sorted(
        [(c, memo.score(c, file_path, function_name, source)) for c in contracts],
        key=lambda x: x[1],
        reverse=True,
    )

    relevant_concepts = [c for c, s in scored_concepts[:max_concepts] if s > 1.0]
    relevant_invariants = [i for i, s in scored_invariants[:max_invariants] if s > 1.0]
    # Contracts are per-function authority: a same-named function in
    # another file must not receive this file's contract (qualified
    # identity — the model's merge keys contracts by (function, file)).
    # File-less contracts pass; the renderer shows their (missing)
    # file and tier tag.
    relevant_contracts = [
        c for c, s in scored_contracts[:max_contracts]
        if s > 1.0 and not (
            str(c.get("file") or "") and _file_gate_applies(file_path)
            and not _paths_match(file_path, str(c.get("file") or ""))
        )
    ]

    relevant_invariants = _add_derived_slots(
        relevant_invariants, scored_invariants)

    if (
        not relevant_concepts
        and not relevant_invariants
        and not relevant_contracts
        and not sage_block
    ):
        return None

    parts: list[str] = ["## Domain Knowledge (from /understand --study)\n"]
    parts.append(
        "Provenance: entries tagged [verbatim] or [mechanical] carry "
        "receipts verified against the source. Entries tagged "
        "[unverified] are LLM summaries WITHOUT verified receipts — "
        "treat them as context to check against the code, never as "
        "established fact, and never as the basis for a verdict.\n",
    )
    parts.extend(_security_context_lines(model))

    gaps = 0
    if relevant_concepts:
        parts.append("### Semantic Concepts\n")
        for c in relevant_concepts:
            cid = str(c.get("id") or "")
            if not cid:
                _entry_gap("concept", c, "id")
                gaps += 1
                continue
            conf = c.get("confidence", "inferred")
            parts.append(
                f"- **{cid}** {_tier_tag(c)} [{conf}]: "
                f"{c.get('description', '')}"
            )

    if relevant_invariants:
        parts.append("\n### Invariants\n")
        for i in relevant_invariants:
            iid = str(i.get("id") or "")
            if not iid:
                _entry_gap("invariant", i, "id")
                gaps += 1
                continue
            parts.append(
                f"- **{iid}** {_tier_tag(i)}: {i.get('statement', '')}"
            )
            neg = i.get("negation", "")
            if neg:
                parts.append(f"  - Violation: {neg}")
            rule = i.get("mechanical_rule")
            if rule:
                parts.append(f"  - Mechanical check: {rule}")

    if relevant_contracts:
        parts.append("\n### Contracts\n")
        for c in relevant_contracts:
            cfn = str(c.get("function") or "")
            if not cfn:
                _entry_gap("contract", c, "function")
                gaps += 1
                continue
            parts.append(
                f"- **{cfn}** {_tier_tag(c)} ({c.get('file', '')})"
            )
            if c.get("when"):
                parts.append(f"  - When: {c['when']}")
            if c.get("input_semantics"):
                parts.append(f"  - Input: {c['input_semantics']}")
            if c.get("output_semantics"):
                parts.append(f"  - Output: {c['output_semantics']}")
            if c.get("ownership_transfer"):
                parts.append(f"  - Ownership: {c['ownership_transfer']}")
            if c.get("implication"):
                parts.append(f"  - Implication: {c['implication']}")

    bug_patterns = memo.drifted("bug_patterns")
    if bug_patterns:
        parts.append("\n### Bug Patterns (from study)\n")
        parts.append(
            "These are common mistake classes for this subsystem. "
            "Check whether the function under review matches any:\n",
        )
        for bp in bug_patterns:
            desc = bp.get("description", bp.get("id", ""))
            parts.append(f"- {desc}")
            grep_hint = bp.get("what_to_grep", "")
            # Same non-str drift gate as domain_bug_patterns: never
            # render a non-str value as a grep suggestion.
            if isinstance(grep_hint, str) and grep_hint:
                parts.append(f"  - Grep: `{grep_hint}`")

    if gaps:
        # The prompt-visible half of the gap record: reviewers (and
        # prompt-dump debugging) see that study knowledge was partial,
        # instead of a silently thinner block.
        parts.append(
            f"\nNote: {gaps} schema-drifted domain-model entr(y/ies) "
            "were skipped; the knowledge above is complete except for "
            "those."
        )

    if sage_block:
        parts.append(sage_block)

    return "\n".join(parts)


def domain_slice_hash(
    out_dir: Path,
    file_path: str,
    function_name: str,
    source: str = "",
) -> str | None:
    """Content fingerprint of the per-function domain-model prompt slice.

    Hashes exactly the domain-model-derived blocks the audit context
    assembly (``core.audit.context.build_context``) injects for this
    function: the security-context block, the bug-pattern block, the
    dynamic primers, and — only when no primers rendered, mirroring
    the assembly's fallback — the domain-knowledge block. Composed by
    calling the SAME public renderers the assembly calls, so the
    fingerprint tracks what the prompt actually contains rather than
    a parallel re-derivation that could drift.

    Consumed by the review-journal writer (stamps each row with the
    slice its verdict was briefed under) and by the gap fold's
    context-staleness gate: a domain-model regeneration that leaves
    THIS function's injected slice byte-identical must not re-buy the
    function's verdict just because the whole-model hash moved.

    Deliberate exclusions — none of these is part of the whole-model
    invalidation key today either, so excluding them adds no reuse
    the old key would have refused:

    * the SAGE cross-session recall section (``include_sage=False``):
      session-history-dependent, not domain-model content;
    * the token-enforcement block: projected per FILE from
      entry-point sources (not per function), hint-tier steering
      context, and its renderer has the side effect of materialising
      the run's token map;
    * the external hypothesis-seed block (the review context's
      ``seed_hypotheses`` section, stamped onto gaps by
      ``core.audit.hypothesis_intake`` from run-local
      ``sibling-hypotheses.json`` artifacts): not domain-model
      content, and structurally out of reach of this gate anyway —
      seeds stamp gaps in the residual queue, while this fingerprint
      only ever adjudicates rows for ALREADY-covered functions; the
      designed lever for forcing a fresh review when a seed names a
      settled function is the ``--seed-rereview`` consent flag, not
      stamp invalidation. Tradeoff, both directions: excluding seeds
      means a reused verdict's briefing never saw a claim a fresh
      review would be shown (hint-tier only — seeds are never
      verdict weight, so the reuse loses steering, not evidence);
      including them would key the fingerprint on a run-local,
      externally-supplied artifact, so any seed-file delta — or its
      absence on the next run — would mismatch every stamp it
      touched, and a planted seed file would gain a cheap
      mass-re-review-spend lever over settled verdicts.

    Returns None when no domain model is discoverable — the caller
    then persists no stamp and the whole-model behaviour applies.
    A model that selects NOTHING for this function still hashes:
    "no block injected" is a comparable prompt state. Raises on
    renderer failure — callers treat any exception as "no stamp" /
    "no match" (fail toward re-review).

    Model-wide render work is served from the content-keyed slice
    memo (:func:`_slice_memo_for`): the journal writer and the gap
    fold call this once per FUNCTION against the same model, and
    without the memo every call re-derived the per-model parts from
    scratch. The memo is passed to the SAME public renderers, so the
    fingerprint's provenance (prompt content, not a parallel
    re-derivation) is unchanged.
    """
    model = _find_domain_model(out_dir)
    if model is None:
        return None
    memo = _slice_memo_for(model)

    primers = primers_from_domain_model(
        out_dir, file_path, function_name, source, _memo=memo,
    )
    slice_parts: dict[str, Any] = {
        "security": domain_security_context(out_dir, _memo=memo) or "",
        "bug_patterns": domain_bug_patterns(
            out_dir, file_path, function_name, source, _memo=memo,
        ) or "",
        # Order-sensitive on purpose: primer order is prompt content.
        "primers": list(primers),
    }
    if not primers:
        # Mirror build_context: the domain-knowledge block is only
        # injected when no dynamic primers rendered.
        slice_parts["model_context"] = domain_model_context(
            out_dir, file_path, function_name, source,
            include_sage=False, _memo=memo,
        ) or ""

    from core.json.utils import dumps_canonical
    canonical = dumps_canonical(slice_parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sage_recall_for_context(
    out_dir: Path,
    file_path: str,
    function_name: str,
    *,
    max_results: int = 3,
    min_confidence: float = 0.7,
) -> str | None:
    """Query SAGE for cross-session domain knowledge about a function.

    Supplements the local domain-model.json with knowledge accumulated
    across prior runs.  Returns a formatted prompt section or None.
    """
    try:
        from core.sage.hooks import _concepts_domain, _get_client
    except ImportError:
        return None

    client = _get_client()
    if client is None:
        return None

    target = _infer_repo_path(out_dir)
    if not target:
        return None

    domain = _concepts_domain(target)
    query = f"{function_name} {file_path}"

    try:
        results = client.query(
            query, domain_tag=domain,
            top_k=max_results, min_confidence=min_confidence,
        )
    except Exception:
        logger.debug("SAGE recall failed", exc_info=True)
        return None

    if not results:
        return None

    parts = ["\n### Cross-Session Knowledge (SAGE)\n"]
    for r in results:
        conf = r.get("confidence") or 0.0
        content = r.get("content") or ""
        first_line = content.split("\n", 1)[0][:200]  # line-model: SAGE memory content, display slice
        try:
            parts.append(f"- [{conf:.0%}] {first_line}")
        except (TypeError, ValueError):
            parts.append(f"- {first_line}")

    return "\n".join(parts) if len(parts) > 1 else None


def _infer_repo_path(out_dir: Path) -> str | None:
    """Infer the target repository path from a run's study-list.json."""
    candidates = [
        out_dir / "study-list.json",
        out_dir.parent / "study-list.json",
    ]
    from core.json import load_json
    for c in candidates:
        if c.is_file():
            data = load_json(c, max_bytes=_MAX_MODEL_BYTES)
            if not isinstance(data, dict):
                continue
            target = data.get("target", "")
            if target:
                return target
    return None


def primers_from_domain_model(
    out_dir: Path,
    file_path: str,
    function_name: str,
    source: str = "",
    *,
    _memo: _DomainSliceMemo | None = None,
) -> list[str]:
    """Generate dynamic review primers from study output.

    Unlike the fixed primers in strategy.py, these are derived from the
    actual domain model — they carry the specific invariants and contracts
    that study discovered for this codebase.  Each primer is an active
    review directive telling the LLM exactly what to check.

    All candidate primers are scored and ranked — contracts and paired
    operations naturally score highest (exact function match / direct
    source reference), so they are never crowded out by generic concepts.
    The relevance threshold (>1.0) is the only filter; no hard cap.

    ``_memo`` (private): a prebuilt slice memo for the discovered
    model — the fingerprint path passes it so drift filtering, the
    concept→invariants join, and per-item scoring statics are derived
    once per model content.

    Returns a list of primer strings (may be empty).
    """
    model = _memo.model if _memo is not None else _find_domain_model(out_dir)
    if not model:
        return []
    memo = _memo if _memo is not None else _DomainSliceMemo(model)

    candidates: list[tuple[float, str]] = []

    # --- Concepts (Concept.to_dict schema: id/description/evidence/...) ---
    # Two invariant shapes feed a concept's primer:
    #   (a) inline concept["invariants"] entries — plain strings or
    #       dicts (a shape core/audit constructs directly);
    #   (b) the model's TOP-LEVEL invariants list, joined by concept
    #       id (Invariant.concept) — the shape every study writer
    #       actually produces (Concept itself carries no invariants
    #       field, so a top-level join is what makes these primers
    #       reachable from real domain-model.json files).
    invs_by_concept = memo.invs_by_concept()
    for concept in memo.drifted("concepts"):
        cid = str(concept.get("id") or "")
        inv_list: list[Any] = list(concept.get("invariants") or [])
        inv_list.extend(invs_by_concept.get(cid, []))
        if not inv_list:
            continue
        score = memo.score(concept, file_path, function_name, source)
        if score <= 1.0:
            continue
        label = (cid or str(concept.get("name") or "?"))
        label = label.replace("_", " ").replace(".", " — ")
        lines = [f"DOMAIN-SPECIFIC: CONCEPT — {label}"]
        if concept.get("description"):
            lines.append(str(concept["description"]))
        lines.append("")
        lines.append(
            "Check each invariant against the source. Receipt-backed "
            "tiers ([verbatim]/[mechanical]) quote this codebase — a "
            "violation is a real bug; [unverified] entries are hints "
            "to check, never established facts."
        )
        for inv in inv_list:
            if isinstance(inv, str):
                # Bare-string invariants carry no provenance stamp —
                # fail closed to the unverified hint tier.
                stmt, tag = inv, _tier_tag({})
            elif isinstance(inv, dict):
                stmt = str(inv.get("statement") or inv.get("description") or "")
                tag = _tier_tag(inv)
            else:
                continue
            if not stmt:
                continue
            lines.append(f"- {tag} {stmt}")
        candidates.append((score, "\n".join(lines)))

    # --- Paired operations → check for unbalanced acquire/release ---
    paired = memo.drifted("paired_operations")
    if paired and source:
        source_lower = source.lower()
        relevant_pairs = []
        for po in paired:
            acq = po.get("acquire", "")
            rel = po.get("release", "")
            if (acq and _word_boundary_pattern(acq.lower()).search(source_lower)) or (rel and _word_boundary_pattern(rel.lower()).search(source_lower)):
                relevant_pairs.append(po)
        if relevant_pairs:
            score = 6.0 + len(relevant_pairs)
            lines = ["DOMAIN-SPECIFIC: PAIRED OPERATIONS"]
            lines.append(
                "This function touches paired acquire/release APIs. "
                "Every acquire must have a matching release on all paths "
                "(including error paths)."
            )
            lines.append("")
            for po in relevant_pairs:
                note = f" ({po['note']})" if po.get("note") else ""
                lines.append(
                    f"- {po.get('acquire', '?')} / "
                    f"{po.get('release', '?')} "
                    f"[{po.get('kind', '?')}]{note}"
                )
            candidates.append((score, "\n".join(lines)))

    # --- Top-level invariants (rich schema: id/statement/negation) ---
    top_invariants = memo.drifted("invariants")
    if top_invariants:
        scored = sorted(
            [
                (inv, memo.score(inv, file_path, function_name, source))
                for inv in top_invariants
            ],
            key=lambda x: x[1],
            reverse=True,
        )
        relevant_invs = [(inv, s) for inv, s in scored[:5] if s > 1.0]
        # Same derived-slot reserve as domain_model_context — this
        # primers path is what the review prompt actually uses when
        # primers exist, so the routing fix must live here too.
        _selected = _add_derived_slots(
            [inv for inv, _ in relevant_invs], scored)
        _score_by_id = {id(inv): s for inv, s in scored}
        relevant_invs = [
            (inv, _score_by_id.get(id(inv), 0.0)) for inv in _selected
        ]
        if relevant_invs:
            avg_score = sum(s for _, s in relevant_invs) / len(relevant_invs)
            lines = ["DOMAIN-SPECIFIC: INVARIANTS FROM STUDY"]
            lines.append(
                "These invariants come from /understand --study. "
                "Receipt-backed tiers ([verbatim]/[mechanical]) quote "
                "this codebase — a violation is a real bug. "
                "[unverified] entries are LLM inference (derived "
                "threat frames included): hints to check against the "
                "source, never established facts."
            )
            lines.append("")
            for inv, _ in relevant_invs:
                stmt = inv.get("statement") or inv.get("description", "")
                # Same fail-closed tier rendering as the
                # domain_model_context block: everything without a
                # verified receipt reads as a hint, on THIS path too —
                # the one review prompts actually use when primers
                # exist.
                lines.append(f"- {_tier_tag(inv)} {stmt}")
                neg = inv.get("negation")
                if neg:
                    lines.append(f"  Violation consequence: {neg}")
            candidates.append((avg_score, "\n".join(lines)))

    # --- Contracts (rich schema: function/input_semantics/output_semantics) ---
    for contract in memo.drifted("contracts"):
        cf = (contract.get("function") or "").lower()
        if cf not in tuple(v.lower()
                           for v in _name_variants(function_name)):
            continue
        contract_file = str(contract.get("file") or "")
        # Qualified identity, not name alone: same-named functions
        # (parse_header, init, probe — routine statics in C) exist
        # across files, and the model's own merge keys contracts by
        # (function, file) for exactly that reason. Serving another
        # file's contract here injects wrong semantics at the highest
        # primer score — an authority-toned wrong contract can steer
        # the review to dismiss a real finding.
        if (contract_file and _file_gate_applies(file_path)
                and not _paths_match(file_path, contract_file)):
            continue
        if str(contract.get("state") or "") == "stale":
            # Quarantined by the staleness check — the function's
            # source drifted since the contract was written. A stale
            # contract must not be served at all (it describes an old
            # version of the code and can steer the review to dismiss
            # a real finding).
            continue
        # The tier tag rides every served contract (the invariants
        # blocks above tier-tag every line): without it an unverified
        # LLM summary reads as established fact at the top score.
        lines = [
            f"DOMAIN-SPECIFIC: CONTRACT FOR {contract['function']} "
            f"{_tier_tag(contract)}",
        ]
        if not contract_file:
            # File unrecorded — name-only match. Serve it, but never
            # as unqualified authority.
            lines.append(
                "Matched by function name only (the contract records "
                "no file) — confirm it describes THIS function before "
                "relying on it."
            )
        elif not _file_gate_applies(file_path):
            # Pseudo-path fallback (binary audit): the contract has a
            # file but the review path shape is incomparable — this
            # serve is a name-only match too and carries the same
            # caution, never unqualified authority.
            lines.append(
                "Matched by function name only (review path and "
                "contract file are not comparable) — confirm it "
                "describes THIS function before relying on it."
            )
        if contract.get("input_semantics"):
            lines.append(f"Input: {contract['input_semantics']}")
        if contract.get("output_semantics"):
            lines.append(f"Output: {contract['output_semantics']}")
        if contract.get("ownership_transfer"):
            lines.append(f"Ownership: {contract['ownership_transfer']}")
        if contract.get("implication"):
            lines.append(f"Implication: {contract['implication']}")
        candidates.append((10.0, "\n".join(lines)))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [text for _, text in candidates]


def _inv_to_result(inv: dict[str, Any], *, match_pass: str = "") -> dict[str, str]:
    """Convert a raw invariant dict to a match result dict."""
    return {
        "invariant_id": inv.get("id", ""),
        "statement": inv.get("statement", ""),
        "negation": inv.get("negation", ""),
        "mechanical_rule": inv.get("mechanical_rule") or "",
        "confidence": inv.get("confidence", "inferred"),
        "match_pass": match_pass,
    }


def _extract_cwe_id(cwe: str) -> str:
    """Normalise a CWE string to 'CWE-NNN' form."""
    cwe = cwe.strip().upper()
    if cwe.startswith("CWE-"):
        return cwe
    m = re.match(r"(\d+)", cwe)
    if m:
        return f"CWE-{m.group(1)}"
    return cwe


def _match_pass_cwe(
    inv: dict[str, Any],
    finding_cwe: str,
) -> bool:
    """Pass 1: match if the finding's CWE is in the invariant's relevant_cwes."""
    inv_cwes = inv.get("relevant_cwes", [])
    if not inv_cwes or not finding_cwe:
        return False
    norm = _extract_cwe_id(finding_cwe)
    return norm in inv_cwes



def invariant_violations_for_hypothesis(
    out_dir: Path,
    hypothesis: str,
    *,
    finding_cwe: str = "",
) -> list[dict[str, str]]:
    """Find invariants whose domain aligns with a hypothesis.

    Two-pass matching:
      Pass 1 (CWE): finding CWE is in invariant's ``relevant_cwes``.
      Pass 2 (keyword): keyword overlap between invariant negation/id
        and hypothesis text.

    Returns a list of dicts with 'invariant_id', 'statement', 'negation',
    'mechanical_rule', 'confidence', 'match_pass'.
    """
    model = _find_domain_model(out_dir)
    if not model:
        return []

    hyp_lower = hypothesis.lower()
    results: list[dict[str, str]] = []

    for inv in model.get("invariants", []):
        inv_id = inv.get("id", "")

        if _match_pass_cwe(inv, finding_cwe):
            results.append(_inv_to_result(inv, match_pass="cwe"))
            continue

        negation = (inv.get("negation") or "").lower()
        id_parts = re.split(r"[_\-.]", inv_id.lower())
        significant_parts = [p for p in id_parts if len(p) > 3]

        if not negation and not significant_parts:
            continue

        match = False
        if negation:
            neg_terms = [
                w for w in negation.split()
                if len(w) > 4 and w not in _STOPWORDS
            ]
            hits = sum(1 for w in neg_terms if w in hyp_lower)
            match = hits >= 2
        if not match and significant_parts:
            match = sum(
                1 for p in significant_parts if p in hyp_lower
            ) >= 2

        if match:
            results.append(_inv_to_result(inv, match_pass="keyword"))

    return results


def invariants_contradicting_finding(
    out_dir: Path,
    hypothesis: str,
    preconditions: list[dict[str, Any]],
    *,
    finding_cwe: str = "",
) -> list[dict[str, str]]:
    """Find invariants that contradict a finding's hypothesis or preconditions.

    Checks the hypothesis text and each precondition's assumption text
    against all invariants. Returns matching invariants (deduplicated).
    """
    matches = invariant_violations_for_hypothesis(
        out_dir, hypothesis, finding_cwe=finding_cwe,
    )
    seen_ids = {m["invariant_id"] for m in matches}

    for pre in preconditions:
        assumption = pre.get("assumption", "")
        if not assumption:
            continue
        pre_matches = invariant_violations_for_hypothesis(
            out_dir, assumption, finding_cwe=finding_cwe,
        )
        for m in pre_matches:
            if m["invariant_id"] not in seen_ids:
                matches.append(m)
                seen_ids.add(m["invariant_id"])

    return matches


def queue_reading_list_item(
    out_dir: Path,
    *,
    question: str,
    source_command: str = "/audit",
    source_file: str = "",
    source_function: str = "",
    priority: str = "normal",
    resolution: str = "identifier",
    context: str = "",
) -> bool:
    """Queue an item to the reading list for future study.

    Called by /audit when it encounters an unfamiliar type or concept
    that would benefit from semantic study before further analysis.

    Returns True if the item was queued (or already exists).
    """
    from .reading_list import (
        READING_LIST_WRITE_LOCK,
        ReadingList,
        ReadingListItem,
        question_scoped_id,
    )

    rl_path = out_dir / "reading-list.json"

    # The readable prefix truncates the question, so the id must carry
    # the full-question hash: two distinct questions about one
    # function otherwise share an id and the persistence fold destroys
    # one.
    item_id = f"audit-{source_file}:{source_function}:{question[:30]}"
    item_id = re.sub(r"[^a-zA-Z0-9_\-:.]", "_", item_id)
    item_id = question_scoped_id(item_id, question)

    item = ReadingListItem(
        id=item_id,
        question=question,
        source_command=source_command,
        source_file=source_file,
        source_function=source_function,
        priority=priority,
        resolution=resolution,
        context=context,
    )

    from core.atomic_fs.fs_lock import artifact_lock

    # Load-modify-save cycle: hold the shared writer lock end to end
    # so concurrent in-process writers (premise questions, the study
    # consumer) cannot drop this item or lose theirs to this save, and
    # the file lock inside it so concurrent RUNS on a project-level
    # reading list cannot either (thread lock outer, file lock inner —
    # same order as ReadingList.save_merged).
    with READING_LIST_WRITE_LOCK, artifact_lock(
        rl_path, subject="reading list",
    ):
        rl = ReadingList.load(rl_path)
        rl.queue(item)
        try:
            rl.save(rl_path)
            return True
        except OSError as exc:
            logger.debug("failed to save reading list: %s", exc)
            return False
