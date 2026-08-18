"""Release-order verification channel (CWE-354): data released before
verification.

Adjudicates hypotheses of the EFAIL shape — decrypted/parsed data is
handed to the consumer (out BIO, socket, stream, callback) *before*
the integrity/authenticity check completes (``cms_smime.c`` loops
``BIO_write``-ing chunks and consults ``BIO_get_cipher_status`` only at
end-of-stream). The property is temporal and contract-bound: every
release site must be dominated by a condition consuming the integrity
finalizer's result. One function with one release site can violate it,
so this is a channel, not a consistency (peer-majority) comparator —
composition with the in-flight consistency ordering dimension is
evidentiary only: its ``PeerEvidence.to_dict()`` receipts slot into
``corroboration[]`` unchanged (zero shared files).

Legs:

1. **Intra-function dominance (phase 1, LLM-free)** — CFG + dominator
   tree (the ``lifecycle_collector`` path): a release site is safe
   when a dominating condition mentions the finalizer's status binding
   (or the finalizer call itself).
2. **Joern cross-check (optional, when a server is up)** —
   :func:`core.audit.joern_verify.run_guard_dominance_check` invoked
   READ-ONLY with identifier = the status binding and sink = the
   release callee. Agreement upgrades the receipt
   (``engine: cfg+joern``); disagreement ⇒ ``engines-disagree``,
   never a guess.
3. **Cross-function release (phase 2)** — release in a callee returns
   ``release-in-callee`` with the callee named.

Honesty notes: a buffering-then-flush architecture is safe even when a
*write* precedes the check if the write targets an internal buffer
flushed post-check — the release-sink classifier therefore requires
the destination to escape the function (out-param / stream handle /
callback), and ``tmpout == out`` aliasing is resolved from assignment
provenance; an unresolved alias ⇒ ``sink-alias-unresolved``. A
plain-CBC pipeline without a MAC is not this channel's claim
(``finalizer-unresolved``).

Grade split: learned ``verify_release`` pairing (study
``paired_operations``) or operator annotation ⇒ registry-grade
``release_order:release-before-verify``; seed-exemplar-only match ⇒
the ``-naming`` detection variant (aggregation-only). No LLM calls,
no subprocesses.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

RULE_RELEASE_BEFORE_VERIFY = "release_order:release-before-verify"

DETECTION_VARIANT_SUFFIX = "-naming"

# CWE families the channel owns; it additionally joins the CWE-345
# authenticity chain (fail_open keeps its membership — the family
# gets both the role leg and the ordering leg).
RELEASE_ORDER_CWES = frozenset({"CWE-354", "CWE-347"})
_JOINED_CWES = frozenset({"CWE-345"})

# Enumerated inconclusive reasons (each a distinct tested string).
REASON_FINALIZER_UNRESOLVED = "finalizer-unresolved"
REASON_RELEASE_IN_CALLEE = "release-in-callee"
REASON_CFG_UNAVAILABLE = "cfg-unavailable"
REASON_ENGINES_DISAGREE = "engines-disagree"
REASON_SINK_ALIAS_UNRESOLVED = "sink-alias-unresolved"
REASON_LANGUAGE_UNSUPPORTED = "language-unsupported"
REASON_HYPOTHESIS_UNBINDABLE = "hypothesis-unbindable"

INCONCLUSIVE_REASONS = frozenset({
    REASON_FINALIZER_UNRESOLVED,
    REASON_RELEASE_IN_CALLEE,
    REASON_CFG_UNAVAILABLE,
    REASON_ENGINES_DISAGREE,
    REASON_SINK_ALIAS_UNRESOLVED,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_HYPOTHESIS_UNBINDABLE,
})

# SEED SETS — pattern illustrators only (SEED_SET_CAP discipline, the
# callback_lifetime rule verbatim): growth goes to the study loop
# (paired_operations kind "verify_release") or a pack, never here.
_SEED_FINALIZER_NAMES = (
    "EVP_DecryptFinal_ex", "EVP_CipherFinal_ex", "BIO_get_cipher_status",
    "EVP_DigestVerifyFinal", "EVP_MAC_final", "HMAC_Final",
    "crypto_aead_decrypt",
)

_SEED_RELEASE_NAMES = (
    "BIO_write", "fwrite", "fputs", "write", "send", "sendto",
    "SSL_write",
)

# Prepass caps (§2.6).
MAX_PREPASS_CANDIDATES = 100
PREPASS_BUDGET_S = 20.0
MAX_PREPASS_FINDINGS = 50

# Hypothesis shapes asserting release-before-verify ordering.
_RELEASE_ORDER_HYPOTHESIS_RE = re.compile(
    r"(?:(?:releas|output|write|writ|deliver|emit|flush)\w*.{0,60}"
    r"(?:before|prior\s+to|without).{0,40}"
    r"(?:verif|authenticat|\btag\b|\bMAC\b|integrity|signature|"
    r"cipher\s*status)"
    r"|(?:verif|authenticat|integrity|cipher\s*status)\w*.{0,40}"
    r"(?:only\s+)?(?:after|at\s+EOF|at\s+the\s+end|at\s+end)"
    r"|\bEFAIL\b)",
    re.IGNORECASE | re.DOTALL,
)

_BACKTICK_IDENT_RE = re.compile(r"`([A-Za-z_][\w.]*)\s*(?:\(\s*\))?`")
_ASSIGN_FROM_CALL_RE = re.compile(r"=\s*[A-Za-z_]\w*\s*\(")


def is_release_order_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts the release-before-verify
    temporal ordering (EFAIL shape)."""
    return bool(text) and bool(_RELEASE_ORDER_HYPOTHESIS_RE.search(text))


def release_order_applicable(cwe: str) -> bool:
    """True for the channel's own CWEs plus the CWE-345 authenticity
    chain it joins additively."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in RELEASE_ORDER_CWES or norm in _JOINED_CWES


def is_detection_rule_id(rule_id: str) -> bool:
    """True for the detection-grade rule-id variants (seed-only
    pairing) — aggregation-eligible, never promote-alone."""
    return rule_id.startswith("release_order:") and rule_id.endswith(
        DETECTION_VARIANT_SUFFIX,
    )


def seed_budget_violations() -> list[str]:
    """Vocabulary-policy lint: seed tuples stay within SEED_SET_CAP."""
    from .fail_open_roles import SEED_SET_CAP
    violations: list[str] = []
    for name, seeds in (
        ("_SEED_FINALIZER_NAMES", _SEED_FINALIZER_NAMES),
        ("_SEED_RELEASE_NAMES", _SEED_RELEASE_NAMES),
    ):
        if len(seeds) > SEED_SET_CAP:
            violations.append(
                f"release_order.{name} has {len(seeds)} entries "
                f"(cap {SEED_SET_CAP}) — teach the study loop instead",
            )
    return violations


@dataclass
class OrderEvidence:
    """Aggregate channel verdict for one release-order hypothesis."""

    outcome: str                 # confirmed | refuted | inconclusive
    reason: str
    rule_id: str = RULE_RELEASE_BEFORE_VERIFY
    finalizer: dict[str, Any] | None = None
    releases: list[dict[str, Any]] = field(default_factory=list)
    reachability: dict[str, Any] | None = None
    # Consistency §3.5 ordering PeerEvidence dicts and taint receipts
    # slot in unchanged (the fail_open corroboration convention).
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
        }
        if self.finalizer is not None:
            d["finalizer"] = self.finalizer
        if self.releases:
            d["releases"] = self.releases
        if self.reachability is not None:
            d["reachability"] = self.reachability
        if self.corroboration:
            d["corroboration"] = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in self.corroboration
            ]
        return d


def _inconclusive(reason: str, detail: str = "") -> OrderEvidence:
    return OrderEvidence(
        outcome="inconclusive",
        reason=f"{reason}: {detail}" if detail else reason,
    )


# ── vocabulary (seeds < learned) ────────────────────────────────────


def learned_verify_release_pairs(
    domain_model: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Finalizer/output pairs from study-learned ``paired_operations``
    entries of kind ``verify_release`` (acquire = the call reporting
    whether decryption/authentication succeeded, release = the call
    handing data to the consumer). Channel-local parsing — the
    ``learned_cleanup_pairs`` precedent; ``llm_prior`` excluded."""
    pairs: list[dict[str, str]] = []
    for entry in (domain_model or {}).get("paired_operations") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("kind") or "").lower() != "verify_release":
            continue
        if str(entry.get("provenance") or "") == "llm_prior":
            continue
        fin = str(entry.get("acquire") or "").split("(")[0].strip()
        rel = str(entry.get("release") or "").split("(")[0].strip()
        if not fin or not rel:
            continue
        pairs.append({
            "finalizer": fin,
            "release": rel,
            "provenance": str(entry.get("provenance") or "domain_model"),
        })
    return pairs


def _finalizer_vocabulary(
    domain_model: dict[str, Any] | None,
) -> dict[str, tuple[str, str]]:
    vocab: dict[str, tuple[str, str]] = {
        name: ("seed", "seed") for name in _SEED_FINALIZER_NAMES
    }
    for pair in learned_verify_release_pairs(domain_model):
        vocab[pair["finalizer"]] = ("learned", pair["provenance"])
    return vocab


def _release_vocabulary(
    domain_model: dict[str, Any] | None,
) -> dict[str, tuple[str, str]]:
    vocab: dict[str, tuple[str, str]] = {
        name: ("seed", "seed") for name in _SEED_RELEASE_NAMES
    }
    for pair in learned_verify_release_pairs(domain_model):
        vocab[pair["release"]] = ("learned", pair["provenance"])
    return vocab


_REGISTRY_VOCAB_SOURCES = frozenset({"learned", "annotation"})


def _call_re(names: tuple[str, ...] | list[str]) -> re.Pattern:
    alts = "|".join(
        re.escape(n) for n in sorted(names, key=len, reverse=True)
    )
    return re.compile(r"\b(" + alts + r")\s*\(")


# ── structural helpers ──────────────────────────────────────────────


def _read_source(target_path: Path, file_path: str) -> str | None:
    try:
        p = Path(target_path) / file_path
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return None


def _function_segment(
    source: str, function_name: str, language: str,
) -> tuple[list[str], int]:
    try:
        from .fail_open_lang import c_function_span
        span = c_function_span(source, function_name, language=language)
    except ImportError:
        span = None
    lines = source.splitlines()
    if span:
        return lines[span[0] - 1:span[1]], span[0]
    return lines, 1


def _first_arg_base(code: str, callee: str) -> str:
    """Base identifier of the callee's first argument
    (``BIO_write(out, buf, n)`` → ``out``)."""
    m = re.search(rf"\b{re.escape(callee)}\s*\(\s*([^,()]+)", code)
    if not m:
        return ""
    arg = m.group(1).strip()
    m2 = re.match(r"[&*]*\s*([A-Za-z_]\w*)", arg)
    return m2.group(1) if m2 else ""


def _classify_destination(
    dest: str,
    segment_lines: list[str],
    params: tuple[str, ...],
) -> str:
    """``escaping`` (out-param / alias of a param), ``internal``
    (assigned from a fresh call — buffered-then-flush shape), or
    ``unresolved`` (mixed/conditional alias — the CMS ``tmpout``
    shape when provenance cannot be pinned)."""
    if not dest:
        return "unresolved"
    if dest in params:
        return "escaping"
    classes: set[str] = set()
    assign_re = re.compile(rf"\b{re.escape(dest)}\s*=\s*([^;=][^;]*)")
    for raw in segment_lines:
        code = raw.split("//", 1)[0]
        m = assign_re.search(code)
        if not m:
            continue
        rhs = m.group(1).strip()
        cond = re.match(r".+\?\s*(.+?)\s*:\s*(.+)", rhs)
        arms = [cond.group(1), cond.group(2)] if cond else [rhs]
        for arm in arms:
            arm = arm.strip()
            base = re.match(r"[&*]*\s*([A-Za-z_]\w*)\s*$", arm)
            if base and base.group(1) in params:
                classes.add("escaping")
            elif re.match(r"[A-Za-z_]\w*\s*\(", arm):
                classes.add("internal")
            else:
                classes.add("unknown")
    if not classes:
        # Never assigned in-function and not a parameter: a global /
        # captured stream — treat as escaping (data leaves the
        # function's control).
        return "escaping"
    if classes == {"escaping"}:
        return "escaping"
    if classes == {"internal"}:
        return "internal"
    return "unresolved"


def _guards_at(
    source: str,
    function_name: str,
    line: int,
    file_path: str,
    language: str,
) -> list[str] | None:
    """Dominating guard conditions via CFG + dominators; ``None`` =
    CFG unavailable."""
    try:
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        from core.analysis.dominators import build_dom_tree
        from core.analysis.lifecycle_collector import collect_guards_at_site
    except ImportError:
        return None
    tail = function_name.rsplit(".", 1)[-1]
    try:
        cfg = build_cpp_intraproc_cfg(source, tail, language=language)
        if cfg is None:
            return None
        dom = build_dom_tree(cfg)
        guards = collect_guards_at_site(cfg, dom, line, file_path)
    except Exception:
        logger.debug("release_order: guard collection failed",
                     exc_info=True)
        return None
    return [g.condition for g in guards]


def _entry_reachability(
    context: Any,
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    try:
        from .fail_open_verify import _entry_reachability as _fo_reach
    except ImportError:
        return None
    try:
        return _fo_reach(context, inventory, file_path, function_name)
    except Exception:
        logger.debug("release_order: reachability escalator failed",
                     exc_info=True)
        return None


def _status_bindings(
    segment_lines: list[str], span_start: int, finalizer: str,
) -> tuple[list[str], int]:
    """Identifiers bound to the finalizer's result plus the first
    finalizer call line. The finalizer name itself is always a valid
    binding (direct ``if (!EVP_DecryptFinal_ex(...))`` shapes)."""
    bindings = [finalizer]
    first_line = 0
    call_re = re.compile(
        rf"(?:\b([A-Za-z_]\w*)\s*=\s*)?\b{re.escape(finalizer)}\s*\(",
    )
    for idx, raw in enumerate(segment_lines):
        code = raw.split("//", 1)[0]
        m = call_re.search(code)
        if not m:
            continue
        if not first_line:
            first_line = span_start + idx
        if m.group(1) and m.group(1) not in bindings:
            bindings.append(m.group(1))
    return bindings, first_line


def _joern_cross_check(
    joern_server: Any,
    target_path: Path,
    file_path: str,
    function_name: str,
    binding: str,
    release_callee: str,
    cfg_dominated: bool,
) -> tuple[str, str]:
    """Read-only guard-dominance cross-check. Returns
    ``(engine, disagreement_detail)`` — engine ``cfg`` when the leg
    could not run, ``cfg+joern`` on agreement, and a non-empty detail
    on disagreement."""
    if joern_server is None:
        return "cfg", ""
    try:
        from . import joern_verify
        res = joern_verify.run_guard_dominance_check(
            target_path=Path(target_path),
            file_path=file_path,
            function_name=function_name,
            identifier=binding,
            sink_call=release_callee,
            server=joern_server,
        )
    except Exception:
        logger.debug("release_order: joern cross-check failed",
                     exc_info=True)
        return "cfg", ""
    outcome = getattr(res, "outcome", "")
    if outcome not in ("confirmed", "refuted"):
        return "cfg", ""
    joern_dominated = outcome == "refuted"
    if joern_dominated == cfg_dominated:
        return "cfg+joern", ""
    return "cfg", (
        f"CFG says dominated={cfg_dominated}, Joern says "
        f"dominated={joern_dominated} for {release_callee} vs "
        f"{binding}"
    )


# ── channel core ────────────────────────────────────────────────────


def _adjudicate_function(
    source: str,
    file_path: str,
    function_name: str,
    language: str,
    *,
    target_path: Path | None = None,
    hypothesis: str = "",
    domain_model: dict[str, Any] | None = None,
    context: Any = None,
    inventory: dict[str, Any] | None = None,
    joern_server: Any = None,
) -> OrderEvidence:
    segment_lines, span_start = _function_segment(
        source, function_name, language,
    )
    segment = "\n".join(segment_lines)

    fin_vocab = _finalizer_vocabulary(domain_model)
    fin_re = _call_re(list(fin_vocab))
    fin_match = fin_re.search(segment)
    if not fin_match:
        return _inconclusive(
            REASON_FINALIZER_UNRESOLVED,
            f"no integrity finalizer vocabulary binds in "
            f"{function_name} — an unauthenticated pipeline is not "
            "this channel's claim",
        )
    finalizer = fin_match.group(1)
    fin_source, fin_prov = fin_vocab[finalizer]
    bindings, fin_line = _status_bindings(
        segment_lines, span_start, finalizer,
    )

    rel_vocab = _release_vocabulary(domain_model)
    rel_re = _call_re(list(rel_vocab))

    # Enumerate release sites with destination classification.
    params: tuple[str, ...] = ()
    try:
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        cfg = build_cpp_intraproc_cfg(
            source, function_name.rsplit(".", 1)[-1], language=language,
        )
        if cfg is not None:
            params = cfg.params
    except Exception:
        cfg = None
    if not params:
        header = segment_lines[0] if segment_lines else ""
        params = tuple(re.findall(r"[\w\*\s]\b([A-Za-z_]\w*)\s*[,)]",
                                  header))

    release_sites: list[dict[str, Any]] = []
    internal_sites: list[dict[str, Any]] = []
    alias_unresolved: dict[str, Any] | None = None
    for idx, raw in enumerate(segment_lines):
        code = raw.split("//", 1)[0]
        m = rel_re.search(code)
        if not m:
            continue
        callee = m.group(1)
        dest = _first_arg_base(code, callee)
        dest_class = _classify_destination(dest, segment_lines, params)
        site = {
            "file": file_path,
            "line": span_start + idx,
            "code": raw.strip()[:200],
            "callee": callee,
            "destination": dest,
            "destination_class": dest_class,
        }
        if dest_class == "escaping":
            release_sites.append(site)
        elif dest_class == "unresolved":
            alias_unresolved = site
        else:
            internal_sites.append(site)

    fin_receipt = {
        "name": finalizer,
        "file": file_path,
        "line": fin_line,
        "status_binding": ", ".join(b for b in bindings if b != finalizer)
                          or finalizer,
        "vocab_source": fin_source,
        "provenance": fin_prov,
    }

    if not release_sites:
        if alias_unresolved is not None:
            return OrderEvidence(
                outcome="inconclusive",
                reason=(
                    f"{REASON_SINK_ALIAS_UNRESOLVED}: destination "
                    f"`{alias_unresolved['destination']}` of "
                    f"{alias_unresolved['callee']} at "
                    f"{file_path}:{alias_unresolved['line']} mixes "
                    "internal and escaping provenance — buffering vs "
                    "release undecidable"
                ),
                finalizer=fin_receipt,
                releases=[alias_unresolved],
            )
        if internal_sites:
            # Buffered-then-flush architecture: every write targets an
            # internal buffer (fresh-call provenance) — the safe CMS
            # tmpout shape. Per-site provenance receipts.
            return OrderEvidence(
                outcome="refuted",
                reason=(
                    f"all {len(internal_sites)} write(s) in "
                    f"{function_name} target an internal buffer "
                    "(fresh-call provenance) — buffered-then-flush, "
                    "nothing escapes before the check"
                ),
                finalizer=fin_receipt,
                releases=internal_sites,
            )
        # Phase-2 seam: a hypothesis-named callee present in the
        # function may wrap the write (BIO chains, wrapper writers).
        for m in _BACKTICK_IDENT_RE.finditer(hypothesis or ""):
            name = m.group(1).rstrip("(")
            if name not in rel_vocab and re.search(
                rf"\b{re.escape(name)}\s*\(", segment,
            ):
                return _inconclusive(
                    REASON_RELEASE_IN_CALLEE,
                    f"release happens in callee {name} — phase-2 "
                    "callee expansion territory",
                )
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no release-classified call in {function_name}",
        )

    # Dominance test per release site.
    releases: list[dict[str, Any]] = []
    undominated: list[dict[str, Any]] = []
    for site in release_sites:
        guards = _guards_at(
            source, function_name, site["line"], file_path, language,
        )
        if guards is None:
            return _inconclusive(
                REASON_CFG_UNAVAILABLE,
                "CFG/dominators unavailable — dominance cannot be "
                "established structurally",
            )
        dominator = None
        for cond in guards:
            if any(
                re.search(rf"\b{re.escape(b)}\b", cond) for b in bindings
            ):
                dominator = cond[:200]
                break
        cfg_dominated = dominator is not None
        engine, disagreement = _joern_cross_check(
            joern_server, target_path or Path("."), file_path,
            function_name,
            fin_receipt["status_binding"].split(",")[0].strip(),
            site["callee"], cfg_dominated,
        )
        if disagreement:
            return OrderEvidence(
                outcome="inconclusive",
                reason=f"{REASON_ENGINES_DISAGREE}: {disagreement}",
                finalizer=fin_receipt,
                releases=releases + [dict(site, engine="cfg")],
            )
        entry = dict(
            site, dominated=cfg_dominated, dominator=dominator,
            engine=engine,
        )
        releases.append(entry)
        if not cfg_dominated:
            undominated.append(entry)

    if not undominated:
        return OrderEvidence(
            outcome="refuted",
            reason=(
                f"every release site ({len(releases)}) in "
                f"{function_name} is dominated by a "
                f"{finalizer}-status check (per-site dominator "
                "receipts)"
            ),
            finalizer=fin_receipt,
            releases=releases,
        )

    registry = fin_source in _REGISTRY_VOCAB_SOURCES
    rule_id = (
        RULE_RELEASE_BEFORE_VERIFY if registry
        else RULE_RELEASE_BEFORE_VERIFY + DETECTION_VARIANT_SUFFIX
    )
    first = undominated[0]
    result = OrderEvidence(
        outcome="confirmed",
        reason=(
            f"{first['callee']} at {file_path}:{first['line']} "
            f"releases `{first['destination']}` (escaping) with no "
            f"dominating {finalizer}-status check — "
            f"{len(undominated)}/{len(releases)} release site(s) "
            f"undominated; verification completes only after release"
        ),
        rule_id=rule_id,
        finalizer=fin_receipt,
        releases=releases,
    )
    result.reachability = _entry_reachability(
        context, inventory, file_path, function_name,
    )
    return result


def run_release_order_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    domain_model: dict[str, Any] | None = None,
    joern_server: Any = None,
    budget_s: float | None = None,
) -> OrderEvidence:
    """Adjudicate one release-order hypothesis. See module docstring
    for verdict semantics."""
    del budget_s  # phase-2 callee-expansion parameter
    try:
        from .fail_open_lang import language_for_path
        language = language_for_path(file_path)
    except ImportError:
        language = None
    if language not in ("c", "cpp"):
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            f"no phase-1 release-order analyzer for "
            f"{language or Path(file_path).suffix or 'unknown'}",
        )
    source = _read_source(Path(target_path), file_path)
    if source is None:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE, f"could not read {file_path}",
        )
    return _adjudicate_function(
        source, file_path, function_name, language,
        target_path=Path(target_path),
        hypothesis=hypothesis,
        domain_model=domain_model,
        context=context,
        inventory=inventory,
        joern_server=joern_server,
    )


def run_release_order_prepass(
    source_texts: dict[str, str],
    *,
    target_path: Path | None = None,
    out_dir: Path | None = None,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    domain_model: dict[str, Any] | None = None,
    joern_server: Any = None,
    budget_s: float = PREPASS_BUDGET_S,
) -> dict[str, Any]:
    """Standing pre-pass: candidate functions contain both a finalizer
    name and a release-classified call (cheap string prefilter on the
    source set), cap 100/run, budget 20 s (§2.6)."""
    del target_path  # reserved for the phase-2 callee expansion
    t0 = time.monotonic()
    telemetry: dict[str, Any] = {
        "channel": "release_order",
        "confirmed": 0, "refuted": 0, "inconclusive": 0,
        "candidates": 0, "budget_exceeded": False,
        "inconclusive_reasons": {},
    }
    findings: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    mechanical: list[dict[str, Any]] = []

    fin_vocab = _finalizer_vocabulary(domain_model)
    rel_vocab = _release_vocabulary(domain_model)
    fin_re = _call_re(list(fin_vocab))
    rel_re = _call_re(list(rel_vocab))

    from .resource_bounds import _c_function_spans

    candidates: list[tuple[str, str]] = []
    for fp, source in sorted(source_texts.items()):
        if not fp.endswith((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp")):
            continue
        if not (fin_re.search(source) and rel_re.search(source)):
            continue
        for name, start, end in _c_function_spans(source):
            segment = "\n".join(source.splitlines()[start - 1:end])
            if fin_re.search(segment) and rel_re.search(segment):
                candidates.append((fp, name))
            if len(candidates) >= MAX_PREPASS_CANDIDATES:
                break
        if len(candidates) >= MAX_PREPASS_CANDIDATES:
            break
    telemetry["candidates"] = len(candidates)

    for fp, name in candidates:
        if time.monotonic() - t0 > budget_s:
            telemetry["budget_exceeded"] = True
            break
        res = _adjudicate_function(
            source_texts[fp], fp, name, "c",
            domain_model=domain_model,
            context=context,
            inventory=inventory,
            joern_server=joern_server,
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
            and (res.reachability or {}).get("status") == "entry_reachable"
            else "suspicious"
        )
        first = next(
            (r for r in res.releases if not r.get("dominated")),
            res.releases[0] if res.releases else {},
        )
        line = int(first.get("line") or 0)
        if len(findings) < MAX_PREPASS_FINDINGS:
            findings.append({
                "file": fp,
                "function": name,
                "line": line,
                "rule_id": res.rule_id,
                "evidence_tool": res.rule_id,
                "status": status,
                "detection_grade": detection,
                "cwe": "CWE-354",
                "hypothesis": (
                    f"{first.get('callee', 'the writer')} at "
                    f"{fp}:{line} releases data before the "
                    f"{(res.finalizer or {}).get('name', 'integrity')} "
                    "check completes"
                ),
                "description": res.reason,
                "receipts": res.to_dict(),
            })
        mechanical.append({
            "file": fp,
            "function": name,
            "detector": "release_order",
            "line": line,
            "description": res.reason,
            "callee": first.get("callee", ""),
            "rule_id": res.rule_id,
            "cwe": "CWE-354",
        })
        leads.append({
            "channel": "release_order",
            "file": fp,
            "function": name,
            "line": line,
            "rule_id": res.rule_id,
            "description": res.reason[:300],
            "mechanism": (
                f"{first.get('callee', 'a writer')} at {fp}:{line} "
                "hands data to the consumer before the integrity "
                "finalizer's status is consulted (release-before-"
                "verify, CWE-354)"
            ),
        })

    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)
    if out_dir is not None and (findings or leads):
        try:
            path = Path(out_dir) / "release-order.json"
            path.write_text(json.dumps(
                {"findings": findings, "leads": leads,
                 "telemetry": telemetry}, indent=1,
            ))
        except Exception:
            logger.debug("release-order.json write failed", exc_info=True)
    return {
        "findings": findings,
        "leads": leads,
        "mechanical": mechanical,
        "telemetry": telemetry,
    }
