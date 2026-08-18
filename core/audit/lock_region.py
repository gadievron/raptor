"""lock_region channel — callback invoked while a lock is held.

Target class (CWE-833/667, the session-cache flush shape): an
application-registrable callback is invoked inside a lock region —
deadlock when the callback re-enters an API taking the same lock, or
reentrancy corruption. Pure composition, no new vocabulary:

* **Lock regions**: intra-function spans between a learned/pack lock
  acquire and its *paired* release — ``DomainVocabulary.lock_pairs``
  preserves exact pairing; channel-local seeds (≤ 9 names) cover the
  pthread / CRYPTO_THREAD shapes; a project ``foo_lock``/``foo_unlock``
  naming-stem pairing is recognised at detection grade only. Region
  tracking is the callback_lifetime Tier-1 line-scan pattern.
* **In-region callback invocation**, two shapes: (a) indirect call
  through a function-pointer field (``obj->cb(...)`` — structural, no
  vocab); (b) direct calls of names registered via a
  ``callback_registers`` verb (existing vocab class).
* **Registrable-by-application witness** (the severity discriminator):
  the callback member has a setter assigning it from a parameter, and
  the setter is exported (non-static).
* **Cocci corroboration leg**:
  ``engine/coccinelle/rules/callback_under_lock.cocci`` (parametric
  ``-D lock -D unlock`` from the learned pairs, the
  ``unchecked_return.cocci`` precedent) — an independent
  ``coccinelle`` namespace for aggregation.

Grade / status discipline: registry ``lock_region:callback-under-lock``
only when the lock pair is learned/pack/seed (registry vocabulary) AND
the callback is application-registrable via an exported setter;
naming-stem lock or internal-only setter selects the ``-naming``
detection variant. Even registry-grade confirmations cap at
``suspicious`` unless entry-reachable AND setter-exported (both
escalators) — honest about the "requires a specific app callback
pattern" severity profile; the documented-behaviour case is still a
true positive of the property and lands as ``suspicious`` with the
in-region comment quoted in the receipt when present.

Boundary declarations: blocking-call-under-lock stays with
``typestate``; lock-imbalance stays with ``lock_imbalance.cocci`` +
smt check-lock-discipline (CWE-667 chain); the struct-field
lock-discipline context stays ``struct_accessor_index``. This channel
owns only invoke-callback-while-held.

No LLM calls; the phase-1 legs spawn no subprocesses (the cocci leg
runs only as post-confirmation corroboration under the runner's
timeout).
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

RULE_CALLBACK_UNDER_LOCK = "lock_region:callback-under-lock"
DETECTION_VARIANT_SUFFIX = "-naming"

COCCI_RULE_NAME = "callback_under_lock"
COCCI_STAMP = f"coccinelle:{COCCI_RULE_NAME}"

# CWE families the channel joins via the fallback chain. CWE-833
# (deadlock) is channel-owned; the CWE-667 membership is additive to
# its existing smt/cocci entry.
LOCK_REGION_CWES = frozenset({"CWE-833", "CWE-667"})

# Enumerated inconclusive reasons (each a distinct tested string).
REASON_PAIR_UNRESOLVED = "pair-unresolved"
REASON_CALLBACK_SHAPE_UNDECIDED = "callback-shape-undecided"
REASON_REGION_SPANS_CALLEE = "region-spans-callee"
REASON_LANGUAGE_UNSUPPORTED = "language-unsupported"
REASON_HYPOTHESIS_UNBINDABLE = "hypothesis-unbindable"

INCONCLUSIVE_REASONS = frozenset({
    REASON_PAIR_UNRESOLVED,
    REASON_CALLBACK_SHAPE_UNDECIDED,
    REASON_REGION_SPANS_CALLEE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_HYPOTHESIS_UNBINDABLE,
})

# SEED SET — canonical exemplars of the paired-lock shape (pthread +
# OpenSSL CRYPTO_THREAD). The kernel bulk arrives via the linux_kernel
# vocab pack's lock_pairs; project pairs via the study-learned
# DomainVocabulary. Do not grow this tuple — teach the study loop /
# pack instead (SEED_SET_CAP discipline).
_SEED_LOCK_PAIRS = (
    ("pthread_mutex_lock", "pthread_mutex_unlock"),
    ("pthread_rwlock_wrlock", "pthread_rwlock_unlock"),
    ("CRYPTO_THREAD_write_lock", "CRYPTO_THREAD_unlock"),
    ("CRYPTO_THREAD_read_lock", "CRYPTO_THREAD_unlock"),
)

# Naming-stem pairing for project locks (foo_lock → foo_unlock):
# detection grade only.
_STEM_LOCK_RE = re.compile(r"\A(\w*?)_?(?<!un)lock\Z")

# Hypothesis shapes asserting callback-invocation-under-lock (§5.5).
_LOCK_REGION_HYPOTHESIS_RE = re.compile(
    r"(?:(?:callback|handler|hook|function\s+pointer|\bcb\b)\w*"
    r".{0,60}(?:under|while|with|holding|inside)"
    r".{0,20}(?:the\s+|a\s+)?lock"
    r"|lock\s+held.{0,40}(?:callback|reentran)"
    r"|reentran\w+.{0,40}lock"
    r"|deadlock.{0,40}callback"
    r"|callback.{0,40}deadlock)",
    re.IGNORECASE | re.DOTALL,
)

_INDIRECT_CALL_RE = re.compile(
    r"(?:\(\s*\*\s*(\w+)\s*->\s*(\w+)\s*\)|\b(\w+)\s*->\s*(\w+))\s*\(",
)
_COMMENT_RE = re.compile(r"(?://|/\*)\s*(.{0,160})")

_C_KEYWORDS = frozenset({"if", "for", "while", "switch", "return",
                         "sizeof", "do", "else"})

MAX_PREPASS_CANDIDATES = 200
PREPASS_BUDGET_S = 10.0
MAX_LEADS = 20


def is_lock_region_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts a callback / function-pointer
    invocation while a lock is held."""
    return bool(text) and bool(_LOCK_REGION_HYPOTHESIS_RE.search(text))


def lock_region_applicable(cwe: str) -> bool:
    """True when the CWE belongs to the callback-under-lock family."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in LOCK_REGION_CWES


def is_detection_rule_id(rule_id: str) -> bool:
    """True for the detection-grade ``-naming`` variants — they may
    not promote alone but participate in channel aggregation."""
    return rule_id.startswith("lock_region:") and rule_id.endswith(
        DETECTION_VARIANT_SUFFIX,
    )


# ── lock-pair vocabulary (seeds < pack < learned) ───────────────────


def _lock_pairs(vocab: Any = None) -> list[tuple[str, str, str]]:
    """Merged (acquire, release, source) pairs: channel seeds plus
    ``DomainVocabulary.lock_pairs`` (pack + learned, exact pairing
    preserved — read-only consumption)."""
    pairs: list[tuple[str, str, str]] = [
        (a, r, "seed") for a, r in _SEED_LOCK_PAIRS
    ]
    seen = {(a, r) for a, r, _ in pairs}
    for entry in sorted(getattr(vocab, "lock_pairs", None) or ()):
        if not (isinstance(entry, tuple) and len(entry) == 2):
            continue
        acq, rel = entry
        if (acq, rel) in seen:
            continue
        seen.add((acq, rel))
        pairs.append((acq, rel, "learned"))
    return pairs


@lru_cache(maxsize=32)
def _call_arg_re(name: str) -> re.Pattern:
    return re.compile(
        rf"\b{re.escape(name)}\s*\(\s*&?\s*([^,);]*)",
    )


def _normalize_lock_var(arg: str) -> str:
    return re.sub(r"[\s&()]", "", arg)


# ── receipts ────────────────────────────────────────────────────────


@dataclass
class LockRegionEvidence:
    """Channel verdict for one callback-under-lock claim (§5.2)."""

    outcome: str                     # confirmed | refuted | inconclusive
    reason: str
    rule_id: str = RULE_CALLBACK_UNDER_LOCK
    lock: dict[str, Any] | None = None
    region: dict[str, Any] | None = None
    callback: dict[str, Any] | None = None
    comment: str = ""
    reachability: dict[str, Any] | None = None
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
        }
        if self.lock is not None:
            d["lock"] = self.lock
        if self.region is not None:
            d["region"] = self.region
        if self.callback is not None:
            d["callback"] = self.callback
        if self.comment:
            d["comment"] = self.comment
        if self.reachability is not None:
            d["reachability"] = self.reachability
        if self.corroboration:
            d["corroboration"] = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in self.corroboration
            ]
        return d


def _inconclusive(reason: str, detail: str = "") -> LockRegionEvidence:
    return LockRegionEvidence(
        outcome="inconclusive",
        reason=f"{reason}: {detail}" if detail else reason,
    )


# ── Tier-1 line scan ────────────────────────────────────────────────


@dataclass
class _Region:
    acquire: str
    release: str
    pair_source: str        # seed | learned | naming
    variable: str
    acquire_line: int       # absolute line numbers
    release_line: int       # 0 when unresolved


def _find_regions(
    segment: list[str],
    start_line: int,
    vocab: Any,
) -> tuple[list[_Region], list[dict[str, Any]]]:
    """Lock regions in one function segment. Returns (resolved
    regions, unresolved acquires ``{acquire, release, line,
    pair_source}``)."""
    regions: list[_Region] = []
    unresolved: list[dict[str, Any]] = []
    pairs = _lock_pairs(vocab)

    stem_acquires: list[tuple[str, int, str]] = []
    for offset, text in enumerate(segment):
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
            name = m.group(1)
            if name in _C_KEYWORDS:
                continue
            if any(name == a for a, _, _ in pairs):
                continue
            sm = _STEM_LOCK_RE.match(name)
            if sm and sm.group(1):
                stem_acquires.append((name, offset, sm.group(1)))

    def _arg_at(name: str, offset: int) -> str:
        m = _call_arg_re(name).search(segment[offset])
        return _normalize_lock_var(m.group(1)) if m else ""

    # Known pairs (seeds + learned/pack).
    for acq, rel, source in pairs:
        acq_re = re.compile(rf"\b{re.escape(acq)}\s*\(")
        rel_re = re.compile(rf"\b{re.escape(rel)}\s*\(")
        for offset, text in enumerate(segment):
            if not acq_re.search(text):
                continue
            var = _arg_at(acq, offset)
            release_off = 0
            for off2 in range(offset + 1, len(segment)):
                if rel_re.search(segment[off2]):
                    var2 = _arg_at(rel, off2)
                    if not var or not var2 or var == var2:
                        release_off = off2
                        break
            if release_off:
                regions.append(_Region(
                    acquire=acq, release=rel, pair_source=source,
                    variable=var,
                    acquire_line=start_line + offset,
                    release_line=start_line + release_off,
                ))
            else:
                unresolved.append({
                    "acquire": acq, "release": rel,
                    "line": start_line + offset,
                    "pair_source": source, "variable": var,
                })

    # Naming-stem pairing (foo_lock → foo_unlock): detection grade.
    for name, offset, stem in stem_acquires:
        rel_re = re.compile(rf"\b{re.escape(stem)}_?unlock\s*\(")
        release_off = 0
        release_name = ""
        for off2 in range(offset + 1, len(segment)):
            m = rel_re.search(segment[off2])
            if m:
                release_off = off2
                release_name = m.group(0).rstrip("( \t")
                break
        if release_off:
            regions.append(_Region(
                acquire=name, release=release_name,
                pair_source="naming",
                variable=_arg_at(name, offset),
                acquire_line=start_line + offset,
                release_line=start_line + release_off,
            ))
        else:
            unresolved.append({
                "acquire": name, "release": f"{stem}_unlock",
                "line": start_line + offset,
                "pair_source": "naming",
                "variable": _arg_at(name, offset),
            })
    return regions, unresolved


def _registered_callback_names(source: str, vocab: Any) -> set[str]:
    """Identifier arguments of ``callback_registers`` verb calls —
    the names an in-region direct call may invoke as a callback."""
    registers = set(getattr(vocab, "callback_registers", None) or ())
    names: set[str] = set()
    for verb in registers:
        for m in re.finditer(
            rf"\b{re.escape(verb)}\s*\(([^;]*)\)", source,
        ):
            for arg in m.group(1).split(","):
                arg = arg.strip()
                if re.fullmatch(r"[A-Za-z_]\w*", arg) and \
                        arg not in _C_KEYWORDS:
                    names.add(arg)
    return names


def _cancel_names(vocab: Any) -> tuple[str, ...]:
    """Teardown-safe verbs: the callback_lifetime channel's merged
    cancel set (seeds + pack + learned), consumed read-only."""
    try:
        from .callback_lifetime import _cancel_names as _cl_cancel
        return _cl_cancel(vocab)
    except ImportError:
        return tuple(sorted(
            getattr(vocab, "callback_cancels", None) or (),
        ))


def _in_region_invocations(
    segment: list[str],
    start_line: int,
    region: _Region,
    registered: set[str],
    vocab: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(callback invocations, cancel-verb invocations) between the
    region's acquire and release lines."""
    invocations: list[dict[str, Any]] = []
    cancels: list[dict[str, Any]] = []
    cancel_set = set(_cancel_names(vocab))
    lo = region.acquire_line - start_line + 1
    hi = region.release_line - start_line
    for offset in range(max(lo, 0), min(hi, len(segment))):
        text = segment[offset]
        for m in _INDIRECT_CALL_RE.finditer(text):
            base = m.group(1) or m.group(3)
            member = m.group(2) or m.group(4)
            if not base or base in _C_KEYWORDS:
                continue
            invocations.append({
                "shape": "indirect_field",
                "expr": f"{base}->{member}",
                "base": base,
                "member": member,
                "line": start_line + offset,
                "code": text.strip()[:200],
            })
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
            name = m.group(1)
            if name in cancel_set:
                cancels.append({
                    "shape": "cancel",
                    "expr": name,
                    "line": start_line + offset,
                    "code": text.strip()[:200],
                })
            elif name in registered:
                invocations.append({
                    "shape": "named",
                    "expr": name,
                    "member": name,
                    "line": start_line + offset,
                    "code": text.strip()[:200],
                })
    return invocations, cancels


def _setter_witness(
    source_texts: dict[str, str],
    member: str,
    invoking_function: str,
) -> tuple[str | None, bool]:
    """(setter name, exported?) for the callback member: a function
    other than the invoker that assigns ``X-><member>`` from one of
    its parameters. Exported = its definition is not ``static``."""
    from .field_census import function_spans

    assign_re = re.compile(
        rf"\b\w+\s*->\s*{re.escape(member)}\s*=\s*([A-Za-z_]\w*)\s*;",
    )
    for file_path, source in sorted(source_texts.items()):
        spans = function_spans(source, file_path)
        lines = source.splitlines()
        for span in spans:
            if span.name == invoking_function:
                continue
            segment = lines[span.start - 1:span.end]
            for text in segment:
                m = assign_re.search(text)
                if m and m.group(1) in set(span.params):
                    return span.name, not span.is_static
    return None, False


def _region_comment(segment: list[str], start_line: int,
                    region: _Region) -> str:
    """Quote an in-region comment mentioning the lock/callback (the
    documented-behaviour receipt)."""
    lo = region.acquire_line - start_line
    hi = region.release_line - start_line
    for offset in range(max(lo, 0), min(hi + 1, len(segment))):
        m = _COMMENT_RE.search(segment[offset])
        if m and re.search(r"lock|callback|reentr|deadlock",
                           m.group(1), re.IGNORECASE):
            return m.group(1).strip().rstrip("*/").strip()
    return ""


def _entry_reachability(
    inventory: dict[str, Any] | None,
    context: Any,
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    if context is None:
        return None
    try:
        from .fail_open_verify import _entry_reachability as _fo_reach
    except ImportError:
        return None
    try:
        return _fo_reach(context, inventory, file_path, function_name)
    except Exception:
        logger.debug("lock_region: reachability escalator failed",
                     exc_info=True)
        return None


def _grade(region: _Region, setter_exported: bool) -> str:
    """Registry rule-id only for a registry-vocabulary lock pair AND
    an application-registrable (exported-setter) callback."""
    if region.pair_source in ("seed", "learned") and setter_exported:
        return RULE_CALLBACK_UNDER_LOCK
    return RULE_CALLBACK_UNDER_LOCK + DETECTION_VARIANT_SUFFIX


def status_for(result: LockRegionEvidence) -> str:
    """Both-escalators status rule (§5.3): even registry-grade
    confirmations cap at ``suspicious`` unless entry-reachable AND
    setter-exported."""
    if result.outcome != "confirmed":
        return "suspicious"
    reach = (result.reachability or {}).get("status", "")
    exported = bool((result.callback or {}).get("setter_exported"))
    if reach == "entry_reachable" and exported and \
            not is_detection_rule_id(result.rule_id):
        return "finding"
    return "suspicious"


# ── channel entry points ────────────────────────────────────────────


def _adjudicate_function(
    source_texts: dict[str, str],
    file_path: str,
    span: Any,
    *,
    vocab: Any = None,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
) -> LockRegionEvidence | None:
    """Adjudicate one function. Returns None when the function has no
    lock shape at all (prepass skip)."""
    source = source_texts.get(file_path, "")
    lines = source.splitlines()
    segment = lines[span.start - 1:span.end]
    regions, unresolved = _find_regions(segment, span.start, vocab)
    if not regions and not unresolved:
        return None

    registered = _registered_callback_names(source, vocab)
    refutations: list[LockRegionEvidence] = []
    for region in regions:
        invocations, cancels = _in_region_invocations(
            segment, span.start, region, registered, vocab,
        )
        if not invocations:
            if cancels:
                refutations.append(LockRegionEvidence(
                    outcome="refuted",
                    reason=(
                        f"the only in-region invocation is the "
                        f"teardown-safe {cancels[0]['expr']}() at "
                        f"line {cancels[0]['line']} (cancel verb)"
                    ),
                    lock=_lock_dict(region),
                    region=_region_dict(file_path, region),
                    callback=cancels[0],
                ))
            else:
                refutations.append(LockRegionEvidence(
                    outcome="refuted",
                    reason=(
                        f"{region.release}() at line "
                        f"{region.release_line} precedes every "
                        f"callback-shaped invocation — no invocation "
                        f"inside the {region.acquire}() region"
                    ),
                    lock=_lock_dict(region),
                    region=_region_dict(file_path, region),
                ))
            continue

        inv = invocations[0]
        member = inv.get("member", "")
        setter, exported = _setter_witness(
            source_texts, member, span.name,
        ) if member else (None, False)
        rule = _grade(region, exported)
        result = LockRegionEvidence(
            outcome="confirmed",
            reason=(
                f"{inv['expr']}(...) invoked at {file_path}:"
                f"{inv['line']} inside the {region.acquire}/"
                f"{region.release} region "
                f"({region.acquire_line}-{region.release_line}, "
                f"lock pair source: {region.pair_source}"
                + (f"; setter {setter}() "
                   f"{'exported' if exported else 'internal'}"
                   if setter else "; no setter found")
                + ")"
            ),
            rule_id=rule,
            lock=_lock_dict(region),
            region=_region_dict(file_path, region),
            callback={
                "shape": inv["shape"],
                "expr": inv["expr"],
                "line": inv["line"],
                "code": inv["code"],
                "registered_by": setter,
                "setter_exported": exported,
            },
            comment=_region_comment(segment, span.start, region),
        )
        result.reachability = _entry_reachability(
            inventory, context, file_path, span.name,
        )
        return result

    if refutations:
        return refutations[0]

    # Unresolved acquires only: release in a callee vs missing.
    un = unresolved[0]
    rel_name = un["release"]
    for other_file, other_src in sorted(source_texts.items()):
        callee_names = set(re.findall(
            r"\b([A-Za-z_]\w*)\s*\(",
            "\n".join(segment),
        )) - _C_KEYWORDS
        from .field_census import function_spans
        for other_span in function_spans(other_src, other_file):
            if other_span.name not in callee_names:
                continue
            body = "\n".join(
                other_src.splitlines()[
                    other_span.start - 1:other_span.end
                ],
            )
            if re.search(rf"\b{re.escape(rel_name)}\s*\(", body):
                return _inconclusive(
                    REASON_REGION_SPANS_CALLEE,
                    f"{un['acquire']}() at line {un['line']} is "
                    f"released in callee {other_span.name}() — "
                    f"cross-function regions are phase 2",
                )
    return _inconclusive(
        REASON_PAIR_UNRESOLVED,
        f"no {rel_name}() release found for {un['acquire']}() at "
        f"line {un['line']} — possible lock-imbalance territory "
        f"(CWE-667 chain)",
    )


def _lock_dict(region: _Region) -> dict[str, Any]:
    return {
        "acquire": region.acquire,
        "release": region.release,
        "variable": region.variable,
        "pair_source": region.pair_source,
        "provenance": f"lock_pairs:{region.pair_source}",
    }


def _region_dict(file_path: str, region: _Region) -> dict[str, Any]:
    return {
        "file": file_path,
        "span": [region.acquire_line, region.release_line],
    }


def _language_supported(file_path: str) -> bool:
    try:
        from core.inventory.languages import detect_language
        lang = detect_language(file_path)
    except Exception:
        lang = None
    if lang is not None:
        return lang in ("c", "cpp")
    return Path(file_path).suffix in (
        ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
    )


def run_lock_region_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    source_texts: dict[str, str] | None = None,
    domain_vocab: Any = None,
    budget_s: float | None = None,
) -> LockRegionEvidence:
    """Adjudicate one callback-under-lock hypothesis (O(one file))."""
    del budget_s  # phase-2 cross-function parameter
    del hypothesis  # the classifier already gated dispatch on it
    if not _language_supported(file_path):
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            f"no lock_region analyzer for "
            f"{Path(file_path).suffix or 'unknown'}",
        )
    if source_texts is None:
        try:
            p = Path(target_path) / file_path
            source_texts = {
                file_path: p.read_text(encoding="utf-8",
                                       errors="replace"),
            }
        except OSError:
            return _inconclusive(
                REASON_HYPOTHESIS_UNBINDABLE,
                f"could not read {file_path}",
            )
    source = source_texts.get(file_path, "")
    if not source:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"could not read {file_path}",
        )

    from .field_census import function_spans
    spans = function_spans(source, file_path)
    tail = function_name.rsplit(".", 1)[-1]
    span = next((s for s in spans if s.name == tail), None)
    if span is None:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"function {function_name} not found in {file_path}",
        )
    result = _adjudicate_function(
        source_texts, file_path, span,
        vocab=domain_vocab, inventory=inventory, context=context,
    )
    if result is None:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no lock acquire (learned/pack/seed pair or *_lock stem) "
            f"found in {function_name}",
        )
    return result


# ── cocci corroboration leg ─────────────────────────────────────────


def cocci_corroboration(
    target_path: Path,
    result: LockRegionEvidence,
) -> str | None:
    """Post-confirmation corroboration: run the parametric
    ``callback_under_lock.cocci`` rule with ``-D lock -D unlock`` from
    the confirmed pair. Returns the independent ``coccinelle``
    namespace stamp on a match, else None. Never load-bearing — any
    failure degrades to the single-namespace receipt."""
    if result.outcome != "confirmed" or not result.lock:
        return None
    lock = result.lock.get("acquire", "")
    unlock = result.lock.get("release", "")
    ident = re.compile(r"\A[A-Za-z_]\w*\Z")
    if not (ident.match(lock) and ident.match(unlock)):
        return None
    try:
        from packages.coccinelle.runner import is_available, run_rule
        if not is_available():
            return None
        rule_path = Path(__file__).resolve().parents[2] \
            / "engine" / "coccinelle" / "rules" \
            / f"{COCCI_RULE_NAME}.cocci"
        if not rule_path.is_file():
            return None
        res = run_rule(
            Path(target_path),
            str(rule_path),
            defines={"lock": lock, "unlock": unlock},
            timeout=120,
            allow_scripting=True,
        )
        if res.matches:
            return COCCI_STAMP
    except Exception:
        logger.debug("lock_region: cocci corroboration failed",
                     exc_info=True)
    return None


# ── standing pre-pass ───────────────────────────────────────────────


def run_lock_region_prepass(
    source_texts: dict[str, str],
    *,
    domain_vocab: Any = None,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    budget_s: float = PREPASS_BUDGET_S,
    max_candidates: int = MAX_PREPASS_CANDIDATES,
) -> dict[str, Any]:
    """Standing pre-pass: string-prefiltered candidates (a lock
    acquire AND an indirect-call shape in the same function), Tier-1
    adjudication, confirmed shapes seeded as handoff hypotheses.
    Returns the consistency-prepass shape."""
    t0 = time.monotonic()
    telemetry: dict[str, Any] = {
        "dimensions": {},
        "inconclusive_reasons": {},
        "candidates": 0,
        "budget_exceeded": False,
    }
    leads: list[dict[str, Any]] = []
    mechanical: list[dict[str, Any]] = []
    handoffs: list[dict[str, Any]] = []
    counts = telemetry["dimensions"].setdefault(
        "callback-under-lock",
        {"confirmed": 0, "refuted": 0, "inconclusive": 0},
    )

    acquire_names = [a for a, _, _ in _lock_pairs(domain_vocab)]
    from .field_census import function_spans

    for file_path in sorted(source_texts):
        if time.monotonic() - t0 > budget_s:
            telemetry["budget_exceeded"] = True
            break
        if not _language_supported(file_path):
            continue
        source = source_texts[file_path]
        if "->" not in source:
            continue
        if not (
            any(a in source for a in acquire_names)
            or re.search(r"\b\w+_lock\s*\(", source)
        ):
            continue
        lines = source.splitlines()
        for span in function_spans(source, file_path):
            if telemetry["candidates"] >= max_candidates:
                break
            segment = "\n".join(lines[span.start - 1:span.end])
            if not _INDIRECT_CALL_RE.search(segment):
                continue
            if not (
                any(a in segment for a in acquire_names)
                or re.search(r"\b\w+_lock\s*\(", segment)
            ):
                continue
            telemetry["candidates"] += 1
            res = _adjudicate_function(
                source_texts, file_path, span,
                vocab=domain_vocab, inventory=inventory,
                context=context,
            )
            if res is None:
                continue
            counts[res.outcome] = counts.get(res.outcome, 0) + 1
            if res.outcome == "inconclusive":
                key = res.reason.split(":", 1)[0]
                telemetry["inconclusive_reasons"][key] = (
                    telemetry["inconclusive_reasons"].get(key, 0) + 1
                )
                continue
            if res.outcome != "confirmed":
                continue
            cb = res.callback or {}
            handoffs.append({
                "file": file_path,
                "function": span.name,
                "line": cb.get("line", span.start),
                "mechanism": (
                    f"callback invoked while lock held: {res.reason} "
                    f"(deadlock if the callback re-enters an API "
                    f"taking the same lock; CWE-833)"
                ),
            })
            mechanical.append({
                "file": file_path,
                "function": span.name,
                "detector": "callback_under_lock",
                "line": cb.get("line", span.start),
                "description": res.reason,
                "callee": cb.get("expr", ""),
                "rule_id": res.rule_id,
                "cwe": "CWE-833",
            })
            if len(leads) < MAX_LEADS:
                leads.append({
                    "dimension": "callback-under-lock",
                    "callee": cb.get("expr", ""),
                    "file": file_path,
                    "function": span.name,
                    "line": cb.get("line", span.start),
                    "rule_id": res.rule_id,
                    "description": res.reason[:300],
                    "security_relevant": True,
                    "contract_source": (
                        (res.lock or {}).get("pair_source", "")
                    ),
                    "sites": [],
                })

    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)
    return {
        "leads": leads,
        "mechanical": mechanical,
        "handoffs": handoffs,
        "telemetry": telemetry,
    }
