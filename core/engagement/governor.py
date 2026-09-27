"""Engagement depth policy — mechanical tier assignment over the
artifact ledger.

The governor decides HOW DEEP each ledger artifact is engaged and (in
the budget half of this module) how much of the operator's envelope a
segment may charge. Depth is an artifact-level wrapper over the audit
triage vocabulary — :class:`core.audit.triage.TriageBucket` — never a
second vocabulary:

======  ==============================  ===================
tier    engagement meaning              triage bucket
======  ==============================  ===================
T0      inventory only                  ``skip``
T1      map                             ``glance``
T2      map + study                     ``investigate``
T3      + audit + siblings + validate   ``deep_dive``
======  ==============================  ===================

Doctrine (pinned by
``.github/tests/test_engagement_governor_doctrine.py``):

- **Depth assignment is mechanical (M3a).** The LLM never assigns
  depth. Every input is a ledger fact whose row already cites its
  mechanical extractor; this module must never import an LLM /
  dispatch seam. Assignment is a pure, deterministic function of the
  ledger document: same document, same policy.
- **Single-signal T3.** Any ONE exposure signal suffices for T3 —
  multi-signal gates widen an attacker's evasion window (suppressing
  one signal is cheaper than suppressing all), and the audit's own
  per-function triage is the real cost governor inside a T3 chain.
  The signal set is a fixed feature vocabulary
  (:data:`T3_SIGNAL_FEATURES` plus the ledger's forged-identity
  ``elevated_interest`` flag); each recorded signal carries the
  extractor string the ledger row cited.
- **Depth floors are score-independent (M3b).** Every analyzable
  binary class floors at T1 (derived from the ledger's format-tier
  table — ELF full/near-full and the core-capable PE/Mach-O tiers),
  no matter how low it scored. An artifact ``DT_NEEDED`` by a T3
  artifact floors at T2 — DEPTH-1 ONLY: promotion is computed in one
  pass over the signal-earned T3 set and never cascades through the
  promoted artifacts.
- **Stratified sampling (M3c).** A bounded pseudo-random subset of
  low-tier artifacts is promoted to T2 per engagement. The sample is
  seeded from a launch-minted nonce PLUS the eligible artifact-id
  set: the nonce (persisted on the engagement policy block, loaded —
  never re-minted — on every later read) keeps the sample
  unpredictable to whoever authored the artifact bytes, since ids are
  content-derived and an ids-only seed is precomputable offline;
  the id set keeps it row-order independent. A resume over the same
  persisted ledger reproduces the sample exactly.
- **Scored-low is not verified-low (M3d).** Every at-floor assignment
  records ``low_exposure_verified``: ``True`` only when the full
  mechanical exposure pass demonstrably ran (ELF facts extracted, no
  row caps hit); everything else is merely scored-low and the report
  layer renders the two differently.
- **Second-life provenance (principle 9).** Policy records are free
  of target bytes BY CONSTRUCTION: they reference minted artifact
  ids, fixed-vocabulary feature names and extractor module paths —
  and because the ledger document itself sits inside sandbox write
  grants, every string copied out of it is token-charset-gated before
  it enters a policy record. Budgets and costs are operator /
  config / estimator-derived, never target-derived. Rendering still
  escapes everything per ``core.security.log_sanitisation``.

State lives in the ledger (``core.engagement.ledger`` owns the
schema): per-row ``policy`` slots, per-row ``reservation`` slots, the
document-level ``policy`` block, and the append-only
``policy_amendments`` trail. A RESUME loads the slots — the amended
policy — and never recomputes assignment over rows that already carry
one (S15: no oscillation); rows that JOINED after launch (a rebuild
added or re-minted an artifact id) get floors and signals assigned on
load with a residual naming them, so M3b holds across resume.

Trust model, stated plainly: the read-side gates cover INJECTION
(token/escape collapse on strings copied out of the document) and
MONEY CLAMPS (finite, bounded figures) — not tier semantics. A
ledger-file edit that rewrites tiers, amendments or statuses is
within the accepted local-file trust model: the document sits behind
the run directory's write grants, exactly like the C1 status slots it
extends.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.audit.triage import TriageBucket
from core.engagement.ledger import (
    FORMAT_TIER_BY_CLASS,
    TIER_CORE,
    TIER_FULL,
    TIER_NEAR_FULL,
    append_residual,
    is_artifact_id,
    set_artifact_policies,
    update_engagement_policy,
)
from core.security.log_sanitisation import sanitise_for_terminal

logger = logging.getLogger(__name__)

POLICY_VERSION = 1

# ── Tier vocabulary (wrappers over the triage buckets) ───────────────
TIER_T0 = "T0"
TIER_T1 = "T1"
TIER_T2 = "T2"
TIER_T3 = "T3"
TIER_ORDER: tuple[str, ...] = (TIER_T0, TIER_T1, TIER_T2, TIER_T3)
_TIER_RANK: dict[str, int] = {t: i for i, t in enumerate(TIER_ORDER)}

TIER_BUCKET: dict[str, TriageBucket] = {
    TIER_T0: TriageBucket.SKIP,
    TIER_T1: TriageBucket.GLANCE,
    TIER_T2: TriageBucket.INVESTIGATE,
    TIER_T3: TriageBucket.DEEP_DIVE,
}


def tier_bucket(tier: str) -> TriageBucket:
    """The triage bucket an engagement tier wraps."""
    return TIER_BUCKET[tier]


def depth_label(tier: str) -> str:
    """The ledger status ``depth`` label (``T2:investigate``) — fits
    the ledger's charset-gated depth slot."""
    return f"{tier}:{TIER_BUCKET[tier].value}"


# ── Assignment basis vocabulary ──────────────────────────────────────
BASIS_SIGNAL = "exposure_signal"
BASIS_FLOOR = "floor"
BASIS_NEEDED_BY_T3 = "needed_by_t3"
BASIS_SAMPLE = "stratified_sample"
BASIS_CLASS_DEFAULT = "class_default"

#: Exposure features that individually earn T3 (single-signal
#: doctrine). All three are mechanical extractions the ledger row
#: cites an extractor for: recovered input channels, dangerous-API
#: import surface, kernel driver entry symbols.
T3_SIGNAL_FEATURES: frozenset[str] = frozenset({
    "input_channels", "sink_imports", "driver_entry_symbols",
})
#: The forged-identity flag is signal-grade too: an identity collision
#: is a finding-grade anomaly (ledger M2) — an artifact somebody
#: bothered to disguise is engaged at full depth.
_ELEVATED_INTEREST_FEATURE = "elevated_interest"
_ELEVATED_INTEREST_EXTRACTOR = "core.engagement.ledger"

#: Ledger format-capability tiers whose per-class chain can actually
#: run — these floor at T1 (M3b: "every ELF ≥ T1" plus the
#: core-capable PE/Mach-O tiers on the same landed substrate).
#: classify-only / container / data / degraded classes default to T0:
#: assigning map depth to an artifact no chain can map would be a
#: fake floor.
_ANALYSABLE_FORMAT_TIERS: frozenset[str] = frozenset({
    TIER_FULL, TIER_NEAR_FULL, TIER_CORE,
})

# Stratified-sampling bounds (M3c), both directions: a LARGER sample
# spends real budget re-verifying artifacts the mechanical score
# already cleared — at engagement scale that crowds out T3 work; a
# SMALLER one weakens the check that low scores are honest. One
# promotion per _SAMPLE_DIVISOR low-tier artifacts, capped at
# _SAMPLE_MAX per engagement, floor 1 while any low-tier artifact
# exists.
_SAMPLE_MAX = 4
_SAMPLE_DIVISOR = 25

_RENDER_MAX = 120


def _now() -> str:
    # Z-suffixed (not "+00:00"): policy-slot timestamps live in
    # token-validated fields whose charset has no "+".
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _esc(value: str) -> str:
    return sanitise_for_terminal(value, max_len=_RENDER_MAX)


#: The read-side copy gate mirrors the ledger's write-side
#: ``_POLICY_TOKEN_RE`` EXACTLY (ASCII, same charset, same length
#: bound): a wider read gate (e.g. Unicode ``isalnum``) would accept
#: a tampered-doc string here that the validated writer then refuses,
#: turning a hostile document into a crash instead of a degrade.
_COPY_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\[\]:,-]{1,120}$")


def _copy_token(value: Any, fallback: str) -> str:
    """A string copied from the ledger document, token-gated: accepted
    verbatim only when it is provably vocabulary-shaped (the ledger's
    own ASCII policy-token charset); anything else — including hostile
    or merely non-ASCII bytes planted in a tampered document —
    collapses to ``fallback``, so the read side always DEGRADES and
    never feeds the writer a value it would raise on."""
    if isinstance(value, str) and _COPY_TOKEN_RE.fullmatch(value):
        return value
    return fallback


# ── Assignment records ───────────────────────────────────────────────

@dataclass(frozen=True)
class DepthAssignment:
    """One artifact's mechanical tier assignment."""

    artifact_id: str
    tier: str
    basis: str
    floor: str
    signals: tuple[tuple[str, str], ...] = ()   # (feature, extractor)
    promoted_by: tuple[str, ...] = ()           # minted consumer ids
    low_exposure_verified: bool | None = None

    @property
    def bucket(self) -> TriageBucket:
        return TIER_BUCKET[self.tier]

    def to_policy_slot(self, assigned_at: str) -> dict[str, Any]:
        """The ledger row ``policy`` slot for this assignment."""
        slot: dict[str, Any] = {
            "tier": self.tier,
            "bucket": self.bucket.value,
            "basis": self.basis,
            "floor": self.floor,
            "assigned_at": assigned_at,
        }
        if self.signals:
            slot["signals"] = [
                {"feature": f, "extractor": e} for f, e in self.signals
            ]
        if self.promoted_by:
            slot["promoted_by"] = list(self.promoted_by)
        if self.low_exposure_verified is not None:
            slot["low_exposure_verified"] = self.low_exposure_verified
        return slot


@dataclass(frozen=True)
class DepthPolicy:
    """The launch assignment over one ledger document."""

    assignments: tuple[DepthAssignment, ...]
    sample_seed: str
    sampled_ids: tuple[str, ...]
    counts: dict[str, int] = field(default_factory=dict)
    #: The nonce the sample seed was derived under — persisted with
    #: the launch summary so a resume reproduces the sample.
    sample_nonce: str = ""

    def by_id(self) -> dict[str, DepthAssignment]:
        return {a.artifact_id: a for a in self.assignments}


# ── Mechanical assignment (pure over the document) ───────────────────

def _row_signals(row: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Exposure signals present on one row, each carrying the
    extractor string the ledger cited (token-gated on copy)."""
    signals: list[tuple[str, str]] = []
    for feature in row.get("exposure") or []:
        if not isinstance(feature, dict):
            continue
        name = feature.get("feature")
        if name not in T3_SIGNAL_FEATURES:
            continue
        signals.append((
            str(name),
            _copy_token(feature.get("extractor"), "unrecognized"),
        ))
    if row.get("elevated_interest"):
        signals.append((_ELEVATED_INTEREST_FEATURE,
                        _ELEVATED_INTEREST_EXTRACTOR))
    return tuple(signals)


def _row_floor(row: dict[str, Any]) -> str:
    """Score-independent floor (M3b), derived from the ledger's
    format-capability tier table — never from any score."""
    cls = str(row.get("class") or "")
    format_tier = FORMAT_TIER_BY_CLASS.get(cls)
    if format_tier in _ANALYSABLE_FORMAT_TIERS:
        return TIER_T1
    return TIER_T0


def _low_exposure_verified(row: dict[str, Any]) -> bool:
    """M3d: ``True`` only when the full mechanical exposure pass
    demonstrably ran — the row carries an ELF-facts-extracted feature
    and hit no caps. A row whose facts extraction failed, whose class
    has no exposure extractor, or that hit any cap is merely
    SCORED-low."""
    if row.get("caps_hit"):
        return False
    for feature in row.get("exposure") or []:
        if (isinstance(feature, dict)
                and feature.get("extractor")
                == "core.binary.elf.extract_elf_facts"):
            return True
    return False


def _mint_sample_nonce() -> str:
    """Launch-time sampling nonce: 128 bits of OS entropy, hex.
    Minted ONCE per engagement (first :func:`ensure_policy` over a
    slot-less document) and persisted on the engagement policy block;
    every later read LOADS the stored value, so resume determinism
    rides on persistence, never on re-derivation. Without the nonce
    the sample seed would be a pure function of the artifact-id set —
    ids are content-derived, so whoever ships the install tree could
    compute the sample offline and byte-tweak an artifact until it
    dodges the sampled set. The doctrine fence pins this call as the
    module's ONLY unseeded entropy source."""
    return os.urandom(16).hex()


def _doc_sample_nonce(doc: dict[str, Any]) -> str:
    """The persisted sampling nonce (``""`` when the document carries
    none) — token-gated on copy like every string read back from the
    sandbox-writable document."""
    block = doc.get("policy")
    if not isinstance(block, dict):
        return ""
    return _copy_token(block.get("sample_nonce"), "")


def _sample_seed(nonce: str, eligible_ids: list[str]) -> str:
    """Deterministic sample seed over (nonce, eligible id set): the
    persisted launch nonce keeps the sample non-precomputable from
    the ids alone; the sorted id join keeps it row-order independent.
    Reproducible from the persisted ledger alone (resume-safe)."""
    material = nonce + "|" + "|".join(sorted(eligible_ids))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _sample_count(n_eligible: int) -> int:
    if n_eligible <= 0:
        return 0
    return min(_SAMPLE_MAX, max(1, n_eligible // _SAMPLE_DIVISOR),
               n_eligible)


def assign_depth(
    doc: dict[str, Any],
    *,
    sample_nonce: str | None = None,
) -> DepthPolicy:
    """Assign every ledger row an engagement tier — pure, mechanical,
    deterministic over ``(document, nonce)``. No LLM input of any
    kind (M3a). ``sample_nonce`` seeds the stratified sample; when
    ``None`` it is read from the document's persisted policy block
    (so the function stays a pure function of the document), and an
    absent nonce degrades to ``""`` — :func:`ensure_policy` is the
    seam that MINTS and persists a real nonce at launch.

    Order of operations (each later step only raises tiers):

    1. class floor (M3b) — T1 for analyzable binary classes, T0
       otherwise;
    2. exposure signals — any single signal ⇒ T3;
    3. DT_NEEDED promotion — providers a signal-earned T3 artifact
       links against floor at T2, depth-1 only (no cascade);
    4. stratified sampling (M3c) — a bounded, seed-deterministic
       subset of the remaining low-tier analyzable artifacts is
       promoted to T2.
    """
    rows = [r for r in doc.get("rows") or [] if isinstance(r, dict)]
    tiers: dict[str, str] = {}
    basis: dict[str, str] = {}
    floors: dict[str, str] = {}
    signals: dict[str, tuple[tuple[str, str], ...]] = {}
    promoted_by: dict[str, list[str]] = {}
    rows_by_id: dict[str, dict[str, Any]] = {}

    for row in rows:
        artifact_id = str(row.get("artifact_id") or "")
        if not is_artifact_id(artifact_id) or artifact_id in rows_by_id:
            continue
        rows_by_id[artifact_id] = row
        floor = _row_floor(row)
        floors[artifact_id] = floor
        row_sigs = _row_signals(row)
        signals[artifact_id] = row_sigs
        if row_sigs:
            tiers[artifact_id] = TIER_T3
            basis[artifact_id] = BASIS_SIGNAL
        elif floor != TIER_T0:
            tiers[artifact_id] = floor
            basis[artifact_id] = BASIS_FLOOR
        else:
            tiers[artifact_id] = TIER_T0
            basis[artifact_id] = BASIS_CLASS_DEFAULT

    # DT_NEEDED promotion, depth-1 only: computed over the artifacts
    # that earned T3 BY SIGNAL — the promoted set never propagates.
    providers_by_name: dict[str, list[str]] = {}
    for entry in doc.get("reverse_needed") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        providers_by_name[name] = [
            p for p in entry.get("providers") or []
            if isinstance(p, str) and is_artifact_id(p) and p in tiers
        ]
    signal_t3 = [aid for aid, t in tiers.items()
                 if t == TIER_T3 and basis[aid] == BASIS_SIGNAL]
    for consumer_id in sorted(signal_t3):
        links = rows_by_id[consumer_id].get("links") or {}
        for needed in links.get("needed") or []:
            if not isinstance(needed, str):
                continue
            for provider_id in providers_by_name.get(needed, ()):
                if provider_id == consumer_id:
                    continue
                if _TIER_RANK[tiers[provider_id]] < _TIER_RANK[TIER_T2]:
                    tiers[provider_id] = TIER_T2
                    basis[provider_id] = BASIS_NEEDED_BY_T3
                consumers = promoted_by.setdefault(provider_id, [])
                if (consumer_id not in consumers
                        and len(consumers) < 32):
                    consumers.append(consumer_id)

    # Stratified sampling (M3c) over what is STILL low-tier and
    # analyzable — sampling a class no chain can engage would spend
    # nothing and verify nothing.
    eligible = sorted(
        aid for aid, t in tiers.items()
        if _TIER_RANK[t] < _TIER_RANK[TIER_T2]
        and floors[aid] != TIER_T0
    )
    nonce = (sample_nonce if sample_nonce is not None
             else _doc_sample_nonce(doc))
    seed = _sample_seed(nonce, eligible)
    k = _sample_count(len(eligible))
    sampled: list[str] = []
    if k:
        rng = random.Random(int(seed[:16], 16))
        sampled = sorted(rng.sample(eligible, k))
        for aid in sampled:
            tiers[aid] = TIER_T2
            basis[aid] = BASIS_SAMPLE

    assignments: list[DepthAssignment] = []
    for aid in sorted(tiers):
        verified: bool | None = None
        if _TIER_RANK[tiers[aid]] <= _TIER_RANK[TIER_T1] \
                or basis[aid] == BASIS_SAMPLE:
            verified = _low_exposure_verified(rows_by_id[aid])
        assignments.append(DepthAssignment(
            artifact_id=aid,
            tier=tiers[aid],
            basis=basis[aid],
            floor=floors[aid],
            signals=signals.get(aid, ()),
            promoted_by=tuple(promoted_by.get(aid, ())),
            low_exposure_verified=verified,
        ))

    counts: dict[str, int] = {}
    for a in assignments:
        counts[a.tier] = counts.get(a.tier, 0) + 1
        counts[f"basis:{a.basis}"] = counts.get(f"basis:{a.basis}", 0) + 1
        if a.low_exposure_verified is True:
            counts["verified_low_exposure"] = (
                counts.get("verified_low_exposure", 0) + 1)
        elif a.low_exposure_verified is False:
            counts["scored_low"] = counts.get("scored_low", 0) + 1
    return DepthPolicy(
        assignments=tuple(assignments),
        sample_seed=seed,
        sampled_ids=tuple(sampled),
        counts=counts,
        sample_nonce=nonce,
    )


# ── Persistence (slots are the authority; resume loads them) ─────────

def write_policy(
    output_dir: Any, policy: DepthPolicy,
) -> dict[str, dict[str, Any]]:
    """Materialize a launch assignment: every row's ``policy`` slot in
    one flock pass, plus the engagement block's launch summary.
    Returns the written slots by artifact id."""
    assigned_at = _now()
    slots = {
        a.artifact_id: a.to_policy_slot(assigned_at)
        for a in policy.assignments
    }
    written = set_artifact_policies(output_dir, slots)
    if written != len(slots):
        logger.warning(
            "governor: %d of %d policy slots landed on ledger rows",
            written, len(slots))
    updates: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "launch": {
            "assigned_at": assigned_at,
            "sample_seed": policy.sample_seed,
            "sampled_ids": list(policy.sampled_ids),
            "counts": dict(policy.counts),
        },
    }
    if policy.sample_nonce:
        # Persist the nonce the sample was drawn under: a resume (or
        # a second process) LOADS it — the sample is never re-derived
        # from ids alone.
        updates["sample_nonce"] = policy.sample_nonce
    update_engagement_policy(output_dir, updates)
    return slots


def load_assignments(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The materialized (possibly AMENDED) per-row policy slots —
    what a resume must consume instead of recomputing launch policy
    (S15)."""
    out: dict[str, dict[str, Any]] = {}
    for row in doc.get("rows") or []:
        if not isinstance(row, dict):
            continue
        slot = row.get("policy")
        artifact_id = str(row.get("artifact_id") or "")
        if isinstance(slot, dict) and is_artifact_id(artifact_id):
            out[artifact_id] = slot
    return out


def _late_assignments(
    doc: dict[str, Any],
    existing: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Floors + signals for rows that JOINED after launch (a rebuild
    added or re-minted an artifact id): without this pass a
    late-joined artifact would sit slot-less — no tier, no floor,
    absent from the schedule — silently unengaged, contradicting M3b
    across resume. Existing (possibly amended) slots stay
    authoritative and are never recomputed, and the launch sample is
    never re-drawn — late rows get exactly the two row-local steps
    (floor, signals ⇒ T3)."""
    assigned_at = _now()
    slots: dict[str, dict[str, Any]] = {}
    for row in doc.get("rows") or []:
        if not isinstance(row, dict):
            continue
        artifact_id = str(row.get("artifact_id") or "")
        if (not is_artifact_id(artifact_id) or artifact_id in existing
                or artifact_id in slots):
            continue
        floor = _row_floor(row)
        row_sigs = _row_signals(row)
        if row_sigs:
            tier, basis = TIER_T3, BASIS_SIGNAL
        elif floor != TIER_T0:
            tier, basis = floor, BASIS_FLOOR
        else:
            tier, basis = TIER_T0, BASIS_CLASS_DEFAULT
        verified: bool | None = None
        if _TIER_RANK[tier] <= _TIER_RANK[TIER_T1]:
            verified = _low_exposure_verified(row)
        slots[artifact_id] = DepthAssignment(
            artifact_id=artifact_id, tier=tier, basis=basis,
            floor=floor, signals=row_sigs,
            low_exposure_verified=verified,
        ).to_policy_slot(assigned_at)
    return slots


def ensure_policy(
    output_dir: Any, doc: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], bool]:
    """The engagement's effective policy: rows already carrying policy
    slots are LOADED (they embody every amendment applied so far —
    S15's no-oscillation rule); only a slot-less document gets a fresh
    mechanical assignment, under a freshly minted (then persisted)
    sampling nonce. Rows that joined AFTER launch get floors/signals
    assigned on load, with a residual naming them. Returns
    ``(slots_by_id, freshly_assigned)``.
    """
    existing = load_assignments(doc)
    if existing:
        late = _late_assignments(doc, existing)
        if late:
            set_artifact_policies(output_dir, late)
            named = ",".join(sorted(late))
            append_residual(
                output_dir, "late_policy_assignment",
                f"{len(late)} artifact(s) joined after launch; "
                f"floors/signals assigned: {named}")
            existing = {**existing, **late}
        return existing, False
    nonce = _doc_sample_nonce(doc) or _mint_sample_nonce()
    policy = assign_depth(doc, sample_nonce=nonce)
    return write_policy(output_dir, policy), True


# ── Priority scheduling ──────────────────────────────────────────────

def schedule_order(doc: dict[str, Any]) -> list[str]:
    """Deterministic engagement order over rows carrying policy slots:
    deepest tier first (T3 leads), more signals first within a tier,
    then smaller artifacts first (fast feedback), then artifact id."""
    rows_by_id: dict[str, dict[str, Any]] = {}
    for row in doc.get("rows") or []:
        if isinstance(row, dict):
            rows_by_id.setdefault(str(row.get("artifact_id") or ""), row)
    keyed: list[tuple[int, int, int, str]] = []
    for artifact_id, slot in load_assignments(doc).items():
        rank = _TIER_RANK.get(str(slot.get("tier")), 0)
        n_signals = len(slot.get("signals") or [])
        size = rows_by_id.get(artifact_id, {}).get("size_bytes")
        size = size if isinstance(size, int) and size >= 0 else 0
        keyed.append((-rank, -n_signals, size, artifact_id))
    return [aid for _, _, _, aid in sorted(keyed)]


# ── Rendering (M3d: scored-low vs verified-low, escaped) ─────────────

def render_policy_lines(doc: dict[str, Any]) -> list[str]:
    """Operator summary of the materialized policy — every string that
    could carry document bytes escapes through the log-sanitisation
    contract."""
    slots = load_assignments(doc)
    lines: list[str] = []
    if not slots:
        lines.append("Depth policy: not assigned")
        return lines
    by_tier: dict[str, int] = {}
    by_basis: dict[str, int] = {}
    verified_low = 0
    scored_low = 0
    for slot in slots.values():
        tier = _esc(str(slot.get("tier") or "?"))
        by_tier[tier] = by_tier.get(tier, 0) + 1
        b = _esc(str(slot.get("basis") or "?"))
        by_basis[b] = by_basis.get(b, 0) + 1
        flag = slot.get("low_exposure_verified")
        if flag is True:
            verified_low += 1
        elif flag is False:
            scored_low += 1
    lines.append(f"Depth policy: {len(slots)} artifact(s) assigned")
    for tier in sorted(by_tier, reverse=True):
        label = _esc(depth_label(tier)) if tier in TIER_BUCKET else tier
        lines.append(f"  {label:<16s} {by_tier[tier]:>5d}")
    lines.append("  basis: " + ", ".join(
        f"{b}={by_basis[b]}" for b in sorted(by_basis)))
    lines.append(
        f"  low-tier honesty: {verified_low} verified-low-exposure, "
        f"{scored_low} scored-low (exposure pass incomplete)")
    block = doc.get("policy") or {}
    launch = block.get("launch") if isinstance(block, dict) else None
    if isinstance(launch, dict) and launch.get("sampled_ids"):
        sampled = [
            _esc(str(s)) for s in launch["sampled_ids"]
            if isinstance(s, str)
        ]
        lines.append(
            f"  stratified sample: {len(sampled)} promoted to T2 "
            f"({', '.join(sampled)})")
    return lines


__all__ = [
    "BASIS_CLASS_DEFAULT",
    "BASIS_FLOOR",
    "BASIS_NEEDED_BY_T3",
    "BASIS_SAMPLE",
    "BASIS_SIGNAL",
    "POLICY_VERSION",
    "T3_SIGNAL_FEATURES",
    "TIER_BUCKET",
    "TIER_ORDER",
    "TIER_T0",
    "TIER_T1",
    "TIER_T2",
    "TIER_T3",
    "DepthAssignment",
    "DepthPolicy",
    "assign_depth",
    "depth_label",
    "ensure_policy",
    "load_assignments",
    "render_policy_lines",
    "schedule_order",
    "tier_bucket",
    "write_policy",
]
