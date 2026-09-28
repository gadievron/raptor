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

Concurrency, stated plainly: the budget verbs (reserve / reconcile /
death / degradation) are read-check-write — the load and the
validated write each take the document flock separately, so the
envelope check is race-free only under the engagement's
SINGLE-ORCHESTRATOR assumption (one governor process per run
directory, which is how every caller runs it). Cross-process
DOCUMENT integrity still holds unconditionally — every write is
flocked and atomic — so a second orchestrator could transiently
over-admit a reservation, never corrupt the ledger.
"""

from __future__ import annotations

import hashlib
import logging
import math
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
    append_policy_amendment,
    append_residual,
    is_artifact_id,
    load_ledger,
    load_policy_amendments,
    set_artifact_policies,
    set_artifact_policy,
    set_artifact_status,
    update_engagement_policy,
)
from core.run.estimator import estimate_from_scorecard
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


# ══ Budget governor (M4) ═════════════════════════════════════════════
#
# Every segment launch charges a PESSIMISTIC reservation against the
# operator's envelope; a clean ledger close reconciles it to the
# measured actual; a segment that dies unreconciled KEEPS its
# reservation charged, and enough consecutive unreconciled deaths PARK
# the artifact with a named reason. Estimates are shape-aware from
# ledger mechanical facts only — never an LLM judgment. Budgets,
# envelopes and costs are operator/config/estimator-derived, never
# target bytes; figures read back out of the sandbox-writable document
# still clamp (mirroring the resume spend-evidence doctrine).

# Per-tier work units — the scorecard-call volume one artifact's chain
# is expected to spend at that depth (T1 map: a couple of calls; T2
# +study: order ten; T3 audit + siblings + validate: order sixty).
# Both directions: understating a tier's call volume makes
# reservations admit more work than the envelope funds; overstating
# it makes feasibility park engagements the envelope could complete.
_TIER_UNITS: dict[str, int] = {
    TIER_T0: 0, TIER_T1: 2, TIER_T2: 10, TIER_T3: 60,
}
# Pessimistic per-tier fallbacks when the scorecard cannot estimate
# (<5 recorded calls for the model, or no model given). Both
# directions: too LOW and a cold-start engagement books cheap
# reservations and blows through the envelope; too HIGH and cold-start
# feasibility parks work the envelope could fund. Values sit at the
# expensive end of observed chain shapes so the cold-start error
# direction is refuse-to-overspend.
_TIER_FALLBACK_USD: dict[str, float] = {
    TIER_T0: 0.0, TIER_T1: 1.0, TIER_T2: 8.0, TIER_T3: 75.0,
}

#: Cost shapes — mechanical, from ledger facts alone.
SHAPE_PARSER = "parser_shaped"
SHAPE_RUNTIME = "runtime_heavy"
SHAPE_BALANCED = "balanced"
# Shape multipliers, both directions: parser-shaped artifacts (static
# input-format attack surface) dominate audit/validate call volume —
# under-multiplying them starves exactly the artifacts the engagement
# exists for; runtime-heavy artifacts (big, few libraries — engines,
# blobs with thin import surface) spend mostly mechanical passes —
# over-charging them wastes envelope headroom on work that never
# happens. Parser wins when both patterns match.
_SHAPE_MULTIPLIER: dict[str, float] = {
    SHAPE_PARSER: 2.5, SHAPE_RUNTIME: 0.4, SHAPE_BALANCED: 1.0,
}
#: Input-channel kinds that mark an artifact parser-shaped (the
#: channel vocabulary is the ledger's input_channels extraction).
_PARSER_CHANNEL_KINDS: frozenset[str] = frozenset({"file", "stream"})
# Runtime-heavy pattern: large body, thin dynamic linkage. Both
# directions: a lower size bar sweeps ordinary tools into the cheap
# lane; a higher one misses real engines. A larger needed bound lets
# integration-heavy binaries (many libraries = many seams to audit)
# ride the cheap lane.
_RUNTIME_HEAVY_MIN_BYTES = 8 * 1024 * 1024
_RUNTIME_HEAVY_MAX_NEEDED = 3

# Consecutive unreconciled segment deaths before an artifact parks.
# Both directions: lower and one transient infrastructure flap parks
# real work; higher and a crash-looping artifact burns that many
# reservations (each kept charged) before the governor stops feeding
# it.
PARK_AFTER_DEATHS = 3

# Feasibility verdict boundaries (S16). Both directions: a smaller
# conflict ratio parks unattended engagements over mild pessimism in
# the estimates; a larger one lets an unattended engagement start work
# it can only fund a fraction of. want > envelope is "tight"
# (degradation territory); want > envelope * ratio is "conflict".
_CONFLICT_RATIO = 2.0
VERDICT_FITS = "fits"
VERDICT_TIGHT = "tight"
VERDICT_CONFLICT = "conflict"

# Money ceiling on any figure read back from the document — the
# document sits inside sandbox write grants, so read-side budget math
# clamps exactly like the resume spend-evidence doctrine: an
# overclaim clamps to the ceiling (refuse-to-spend direction), an
# underclaim/NaN clamps to $0.
_MAX_USD = 1e7

# Escalation records share the bounded amendment trail; per-kind cap
# so one repeating condition cannot exhaust the trail. Both
# directions: too low hides that a condition kept firing; too high
# and one noisy kind crowds out the degradation/park history the
# trail exists to keep.
_MAX_SAME_ESCALATIONS = 8

#: Status states that mean an artifact's chain has not started (a
#: missing status slot counts — the build stamps ``inventoried``).
_UNSTARTED_STATES: frozenset[str] = frozenset({"", "inventoried",
                                               "queued"})


def _usd(value: Any) -> float:
    """Finite, bounded, non-negative money figure from document data
    (``0.0`` for non-numeric shapes)."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return 0.0
    v = float(value)
    if not math.isfinite(v):
        v = _MAX_USD if v > 0 else 0.0
    return min(max(0.0, v), _MAX_USD)


def _row_status_state(row: dict[str, Any]) -> str:
    status = row.get("status")
    if isinstance(status, dict):
        return str(status.get("state") or "")
    return ""


def artifact_shape(row: dict[str, Any]) -> str:
    """Mechanical cost shape from ledger facts: parser-shaped when the
    recovered input channels include a byte-stream kind; runtime-heavy
    when the artifact is large with thin dynamic linkage; balanced
    otherwise. Parser wins when both match."""
    for feature in row.get("exposure") or []:
        if (isinstance(feature, dict)
                and feature.get("feature") == "input_channels"):
            kinds = feature.get("value")
            # Type-gate each entry: the document is sandbox-writable
            # and an unhashable entry (list/dict) in a tampered value
            # would raise on the set probe — degrade, never crash.
            if isinstance(kinds, list) and any(
                    isinstance(k, str) and k in _PARSER_CHANNEL_KINDS
                    for k in kinds):
                return SHAPE_PARSER
    size = row.get("size_bytes")
    links = row.get("links") or {}
    needed = links.get("needed") if isinstance(links, dict) else None
    n_needed = len(needed) if isinstance(needed, list) else 0
    if (isinstance(size, int) and size >= _RUNTIME_HEAVY_MIN_BYTES
            and n_needed <= _RUNTIME_HEAVY_MAX_NEEDED):
        return SHAPE_RUNTIME
    return SHAPE_BALANCED


def estimate_artifact_usd(
    row: dict[str, Any],
    tier: str,
    *,
    model: str | None = None,
    max_parallel: int = 3,
) -> tuple[float, str]:
    """Pessimistic per-artifact estimate for one tier's chain:
    scorecard-fed (``cost_high`` — the pessimistic end) when the model
    has history, per-tier fallback otherwise, then shape-multiplied.
    Returns ``(usd, source)`` with source ``scorecard`` / ``fallback``
    / ``none`` (T0 costs nothing)."""
    units = _TIER_UNITS.get(tier, 0)
    if units <= 0:
        return 0.0, "none"
    base: float | None = None
    source = "fallback"
    if model:
        est = estimate_from_scorecard(model, units,
                                      max_parallel=max_parallel)
        if est is not None:
            base = est.cost_high
            source = "scorecard"
    if base is None:
        base = _TIER_FALLBACK_USD.get(tier, _TIER_FALLBACK_USD[TIER_T3])
    usd = _usd(base * _SHAPE_MULTIPLIER[artifact_shape(row)])
    return round(usd, 6), source


def committed_usd(doc: dict[str, Any]) -> float:
    """The envelope charge currently booked across the document:
    reconciled reservations charge their measured actual, open
    (``reserved``) ones — including a parked artifact's kept
    reservation — charge the pessimistic figure."""
    total = 0.0
    for row in doc.get("rows") or []:
        if not isinstance(row, dict):
            continue
        res = row.get("reservation")
        if not isinstance(res, dict):
            continue
        if res.get("state") == "reconciled":
            total += _usd(res.get("actual_usd"))
        elif res.get("state") == "reserved":
            total += _usd(res.get("reserved_usd"))
    return round(min(total, _MAX_USD), 6)


def policy_want(
    doc: dict[str, Any],
    *,
    model: str | None = None,
) -> tuple[float, dict[str, float], str]:
    """What the materialized depth policy STILL wants to spend: the
    summed per-artifact estimates over assigned rows that are not
    parked and carry no reservation — rows whose reservation is open
    or reconciled are already charged by :func:`committed_usd`, so
    counting them here would double-charge. Returns ``(want_usd,
    by_tier, estimate_source)`` — source ``scorecard`` / ``fallback``
    / ``mixed`` / ``none``."""
    rows_by_id: dict[str, dict[str, Any]] = {}
    for row in doc.get("rows") or []:
        if isinstance(row, dict):
            rows_by_id.setdefault(str(row.get("artifact_id") or ""), row)
    want = 0.0
    by_tier: dict[str, float] = {}
    sources: set[str] = set()
    for artifact_id, slot in load_assignments(doc).items():
        row = rows_by_id.get(artifact_id)
        if row is None:
            continue
        if _row_status_state(row) == "parked":
            continue
        res = row.get("reservation")
        if isinstance(res, dict) and res.get("state") in ("reserved",
                                                          "reconciled"):
            # A reconciled row's spend is history, and an OPEN
            # reservation's figure is already booked by committed_usd —
            # estimating either again double-charges the envelope and
            # falsely parks a fundable resume (a killed run holding an
            # open reservation the envelope exactly funds must fit).
            continue
        tier = str(slot.get("tier") or TIER_T0)
        usd, source = estimate_artifact_usd(row, tier, model=model)
        if usd > 0:
            want += usd
            by_tier[tier] = round(by_tier.get(tier, 0.0) + usd, 6)
            sources.add(source)
    if not sources:
        combined = "none"
    elif len(sources) == 1:
        combined = sources.pop()
    else:
        combined = "mixed"
    return round(min(want, _MAX_USD), 6), by_tier, combined


@dataclass(frozen=True)
class FeasibilityVerdict:
    """S16 launch-time feasibility: policy want vs operator envelope.
    Library code only computes and records — an interactive CALLER
    surfaces the choice; unattended enforcement parks BEFORE spend."""

    verdict: str
    want_usd: float
    envelope_usd: float | None
    by_tier: dict[str, float] = field(default_factory=dict)
    estimate_source: str = "none"

    def lines(self) -> list[str]:
        env = ("uncapped" if self.envelope_usd is None
               else f"${self.envelope_usd:.2f}")
        out = [
            f"Engagement feasibility: policy wants ~${self.want_usd:.2f}"
            f" vs envelope {env} — {self.verdict}",
        ]
        for tier in sorted(self.by_tier, reverse=True):
            out.append(f"  {_esc(tier):<4s} ~${self.by_tier[tier]:.2f}")
        out.append(f"  estimates: {_esc(self.estimate_source)}")
        return out


def _envelope(doc: dict[str, Any],
              envelope_usd: float | None) -> float | None:
    """Effective envelope: the caller's figure wins; else the
    engagement policy block's persisted one; else None (uncapped)."""
    if envelope_usd is not None:
        return _usd(envelope_usd)
    block = doc.get("policy")
    if isinstance(block, dict) and isinstance(
            block.get("envelope_usd"), (int, float)):
        return _usd(block["envelope_usd"])
    return None


def set_envelope(output_dir: Any, envelope_usd: float) -> bool:
    """Persist the operator's engagement envelope on the policy block
    (operator/config-derived — refuses non-finite or out-of-range
    figures rather than clamping an operator's typo)."""
    if (isinstance(envelope_usd, bool)
            or not isinstance(envelope_usd, (int, float))
            or not math.isfinite(float(envelope_usd))
            or not 0.0 <= float(envelope_usd) <= _MAX_USD):
        raise ValueError(f"invalid envelope figure: {envelope_usd!r}")
    return update_engagement_policy(output_dir, {
        "envelope_usd": round(float(envelope_usd), 6),
    })


def launch_feasibility(
    doc: dict[str, Any],
    envelope_usd: float | None = None,
    *,
    model: str | None = None,
) -> FeasibilityVerdict:
    """Compute the S16 verdict over the materialized policy: remaining
    envelope (envelope minus already-committed) against the policy's
    want."""
    want, by_tier, source = policy_want(doc, model=model)
    envelope = _envelope(doc, envelope_usd)
    if envelope is None:
        verdict = VERDICT_FITS
    else:
        remaining = max(0.0, envelope - committed_usd(doc))
        if want > remaining * _CONFLICT_RATIO:
            verdict = VERDICT_CONFLICT
        elif want > remaining:
            verdict = VERDICT_TIGHT
        else:
            verdict = VERDICT_FITS
    return FeasibilityVerdict(
        verdict=verdict, want_usd=want, envelope_usd=envelope,
        by_tier=by_tier, estimate_source=source,
    )


def is_engagement_parked(doc: dict[str, Any]) -> bool:
    """True when the whole engagement carries a park record (S16
    pre-spend park or an operator park)."""
    block = doc.get("policy")
    return isinstance(block, dict) and isinstance(
        block.get("parked"), dict)


def park_engagement(
    output_dir: Any,
    reason: str,
    *,
    want_usd: float | None = None,
    envelope_usd: float | None = None,
) -> bool:
    """Park the WHOLE engagement, durably: a ``parked`` record on the
    policy block, a residual, and an amendment — all before any
    segment spend."""
    record: dict[str, Any] = {"reason": str(reason)[:200], "at": _now()}
    if want_usd is not None:
        record["want_usd"] = _usd(want_usd)
    if envelope_usd is not None:
        record["envelope_usd"] = _usd(envelope_usd)
    ok = update_engagement_policy(output_dir, {"parked": record})
    if ok:
        append_residual(output_dir, "engagement_parked",
                        str(reason)[:200])
        append_policy_amendment(output_dir, {
            "kind": "engagement_parked", "reason": str(reason)[:200],
        })
    return ok


def enforce_feasibility(
    output_dir: Any,
    doc: dict[str, Any],
    envelope_usd: float | None = None,
    *,
    attended: bool,
    model: str | None = None,
) -> FeasibilityVerdict:
    """Record the launch feasibility verdict and enforce S16: an
    unattended conflict parks the engagement BEFORE spend. An attended
    conflict only records — the interactive caller owns the structured
    choice (never this library)."""
    verdict = launch_feasibility(doc, envelope_usd, model=model)
    update_engagement_policy(output_dir, {
        "feasibility": {
            "verdict": verdict.verdict,
            "want_usd": verdict.want_usd,
            "envelope_usd": verdict.envelope_usd,
            "estimate_source": verdict.estimate_source,
            "at": _now(),
        },
    })
    if verdict.verdict == VERDICT_CONFLICT and not attended:
        park_engagement(
            output_dir, "feasibility_conflict",
            want_usd=verdict.want_usd,
            envelope_usd=verdict.envelope_usd,
        )
    return verdict


# ── Per-segment reservations ─────────────────────────────────────────

def park_artifact(output_dir: Any, artifact_id: str,
                  reason: str) -> bool:
    """Park one artifact, durably: ledger status ``parked`` with the
    named reason, plus a residual and an amendment."""
    ok = set_artifact_status(output_dir, artifact_id, "parked",
                             detail=str(reason)[:200])
    if ok:
        append_residual(output_dir, "artifact_parked",
                        str(reason)[:200], artifact_id=artifact_id)
        append_policy_amendment(output_dir, {
            "kind": "artifact_parked", "artifact_id": artifact_id,
            "reason": str(reason)[:200],
        })
    return ok


def _find_row(doc: dict[str, Any],
              artifact_id: str) -> dict[str, Any] | None:
    for row in doc.get("rows") or []:
        if (isinstance(row, dict)
                and row.get("artifact_id") == artifact_id):
            return row
    return None


def reserve_segment(
    output_dir: Any,
    artifact_id: str,
    segment: int,
    *,
    model: str | None = None,
    envelope_usd: float | None = None,
    max_parallel: int = 3,
) -> dict[str, Any] | None:
    """Charge a segment's pessimistic reservation at launch. Refuses
    (returns ``None``, with a durable ``reservation_refused``
    residual) when the ENGAGEMENT is parked, the artifact has no
    ledger row / policy slot, is parked, or the charge would push the
    committed total over the envelope. A prior unreconciled
    reservation on the same artifact is REPLACED (its deaths carry) —
    the artifact never double-charges.
    """
    if not is_artifact_id(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    doc = load_ledger(output_dir)
    if doc is None:
        return None
    if is_engagement_parked(doc):
        # Fail closed: an engagement-level park (S16 feasibility
        # conflict) refuses every reservation — otherwise per-segment
        # spend walks straight past the park that exists to stop it.
        append_residual(output_dir, "reservation_refused",
                        "engagement is parked",
                        artifact_id=artifact_id)
        return None
    row = _find_row(doc, artifact_id)
    slot = row.get("policy") if isinstance(row, dict) else None
    if row is None or not isinstance(slot, dict):
        append_residual(output_dir, "reservation_refused",
                        "no ledger row / policy slot",
                        artifact_id=artifact_id if row else None)
        return None
    if _row_status_state(row) == "parked":
        append_residual(output_dir, "reservation_refused",
                        "artifact is parked",
                        artifact_id=artifact_id)
        return None
    tier = str(slot.get("tier") or TIER_T0)
    usd, source = estimate_artifact_usd(row, tier, model=model,
                                        max_parallel=max_parallel)
    prior = row.get("reservation")
    prior_deaths = 0
    prior_charge = 0.0
    if isinstance(prior, dict):
        deaths = prior.get("deaths")
        if isinstance(deaths, int) and not isinstance(deaths, bool):
            prior_deaths = max(0, min(deaths, 1_000))
        if prior.get("state") == "reserved":
            prior_charge = _usd(prior.get("reserved_usd"))
        elif prior.get("state") == "reconciled":
            # The new reservation REPLACES the reconciled record, and
            # the artifact's measured actual is CUMULATIVE across
            # segments — the next reconcile books the prior spend
            # inside its own figure. Leaving the prior actual charged
            # here as well double-counts it against the envelope and
            # falsely parks a fundable follow-on segment.
            prior_charge = _usd(prior.get("actual_usd"))
    envelope = _envelope(doc, envelope_usd)
    if envelope is not None:
        committed_after = committed_usd(doc) - prior_charge + usd
        if committed_after > envelope:
            append_residual(
                output_dir, "reservation_refused",
                f"reserving {usd:.2f} would commit "
                f"{committed_after:.2f} of a {envelope:.2f} envelope",
                artifact_id=artifact_id)
            return None
    reservation: dict[str, Any] = {
        "segment": int(segment),
        "reserved_usd": usd,
        "state": "reserved",
        "deaths": prior_deaths,
        "updated_at": _now(),
        "estimate_source": source,
        "shape": artifact_shape(row),
    }
    if not set_artifact_policy(output_dir, artifact_id,
                               reservation=reservation):
        return None
    return reservation


def reconcile_segment(
    output_dir: Any,
    artifact_id: str,
    actual_usd: float,
) -> dict[str, Any] | None:
    """Clean ledger close: the reservation reconciles to the MEASURED
    actual — typically down from the pessimistic figure, but an actual
    above the reservation still commits (the money is already spent;
    refusing the write would hide it) and leaves a durable
    ``reconcile_over_reservation`` residual. The death counter resets.
    Only an OPEN reservation reconciles — a reconcile with no
    reservation is a caller bug, returned as ``None``."""
    if not is_artifact_id(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    doc = load_ledger(output_dir)
    row = _find_row(doc, artifact_id) if doc else None
    prior = row.get("reservation") if isinstance(row, dict) else None
    if not isinstance(prior, dict) or prior.get("state") != "reserved":
        return None
    actual = _usd(actual_usd)
    reserved = _usd(prior.get("reserved_usd"))
    reservation = dict(prior)
    reservation.update({
        "state": "reconciled",
        "actual_usd": actual,
        "deaths": 0,
        "updated_at": _now(),
    })
    if not set_artifact_policy(output_dir, artifact_id,
                               reservation=reservation):
        return None
    if actual > reserved:
        append_residual(
            output_dir, "reconcile_over_reservation",
            f"actual {actual:.2f} exceeded the reserved "
            f"{reserved:.2f} — envelope excess recorded",
            artifact_id=artifact_id)
    return reservation


def record_segment_death(
    output_dir: Any,
    artifact_id: str,
    *,
    detail: str = "",
) -> dict[str, Any] | None:
    """An unreconciled segment death: the reservation stays charged
    (pessimism is the point — the dead segment may have spent it) and
    the death counter increments. At :data:`PARK_AFTER_DEATHS` the
    artifact parks with the named reason; deaths past that still
    COUNT but never re-park (no duplicate park amendment/residual per
    extra death). Returns ``{"deaths": n, "parked": bool}`` or
    ``None`` when the artifact has no reservation to keep."""
    if not is_artifact_id(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    doc = load_ledger(output_dir)
    row = _find_row(doc, artifact_id) if doc else None
    if row is None:
        return None
    prior = row.get("reservation")
    if not isinstance(prior, dict) or prior.get("state") != "reserved":
        return None
    deaths = prior.get("deaths")
    deaths = deaths if (isinstance(deaths, int)
                        and not isinstance(deaths, bool)
                        and deaths >= 0) else 0
    deaths = min(deaths + 1, 1_000)
    reservation = dict(prior)
    reservation.update({"deaths": deaths, "updated_at": _now()})
    if not set_artifact_policy(output_dir, artifact_id,
                               reservation=reservation):
        return None
    parked = False
    if (deaths >= PARK_AFTER_DEATHS
            and _row_status_state(row) != "parked"):
        # Already-parked artifacts keep counting deaths (the figure
        # stays honest) without minting a duplicate park record.
        reason = f"unreconciled_deaths:{deaths}"
        if detail:
            reason = f"{reason} ({str(detail)[:120]})"
        parked = park_artifact(output_dir, artifact_id, reason)
    return {"deaths": deaths, "parked": parked}


# ── Degradation ladder (S15) + escalations (S9 contact) ─────────────

def apply_degradation(
    output_dir: Any,
    *,
    reason: str,
    model: str | None = None,
) -> dict[str, Any] | None:
    """One rung of budget-pressure degradation, recorded as a policy
    AMENDMENT (S15 — a resume that loads the slots sees the amended
    policy, never the launch policy):

    1. revoke one UNSTARTED stratified-sample promotion (back to its
       floor — sampling is verification spend, first to give);
    2. else park the UNSTARTED artifact with the largest outstanding
       estimate — exhausting NON-signal-earned candidates before any
       signal-earned T3 parks — stamping the parked slot's tier and
       basis into the amendment and the park detail, reason
       ``budget_pressure``.

    One call = one rung on one artifact = one amendment. Returns the
    action record, or ``None`` when nothing is left to degrade.
    """
    doc = load_ledger(output_dir)
    if doc is None:
        return None
    candidates: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for row in doc.get("rows") or []:
        if not isinstance(row, dict):
            continue
        artifact_id = str(row.get("artifact_id") or "")
        slot = row.get("policy")
        if not is_artifact_id(artifact_id) or not isinstance(slot, dict):
            continue
        if _row_status_state(row) not in _UNSTARTED_STATES:
            continue
        # A reservation slot — open OR reconciled — means a segment
        # was already funded for this artifact; degrading it frees
        # nothing (reconciled money is spent, an open reservation is
        # the in-flight segment's). Only truly unfunded work degrades.
        if isinstance(row.get("reservation"), dict):
            continue
        candidates.append((artifact_id, slot, row))

    # Rung 1: revoke a sample promotion.
    for artifact_id, slot, _row in sorted(candidates,
                                          key=lambda c: c[0]):
        if slot.get("basis") != BASIS_SAMPLE:
            continue
        floor = str(slot.get("floor") or TIER_T0)
        if floor not in TIER_BUCKET:
            floor = TIER_T0
        revoked = dict(slot)
        revoked.update({
            "tier": floor,
            "bucket": TIER_BUCKET[floor].value,
            "basis": "sample_revoked",
            "assigned_at": _now(),
        })
        if not set_artifact_policy(output_dir, artifact_id,
                                   policy=revoked):
            continue
        append_policy_amendment(output_dir, {
            "kind": "degradation", "action": "sample_revoked",
            "artifact_id": artifact_id, "tier": floor,
            "reason": str(reason)[:200],
        })
        return {"action": "sample_revoked",
                "artifact_id": artifact_id, "tier": floor}

    # Rung 2: park the most expensive unstarted artifact. Signal-earned
    # T3 rows are the engagement's reason to exist (the parser-shaped
    # ones also carry the LARGEST estimates, so a naive largest-first
    # rung sheds exactly the hottest artifact at the first park) —
    # they park only after every non-signal candidate is exhausted.
    def _best(
        pool: list[tuple[str, dict[str, Any], dict[str, Any]]],
    ) -> tuple[float, str, dict[str, Any]] | None:
        best: tuple[float, str, dict[str, Any]] | None = None
        for artifact_id, slot, row in pool:
            tier = str(slot.get("tier") or TIER_T0)
            usd, _source = estimate_artifact_usd(row, tier,
                                                 model=model)
            if usd <= 0:
                continue
            # Highest estimate wins; the LOWER artifact id breaks
            # ties so the rung is deterministic over any order.
            if (best is None or usd > best[0]
                    or (usd == best[0] and artifact_id < best[1])):
                best = (usd, artifact_id, slot)
        return best

    non_signal = [c for c in candidates
                  if c[1].get("basis") != BASIS_SIGNAL]
    signal_earned = [c for c in candidates
                     if c[1].get("basis") == BASIS_SIGNAL]
    best = _best(non_signal) or _best(signal_earned)
    if best is not None:
        usd, artifact_id, slot = best
        tier_token = _copy_token(slot.get("tier"), "unrecognized")
        basis_token = _copy_token(slot.get("basis"), "unrecognized")
        park_detail = (f"budget_pressure tier={tier_token} "
                       f"basis={basis_token}")
        if park_artifact(output_dir, artifact_id, park_detail):
            append_policy_amendment(output_dir, {
                "kind": "degradation",
                "action": "parked_budget_pressure",
                "artifact_id": artifact_id,
                "estimated_usd": usd,
                "tier": tier_token,
                "basis": basis_token,
                "reason": str(reason)[:200],
            })
            return {"action": "parked_budget_pressure",
                    "artifact_id": artifact_id,
                    "estimated_usd": usd,
                    "tier": tier_token,
                    "basis": basis_token}
    return None


def record_escalation(output_dir: Any, *, kind: str,
                      message: str) -> bool:
    """A governor escalation event (e.g. the coverage journal's
    index-over-budget refusal), durable on the amendment trail.
    Bounded per kind so a repeating condition cannot exhaust the
    trail. No-op (``False``) when the output dir carries no ledger."""
    kind_token = _copy_token(kind, "")
    if not kind_token:
        raise ValueError(f"invalid escalation kind: {kind!r}")
    same = sum(
        1 for a in load_policy_amendments(output_dir)
        if a.get("kind") == "escalation"
        and a.get("escalation") == kind_token
    )
    if same >= _MAX_SAME_ESCALATIONS:
        return False
    seq = append_policy_amendment(output_dir, {
        "kind": "escalation",
        "escalation": kind_token,
        "message": str(message)[:300],
    })
    return seq > 0


__all__ = [
    "BASIS_CLASS_DEFAULT",
    "BASIS_FLOOR",
    "BASIS_NEEDED_BY_T3",
    "BASIS_SAMPLE",
    "BASIS_SIGNAL",
    "PARK_AFTER_DEATHS",
    "POLICY_VERSION",
    "SHAPE_BALANCED",
    "SHAPE_PARSER",
    "SHAPE_RUNTIME",
    "T3_SIGNAL_FEATURES",
    "TIER_BUCKET",
    "TIER_ORDER",
    "TIER_T0",
    "TIER_T1",
    "TIER_T2",
    "TIER_T3",
    "VERDICT_CONFLICT",
    "VERDICT_FITS",
    "VERDICT_TIGHT",
    "DepthAssignment",
    "DepthPolicy",
    "FeasibilityVerdict",
    "apply_degradation",
    "artifact_shape",
    "assign_depth",
    "committed_usd",
    "depth_label",
    "enforce_feasibility",
    "ensure_policy",
    "estimate_artifact_usd",
    "is_engagement_parked",
    "launch_feasibility",
    "load_assignments",
    "park_artifact",
    "park_engagement",
    "policy_want",
    "reconcile_segment",
    "record_escalation",
    "record_segment_death",
    "render_policy_lines",
    "reserve_segment",
    "schedule_order",
    "set_envelope",
    "tier_bucket",
    "write_policy",
]
