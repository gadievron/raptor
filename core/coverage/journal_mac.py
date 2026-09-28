"""HMAC provenance for review-journal rows.

Review-journal entries are the durable record the gap fold trusts: a
row whose ``verdict`` is conclusive and whose ``source_hash`` matches
the current source SUPPRESSES future review of that function (and,
when eligible, is imported as a $0 reused verdict). The journal lives
in run/project directories that are target-writable during runs and
restorable verbatim by ``/project import`` — and rows were plain
unauthenticated JSON, so a forged ``clean`` row silenced review of a
function forever.

Writers stamp each row at append time with an HMAC-SHA256 token over
the row's canonical JSON (token key excluded); the fold verifies
before granting a row verdict-reuse authority, and rows whose token
is present but invalid are skipped entirely (tampered). Rows with NO
token (pre-MAC legacy, or forged-unstamped) keep fold-credit only
behind the exact full-length source-hash gate and are never eligible
for $0 verdict reuse — the tolerant-reader compromise that avoids a
re-review storm on upgrade while denying unauthenticated rows every
authority tier above "the source hash checks out". Same trust story
and key-handling discipline as ``core/witness/provenance.py`` /
``core/llm/scorecard/integrity.py``.

Key
    ``$XDG_DATA_HOME/raptor/journal-mac.key`` (default
    ``~/.local/share/raptor/journal-mac.key``). Deliberately its OWN
    key file — per-purpose keys keep reset/rotation semantics scoped.
    No rotation: deleting the key demotes every stamped row to the
    unstamped tier (fold-credit behind the hash gate, no reuse) and
    new appends re-key lazily.

The ``.audit-log.jsonl`` event log in the same directory carries one
row class with the same authority (resume review-suppression via
``get_reviewed_set``) and gets the same treatment through its own
domain prefix (:func:`mint_audit_log_row` /
:func:`verify_audit_log_row`): writers stamp every appended event,
and the resume reader lets a row suppress ONLY when its token
verifies — everything else in the log stays telemetry-tier and
tolerant. UNLIKE journal rows, audit-log tokens ARE run-bound: the
MAC covers the run dir's resolved-path identity
(:func:`audit_log_run_binding`), supplied implicitly by whichever
directory the verifier reads — a row copied verbatim from a sibling
run's log fails verification, because the audit-log lane has no
source-hash gate or fold to bound a replay the way the journal does
(a replayed clean row is NOT genuine history for another run's
resume set). Moving a run dir demotes its rows to unstamped —
re-review, the safe direction, same posture as cross-install.

No run binding for JOURNAL rows: they deliberately travel across
runs — the project index aggregates them and cross-run verdict reuse
is the feature. A replayed validly-stamped row is genuine history
for the exact source hash it names; staleness is bounded by the
fold's hash compare, not the MAC, and the reuse import demotes the
row's tool receipts to prior-claim context
(``journal:recall:<origin>``) rather than confirming evidence. The
one journal consumer that DOES grant a row run-attributed receipt
authority — the journal-derived graded export — therefore adds a
run-scope check on top of the MAC: ``run_id`` is covered by the
token, so a verified row's run attribution is authentic, and
receipts are honoured only when it names the consuming run
(legacy rows without attribution grandfather with a visible
marker). A byte-copied row still verifies as genuine INSTALL
history; it no longer passes as another run's own record.

Forward compatibility: verification round-trips the row through this
reader's dataclass, so a row written by a NEWER schema (additive
fields this reader doesn't know) — or stamped by another install's
key — reads as token-present-but-unverifiable. That is NOT treated
as a distinct security tier: whoever can edit a row can simply strip
its token and land in the unstamped tier anyway, so consumers demote
unverifiable rows to the same unstamped tier (exact-hash-gated fold
credit, never verdict reuse) instead of dropping them below it.

Canonicalisation generations. A token attests the row's canonical
byte form, and that form is a shipped artifact: the serializer pin
(``dumps_canonical``), the MAC message derivation, and the row-field
vocabulary the writer's schema could emit. Any of those changing
between mint and verify demotes every honest prior row at once — a
follow-on run then re-buys reviews that were already paid for (an
exhaustive audit run of a large C codebase lost 1,490 prior verdicts
to one such fold). Verification is therefore GENERATION-AWARE:

* every token carries its mint generation — generation 1 is the bare
  64-hex form every writer has ever emitted (absence of a prefix IS
  the gen-1 tag; ``g1:`` is deliberately not an accepted alias), and
  future generations mint ``g<N>:<hex>`` with the generation bound
  into the MAC message (:func:`_mac_message`), so a token can never
  be claimed across generations;
* a row verifies under the generation it was minted with, drawn from
  the CLOSED ladder ``_KNOWN_GENERATIONS`` — each rung an exact byte
  form this repo actually shipped, never a normalizing/fuzzy match.
  An unknown or malformed generation tag fails outright. The strict
  grammar is itself a deliberate fail-closed CHANGE: the
  pre-generation verifier normalised tokens with ``.strip().lower()``,
  so uppercase or whitespace-padded tokens DID verify before. No
  shipped writer ever emitted such a token — every mint is the bare
  lowercase ``hexdigest()`` — so no honest row is affected;
* verification success under a legacy generation grants the SAME
  authority as the current one (the whole point: schema churn must
  not forfeit verdicts), and the index merge re-stamps such rows at
  the current generation so the ladder's live population shrinks;
* a row that verifies under NO known generation demotes exactly as
  before (unstamped tier).

Within generation 1, TWO shipped byte forms exist and both are
enumerated: the reader-projection form (the dataclass round-trip
this module always verified — the only form available for entries
reconstructed programmatically) and the persisted-raw form (the
exact bytes every writer actually minted over, stashed by the
journal loader as :data:`RAW_FORM_ATTR`). The raw form is what keeps
a row verifiable when the live dataclass drifts — the incident
class: a version-skewed reader's round-trip drops a stamped field it
does not know, and projection-only verification then reads honest
rows as tampered. The raw form is bounded by the generation's FIELD
VOCABULARY (:data:`_GENERATION_VOCABULARY`): a row whose extra keys
fall outside the enumerated shipped vocabulary never verifies via
the raw form, preserving the covered-additive-field invariant — a
future writer's authority-bearing field must gate this reader's
authority grant, not slide past it (see
``test_covered_additive_field_demotes_to_tampered``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from pathlib import Path

from core.json.utils import dumps_canonical
from core.logging import get_logger
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

# Sentinel: a key file EXISTS but is unusable (symlink, foreign owner,
# group/other-readable). Distinct from "absent" — an unusable key must
# never be silently replaced and must never mint or verify.
_REFUSED = mac_key.REFUSED

_warned_paths: set = set()

# Row key holding the token. Popped before canonicalisation so the
# MAC covers everything else in the row.
TOKEN_KEY = "integrity"

#: Tri-state provenance of a loaded row.
ROW_VERIFIED = "verified"
ROW_TAMPERED = "tampered"
ROW_UNSTAMPED = "unstamped"

# --- Canonicalisation generations (see module docstring) -------------------

#: Generation new tokens are minted at. Gen 1 = bare 64-hex token,
#: legacy MAC message (domain + sha), the only form ever shipped.
#: Shared by ALL FOUR MAC domains (journal, audit-log, prep-cache,
#: coverage-row): a future bump to 2 starts minting ``g2:`` tokens on
#: every lane, not just the journal — version-skewed older readers of
#: the other lanes' artifacts would demote them too, so the
#: bump-owning change must account for all four lanes.
GENERATION_CURRENT = 1

# Ladder size limit — a churn-prone constant, rationale in BOTH
# directions (regression tests pin each):
#   too small  — a shipped generation falling off the ladder demotes
#                every honest row still carrying its token: the exact
#                mass-forfeiture this machinery exists to prevent.
#                The ladder must always hold generation 1 (rows from
#                before the tag existed) and GENERATION_CURRENT.
#   too large  — each rung is one more exact byte form a forger may
#                target and one more HMAC on every demote path (the
#                fold walks tens of thousands of rows), and a ladder
#                that keeps growing means generations are being
#                minted faster than the merge-time re-stamp retires
#                them. Bump this only together with a re-stamp story
#                for the oldest rung.
_GENERATION_LADDER_MAX = 4

#: CLOSED enumeration of canonicalisation generations this repo has
#: shipped. Never extended at runtime; adding a generation is a code
#: change that also defines its MAC message form and field
#: vocabulary below.
_KNOWN_GENERATIONS: frozenset[int] = frozenset({1})

#: Every retired journal-row field name (shipped in the dataclass,
#: later removed). Retired names STAY in the generation vocabulary —
#: historical rows carrying them keep verifying via the raw form —
#: and this set exists so the vocabulary lockstep test can prove the
#: vocabulary is exactly (current dataclass fields | retired names),
#: never an open-ended pattern.
RETIRED_ROW_FIELDS: frozenset[str] = frozenset()

#: Per-generation row-field vocabulary: the field names a writer at
#: that generation could stamp. A frozen LITERAL record independent
#: of the live dataclass — that independence is the point: the live
#: schema drifts, the shipped generation does not. The lockstep test
#: (test_journal_mac_generations) fails when the dataclass gains a
#: field that is not recorded here, so extending the schema is
#: always a deliberate vocabulary extension too.
_GENERATION_VOCABULARY: dict[int, frozenset[str]] = {
    1: frozenset({
        "body",
        "body_offload",
        "confidence",
        "context_reduced",
        "cost_usd",
        "counter_hypothesis",
        "cwe",
        "domain_concepts_available",
        "domain_model_hash",
        "domain_slice_hash",
        "duration_s",
        "edge_callee",
        "edge_verdicts",
        "error_class",
        "evidence_tools",
        "file",
        "function",
        "function_qualified",
        "hypotheses",
        "integrity",
        "invariants_available",
        "lesson",
        "line_end",
        "line_start",
        "model",
        "prior_review",
        "producer",
        "provisional",
        "reading_list_items",
        "reused",
        "reused_from_run",
        "run_id",
        "run_path",
        "schema_version",
        "seed_provenance",
        "seed_rereview",
        "source_drifted",
        "source_hash",
        "strategies",
        "strategy_id",
        "study_receipts",
        "token_budget",
        "tools_dispatched",
        "tools_skipped",
        "ts",
        "validate_reason",
        "validate_verdict",
        "verdict",
        "verdict_rationale",
    }),
}

#: Attribute the journal loader stashes on entries whose PERSISTED
#: row carries keys the local dataclass does not know: a
#: ``(sha256_hex, frozenset(extra_keys))`` pair over the raw
#: persisted row (token excluded). This is the raw-form ladder rung's
#: input — without it, verification of such a row could only use the
#: lossy dataclass projection and would read the honest row as
#: tampered. Never persisted (not a dataclass field; ``asdict`` and
#: ``replace`` both drop it), and it attests the AS-LOADED bytes: an
#: entry reconstructed or copied programmatically simply has no raw
#: form and verifies via the projection like before.
RAW_FORM_ATTR = "_journal_raw_form"

_HEX64 = re.compile(r"[0-9a-f]{64}")


def parse_token(token: object) -> tuple[int, str] | None:
    """``(generation, mac_hex)`` for a well-formed token, else None.

    Closed grammar: a bare LOWERCASE 64-hex string is a generation-1
    token (``g1:`` is NOT an accepted alias — one byte form per
    shipped token, no normalisation: uppercase hex, surrounding
    whitespace, and leading-zero generation digits are all
    malformed), and ``g<N>:<64-hex>`` with ASCII ``N >= 2`` (no
    leading zeros, at most 3 digits) is a generation-N token.
    Anything else is malformed and verifies nowhere. The
    no-normalisation rule is a deliberate fail-closed CHANGE from the
    pre-generation verifier (which ``.strip().lower()``-ed the token,
    so uppercase / padded variants used to verify); no shipped writer
    ever emitted a non-canonical token, so no honest row is affected.
    """
    if not isinstance(token, str):
        return None
    t = token
    if t.startswith("g"):
        head, sep, mac_hex = t.partition(":")
        digits = head[1:]
        if (
            sep
            and digits.isascii()
            and digits.isdigit()
            and len(digits) <= 3
            and not digits.startswith("0")
            and _HEX64.fullmatch(mac_hex)
        ):
            generation = int(digits)
            if generation >= 2:
                return generation, mac_hex
        return None
    if _HEX64.fullmatch(t):
        return 1, t
    return None


def token_generation(token: object) -> int | None:
    """The generation a well-formed token claims, else None."""
    parsed = parse_token(token)
    return parsed[0] if parsed else None


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "journal-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"journal integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"journal integrity: refusing key {path} — {reason}. Journal "
        f"rows will not mint or verify (stamped rows demote to the "
        f"unstamped tier: hash-gated fold credit only, no verdict "
        f"reuse) until this is fixed: {remedy}"
    )


def _read_existing_key(path: Path) -> bytes | mac_key.Refused | None:
    """Read an EXISTING key with the shared fd-fstat discipline
    (:func:`core.security.mac_key.read_existing_key`): refuse symlinks
    (O_NOFOLLOW + fstat on the opened inode), foreign owners, and any
    group/other permission bits."""
    return mac_key.read_existing_key(
        path, key_len=_KEY_LEN, warn=_warn_once_suspect_key)


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent — the shared hardened discipline in
    :func:`core.security.mac_key.load_or_create_key`. Returns None
    when a key file exists but is unusable — the suspect key is never
    used, never replaced. The creation-race loser polls through the
    winner's create-to-write window instead of mis-flagging the
    mid-write key as suspect (which left the loser's rows unstamped —
    demoted to the no-reuse tier — under a false suspect-key
    warning)."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key)


def key_usable() -> bool:
    """Whether this install can mint/verify tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def row_sha256(row: dict) -> str:
    """sha256 over the row's canonical JSON (token key excluded).

    Canonical form: :func:`core.json.utils.dumps_canonical` (stdlib
    ``sort_keys=True, separators=(",", ":"), default=str`` — the
    repo-wide frozen canonical byte form; its tests pin byte-identity
    against this function) — key order and whitespace don't matter,
    values do. The token covers the WHOLE row (verdict, source_hash,
    spans, producer, model, strategies, body, ...): partial coverage
    would let an attacker rewrite the unauthenticated remainder of a
    validly-stamped row."""
    scrubbed = {k: v for k, v in row.items() if k != TOKEN_KEY}
    canonical = dumps_canonical(scrubbed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Domain separation: a token minted for another artifact class can
# never verify here even if a key were ever shared by mistake. The
# audit event log shares the journal's key (same trust domain —
# review-suppression authority in target-writable run dirs; deleting
# the key demotes both artifact classes together) but its own domain
# prefix, so journal tokens never authenticate audit-log rows or vice
# versa.
_JOURNAL_DOMAIN = b"review-journal-row\x00"
_AUDIT_LOG_DOMAIN = b"audit-log-row\x00"
_PREP_CACHE_DOMAIN = b"prep-cache-artifact\x00"
_COVERAGE_ROW_DOMAIN = b"coverage-analysed-row\x00"


def _mac_message(
    sha256_hex: str,
    domain: bytes = _JOURNAL_DOMAIN,
    generation: int = 1,
) -> bytes:
    """MAC message for one row hash under one generation.

    Generation 1 is the legacy byte form every shipped token was
    minted with — it MUST stay byte-identical forever or every
    existing token demotes at once. Generations >= 2 bind the
    generation number into the message (NUL-terminated, so it can
    never collide with a hex row hash), which domain-separates the
    generations: a token minted at one generation cannot be replayed
    with another generation's tag.
    """
    if generation == 1:
        return domain + sha256_hex.encode("ascii")
    return (
        domain
        + f"g{generation}\x00".encode("ascii")
        + sha256_hex.encode("ascii")
    )


def _format_token(generation: int, mac_hex: str) -> str:
    return mac_hex if generation == 1 else f"g{generation}:{mac_hex}"


def _mint(
    row: dict, domain: bytes, generation: int | None = None,
) -> str | None:
    gen = GENERATION_CURRENT if generation is None else generation
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    mac_hex = hmac.new(
        key, _mac_message(row_sha256(row), domain, gen), hashlib.sha256,
    ).hexdigest()
    return _format_token(gen, mac_hex)


def _verify_sha(
    sha256_hex: str, mac_hex: str, domain: bytes, generation: int,
) -> bool:
    """Constant-time check of one MAC against one exact row hash
    under one generation. Never raises — any failure is the caller's
    demote path."""
    try:
        key = _load_or_create_key()
    except OSError:
        return False
    if not key:
        return False
    try:
        expected = hmac.new(
            key, _mac_message(sha256_hex, domain, generation),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, mac_hex)
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def _verify(row: dict, token: str | None, domain: bytes) -> bool:
    if not token:
        return False
    try:
        parsed = parse_token(token)
        if parsed is None:
            return False
        generation, mac_hex = parsed
        if generation not in _KNOWN_GENERATIONS:
            # Closed ladder: a generation this checkout has not
            # shipped verifies nowhere (fail-closed; the row demotes
            # to the unstamped tier like any unverifiable token).
            return False
        return _verify_sha(row_sha256(row), mac_hex, domain, generation)
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def mint_row(row: dict) -> str | None:
    """Hex HMAC-SHA256 token over the row's canonical payload, or
    None when no usable key is available. Writers treat None as
    "persist unstamped" — the fold then applies unstamped-tier
    semantics."""
    return _mint(row, _JOURNAL_DOMAIN)


def verify_row(row: dict, token: str | None) -> bool:
    """Whether *token* is a valid MAC over *row*'s canonical payload
    under this install's key. Constant-time; never raises — any
    failure is the caller's demote path."""
    return _verify(row, token, _JOURNAL_DOMAIN)


def audit_log_run_binding(out_dir: Path | str) -> str:
    """The run identity bound into audit-log tokens: the run dir's
    resolved path. Derived — never stored in the row or read from a
    run-dir artifact (an attacker holding the run-dir write grant
    could plant any STORED identity alongside a copied log; the
    consumer's own directory cannot be forged from inside it). One
    derivation for writers and the reader."""
    try:
        return str(Path(out_dir).resolve())
    except OSError:
        return str(out_dir)


def _audit_domain(run_binding: str) -> bytes:
    return (_AUDIT_LOG_DOMAIN
            + run_binding.encode("utf-8", "surrogatepass") + b"\x00")


def mint_audit_log_row(row: dict, run_binding: str) -> str | None:
    """Token for a ``.audit-log.jsonl`` row (the journal's sibling
    suppression lane): the resume path grants ``action=record`` /
    ``orchestrator_review`` rows review-SUPPRESSION authority, and the
    log lives in the same target-writable run dir whose forged-clean-
    row problem motivated the journal MAC. Same canonical form and
    key, own domain, RUN-BOUND via *run_binding*
    (:func:`audit_log_run_binding` — a row replayed from a sibling
    run's log must not verify). ``None`` = persist unstamped (the row
    keeps its telemetry value; it just never suppresses)."""
    return _mint(row, _audit_domain(run_binding))


def verify_audit_log_row(
    row: dict, token: str | None, run_binding: str,
) -> bool:
    """Audit-log twin of :func:`verify_row`, against the VERIFIER'S
    own run binding. Consumers that grant a row suppression authority
    MUST fail toward NOT suppressing when this returns False
    (unstamped legacy, tampered, and cross-run-replayed rows all
    re-review — the same tolerant-reader compromise as the journal's
    unstamped tier, which grants no verdict authority either)."""
    return _verify(row, token, _audit_domain(run_binding))


def _prep_cache_domain(run_binding: str) -> bytes:
    return (_PREP_CACHE_DOMAIN
            + run_binding.encode("utf-8", "surrogatepass") + b"\x00")


def mint_prep_cache_row(row: dict, run_binding: str) -> str | None:
    """Token for a ``prep-cache/`` artifact row (fingerprint +
    payload): resumed segments serve these payloads back as
    MECHANICAL analysis inputs (detector results, codeql prep,
    consistency prepass), and the cache lives in the target-writable
    run dir while its fingerprint is computed over attacker-knowable
    inputs — so fingerprint equality alone authenticates nothing.
    Same canonical form and key as the journal, own domain, RUN-BOUND
    via :func:`audit_log_run_binding` (a payload replayed from a
    sibling run must not verify). ``None`` = persist unstamped (the
    loader then treats it as a miss and rebuilds — fail toward
    recompute)."""
    return _mint(row, _prep_cache_domain(run_binding))


def verify_prep_cache_row(
    row: dict, token: str | None, run_binding: str,
) -> bool:
    """Prep-cache twin of :func:`verify_audit_log_row`. Loaders MUST
    treat False as a cache miss (rebuild from the tree) — never serve
    an unverified payload."""
    return _verify(row, token, _prep_cache_domain(run_binding))


def _coverage_row_domain(tool: str) -> bytes:
    return (_COVERAGE_ROW_DOMAIN
            + str(tool).encode("utf-8", "surrogatepass") + b"\x00")


def mint_coverage_row(row: dict, tool: str) -> str | None:
    """Token for one ``functions_analysed`` row of a coverage record.

    Coverage records are the OTHER durable review-suppression lane
    beside the journal: a ``functions_analysed`` row under a
    review-grade tool label removes the named function from the gap
    fold's review queue, and the records live in the same
    target-writable run/project directories — a dropped
    ``coverage-llm.json`` naming a function silenced its review with
    no stamp, no verdict and no source evidence. Same canonical form
    and key as the journal, own domain.

    Per-ROW, not per-record, deliberately: the mark/unmark CLI and
    the run-completion snapshot read-modify-write whole records, so a
    record-level token would re-stamp — launder — any planted row
    that was sitting in the file when a legitimate writer next saved
    it. Rows are stamped once at CREATION (record builders, the mark
    CLI append) and copied verbatim by every RMW writer, so a planted
    row stays unstamped no matter how many legitimate saves follow.

    TOOL-BOUND: the record's ``tool`` label is part of the domain,
    because the label is what grades a row's authority — a row
    legitimately minted for a scanned-tier record (``understand``
    map-grade marks: examination evidence, never review credit) must
    not verify when replayed into a review-grade ``coverage-llm.json``.
    Not run-bound, same rationale as journal rows: records aggregate
    across runs by design and a replayed stamped row is genuine
    install history for the row it names.

    ``None`` = persist unstamped — the fold then grants credit only
    behind the exact full-length source-hash gate
    (``core.audit.gaps._build_covered_set``), the journal's
    tolerant-reader compromise. That gate is source-CURRENCY, not
    authentication: the hash is unkeyed and computable from readable
    source, so a hash-carrying plant passes it — the gate exists to
    keep legacy rows credited while refusing hashless plants and
    stale credit. Authorship assurance is this token, nothing
    weaker."""
    return _mint(row, _coverage_row_domain(tool))


def verify_coverage_row(row: dict, token: str | None, tool: str) -> bool:
    """Coverage-row twin of :func:`verify_row`, against the record's
    ``tool`` label. Consumers that grant a row review-suppression
    authority MUST fail toward NOT suppressing when this returns
    False unless the row carries positive source-hash evidence."""
    return _verify(row, token, _coverage_row_domain(tool))


def coverage_row_provenance(row: dict, tool: str) -> str:
    """Tri-state provenance of one ``functions_analysed`` row dict —
    same tiers and consumer semantics as :func:`entry_provenance`
    (``tampered`` is attribution, not a security boundary: consumers
    give it unstamped-tier authority)."""
    token = row.get(TOKEN_KEY)
    if not token:
        return ROW_UNSTAMPED
    return (ROW_VERIFIED if verify_coverage_row(row, str(token), tool)
            else ROW_TAMPERED)


def entry_provenance(entry) -> str:
    """Tri-state provenance of a loaded ``ReviewJournalEntry``.

    * ``verified`` — token present and valid for the row's content
      under the generation it was minted with (see
      :func:`entry_provenance_detail` — legacy-generation and
      raw-form verification grant the SAME authority).
    * ``tampered`` — token present but invalid under every known
      generation: content edited, a row minted by another install,
      or a row written by a newer schema whose extra fields fall
      outside the shipped vocabulary. Consumers give these the same
      authority as ``unstamped`` (the token is strippable, so
      "tampered" is attribution, not a security boundary) but log
      them distinctly.
    * ``unstamped`` — no token (pre-MAC legacy or forged-unstamped):
      fold-credit only behind the exact source-hash gate, never
      verdict reuse.
    """
    return entry_provenance_detail(entry)[0]


#: ``entry_provenance_detail`` reason strings — the fold's telemetry
#: bucket names. ``verified``-tier reasons first.
REASON_CURRENT_FORM = "current_form"
REASON_LEGACY_GENERATION = "legacy_generation"
REASON_RAW_FORM = "raw_form"
REASON_UNSTAMPED = "unstamped"
REASON_MALFORMED_TOKEN = "malformed_token"
REASON_UNKNOWN_GENERATION = "unknown_generation"
REASON_HASH_MISMATCH = "hash_mismatch"


def entry_provenance_detail(entry) -> tuple[str, str]:
    """``(tier, reason)`` provenance of a loaded entry.

    The tier is :func:`entry_provenance`'s tri-state; the reason is
    the telemetry bucket that keeps canonicalisation drift loud in
    the fold log:

    * ``verified`` / ``current_form`` — token verifies over this
      reader's dataclass projection at the current generation.
    * ``verified`` / ``legacy_generation`` — token verifies over the
      projection under an OLDER ladder generation. Same authority;
      the index merge re-stamps these at the current generation.
    * ``verified`` / ``raw_form`` — the projection is lossy for this
      row (the persisted row carries shipped-vocabulary fields this
      reader's dataclass does not know) and the token verifies over
      the loader-stashed persisted-raw form instead. Same authority:
      the raw bytes are exactly what the writer minted, and the
      consumer only ever acts on the MAC-covered subset it can see.
    * ``tampered`` / ``hash_mismatch`` — no generation and no
      enumerated form verifies: edited content, a foreign key, a
      reduced copy whose stamped field a version-skewed merge
      dropped, or a covered field outside the shipped vocabulary.
    * ``tampered`` / ``unknown_generation`` — well-formed tag naming
      a generation outside the closed ladder.
    * ``tampered`` / ``malformed_token`` — token fits no shipped
      token grammar at all.
    * ``unstamped`` / ``unstamped`` — no token.
    """
    token = getattr(entry, "integrity", None)
    if not token:
        return ROW_UNSTAMPED, REASON_UNSTAMPED
    parsed = parse_token(token)
    if parsed is None:
        return ROW_TAMPERED, REASON_MALFORMED_TOKEN
    generation, mac_hex = parsed
    if generation not in _KNOWN_GENERATIONS:
        return ROW_TAMPERED, REASON_UNKNOWN_GENERATION
    try:
        projected_sha = row_sha256(entry.to_dict())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        projected_sha = None
    if projected_sha is not None and _verify_sha(
            projected_sha, mac_hex, _JOURNAL_DOMAIN, generation):
        return ROW_VERIFIED, (
            REASON_CURRENT_FORM if generation == GENERATION_CURRENT
            else REASON_LEGACY_GENERATION)
    raw_form = getattr(entry, RAW_FORM_ATTR, None)
    if raw_form:
        raw_sha, extra_keys = raw_form
        vocabulary = _GENERATION_VOCABULARY.get(generation, frozenset())
        # Vocabulary bound: extra keys outside the enumerated shipped
        # vocabulary never verify — a future writer's covered
        # (possibly authority-bearing) field must gate this reader's
        # authority grant, not slide past it.
        if frozenset(extra_keys) <= vocabulary and _verify_sha(
                raw_sha, mac_hex, _JOURNAL_DOMAIN, generation):
            return ROW_VERIFIED, REASON_RAW_FORM
    return ROW_TAMPERED, REASON_HASH_MISMATCH


__all__ = [
    "GENERATION_CURRENT",
    "RAW_FORM_ATTR",
    "REASON_CURRENT_FORM",
    "REASON_HASH_MISMATCH",
    "REASON_LEGACY_GENERATION",
    "REASON_MALFORMED_TOKEN",
    "REASON_RAW_FORM",
    "REASON_UNKNOWN_GENERATION",
    "REASON_UNSTAMPED",
    "RETIRED_ROW_FIELDS",
    "ROW_TAMPERED",
    "ROW_UNSTAMPED",
    "ROW_VERIFIED",
    "TOKEN_KEY",
    "audit_log_run_binding",
    "coverage_row_provenance",
    "entry_provenance",
    "entry_provenance_detail",
    "key_usable",
    "mint_audit_log_row",
    "mint_coverage_row",
    "mint_prep_cache_row",
    "mint_row",
    "parse_token",
    "row_sha256",
    "token_generation",
    "verify_audit_log_row",
    "verify_coverage_row",
    "verify_prep_cache_row",
    "verify_row",
]
