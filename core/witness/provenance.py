"""HMAC provenance for witness/feasibility evidence records.

The /validate pipeline persists evidence records inside
``findings.json`` — a document the LLM stage owns writes to in the
skill flow (and that ``--findings`` imports from arbitrary operator
files). Two record shapes in that document claim *mechanical*
provenance and drive verdict-tier decisions:

* ``finding["witness_execution"]`` — "a sandboxed harness executed a
  witness and observed this verdict" (consumers: Stage-E witness
  eligibility skip, ruling upgrades/rule-outs, /audit feedback's
  mechanical-disqualifier import).
* ``finding["feasibility"]`` with ``status == "analyzed"`` — "binary
  feasibility analysis ran and produced this verdict" (consumers:
  final_status mapping to ``exploitable``/``likely_exploitable``,
  scorecard TOOL_EVIDENCE back-prop).

Nothing in the document itself distinguishes records the mechanical
stages produced from records a prompt-injected LLM (or a hostile
findings file) wrote — so forged records were laundered into
operator-facing verdicts as if tool-produced. This module gives the
mechanical writers an unforgeable marker: they stamp each record with
an HMAC-SHA256 token over the exact fields consumers act on; consumers
verify and *demote* records that fail (strip the mechanical claim,
re-derive or re-execute — never an error).

Same trust story and key-handling discipline as
``core/sandbox/telemetry_mac.py`` (which in turn copies
``core/sage/rowmac.py``): the key lives OUTSIDE every LLM-writable and
sandbox-readable tree, symlinked / foreign-owned / group-readable key
files are refused rather than replaced, and verification failure is a
demote path, never an error.

Key
    ``$XDG_DATA_HOME/raptor/witness-mac.key`` (default
    ``~/.local/share/raptor/witness-mac.key``). Deliberately a
    SEPARATE key from rowmac's and telemetry's: per-purpose keys keep
    reset/rotation semantics scoped. No rotation: deleting the key
    makes existing tokens fail verification (records demote to
    LLM-tier and the mechanical stages re-derive), and new runs re-key
    lazily.

Run binding
    Every field set carries the run directory's resolved basename
    (the directory holding the ``findings.json`` the record lives in).
    Without it, any token this install ever minted would verify in ANY
    run directory forever — a hostile findings file could replay a
    validly-stamped record from an old run. The VERIFIER recomputes
    the binding from the directory it is actually reading, so a
    replayed record carries the wrong run's binding and fails
    (cross-run imports re-derive — the safe direction).

    The basename alone is forgeable by layout: any two directories
    sharing a basename verified interchangeably. The binding is
    therefore VERSIONED. New records are minted against
    ``<basename>#<per-run nonce>`` where the nonce lives in a
    ``.witness-binding`` file inside the run directory (created lazily
    at first stamp, 0600, O_EXCL) and travels with the directory on
    archive/move — the documented moved-runs-keep-verifying property
    holds as long as the directory moves whole. Records minted under
    the stronger binding carry ``provenance_binding: "run-nonce"``;
    the marker directs the verifier and cannot be stripped to demote
    the check (a v2 token never verifies against the v1 field set).
    Legacy records (no marker) keep verifying under the basename-only
    rule. The graded verifiers report which binding grade a record
    verified at so consumers can distinguish.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.run.finding_status import read_verdict
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

# Sentinel: a key file EXISTS but is unusable (symlink, foreign owner,
# group/other-readable). Distinct from "absent" — an unusable key must
# never be silently replaced and must never mint or verify.
_REFUSED = mac_key.REFUSED

_warned_paths: set = set()

#: Key under which the token is stored inside the stamped record.
PROVENANCE_KEY = "provenance"

_WITNESS_KIND = "witness-execution"
_FEASIBILITY_KIND = "feasibility-analysis"
_IRIS_KIND = "iris-tier1-refutation"
_SMT_KIND = "smt-path-feasibility"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "witness-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug("witness provenance: suspect key %s (%s)", path, reason)
        return
    _warned_paths.add(key)
    logger.warning(
        "witness provenance: refusing key %s — %s. Evidence provenance "
        "tokens will not mint or verify (consumers demote records to "
        "LLM-tier and re-derive) until this is fixed: %s",
        path, reason, remedy,
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
    mid-write key as suspect (which persisted the loser's evidence
    records unstamped — demoted to LLM-tier and re-derived — under a
    false suspect-key warning)."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key)


def _canonical(fields: Mapping[str, object]) -> bytes:
    """Injective canonical encoding — key-sorted, length-prefixed —
    identical construction to rowmac's / telemetry_mac's."""
    items = sorted((str(k), str(v)) for k, v in fields.items())
    out = bytearray()
    out += len(items).to_bytes(4, "big")
    for key, value in items:
        for part in (key.encode("utf-8"), value.encode("utf-8")):
            out += len(part).to_bytes(4, "big")
            out += part
    return bytes(out)


def key_usable() -> bool:
    """Whether this install can mint/verify tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def mint(fields: Mapping[str, object]) -> str | None:
    """Hex HMAC-SHA256 token over the record *fields*, or None when no
    usable key is available. Writers treat None as "persist unstamped"
    — consumers then demote the record and re-derive."""
    if "kind" not in fields:
        msg = "witness provenance mint: fields must carry 'kind'"
        raise ValueError(msg)
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()


def verify(fields: Mapping[str, object], token: str | None) -> bool:
    """Whether *token* is a valid MAC over *fields* under this
    install's key. Constant-time; never raises — any failure is the
    caller's demote path."""
    if not token:
        return False
    try:
        expected = mint(fields)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def run_binding(run_dir: Path | str) -> str:
    """Legacy (v1) per-run binding: the resolved basename of the
    directory holding the findings document. Basename (not full path)
    so archived/moved runs keep verifying. Records minted today use
    the nonced binding when a per-run nonce is available."""
    return Path(run_dir).resolve().name


# ── Versioned run binding ────────────────────────────────────────────
#
# The v1 basename binding lets any two directories sharing a basename
# verify each other's records (operator restores, attacker-influenced
# layouts). v2 adds a per-run random nonce persisted INSIDE the run
# directory (so archived/moved runs keep verifying) and a record-side
# marker that directs the verifier.

_BINDING_FILE = ".witness-binding"

#: Record key naming the binding grade the record was minted under.
BINDING_GRADE_KEY = "provenance_binding"

#: Binding grades, as reported by the graded verifiers.
#:
#: What each grade DOES and DOES NOT prove — consumers weighting
#: GRADE_RUN_NONCE above GRADE_BASENAME should know both rest on
#: same-user-readable material:
#:
#: * GRADE_RUN_NONCE defeats replay of stamped records ACROSS run
#:   directories (a record minted under run A's nonce never verifies
#:   in run B). It does NOT defeat directory staging by a same-user
#:   reader: verification recomputes the binding from the
#:   ``.witness-binding`` file INSIDE the directory under
#:   verification, so an actor who can read a donor run's nonce file
#:   can stage a directory (donor basename + copied nonce +
#:   selectively copied validly-stamped records) that verifies at
#:   this grade — a PARTIAL clone is indistinguishable from the
#:   documented whole-directory archive/move, and that equivalence is
#:   inherent to the portability property, not a defect a stronger
#:   nonce could remove.
#: * GRADE_BASENAME proves only that the record was minted by this
#:   install for a directory of the same resolved basename.
GRADE_RUN_NONCE = "run-nonce"
GRADE_BASENAME = "basename"

_NONCE_HEX_LEN = 32


def _valid_nonce(text: str) -> bool:
    return (
        len(text) == _NONCE_HEX_LEN
        and all(c in "0123456789abcdef" for c in text)
    )


def _read_run_nonce(run_dir: Path | str) -> str | None:
    """The run's persisted binding nonce, or None (absent/malformed).

    Gated read on the OPEN fd: the binding file lives in the
    directory UNDER VERIFICATION — exactly the surface a stager
    controls — so a planted FIFO must be refused (O_NONBLOCK +
    S_ISREG) instead of hanging every graded verifier, and the read
    is capped (a nonce is 32 hex characters; anything bigger is
    malformed by construction).
    """
    import stat as _stat_mod

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(str(Path(run_dir) / _BINDING_FILE), flags)
    except OSError:
        return None
    try:
        if not _stat_mod.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # fdopen owns it now
            raw = fh.read(_NONCE_HEX_LEN + 16)
    except OSError:
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    return text if _valid_nonce(text) else None


def _load_or_create_run_nonce(run_dir: Path | str) -> str | None:
    """Read the run nonce, creating it (0600, O_EXCL) when absent.

    Returns None when no nonce can be established (unwritable or
    missing run dir, or an existing malformed binding file — which is
    never replaced): stamping then falls back to the v1 binding.
    """
    nonce = _read_run_nonce(run_dir)
    if nonce:
        return nonce
    path = Path(run_dir) / _BINDING_FILE
    if path.exists():
        return None  # malformed existing file: refuse, never clobber
    new = secrets.token_hex(_NONCE_HEX_LEN // 2)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _read_run_nonce(run_dir)  # lost the creation race
    except OSError:
        return None
    try:
        os.write(fd, new.encode("utf-8"))
    finally:
        os.close(fd)
    return new


def run_binding_nonced(run_dir: Path | str, nonce: str) -> str:
    """v2 binding value: basename + per-run nonce."""
    return f"{run_binding(run_dir)}#{nonce}"


def _binding_for_verify(
    record: Mapping[str, Any], run_dir: Path | str,
) -> tuple[str | None, str | None]:
    """(binding value, grade) the record's marker directs verification
    to, or (None, None) when the required nonce is unavailable.

    The marker cannot be stripped to demote the check: a token minted
    over the nonced binding never verifies against the basename-only
    field set, and vice versa.

    The nonce is read FROM the directory under verification (the
    archive/move portability property), so a fully STAGED directory —
    donor basename, copied nonce file, selectively copied stamped
    records — verifies at GRADE_RUN_NONCE for a same-user reader; see
    the partial-clone note at the grade constants before weighting
    the grade as more than cross-run replay defence.
    """
    if record.get(BINDING_GRADE_KEY) == GRADE_RUN_NONCE:
        nonce = _read_run_nonce(run_dir)
        if not nonce:
            return None, None
        return run_binding_nonced(run_dir, nonce), GRADE_RUN_NONCE
    return run_binding(run_dir), GRADE_BASENAME


# ---------------------------------------------------------------------------
# Record field sets — kept in one place so writers and verifiers can
# never drift on WHICH fields are authenticated.
# ---------------------------------------------------------------------------


def _finding_coords(finding: Mapping[str, Any]) -> dict:
    return {
        "id": str(finding.get("id") or finding.get("finding_id") or ""),
        "file": str(finding.get("file") or ""),
        "function": str(finding.get("function") or ""),
    }


def witness_execution_fields(
    finding: Mapping[str, Any],
    record: Mapping[str, Any],
    run_dir: Path | str,
    *,
    binding: str | None = None,
) -> dict:
    """The exact witness_execution fields consumers act on, in MAC form.

    ``verdict`` drives the eligibility skip, the ruling upgrade /
    rule-out, and the /audit feedback mechanical-disqualifier — so it
    is authenticated together with the finding coordinates the record
    claims to be about. ``binding`` overrides the run-binding value
    (the v2 nonced binding); default is the legacy basename binding."""
    return {
        "kind": _WITNESS_KIND,
        "run": binding if binding is not None else run_binding(run_dir),
        "verdict": str(record.get("verdict") or ""),
        **_finding_coords(finding),
    }


def feasibility_fields(
    finding: Mapping[str, Any],
    feasibility: Mapping[str, Any],
    run_dir: Path | str,
    *,
    binding: str | None = None,
) -> dict:
    """The exact feasibility fields consumers act on, in MAC form:
    ``status == "analyzed"`` asserts mechanical provenance and
    ``verdict`` is what maps to final_status / is_exploitable."""
    return {
        "kind": _FEASIBILITY_KIND,
        "run": binding if binding is not None else run_binding(run_dir),
        "status": str(feasibility.get("status") or ""),
        "verdict": str(feasibility.get("verdict") or ""),
        "binary_path": str(feasibility.get("binary_path") or ""),
        **_finding_coords(finding),
    }


def iris_refutation_fields(
    row: Mapping[str, Any],
    run_dir: Path | str,
) -> dict:
    """The exact disproven.json row fields consumers act on, in MAC
    form. ``lesson == "iris_tier1_refuted"`` is what /audit feedback's
    mechanical-disqualifier keys on, and ``finding`` names the finding
    it refutes — both authenticated together with the run binding so a
    forged or replayed row carries no mechanical weight."""
    return {
        "kind": _IRIS_KIND,
        "run": run_binding(run_dir),
        "finding": str(row.get("finding") or ""),
        "lesson": str(row.get("lesson") or ""),
    }


def smt_conditions_hash(conditions: Any) -> str:
    """Canonical hash of an attack path's ``path_conditions``.

    Single source of truth shared by the sweep writer (which stores it
    in the record and inside the MAC) and the verifier (which
    recomputes it from the path's OWN conditions). The MAC binds
    ``(run, finding, feasible, conditions_hash)`` but two paths of the
    same finding are otherwise indistinguishable to it — without the
    verifier-side equality check, a genuinely-stamped
    ``feasible: false`` record copied onto a sibling path the solver
    ruled SAT would verify there. The recomputed hash ties each record
    to the exact condition set it ruled on."""
    if not isinstance(conditions, list) or not conditions:
        # No conditions → the sweep never produced a record for this
        # path; any record present is foreign. A non-matchable
        # sentinel (not a hex digest) guarantees inequality.
        return "<no-conditions>"
    import json as _json
    try:
        payload = _json.dumps(conditions, sort_keys=True, default=str)
    except (TypeError, ValueError):
        payload = repr(conditions)
    # Full digest, deliberately: this equality is the verifier's
    # suppression-direction path binding, and BOTH condition sets in
    # a transplant are attacker-influenceable (path_conditions are
    # LLM-extracted over a hostile target). A truncated 64-bit prefix
    # left a ~2^32-work offline birthday collision as the transplant
    # margin; 48 extra JSON bytes buy the full 256-bit margin.
    # Records stamped under the old truncated form fail the equality
    # against a full recompute — fail CLOSED: the refutation demotes
    # to unverified, never verifies wrongly.
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def smt_feasibility_fields(
    path: Mapping[str, Any],
    record: Mapping[str, Any],
    run_dir: Path | str,
) -> dict:
    """The exact attack-path ``smt_feasibility`` fields consumers act
    on, in MAC form: ``feasible is False`` is the mechanical
    refutation signal, ``conditions_hash`` pins WHICH condition set
    the solver ruled on, and the path's finding id binds the verdict
    to the finding it refutes. The MAC alone cannot tell two paths of
    the same finding apart, so ``verify_smt_feasibility`` ALSO checks
    the record's ``conditions_hash`` against
    :func:`smt_conditions_hash` of the path's own conditions."""
    return {
        "kind": _SMT_KIND,
        "run": run_binding(run_dir),
        "finding": str(
            path.get("finding_id") or path.get("finding") or ""),
        "feasible": str(record.get("feasible")),
        "conditions_hash": str(record.get("conditions_hash") or ""),
    }


# ---------------------------------------------------------------------------
# Stamp / verify — the writer- and reader-facing API
# ---------------------------------------------------------------------------


def stamp_witness_execution(
    finding: Mapping[str, Any],
    record: dict,
    run_dir: Path | str,
) -> None:
    """Stamp a witness_execution *record* the mechanical stage just
    produced. No usable key → record stays unstamped (demote-on-read).
    Minted under the v2 nonced binding whenever a per-run nonce can be
    read/created; falls back to the v1 basename binding otherwise."""
    nonce = _load_or_create_run_nonce(run_dir)
    binding = run_binding_nonced(run_dir, nonce) if nonce else None
    token = mint(
        witness_execution_fields(finding, record, run_dir, binding=binding),
    )
    if token:
        record[PROVENANCE_KEY] = token
        if binding is not None:
            record[BINDING_GRADE_KEY] = GRADE_RUN_NONCE


def verify_witness_execution_graded(
    finding: Mapping[str, Any],
    run_dir: Path | str,
) -> str | None:
    """Binding grade the finding's witness_execution record verifies
    at (``GRADE_RUN_NONCE`` / ``GRADE_BASENAME``), or None when it
    does not verify. Consumers that must distinguish layout-forgeable
    basename bindings from nonce-bound records read the grade."""
    record = finding.get("witness_execution")
    if not isinstance(record, Mapping):
        return None
    binding, grade = _binding_for_verify(record, run_dir)
    if binding is None:
        return None
    ok = verify(
        witness_execution_fields(finding, record, run_dir, binding=binding),
        record.get(PROVENANCE_KEY),
    )
    return grade if ok else None


def verify_witness_execution(
    finding: Mapping[str, Any],
    run_dir: Path | str,
) -> bool:
    """Whether the finding's witness_execution record was produced by
    a mechanical stage of THIS install in THIS run directory."""
    return verify_witness_execution_graded(finding, run_dir) is not None


def stamp_feasibility(
    finding: Mapping[str, Any],
    feasibility: dict,
    run_dir: Path | str,
) -> None:
    """Stamp a feasibility record the mechanical stage just produced."""
    nonce = _load_or_create_run_nonce(run_dir)
    binding = run_binding_nonced(run_dir, nonce) if nonce else None
    token = mint(
        feasibility_fields(finding, feasibility, run_dir, binding=binding),
    )
    if token:
        feasibility[PROVENANCE_KEY] = token
        if binding is not None:
            feasibility[BINDING_GRADE_KEY] = GRADE_RUN_NONCE


def verify_feasibility_graded(
    finding: Mapping[str, Any],
    run_dir: Path | str,
) -> str | None:
    """Binding grade the finding's feasibility record verifies at,
    or None when it does not verify."""
    feasibility = finding.get("feasibility")
    if not isinstance(feasibility, Mapping):
        return None
    binding, grade = _binding_for_verify(feasibility, run_dir)
    if binding is None:
        return None
    ok = verify(
        feasibility_fields(finding, feasibility, run_dir, binding=binding),
        feasibility.get(PROVENANCE_KEY),
    )
    return grade if ok else None


def verify_feasibility(
    finding: Mapping[str, Any],
    run_dir: Path | str,
) -> bool:
    """Whether the finding's feasibility record was produced by a
    mechanical stage of THIS install in THIS run directory."""
    return verify_feasibility_graded(finding, run_dir) is not None


def stamp_iris_refutation(row: dict, run_dir: Path | str) -> None:
    """Stamp a disproven.json row the IRIS Tier-1 gate just produced.
    No usable key → row stays unstamped (ignored-on-read)."""
    token = mint(iris_refutation_fields(row, run_dir))
    if token:
        row[PROVENANCE_KEY] = token


def verify_iris_refutation(
    row: Mapping[str, Any],
    run_dir: Path | str,
) -> bool:
    """Whether the disproven row was produced by the mechanical IRIS
    Tier-1 gate of THIS install in THIS run directory."""
    if not isinstance(row, Mapping):
        return False
    return verify(
        iris_refutation_fields(row, run_dir), row.get(PROVENANCE_KEY),
    )


def stamp_smt_feasibility(
    path: Mapping[str, Any],
    record: dict,
    run_dir: Path | str,
) -> None:
    """Stamp an ``smt_feasibility`` record the mechanical SMT sweep
    just produced for *path*."""
    token = mint(smt_feasibility_fields(path, record, run_dir))
    if token:
        record[PROVENANCE_KEY] = token


def verify_smt_feasibility(
    path: Mapping[str, Any],
    run_dir: Path | str,
) -> bool:
    """Whether the path's ``smt_feasibility`` record was produced by
    the mechanical SMT sweep of THIS install in THIS run directory
    FOR THIS PATH's condition set.

    The final clause is the path binding: the MAC covers the
    conditions hash the solver ruled on, and the path's own
    ``path_conditions`` must hash to that same value — a
    validly-stamped record copied from a sibling path of the same
    finding carries the donor path's hash and fails here."""
    record = path.get("smt_feasibility") if isinstance(path, Mapping) else None
    if not isinstance(record, Mapping):
        return False
    if not verify(
        smt_feasibility_fields(path, record, run_dir),
        record.get(PROVENANCE_KEY),
    ):
        return False
    return (
        smt_conditions_hash(path.get("path_conditions"))
        == str(record.get("conditions_hash") or "")
    )


# ---------------------------------------------------------------------------
# Ingest sanitiser — the tier chokepoint consumers call on load
# ---------------------------------------------------------------------------

#: final_status values only a feasibility verdict may legitimately
#: produce (Stage E verdict mapping — orchestrator verdict_to_status /
#: validation-helper VERDICT_MAP).
FEASIBILITY_TIER_STATUSES = frozenset({
    "exploitable", "likely_exploitable",
    "confirmed_constrained", "confirmed_blocked",
})


def _strip_witness_claim(finding: dict) -> None:
    """Remove an unverified witness_execution record AND every ruling
    consequence it claims, restoring the finding to its pre-witness
    state so the stage re-executes (or, absent a witness stage, the
    claim simply carries no mechanical weight)."""
    finding.pop("witness_execution", None)
    ruling = finding.get("ruling")
    if not isinstance(ruling, dict):
        return
    witness_marker = str(ruling.get("witness") or "")
    has_marker = witness_marker.startswith("dark_verify:")
    # A bare ``disqualifier: witness_refuted`` with no marker is the
    # same forged-refutation shape spelled differently — consumers
    # (e.g. /audit feedback's mechanical-disqualifier) key on the
    # string alone, so it must roll back the same way.
    if not has_marker and ruling.get("disqualifier") != "witness_refuted":
        return
    if has_marker:
        ruling.pop("witness", None)
    if ruling.get("disqualifier") == "witness_refuted":
        # A forged refutation suppresses a real finding — roll the
        # ruling back entirely so later stages re-examine it.
        finding.pop("ruling", None)
        finding["status"] = "pending"
        finding.pop("final_status", None)
    elif ruling.get("status") in ("confirmed", "exploitable"):
        # A forged confirmation minted a runtime-grade ruling — drop
        # to the unverified quarantine tier.
        ruling["status"] = "confirmed_unverified"
        finding["status"] = "confirmed_unverified"
        if finding.get("final_status"):
            finding["final_status"] = "confirmed_unverified"


def sanitise_findings_evidence(
    findings_data: Mapping[str, Any] | None,
    run_dir: Path | str,
) -> dict:
    """Demote every mechanical-provenance claim in *findings_data*
    that this install's key did not stamp for *run_dir*.

    Mutates the findings in place. Returns
    ``{"witness_stripped": n, "feasibility_demoted": n,
    "final_status_demoted": n}`` so callers can log what was refused.
    Verified records are left untouched (including their ruling /
    final_status consequences); unverified ones lose the mechanical
    claim and keep only their LLM-tier content (source-analysis
    fields survive for re-derivation).
    """
    stats = {
        "witness_stripped": 0,
        "feasibility_demoted": 0,
        "final_status_demoted": 0,
    }
    if not isinstance(findings_data, Mapping):
        return stats
    findings = findings_data.get("findings")
    if not isinstance(findings, list):
        return stats

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        record = finding.get("witness_execution")
        if record is not None:
            if not verify_witness_execution(finding, run_dir):
                _strip_witness_claim(finding)
                stats["witness_stripped"] += 1
            else:
                # Verified record: the ruling's witness marker AND its
                # disqualifier must agree with the authenticated
                # verdict — a marker or refutation string grafted onto
                # someone else's record is a forgery.
                ruling = finding.get("ruling")
                marker = (
                    str(ruling.get("witness") or "")
                    if isinstance(ruling, dict) else ""
                )
                disqualifier = (
                    ruling.get("disqualifier")
                    if isinstance(ruling, dict) else None
                )
                verdict = str(record.get("verdict") or "")
                if (
                    marker.startswith("dark_verify:")
                    and marker != f"dark_verify:{verdict}"
                ) or (
                    disqualifier == "witness_refuted"
                    and verdict != "refuted"
                ):
                    _strip_witness_claim(finding)
                    stats["witness_stripped"] += 1
        else:
            # No witness record at all, but a ruling claiming one —
            # via the dark_verify marker or the bare refutation
            # disqualifier string.
            ruling = finding.get("ruling")
            if isinstance(ruling, dict) and (
                str(ruling.get("witness") or "").startswith("dark_verify:")
                or ruling.get("disqualifier") == "witness_refuted"
            ):
                _strip_witness_claim(finding)
                stats["witness_stripped"] += 1

        feasibility = finding.get("feasibility")
        if (
            isinstance(feasibility, dict)
            and feasibility.get("status") == "analyzed"
            and not verify_feasibility(finding, run_dir)
        ):
            # Demote the mechanical claim; keep the LLM-tier source-
            # analysis fields (chain_breaks / what_would_help) so the
            # consumer re-derives instead of trusting the verdict.
            feasibility["status"] = "pending"
            feasibility.pop("verdict", None)
            feasibility.pop("binary_analysis", None)
            feasibility.pop(PROVENANCE_KEY, None)
            feasibility.pop(BINDING_GRADE_KEY, None)
            stats["feasibility_demoted"] += 1

        # Verdict-tier clamp: exploitable-family final statuses are
        # only ever produced by mapping a feasibility verdict (Stage E
        # / validation-helper VERDICT_MAP / the E-5 skill table), so
        # they require a VERIFIED analyzed feasibility record. A
        # pre-set "exploitable" with no (or a forged) record is
        # quarantined until a mechanical stage re-derives it.
        if finding.get("final_status") in FEASIBILITY_TIER_STATUSES:
            feasibility = finding.get("feasibility")
            supported = (
                isinstance(feasibility, dict)
                and feasibility.get("status") == "analyzed"
                and verify_feasibility(finding, run_dir)
            )
            if not supported:
                finding["final_status"] = "confirmed_unverified"
                if finding.get("status") in FEASIBILITY_TIER_STATUSES:
                    finding["status"] = "confirmed_unverified"
                # Demote only a genuine True claim: an abstention is
                # not a positive claim to overwrite with a fabricated
                # explicit False. A junk shape is normalised to the
                # explicit abstention instead — this is a
                # sanitisation chokepoint, and leaving junk in place
                # would hand downstream/external truthy readers a
                # value the tri-state accessor refuses.
                _claim = read_verdict(finding, "is_exploitable")
                if _claim is True:
                    finding["is_exploitable"] = False
                elif _claim is None:
                    # Presence check on the raw value (not verdict
                    # consumption — the verdict was read above):
                    # present-but-junk becomes the explicit
                    # abstention; absent / already-None untouched.
                    _raw_claim = finding.get("is_exploitable")
                    if _raw_claim is not None:
                        finding["is_exploitable"] = None
                stats["final_status_demoted"] += 1

    if any(stats.values()):
        logger.warning(
            "witness provenance: demoted unverified evidence claims "
            "(witness_execution stripped: %d, feasibility demoted: %d, "
            "final_status demoted: %d) — records lacked a valid "
            "mechanical-provenance stamp for run %r",
            stats["witness_stripped"], stats["feasibility_demoted"],
            stats["final_status_demoted"], run_binding(run_dir),
        )
    return stats


# ---------------------------------------------------------------------------
# Witness-store manifests — content-MAC provenance for collect_outcomes
# ---------------------------------------------------------------------------

_MANIFEST_KIND = "witness-manifest"


def manifest_content_sha256(manifest: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical (key-sorted, compact) JSON of the
    manifest WITHOUT its provenance token — the exact content identity
    the token authenticates. Covering the whole record rather than a
    field subset means nothing in a validly-stamped manifest can be
    rewritten under a surviving token (same construction as
    ``triage_report_fields`` in core/sandbox/telemetry_mac)."""
    from core.json import dumps_canonical
    body = {str(k): manifest[k] for k in manifest if k != PROVENANCE_KEY}
    try:
        text = dumps_canonical(body)
    except (TypeError, ValueError):
        # Non-JSON-safe content can never match a writer-side hash
        # (writers serialise the manifest, so theirs was JSON-safe).
        return "<unhashable>"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def witness_manifest_fields(manifest_sha256: str) -> dict:
    """MAC fields for a WitnessStore manifest.

    Deliberately NO run binding: a witness asserts a
    location-independent fact ("these bytes produced this outcome on
    this target"), so replaying a GENUINE record into another store
    changes nothing a consumer acts on. The token defends AUTHORSHIP:
    verified-outcome records feed threat-status flips, threat ids are
    content-derived and attacker-predictable, and a disk-staging
    attacker must not be able to mint a record naming an exact
    threat id.
    """
    return {"kind": _MANIFEST_KIND, "manifest_sha256": manifest_sha256}


def stamp_witness_manifest(manifest: dict) -> None:
    """Stamp a manifest dict the store is about to persist. No usable
    key → the manifest stays unstamped and consumers demote it to
    evidence-only weight (the pre-stamp behaviour)."""
    token = mint(witness_manifest_fields(manifest_content_sha256(manifest)))
    if token:
        manifest[PROVENANCE_KEY] = token


def verify_witness_manifest(manifest: Mapping[str, Any]) -> bool:
    """Whether *manifest* was written by a WitnessStore of THIS
    install. False for unstamped (legacy / foreign / attacker-staged)
    manifests and on any verification failure — the caller's demote
    path, never an error."""
    if not isinstance(manifest, Mapping):
        return False
    token = manifest.get(PROVENANCE_KEY)
    if not token:
        return False
    return verify(
        witness_manifest_fields(manifest_content_sha256(manifest)),
        str(token),
    )


__all__ = [
    "BINDING_GRADE_KEY",
    "FEASIBILITY_TIER_STATUSES",
    "GRADE_BASENAME",
    "GRADE_RUN_NONCE",
    "PROVENANCE_KEY",
    "feasibility_fields",
    "iris_refutation_fields",
    "key_usable",
    "manifest_content_sha256",
    "mint",
    "run_binding",
    "run_binding_nonced",
    "sanitise_findings_evidence",
    "smt_conditions_hash",
    "smt_feasibility_fields",
    "stamp_feasibility",
    "stamp_iris_refutation",
    "stamp_smt_feasibility",
    "stamp_witness_execution",
    "stamp_witness_manifest",
    "verify",
    "verify_feasibility",
    "verify_feasibility_graded",
    "verify_iris_refutation",
    "verify_smt_feasibility",
    "verify_witness_execution",
    "verify_witness_execution_graded",
    "verify_witness_manifest",
    "witness_execution_fields",
    "witness_manifest_fields",
]
