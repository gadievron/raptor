"""Auto-siblings composition for binary audit targets.

When ``/audit`` runs against a binary and a mapped sibling run
directory exists for that binary, the sibling-consistency pass
(``packages.binary_analysis.siblings.run_siblings`` — the exact
engine ``raptor-binary siblings --auto`` dispatches) feeds the audit
automatically: the map run's ``sibling-hypotheses.json`` is captured
into the AUDIT run directory, where the existing hypothesis-seed
intake (:mod:`core.audit.hypothesis_intake`) discovers the
co-located file on its normal path. Thin sequencing glue over
EXISTING tools — the composition idiom of
``raptor-binary-study-oneshot``:

* discovery REUSES :func:`core.orchestration.run_discovery.
  find_sibling_run` (session-ledger tier, project siblings, global
  ``out/`` fallback, recorded-target gate) — no new discovery logic;
* a map run that ALREADY holds a ``sibling-hypotheses.json`` (a
  prior hand-run, possibly adjudicated) is captured as-is — the
  engine is never re-run over an existing artifact, so an
  operator-reviewed file is preserved verbatim and analysed maps add
  no engine latency to audit start;
* only when the map has no artifact does the landed siblings engine
  run, through its Python API with ``--auto`` defaults, inside a
  bounded worker (:data:`ENGINE_WALL_S`);
* ingestion is the landed intake: capture at the intake's own
  co-located spelling means operator ``--hypothesis-seeds`` files
  merge through the intake's normal multi-source path (shared record
  cap, per-seed source provenance), and a ``--seed-rereview``-style
  consumer of the same sources composes with no special-casing.

Build identity is fail-closed: the map manifest's ``binary_sha256``
must be present AND match the audit target's content hash before
anything is captured or computed — an unstamped or unreadable
manifest refuses (``identity_unverified``), a mismatch refuses
(``build_mismatch``). Another build's sibling analysis never seeds
this audit.

Failure honesty: every non-captured outcome short of "flag off"
degrades LOUDLY to today's behaviour — the audit proceeds unseeded,
ONE warning names the skip and its reason, and the receipt
(``auto-siblings.json``) persists the outcome for the run report's
degradation surface. The pass never blocks or fails the audit.

Second-life provenance: sibling claims carry target-derived function
names and strings. They ride the intake's untrusted-seed envelope
unchanged (escape-at-load, length caps, enveloped prompt rendering);
this module adds NO raw render — reason text that can embed
target-derived bytes (engine errors) is escaped before it reaches
the log line or the receipt.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Outcome receipt written into the audit run dir on every attempted
#: pass (the run report surfaces degraded outcomes; a captured
#: outcome is the audit trail for "where did the co-located seed
#: file come from").
RECEIPT_FILENAME = "auto-siblings.json"

#: Map-run manifest read ceiling — a tiny descriptor (the binary
#: manifest), same budget class as run metadata in the binary bridge.
_MAX_MANIFEST_BYTES = 1024 * 1024

#: Reason/detail text cap in the receipt and the warning line.
#: Engine errors can embed target-derived bytes; they are escaped
#: AND bounded before any surface sees them.
_MAX_DETAIL_CHARS = 500

#: Wall bound for the engine leg (the existing-artifact fast path
#: never enters it). Both directions: legitimate first-contact passes
#: can reach the live whole-binary r2 call-graph fallback, which
#: takes tens of minutes on large maps — tighter kills healthy work;
#: looser lets an untimed stall (e.g. the map-dir artifact lock held
#: indefinitely by another process, or a future engine pathology)
#: pin audit START without bound. 45 minutes covers every observed
#: legitimate pass with margin. On expiry the worker (a daemon
#: thread) is abandoned and the pass degrades to ``engine_timeout``.
ENGINE_WALL_S = 45 * 60.0

#: The mapped-run marker pair the siblings engine itself requires
#: (its loaders raise on either missing). Discovery keys on the
#: context map and filters on the manifest — the graph substrate is
#: confirmed by the engine, whose refusal degrades loudly here.
_MAP_MARKER = "binary-context-map.json"
_MANIFEST_FILENAME = "binary-manifest.json"


def _esc(value: Any) -> str:
    from core.security.log_sanitisation import escape_nonprintable
    return escape_nonprintable(str(value))[:_MAX_DETAIL_CHARS]


def _write_receipt(out_dir: Path, receipt: dict[str, Any]) -> None:
    try:
        from core.json import save_json
        save_json(Path(out_dir) / RECEIPT_FILENAME, receipt)
    except OSError:
        logger.warning("auto-siblings receipt write failed",
                       exc_info=True)


def _degrade(
    out_dir: Path, reason: str, detail: str,
) -> dict[str, Any]:
    """Loud skip: one warning naming the reason, receipt persisted,
    audit proceeds unseeded (today's behaviour)."""
    receipt = {
        "schema_version": 1,
        "status": "degraded",
        "reason": reason,
        "detail": _esc(detail),
    }
    _write_receipt(out_dir, receipt)
    logger.warning(
        "auto-siblings skipped (%s): %s — the audit proceeds "
        "unseeded; hand-run `raptor-binary siblings <map-run-dir> "
        "--auto` and re-run with --hypothesis-seeds to seed manually",
        reason, receipt["detail"],
    )
    return receipt


def _manifest_sha(map_dir: Path) -> str:
    """The mapped run's recorded binary_sha256 ('' when unreadable)."""
    from core.json import load_json
    payload = load_json(
        Path(map_dir) / _MANIFEST_FILENAME,
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if not isinstance(payload, dict):
        return ""
    recorded = payload.get("binary_sha256")
    return recorded if isinstance(recorded, str) else ""


def _engine_bounded(engine: Any, map_dir: Path, wall_s: float) -> Any:
    """Run the engine in a daemon worker bounded by *wall_s* seconds.

    A daemon thread (not an executor) on purpose: expiry ABANDONS the
    worker — executor threads are joined at interpreter exit, so a
    worker wedged on an untimed lock would convert the degrade into a
    process that cannot exit. The abandoned worker can still finish
    and write its artifacts into the MAP run dir (harmless — the
    audit already degraded and captured nothing).
    """
    result: list[Any] = []
    error: list[BaseException] = []

    def _work() -> None:
        try:
            result.append(engine(Path(map_dir), auto=True))
        except BaseException as exc:  # noqa: BLE001 — re-raised on the caller thread
            error.append(exc)

    worker = threading.Thread(
        target=_work, daemon=True, name="auto-siblings-engine",
    )
    worker.start()
    worker.join(wall_s)
    if worker.is_alive():
        raise TimeoutError(
            f"siblings engine still running after {int(wall_s)}s",
        )
    if error:
        raise error[0]
    return result[0] if result else None


def run_auto_siblings(
    out_dir: Path,
    target_path: Path,
    *,
    engine: Any | None = None,
) -> dict[str, Any]:
    """Run the sibling-consistency pass for a binary audit target.

    Returns the outcome receipt (also persisted as
    ``auto-siblings.json`` in *out_dir*). Statuses:

    * ``captured`` — the map run's seed file reached *out_dir*
      co-located (the intake discovers it from there). Provenance:
      ``captured_existing`` (the map run already held a
      ``sibling-hypotheses.json`` — captured verbatim, engine not
      run) or ``computed`` (the engine ran over the map run first);
    * ``reused`` — *out_dir* already carries a co-located
      ``sibling-hypotheses.json`` (operator-ferried, or a prior
      segment's capture): nothing runs, the intake ingests the
      existing file unchanged;
    * ``degraded`` — no mapped run, unverifiable or mismatched build
      identity, engine failure/timeout, or capture failure: warned
      once, audit proceeds unseeded.

    Never raises: any unexpected error degrades. *engine* is a test
    seam (defaults to the landed ``run_siblings``).
    """
    out_dir = Path(out_dir)
    target_path = Path(target_path)
    try:
        return _run(out_dir, target_path, engine)
    except Exception as exc:  # noqa: BLE001 — enrichment, never a gate
        logger.debug("auto-siblings pass failed", exc_info=True)
        return _degrade(out_dir, "engine_error", str(exc))


def _run(
    out_dir: Path, target_path: Path, engine: Any | None,
) -> dict[str, Any]:
    try:
        from core.audit.hypothesis_intake import SEEDS_FILENAME
        from packages.binary_analysis.siblings import (
            HYPOTHESES_FILENAME,
            run_siblings,
        )
    except ImportError as exc:
        return _degrade(out_dir, "engine_unavailable", str(exc))
    if engine is None:
        engine = run_siblings

    captured_path = out_dir / SEEDS_FILENAME
    if captured_path.is_file():
        # Operator-ferried seeds or a prior segment's capture: the
        # intake discovers the co-located file on its normal path —
        # re-running the engine would silently overwrite an
        # operator-provided artifact.
        receipt = {
            "schema_version": 1,
            "status": "reused",
            "reason": "seeds_already_present",
            "captured": str(captured_path),
        }
        _write_receipt(out_dir, receipt)
        logger.info(
            "auto-siblings: co-located %s already present — engine "
            "not re-run; the intake ingests the existing file",
            SEEDS_FILENAME,
        )
        return receipt

    # Discovery: the shared sibling-run skeleton (never twinned).
    # Marker = the map's context map; filter = the engine's other
    # hard requirement (the binary manifest). The recorded-target
    # gate keeps another binary's map from seeding this audit.
    from core.orchestration.run_discovery import find_sibling_run
    map_dir = find_sibling_run(
        out_dir, _MAP_MARKER,
        dir_filter=lambda d: (d / _MANIFEST_FILENAME).is_file(),
        exclude=out_dir,
        target_path=target_path,
    )
    if map_dir is None:
        return _degrade(
            out_dir, "no_mapped_run",
            "no mapped binary run dir (binary-context-map.json + "
            "binary-manifest.json) found for this target — run "
            "`raptor-binary map <binary>` first, or pass "
            "--hypothesis-seeds explicitly",
        )

    # Build-identity gate, FAIL-CLOSED: the map manifest stamps the
    # analysed binary's content hash (the RAPTOR producer always
    # does). Unverifiable identity — an unstamped or unreadable
    # manifest, or an unhashable target — refuses outright: a
    # stripped manifest must not become the way a rebuilt binary's
    # stale map seeds this audit. A verified mismatch refuses too
    # (a rebuilt binary at the same path passes the recorded-target
    # gate but its siblings evidence describes the OLD build).
    recorded_sha = _manifest_sha(map_dir)
    actual_sha = ""
    try:
        from core.hash import sha256_file
        actual_sha = sha256_file(target_path)
    except OSError:
        logger.debug("target hash failed", exc_info=True)
    if not recorded_sha or not actual_sha:
        missing = ("the map manifest records no binary_sha256"
                   if not recorded_sha
                   else "the audit target could not be hashed")
        return _degrade(
            out_dir, "identity_unverified",
            f"mapped run {map_dir}: {missing} — refusing to seed "
            "this audit without a verified build identity",
        )
    if recorded_sha != actual_sha:
        return _degrade(
            out_dir, "build_mismatch",
            f"mapped run {map_dir} records binary_sha256 "
            f"{recorded_sha[:16]}… but the audit target hashes to "
            f"{actual_sha[:16]}… — refusing to seed this audit from "
            "a different build's sibling analysis",
        )

    # Prefer an EXISTING map-run artifact over a fresh engine run:
    # a prior hand-run's sibling-hypotheses.json may be adjudicated
    # (operator-reviewed rows cited by their notes), and the engine
    # is not bit-deterministic across substrate state — re-running
    # would silently replace the reviewed artifact's story. Capturing
    # as-is preserves it verbatim, costs no engine latency, and keeps
    # the fresh-compute path for maps that were never sibling-passed.
    produced = Path(map_dir) / HYPOTHESES_FILENAME
    if produced.is_file():
        return _capture(
            out_dir, captured_path, map_dir, produced,
            recorded_sha, provenance="captured_existing",
        )

    # The engine (--auto defaults): full peer-group formation over
    # the map run dir's persisted artifacts, inside the bounded
    # worker. Writes its artifacts into the MAP run dir exactly as
    # the hand-run command does; its refusals (no call-graph
    # substrate, unreadable map) surface as exceptions and degrade
    # loudly here.
    try:
        _engine_bounded(engine, Path(map_dir), ENGINE_WALL_S)
    except TimeoutError:
        return _degrade(
            out_dir, "engine_timeout",
            f"siblings engine produced no result within "
            f"{int(ENGINE_WALL_S)}s — worker abandoned; the map run "
            "dir may hold a lock or an oversized substrate",
        )
    except Exception as exc:  # noqa: BLE001 — engine refusal = loud degrade
        logger.debug("siblings engine failed", exc_info=True)
        return _degrade(
            out_dir, "siblings_failed",
            f"{type(exc).__name__}: {exc}",
        )

    return _capture(
        out_dir, captured_path, map_dir, produced,
        recorded_sha, provenance="computed",
    )


def _capture(
    out_dir: Path,
    captured_path: Path,
    map_dir: Path,
    produced: Path,
    recorded_sha: str,
    *,
    provenance: str,
) -> dict[str, Any]:
    """Capture *produced* byte-for-byte (provenance stamp included)
    at the intake's co-located spelling in the AUDIT run dir.
    Bounded read at the intake's own file budget — a file the intake
    could not read is not worth capturing."""
    import json

    from core.audit.hypothesis_intake import MAX_SEED_FILE_BYTES
    from core.source import read_bytes_capped
    capped = read_bytes_capped(produced, MAX_SEED_FILE_BYTES)
    if capped is None or capped[1]:
        return _degrade(
            out_dir, "capture_failed",
            f"produced {produced.name} in {map_dir} is unreadable "
            "or over the intake's read budget",
        )
    from core.atomic_fs import write_bytes_atomically
    write_bytes_atomically(captured_path, capped[0])

    # Seed count from the bytes actually captured (one code path for
    # both provenances; the computed engine payload's own counter
    # describes the same file).
    seeds_emitted = None
    try:
        doc = json.loads(capped[0])
        if isinstance(doc, dict) and isinstance(doc.get("seeds"), list):
            seeds_emitted = len(doc["seeds"])
    except ValueError:
        logger.debug("captured seed file is not JSON", exc_info=True)

    receipt = {
        "schema_version": 1,
        "status": "captured",
        "provenance": provenance,
        "map_run_dir": _esc(str(map_dir)),
        "binary_sha256": recorded_sha,
        "seeds_emitted": seeds_emitted,
        "captured": str(captured_path),
    }
    _write_receipt(out_dir, receipt)
    logger.info(
        "auto-siblings: %s seed(s) captured (%s) from %s into %s — "
        "the hypothesis-seed intake ingests them as hints (seeds "
        "never mint findings)",
        receipt["seeds_emitted"], provenance,
        receipt["map_run_dir"], captured_path,
    )
    return receipt
