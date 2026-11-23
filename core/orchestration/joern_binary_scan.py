"""Joern-on-binary bridge: ghidra2cpg CPG + C-profile sweeps.

Entry point :func:`run_joern_binary_scan` takes a compiled binary,
builds a CPG with the ghidra2cpg frontend
(:func:`packages.joern.binary_cpg.build_ghidra_cpg`), binds it to the
resident graph service (``GraphClient.import_cpg``) and runs the same
two sweeps the source-level scan phase runs: the tiered taint sweep
(C profile) and the fourteen structural queries in
``structural_c.sc``. The record transport and sentinel discipline are
shared with :mod:`core.orchestration.joern_scan` — a transcript
without the completion sentinel reads as "not scanned", never as
"clean".

The results are ADDRESS-LEVEL EVIDENCE, deliberately kept out of the
source-finding SARIF stream: on a Ghidra-recovered graph, "line"
fields carry virtual addresses, call arguments are registers, and
literal detection degrades (a string literal in source is a pointer
load in the binary), so structural hits here are triage hints with
reduced precision, not confirmed findings. The artifact is one JSON
document, ``joern-binary-scan.json`` in the run directory, consumed by
`/binary` as hint-tier evidence (binary-oracle doctrine: hints never
suppress and never confirm on their own).

Never raises for operational failures — the outcome carries
``errors`` / ``degraded`` and the caller decides how loudly to
surface them.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ARTIFACT_NAME = "joern-binary-scan.json"

#: Bound on taint flows / structural hits mirrored into the artifact.
MAX_ARTIFACT_FLOWS = 100
MAX_ARTIFACT_HITS = 400

#: Bound on steps mirrored per flow and on error strings mirrored into
#: the artifact — both carry target-derived text.
MAX_FLOW_STEPS = 100
MAX_ARTIFACT_ERRORS = 50

_PRECISION_NOTE = (
    "address-level evidence from a Ghidra-recovered graph: locations"
    " are virtual addresses, arguments are registers, literal"
    " detection is degraded — triage hints, not confirmed findings"
)


@dataclass
class JoernBinaryScanOutcome:
    """Result surface for the binary bridge — mirrors JoernScanOutcome."""

    artifact_path: Path | None = None
    cpg_path: Path | None = None
    method_count: int | None = None
    taint_flow_count: int = 0
    structural_hit_count: int = 0
    queries_failed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    degraded: bool = False
    elapsed_s: float = 0.0

    def metrics(self) -> dict[str, Any]:
        return {
            "method_count": self.method_count,
            "taint_flow_count": self.taint_flow_count,
            "structural_hit_count": self.structural_hit_count,
            "queries_failed": list(self.queries_failed),
            "error_count": len(self.errors),
            "degraded": self.degraded,
            "elapsed_s": round(self.elapsed_s, 1),
        }


# The query echo is REPL-coloured ("val res6: Int = 91" with ANSI SGR
# sequences around each token) — a naive digit scrape concatenates the
# colour-code digits into nonsense, so strip SGR first, then take the
# value after the final '='.
_ANSI_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")


def _parse_count(raw: str) -> int | None:
    m = re.search(r"=\s*(\d+)\s*$", _ANSI_SGR_RE.sub("", raw).strip())
    return int(m.group(1)) if m else None


def _addr(value: Any) -> tuple[int, str] | None:
    """(decimal, hex-string) from a record's address-bearing field.

    Integers only — a float would silently truncate and a bool is a
    type confusion, not an address.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value <= 0:
        return None
    return value, hex(value)


def _structural_hits(
    raw_output: str,
    outcome: JoernBinaryScanOutcome,
) -> list[dict[str, Any]]:
    """Parse structural records into address-level hit entries.

    Same sentinel discipline as the source scan: missing completion
    sentinel or a declared-query-count drift degrades the outcome.
    """
    from core.analysis._joern_lines import parse_marker_records
    from core.orchestration.joern_scan import (
        _SCANDONE_MARKER,
        _SCANERR_MARKER,
        _SCANHIT_MARKER,
        _STRUCTURAL_QUERY_COUNT,
        STRUCTURAL_RULES,
    )

    hits, hit_errors = parse_marker_records(raw_output, _SCANHIT_MARKER)
    query_errs, _ = parse_marker_records(raw_output, _SCANERR_MARKER)
    done, _ = parse_marker_records(raw_output, _SCANDONE_MARKER)
    outcome.errors.extend(hit_errors)

    for rec in query_errs:
        if isinstance(rec, dict):
            name = str(rec.get("query", "unknown"))[:80]
            outcome.queries_failed.append(name)
            outcome.errors.append(
                f"structural query {name} failed:"
                f" {str(rec.get('error', ''))[:200]}")

    done_recs = [d for d in done if isinstance(d, dict)]
    if not done_recs:
        outcome.errors.append(
            "structural query script did not complete (no completion"
            " sentinel) — binary structural coverage is incomplete,"
            " not clean")
    elif done_recs[0].get("queries") != _STRUCTURAL_QUERY_COUNT:
        outcome.errors.append(
            f"structural query count drift: script declared"
            f" {done_recs[0].get('queries')!r}, expected"
            f" {_STRUCTURAL_QUERY_COUNT}")

    # Sort on the DECIMAL address (hex strings order lexicographically:
    # '0x99' > '0x100'), so the post-sort cap keeps the lowest-address
    # hits per query rather than a lexicographically-biased subset.
    keyed: list[tuple[str, int, dict[str, Any]]] = []
    seen: set[tuple[str, int, str]] = set()
    for rec in hits:
        if not isinstance(rec, dict):
            continue
        query = str(rec.get("query", ""))
        meta = STRUCTURAL_RULES.get(query)
        if meta is None:
            msg = f"unknown structural query in records: {query[:80]!r}"
            if msg not in outcome.errors:
                outcome.errors.append(msg)
            continue
        addr = _addr(rec.get("line"))
        if addr is None:
            continue
        function = str(rec.get("function", ""))[:120]
        key = (query, addr[0], function)
        if key in seen:
            continue
        seen.add(key)
        keyed.append((query, addr[0], {
            "query": query,
            "rule_id": f"joern-{query}",
            "cwe": meta["cwe"],
            "level": meta["level"],
            "description": meta["description"],
            "function": function,
            "address": addr[1],
            "code": str(rec.get("code", ""))[:200],
        }))
    keyed.sort(key=lambda item: (item[0], item[1]))
    return [entry for _, _, entry in keyed[:MAX_ARTIFACT_HITS]]


def _flow_entries(flows: list[Any]) -> list[dict[str, Any]]:
    """Serialise taint flows as address-level step chains."""
    out: list[dict[str, Any]] = []
    for flow in flows[:MAX_ARTIFACT_FLOWS]:
        steps = []
        for s in (getattr(flow, "steps", None) or [])[:MAX_FLOW_STEPS]:
            if hasattr(s, "to_dict"):
                s = s.to_dict()
            if not isinstance(s, dict):
                continue
            addr = _addr(s.get("line"))
            steps.append({
                "function": str(s.get("function", ""))[:120],
                "address": addr[1] if addr else None,
                "code": str(s.get("code", ""))[:200],
            })
        out.append({"steps": steps})
    return out


def run_joern_binary_scan(
    binary_path: Path,
    out_dir: Path,
    *,
    query_timeout_s: int | None = None,
    build_timeout_s: int | None = None,
    build_fn=None,
    client_factory=None,
) -> JoernBinaryScanOutcome:
    """Build a Ghidra CPG from ``binary_path`` and run the C sweeps.

    Writes ``<out_dir>/joern-binary-scan.json`` whenever the CPG binds
    — including degraded runs where the sweeps themselves failed (the
    artifact then carries ``degraded: true`` and the errors); only a
    build or bind failure skips the write. The Ghidra build scratch
    (CPG included) lives in ``<out_dir>/joern-ghidra/``. ``build_fn``
    / ``client_factory`` are test seams for the frontend build and the
    graph client.
    """
    outcome = JoernBinaryScanOutcome()
    t0 = time.monotonic()
    binary_path = Path(binary_path)
    out_dir = Path(out_dir)

    # A previous run's artifact in a reused out_dir must never survive
    # an early failure of THIS run and impersonate its result. If the
    # stale file cannot be removed, refuse rather than risk it.
    try:
        (out_dir / ARTIFACT_NAME).unlink(missing_ok=True)
    except OSError as error:
        outcome.errors.append(f"could not clear stale artifact: {error}")
        outcome.degraded = True
        return outcome

    try:
        from packages.joern.binary_cpg import (
            DEFAULT_BUILD_TIMEOUT_S,
            build_ghidra_cpg,
        )
        from packages.joern.client import GraphClient
        from packages.joern.lang_config import profile_for
        from packages.joern.tunables import JoernTunables
    except ImportError as error:
        outcome.errors.append(f"joern package unavailable: {error}")
        outcome.degraded = True
        return outcome

    try:
        tunables = JoernTunables.from_tuning()
    except Exception:  # noqa: BLE001 — tuning read must not cost the phase
        logger.debug("joern tunables from_tuning failed", exc_info=True)
        tunables = JoernTunables()
    timeout = int(query_timeout_s or tunables.query_timeout_s)

    build = build_fn or build_ghidra_cpg
    cpg_path = build(
        binary_path, out_dir / "joern-ghidra",
        timeout=int(build_timeout_s or DEFAULT_BUILD_TIMEOUT_S),
        errors_out=outcome.errors,
    )
    if cpg_path is None:
        outcome.degraded = True
        outcome.elapsed_s = time.monotonic() - t0
        return outcome
    outcome.cpg_path = Path(cpg_path)

    structural_script = (Path(__file__).resolve().parents[2]
                         / "packages" / "joern" / "queries"
                         / "structural_c.sc")

    taint_entries: list[dict[str, Any]] = []
    structural_entries: list[dict[str, Any]] = []
    srv = None
    try:
        factory = client_factory or (
            lambda: GraphClient.from_tunables(tunables))
        srv = factory()
        # No timeout override: binding a large Ghidra CPG is governed
        # by the tunables' import_timeout_s (default 900 s), not the
        # much shorter per-query timeout.
        if not srv.import_cpg(outcome.cpg_path):
            outcome.errors.append("graph service could not bind the CPG")
            outcome.degraded = True
            outcome.elapsed_s = time.monotonic() - t0
            return outcome

        count = srv.query("cpg.method.size", timeout=timeout)
        outcome.method_count = _parse_count(
            getattr(count, "raw_output", "") or "")

        # Ghidra-recovered call names are C-shaped — the C profile is
        # the right tier set regardless of the original source language.
        taint = srv.run_tiered_sweep(
            timeout=timeout, lang_profile=profile_for("c"))
        if taint.errors:
            outcome.errors.extend(str(e)[:300] for e in taint.errors)
            outcome.degraded = True
        flows = list(taint.flows or [])
        outcome.taint_flow_count = len(flows)
        taint_entries = _flow_entries(flows)

        if structural_script.exists():
            structural = srv.query_script(structural_script, timeout=timeout)
            if structural.errors:
                outcome.errors.extend(
                    str(e)[:300] for e in structural.errors)
                outcome.degraded = True
            structural_entries = _structural_hits(
                structural.raw_output or "", outcome)
            outcome.structural_hit_count = len(structural_entries)
        else:
            outcome.errors.append("structural_c.sc missing from install")
    except Exception as error:  # noqa: BLE001 — bridge is never fatal
        logger.warning("joern binary scan failed", exc_info=True)
        outcome.errors.append(f"joern binary scan failed: {error}")
        outcome.degraded = True
    finally:
        if srv is not None:
            try:
                srv.stop()
            except Exception:  # noqa: BLE001 — teardown must not mask results
                logger.debug("graph client stop failed", exc_info=True)

    outcome.elapsed_s = time.monotonic() - t0
    if outcome.errors or outcome.queries_failed:
        outcome.degraded = True

    from core.hash import sha256_file
    try:
        binary_sha = sha256_file(binary_path)
    except OSError:
        binary_sha = None
    artifact = {
        "engine": "joern-ghidra2cpg",
        "evidence_tier": "hint",
        "precision": _PRECISION_NOTE,
        "binary": str(binary_path),
        "binary_sha256": binary_sha,
        "method_count": outcome.method_count,
        "taint_flow_count": outcome.taint_flow_count,
        "taint_flows": taint_entries,
        "structural_hit_count": outcome.structural_hit_count,
        "structural_hits": structural_entries,
        "queries_failed": list(outcome.queries_failed)[:MAX_ARTIFACT_ERRORS],
        "errors": [str(e)[:300] for e in outcome.errors[:MAX_ARTIFACT_ERRORS]],
        "degraded": outcome.degraded,
        "elapsed_s": round(outcome.elapsed_s, 1),
    }
    from core.json import save_json
    artifact_path = out_dir / ARTIFACT_NAME
    try:
        save_json(artifact_path, artifact)
        outcome.artifact_path = artifact_path
    except OSError as error:
        outcome.errors.append(f"artifact write failed: {error}")
        outcome.degraded = True
    return outcome
