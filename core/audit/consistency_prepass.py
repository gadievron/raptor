"""Standing consistency pre-pass for the audit prep phase.

Runs once per run, on the same source set as the mechanical
detectors (§2.3/§2.4):

1. builds the return-usage census (one parse per file, shared cache)
   and writes ``return-census.json``;
2. adjudicates every census deviant through
   :func:`~core.audit.consistency_verify.census_verdict` —
   registry-grade contract witnesses become **LLM-free promote-capable
   findings** (synthesized hypothesis, PeerEvidence receipts,
   entry-reachability escalator deciding ``finding`` vs
   ``suspicious``); majority-only confirmations stay detection-grade
   (``suspicious``, aggregation-eligible);
3. runs the flag/mode (§3.7) and error-path cleanup (§3.2)
   comparators;
4. assembles capped checklist leads (``MAX_CONSISTENCY_LEADS``/run,
   ``MAX_LEADS_PER_FILE``/file, ranked by contract strength →
   security relevance → ratio) and fail-open handoff hypotheses (the
   acknowledged-discard premise split);
5. emits per-dimension telemetry (counts, contract-source histogram,
   inconclusive-reason histogram, wall time, budget state).

Wall-clock budget 60 s: on overrun the remaining comparators are
skipped and the telemetry says so — the census never blocks prep.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from .callsite_consistency import (
    CalleeCensus,
    build_return_census,
    census_to_dict,
)
from .prep_cache import (
    load_prep_cache,
    source_fingerprint as _source_fingerprint,
    write_prep_cache,
)
from .consistency_dimensions import DIMENSION_ORDERING
from .consistency_verify import (
    DIMENSION_CLEANUP,
    DIMENSION_RETURN_CHECK,
    census_verdict,
    cleanup_verdict,
)
from .fail_open_roles import RoleContext
from .return_contracts import harvest_wur_declarations

logger = logging.getLogger(__name__)

MAX_CONSISTENCY_LEADS = 40
MAX_LEADS_PER_FILE = 5
MAX_FINDINGS = 100
MAX_DEVIANTS_PER_CALLEE = 5
MAX_VERDICT_CALLEES = 200
PREPASS_BUDGET_S = 60.0
# Joern-flow escalator budget (§2.3 "Joern flow only budget-
# permitting"): at most this many CPG caller-closure queries per run;
# only promote-capable confirmations whose cheap reachability leg
# answered unknown spend from it.
MAX_JOERN_ESCALATIONS = 16

# CWE per cleanup pair kind (lock-shaped kinds are deadlock territory,
# everything else is leak territory).
_LOCK_KINDS = frozenset({
    "mutex", "spinlock", "rwlock", "rcu", "lock", "semaphore",
    "lock_unlock",
})


def _cleanup_cwe(kind: str) -> str:
    return "CWE-667" if kind in _LOCK_KINDS else "CWE-401"


# Sink-class → CWE grading for the sanitize-before-sink dimension
# (§3.3 "CWE per sink class"). Structural category stems only — the
# sink names themselves come from the learned surfaces.
_SINK_CLASS_CWES = (
    (("sql", "query", "database"), "CWE-89"),
    (("command", "exec", "shell", "process"), "CWE-78"),
    (("path", "file", "directory"), "CWE-22"),
    (("html", "xss", "template", "render"), "CWE-79"),
)


def _sink_cwe(entry: dict[str, Any]) -> str:
    explicit = str(entry.get("cwe") or "")
    if explicit:
        return explicit if explicit.startswith("CWE-") \
            else f"CWE-{explicit}"
    category = str(
        entry.get("category") or entry.get("sink_type") or "",
    ).lower()
    for stems, cwe in _SINK_CLASS_CWES:
        if any(s in category for s in stems):
            return cwe
    return ""


def _collect_sink_vocabulary(
    source_texts: dict[str, str],
    *,
    out_dir: Path | None,
    annotations_dir: Path | None,
    context_map: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Sink names from the landed vocab machinery (§3.3): human-grade
    operator ``status: sink`` annotations (the registry-grade
    convention source), learned IRIS ``sink`` specs, and the
    context-map sink catalog (taxonomy + discovered wrapper sinks).
    No hardcoded sink list exists here or in the comparator."""
    sinks: dict[str, dict[str, Any]] = {}

    ann_base = annotations_dir
    if ann_base is None and out_dir is not None:
        candidate = Path(out_dir) / "annotations"
        ann_base = candidate if candidate.is_dir() else None
    if ann_base is not None:
        try:
            from core.annotations.provenance import is_human_grade
            from core.annotations.storage import (
                annotation_file_mtime,
                read_file_annotations,
            )
            for fp in source_texts:
                ann_mtime = annotation_file_mtime(Path(ann_base), fp)
                for ann in read_file_annotations(Path(ann_base), fp):
                    meta = ann.metadata or {}
                    if meta.get("status") != "sink":
                        continue
                    sinks[ann.function] = {
                        "source": "annotation",
                        "cwe": _sink_cwe(meta),
                        "registry": is_human_grade(
                            meta, note_mtime=ann_mtime,
                        ),
                    }
        except Exception:
            logger.debug("sanitize-sink: annotation sink read failed",
                         exc_info=True)

    if out_dir is not None:
        try:
            from core.iris.api import load_project_specs
            for spec in load_project_specs(
                    out_dir=Path(out_dir), roles={"sink"}):
                sinks.setdefault(spec.function, {
                    "source": "iris_spec",
                    "cwe": "",
                    "registry": False,
                })
        except Exception:
            logger.debug("sanitize-sink: IRIS sink load failed",
                         exc_info=True)

    for entry in (context_map or {}).get("sinks") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("function") or entry.get("name") or "")
        if not name:
            continue
        sinks.setdefault(name, {
            "source": "context_map",
            "cwe": _sink_cwe(entry),
            "registry": False,
        })
    return sinks


def _collect_sanitizer_vocabulary(out_dir: Path | None) -> frozenset[str]:
    """Learned sanitizer names: the IRIS ``sanitiser`` role through
    the tool-corroborated (suppression-gated) reader — recognising a
    sanitizer at a peer site is exactly the direction a hallucinated
    spec must not steer."""
    if out_dir is None:
        return frozenset()
    try:
        from core.iris.api import get_project_sanitisers
        return get_project_sanitisers(out_dir=Path(out_dir))
    except Exception:
        logger.debug("sanitize-sink: sanitiser load failed",
                     exc_info=True)
        return frozenset()


def _lead_from_result(res: Any, *, file: str, function: str,
                      line: int, security_relevant: bool) -> dict[str, Any]:
    pe = res.peer_evidence
    lead: dict[str, Any] = {
        "dimension": res.dimension,
        "callee": res.callee,
        "file": file,
        "function": function,
        "line": line,
        "rule_id": res.rule_id,
        "description": res.reason[:300],
        "security_relevant": security_relevant,
    }
    if pe is not None:
        lead.update({
            "n": pe.n,
            "conforming": pe.conforming,
            "ratio": pe.ratio,
            "contract_source": pe.contract_source,
            "sites": [
                f"{e.file}:{e.line} {e.snippet}".strip()
                for e in pe.exhibits
            ],
        })
    return lead


def _rank_leads(leads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank by (contract strength, security_relevant, ratio) and apply
    the run/file caps (§2.4.2)."""
    ranked = sorted(
        leads,
        key=lambda ld: (
            ld.get("contract_source", "none") == "majority",
            not ld.get("security_relevant", False),
            -float(ld.get("ratio") or 0.0),
            ld.get("file", ""),
            ld.get("line", 0),
        ),
    )
    per_file: dict[str, int] = {}
    capped: list[dict[str, Any]] = []
    for lead in ranked:
        if len(capped) >= MAX_CONSISTENCY_LEADS:
            break
        fp = lead.get("file", "")
        if per_file.get(fp, 0) >= MAX_LEADS_PER_FILE:
            continue
        per_file[fp] = per_file.get(fp, 0) + 1
        capped.append(lead)
    return capped


def _inventory_function_names(inventory: Any) -> set[str]:
    """Function/item names from an inventory dict.

    The builder emits per-file "items"; older inventories carried
    "functions" — accept both (builder-side compat reads both too).
    """
    names: set[str] = set()
    for frec in (inventory or {}).get("files", []) or []:
        if not isinstance(frec, dict):
            continue
        for fn in frec.get("items", frec.get("functions", [])) or []:
            if isinstance(fn, dict) and fn.get("name"):
                names.add(fn["name"])
    return names


def _status_for(res: Any, *, detection: bool) -> str:
    """G7-respecting status mapping (§2.3): a registry-grade
    confirmation promotes to ``finding`` only when the enclosing
    function is entry-reachable; unknown reachability keeps the
    confirmation as ``suspicious``. Detection-grade never exceeds
    ``suspicious``."""
    if detection:
        return "suspicious"
    reach = (res.reachability or {}).get("status", "")
    return "finding" if reach == "entry_reachable" else "suspicious"


_CENSUS_CACHE_FILENAME = "return-census-cache.json"


def _load_census_cache(
    out_dir: Path, fingerprint: str,
) -> dict[str, CalleeCensus] | None:
    """The cached census, or None on miss/mismatch/corruption.

    Same-run resume re-walked the whole tree every segment (the census
    per-site scope walks are the prep phase's dominant wall cost) even
    though the checklist is pinned and the sources unchanged.
    """
    rows = load_prep_cache(
        out_dir, _CENSUS_CACHE_FILENAME, fingerprint,
        label="return-census",
    )
    if not isinstance(rows, dict):
        return None
    return {
        callee: CalleeCensus.from_full_dict(d)
        for callee, d in rows.items()
        if isinstance(d, dict)
    }


def _write_census_cache(
    out_dir: Path, fingerprint: str, census: dict[str, CalleeCensus],
) -> None:
    """Best-effort atomic persist; a failure never costs the run."""
    write_prep_cache(
        out_dir, _CENSUS_CACHE_FILENAME, fingerprint,
        {callee: c.to_full_dict() for callee, c in sorted(census.items())},
        label="return-census",
    )


def run_consistency_prepass(
    source_texts: dict[str, str],
    *,
    target_path: Path | None = None,
    out_dir: Path | None = None,
    annotations_dir: Path | None = None,
    inventory: dict[str, Any] | None = None,
    context_map: dict[str, Any] | None = None,
    domain_model: dict[str, Any] | None = None,
    joern_server: Any = None,
    peer_groups: list[Any] | None = None,
    budget_s: float = PREPASS_BUDGET_S,
) -> dict[str, Any]:
    """Run the standing pre-pass. Returns::

        {
          "census": {callee: CalleeCensus},
          "findings": [...],        # LLM-free confirmed verdicts
          "leads": [...],           # capped checklist leads
          "mechanical": [...],      # detector-shaped prompt entries
          "handoffs": [...],        # fail-open hypothesis seeds
          "telemetry": {...},
        }
    """
    t0 = time.monotonic()
    telemetry: dict[str, Any] = {
        "dimensions": {},
        "contract_sources": {},
        "inconclusive_reasons": {},
        # Dimension-level failure counter: a dimension whose detector
        # raised is recorded here so "0 deviations" is distinguishable
        # from "dimension failed" in the run telemetry.
        "dimension_failures": {},
        "leads_seeded": 0,
        "promotions": 0,
        "budget_exceeded": False,
    }

    def _dim(dimension: str) -> dict[str, int]:
        return telemetry["dimensions"].setdefault(
            dimension,
            {"confirmed": 0, "refuted": 0, "inconclusive": 0},
        )

    def _dim_failed(dimension: str) -> None:
        telemetry["dimension_failures"][dimension] = (
            telemetry["dimension_failures"].get(dimension, 0) + 1
        )

    def _over_budget() -> bool:
        if time.monotonic() - t0 > budget_s:
            telemetry["budget_exceeded"] = True
            return True
        return False

    # Joern-flow escalator accounting: pass the server to a verdict
    # only while queries remain; charge the budget when the returned
    # receipt shows the flow leg actually ran.
    joern_state = {"spent": 0}

    def _joern_arg() -> Any:
        if joern_server is None \
                or joern_state["spent"] >= MAX_JOERN_ESCALATIONS:
            return None
        return joern_server

    def _charge_joern(res: Any) -> None:
        r = getattr(res, "reachability", None) or {}
        if r.get("via") == "joern_flow" or "joern_flow" in r:
            joern_state["spent"] += 1
            telemetry["joern_escalations"] = joern_state["spent"]

    findings: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    mechanical: list[dict[str, Any]] = []
    handoffs: list[dict[str, Any]] = []

    census: dict[str, CalleeCensus] = {}
    census_cached = False
    _census_fp = _source_fingerprint(source_texts)
    if out_dir is not None:
        cached = _load_census_cache(Path(out_dir), _census_fp)
        if cached is not None:
            census = cached
            census_cached = True
            logger.info(
                "return census: reloaded %d callees from the prep "
                "cache (source fingerprint match) — census re-walk "
                "skipped", len(census),
            )
    if not census_cached:
        try:
            # The census self-limits to half the prepass budget: it runs
            # BEFORE the first _over_budget() check, so without its own
            # deadline one hostile file of module-level assignments
            # stalls prep for hours (per-site scope walks are O(file)).
            census = build_return_census(
                source_texts, joern_server=joern_server,
                budget_s=budget_s / 2,
            )
            if out_dir is not None and census:
                _write_census_cache(Path(out_dir), _census_fp, census)
        except Exception:
            _dim_failed("census")
            logger.debug("consistency prepass: census build failed",
                         exc_info=True)

    wur_names = harvest_wur_declarations(source_texts)
    if target_path is not None:
        try:
            from .return_contracts import harvest_wur_from_target
            wur_names = wur_names | harvest_wur_from_target(
                Path(target_path),
            )
        except Exception:
            logger.debug("consistency prepass: header wur harvest "
                         "failed", exc_info=True)
    ctx = RoleContext(
        out_dir=out_dir,
        annotations_dir=annotations_dir,
        inventory=inventory,
        context_map=context_map,
        wur_functions=wur_names,
    )

    # ── return-check dimension (§3.1 / §2.3) ────────────────────────
    eligible = [
        c for c in census.values()
        if c.deviants or c.acknowledged_sites
    ]
    eligible.sort(
        key=lambda c: (not c.security_relevant, -c.considered, c.callee),
    )
    for entry in eligible[:MAX_VERDICT_CALLEES]:
        if _over_budget():
            break
        callee = entry.callee
        deviants = entry.deviants[:MAX_DEVIANTS_PER_CALLEE]
        ack_sites = entry.acknowledged_sites[:MAX_DEVIANTS_PER_CALLEE]
        for site in list(deviants) + list(ack_sites):
            try:
                res = census_verdict(
                    entry, site, context=ctx, inventory=inventory,
                    source_texts=source_texts,
                    joern_server=_joern_arg(),
                )
                _charge_joern(res)
            except Exception:
                logger.debug(
                    "consistency prepass: verdict failed for %s",
                    callee, exc_info=True,
                )
                continue
            counts = _dim(DIMENSION_RETURN_CHECK)
            counts[res.outcome] = counts.get(res.outcome, 0) + 1
            if res.outcome == "inconclusive":
                reason_key = res.reason.split(":", 1)[0]
                telemetry["inconclusive_reasons"][reason_key] = (
                    telemetry["inconclusive_reasons"].get(reason_key, 0)
                    + 1
                )
                continue
            if res.outcome == "refuted":
                if res.fail_open_handoff:
                    handoffs.append({
                        "file": site.file,
                        "function": site.enclosing_function,
                        "line": site.line,
                        "callee": callee,
                        "mechanism": (
                            f"the return value of {callee} is ignored "
                            f"(explicitly discarded) at line "
                            f"{site.line}; a failure of this "
                            f"security-role call would proceed "
                            f"silently"
                        ),
                    })
                continue
            # confirmed
            pe = res.peer_evidence
            source_key = pe.contract_source if pe else "none"
            telemetry["contract_sources"][source_key] = (
                telemetry["contract_sources"].get(source_key, 0) + 1
            )
            if entry.contract is None and res.contract is not None:
                entry.contract = res.contract
            detection = res.rule_id.endswith("-majority")
            status = _status_for(res, detection=detection)
            if status == "finding":
                telemetry["promotions"] += 1
            if len(findings) < MAX_FINDINGS:
                findings.append({
                    "file": site.file,
                    "function": site.enclosing_function,
                    "line": site.line,
                    "callee": callee,
                    "dimension": DIMENSION_RETURN_CHECK,
                    "rule_id": res.rule_id,
                    "evidence_tool": res.rule_id,
                    "status": status,
                    "detection_grade": detection,
                    "cwe": "CWE-252",
                    "hypothesis": (
                        f"return of {callee}() is {site.usage} at "
                        f"{site.file}:{site.line} while "
                        f"{len(entry.conforming)}/{entry.considered} "
                        f"sites check it"
                    ),
                    "description": res.reason,
                    "receipts": res.to_dict(),
                })
            leads.append(_lead_from_result(
                res,
                file=site.file,
                function=site.enclosing_function,
                line=site.line,
                security_relevant=entry.security_relevant,
            ))

    # ── flag/mode dimension (§3.7) ──────────────────────────────────
    if not _over_budget():
        constants = None
        try:
            if target_path is not None and Path(target_path).is_dir():
                from .constant_resolution import build_unique_constants
                constants = build_unique_constants(
                    Path(target_path),
                ).as_int_dict()
        except Exception:
            logger.debug("consistency prepass: constant table failed",
                         exc_info=True)
        try:
            from .consistency_dimensions import (
                detect_flag_mode_deviations,
            )
            flag_devs = detect_flag_mode_deviations(
                source_texts, constants=constants,
            )
        except Exception:
            _dim_failed("flag-mode")
            logger.debug("consistency prepass: flag/mode failed",
                         exc_info=True)
            flag_devs = []
        counts = _dim("flag-mode")
        for dev in flag_devs:
            counts["confirmed"] += 1
            mechanical.append({
                "file": dev.file,
                "function": dev.enclosing_function,
                "detector": "flag_mode_deviation",
                "line": dev.line,
                "description": dev.description,
                "callee": dev.callee,
                "rule_id": (
                    dev.peer_evidence.rule_id
                    if dev.peer_evidence else ""
                ),
                "cwe": dev.cwe,
            })
            leads.append({
                "dimension": "flag-mode",
                "callee": dev.callee,
                "file": dev.file,
                "function": dev.enclosing_function,
                "line": dev.line,
                "rule_id": (
                    dev.peer_evidence.rule_id
                    if dev.peer_evidence else ""
                ),
                "description": dev.description[:300],
                "security_relevant": dev.security is not None,
                "n": dev.n,
                "conforming": dev.conforming,
                "ratio": dev.ratio,
                "contract_source": "majority",
                "sites": [
                    f"{e.file}:{e.line} {e.snippet}".strip()
                    for e in (
                        dev.peer_evidence.exhibits
                        if dev.peer_evidence else []
                    )
                ],
            })

    # ── argument-shape dimension (§3.6) ─────────────────────────────
    if not _over_budget():
        try:
            from .consistency_dimensions import (
                DIMENSION_ARGUMENT_SHAPE,
                detect_argument_shape_deviations,
            )
            from .consistency_verify import argument_shape_verdict
            shape_devs = detect_argument_shape_deviations(source_texts)
        except Exception:
            _dim_failed("argument-shape")
            logger.debug("consistency prepass: argument shape failed",
                         exc_info=True)
            shape_devs = []
        if shape_devs:
            counts = _dim(DIMENSION_ARGUMENT_SHAPE)
            for dev in shape_devs:
                try:
                    res = argument_shape_verdict(
                        dev, context=ctx, inventory=inventory,
                        joern_server=_joern_arg(),
                    )
                    _charge_joern(res)
                except Exception:
                    logger.debug("consistency prepass: argument-shape "
                                 "verdict failed", exc_info=True)
                    continue
                counts[res.outcome] = counts.get(res.outcome, 0) + 1
                mechanical.append({
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    "detector": "argument_shape_deviation",
                    "line": dev.line,
                    "description": dev.description,
                    "callee": dev.callee,
                    "rule_id": res.rule_id,
                    "cwe": dev.cwe,
                })
                if dev.type_witness and res.outcome == "confirmed":
                    pe = res.peer_evidence
                    source_key = pe.contract_source if pe else "none"
                    telemetry["contract_sources"][source_key] = (
                        telemetry["contract_sources"].get(source_key, 0)
                        + 1
                    )
                    status = _status_for(res, detection=False)
                    if status == "finding":
                        telemetry["promotions"] += 1
                    if len(findings) < MAX_FINDINGS:
                        findings.append({
                            "file": dev.file,
                            "function": dev.enclosing_function,
                            "line": dev.line,
                            "callee": dev.callee,
                            "dimension": DIMENSION_ARGUMENT_SHAPE,
                            "rule_id": res.rule_id,
                            "evidence_tool": res.rule_id,
                            "status": status,
                            "detection_grade": False,
                            "cwe": dev.cwe,
                            "hypothesis": (
                                f"{dev.callee}({dev.position}) receives "
                                f"sizeof over a pointer at "
                                f"{dev.file}:{dev.line} while "
                                f"{dev.conforming}/{dev.n} sites pass "
                                f"the buffer size"
                            ),
                            "description": res.reason,
                            "receipts": res.to_dict(),
                        })
                leads.append(_lead_from_result(
                    res,
                    file=dev.file,
                    function=dev.enclosing_function,
                    line=dev.line,
                    security_relevant=dev.type_witness,
                ))

    # ── learned pairs (shared by cleanup §3.2 and ordering §3.5) ────
    learned_pairs: list[Any] = []
    try:
        from .consistency_dimensions import learned_cleanup_pairs

        function_names = _inventory_function_names(inventory)
        if not function_names:
            for entry in census.values():
                for site in entry.sites:
                    if site.enclosing_function not in ("", "<module>"):
                        function_names.add(site.enclosing_function)
        learned_pairs = learned_cleanup_pairs(
            domain_model, function_names,
        )
    except Exception:
        _dim_failed("learned-pairs")
        logger.debug("consistency prepass: learned pairs failed",
                     exc_info=True)

    # ── cleanup dimension (§3.2) ────────────────────────────────────
    if not _over_budget():
        try:
            from .consistency_dimensions import detect_cleanup_deviations
            cleanup_devs = (
                detect_cleanup_deviations(source_texts, learned_pairs)
                if learned_pairs else []
            )
        except Exception:
            _dim_failed(DIMENSION_CLEANUP)
            logger.debug("consistency prepass: cleanup failed",
                         exc_info=True)
            cleanup_devs = []
        counts = _dim(DIMENSION_CLEANUP)
        for dev in cleanup_devs:
            try:
                res = cleanup_verdict(
                    dev, context=ctx, inventory=inventory,
                    joern_server=_joern_arg(),
                )
                _charge_joern(res)
            except Exception:
                logger.debug("consistency prepass: cleanup verdict "
                             "failed", exc_info=True)
                continue
            counts[res.outcome] = counts.get(res.outcome, 0) + 1
            mechanical.append({
                "file": dev.file,
                "function": dev.enclosing_function,
                "detector": "cleanup_deviation",
                "line": dev.line,
                "description": dev.description,
                "callee": dev.pair.acquire,
                "rule_id": res.rule_id,
                "cwe": _cleanup_cwe(dev.pair.kind),
            })
            if res.outcome == "inconclusive":
                reason_key = res.reason.split(":", 1)[0]
                telemetry["inconclusive_reasons"][reason_key] = (
                    telemetry["inconclusive_reasons"].get(reason_key, 0)
                    + 1
                )
                leads.append(_lead_from_result(
                    res,
                    file=dev.file,
                    function=dev.enclosing_function,
                    line=dev.line,
                    security_relevant=True,
                ))
                continue
            if res.outcome != "confirmed":
                continue
            pe = res.peer_evidence
            source_key = pe.contract_source if pe else "none"
            telemetry["contract_sources"][source_key] = (
                telemetry["contract_sources"].get(source_key, 0) + 1
            )
            status = _status_for(res, detection=False)
            if status == "finding":
                telemetry["promotions"] += 1
            if len(findings) < MAX_FINDINGS:
                findings.append({
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    "line": dev.line,
                    "callee": dev.pair.acquire,
                    "dimension": DIMENSION_CLEANUP,
                    "rule_id": res.rule_id,
                    "evidence_tool": res.rule_id,
                    "status": status,
                    "detection_grade": False,
                    "cwe": _cleanup_cwe(dev.pair.kind),
                    "hypothesis": (
                        f"{dev.conforming}/{dev.n} "
                        f"{'error paths' if dev.leg == 'intra_path' else 'sibling callers'} "
                        f"release {dev.pair.acquire}()'s resource via "
                        f"{dev.pair.release}(); "
                        f"{dev.enclosing_function} does not"
                    ),
                    "description": res.reason,
                    "receipts": res.to_dict(),
                })
            leads.append(_lead_from_result(
                res,
                file=dev.file,
                function=dev.enclosing_function,
                line=dev.line,
                security_relevant=True,
            ))

    # ── ordering dimension (§3.5) — detection-grade throughout ──────
    if not _over_budget():
        try:
            from .consistency_dimensions import (
                detect_ordering_deviations,
            )
            order_devs = detect_ordering_deviations(
                source_texts, pairs=learned_pairs,
            )
        except Exception:
            _dim_failed(DIMENSION_ORDERING)
            logger.debug("consistency prepass: ordering failed",
                         exc_info=True)
            order_devs = []
        counts = _dim(DIMENSION_ORDERING)
        for dev in order_devs:
            if dev.data_dependent:
                # The deviant's earlier call feeds the later call —
                # the order is forced; enumerated inconclusive, no lead.
                counts["inconclusive"] += 1
                telemetry["inconclusive_reasons"][
                    "order-data-dependent"
                ] = telemetry["inconclusive_reasons"].get(
                    "order-data-dependent", 0,
                ) + 1
                continue
            counts["confirmed"] += 1
            mechanical.append({
                "file": dev.file,
                "function": dev.enclosing_function,
                "detector": "ordering_deviation",
                "line": dev.line,
                "description": dev.description,
                "callee": dev.second_op,
                "rule_id": (
                    dev.peer_evidence.rule_id
                    if dev.peer_evidence else ""
                ),
                "cwe": dev.cwe,
            })
            leads.append({
                "dimension": DIMENSION_ORDERING,
                "callee": f"{dev.first_op}/{dev.second_op}",
                "file": dev.file,
                "function": dev.enclosing_function,
                "line": dev.line,
                "rule_id": (
                    dev.peer_evidence.rule_id
                    if dev.peer_evidence else ""
                ),
                "description": dev.description[:300],
                "security_relevant": dev.flavor != "sequence",
                "n": dev.n,
                "conforming": dev.conforming,
                "ratio": dev.ratio,
                "contract_source": "majority",
                "sites": [
                    f"{e.file}:{e.line} {e.snippet}".strip()
                    for e in (
                        dev.peer_evidence.exhibits
                        if dev.peer_evidence else []
                    )
                ],
            })

    # ── interface-implementor parity (§3.8) — escalation-only ───────
    if not _over_budget() and peer_groups:
        try:
            from .consistency_dimensions import (
                DIMENSION_INTERFACE,
                detect_interface_deviations,
            )
            iface_devs = detect_interface_deviations(
                source_texts, peer_groups,
            )
        except Exception:
            _dim_failed("interface")
            logger.debug("consistency prepass: interface parity "
                         "failed", exc_info=True)
            iface_devs = []
        if iface_devs:
            counts = _dim(DIMENSION_INTERFACE)
            for dev in iface_devs:
                counts["confirmed"] += 1
                mechanical.append({
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    "detector": "interface_deviation",
                    "line": dev.line,
                    "description": dev.description,
                    "callee": dev.property_name,
                    "rule_id": (
                        dev.peer_evidence.rule_id
                        if dev.peer_evidence else ""
                    ),
                    "cwe": dev.cwe,
                })
                leads.append({
                    "dimension": DIMENSION_INTERFACE,
                    "callee": dev.property_name,
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    "line": dev.line,
                    "rule_id": (
                        dev.peer_evidence.rule_id
                        if dev.peer_evidence else ""
                    ),
                    "description": dev.description[:300],
                    "security_relevant": dev.cwe == "CWE-862",
                    "n": dev.n,
                    "conforming": dev.conforming,
                    "ratio": dev.ratio,
                    "contract_source": "majority",
                    "sites": [
                        f"{e.file}:{e.line} {e.snippet}".strip()
                        for e in (
                            dev.peer_evidence.exhibits
                            if dev.peer_evidence else []
                        )
                    ],
                })

    # ── clone-drift dimension (§3.9) ────────────────────────────────
    if not _over_budget():
        from .consistency_verify import (
            DIMENSION_CLONE_DRIFT,
            clone_drift_verdict,
        )
        counts = _dim(DIMENSION_CLONE_DRIFT)

        # Fix-anchored leg (promote-capable): the fix commit is the
        # contract witness; anchors come from apply_fix_history's
        # variant hunt earlier in the same prep run.
        try:
            from .clone_drift import fix_anchored_drift, load_fix_anchors
            anchored = fix_anchored_drift(
                load_fix_anchors(out_dir), source_texts,
                telemetry=counts,
            )
        except Exception:
            _dim_failed(DIMENSION_CLONE_DRIFT)
            logger.debug("consistency prepass: fix-anchored clone "
                         "drift failed", exc_info=True)
            anchored = []
        for dev in anchored:
            try:
                res = clone_drift_verdict(
                    dev, context=ctx, inventory=inventory,
                    joern_server=_joern_arg(),
                )
                _charge_joern(res)
            except Exception:
                logger.debug("consistency prepass: clone-drift "
                             "verdict failed", exc_info=True)
                continue
            counts[res.outcome] = counts.get(res.outcome, 0) + 1
            mechanical.append({
                "file": dev.file,
                "function": dev.enclosing_function,
                "detector": "clone_drift",
                "line": dev.line,
                "description": dev.description,
                "callee": dev.token,
                "rule_id": res.rule_id,
                "cwe": dev.cwe,
            })
            if res.outcome != "confirmed":
                continue
            pe = res.peer_evidence
            source_key = pe.contract_source if pe else "none"
            telemetry["contract_sources"][source_key] = (
                telemetry["contract_sources"].get(source_key, 0) + 1
            )
            status = _status_for(res, detection=False)
            if status == "finding":
                telemetry["promotions"] += 1
            if len(findings) < MAX_FINDINGS:
                findings.append({
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    "line": dev.line,
                    "callee": dev.token,
                    "dimension": DIMENSION_CLONE_DRIFT,
                    "rule_id": res.rule_id,
                    "evidence_tool": res.rule_id,
                    "status": status,
                    "detection_grade": False,
                    "cwe": dev.cwe,
                    "hypothesis": (
                        f"{dev.enclosing_function} reproduces the "
                        f"region fix {dev.fix_sha[:12]} patched but "
                        f"lacks the added guard {dev.token}()"
                    ),
                    "description": res.reason,
                    "receipts": res.to_dict(),
                })
            leads.append(_lead_from_result(
                res,
                file=dev.file,
                function=dev.enclosing_function,
                line=dev.line,
                security_relevant=True,
            ))

        # Generic winnowing leg (detection-grade).
        try:
            from .clone_drift import detect_clone_drift
            generic = detect_clone_drift(source_texts, telemetry=counts)
        except Exception:
            _dim_failed(DIMENSION_CLONE_DRIFT)
            logger.debug("consistency prepass: clone winnowing "
                         "failed", exc_info=True)
            generic = []
        for dev in generic:
            counts["confirmed"] = counts.get("confirmed", 0) + 1
            mechanical.append({
                "file": dev.file,
                "function": dev.enclosing_function,
                "detector": "clone_drift",
                "line": dev.line,
                "description": dev.description,
                "callee": dev.token,
                "rule_id": (
                    dev.peer_evidence.rule_id
                    if dev.peer_evidence else ""
                ),
                "cwe": dev.cwe,
            })
            leads.append({
                "dimension": DIMENSION_CLONE_DRIFT,
                "callee": dev.token,
                "file": dev.file,
                "function": dev.enclosing_function,
                "line": dev.line,
                "rule_id": (
                    dev.peer_evidence.rule_id
                    if dev.peer_evidence else ""
                ),
                "description": dev.description[:300],
                "security_relevant": dev.kind in ("guard", "bound"),
                "n": 2,
                "conforming": 1,
                "ratio": dev.similarity,
                "contract_source": "majority",
                "sites": [
                    f"{e.file}:{e.line} {e.snippet}".strip()
                    for e in (
                        dev.peer_evidence.exhibits
                        if dev.peer_evidence else []
                    )
                ],
            })

    # ── sanitize-before-sink dimension (§3.3) ───────────────────────
    if not _over_budget():
        try:
            from .consistency_dimensions import (
                DIMENSION_SANITIZE_SINK,
                detect_sanitize_sink_deviations,
            )
            from .consistency_verify import sanitize_sink_verdict
            sink_vocab = _collect_sink_vocabulary(
                source_texts,
                out_dir=out_dir,
                annotations_dir=annotations_dir,
                context_map=context_map,
            )
            sanitizer_vocab = _collect_sanitizer_vocabulary(out_dir)
            sanitize_devs = (
                detect_sanitize_sink_deviations(
                    source_texts, sink_vocab, sanitizer_vocab,
                )
                if sink_vocab and sanitizer_vocab else []
            )
        except Exception:
            _dim_failed("sanitize-sink")
            logger.debug("consistency prepass: sanitize-sink failed",
                         exc_info=True)
            sanitize_devs = []
        if sanitize_devs:
            counts = _dim(DIMENSION_SANITIZE_SINK)
            for dev in sanitize_devs:
                try:
                    res = sanitize_sink_verdict(
                        dev, context=ctx, inventory=inventory,
                        joern_server=_joern_arg(),
                    )
                    _charge_joern(res)
                except Exception:
                    logger.debug("consistency prepass: sanitize-sink "
                                 "verdict failed", exc_info=True)
                    continue
                counts[res.outcome] = counts.get(res.outcome, 0) + 1
                mechanical.append({
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    "detector": "sanitize_sink_deviation",
                    "line": dev.line,
                    "description": dev.description,
                    "callee": dev.sink,
                    "rule_id": res.rule_id,
                    "cwe": dev.cwe,
                })
                if dev.registry_grade and res.outcome == "confirmed":
                    pe = res.peer_evidence
                    source_key = pe.contract_source if pe else "none"
                    telemetry["contract_sources"][source_key] = (
                        telemetry["contract_sources"].get(source_key, 0)
                        + 1
                    )
                    status = _status_for(res, detection=False)
                    if status == "finding":
                        telemetry["promotions"] += 1
                    if len(findings) < MAX_FINDINGS:
                        findings.append({
                            "file": dev.file,
                            "function": dev.enclosing_function,
                            "line": dev.line,
                            "callee": dev.sink,
                            "dimension": DIMENSION_SANITIZE_SINK,
                            "rule_id": res.rule_id,
                            "evidence_tool": res.rule_id,
                            "status": status,
                            "detection_grade": False,
                            "cwe": dev.cwe,
                            "hypothesis": (
                                f"{dev.conforming}/{dev.n} call sites "
                                f"of the operator-annotated sink "
                                f"{dev.sink}() sanitize the argument "
                                f"first; {dev.enclosing_function} "
                                f"passes it unsanitized at "
                                f"{dev.file}:{dev.line}"
                            ),
                            "description": res.reason,
                            "receipts": res.to_dict(),
                        })
                leads.append(_lead_from_result(
                    res,
                    file=dev.file,
                    function=dev.enclosing_function,
                    line=dev.line,
                    security_relevant=True,
                ))

    # ── bounds/null-guard presence dimension (§3.4) ─────────────────
    if not _over_budget():
        try:
            from .consistency_dimensions import (
                DIMENSION_GUARD_PRESENCE,
                detect_guard_presence_deviations,
            )
            from .consistency_verify import guard_presence_verdict
            guard_devs = detect_guard_presence_deviations(
                source_texts,
                budget_s=max(
                    0.0, budget_s - (time.monotonic() - t0),
                ),
            )
        except Exception:
            _dim_failed("guard-presence")
            logger.debug("consistency prepass: guard presence failed",
                         exc_info=True)
            guard_devs = []
        if guard_devs:
            counts = _dim(DIMENSION_GUARD_PRESENCE)
            for dev in guard_devs:
                try:
                    res = guard_presence_verdict(
                        dev, context=ctx, inventory=inventory,
                        source_texts=source_texts,
                        joern_server=_joern_arg(),
                    )
                    _charge_joern(res)
                except Exception:
                    logger.debug("consistency prepass: guard-presence "
                                 "verdict failed", exc_info=True)
                    continue
                counts[res.outcome] = counts.get(res.outcome, 0) + 1
                if res.outcome == "refuted":
                    continue
                promoted = (
                    res.outcome == "confirmed"
                    and not res.rule_id.endswith("-majority")
                )
                mechanical.append({
                    "file": dev.file,
                    "function": dev.enclosing_function,
                    # The SMT-witnessed upgrade rides the EXISTING
                    # insufficient_guard_smt detector id (§3.4 "through
                    # the existing detector") so its downstream
                    # consumers treat it exactly like a condition_smt
                    # hit; plain outliers keep their own id.
                    "detector": (
                        "insufficient_guard_smt" if promoted
                        else "guard_presence_deviation"
                    ),
                    "line": dev.line,
                    "description": res.reason[:400],
                    "callee": dev.group_key,
                    "rule_id": res.rule_id,
                    "cwe": dev.cwe,
                })
                if res.outcome == "inconclusive":
                    reason_key = res.reason.split(":", 1)[0]
                    telemetry["inconclusive_reasons"][reason_key] = (
                        telemetry["inconclusive_reasons"].get(
                            reason_key, 0,
                        ) + 1
                    )
                    continue
                if promoted:
                    pe = res.peer_evidence
                    source_key = pe.contract_source if pe else "none"
                    telemetry["contract_sources"][source_key] = (
                        telemetry["contract_sources"].get(source_key, 0)
                        + 1
                    )
                    status = _status_for(res, detection=False)
                    if status == "finding":
                        telemetry["promotions"] += 1
                    if len(findings) < MAX_FINDINGS:
                        findings.append({
                            "file": dev.file,
                            "function": dev.enclosing_function,
                            "line": dev.line,
                            "callee": dev.group_key,
                            "dimension": DIMENSION_GUARD_PRESENCE,
                            "rule_id": res.rule_id,
                            "evidence_tool": res.rule_id,
                            "status": status,
                            "detection_grade": False,
                            "cwe": dev.cwe,
                            "hypothesis": (
                                f"{dev.conforming}/{dev.n} access "
                                f"sites of {dev.group_key} apply the "
                                f"{dev.kind} guard; "
                                f"{dev.enclosing_function} accesses "
                                f"{dev.guard_target!r} unguarded at "
                                f"{dev.file}:{dev.line} on an "
                                f"SMT-feasible path"
                            ),
                            "description": res.reason,
                            "receipts": res.to_dict(),
                        })
                leads.append(_lead_from_result(
                    res,
                    file=dev.file,
                    function=dev.enclosing_function,
                    line=dev.line,
                    security_relevant=True,
                ))

    capped_leads = _rank_leads(leads)
    telemetry["leads_seeded"] = len(capped_leads)
    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)

    if out_dir is not None and census:
        try:
            path = Path(out_dir) / "return-census.json"
            path.write_text(json.dumps(
                census_to_dict(census), indent=1,
            ))
            logger.info(
                "return census: %d callees, %d LLM-free confirmations "
                "(%d promote-capable), %d leads → %s",
                len(census), len(findings),
                sum(1 for f in findings if not f["detection_grade"]),
                len(capped_leads), path,
            )
        except Exception:
            logger.debug("return-census.json write failed",
                         exc_info=True)

    return {
        "census": census,
        "findings": findings,
        "leads": capped_leads,
        "mechanical": mechanical,
        "handoffs": handoffs,
        "telemetry": telemetry,
    }


def seed_consistency_leads(
    gaps: list[dict[str, Any]],
    leads: list[dict[str, Any]],
    *,
    boost: float = 2.0,
) -> int:
    """Attach capped leads to their gaps (gap-extra-key pattern, the
    ``reachable_sinks`` precedent) and notch the priority score."""
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for lead in leads:
        by_key.setdefault(
            (lead.get("file", ""), lead.get("function", "")), [],
        ).append(lead)
    seeded = 0
    for gap in gaps:
        key = (gap.get("file", ""), gap.get("name", ""))
        gap_leads = by_key.get(key)
        if not gap_leads:
            continue
        gap.setdefault("consistency_leads", []).extend(
            gap_leads[:MAX_LEADS_PER_FILE],
        )
        gap["priority_score"] = (
            float(gap.get("priority_score") or 0.0) + boost
        )
        seeded += len(gap_leads[:MAX_LEADS_PER_FILE])
    return seeded


def seed_fail_open_handoffs(
    gaps: list[dict[str, Any]],
    handoffs: list[dict[str, Any]],
) -> int:
    """The acknowledged-discard premise split (§2.3): seed a fail-open
    hypothesis on the gap so the loop dispatches the fail_open channel
    (the fix_history mechanically-injected-hypothesis precedent)."""
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for h in handoffs:
        by_key.setdefault(
            (h.get("file", ""), h.get("function", "")), [],
        ).append(h)
    seeded = 0
    for gap in gaps:
        key = (gap.get("file", ""), gap.get("name", ""))
        for h in by_key.get(key, []):
            gap.setdefault("injected_hypotheses", []).append({
                "mechanism": h["mechanism"],
                "confidence": "medium",
                "source": "consistency_census",
            })
            seeded += 1
    return seeded
