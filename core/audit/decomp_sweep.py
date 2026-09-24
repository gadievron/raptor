"""Tree-wide decompiler Semgrep sweep for binary audit targets.

The audit's per-hypothesis decompiler lane
(:func:`core.audit.binary_verification.decompiler_rules_for_hypothesis`
over per-function decompilations assembled by
:mod:`core.audit.binary_context`) only ever sees the functions the
review loop visited. This module widens that SAME lane to tree scope:
it materializes (or reuses) the run's decomp-tree — the pseudo-source
rendering of the RE database that binary ``--study`` already builds —
and runs the curated decompiler-tolerant rule corpus
(``core/audit/rules/decompiler/``), plus any curated strategy rules
carrying the ``# raptor: decomp-safe`` header marker, over the WHOLE
tree in one post-loop pass.

Trust footing (second-life provenance): the decomp-tree lives in the
RAPTOR-owned run directory, but its CONTENT is decompiled from the
analysed binary — attacker-shaped pseudo-C, exactly as untrusted as
the binary itself. Run-dir residency is not trust. The semgrep
invocations here therefore go through
:func:`packages.semgrep.runner.run_rule`'s DEFAULT sandboxed path
(``core.sandbox.run``: namespace + Landlock, network blocked) — the
same posture the audit's per-file sweeps already have against scanned
source — and this module never spells the runner's trusted-input
opt-out (a source-grep test pins that). When the sandbox is
unavailable the runner refuses and the refusal is recorded loudly;
the sweep never falls back to an unsandboxed scan.

Findings map back through the tree's ``decomp-map.json`` sidecar
(``file:line`` → ``function @ address`` + normalized ``fid``) to the
audit's ``binary:<stem>`` + address join, and enter the review journal
as ``[mechanical]`` echo rows carrying the semgrep receipt. Grading
discipline: decompilation is derived evidence, so every record is
clamped to the shared decompiled-evidence ceiling
(:data:`core.concepts.model.DECOMP_EVIDENCE_MAX_CONFIDENCE`, tag
:data:`core.concepts.model.DECOMP_EVIDENCE_TAG` — the one spelling
binary ``--study``'s domain-model clamp uses). Quoted match text is
escaped at capture and stamped ``derived_from_target``; unmapped
matches (lines no sidecar entry covers) are counted and recorded,
never silently dropped.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.concepts.model import (
    DECOMP_EVIDENCE_MAX_CONFIDENCE,
    DECOMP_EVIDENCE_TAG,
    clamp_decomp_confidence,
)
from core.inventory.binary_builder import BINARY_PATH_PREFIX, binary_path_key
from core.security.log_sanitisation import escape_nonprintable

logger = logging.getLogger(__name__)

#: Artifact written into the run output directory (consumed by the
#: report's binary section).
SWEEP_RECORD_NAME = "decomp-sweep.json"

#: Per-rule-file semgrep timeout over the whole tree. Lower and a
#: large tree (the emitter allows up to 256 MiB) times out its rules
#: into recorded errors; higher and a pathological rule can hold the
#: post-loop phase for most of an hour per rule. 600s matches the
#: order of the pre-scan's whole-target pass (900s) while keeping the
#: capped worst case (32 rules) bounded.
TREE_SWEEP_TIMEOUT_S = 600

#: Rule-file cap per sweep. Lower and legitimately marked decomp-safe
#: rules are silently left out of the sweep; higher and the bounded
#: worst-case wall time above stops being bounded. The curated
#: decompiler corpus is 5 files today — 32 leaves ample opt-in room
#: and the overflow is recorded in the sweep artifact, never silent.
MAX_RULE_FILES = 32

#: Per-finding record cap in the sweep artifact. Lower and a normal
#: noisy tree loses record detail (counts are still exact); higher
#: and a hostile binary that decompiles into rule-bait inflates the
#: run directory through this artifact. Overflow keeps exact COUNTS
#: and sets ``records_truncated``.
MAX_RECORDS = 2000

#: Journal echo-row cap per sweep. Lower and cross-layer visibility
#: of a legitimately match-heavy binary suffers (the artifact still
#: holds every record up to MAX_RECORDS); higher and a hostile
#: decompilation floods the durable journal with rows every reader
#: must walk forever after. Overflow is recorded in the artifact.
MAX_JOURNAL_ROWS = 200

#: Quoted-match-text clip (post-escape). Matches the report layer's
#: per-line bound; the full match lives in the tree file itself.
MAX_MESSAGE_CHARS = 300


def _esc(text: object, limit: int = MAX_MESSAGE_CHARS) -> str:
    """Escape-at-capture + clip for target-derived text."""
    s = escape_nonprintable(str(text or ""))
    return s if len(s) <= limit else s[:limit] + "…"


@dataclass
class _SidecarIndex:
    """Interval index over a loaded decomp-map sidecar."""

    binary_path: str = ""
    #: file name → [(start_line, end_line, entry), ...]
    by_file: dict[str, list[tuple[int, int, dict]]] = field(
        default_factory=dict)

    @classmethod
    def load(cls, tree_root: Path) -> "_SidecarIndex | None":
        from core.json import load_json
        from core.json.utils import RE_DATABASE_MAX_BYTES
        from packages.ghidra.decomp_tree import SIDECAR_NAME
        path = Path(tree_root) / SIDECAR_NAME
        if not path.is_file():
            return None
        try:
            data = load_json(path, max_bytes=RE_DATABASE_MAX_BYTES)
        except Exception:  # noqa: BLE001 — corrupt sidecar = no index
            logger.warning("decomp-sweep: unreadable sidecar %s", path,
                           exc_info=True)
            return None
        if not isinstance(data, dict):
            return None
        files = data.get("files")
        if not isinstance(files, dict):
            return None
        idx = cls(binary_path=str(data.get("binary_path") or ""))
        for fname, entries in files.items():
            if not isinstance(entries, list):
                continue
            spans = []
            for e in entries:
                if not isinstance(e, dict):
                    continue
                start, end = e.get("start_line"), e.get("end_line")
                if isinstance(start, int) and isinstance(end, int):
                    spans.append((start, end, e))
            idx.by_file[str(fname)] = spans
        return idx

    def resolve(self, file: str, line: int) -> dict | None:
        for start, end, entry in self.by_file.get(Path(file).name, []):
            if isinstance(line, int) and start <= line <= end:
                return entry
        return None


def build_finding_record(
    *,
    binary_file_key: str,
    entry: dict,
    rule_id: str,
    tree_file: str,
    line: int,
    message: str,
    match_count: int = 1,
    confidence: str = DECOMP_EVIDENCE_MAX_CONFIDENCE,
) -> dict[str, Any]:
    """One mapped per-finding record for the sweep artifact.

    ``confidence`` always passes through the shared decomp ceiling
    clamp — a caller proposing a grade above the ceiling gets the
    ceiling back (the study's discipline extended to sweep findings;
    removal of this clamp fails the cap test). ``message`` is quoted
    decomp-derived text: escaped at capture, clipped, and stamped
    ``derived_from_target``.
    """
    record: dict[str, Any] = {
        "file": binary_file_key,
        "function": _esc(entry.get("function"), 200),
        "address": entry.get("address")
        if isinstance(entry.get("address"), int) else None,
        "rule_id": _esc(rule_id, 200),
        "tree_file": _esc(tree_file, 200),
        "line": line if isinstance(line, int) else 0,
        "message": _esc(message),
        "derived_from_target": True,
        "confidence": clamp_decomp_confidence(confidence),
        "tags": [DECOMP_EVIDENCE_TAG],
        "match_count": match_count,
    }
    fid = entry.get("fid")
    if isinstance(fid, str) and fid:
        record["fid"] = _esc(fid, 100)
    return record


def _select_rules() -> list[Path]:
    """Curated decompiler corpus + decomp-safe curated opt-ins.

    Reuses the per-hypothesis lane's selection widened to tree scope
    (extend, never twin): the decompiler corpus resolves through
    :func:`~core.audit.binary_verification.decompiler_rules_for_tree`
    and the opt-ins through the sweep engine's header-marker
    machinery. Deterministic order; capped at :data:`MAX_RULE_FILES`
    (overflow is the caller's to record).
    """
    from .binary_verification import decompiler_rules_for_tree
    from .sweep import decomp_safe_curated_rules
    rules: list[Path] = list(decompiler_rules_for_tree())
    seen = {str(r) for r in rules}
    for extra in decomp_safe_curated_rules():
        if str(extra) not in seen:
            seen.add(str(extra))
            rules.append(extra)
    return rules


def _binary_gaps(gaps: list[dict] | None) -> list[dict]:
    return [
        g for g in (gaps or [])
        if isinstance(g, dict)
        and str(g.get("file") or "").startswith(BINARY_PATH_PREFIX)
    ]


def _gap_name_joins(
    binary_gaps: list[dict],
) -> tuple[dict[int, str], set[str]]:
    """(address → checklist name, set of checklist names) for the join.

    Checklist items keep their collision-suffixed names (``name@0x..``)
    — journal rows must land on the SAME keys the review loop used, so
    the address join takes precedence over the bare sidecar name.
    """
    by_addr: dict[int, str] = {}
    names: set[str] = set()
    for g in binary_gaps:
        name = str(g.get("name") or "")
        if not name:
            continue
        names.add(name)
        addr = g.get("address")
        if addr is None:
            addr = (g.get("metadata") or {}).get("address") \
                if isinstance(g.get("metadata"), dict) else None
        if isinstance(addr, int) and not isinstance(addr, bool):
            by_addr.setdefault(addr, name)
    return by_addr, names


def _journal_function_name(
    entry: dict,
    by_addr: dict[int, str],
    names: set[str],
) -> tuple[str, bool]:
    """(journal function name, matched-a-checklist-item)."""
    addr = entry.get("address")
    if isinstance(addr, int) and addr in by_addr:
        return by_addr[addr], True
    func = str(entry.get("function") or "")
    if func in names:
        return func, True
    if isinstance(addr, int) and f"{func}@{hex(addr)}" in names:
        return f"{func}@{hex(addr)}", True
    return func, False


def _append_journal_row(
    *,
    out_dir: Path,
    target_path: Path,
    run_id: str,
    binary_file_key: str,
    function_name: str,
    record: dict[str, Any],
) -> bool:
    """One ``[mechanical]`` echo row carrying the semgrep receipt.

    Same row kind as the orchestrator's post-loop pattern checks
    (``is_mechanical_echo`` consumers treat it as cross-layer
    visibility, never as a review): status ``suspicious`` — a pattern
    match on decompilation is a detection-tier lead, never a
    promotion — with the tool receipt in ``evidence_tools`` and the
    ceiling/tag stated in the body.
    """
    try:
        from .collector import append_journal_for_outcome

        class _SweepOutcome:
            file: str
            function: str
            status: str
            body: str
            model: "str | None"
            hypothesis: "str | None"
            hypotheses: "list | None"
            evidence_tool: str
            tools_dispatched: "set[str] | None"
            review_result: "dict | None"
            cost_usd: "float | None"
            duration_s: "float | None"

        o = _SweepOutcome()
        o.file = binary_file_key
        o.function = function_name
        o.status = "suspicious"
        addr = record.get("address")
        fid = record.get("fid")
        loc = f" @ {hex(addr)}" if isinstance(addr, int) else ""
        fid_part = f" (fid {fid})" if fid else ""
        o.body = (
            f"[mechanical] decomp-sweep: semgrep {record['rule_id']} "
            f"matched in decompilation of {record['function']}{loc}"
            f"{fid_part} — {DECOMP_EVIDENCE_TAG}, confidence capped at "
            f"{DECOMP_EVIDENCE_MAX_CONFIDENCE}: {record['message']}"
        )
        o.model = None
        o.hypothesis = None
        o.hypotheses = None
        # Genuine mechanical receipt (this module ran the tool), not
        # an LLM claim — same trust class as the sweep engine's own
        # stamps.
        o.evidence_tool = f"semgrep:{record['rule_id']}"
        o.tools_dispatched = {"semgrep"}
        o.review_result = None
        o.cost_usd = None
        o.duration_s = None
        append_journal_for_outcome(
            out_dir=out_dir,
            target_path=target_path,
            run_id=run_id,
            outcome=o,
            gap={
                "line_start": 0,
                "strategies": ["post-loop-mechanical", "decomp-sweep"],
            },
            checked_by=["audit:decomp-sweep"],
        )
        return True
    except Exception:
        logger.debug(
            "decomp-sweep: journal append failed for %s:%s",
            binary_file_key, function_name, exc_info=True,
        )
        return False


def _skip(out_dir: Path | None, reason: str) -> dict[str, Any]:
    """Loud skip: warn AND persist the reason — never a silent no-sweep."""
    logger.warning("decomp-sweep skipped: %s", _esc(reason, 500))
    record = {
        "schema": 1,
        "skipped": True,
        "skip_reason": _esc(reason, 500),
    }
    _write_record(out_dir, record)
    return record


def _write_record(out_dir: Path | None, record: dict[str, Any]) -> None:
    if out_dir is None:
        return
    try:
        from core.json import save_json
        from core.coverage.journal import now_iso
        record.setdefault("generated_at", now_iso())
        save_json(Path(out_dir) / SWEEP_RECORD_NAME, record)
    except Exception:
        logger.warning("decomp-sweep: record write failed", exc_info=True)


def _sidecar_key(idx: "_SidecarIndex") -> str | None:
    """The checklist file key a sidecar's recorded identity maps to,
    or ``None`` when the sidecar recorded no binary path (identity
    unknown — never treated as a match)."""
    if not idx.binary_path:
        return None
    return binary_path_key(Path(idx.binary_path))


def _locate_or_build_tree(
    target_path: Path,
    out_dir: Path,
    expected_keys: set[str],
) -> "tuple[_SidecarIndex | None, Path | None, str]":
    """(sidecar index, tree root, failure reason) — identity-gated.

    Reuses the decomp-tree convention binary ``--study`` established
    (``<out_dir>/decomp-tree`` + ``decomp-map.json``); builds it from
    the run's re-database via the existing
    :func:`core.audit.binary_context.find_redb` /
    :func:`~core.audit.binary_context.load_redb` +
    :func:`packages.ghidra.decomp_tree.write_decomp_tree` machinery
    when absent.

    Identity discipline (*expected_keys* = the run's binary checklist
    ``binary:<stem>`` file keys): the EXISTING tree's sidecar, the
    re-database a rebuild would consume, AND the freshly rebuilt
    tree's sidecar must each name one of this run's binaries — with a
    content-hash gate on the database when the target is the real
    binary file (the checklist-builder's cached-database discipline).
    Any mismatch is a loud recorded refusal: a foreign binary's
    decompilation must never be swept into THIS target's journal
    (bare-address collisions would land its findings under this
    run's checklist names).
    """
    import packages.ghidra.decomp_tree as _dt

    from .binary_context import find_redb, load_redb

    root = Path(out_dir) / "decomp-tree"
    # (1) Existing tree: accepted only when its sidecar records a
    # binary whose checklist key is one of THIS run's binary gap
    # keys — exact for every target spelling (raw binary, .gpr, run
    # dir; a stem-vs-target-stem compare falsely rebuilt on .gpr
    # targets and falsely accepted same-stem foreign trees). An
    # EMPTY recorded binary_path is identity-unknown and is never
    # accepted — it falls through to the gated rebuild.
    if (root / _dt.SIDECAR_NAME).is_file():
        idx = _SidecarIndex.load(root)
        if idx is not None:
            key = _sidecar_key(idx)
            if key is not None and key in expected_keys:
                return idx, root, ""
            logger.warning(
                "decomp-sweep: existing decomp-tree records identity "
                "%s — not one of this run's binary checklist keys; "
                "rebuilding from the run's re-database",
                _esc(key or "(none)", 120),
            )

    redb_path = find_redb(out_dir, target_path)
    if redb_path is None:
        return None, None, (
            "no decomp-tree and no re-database for this run — import "
            "the binary first (raptor-ghidra import --decompile-all, "
            "raptor-ghidra attach, or a binary --study pass) and "
            "re-run the audit"
        )
    try:
        db = load_redb(redb_path)
    except (OSError, ValueError, KeyError) as exc:
        return None, None, (
            f"re-database at {redb_path} unreadable "
            f"({_esc(exc, 200)}) — decomp-tree sweep cannot run"
        )
    # (2a) Identity gate, exact: the database's own binary key must
    # be one of the run's binary checklist keys. find_redb also
    # searches the PARENT directory (shared pipeline dirs), so a
    # foreign binary's cached database can be the first hit — swept,
    # a bare-address collision would journal a foreign binary's
    # finding under THIS target's checklist name.
    db_key = binary_path_key(Path(db.binary_path)) \
        if db.binary_path else None
    if db_key is None or db_key not in expected_keys:
        return None, None, (
            f"re-database at {redb_path} was built for "
            f"{_esc(db_key or 'an unrecorded binary', 120)} — not one "
            "of this run's binary checklist keys; refusing to sweep a "
            "foreign binary's decompilation"
        )
    # (2b) Identity gate, content: when the audit target is the real
    # binary file and the database carries a content stamp, they must
    # agree — the checklist-builder's cached-database discipline; a
    # same-stem foreign file must not pass on its name.
    tp = Path(target_path)
    if tp.is_file() and tp.suffix != ".gpr":
        stamped = (db.metadata or {}).get("binary_sha256")
        if stamped:
            from core.hash import sha256_file
            if stamped != sha256_file(tp):
                return None, None, (
                    f"re-database at {redb_path} is stamped with a "
                    "different binary's sha256 — refusing to sweep a "
                    "foreign binary's decompilation"
                )
    try:
        # Module-attribute call so tests can observe/stub the build.
        _dt.write_decomp_tree(db, root)
    except Exception as exc:  # noqa: BLE001 — build failure is a loud skip
        return None, None, (
            f"decomp-tree build failed ({_esc(exc, 200)}) — "
            "decomp-tree sweep cannot run"
        )
    # (3) Rebuilt-tree recheck: the freshly emitted sidecar must carry
    # the verified identity — an emitter that recorded a different or
    # empty key is refused, never swept on the strength of gate (2).
    idx = _SidecarIndex.load(root)
    if idx is None:
        return None, None, (
            f"rebuilt decomp-tree at {root} has no readable decomp-map "
            "sidecar — findings could not be mapped back to functions"
        )
    key = _sidecar_key(idx)
    if key is None or key not in expected_keys:
        return None, None, (
            "rebuilt decomp-tree records identity "
            f"{_esc(key or '(none)', 120)} — not one of this run's "
            "binary checklist keys; refusing to sweep"
        )
    return idx, root, ""


def run_decomp_tree_sweep(
    *,
    target_path: Path,
    out_dir: Path | None,
    gaps: list[dict] | None = None,
    run_id: str = "",
    run_rule_fn: Any = None,
) -> dict[str, Any] | None:
    """Run the tree-wide decompiler Semgrep sweep for a binary run.

    Returns the sweep record (also persisted as ``decomp-sweep.json``
    in *out_dir*), or ``None`` when the run has no binary checklist
    items — source-only runs are out of scope, not skipped. A binary
    run that CANNOT sweep (no tree and no re-database, an identity-
    gate refusal on a foreign tree/database, semgrep or its sandbox
    unavailable, no rules) produces a loud skip record.

    ``run_rule_fn`` is test injection (same convention as
    :mod:`core.audit.pre_scan`); production always resolves to
    :func:`packages.semgrep.runner.run_rule`, whose default execution
    path is sandboxed — see the module docstring for why that is a
    hard requirement here, not hygiene.
    """
    binary_gaps = _binary_gaps(gaps)
    if not binary_gaps:
        return None
    if out_dir is None:
        return _skip(None, "run has no output directory")

    try:
        from packages.semgrep.runner import is_available, run_rule
    except ImportError:
        return _skip(out_dir, "semgrep runner unavailable")
    if run_rule_fn is None:
        if not is_available():
            return _skip(out_dir, "semgrep not installed")
        run_rule_fn = run_rule

    # The run's binary checklist keys — the identity vocabulary every
    # tree/database candidate is gated against (see
    # :func:`_locate_or_build_tree`).
    expected_keys = {str(g.get("file")) for g in binary_gaps}
    sidecar, tree_root, fail_reason = _locate_or_build_tree(
        Path(target_path), Path(out_dir), expected_keys)
    if sidecar is None or tree_root is None:
        return _skip(out_dir, fail_reason)

    rules = _select_rules()
    rules_overflow = 0
    if len(rules) > MAX_RULE_FILES:
        rules_overflow = len(rules) - MAX_RULE_FILES
        rules = rules[:MAX_RULE_FILES]
    if not rules:
        return _skip(out_dir, "no decompiler-tolerant rules available")

    # Identity-gated above: the sidecar key is guaranteed to be one of
    # the run's binary checklist keys (the target_path fallback is
    # unreachable belt-and-braces).
    binary_file_key = _sidecar_key(sidecar) \
        or binary_path_key(Path(target_path))
    by_addr, gap_names = _gap_name_joins(binary_gaps)

    findings_total = 0
    rules_errored: dict[str, str] = {}
    # (function, rule_id) → record, aggregated so one noisy rule on
    # one function is one journal row with a match count.
    mapped: dict[tuple[str, str], dict[str, Any]] = {}
    unmapped_records: list[dict[str, Any]] = []
    unmapped_count = 0
    checklist_misses = 0

    for rule_path in rules:
        rule_name = Path(str(rule_path)).name
        try:
            # Default-sandboxed invocation (see module docstring):
            # the runner's trusted-input opt-out kwarg is never
            # passed — the tree content is attacker-shaped pseudo-C
            # regardless of where it lives.
            result = run_rule_fn(
                tree_root, str(rule_path), timeout=TREE_SWEEP_TIMEOUT_S,
            )
        except Exception as exc:  # noqa: BLE001 — one rule must not kill the sweep
            rules_errored[rule_name] = _esc(exc, 300)
            continue
        errors = list(getattr(result, "errors", None) or [])
        rc = getattr(result, "returncode", 0)
        if errors or rc not in (0, 1):
            rules_errored[rule_name] = _esc(
                errors[0] if errors else f"semgrep exited with code {rc}",
                300,
            )
            continue
        for f in getattr(result, "findings", None) or []:
            f_file = getattr(f, "file", "") or ""
            f_line = getattr(f, "line", 0) or 0
            f_rule = getattr(f, "rule_id", "") or rule_name
            f_msg = getattr(f, "message", "") or ""
            findings_total += 1
            entry = sidecar.resolve(f_file, f_line)
            if entry is None:
                unmapped_count += 1
                if len(unmapped_records) < MAX_RECORDS:
                    unmapped_records.append({
                        "tree_file": _esc(Path(f_file).name, 200),
                        "line": f_line,
                        "rule_id": _esc(f_rule, 200),
                        "message": _esc(f_msg),
                        "derived_from_target": True,
                        "reason": "no decomp-map entry covers this line",
                    })
                continue
            jname, matched = _journal_function_name(
                entry, by_addr, gap_names)
            if not matched:
                checklist_misses += 1
            key = (jname or str(entry.get("function") or ""), f_rule)
            if key in mapped:
                mapped[key]["match_count"] += 1
                continue
            record = build_finding_record(
                binary_file_key=binary_file_key,
                entry=entry,
                rule_id=f_rule,
                tree_file=Path(f_file).name,
                line=f_line,
                message=f_msg,
            )
            record["checklist_match"] = matched
            mapped[key] = record

    journal_rows = 0
    journal_capped = False
    for key, record in mapped.items():
        if journal_rows >= MAX_JOURNAL_ROWS:
            journal_capped = True
            break
        if _append_journal_row(
            out_dir=Path(out_dir),
            target_path=Path(target_path),
            run_id=run_id,
            binary_file_key=binary_file_key,
            function_name=key[0],
            record=record,
        ):
            journal_rows += 1

    records = list(mapped.values())
    records_truncated = len(records) > MAX_RECORDS
    sweep_record: dict[str, Any] = {
        "schema": 1,
        "skipped": False,
        "tree_root": str(tree_root),
        "binary_file_key": binary_file_key,
        "rules_run": [Path(str(r)).name for r in rules],
        "rules_errored": rules_errored,
        "rules_overflow": rules_overflow,
        "findings_total": findings_total,
        "mapped": len(records),
        "unmapped": unmapped_count,
        "checklist_misses": checklist_misses,
        "journal_rows": journal_rows,
        "journal_rows_capped": journal_capped,
        "records": records[:MAX_RECORDS],
        "records_truncated": records_truncated,
        "unmapped_records": unmapped_records,
        "unmapped_truncated": unmapped_count > len(unmapped_records),
    }
    _write_record(out_dir, sweep_record)
    logger.info(
        "decomp-sweep: %d rule file(s), %d match(es) — %d mapped to "
        "functions (%d journal row(s)), %d unmapped (recorded)",
        len(rules), findings_total, len(records), journal_rows,
        unmapped_count,
    )
    return sweep_record
