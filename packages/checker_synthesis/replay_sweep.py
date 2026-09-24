"""Cross-target replay sweep of proven rules — zero-LLM variant hunting.

/agentic and /audit replay library rules against the ONE target of the
current run. This module sweeps the proven-rule corpus across MANY
targets in a single invocation (poor-man's multi-repo variant
analysis): every replay-worthy RuleLibrary entry (and optionally the
graduated engine-rules directory) runs against every given target via
the sandboxed engine runners. No LLM is called anywhere on this path.

Engine coverage:

* semgrep — every replayable library rule, any target.
* coccinelle — replayable library rules, C targets only (spatch parses
  C; targets without ``.c``/``.h`` sources are skipped per rule set).
* codeql — the RuleLibrary cannot currently hold ``engine="codeql"``
  entries (checker synthesis promotes semgrep/coccinelle only), so
  there is nothing to replay; entries with an unrecognised engine are
  counted and reported, never silently dropped. When codeql-engine
  entries exist some day, the sweep must query the database cache
  (packages/codeql/database_manager) and run against CACHED databases
  only — a sweep must never trigger new database builds.

Library API only: the raptor-variant-sweep CLI that used to front
this module was removed as an undiscoverable orphan; run_sweep /
write_report are the supported entry points for future wiring.

Feedback: matches are recorded back into the library via
``RuleLibrary.update`` with an EMPTY triage list — that records target
coverage and match counts while leaving ``tp_rate`` untouched
(``TargetRecord.tp_rate=None`` is excluded from the precision
aggregate). ``record_match``'s per-match TP/FP verdict is deliberately
NOT used: a mechanical sweep has no triage verdict, and recording one
would corrupt the precision the replay gate is built on.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.atomic_fs import write_text_atomically
from core.json import save_json
from packages.coccinelle import runner as cocci_runner
from packages.semgrep import runner as semgrep_runner

from .library import (
    _MIN_TARGETS_FOR_REPLAY,
    _REPLAY_TP_THRESHOLD,
    LibraryEntry,
    RuleLibrary,
    graduated_stem,
    rule_join_key,
)
from .models import Match

logger = logging.getLogger(__name__)

# Per-rule per-target match cap, aligned with checker synthesis's
# "rule too loose" threshold (synthesise._RULE_TOO_LOOSE_THRESHOLD):
# a rule producing this many hits on one target is telling us about
# itself, not the target. Capped drops are counted loudly.
MATCH_CAP = 200

_C_EXTENSIONS = (".c", ".h")


@dataclass
class SweepMatch:
    """One cross-target hit from replaying a proven rule."""

    rule_id: str
    engine: str
    cwe: str
    target: str
    file: str
    line: int
    message: str
    provenance: str  # "rule-library" | "graduated"
    tier: str  # library entry rule tier context for ranking
    tp_rate: float | None
    targets_tested: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SweepReport:
    """Aggregate result of one sweep invocation."""

    targets: list[str] = field(default_factory=list)
    rules_semgrep: int = 0
    rules_coccinelle: int = 0
    rules_graduated: int = 0
    rules_skipped_unsupported_engine: list[str] = field(default_factory=list)
    matches: list[SweepMatch] = field(default_factory=list)
    capped: dict[str, int] = field(default_factory=dict)  # "rule@target" -> dropped
    errors: list[str] = field(default_factory=list)
    # "rule@target" keys whose engine run ERRORED but still produced
    # matches — the matches are reported (flagged partial here), only
    # the coverage recording is skipped.
    partial: list[str] = field(default_factory=list)
    cocci_skipped_targets: list[str] = field(default_factory=list)
    recorded_updates: int = 0

    def summary_dict(self) -> dict[str, Any]:
        return {
            "targets": self.targets,
            "rules_semgrep": self.rules_semgrep,
            "rules_coccinelle": self.rules_coccinelle,
            "rules_graduated": self.rules_graduated,
            "rules_skipped_unsupported_engine":
                self.rules_skipped_unsupported_engine,
            "total_matches": len(self.matches),
            "capped": self.capped,
            "errors": self.errors,
            "partial": self.partial,
            "cocci_skipped_targets": self.cocci_skipped_targets,
            "recorded_updates": self.recorded_updates,
        }


def replayable_entries(
    lib: RuleLibrary,
) -> tuple[list[LibraryEntry], list[LibraryEntry], list[str]]:
    """Partition replay-worthy entries by engine.

    Applies the same gates as ``RuleLibrary.find_replayable`` (TP rate,
    targets tested, dual control — the module constants are imported so
    the gates cannot drift) but across ALL CWEs, since a sweep replays
    the whole proven corpus rather than answering one CWE query.

    Returns (semgrep_entries, cocci_entries, unsupported_engine_ids).
    """
    semgrep_entries: list[LibraryEntry] = []
    cocci_entries: list[LibraryEntry] = []
    unsupported: list[str] = []
    for e in lib.active_entries():
        if e.tp_rate < _REPLAY_TP_THRESHOLD:
            continue
        if len(e.targets) < _MIN_TARGETS_FOR_REPLAY:
            continue
        if not e.dual_control:
            continue
        # Same doctrine as graduate()/find_replayable: replay treats
        # the rule as proven, and only the full mechanical-control
        # tier (fix-mutant included) earns that.
        if e.rule_tier != "library":
            continue
        if e.engine == "semgrep":
            semgrep_entries.append(e)
        elif e.engine == "coccinelle":
            cocci_entries.append(e)
        else:
            unsupported.append(f"{e.rule_id} (engine={e.engine})")
    key = lambda e: (e.tp_rate, len(e.targets))  # noqa: E731
    semgrep_entries.sort(key=key, reverse=True)
    cocci_entries.sort(key=key, reverse=True)
    return semgrep_entries, cocci_entries, unsupported


def target_has_c_sources(target: Path) -> bool:
    """True when the target tree contains at least one C source/header."""
    if target.is_file():
        return target.suffix.lower() in _C_EXTENSIONS
    for p in target.rglob("*"):
        if p.is_file() and p.suffix.lower() in _C_EXTENSIONS:
            return True
    return False


def _target_hash(target: Path) -> str:
    """Target identity for library TargetRecords.

    sha256 of the RESOLVED path, 12 hex chars — resolving first means
    relative and symlinked spellings of one physical target dedup to a
    single TargetRecord. Every recorder must join on this convention:
    hashing the path as passed would mint a second TargetRecord for
    the same physical target, inflating len(entry.targets) (the
    replay-confidence sort key and the auto-archive floor) and
    targets_tested. Out-of-package recorders use the public
    :func:`target_hash_for` spelling.
    """
    return hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:12]


def target_hash_for(target: Path) -> str:
    """Public spelling of the TargetRecord identity convention (see
    :func:`_target_hash`) for out-of-package recorders — per-run
    replay recording in llm_analysis joins on the same hash."""
    return _target_hash(Path(target))


def _cap(
    report: SweepReport, rule_id: str, target: Path, hits: list,
) -> list:
    if len(hits) <= MATCH_CAP:
        return hits
    dropped = len(hits) - MATCH_CAP
    key = f"{rule_id}@{target}"
    report.capped[key] = dropped
    logger.warning(
        "variant-sweep: rule %s produced %d matches on %s — capped at "
        "%d (%d dropped); the rule is likely too loose for this target",
        rule_id, len(hits), target, MATCH_CAP, dropped,
    )
    return hits[:MATCH_CAP]


def _sweep_semgrep_rule(
    report: SweepReport,
    target: Path,
    rule_path: Path,
    *,
    rule_id: str,
    cwe: str,
    provenance: str,
    tier: str,
    tp_rate: float | None,
    targets_tested: int,
) -> tuple[list[SweepMatch], bool]:
    """Run one semgrep library rule against *target*.

    Returns ``(matches, engine_errored)``. An errored run is NOT a
    zero-match run and must never become coverage evidence (see the
    ``engine_errored`` handling in ``run_sweep``), but the matches
    the rule DID produce before/around the error (fatal per-file
    failures land in ``errors`` alongside real findings on large
    targets) are still worth reporting — they are returned flagged
    partial instead of being discarded with the failure. The error
    is recorded on ``report.errors``.
    """
    result = semgrep_runner.run_rule(target, str(rule_path), name=rule_id)
    errored = bool(result.errors)
    if errored:
        report.errors.extend(
            f"semgrep {rule_id} @ {target}: {e}" for e in result.errors
        )
        if result.findings:
            report.partial.append(f"{rule_id}@{target}")
    hits = _cap(report, rule_id, target, result.findings)
    return [
        SweepMatch(
            rule_id=rule_id,
            engine="semgrep",
            cwe=cwe,
            target=str(target),
            file=f.file,
            line=f.line,
            message=f.message,
            provenance=provenance,
            tier=tier,
            tp_rate=tp_rate,
            targets_tested=targets_tested,
        )
        for f in hits
    ], errored


def _sweep_cocci_rule(
    report: SweepReport,
    target: Path,
    rule_path: Path,
    *,
    rule_id: str,
    cwe: str,
    tp_rate: float | None,
    targets_tested: int,
    provenance: str = "rule-library",
    tier: str = "library",
) -> tuple[list[SweepMatch], bool]:
    """Coccinelle counterpart to ``_sweep_semgrep_rule`` — same
    ``(matches, engine_errored)`` contract."""
    result = cocci_runner.run_rule(target, rule_path, no_includes=True)
    errored = bool(result.errors)
    if errored:
        report.errors.extend(
            f"coccinelle {rule_id} @ {target}: {e}" for e in result.errors
        )
        if result.matches:
            report.partial.append(f"{rule_id}@{target}")
    hits = _cap(report, rule_id, target, result.matches)
    return [
        SweepMatch(
            rule_id=rule_id,
            engine="coccinelle",
            cwe=cwe,
            target=str(target),
            file=m.file,
            line=m.line,
            message=m.message,
            provenance=provenance,
            tier=tier,
            tp_rate=tp_rate,
            targets_tested=targets_tested,
        )
        for m in hits
    ], errored


def _record(
    lib: RuleLibrary,
    report: SweepReport,
    entry: LibraryEntry,
    target: Path,
    matches: list[SweepMatch],
    timestamp: str,
) -> None:
    """Record sweep matches on the library entry (coverage, not verdicts).

    Empty triage → TargetRecord.tp_rate=None → excluded from the
    precision aggregate; only match counts and target coverage accrue.
    Zero-match targets are recorded too: a target where the rule fired
    nowhere is negative evidence — skipping it would let a stale rule
    keep its precision forever (auto-archive can only trigger when the
    target list grows) and overstate per-target confidence (counting
    only hit-targets).

    Engine-ERRORED runs never reach this function: a target the
    engine could not fully scan proves nothing about coverage (same
    fail-closed stance as synthesis's fixture handling), so
    ``run_sweep`` skips this record when the runner flags
    ``engine_errored`` — the failure lives on ``report.errors`` (one
    explicit entry per rule@target) instead of becoming zero-match
    coverage that inflates targets_tested and feeds auto-archive.
    The matches such a run DID produce still flow to
    ``report.matches`` (flagged on ``report.partial``): reporting is
    not coverage, and discarding real hits over one fatal per-file
    failure silently cost every variant hit on large targets.
    """
    updated = lib.update(
        rule_join_key(entry),
        _target_hash(target),
        [Match(file=m.file, line=m.line) for m in matches],
        [],
        timestamp=timestamp,
    )
    if updated is not None:
        report.recorded_updates += 1


def _graduated_rule_files(
    engine_rules_dir: Path,
) -> tuple[list[Path], list[Path]]:
    """(semgrep_files, cocci_files) graduated into the engine rules dir.

    Graduation writes semgrep rules to ``semgrep/rules/*.y(a)ml`` AND
    coccinelle rules to ``coccinelle/*.cocci`` — both engines must
    join the sweep, otherwise graduated cocci rules would be silently
    dropped (against the never-silently-dropped stance above).
    """
    semgrep_dir = engine_rules_dir / "semgrep" / "rules"
    semgrep_files = sorted(
        p for p in semgrep_dir.iterdir()
        if p.is_file() and p.suffix in (".yaml", ".yml")
    ) if semgrep_dir.is_dir() else []
    cocci_dir = engine_rules_dir / "coccinelle"
    cocci_files = sorted(
        p for p in cocci_dir.iterdir()
        if p.is_file() and p.suffix == ".cocci"
    ) if cocci_dir.is_dir() else []
    return semgrep_files, cocci_files


def run_sweep(
    targets: list[Path],
    *,
    library_dir: Path | None = None,
    engine_rules_dir: Path | None = None,
    record: bool = True,
) -> SweepReport:
    """Replay the proven-rule corpus across *targets*."""
    lib = RuleLibrary(library_dir)
    report = SweepReport(targets=[str(t) for t in targets])
    timestamp = datetime.now(timezone.utc).isoformat()

    semgrep_entries, cocci_entries, unsupported = replayable_entries(lib)
    report.rules_semgrep = len(semgrep_entries)
    report.rules_coccinelle = len(cocci_entries)
    report.rules_skipped_unsupported_engine = unsupported
    if unsupported:
        logger.warning(
            "variant-sweep: %d library entr%s with unsupported engines "
            "skipped: %s",
            len(unsupported), "y" if len(unsupported) == 1 else "ies",
            ", ".join(unsupported),
        )

    graduated_semgrep, graduated_cocci = (
        _graduated_rule_files(engine_rules_dir)
        if engine_rules_dir is not None else ([], [])
    )
    report.rules_graduated = len(graduated_semgrep) + len(graduated_cocci)
    # Graduated files are named with graduated_stem(entry.rule_id) —
    # every join from a file stem back to the library goes through the
    # same constructor. Comparing stems against raw rule_ids silently
    # never matched ids that sanitisation changed, double-sweeping the
    # rule and recording no coverage for it. Stems shared by several
    # entries are ambiguous: resolve to None (no record, one warning)
    # rather than first-entry-wins.
    stem_to_entries: dict[str, list[LibraryEntry]] = {}
    for e in lib.all_entries():
        stem_to_entries.setdefault(graduated_stem(e.rule_id), []).append(e)

    def _entry_for_stem(stem: str) -> "LibraryEntry | None":
        candidates = stem_to_entries.get(stem, [])
        if len(candidates) > 1:
            logger.warning(
                "variant-sweep: graduated stem %r matches %d library "
                "entries — skipping coverage recording for it",
                stem, len(candidates),
            )
            return None
        return candidates[0] if candidates else None

    # Rules present BOTH as replayable library entries and as
    # graduated files (the normal case — graduation copies FROM the
    # library) run once, in the library loop. Sweeping the graduated
    # copy again duplicated every match in the report and, with
    # record=True, double-incremented total_matches via a second
    # lib.update on the same target.
    swept_library_stems = {
        graduated_stem(e.rule_id)
        for e in (*semgrep_entries, *cocci_entries)
    }

    for target in targets:
        target = Path(target)
        target_is_c = (
            target_has_c_sources(target)
            if (cocci_entries or graduated_cocci) else False
        )
        run_cocci = bool(cocci_entries) and target_is_c
        # Graduated cocci rules skip non-C targets the same way the
        # library entries do — the skip record must cover both, or a
        # graduated-only sweep under-reports its skipped targets.
        if (cocci_entries or graduated_cocci) and not target_is_c:
            report.cocci_skipped_targets.append(str(target))

        for entry in semgrep_entries:
            rule_path = lib.rule_path(entry)
            if not rule_path.exists():
                report.errors.append(
                    f"semgrep {entry.rule_id}: rule file missing "
                    f"({rule_path})"
                )
                continue
            matches, errored = _sweep_semgrep_rule(
                report, target, rule_path,
                rule_id=entry.rule_id,
                cwe=entry.cwe,
                provenance="rule-library",
                tier="library",
                tp_rate=entry.tp_rate,
                targets_tested=len(entry.targets),
            )
            report.matches.extend(matches)
            if record and not errored:
                # Errored runs are never coverage evidence — the
                # failure is on report.errors, matches flow above.
                _record(lib, report, entry, target, matches, timestamp)

        if run_cocci:
            for entry in cocci_entries:
                rule_path = lib.rule_path(entry)
                if not rule_path.exists():
                    report.errors.append(
                        f"coccinelle {entry.rule_id}: rule file missing "
                        f"({rule_path})"
                    )
                    continue
                matches, errored = _sweep_cocci_rule(
                    report, target, rule_path,
                    rule_id=entry.rule_id,
                    cwe=entry.cwe,
                    tp_rate=entry.tp_rate,
                    targets_tested=len(entry.targets),
                )
                report.matches.extend(matches)
                if record and not errored:
                    _record(lib, report, entry, target, matches, timestamp)

        for rule_file in graduated_semgrep:
            rule_id = rule_file.stem
            if rule_id in swept_library_stems:
                continue  # already ran as a library entry on this target
            entry = _entry_for_stem(rule_id)
            matches, errored = _sweep_semgrep_rule(
                report, target, rule_file,
                rule_id=rule_id,
                cwe=entry.cwe if entry else "",
                provenance="graduated",
                tier="graduated",
                tp_rate=entry.tp_rate if entry else None,
                targets_tested=len(entry.targets) if entry else 0,
            )
            report.matches.extend(matches)
            if record and not errored and entry is not None:
                _record(lib, report, entry, target, matches, timestamp)

        if target_is_c:
            for rule_file in graduated_cocci:
                rule_id = rule_file.stem
                if rule_id in swept_library_stems:
                    continue
                entry = _entry_for_stem(rule_id)
                matches, errored = _sweep_cocci_rule(
                    report, target, rule_file,
                    rule_id=rule_id,
                    cwe=entry.cwe if entry else "",
                    tp_rate=entry.tp_rate if entry else None,
                    targets_tested=len(entry.targets) if entry else 0,
                    provenance="graduated",
                    tier="graduated",
                )
                report.matches.extend(matches)
                if record and not errored and entry is not None:
                    _record(lib, report, entry, target, matches, timestamp)

    return report


def write_report(report: SweepReport, out_dir: Path) -> Path:
    """Write matches.jsonl + summary.json under *out_dir*."""
    out_dir.mkdir(parents=True, exist_ok=True)
    matches_path = out_dir / "matches.jsonl"
    # Atomic like the save_json below (planted-symlink defence at the
    # predictable artifact name in the reused out dir).
    write_text_atomically(
        matches_path,
        "".join(
            json.dumps(m.to_dict(), sort_keys=True) + "\n"
            for m in report.matches
        ),
    )
    summary_path = out_dir / "summary.json"
    save_json(summary_path, report.summary_dict(), sort_keys=True)
    return matches_path
