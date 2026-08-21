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

Feedback: matches are recorded back into the library via
``RuleLibrary.update`` with an EMPTY triage list — that records target
coverage and match counts while leaving ``tp_rate`` untouched
(``TargetRecord.tp_rate=None`` is excluded from the precision
aggregate). ``record_match``'s per-match TP/FP verdict is deliberately
NOT used: a mechanical sweep has no triage verdict, and recording one
would corrupt the precision the replay gate is built on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packages.coccinelle import runner as cocci_runner
from packages.semgrep import runner as semgrep_runner

from .library import (
    _MIN_TARGETS_FOR_REPLAY,
    _REPLAY_TP_THRESHOLD,
    LibraryEntry,
    RuleLibrary,
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

    Matches the convention in packages/llm_analysis/checker_followup.py
    (sha256 of the resolved path, 12 hex chars) so sweep records and
    per-run replay records refer to the same target the same way.
    """
    return hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:12]


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
) -> list[SweepMatch]:
    result = semgrep_runner.run_rule(target, str(rule_path), name=rule_id)
    if result.errors:
        report.errors.extend(
            f"semgrep {rule_id} @ {target}: {e}" for e in result.errors
        )
        return []
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
    ]


def _sweep_cocci_rule(
    report: SweepReport,
    target: Path,
    rule_path: Path,
    *,
    rule_id: str,
    cwe: str,
    tp_rate: float | None,
    targets_tested: int,
) -> list[SweepMatch]:
    result = cocci_runner.run_rule(target, rule_path, no_includes=True)
    if result.errors:
        report.errors.extend(
            f"coccinelle {rule_id} @ {target}: {e}" for e in result.errors
        )
        return []
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
            provenance="rule-library",
            tier="library",
            tp_rate=tp_rate,
            targets_tested=targets_tested,
        )
        for m in hits
    ]


def _record(
    lib: RuleLibrary,
    report: SweepReport,
    rule_id: str,
    target: Path,
    matches: list[SweepMatch],
    timestamp: str,
) -> None:
    """Record sweep matches on the library entry (coverage, not verdicts).

    Empty triage → TargetRecord.tp_rate=None → excluded from the
    precision aggregate; only match counts and target coverage accrue.
    """
    if not matches:
        return
    entry = lib.update(
        rule_id,
        _target_hash(target),
        [Match(file=m.file, line=m.line) for m in matches],
        [],
        timestamp=timestamp,
    )
    if entry is not None:
        report.recorded_updates += 1


def _graduated_rule_files(engine_rules_dir: Path) -> list[Path]:
    rules_dir = engine_rules_dir / "semgrep" / "rules"
    if not rules_dir.is_dir():
        return []
    return sorted(
        p for p in rules_dir.iterdir()
        if p.is_file() and p.suffix in (".yaml", ".yml")
    )


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

    graduated = (
        _graduated_rule_files(engine_rules_dir)
        if engine_rules_dir is not None else []
    )
    report.rules_graduated = len(graduated)
    library_rule_ids = {e.rule_id for e in lib.all_entries()}

    for target in targets:
        target = Path(target)
        run_cocci = bool(cocci_entries) and target_has_c_sources(target)
        if cocci_entries and not run_cocci:
            report.cocci_skipped_targets.append(str(target))

        for entry in semgrep_entries:
            rule_path = lib.rule_path(entry)
            if not rule_path.exists():
                report.errors.append(
                    f"semgrep {entry.rule_id}: rule file missing "
                    f"({rule_path})"
                )
                continue
            matches = _sweep_semgrep_rule(
                report, target, rule_path,
                rule_id=entry.rule_id,
                cwe=entry.cwe,
                provenance="rule-library",
                tier="library",
                tp_rate=entry.tp_rate,
                targets_tested=len(entry.targets),
            )
            report.matches.extend(matches)
            if record:
                _record(lib, report, entry.rule_id, target, matches,
                        timestamp)

        if run_cocci:
            for entry in cocci_entries:
                rule_path = lib.rule_path(entry)
                if not rule_path.exists():
                    report.errors.append(
                        f"coccinelle {entry.rule_id}: rule file missing "
                        f"({rule_path})"
                    )
                    continue
                matches = _sweep_cocci_rule(
                    report, target, rule_path,
                    rule_id=entry.rule_id,
                    cwe=entry.cwe,
                    tp_rate=entry.tp_rate,
                    targets_tested=len(entry.targets),
                )
                report.matches.extend(matches)
                if record:
                    _record(lib, report, entry.rule_id, target, matches,
                            timestamp)

        for rule_file in graduated:
            rule_id = rule_file.stem
            entry = next(
                (e for e in lib.all_entries() if e.rule_id == rule_id),
                None,
            )
            matches = _sweep_semgrep_rule(
                report, target, rule_file,
                rule_id=rule_id,
                cwe=entry.cwe if entry else "",
                provenance="graduated",
                tier="graduated",
                tp_rate=entry.tp_rate if entry else None,
                targets_tested=len(entry.targets) if entry else 0,
            )
            report.matches.extend(matches)
            if record and rule_id in library_rule_ids:
                _record(lib, report, rule_id, target, matches, timestamp)

    return report


def write_report(report: SweepReport, out_dir: Path) -> Path:
    """Write matches.jsonl + summary.json under *out_dir*."""
    out_dir.mkdir(parents=True, exist_ok=True)
    matches_path = out_dir / "matches.jsonl"
    with matches_path.open("w", encoding="utf-8") as f:
        for m in report.matches:
            f.write(json.dumps(m.to_dict(), sort_keys=True) + "\n")
    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps(report.summary_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return matches_path


def _print_summary(report: SweepReport) -> None:
    by_rule: dict[str, list[SweepMatch]] = {}
    for m in report.matches:
        by_rule.setdefault(m.rule_id, []).append(m)
    print(
        f"variant-sweep: {len(report.targets)} target(s), "
        f"{report.rules_semgrep} semgrep + {report.rules_coccinelle} "
        f"coccinelle library rule(s) + {report.rules_graduated} "
        f"graduated, {len(report.matches)} match(es)"
    )
    for rule_id in sorted(by_rule):
        ms = by_rule[rule_id]
        hit_targets = len({m.target for m in ms})
        first = ms[0]
        tp = f"{first.tp_rate:.0%}" if first.tp_rate is not None else "n/a"
        print(
            f"  {rule_id}  [{first.engine} {first.cwe or '-'} "
            f"{first.provenance} tp={tp}]  "
            f"{len(ms)} match(es) across {hit_targets} target(s)"
        )
    if report.capped:
        print(f"  ⚠ {len(report.capped)} rule/target pair(s) hit the "
              f"{MATCH_CAP}-match cap; see summary.json")
    if report.cocci_skipped_targets:
        print(
            "  coccinelle skipped (no C sources): "
            + ", ".join(report.cocci_skipped_targets)
        )
    if report.errors:
        print(f"  ⚠ {len(report.errors)} error(s); see summary.json")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-variant-sweep",
        description=(
            "Replay the proven rule library (and optionally graduated "
            "engine rules) across multiple targets — zero-LLM variant "
            "hunting. Matches are ranked by each rule's earned "
            "precision tier."
        ),
    )
    p.add_argument("targets", nargs="+", type=Path,
                   help="target directories/files to sweep")
    p.add_argument("--library-dir", type=Path, default=None,
                   help="rule library dir (default: out/rule-library)")
    p.add_argument("--engine-rules-dir", type=Path, default=None,
                   help=("project engine-rules dir; its "
                         "semgrep/rules/*.yaml graduated rules join "
                         "the sweep"))
    p.add_argument("--out", type=Path, default=None,
                   help=("output dir (default: "
                         "out/variant-sweep/runs/<ts>)"))
    p.add_argument("--no-record", action="store_true",
                   help=("do not record sweep matches back onto library "
                         "entries (coverage/match counts only; "
                         "precision is never touched either way)"))
    args = p.parse_args(argv)

    missing = [str(t) for t in args.targets if not Path(t).exists()]
    if missing:
        print(f"targets do not exist: {missing}", file=sys.stderr)
        return 2

    if args.out is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        args.out = Path("out/variant-sweep/runs") / ts

    report = run_sweep(
        [Path(t) for t in args.targets],
        library_dir=args.library_dir,
        engine_rules_dir=args.engine_rules_dir,
        record=not args.no_record,
    )
    matches_path = write_report(report, args.out)
    _print_summary(report)
    print(f"matches: {matches_path}")
    return 0
