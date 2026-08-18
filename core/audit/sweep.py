"""Tool-grounded sweep execution for /audit.

Wraps existing tool packages (semgrep, coccinelle) and SMT verb shims
to run a hypothesis test against a specific file/function, then logs
the result to the audit trail.  The sweep log entry is the breadcrumb
that G3 (NO-SELF-CRITIQUE) checks: re-recording a function requires a
sweep since the last record.

Uses ``packages.semgrep.runner.run_rule``,
``packages.coccinelle.runner.run_rule``, and the
``libexec/raptor-smt-*`` CLI shims.
"""

from __future__ import annotations

import contextlib
import json as _json
import logging
import os
import pickle
import re as _re
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._util import is_valid_identifier, safe_join

logger = logging.getLogger(__name__)


_ROLE_RE = _re.compile(r"^//\s*@role:\s*(\w+)", _re.MULTILINE)


def get_rule_role(rule_path: str) -> str:
    """Parse ``// @role: detection|verification`` from a rule file.

    Returns ``"detection"`` (default for stock rules without an
    annotation) or ``"verification"``.  Detection rules surface
    candidates; only verification rules may promote status directly.
    Dynamic per-hypothesis rules (not on disk) bypass this check
    entirely — the orchestrator's ``_is_detection_only`` returns
    False for files not in the stock library.
    """
    try:
        with open(rule_path) as f:
            head = f.read(2048)
        m = _ROLE_RE.search(head)
        if m:
            role = m.group(1).lower()
            if role in ("detection", "verification"):
                return role
    except OSError:
        pass
    return "detection"


_IDENTIFIER_QUALIFIED_RE = None  # lazy import


def _is_valid_qualified(name: str) -> bool:
    """Validate a potentially qualified identifier (e.g., os.system)."""
    global _IDENTIFIER_QUALIFIED_RE
    if _IDENTIFIER_QUALIFIED_RE is None:
        import re
        _IDENTIFIER_QUALIFIED_RE = re.compile(
            r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
        )
    return bool(_IDENTIFIER_QUALIFIED_RE.match(name))


@dataclass
class SarifCache:
    """Index of prior SARIF results keyed by (file, rule_id).

    Loaded once at orchestrator start from scan/*.sarif in the output
    directory. When the sweep engine wants to run semgrep on a file,
    it checks here first — a cache hit returns the pre-existing matches
    without spawning a subprocess.
    """
    _by_file: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    hit_count: int = 0
    miss_count: int = 0
    _counter_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __bool__(self) -> bool:
        return bool(self._by_file)

    def __len__(self) -> int:
        return len(self._by_file)

    def lookup(
        self, file_path: str, line_start: int = 0, line_end: int = 0,
    ) -> list[dict[str, Any]] | None:
        """Return SARIF results overlapping the given file and line range.

        Returns None on cache miss (file not in any prior SARIF).
        Returns [] if the file was scanned but had no hits in range.
        """
        normalized = _normalize_sarif_path(file_path)
        results = self._by_file.get(normalized)
        if results is None:
            with self._counter_lock:
                self.miss_count += 1
            return None

        with self._counter_lock:
            self.hit_count += 1
        if not line_start:
            return results

        return [
            r for r in results
            if _sarif_result_in_range(r, line_start, line_end)
        ]

    @classmethod
    def from_directory(cls, out_dir: Path) -> SarifCache:
        """Load all .sarif files from out_dir/scan/."""
        cache = cls()
        scan_dir = out_dir / "scan"
        if not scan_dir.is_dir():
            return cache

        for sarif_file in scan_dir.glob("*.sarif"):
            _ingest_sarif_file(cache, sarif_file)

        total = sum(len(v) for v in cache._by_file.values())
        if total:
            logger.info(
                "sarif_cache: loaded %d results across %d files",
                total, len(cache._by_file),
            )
        return cache


def _annotate_sarif_result(
    result: dict[str, Any],
    *,
    run_label: str = "",
) -> None:
    """Attach flat convenience keys + provenance to a raw SARIF result.

    The evidence formatters read ``rule_id`` / ``line``; raw SARIF
    carries ``ruleId`` and nested locations, so cache-fed hits used to
    render as "unknown at line 0". ``_sarif_cwe`` uses the existing
    rule_id→CWE inference; ``_sarif_sibling`` marks results imported
    from a prior run's SARIF.
    """
    if run_label:
        result["_sarif_sibling"] = run_label
    rule_id = result.get("ruleId") or ""
    if rule_id and not result.get("rule_id"):
        result["rule_id"] = rule_id
    locs = result.get("locations") or [{}]
    loc = locs[0] if locs else {}
    region = loc.get("physicalLocation", {}).get("region", {})
    if not result.get("line"):
        result["line"] = region.get("startLine", 0)
    msg = result.get("message")
    msg_text = msg.get("text", "") if isinstance(msg, dict) else str(msg or "")
    if isinstance(msg, dict):
        # Flatten for the evidence prose formatter (_safe_text expects
        # str; the raw SARIF message object crashed it).
        result["message"] = msg_text
    if rule_id and "_sarif_cwe" not in result:
        try:
            # The existing rule_id→CWE inference (vuln-type reverse map
            # + message patterns) — shared with the SARIF importer.
            from core.sarif.import_normalizer import _infer_cwe

            cwe = _infer_cwe(rule_id, msg_text[:500])
            if cwe:
                result["_sarif_cwe"] = cwe
        except Exception:
            logger.debug("sarif cwe inference failed", exc_info=True)


def _ingest_sarif_file(
    cache: SarifCache,
    sarif_file: Path,
    *,
    run_label: str = "",
    freshness: Callable[[str], bool] | None = None,
) -> int:
    """Parse one SARIF file into the cache. Returns results ingested.

    ``freshness`` (normalized file path → bool) gates each result:
    sibling-run imports drop results for files that changed since the
    producing scan (line drift makes stale SARIF actively harmful).
    """
    try:
        data = _json.loads(sarif_file.read_text())
    except (OSError, _json.JSONDecodeError):
        return 0
    ingested = 0
    fresh_memo: dict[str, bool] = {}
    for run in data.get("runs", []):
        tool_name = (
            run.get("tool", {}).get("driver", {}).get("name", "")
        ).lower()
        is_codeql = "codeql" in tool_name
        for result in run.get("results", []):
            locs = result.get("locations") or [{}]
            loc = locs[0] if locs else {}
            phys = loc.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            normalized = _normalize_sarif_path(uri)
            if not normalized:
                continue
            if freshness is not None:
                if normalized not in fresh_memo:
                    fresh_memo[normalized] = bool(freshness(normalized))
                if not fresh_memo[normalized]:
                    continue
            result["_sarif_source"] = "codeql" if is_codeql else "semgrep"
            _annotate_sarif_result(result, run_label=run_label)
            cache._by_file.setdefault(normalized, []).append(result)
            ingested += 1
    return ingested


# Sibling SARIF import bounds: prior runs go stale as the target
# drifts, and every extra run is more lookup noise.
SIBLING_SARIF_MAX_RUNS = 3
SIBLING_SARIF_MAX_AGE_DAYS = 30


def _load_checklist_hashes(run_dir: Path) -> dict[str, str]:
    """{relative_path: sha256} from a sibling run's checklist.json.

    Same shape understand_bridge gates on; empty when the run carries
    no checklist (plain /scan runs).
    """
    path = run_dir / "checklist.json"
    if not path.is_file():
        return {}
    try:
        checklist = _json.loads(path.read_text())
    except (OSError, _json.JSONDecodeError):
        return {}
    out: dict[str, str] = {}
    for f in checklist.get("files", []):
        if not isinstance(f, dict):
            continue
        p, sha = f.get("path"), f.get("sha256")
        if isinstance(p, str) and isinstance(sha, str) and p and sha:
            out[_normalize_sarif_path(p)] = sha
    return out


def _sibling_freshness_gate(
    target_path: Path,
    recorded_hashes: dict[str, str],
    sarif_mtime: float,
    disk_hash_cache: dict[str, str | None],
) -> Callable[[str], bool]:
    """Per-file freshness check for one sibling SARIF artifact.

    Hash-gated when the producing run recorded per-file SHA-256
    (checklist.json, understand_bridge's pattern); mtime-gated
    otherwise (target file unchanged since the SARIF was written).
    Paths escaping the target are never fresh.
    """
    target_resolved = Path(target_path).resolve()

    def _fresh(normalized: str) -> bool:
        full = target_resolved / normalized
        try:
            full.resolve().relative_to(target_resolved)
        except (ValueError, OSError):
            return False
        recorded = recorded_hashes.get(normalized)
        if recorded:
            if normalized not in disk_hash_cache:
                try:
                    from core.hash import sha256_file

                    disk_hash_cache[normalized] = sha256_file(full)
                except Exception:
                    logger.debug(
                        "hash for %s failed", normalized, exc_info=True,
                    )
                    disk_hash_cache[normalized] = None
            return disk_hash_cache[normalized] == recorded
        try:
            return full.stat().st_mtime <= sarif_mtime
        except OSError:
            return False

    return _fresh


def import_sibling_sarif(
    cache: SarifCache,
    out_dir: Path,
    target_path: Path,
    *,
    max_runs: int = SIBLING_SARIF_MAX_RUNS,
    max_age_days: int = SIBLING_SARIF_MAX_AGE_DAYS,
    now: float | None = None,
) -> int:
    """Merge prior scan runs' SARIF into the cache, freshness-gated.

    In project mode every command gets its own run dir, so /audit
    never saw the SARIF a prior /scan or /agentic run produced.
    Discovers sibling run dirs for the same target (the
    ``sibling_run_dirs`` lookup already used for coverage artifacts),
    reads SARIF from both layouts (``<run>/scan/*.sarif`` for
    /agentic, ``<run>/*.sarif`` top-level for /scan), bounded by age
    and run count, newest runs first. Every result is freshness-gated
    per file. Returns the number of results imported.
    """
    import time as _time

    from .joern_backend import sibling_run_dirs

    siblings = sibling_run_dirs(out_dir, target_path=target_path)
    if not siblings:
        return 0
    now = now if now is not None else _time.time()

    candidates: list[tuple[float, Path, list[Path]]] = []
    for d in siblings:
        run_dir = Path(d)
        files: list[Path] = []
        scan_dir = run_dir / "scan"
        if scan_dir.is_dir():
            files.extend(sorted(scan_dir.glob("*.sarif")))
        files.extend(sorted(run_dir.glob("*.sarif")))
        if not files:
            continue
        try:
            newest = max(f.stat().st_mtime for f in files)
        except OSError:
            continue
        if now - newest > max_age_days * 86400:
            continue
        candidates.append((newest, run_dir, files))

    candidates.sort(key=lambda t: t[0], reverse=True)

    imported = 0
    disk_hash_cache: dict[str, str | None] = {}
    for _newest, run_dir, files in candidates[:max_runs]:
        recorded_hashes = _load_checklist_hashes(run_dir)
        for sarif_file in files:
            try:
                sarif_mtime = sarif_file.stat().st_mtime
            except OSError:
                continue
            gate = _sibling_freshness_gate(
                target_path, recorded_hashes, sarif_mtime,
                disk_hash_cache,
            )
            imported += _ingest_sarif_file(
                cache,
                sarif_file,
                run_label=run_dir.name,
                freshness=gate,
            )
    return imported


def _normalize_sarif_path(uri_or_path: str) -> str:
    """Normalize a SARIF artifact URI or file path to a stable key.

    Strips leading ``file://`` and ``./`` prefixes, collapses to a
    forward-slash-separated relative path so that lookup keys match
    insertion keys regardless of how the caller spells the path.
    """
    p = uri_or_path
    p = p.removeprefix("file://")
    p = p.lstrip("/")
    p = p.removeprefix("./")
    return p.replace("\\", "/")


def _sarif_result_in_range(
    result: dict[str, Any], line_start: int, line_end: int,
) -> bool:
    locs = result.get("locations") or [{}]
    loc = locs[0] if locs else {}
    region = loc.get("physicalLocation", {}).get("region", {})
    rline = region.get("startLine", 0)
    if not rline:
        return True
    if line_end:
        return line_start <= rline <= line_end
    return rline >= line_start


def _match_in_range(
    match: dict[str, Any], line_start: int, line_end: int,
) -> bool:
    """Return True if a match dict falls within the function line range.

    A match with no line information (coccinelle sometimes reports
    line 0) cannot be placed inside the function: counting it as
    in-range confirmed hypotheses from matches anywhere in the file,
    while the semgrep path dropped the same shape. One policy for
    both: unplaceable matches are NOT in range.
    """
    match_line = match.get("line", 0)
    if not match_line:
        return False
    return line_start <= match_line <= line_end


def _check_path_containment(
    target_path: Path, file_path: str, tool: str,
) -> SweepResult | None:
    """Return an error SweepResult if file_path escapes target_path."""
    if safe_join(target_path, file_path) is None:
        return SweepResult(
            tool=tool,
            file_path=file_path,
            function_name="",
            outcome="error",
            errors=[f"path escapes target: {file_path}"],
        )
    return None


@dataclass
class SweepResult:
    tool: str
    file_path: str
    function_name: str
    outcome: str  # confirmed | refuted | error | inconclusive
    matches: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rule_id: str | None = None
    raw_output: str | None = None
    details: dict[str, Any] | None = None

    def to_log_entry(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "action": "sweep",
            "key": f"{self.file_path}:{self.function_name}",
            "file": self.file_path,
            "function": self.function_name,
            "tool": self.tool,
            "outcome": self.outcome,
        }
        if self.rule_id:
            entry["rule_id"] = self.rule_id
        if self.matches:
            entry["match_count"] = len(self.matches)
        if self.errors:
            entry["errors"] = self.errors
        if self.details and self.details.get("reason"):
            entry["reason"] = self.details["reason"]
        return entry


def run_semgrep_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    rule_config: str,
    line_start: int = 0,
    line_end: int = 0,
    hypothesis: str = "",
    rule_keyword: str = "",
) -> SweepResult:
    """Run a semgrep rule against a single file and classify matches.

    Args:
        target_path: Root of the target codebase.
        file_path: Relative path to the source file.
        function_name: Function being audited (for match filtering).
        rule_config: Semgrep config — can be a .yaml path, rule pack, or
            inline rule written to a temp file by the caller.
        line_start: Function start line (for filtering matches to function).
        line_end: Function end line.
        hypothesis: For dynamic per-hypothesis rules: the hypothesis text.
            When it names concrete identifiers, a match may only confirm
            if its ±2-line window mentions one of them.
        rule_keyword: For dynamic per-hypothesis rules: the keyword that
            selected the pattern (from hypothesis_to_semgrep_rule_keyed).
            Enables the negative-control check — a rule that also matches
            the keyword's guarded fixture is a presence detector and is
            capped at "inconclusive".

    Returns:
        SweepResult with outcome and matches.
    """
    escape = _check_path_containment(target_path, file_path, "semgrep")
    if escape:
        return escape

    full_path = target_path / file_path
    if not full_path.exists():
        return SweepResult(
            tool="semgrep",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"file not found: {full_path}"],
        )

    try:
        from packages.semgrep.runner import is_available, run_rule

        if not is_available():
            return SweepResult(
                tool="semgrep",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=["semgrep not installed"],
            )

        result = run_rule(full_path, rule_config, timeout=120)

        in_function = []
        for finding in result.findings:
            if hasattr(finding, "line"):
                finding_line = finding.line
            elif isinstance(finding, dict):
                finding_line = finding.get("start", {}).get("line", 0)
            else:
                finding_line = 0
            if line_start and line_end:
                if line_start <= finding_line <= line_end:
                    in_function.append(finding)
            else:
                in_function.append(finding)

        capped_reason: str | None = None
        if in_function and hypothesis:
            named = _hypothesis_identifiers(hypothesis)
            if named:
                consistent = _filter_identifier_consistent(
                    in_function, full_path, named,
                )
                if consistent:
                    in_function = consistent
                else:
                    capped_reason = (
                        "identifier mismatch: no match line (±2) mentions "
                        "any identifier named by the hypothesis ("
                        + ", ".join(sorted(named)[:5]) + ")"
                    )

        if (
            in_function and capped_reason is None and rule_keyword
            and _rule_matches_negative_control(
                rule_config, rule_keyword, file_path,
            )
        ):
            capped_reason = (
                f"presence detector: rule for {rule_keyword!r} also "
                "matches the guarded negative-control fixture"
            )

        if capped_reason:
            logger.info(
                "semgrep sweep capped at inconclusive for %s:%s — %s",
                file_path, function_name, capped_reason,
            )
            outcome = "inconclusive"
        elif in_function:
            outcome = "confirmed"
        elif result.errors:
            # A rule that failed to parse/run produced no findings for
            # a reason that says NOTHING about the code. Reporting
            # "refuted" here recorded tool failures as refutations —
            # feeding tier counters and demotion logic a
            # disconfirmation the tool never made.
            outcome = "error"
        else:
            outcome = "refuted"

        if outcome == "refuted":
            # Second pass over the fidelity-3 expanded view: pattern
            # rules can't see through macros (LIST_FOREACH wrappers,
            # lock macros, allocator wrappers), so a no-match on
            # macro-bearing C/C++ source is not yet a refutation.
            # Cheap textual gate + per-run expansion budget inside;
            # any failure degrades to the plain refuted outcome.
            expanded = _expanded_second_pass(
                target_path=target_path,
                file_path=file_path,
                full_path=full_path,
                function_name=function_name,
                rule_config=rule_config,
                line_start=line_start,
                line_end=line_end,
                hypothesis=hypothesis,
                rule_keyword=rule_keyword,
            )
            if expanded is not None:
                return expanded
        serialized = []
        for f in in_function:
            if hasattr(f, "to_dict"):
                serialized.append(f.to_dict())
            elif isinstance(f, dict):
                serialized.append(f)
            else:
                serialized.append({"line": getattr(f, "line", 0),
                                   "rule_id": getattr(f, "rule_id", ""),
                                   "message": getattr(f, "message", "")})
        return SweepResult(
            tool="semgrep",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=serialized,
            rule_id=rule_config,
            errors=result.errors,
            details={"reason": capped_reason} if capped_reason else None,
        )
    except Exception as exc:  # noqa: BLE001
        return SweepResult(
            tool="semgrep",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


def _expanded_second_pass(
    *,
    target_path: Path,
    file_path: str,
    full_path: Path,
    function_name: str,
    rule_config: str,
    line_start: int,
    line_end: int,
    hypothesis: str,
    rule_keyword: str,
) -> SweepResult | None:
    """Retry a no-match semgrep sweep against the fidelity-3 view.

    Runs only when the function's source shows a function-like
    ALL_CAPS macro invocation (cheap textual gate) — pattern rules
    cannot see through macros, so the plain pass's silence proves
    nothing there.  Matches are line-mapped back to original
    coordinates by :mod:`core.audit.expanded_semgrep`; only in-file,
    in-range matches count.  The same identifier-consistency and
    negative-control caps as the plain pass apply.

    A confirmed match is evidence-stamped distinctly — ``rule_id``
    gets an ``:expanded`` suffix, so the orchestrator's stamp becomes
    ``semgrep:<rule>:expanded`` and downstream review can see the
    match came from the expanded view.

    Returns None whenever the expanded pass cannot improve on the
    plain outcome (gate not met, budget spent, preprocess/semgrep
    failure, no in-range match) — the caller's ``refuted`` stands.
    Never raises.
    """
    try:
        # Function-level import: expanded_semgrep pulls in
        # preprocessor_view → compiler_sweep, which imports
        # SweepResult from THIS module — a module-level import here
        # would be circular.
        from .expanded_semgrep import (
            has_macro_invocation,
            is_c_family,
            run_expanded_semgrep_rule,
        )

        if not is_c_family(file_path):
            return None
        try:
            source = full_path.read_text(errors="replace")
        except OSError:
            return None
        if line_start and line_end:
            lines = source.split("\n")
            segment = "\n".join(lines[max(0, line_start - 1):line_end])
        else:
            segment = source
        if not has_macro_invocation(segment):
            return None

        exp = run_expanded_semgrep_rule(
            target_path=target_path,
            file_path=file_path,
            rule_config=rule_config,
            line_start=line_start,
            line_end=line_end,
        )
        if not exp.ok:
            logger.debug(
                "expanded semgrep pass degraded for %s:%s — %s",
                file_path, function_name, exp.reason,
            )
            return None
        if not exp.matches:
            return None

        matches = list(exp.matches)
        capped_reason: str | None = None
        if hypothesis:
            named = _hypothesis_identifiers(hypothesis)
            if named:
                consistent = _filter_identifier_consistent(
                    matches, full_path, named,
                )
                if consistent:
                    matches = consistent
                else:
                    capped_reason = (
                        "identifier mismatch: no expanded-view match line "
                        "(±2) mentions any identifier named by the "
                        "hypothesis ("
                        + ", ".join(sorted(named)[:5]) + ")"
                    )

        if (
            matches and capped_reason is None and rule_keyword
            and _rule_matches_negative_control(
                rule_config, rule_keyword, file_path,
            )
        ):
            capped_reason = (
                f"presence detector: rule for {rule_keyword!r} also "
                "matches the guarded negative-control fixture"
            )

        details: dict[str, Any] = {
            "expanded_view": True,
            "dropped_out_of_file": exp.dropped_out_of_file,
        }
        if capped_reason:
            details["reason"] = capped_reason
            logger.info(
                "expanded semgrep sweep capped at inconclusive for "
                "%s:%s — %s",
                file_path, function_name, capped_reason,
            )
            outcome = "inconclusive"
        else:
            outcome = "confirmed"
        return SweepResult(
            tool="semgrep",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=matches,
            rule_id=f"{rule_config}:expanded",
            details=details,
        )
    except Exception as exc:  # noqa: BLE001 — degrade, never kill the sweep
        logger.debug(
            "expanded semgrep pass failed for %s:%s: %s",
            file_path, function_name, exc,
        )
        return None


# ── Negative controls for dynamic per-hypothesis rules ──────────────
#
# The dynamic rules in hypothesis_mapping are keyword→regex presence
# patterns ("use after free" → free\().  Presence of the API must not
# count as confirmation of the vulnerability claim, so each keyword
# family has a small human-authored fixture that uses the API *safely*
# (guarded free, parameterized SQL, ...).  A rule that also matches its
# fixture is a presence detector and its outcome is capped at
# "inconclusive".

_NEGATIVE_CONTROLS_DIR = (
    Path(__file__).resolve().parents[2] / "engine" / "negative_controls"
)

# hypothesis_mapping keyword → fixture stem.  xss/reflected/cross-site
# share one pattern (and therefore one fixture).
_KEYWORD_FIXTURE_STEMS: dict[str, str] = {
    "buffer overflow": "buffer_overflow",
    "sql injection": "sql_injection",
    "command injection": "command_injection",
    "path traversal": "path_traversal",
    "format string": "format_string",
    "use after free": "use_after_free",
    "double free": "double_free",
    "xss": "xss",
    "reflected": "xss",
    "cross-site": "xss",
    "deserialization": "deserialization",
    "deserialisation": "deserialization",
    "unpickle": "deserialization",
    "ssrf": "ssrf",
    "server-side request": "ssrf",
    "xxe": "xxe",
    "xml external entit": "xxe",
    "open redirect": "open_redirect",
    "unvalidated redirect": "open_redirect",
}

# Keyed by (keyword, fixture suffix): the pattern for a keyword is a
# module constant, so the control verdict is stable per language.
_negative_control_cache: dict[tuple, bool] = {}


def negative_control_fixture(keyword: str, file_path: str) -> Path | None:
    """Return the negative-control fixture for a rule keyword, or None.

    The fixture language follows the audited file's extension so the
    dynamic rule (whose ``languages:`` key now matches the target — see
    ``semgrep_language_for``) actually scans its control fixture.
    Rules emitted with the ``generic`` language scan any file, so they
    fall back to whichever fixture exists (.c, then .py). Targets whose
    language has no fixture return None — the control check is then
    skipped rather than silently run against a file the rule's language
    key would never select.
    """
    stem = _KEYWORD_FIXTURE_STEMS.get(keyword)
    if not stem:
        return None
    from .hypothesis_mapping import semgrep_language_for

    target_suffix = Path(file_path).suffix.lower()
    candidates = [target_suffix] if target_suffix else []
    lang = semgrep_language_for(file_path)
    if lang == "generic":
        # generic rules scan any file handed to them
        candidates += [".c", ".py"]
    elif lang in ("c", "cpp"):
        candidates.append(".c")
    for suffix in candidates:
        fixture = _NEGATIVE_CONTROLS_DIR / f"{stem}{suffix}"
        if fixture.is_file():
            return fixture
    return None


def _rule_matches_negative_control(
    rule_config: str, keyword: str, file_path: str,
) -> bool:
    """Run *rule_config* against the keyword's guarded fixture.

    True means the rule fires on safe code — it is a presence detector.
    Errors return False: a broken control run must not fabricate
    inconclusive outcomes for rules that behaved on the real target.
    """
    fixture = negative_control_fixture(keyword, file_path)
    if fixture is None:
        return False
    cache_key = (keyword, fixture.suffix)
    if cache_key in _negative_control_cache:
        return _negative_control_cache[cache_key]
    try:
        from packages.semgrep.runner import run_rule

        result = run_rule(fixture, rule_config, timeout=60)
        matched = bool(result.findings)
    except Exception:  # noqa: BLE001
        return False
    _negative_control_cache[cache_key] = matched
    return matched


def _finding_line(finding: Any) -> int:
    """Extract the (1-based) line from a semgrep finding of any shape."""
    if hasattr(finding, "line"):
        return finding.line or 0
    if isinstance(finding, dict):
        return finding.get("start", {}).get("line", 0) or finding.get("line", 0)
    return 0


def _hypothesis_identifiers(hypothesis: str) -> frozenset:
    """Identifiers explicitly named by a hypothesis.

    Prose words don't count — only tokens marked as code (backticks or
    quotes), call syntax ``name(...)``, member references, or
    code-shaped bare tokens (underscore / digit / mixedCase).  An empty
    result means the hypothesis names nothing concrete and the
    identifier-consistency check does not apply.
    """
    import re

    idents: set = set()
    idents.update(re.findall(
        r"[`'\"]([A-Za-z_][A-Za-z0-9_]*)(?:\(\))?[`'\"]", hypothesis,
    ))
    idents.update(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", hypothesis))
    idents.update(re.findall(r"(?:->|\.)([A-Za-z_][A-Za-z0-9_]*)", hypothesis))
    idents.update(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*->", hypothesis))
    for tok in _IDENT_RE.findall(hypothesis):
        if "_" in tok or any(c.isdigit() for c in tok):
            idents.add(tok)
        elif tok[:1].islower() and not tok.islower():
            idents.add(tok)  # mixedCase
    return frozenset(
        i for i in idents
        if len(i) > 1 and i.lower() not in _PROSE_STOP_WORDS
    )


def _filter_identifier_consistent(
    findings: list[Any], full_path: Path, identifiers: frozenset,
) -> list[Any]:
    """Keep findings whose match line ±2 mentions a hypothesis identifier.

    Findings without line information cannot be tied to the hypothesis
    and are dropped (fail closed — the caller caps at inconclusive).
    """
    import re

    try:
        file_lines = full_path.read_text(errors="replace").splitlines()
    except OSError:
        return []

    patterns = [
        re.compile(r"\b" + re.escape(ident) + r"\b")
        for ident in identifiers
    ]
    consistent = []
    for finding in findings:
        line = _finding_line(finding)
        if not line:
            continue
        window = "\n".join(file_lines[max(0, line - 3):line + 2])
        if any(p.search(window) for p in patterns):
            consistent.append(finding)
    return consistent


def run_coccinelle_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    cocci_rule: str,
    defines: dict[str, str] | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    domain_vocab: Any = None,
) -> SweepResult:
    """Run a Coccinelle rule against a single C file.

    Args:
        target_path: Root of the target codebase.
        file_path: Relative path to the C source file.
        function_name: Function being audited.
        cocci_rule: Path to the .cocci rule file.
        defines: Optional spatch -D defines (e.g. {"func": "parse_input"}).

    Returns:
        SweepResult with outcome and matches.
    """
    escape = _check_path_containment(target_path, file_path, "coccinelle")
    if escape:
        return escape

    full_path = target_path / file_path
    if not full_path.exists():
        return SweepResult(
            tool="coccinelle",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"file not found: {full_path}"],
        )

    try:
        from packages.coccinelle.runner import is_available, run_rule

        if not is_available():
            return SweepResult(
                tool="coccinelle",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=["coccinelle (spatch) not installed"],
            )

        effective_rule = cocci_rule
        _rendered_tmp = None
        if domain_vocab is not None:
            # Rendering reads the rule file and writes a tempfile: IO
            # and text-decode errors are the legitimate failure set.
            with contextlib.suppress(OSError, ValueError):
                from engine.coccinelle.vocab_renderer import render as _render_cocci
                _rendered_tmp = _render_cocci(Path(cocci_rule), domain_vocab)
                if _rendered_tmp is not None:
                    effective_rule = str(_rendered_tmp)

        try:
            result = run_rule(
                full_path,
                effective_rule,
                defines=defines or {},
                timeout=120,
                # In-repo engine/coccinelle rules via cwe_dispatch
                # (code trust) — @script:python blocks are trusted.
                allow_scripting=True,
            )
        finally:
            if _rendered_tmp is not None:
                _rendered_tmp.unlink(missing_ok=True)

        matches = []
        for f in result.matches:
            if hasattr(f, "to_dict"):
                matches.append(f.to_dict())
            else:
                matches.append({"raw": str(f)})

        if line_start is not None and line_end is not None:
            matches = [
                m for m in matches
                if _match_in_range(m, line_start, line_end)
            ]

        outcome = "confirmed" if matches else "refuted"
        return SweepResult(
            tool="coccinelle",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=matches,
            rule_id=cocci_rule,
            errors=result.errors if hasattr(result, "errors") else [],
        )
    except Exception as exc:  # noqa: BLE001
        return SweepResult(
            tool="coccinelle",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


# SMT verb names → libexec shim basenames
_SMT_VERBS = {
    "check-overflow": "raptor-smt-check-overflow",
    "check-oob": "raptor-smt-check-oob",
    "check-null-deref": "raptor-smt-check-null-deref",
    "check-overflow-to-oob": "raptor-smt-check-overflow-to-oob",
    "check-negative-bypass": "raptor-smt-check-negative-bypass",
    "validate-path": "raptor-smt-validate-path",
    "check-auth-bypass": "raptor-smt-check-auth-bypass",
    "check-lock-discipline": "raptor-smt-check-lock-discipline",
    "check-resource-leak": "raptor-smt-check-resource-leak",
    "check-null-propagation": "raptor-smt-check-null-propagation",
    "check-integer-narrowing": "raptor-smt-check-integer-narrowing",
    "check-early-release": "raptor-smt-check-early-release",
    "check-lock-domain": "raptor-smt-check-lock-domain",
    "check-toctou": "raptor-smt-check-toctou",
}

_SMT_VERB_ROLES = {
    # Invariant-preservation harness (core.audit.invariant_smt): a sat
    # model shows one mutation site can break the stated invariant
    # ASSUMING it held before — real evidence, but blind to caller
    # context and the base case, so it may not promote on its own.
    "invariant-preservation": "detection",
    "check-overflow": "verification",
    "check-oob": "verification",
    "check-null-deref": "verification",
    "check-overflow-to-oob": "detection",
    "check-negative-bypass": "detection",
    "validate-path": "verification",
    "check-auth-bypass": "verification",
    "check-lock-discipline": "verification",
    "check-resource-leak": "verification",
    "check-null-propagation": "verification",
    "check-integer-narrowing": "verification",
    "check-early-release": "verification",
    "check-lock-domain": "detection",
    "check-toctou": "verification",
}


def get_smt_verb_role(verb: str) -> str:
    """Return the role of an SMT verb: ``"detection"`` or ``"verification"``.

    Detection verbs identify arithmetic patterns that *could* be
    exploitable but lack domain constraints (e.g. caller-enforced
    ranges).  Verification verbs model enough semantics to be
    authoritative — their findings can promote status directly.

    Unknown verbs default to ``"detection"``.
    """
    bare = verb.split(":")[0]
    return _SMT_VERB_ROLES.get(bare, "detection")


# SMT verbs whose intrinsic predicate is satisfiable for almost any
# unconstrained operand assignment: "can these bitvectors wrap / index
# past a free-variable bound?" — yes, always, unless a guard forbids
# it.  The vacuity policy is centralised HERE (the sweep/SMT layer) so
# every caller inherits it — no per-callsite guard lists:
#
#   * SAT without encoded source-level guard premises is VACUOUS →
#     outcome "inconclusive", never "confirmed".
#   * SAT becomes meaningful only when comparison expressions
#     mentioning the operands are extracted from the source and added
#     as Z3 constraints (premises) — and those premises are themselves
#     jointly satisfiable.
#   * Premises that are jointly UNSAT are vacuous premises → outcome
#     "inconclusive" (never "refuted" — an UNSAT caused by
#     contradictory premises says nothing about the code).
#   * UNSAT of the full query (premises SAT on their own) stays
#     "refuted" — guards proving infeasibility is real information.
VACUOUS_SMT_VERBS = frozenset({
    "check-overflow", "check-oob", "check-overflow-to-oob",
})


def is_vacuous_smt_verb(verb: str) -> bool:
    """True when *verb* (bare or ``smt:``-prefixed) is in the vacuous set."""
    bare = verb.split(":")[-1] if verb.startswith("smt:") else verb
    return bare.split(":")[0] in VACUOUS_SMT_VERBS


def run_smt_sweep(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    smt_args: dict[str, Any],
) -> SweepResult:
    """Run an SMT verb shim and classify the result.

    Args:
        file_path: Source file being audited (for logging).
        function_name: Function being audited.
        verb: SMT verb name (e.g. "check-overflow", "validate-path").
        smt_args: Dict of CLI args for the verb (keys become --key flags,
            values become their arguments). List values are serialised
            as JSON.

    Returns:
        SweepResult with outcome ``confirmed`` (sat — the condition is
        feasible) or ``refuted`` (unsat — the condition is infeasible).
    """
    shim_name = _SMT_VERBS.get(verb)
    if not shim_name:
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"unknown SMT verb {verb!r}; valid: {sorted(_SMT_VERBS)}"],
        )

    raptor_dir = Path(__file__).resolve().parents[2]
    shim_path = raptor_dir / "libexec" / shim_name
    if not shim_path.exists():
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"shim not found: {shim_path}"],
        )

    cmd = ["python3", str(shim_path)]
    import re as _re
    _safe_key_re = _re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    for key, value in smt_args.items():
        if not _safe_key_re.match(key):
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=[
                    (f"invalid smt_args key {key!r}: "
                     "must be alphanumeric/underscore/hyphen")
                ],
            )
        flag = f"--{key}"
        if isinstance(value, bool):
            if value:
                cmd.append(flag)
        elif isinstance(value, list):
            for item in value:
                cmd.extend([flag, str(item)])
        elif isinstance(value, dict):
            cmd.extend([flag, _json.dumps(value)])
        else:
            cmd.extend([flag, str(value)])

    try:
        try:
            from core.config import RaptorConfig
            safe_env = RaptorConfig.get_safe_env()
        except ImportError:
            safe_env = dict(os.environ)
            for var in ("TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"):
                safe_env.pop(var, None)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=safe_env,
        )
        raw = proc.stdout.strip()

        if proc.returncode != 0:
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=[proc.stderr.strip() or f"exit code {proc.returncode}"],
                raw_output=raw,
                rule_id=f"smt:{verb}",
            )

        try:
            result_data = _json.loads(raw)
        except _json.JSONDecodeError:
            result_data = {"raw": raw}

        smt_result = result_data.get("result", raw.lower())
        if smt_result in ("sat", "satisfiable", "feasible"):
            outcome = "confirmed"
        elif smt_result in ("unsat", "unsatisfiable", "infeasible"):
            outcome = "refuted"
        else:
            outcome = "inconclusive"

        # Centralised vacuity policy (see VACUOUS_SMT_VERBS): for the
        # unconstrained-arithmetic verbs, SAT is near-certain when no
        # guards constrain the model, so it must not read as
        # confirmation.  Guards supplied by the caller (``--guard``
        # flags in smt_args) make SAT meaningful again.
        if outcome == "confirmed" and is_vacuous_smt_verb(verb) \
                and not _smt_args_have_guards(smt_args):
            outcome = "inconclusive"
            if isinstance(result_data, dict):
                result_data.setdefault(
                    "vacuity_note",
                    "sat without guard constraints is vacuous for "
                    f"{verb}; pass --guard premises to make SAT "
                    "meaningful",
                )

        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=[result_data] if outcome == "confirmed" else [],
            rule_id=f"smt:{verb}",
            raw_output=raw,
        )
    except subprocess.TimeoutExpired:
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["SMT solver timed out (60s)"],
            rule_id=f"smt:{verb}",
        )
    except Exception as exc:  # noqa: BLE001
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
            rule_id=f"smt:{verb}",
        )


def _smt_args_have_guards(smt_args: dict[str, Any]) -> bool:
    """True when the shim CLI args carry at least one non-empty guard."""
    for key in ("guard", "guards"):
        value = smt_args.get(key)
        if isinstance(value, (list, tuple)):
            if any(str(item).strip() for item in value):
                return True
        elif isinstance(value, str) and value.strip():
            return True
    return False


def _verb_vocab(target_path: str | None):
    """Vocab for the SMT verb checkers: target-kind pack (learned
    domain vocabulary is unavailable in the verb child — the pack keeps
    kernel-name coverage at today's level)."""
    from core.audit.condition_smt import _EMPTY_VOCAB, DomainVocabulary
    if not target_path:
        return _EMPTY_VOCAB
    try:
        return DomainVocabulary.from_domain_model(
            None, target_path=target_path,
        )
    except Exception:  # noqa: BLE001 — checker runs on seeds if the pack fails
        return _EMPTY_VOCAB


def run_smt_verb_direct(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    source: str,
    hypothesis: str,
    target_path: str | None = None,
) -> SweepResult:
    """Call an SMT verb directly from Python (no shim subprocess).

    Extracts operands from the hypothesis text and calls the verb
    function.  Falls back to inconclusive if operands can't be extracted
    or Z3 is unavailable.

    ``target_path`` gates the target-kind vocab packs so the mechanical
    checkers keep kernel-API coverage on kernel targets (the checkers'
    hardcoded lists are seed-sized).

    Runs in a forked subprocess so Z3 assertion failures (segfaults in
    the C++ core) return inconclusive instead of killing the parent.
    """
    return _smt_verb_in_subprocess(
        file_path=file_path,
        function_name=function_name,
        verb=verb,
        source=source,
        hypothesis=hypothesis,
        target_path=target_path,
    )


_SMT_VERB_CHILD_SCRIPT = (
    "import sys,os,pickle\n"
    "sys.path.insert(0,os.environ['RAPTOR_DIR'])\n"
    "from core.audit.sweep import _run_smt_verb_inner\n"
    "r=_run_smt_verb_inner(**pickle.loads(sys.stdin.buffer.read()))\n"
    "sys.stdout.buffer.write(pickle.dumps(r))\n"
)


def smt_child_env() -> dict:
    """Env for SMT/Z3 probe children with RAPTOR_DIR pinned to THIS tree.

    The child bootstraps ``sys.path`` from ``RAPTOR_DIR``; an ambient
    value inherited from the launching shell can point at a different
    checkout, making the child import the OTHER tree's modules
    (observed: ``TypeError: _run_smt_verb_inner() got an unexpected
    keyword argument 'target_path'`` — every SMT probe of a run exit
    1 because a stale checkout's ``core.audit.sweep`` was imported).

    Full-environ copy MINUS the LLM env (credentials, transport-
    routing family, dispatcher route): SMT children run only RAPTOR's
    own solver code and make no LLM calls — the interpreter
    environment must mirror the parent, the LLM surface must not.
    """
    from core.config import RaptorConfig, pin_raptor_dir
    return RaptorConfig.strip_llm_env_vars(
        pin_raptor_dir(dict(os.environ)))


def _smt_verb_in_subprocess(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    source: str,
    hypothesis: str,
    timeout: int = 10,
    target_path: str | None = None,
) -> SweepResult:
    """Run SMT verb in an isolated subprocess.

    Uses subprocess.Popen (fork+exec) rather than bare os.fork() so the
    child gets a clean, single-threaded process image -- safe when the
    parent has worker threads.
    """
    payload = pickle.dumps({
        "file_path": file_path,
        "function_name": function_name,
        "verb": verb,
        "source": source,
        "hypothesis": hypothesis,
        "target_path": target_path,
    })
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _SMT_VERB_CHILD_SCRIPT],
            input=payload, capture_output=True, timeout=timeout,
            check=False, env=smt_child_env(),
        )
        if proc.returncode == 0:
            # Broad by design: pickle.loads on malformed child stdout
            # can raise nearly anything (UnpicklingError, EOFError,
            # AttributeError, ImportError, ...); any failure degrades
            # to the loud warning below.
            with contextlib.suppress(Exception):
                sr = pickle.loads(proc.stdout)
                if isinstance(sr, SweepResult):
                    return sr
        logger.warning(
            "SMT subprocess exited %d for %s:%s verb=%s",
            proc.returncode, file_path, function_name, verb,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "SMT subprocess timed out for %s:%s verb=%s",
            file_path, function_name, verb,
        )
    return SweepResult(
        tool="smt", file_path=file_path,
        function_name=function_name, outcome="inconclusive",
        errors=["Z3 subprocess crashed or timed out"],
        rule_id=f"smt:{verb}",
    )


def _run_smt_verb_inner(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    source: str,
    hypothesis: str,
    target_path: str | None = None,
) -> SweepResult:
    """Actual SMT verb execution (runs inside forked child)."""
    vocab = _verb_vocab(target_path)
    try:
        if verb == "check-negative-bypass":
            from packages.exploit_feasibility.smt_verbs import check_negative_bypass
            value, limit = _extract_negative_bypass_operands(hypothesis, source)
            if not value or not limit:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = check_negative_bypass(value, limit, profile="int32")
        elif verb == "check-null-deref":
            from packages.exploit_feasibility.smt_verbs import check_null_deref
            ptr = _extract_ptr_operand(hypothesis)
            if not ptr:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = check_null_deref(ptr, profile="uint64")
        elif verb == "check-overflow":
            if _lang_has_overflow_safety(file_path):
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            from packages.exploit_feasibility.smt_verbs import check_overflow
            operands = _extract_arithmetic_operands(hypothesis, source)
            if len(operands) < 2:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            # Vacuity policy: SAT on unconstrained bitvectors is
            # near-certain and meaningless.  Extract comparison lines
            # mentioning the operands and add them as Z3 PREMISES —
            # only then may SAT mean "the guards do not rule out the
            # wrap".  No premises / vacuous premises → inconclusive.
            premises = _extract_comparison_premises(operands, source)
            gate = _premise_gate(premises, "uint32")
            if gate is not None:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                    details={"summary": gate},
                )
            op = _extract_arith_operator(hypothesis)
            result = check_overflow(
                operands, op, profile="uint32", guards=premises,
            )
        elif verb == "check-oob":
            if _lang_has_overflow_safety(file_path):
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            from packages.exploit_feasibility.smt_verbs import check_oob
            index, size = _extract_oob_operands(hypothesis, source)
            if not index or not size:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            premises = _extract_comparison_premises([index, size], source)
            gate = _premise_gate(premises, "uint64")
            if gate is not None:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                    details={"summary": gate},
                )
            result = check_oob(size, index, profile="uint64", guards=premises)
        elif verb == "check-overflow-to-oob":
            from packages.exploit_feasibility.smt_verbs import check_overflow_to_oob
            count, elem_size, index = _extract_overflow_to_oob_operands(
                hypothesis, source,
            )
            if not count or not elem_size or not index:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            premises = _extract_comparison_premises(
                [count, elem_size, index], source,
            )
            gate = _premise_gate(premises, "uint32")
            if gate is not None:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                    details={"summary": gate},
                )
            result = check_overflow_to_oob(
                count, elem_size, index, profile="uint32", guards=premises,
            )
        elif verb == "check-auth-bypass":
            from core.audit.condition_smt import check_auth_bypass
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            auth_result = check_auth_bypass(source, vocab)
            if auth_result.bypass_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=auth_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=auth_result.to_dict(),
            )
        elif verb == "check-integer-narrowing":
            from core.audit.condition_smt import check_integer_narrowing
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            narr_result = check_integer_narrowing(source)
            if narr_result.narrowing_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=narr_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=narr_result.to_dict(),
            )
        elif verb == "check-lock-discipline":
            from core.audit.condition_smt import check_lock_discipline
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            lock_result = check_lock_discipline(source, vocab)
            if lock_result.violation_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=lock_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=lock_result.to_dict(),
            )
        elif verb == "check-null-propagation":
            from core.audit.condition_smt import check_null_propagation
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            null_result = check_null_propagation(source, vocab)
            if null_result.null_deref_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=null_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=null_result.to_dict(),
            )
        elif verb == "check-resource-leak":
            from core.audit.condition_smt import check_resource_leak
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            leak_result = check_resource_leak(source, vocab)
            if leak_result.leak_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=leak_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=leak_result.to_dict(),
            )
        elif verb == "check-early-release":
            from core.audit.condition_smt import check_early_release
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            er_result = check_early_release(source, vocab)
            if er_result.early_release_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=er_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=er_result.to_dict(),
            )
        elif verb == "check-lock-domain":
            from core.audit.condition_smt import check_lock_domain
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            ld_result = check_lock_domain(source, vocab)
            if ld_result.mismatch_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=ld_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=ld_result.to_dict(),
            )
        elif verb == "check-toctou":
            from core.audit.condition_smt import check_toctou
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            tt_result = check_toctou(source)
            if tt_result.toctou_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=tt_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=tt_result.to_dict(),
            )
        elif verb == "validate-path":
            from packages.exploit_feasibility.smt_path import validate_path
            conditions = _extract_path_conditions(hypothesis, source)
            if not conditions:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = validate_path(conditions)
        else:
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="inconclusive",
                errors=[f"no direct caller for verb {verb!r}"],
                rule_id=f"smt:{verb}",
            )

        feasible = result.get("feasible")
        if feasible is True:
            outcome = "confirmed"
        elif feasible is False:
            outcome = "refuted"
        else:
            outcome = "inconclusive"

        return SweepResult(
            tool="smt", file_path=file_path,
            function_name=function_name, outcome=outcome,
            matches=[result] if outcome == "confirmed" else [],
            rule_id=f"smt:{verb}",
            raw_output=_json.dumps(result),
        )
    except Exception as exc:  # noqa: BLE001
        return SweepResult(
            tool="smt", file_path=file_path,
            function_name=function_name, outcome="error",
            errors=[str(exc)], rule_id=f"smt:{verb}",
        )


_IDENT_RE = __import__("re").compile(r"[a-z_][a-z0-9_]*", __import__("re").IGNORECASE)


def _extract_negative_bypass_operands(
    hypothesis: str, source: str,
) -> tuple:
    """Extract (value, limit) from hypothesis like 'negative msg_qbytes bypasses size check'."""
    import re
    hyp = hypothesis.lower()
    m = re.search(
        r"negative\s+(?:value\s+(?:for\s+)?)?(?:the\s+)?[`'\"]?(\w+)[`'\"]?",
        hyp,
    )
    value = m.group(1) if m else None

    m = re.search(
        r"(?:bypass|exceed|circumvent)\w*\s+(?:the\s+)?[`'\"]?(\w+)[`'\"]?\s+(?:check|limit|bound)",
        hyp,
    )
    if m:
        limit = m.group(1)
    else:
        identifiers = _IDENT_RE.findall(source)
        limit_candidates = [
            i for i in identifiers
            if any(kw in i.lower() for kw in ("limit", "max", "size", "bound", "rlim"))
        ]
        limit = limit_candidates[0] if limit_candidates else None

    if value and not _IDENT_RE.fullmatch(value):
        value = None
    if limit and not _IDENT_RE.fullmatch(limit):
        limit = None

    return value, limit


_OVERFLOW_SAFE_EXTS = frozenset({".go", ".py", ".rs", ".java"})


def _lang_has_overflow_safety(file_path: str) -> bool:
    """Languages where unconstrained SMT overflow/OOB checks are meaningless."""
    from pathlib import Path
    return Path(file_path).suffix in _OVERFLOW_SAFE_EXTS


def _strip_comments_and_strings(source: str) -> str:
    """Blank out comments and string literals so lexical scans don't
    match prose that merely mentions code."""
    import re
    return re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'',
        " ", source, flags=re.DOTALL,
    )


def _operand_in_source_arithmetic(operand: str, source: str) -> bool:
    """Check if *operand* appears adjacent to an arithmetic operator in source."""
    import re
    cleaned = _strip_comments_and_strings(source)
    pat = rf"(?:\b{re.escape(operand)}\b\s*[+\-*/%]|[+\-*/%]\s*\b{re.escape(operand)}\b)"
    return bool(re.search(pat, cleaned))


# Simple relational expression with atomic sides: ``ident OP ident``
# or ``ident OP literal`` (either order).  Lookarounds exclude shift
# operators (``<<`` / ``>>``) and compound assignment fragments so
# ``a << 2`` and ``a <<= b`` never read as comparisons.  Deliberately
# only matches forms the path-condition parser can encode — compound
# expressions would land in the parser's ``unknown`` bucket anyway.
_COMPARISON_PREMISE_RE = _re.compile(
    r"\b([A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+)\s*"
    r"(==|!=|<=|>=|(?<![<>])<(?![<=])|(?<![<>])>(?![>=]))\s*"
    r"([A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+)\b"
)

# Bound on premises fed to the solver per check — keeps solve time
# and unsat-core noise bounded on comparison-heavy functions.
_MAX_PREMISES = 8


def _extract_comparison_premises(
    operands: list[str], source: str,
) -> list[str]:
    """Extract comparison expressions mentioning *operands* from *source*.

    These become Z3 premises (``guards=``) for the vacuous SMT verbs
    (see ``VACUOUS_SMT_VERBS``): the presence of a source-level guard
    is what makes a SAT verdict on "can this arithmetic wrap?" carry
    information — Z3 must find a wrap *within* the guarded value
    space, not over unconstrained bitvectors.

    Only comparisons with atomic sides are extracted (the same forms
    the path-condition parser accepts).  Comments and string literals
    are stripped first.  Returns a de-duplicated, order-preserving
    list capped at ``_MAX_PREMISES``.
    """
    idents = {op for op in operands if op and _IDENT_RE.fullmatch(op)}
    if not idents or not source:
        return []
    cleaned = _strip_comments_and_strings(source)
    premises: list[str] = []
    seen: set = set()
    for m in _COMPARISON_PREMISE_RE.finditer(cleaned):
        lhs, cmp_op, rhs = m.group(1), m.group(2), m.group(3)
        if lhs not in idents and rhs not in idents:
            continue
        text = f"{lhs} {cmp_op} {rhs}"
        if text in seen:
            continue
        seen.add(text)
        premises.append(text)
        if len(premises) >= _MAX_PREMISES:
            break
    return premises


def _premise_gate(premises: list[str], profile: str) -> str | None:
    """Vet extracted premises before a vacuous-verb SMT call.

    Returns ``None`` when the premises are usable (at least one
    extracted, encodable, and jointly satisfiable), otherwise the
    inconclusive-reason string.  The premise-vacuity check matters
    because contradictory premises would drive the *full* query UNSAT
    and masquerade as an authoritative "refuted".
    """
    if not premises:
        return (
            "no source-level guard premises extracted; "
            "unconstrained SAT is vacuous"
        )
    try:
        from packages.exploit_feasibility.smt_path import validate_path
        premise_check = validate_path(premises, profile=profile)
    except Exception as exc:  # noqa: BLE001 — degrade, never crash the sweep
        return f"premise encoding failed: {exc}"
    feasible = premise_check.get("feasible")
    if feasible is False:
        return "vacuous premises"
    if feasible is None:
        # Z3 missing or every premise unparseable — without encoded
        # premises the main query degenerates to the unconstrained
        # (vacuous) form.
        return (
            "premises unencodable; unconstrained SAT is vacuous"
        )
    return None


_ARITH_OP_KEYWORDS = (
    ("*", ("multipl", "product", "times", "mul ")),
    ("-", ("subtract", "minus", "underflow", "decrement")),
    ("+", ("add", "sum", "plus", "increment")),
)


def _extract_arith_operator(hypothesis: str) -> str:
    """Determine the arithmetic operator a CWE-190 hypothesis is about.

    Order of preference: an explicit operator inside a backticked
    expression (`` `a * b` ``), then an explicit spaced operator in
    the prose, then operation keywords.  Defaults to ``"+"`` — the
    historical behaviour — when nothing is recognisable.
    """
    import re
    for expr in re.findall(r"`([^`]+)`", hypothesis):
        m = re.search(r"\w\s*([+*-])\s*\w", expr)
        if m:
            return m.group(1)
    # Spaced operator in prose ("count * size overflows"); require
    # whitespace on both sides.  Backticks are stripped first so
    # "`count` * `size`" (operands quoted individually) also matches.
    # ``-`` is excluded here — a spaced hyphen in prose is usually
    # punctuation, so subtraction is only recognised via backticks or
    # keywords.
    m = re.search(r"\w\s+([+*])\s+\w", hypothesis.replace("`", ""))
    if m:
        return m.group(1)
    hyp = hypothesis.lower()
    for op, keywords in _ARITH_OP_KEYWORDS:
        if any(kw in hyp for kw in keywords):
            return op
    return "+"


def _extract_ptr_operand(hypothesis: str) -> str | None:
    """Extract pointer name from hypothesis like 'NULL pointer dereference of ptr'."""
    import re
    m = re.search(r"[`'\"]?(\w+)[`'\"]?\s+(?:is\s+)?(?:null|NULL)", hypothesis)
    if m and _IDENT_RE.fullmatch(m.group(1)):
        return m.group(1)
    m = re.search(r"(?:null|NULL)\s+(?:pointer\s+)?(?:dereference\s+)?(?:of\s+)?[`'\"]?(\w+)[`'\"]?", hypothesis)
    if m and _IDENT_RE.fullmatch(m.group(1)):
        return m.group(1)
    return None


def _extract_arithmetic_operands(
    hypothesis: str, source: str,
) -> list:
    """Extract operand identifiers from hypothesis about integer overflow.

    After extracting candidates from hypothesis text, verifies each
    actually participates in an arithmetic expression in the source.
    """
    import re
    backtick_ids = re.findall(r"`(\w+)`", hypothesis)
    if len(backtick_ids) >= 2:
        raw = [i for i in backtick_ids[:3] if _IDENT_RE.fullmatch(i)]
    else:
        ids = _IDENT_RE.findall(hypothesis)
        raw = [
            i for i in ids
            if i.lower() not in {
                "integer", "overflow", "the", "in", "of", "can", "cause",
                "value", "large", "leading", "to", "size", "check", "a",
                "an", "this", "that", "with", "from", "by", "for", "is",
            }
        ]
        raw = raw[:3]
    if source:
        verified = [c for c in raw if _operand_in_source_arithmetic(c, source)]
        return verified[:2]
    return raw[:2]


def _extract_oob_operands(
    hypothesis: str, source: str,
) -> tuple:
    """Extract (index, size) from hypothesis about out-of-bounds access."""
    import re
    m = re.search(r"[`'\"]?(\w+)[`'\"]?\s+(?:is\s+)?(?:used\s+)?(?:as\s+)?(?:an?\s+)?(?:array\s+)?index", hypothesis.lower())
    index = m.group(1) if m and _IDENT_RE.fullmatch(m.group(1)) else None

    m = re.search(r"(?:array|buffer)\s+(?:of\s+)?(?:size\s+)?[`'\"]?(\w+)[`'\"]?", hypothesis.lower())
    if m and _IDENT_RE.fullmatch(m.group(1)):
        size = m.group(1)
    else:
        ids = _IDENT_RE.findall(source)
        size_candidates = [
            i for i in ids
            if any(kw in i.lower() for kw in ("size", "len", "count", "num", "nsems"))
        ]
        size = size_candidates[0] if size_candidates else None

    return index, size


_PROSE_STOP_WORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can",
    "cause", "check", "could", "do", "does", "for", "from", "has",
    "have", "if", "in", "into", "is", "it", "its", "leading", "may",
    "no", "not", "of", "on", "or", "overflow", "so", "the", "that",
    "then", "this", "to", "via", "was", "when", "which", "will",
    "with", "without", "would", "writes", "integer", "large", "value",
})


def _extract_overflow_to_oob_operands(
    hypothesis: str, source: str,
) -> tuple:
    """Extract (count, element_size, index) for CWE-680 check."""
    import re
    backtick_ids = re.findall(r"`(\w+)`", hypothesis)
    if len(backtick_ids) >= 3:
        valid = [i for i in backtick_ids[:3] if _IDENT_RE.fullmatch(i)]
        if len(valid) == 3:
            return tuple(valid)

    ids = [
        i for i in _IDENT_RE.findall(hypothesis)
        if i.lower() not in _PROSE_STOP_WORDS and len(i) > 1
    ]
    count_kw = ("count", "num", "nelem", "nitems")
    size_kw = ("size", "elem_size", "element_size", "stride", "width")
    idx_kw = ("index", "idx", "offset")

    count = next(
        (i for i in ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in count_kw)), None,
    )
    elem = next(
        (i for i in ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in size_kw)), None,
    )
    index = next(
        (i for i in ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in idx_kw)), None,
    )

    if not count:
        src_ids = [
            i for i in _IDENT_RE.findall(source)
            if i.lower() not in _PROSE_STOP_WORDS and len(i) > 1
        ]
        count = next(
            (i for i in src_ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in count_kw)), None,
        )
    if not elem:
        elem = "4"

    return count, elem, index


def _extract_path_conditions(
    hypothesis: str, source: str,
) -> list:
    """Extract condition strings for validate-path from hypothesis text.

    Looks for backtick-quoted expressions first, then falls back to
    quoted conditions or simple relational expressions.
    """
    import re
    backtick_conds = re.findall(r"`([^`]*[<>=!]+[^`]*)`", hypothesis)
    if backtick_conds:
        return backtick_conds

    quoted_conds = re.findall(r'"([^"]*[<>=!]+[^"]*)"', hypothesis)
    if quoted_conds:
        return quoted_conds

    relational = re.findall(
        r"(\w+\s*(?:[<>=!]=?|!=)\s*\w+)", hypothesis,
    )
    return relational or []


def run_codeql_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    query_path: str,
    database_path: str | None = None,
    line_start: int = 0,
    line_end: int = 0,
) -> SweepResult:
    """Run a CodeQL query against a database and classify matches.

    Args:
        target_path: Root of the target codebase.
        file_path: Relative path to the source file being audited.
        function_name: Function being audited.
        query_path: Path to the .ql query file.
        database_path: Path to the CodeQL database. If None, attempts
            to find one under ``target_path``.
        line_start: Function start line (for match filtering).
        line_end: Function end line.

    Returns:
        SweepResult with outcome based on whether any matches fall
        within the target function.
    """
    qpath = Path(query_path)
    if not qpath.exists():
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"query file not found: {query_path}"],
        )

    try:
        from core.dataflow.codeql_augmented_run import analyze

        db = database_path
        if not db:
            for candidate in (
                target_path / "codeql-db",
                target_path / ".codeql" / "db",
                target_path / "codeql-database",
            ):
                if candidate.is_dir():
                    db = str(candidate)
                    break

        if not db:
            return SweepResult(
                tool="codeql",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=["no CodeQL database found; build one first"],
            )

        import tempfile

        with tempfile.TemporaryDirectory(prefix="codeql-sweep-") as tmp:
            sarif_out = Path(tmp) / "sweep.sarif"
            result = analyze(
                Path(db),
                [str(qpath)],
                sarif_out,
                timeout_seconds=300,
            )
            sarif = _json.loads(result.sarif_path.read_text(encoding="utf-8"))

        runs = sarif.get("runs") or [{}]
        sarif_results = runs[0].get("results") or []
        in_function = []
        for r in sarif_results:
            locs = r.get("locations") or [{}]
            loc = locs[0] if locs else {}
            phys = loc.get("physicalLocation", {})
            art = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            rline = region.get("startLine", 0)

            if art.endswith("/" + file_path) or art == file_path:
                if line_start and line_end:
                    if line_start <= rline <= line_end:
                        in_function.append(r)
                else:
                    in_function.append(r)

        outcome = "confirmed" if in_function else "refuted"
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=in_function,
            rule_id=query_path,
        )
    except ImportError:
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["core.dataflow.codeql_augmented_run not available"],
        )
    except Exception as exc:  # noqa: BLE001
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


def run_consistency_check(
    *,
    target_path: Path,
    function_name: str,
    cocci_rule: str,
    domain_vocab: Any = None,
) -> SweepResult:
    """Run a Coccinelle consistency check across the entire target.

    The design pattern: "9/10 callers check return, find the 10th."
    Runs a parametric Coccinelle rule with -D func=<function_name>
    against the full target tree to find callers that violate a
    consistency pattern (e.g. unchecked return value).

    Unlike run_coccinelle_sweep (single file), this scans the whole
    codebase — it's the Mode 2 (checker synthesis) pattern applied
    to inconsistency detection.

    Args:
        target_path: Root of the target codebase.
        function_name: Function whose callers to check.
        cocci_rule: Path to the .cocci rule file. Must accept
            -D func=<name> for parametric matching.

    Returns:
        SweepResult with matches being the inconsistent call sites.
    """
    if not is_valid_identifier(function_name):
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome="error",
            errors=[f"invalid function name for -D define: {function_name!r}"],
        )

    try:
        from packages.coccinelle.runner import is_available, run_rule

        if not is_available():
            return SweepResult(
                tool="coccinelle_consistency",
                file_path="<codebase>",
                function_name=function_name,
                outcome="error",
                errors=["coccinelle (spatch) not installed"],
            )

        effective_rule = cocci_rule
        _rendered_tmp = None
        if domain_vocab is not None:
            # Rendering reads the rule file and writes a tempfile: IO
            # and text-decode errors are the legitimate failure set.
            with contextlib.suppress(OSError, ValueError):
                from engine.coccinelle.vocab_renderer import render as _render_cocci
                _rendered_tmp = _render_cocci(Path(cocci_rule), domain_vocab)
                if _rendered_tmp is not None:
                    effective_rule = str(_rendered_tmp)

        try:
            result = run_rule(
                target_path,
                effective_rule,
                defines={"func": function_name},
                timeout=300,
                # In-repo engine/coccinelle rules via cwe_dispatch
                # (code trust) — @script:python blocks are trusted.
                allow_scripting=True,
            )
        finally:
            if _rendered_tmp is not None:
                _rendered_tmp.unlink(missing_ok=True)

        matches = []
        for match in result.matches:
            if hasattr(match, "to_dict"):
                matches.append(match.to_dict())
            else:
                matches.append({"raw": str(match)})

        outcome = "confirmed" if matches else "refuted"
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome=outcome,
            matches=matches,
            rule_id=cocci_rule,
        )
    except ImportError:
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome="error",
            errors=["coccinelle package not available"],
        )
    except Exception as exc:  # noqa: BLE001
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


# ── Joern CPG sweep ─────────────────────────────────────────────────


def run_joern_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    source_param: str,
    sink_call: str,
    cpg=None,
    timeout: int = 300,
) -> SweepResult:
    """Run a Joern taint query for a specific function.

    If cpg is provided, reuses it. If not, returns an error (CPG
    should be built once per run via run_joern_pre_sweep).
    """
    escape = _check_path_containment(target_path, file_path, "joern")
    if escape:
        return escape

    if not is_valid_identifier(function_name):
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"invalid function name: {function_name!r}"],
        )

    if not _is_valid_qualified(source_param):
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"invalid source_param: {source_param!r}"],
        )

    if not _is_valid_qualified(sink_call):
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"invalid sink_call: {sink_call!r}"],
        )

    try:
        from packages.joern.runner import run_taint_query
    except ImportError:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["joern package not available"],
        )

    if cpg is None:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["no CPG provided (build via run_joern_pre_sweep)"],
        )

    # Use per-language max_call_depth_targeted instead of the
    # hardcoded default (2) -- deeper languages like C need depth 3.
    try:
        from packages.joern.lang_config import detect_language, profile_for
        _lang = detect_language(file_path)
        _depth = profile_for(_lang).max_call_depth_targeted
    except Exception:  # noqa: BLE001
        _depth = 2

    flows = run_taint_query(
        cpg,
        function_name,
        sink_call,
        source_param=source_param,
        timeout=timeout,
        max_call_depth=_depth,
    )

    if flows:
        matches = [f.to_dict() for f in flows]
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=matches,
            rule_id=f"joern:taint:{function_name}->{sink_call}",
        )

    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="refuted",
        rule_id=f"joern:taint:{function_name}->{sink_call}",
    )


def run_joern_pre_sweep(
    target_path: Path,
    checklist: dict,
    cache_dir: Path | None = None,
    on_progress: Callable | None = None,
    stall_timeout: int = 600,
    query_timeout: int = 300,
    heap_mb: int | None = None,
    server=None,
) -> dict[str, list]:
    """Run standard taint queries before the LLM loop.

    Builds the CPG once and runs the standard_sinks.sc query.
    Returns per-function flows keyed by "file:function".
    When cache_dir is set, reuses a cached CPG if fresh.
    When server is provided, uses the already-running JoernServer.

    Returns {} when joern is unavailable.
    """
    try:
        from packages.joern.prereqs import is_available
        from packages.joern.runner import (
            build_cpg,
            build_cpg_cached,
            cleanup_cpg,
            run_query,
        )
    except ImportError:
        logger.debug("joern package not importable; skipping pre-sweep")
        return {}

    if server is None and not is_available():
        logger.debug("joern not available on PATH; skipping pre-sweep")
        return {}

    target_path = Path(target_path)
    if not target_path.is_dir():
        return {}

    queries_dir = Path(__file__).resolve().parents[2] / "packages" / "joern" / "queries"
    sinks_script = queries_dir / "standard_sinks.sc"
    if not sinks_script.exists():
        logger.warning("standard_sinks.sc not found at %s", sinks_script)
        return {}

    # Sink list authority: lang_config.STANDARD_SWEEP_SINKS, rendered
    # into the script's __SINK_NAMES__ slot (was a hardcoded copy).
    from packages.joern.lang_config import (
        STANDARD_SWEEP_SINKS,
        scala_string_list,
    )
    sink_subst = {"__SINK_NAMES__": scala_string_list(STANDARD_SWEEP_SINKS)}

    if server is not None:
        result = server.query_script(
            sinks_script, timeout=query_timeout, substitutions=sink_subst,
        )
        if result.errors:
            logger.warning("joern pre-sweep errors: %s", result.errors)

        flows_by_key: dict[str, list] = {}
        for flow in result.flows:
            if flow.steps:
                step_file = flow.steps[0].file
                if safe_join(target_path, step_file) is None:
                    logger.debug("joern flow step has unsafe path: %s", step_file)
                    continue
                key = f"{step_file}:{flow.source_method}"
                flows_by_key.setdefault(key, []).append(flow)
        return flows_by_key

    build_kwargs = {"timeout": stall_timeout, "on_progress": on_progress}
    if heap_mb is not None:
        build_kwargs["heap_mb"] = heap_mb
    # Pin the joern-parse frontend to the detected dominant language
    # (curated per-profile joern_parse_language) instead of trusting
    # parse-side guessing on mixed-language repos.
    from packages.joern.lang_config import parse_languages_for
    parse_langs = parse_languages_for(str(target_path))
    if parse_langs:
        build_kwargs["languages"] = parse_langs

    if cache_dir is not None:
        cpg = build_cpg_cached(target_path, cache_dir, **build_kwargs)
    else:
        cpg = build_cpg(target_path, **build_kwargs)
    if not cpg.exists():
        logger.warning("CPG build produced no output")
        return {}

    try:
        result = run_query(
            cpg, str(sinks_script), timeout=query_timeout,
            substitutions=sink_subst,
        )
        if result.errors:
            logger.warning("joern pre-sweep errors: %s", result.errors)

        flows_by_key: dict[str, list] = {}
        for flow in result.flows:
            if flow.steps:
                step_file = flow.steps[0].file
                if safe_join(target_path, step_file) is None:
                    logger.debug("joern flow step has unsafe path: %s", step_file)
                    continue
                key = f"{step_file}:{flow.source_method}"
                flows_by_key.setdefault(key, []).append(flow)

        return flows_by_key
    finally:
        cleanup_cpg(cpg)


_MECHANICAL_CHECK_PATTERNS: dict[str, str] = {
    "unchecked return": (
        "$X = $FUNC(...);\n"
        "...\n"
        "// ERROR: missing NULL check on $X"
    ),
    "missing null check": (
        "$X = $FUNC(...);\n"
        "...\n"
        "// ERROR: no null check on $X before use"
    ),
    "missing bounds check": (
        "$BUF[$IDX]\n"
        "// ERROR: index $IDX not bounds-checked"
    ),
    "format string": (
        "printf($FMT, ...);\n"
        "// ERROR: format string from user input"
    ),
}


def mechanical_check_to_semgrep(check: str) -> str | None:
    """Map a mechanical_check string to a Semgrep pattern.

    Returns the pattern string if the check maps to a known shape,
    None otherwise.
    """
    check_lower = check.lower().strip()
    for keyword, pattern in _MECHANICAL_CHECK_PATTERNS.items():
        if keyword in check_lower:
            return pattern
    return None
