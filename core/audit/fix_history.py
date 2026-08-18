"""Mine the target's past security fixes for variant hunts and
regression-shaped hypotheses.

Git history was consulted only per-finding, after the fact, as
corroboration ("CORROBORATION ONLY" — see :mod:`.git_oracle`). Fix-
dense code is empirically where the next bugs are, and incomplete
fixes are among the highest-precision find classes, so this module
turns each mined past security fix into review pressure BEFORE the
loop runs:

(a) **Fix-pattern variant hunts** — the fix's diff names a sensitive
    callee (touched by the removed/changed lines) and the guard the
    fix added. Sites elsewhere that call the same callee WITHOUT the
    guard nearby are structurally similar un-fixed candidates: they
    become high-priority gaps carrying an injected hypothesis.

(b) **Regression-shaped hypotheses** — a past fix whose added lines no
    longer exist in the current tree (refactored away) generates a
    "was the fix lost?" hypothesis on the successor function covering
    the hunk's location.

Everything runs under the hardened read-only git substrate
(:func:`core.audit.git_oracle._run_git` — sandboxed, strict readonly
overrides, refuse-unsandboxed); the two invocations used here
(``log --grep`` and ``show --no-ext-diff``) are object-DB reads inside
the posture's stated plumbing envelope. Like the oracle, nothing here
is a verdict: outputs are hypotheses and priority, never evidence
tiers.

Bounded per run: :data:`MAX_FIXES_PER_RUN` mined fixes,
:data:`MAX_VARIANT_GAPS` variant gaps, :data:`MAX_REGRESSION_GAPS`
regression gaps.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_FIXES_PER_RUN = 8
MAX_VARIANT_GAPS = 10
MAX_REGRESSION_GAPS = 5

# Additive priority boost on the main scorer's integer scale
# (SCORE_ENTRY_POINT is 10; a fix-history hit ranks just below a sink).
FIX_HISTORY_BOOST = 6

# Sweep window (lines) around a callee site checked for the guard.
_GUARD_WINDOW = 10

_FIELD_SEP = "\x1f"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(")

# A function-definition header (ends with an opening brace) — its
# name matches the call regex but is not a call site.
_DEF_LINE_RE = re.compile(r"^[^;=]*\)\s*\{\s*$")

# Callee names too generic to anchor a variant hunt.
_GENERIC_CALLEES = frozenset({
    "sizeof", "return", "printf", "fprintf", "assert", "define",
    "if", "for", "while", "switch", "sprintf_s", "print", "format",
    "logger", "log", "debug", "info", "warning", "error",
})


@dataclass
class SecurityFix:
    """One mined past security fix."""

    sha: str
    subject: str
    category: str
    # file → [(post-image line number, added text)]
    added: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    # file → [removed text]
    removed: dict[str, list[str]] = field(default_factory=dict)

    @property
    def files(self) -> list[str]:
        return sorted(set(self.added) | set(self.removed))


def parse_show_diff(text: str) -> dict[str, dict[str, list]]:
    """Parse ``git show --unified=0`` output into per-file +/- lines.

    Returns ``{file: {"added": [(new_lineno, text)], "removed":
    [text]}}``. Post-image line numbers come from the hunk headers.
    """
    out: dict[str, dict[str, list]] = {}
    current_file: str | None = None
    new_line = 0
    for raw in text.splitlines():
        m = _DIFF_FILE_RE.match(raw)
        if m:
            current_file = m.group(1)
            out.setdefault(current_file, {"added": [], "removed": []})
            continue
        m = _HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if current_file is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            out[current_file]["added"].append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            out[current_file]["removed"].append(raw[1:])
    return out


def mine_security_fixes(
    target_path: Path,
    *,
    max_fixes: int = MAX_FIXES_PER_RUN,
    out_dir: Path | None = None,
) -> list[SecurityFix]:
    """Mine past security fixes from the target's git history.

    Uses the oracle's hardened, sandboxed, strict-readonly git
    invocation; returns [] when the target isn't a git repo, git is
    absent, or the sandbox is unavailable. Never raises.
    """
    from core.git.security_fixes import GREP_UNION, classify

    from .git_oracle import _is_git_repo, _run_git

    target_path = Path(target_path)
    if not _is_git_repo(target_path):
        # Loud once: on an extracted tarball this feature has nothing
        # to mine, and a silent skip is indistinguishable from a
        # broken oracle.
        logger.info(
            "fix-history: target is not a git repository — "
            "security-fix mining skipped (run against a git checkout "
            "to enable variant hunts and regression hypotheses)",
        )
        return []

    proc = _run_git(
        target_path,
        [
            "log",
            "-n", str(max_fixes * 3),
            "-i", "-E",
            f"--grep={GREP_UNION}",
            f"--format=%H{_FIELD_SEP}%s",
        ],
        out_dir=out_dir,
    )
    if proc is None or proc.returncode != 0:
        return []

    fixes: list[SecurityFix] = []
    for line in (proc.stdout or "").splitlines():
        if len(fixes) >= max_fixes:
            break
        sha, sep, subject = line.partition(_FIELD_SEP)
        if not sep or not _SHA_RE.match(sha):
            continue
        category = classify(subject) or ""
        if not category:
            continue
        show = _run_git(
            target_path,
            [
                "show",
                # --no-ext-diff must ride every diff-family invocation:
                # a repo-configured external diff driver survives the
                # `-c diff.external=` pin otherwise (see git_oracle's
                # -L call site).
                "--no-ext-diff",
                "--unified=0",
                "--format=",
                sha,
            ],
            out_dir=out_dir,
        )
        if show is None or show.returncode != 0:
            continue
        parsed = parse_show_diff(show.stdout or "")
        if not parsed:
            continue
        fix = SecurityFix(sha=sha, subject=subject, category=category)
        for file_path, lines in parsed.items():
            if lines["added"]:
                fix.added[file_path] = lines["added"]
            if lines["removed"]:
                fix.removed[file_path] = lines["removed"]
        if fix.added or fix.removed:
            fixes.append(fix)
    return fixes


def _significant(text: str) -> bool:
    """Is a diff line meaningful enough to anchor analysis?"""
    stripped = text.strip()
    if len(stripped) < 8:
        return False
    return not stripped.startswith(("//", "/*", "*", "#include", "#"))


def _call_names(lines: list[str]) -> list[str]:
    """Call identifiers on diff lines, most frequent first."""
    counts: dict[str, int] = {}
    for text in lines:
        if not _significant(text):
            continue
        for m in _CALL_RE.finditer(text):
            name = m.group(1)
            if name.lower() in _GENERIC_CALLEES:
                continue
            counts[name] = counts.get(name, 0) + 1
    return sorted(counts, key=lambda n: (-counts[n], n))


def fix_sweep_targets(
    fix: SecurityFix,
    target_path: Path | None = None,
) -> tuple[str | None, str | None]:
    """(sensitive_callee, guard_callee) for one fix, either may be None.

    The sensitive callee comes from the removed (vulnerable) lines —
    what the buggy code was doing; the guard comes from the added
    lines — what the fix now requires. A guard that also appears on
    removed lines is not a guard (it was already there).

    Pure-addition fixes (the common "insert a check" shape) have no
    removed lines; when *target_path* is given the guarded callee is
    recovered from the CURRENT file content adjacent to the added
    guard line.
    """
    removed_lines = [t for lines in fix.removed.values() for t in lines]
    added_lines = [
        t for lines in fix.added.values() for _ln, t in lines
    ]
    removed_calls = _call_names(removed_lines)
    added_calls = _call_names(added_lines)

    guard = None
    for name in added_calls:
        if name not in removed_calls:
            guard = name
            break

    sensitive = None
    for name in removed_calls:
        if name != guard:
            sensitive = name
            break

    if sensitive is None and guard and target_path is not None:
        sensitive = _callee_near_added_guard(fix, guard, target_path)
    return sensitive, guard


def _callee_near_added_guard(
    fix: SecurityFix, guard: str, target_path: Path,
) -> str | None:
    """The call being guarded, from lines adjacent to the added guard."""
    target = Path(target_path).resolve()
    for file_path, added in fix.added.items():
        try:
            full = (target / file_path).resolve()
            full.relative_to(target)
            lines = full.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
        except (ValueError, OSError):
            continue
        for ln, text in added:
            if guard not in text:
                continue
            # Guarded code usually FOLLOWS the check — prefer the
            # lines after the guard, then look before it. Definition
            # headers (`void handler(char *p) {`) match the call
            # regex; skip them.
            after = [
                x for x in lines[ln:min(len(lines), ln + 3)]
                if not _DEF_LINE_RE.match(x)
            ]
            before = [
                x for x in lines[max(0, ln - 4):ln - 1]
                if not _DEF_LINE_RE.match(x)
            ]
            for chunk in (after, before):
                for name in _call_names(chunk):
                    if name != guard:
                        return name
    return None


def _sweep_callee_sites(
    target_path: Path,
    callee: str,
    checklist: dict[str, Any],
    *,
    run_rule_fn: Any = None,
) -> list[tuple[str, int]]:
    """Find (file, line) call sites of *callee* across the target.

    Prefers the existing semgrep machinery (one generated
    pattern-regex rule over the tree); degrades to an in-process regex
    scan over checklist files when semgrep is unavailable.
    """
    pattern = re.compile(rf"\b{re.escape(callee)}\s*\(")

    if run_rule_fn is None:
        try:
            from packages.semgrep.runner import is_available, run_rule

            if is_available():
                run_rule_fn = run_rule
        except ImportError:
            run_rule_fn = None

    if run_rule_fn is not None:
        import tempfile

        rule_yaml = (
            "rules:\n"
            f"  - id: fix-history-{re.sub(r'[^a-zA-Z0-9_-]', '', callee)}\n"
            "    languages: [generic]\n"
            "    severity: INFO\n"
            "    message: fix-history callee sweep\n"
            f"    pattern-regex: '\\b{re.escape(callee)}\\s*\\('\n"
        )
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".yml", prefix="fix_history_", delete=False,
            ) as tmp:
                tmp.write(rule_yaml)
                rule_path = Path(tmp.name)
            try:
                result = run_rule_fn(
                    Path(target_path), str(rule_path), timeout=300,
                )
                sites = []
                target = Path(target_path).resolve()
                for f in getattr(result, "findings", []) or []:
                    file_path = getattr(f, "file", "") or ""
                    line = int(getattr(f, "line", 0) or 0)
                    if not file_path or line <= 0:
                        continue
                    # Semgrep may report absolute paths; the checklist
                    # keys are target-relative.
                    p = Path(file_path)
                    if p.is_absolute():
                        try:
                            file_path = str(p.resolve().relative_to(target))
                        except (ValueError, OSError):
                            continue
                    sites.append((file_path, line))
                if sites or getattr(result, "returncode", 1) == 0:
                    return sites
            finally:
                rule_path.unlink(missing_ok=True)
        except Exception:
            logger.debug("semgrep callee sweep failed", exc_info=True)

    # In-process fallback over the inventory's files.
    sites = []
    target = Path(target_path).resolve()
    for file_info in checklist.get("files", []):
        rel = file_info.get("path", "")
        if not rel:
            continue
        try:
            full = (target / rel).resolve()
            full.relative_to(target)
            text = full.read_text(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue
        for i, line_text in enumerate(text.splitlines(), start=1):
            if pattern.search(line_text):
                sites.append((rel, i))
    return sites


def _window_has_guard(
    target_path: Path, file_path: str, line: int, guard: str,
) -> bool:
    """Does the ±window around file:line mention the guard callee?"""
    try:
        target = Path(target_path).resolve()
        full = (target / file_path).resolve()
        full.relative_to(target)
        lines = full.read_text(
            encoding="utf-8", errors="replace",
        ).splitlines()
    except (ValueError, OSError):
        return False
    lo = max(0, line - 1 - _GUARD_WINDOW)
    hi = min(len(lines), line + _GUARD_WINDOW)
    window = "\n".join(lines[lo:hi])
    return re.search(rf"\b{re.escape(guard)}\s*\(", window) is not None


def fix_pattern_variant_gaps(
    fixes: list[SecurityFix],
    checklist: dict[str, Any],
    target_path: Path,
    *,
    max_gaps: int = MAX_VARIANT_GAPS,
    run_rule_fn: Any = None,
) -> list[dict[str, Any]]:
    """(a) High-priority gaps for structurally similar un-fixed sites."""
    from .gaps import gap_for_site

    gaps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for fix in fixes:
        if len(gaps) >= max_gaps:
            break
        sensitive, guard = fix_sweep_targets(fix, target_path)
        if not sensitive or not guard:
            continue
        fixed_files = set(fix.files)
        for file_path, line in _sweep_callee_sites(
            target_path, sensitive, checklist, run_rule_fn=run_rule_fn,
        ):
            if len(gaps) >= max_gaps:
                break
            if file_path in fixed_files:
                # The fix's own file carries the guard now; skip it —
                # variants live at OTHER call sites.
                continue
            if _window_has_guard(target_path, file_path, line, guard):
                continue
            gap = gap_for_site(checklist, file_path, line)
            if gap is None:
                continue
            key = f"{gap['file']}:{gap['name']}"
            if key in seen:
                continue
            seen.add(key)
            gap["priority_score"] = float(
                gap.get("priority_score") or 0.0,
            ) + FIX_HISTORY_BOOST
            gap["from_fix_history"] = True
            # Anchor for the clone-drift composition (§3.9): the fix
            # commit is the contract witness; clone_drift decides
            # whether the variant reproduces the fixed region.
            gap["fix_anchor"] = {
                "sha": fix.sha,
                "guard": guard,
                "sensitive": sensitive,
            }
            gap["injected_hypotheses"] = [
                {
                    "mechanism": (
                        f"Past security fix {fix.sha[:12]} "
                        f"({fix.category}: {fix.subject[:80]}) added "
                        f"{guard} around {sensitive}; this site calls "
                        f"{sensitive} with no {guard} nearby — "
                        "possible incomplete fix / missed variant"
                    )[:300],
                    "confidence": "medium",
                    "source": "fix_history_variant",
                }
            ]
            gaps.append(gap)
    return gaps


def regression_gaps(
    fixes: list[SecurityFix],
    checklist: dict[str, Any],
    target_path: Path,
    *,
    max_gaps: int = MAX_REGRESSION_GAPS,
) -> list[dict[str, Any]]:
    """(b) 'Was the fix lost?' hypotheses for vanished fix lines."""
    from .gaps import gap_for_site

    target = Path(target_path).resolve()
    gaps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for fix in fixes:
        if len(gaps) >= max_gaps:
            break
        for file_path, added in fix.added.items():
            if len(gaps) >= max_gaps:
                break
            significant = [
                (ln, text) for ln, text in added if _significant(text)
            ]
            if not significant:
                continue
            try:
                full = (target / file_path).resolve()
                full.relative_to(target)
                current = full.read_text(
                    encoding="utf-8", errors="replace",
                )
            except (ValueError, OSError):
                # File itself gone/renamed — different signal (churn),
                # not a resolvable regression hypothesis.
                continue
            current_stripped = {
                line.strip() for line in current.splitlines()
            }
            missing = [
                (ln, text) for ln, text in significant
                if text.strip() not in current_stripped
            ]
            if len(missing) < len(significant):
                # Some fix lines survive — fix still (partially)
                # present; not regression-shaped.
                continue
            anchor_line = missing[0][0]
            gap = gap_for_site(checklist, file_path, anchor_line)
            if gap is None:
                continue
            key = f"{gap['file']}:{gap['name']}"
            if key in seen:
                continue
            seen.add(key)
            gap["priority_score"] = float(
                gap.get("priority_score") or 0.0,
            ) + FIX_HISTORY_BOOST
            gap["from_fix_history"] = True
            gap["injected_hypotheses"] = [
                {
                    "mechanism": (
                        f"Security fix {fix.sha[:12]} ({fix.category}: "
                        f"{fix.subject[:80]}) added lines to "
                        f"{file_path} that no longer exist — was the "
                        "fix lost in a refactor? Verify the successor "
                        "code still enforces the fixed property"
                    )[:300],
                    "confidence": "medium",
                    "source": "fix_history_regression",
                }
            ]
            gaps.append(gap)
    return gaps


# Fixed-region window for the clone-drift anchor (same ±10-line
# convention as _window_has_guard) and a size cap on the persisted
# region text.
_REGION_WINDOW = 10
_MAX_REGION_CHARS = 3000


def _fixed_region(
    fix: SecurityFix, guard: str, target_path: Path,
) -> tuple[str, int, str]:
    """(fixed_file, fixed_line, region_text) around the added guard in
    the CURRENT tree — the clone-drift comparison anchor. Empty when
    the guard line cannot be located."""
    target = Path(target_path).resolve()
    for file_path, added in fix.added.items():
        for ln, text in added:
            if guard not in text:
                continue
            try:
                full = (target / file_path).resolve()
                full.relative_to(target)
                lines = full.read_text(
                    encoding="utf-8", errors="replace",
                ).splitlines()
            except (ValueError, OSError):
                continue
            lo = max(0, ln - 1 - _REGION_WINDOW)
            hi = min(len(lines), ln + _REGION_WINDOW)
            region = "\n".join(lines[lo:hi])[:_MAX_REGION_CHARS]
            if region.strip():
                return file_path, ln, region
    return "", 0, ""


def _variant_site_records(
    variant: list[dict[str, Any]],
    fixes: list[SecurityFix],
    target_path: Path,
) -> list[dict[str, Any]]:
    """Clone-drift anchor records for ``fix-history.json`` (additive
    ``variant_sites`` field, consumed by ``core.audit.clone_drift``)."""
    fixes_by_sha = {f.sha: f for f in fixes}
    region_cache: dict[tuple[str, str], tuple[str, int, str]] = {}
    records: list[dict[str, Any]] = []
    for g in variant:
        anchor = g.get("fix_anchor") or {}
        sha = anchor.get("sha") or ""
        guard = anchor.get("guard") or ""
        if not sha or not guard:
            continue
        key = (sha, guard)
        if key not in region_cache:
            fix = fixes_by_sha.get(sha)
            region_cache[key] = (
                _fixed_region(fix, guard, target_path)
                if fix is not None else ("", 0, "")
            )
        fixed_file, fixed_line, region = region_cache[key]
        if not region:
            continue
        records.append({
            "file": g.get("file", ""),
            "name": g.get("name", ""),
            "sha": sha,
            "guard": guard,
            "sensitive": anchor.get("sensitive") or "",
            "fixed_file": fixed_file,
            "fixed_line": fixed_line,
            "fixed_region": region,
        })
    return records


def apply_fix_history(
    gaps: list[dict[str, Any]],
    checklist: dict[str, Any],
    target_path: Path,
    *,
    out_dir: Path | None = None,
    run_rule_fn: Any = None,
) -> list[dict[str, Any]]:
    """Mine fixes and merge variant/regression gaps into the worklist.

    Existing gaps for the same function get the boost + injected
    hypotheses attached; new functions (already reviewed / filtered
    out) are appended so the loop revisits them with the hypothesis.
    Returns the merged gap list (caller re-sorts). Never raises.
    """
    try:
        fixes = mine_security_fixes(target_path, out_dir=out_dir)
        if not fixes:
            return gaps
        variant = fix_pattern_variant_gaps(
            fixes, checklist, target_path, run_rule_fn=run_rule_fn,
        )
        regression = regression_gaps(fixes, checklist, target_path)
        injected = variant + regression
        if out_dir is not None:
            try:
                (Path(out_dir) / "fix-history.json").write_text(
                    json.dumps(
                        {
                            "fixes": [
                                {
                                    "sha": f.sha,
                                    "subject": f.subject,
                                    "category": f.category,
                                    "files": f.files,
                                }
                                for f in fixes
                            ],
                            "variant_gaps": [
                                {
                                    "file": g["file"],
                                    "name": g["name"],
                                    "hypothesis": g[
                                        "injected_hypotheses"
                                    ][0]["mechanism"],
                                }
                                for g in variant
                            ],
                            "regression_gaps": [
                                {
                                    "file": g["file"],
                                    "name": g["name"],
                                    "hypothesis": g[
                                        "injected_hypotheses"
                                    ][0]["mechanism"],
                                }
                                for g in regression
                            ],
                            "variant_sites": _variant_site_records(
                                variant, fixes, target_path,
                            ),
                        },
                        indent=2,
                    )
                )
            except OSError:
                logger.debug("fix-history artifact write failed", exc_info=True)
        if not injected:
            return gaps
        logger.info(
            "fix-history: %d past security fixes → %d variant gaps, "
            "%d regression gaps",
            len(fixes), len(variant), len(regression),
        )
        by_key = {f"{g['file']}:{g['name']}": g for g in gaps}
        merged = list(gaps)
        for inj in injected:
            key = f"{inj['file']}:{inj['name']}"
            existing = by_key.get(key)
            if existing is not None:
                existing["priority_score"] = (
                    float(existing.get("priority_score") or 0.0)
                    + FIX_HISTORY_BOOST
                )
                existing["from_fix_history"] = True
                hyps = list(existing.get("injected_hypotheses") or [])
                hyps.extend(inj["injected_hypotheses"])
                existing["injected_hypotheses"] = hyps
            else:
                merged.append(inj)
                by_key[key] = inj
        return merged
    except Exception:
        logger.warning("fix-history mining failed — skipped", exc_info=True)
        return gaps
