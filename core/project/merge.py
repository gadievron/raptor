"""Merge findings and SARIF across multiple run directories.

Combines findings.json, SARIF files, and artefacts from multiple runs
into a single output directory. Deduplicates findings by (file, function, line),
latest wins.
"""

import hashlib as _hashlib
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List

from core.json import save_json
from core.logging import get_logger
from core.project.findings_utils import count_vulns as _count_vulns
from core.project.findings_utils import dedup_key as _dedup_key
from core.project.findings_utils import load_findings_from_dir as _load_findings_from_dir
from core.sarif.parser import merge_sarif

logger = get_logger()

# Files that the merge logic knows how to handle directly.
KNOWN_FILES = {
    "findings.json",
    ".raptor-run.json",
    "checklist.json",
    "validation-report.md",
    "agentic-report.md",
    "summary.txt",
    "diagrams.md",
    "scan_metrics.json",
    "scan-manifest.json",
    "verification.json",
    "orchestrated_report.json",
    "raptor_agentic_report.json",
}

# Patterns for known file types (matched by extension).
KNOWN_EXTENSIONS = {".sarif", ".exit", ".stderr.log"}


def _is_known_file(name: str) -> bool:
    """Check if a filename is in the known set or matches known extensions."""
    if name in KNOWN_FILES:
        return True
    for ext in KNOWN_EXTENSIONS:
        if name.endswith(ext):
            return True
    return False


def _extract_date_from_dir(run_dir: Path) -> str:
    """Extract a date-like suffix from a run directory name for collision renaming.

    Fallback: when no date pattern matches, derive a short
    deterministic suffix from a SHA-256 of the dir name. Pre-fix
    the fallback returned `run_dir.name` verbatim, which:

    * could be arbitrarily long
      (`scan_libxml_v2_attempt_3_postfix_with_extra_notes`) — when
      composed into a `<finding-id>__<suffix>` collision-renamed
      key, the resulting filename blew past `NAME_MAX` (255 on
      ext4) and the rename failed
    * leaked free-form operator notes from the run dir name into
      collision-renamed file paths, where they showed up in
      report listings the operator didn't expect
    * collided across two runs whose dir names happened to start
      with the same prefix once the date-pattern fallback was
      missed (rare but possible with hand-named dirs)

    The 12-char hash is deterministic (same input → same output,
    so collision-renamed files stay stable across re-merges) and
    short enough to not bloat downstream filenames.
    """
    match = re.search(r'(\d{8}[-_]\d{6})', run_dir.name)
    if match:
        return match.group(1)
    match = re.search(r'(\d{8})', run_dir.name)
    if match:
        return match.group(1)
    return _content_suffix(run_dir.name)


def _content_suffix(name: str) -> str:
    """Short SHA-256 prefix for collision-rename suffixes."""
    return _hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest()[:12]


def _uniquify(parent: Path, stem: str, date_tag: str, suffix: str) -> Path:
    """Build a non-colliding path under ``parent`` of shape
    ``<stem>-<date_tag><suffix>``, appending a numeric counter
    if the date-tagged path already exists.

    Caller has already checked the bare path collides and computed
    the date-tag. We add a `.N` counter (1-indexed) before the
    suffix on second+ collision so neither file ``shutil.copy2``
    nor dir ``shutil.copytree`` silently overwrites/skips the
    earlier-renamed entry.
    """
    base = f"{stem}-{date_tag}"
    candidate = parent / f"{base}{suffix}"
    if not candidate.exists():
        return candidate
    n = 1
    while True:
        candidate = parent / f"{base}.{n}{suffix}"
        if not candidate.exists():
            return candidate
        n += 1
        if n > 1000:
            # Pathological: 1000 collisions on the same stem+date
            # almost certainly indicates a bug in caller. Fail loud
            # rather than spinning.
            raise RuntimeError(
                f"_uniquify: 1000 collisions on {base!r} — refusing to spin"
            )


def _finding_key(finding: Dict[str, Any]) -> tuple:
    """Dedup key for a finding: (file, function, line, vuln_type).

    Aligns with `count_vulns` (which groups by `(file, function, vuln_type)`)
    so the merged-list raw count and the vuln count agree on the
    "are these the same finding?" question:

    * Two findings at the same `(file, function, line)` with
      DIFFERENT `vuln_type` are now treated as distinct entries
      (raw=2). Pre-fix they collided on the line-only dedup key
      so one of the two was overwritten by `_status_rank` tie-
      break — and `count_vulns` then reported `1 vuln` against
      a `1 finding` raw count, hiding the second vulnerability
      class entirely.
    * Two findings with the same `vuln_type` at different lines
      stay distinct in the raw count (different lines), and
      `count_vulns` groups them as one logical vuln — so the
      operator sees `2 findings (1 vuln)`, which correctly
      reflects "one logical issue manifesting at two
      locations".

    The `_dedup_key` helper in `findings_utils` keeps its
    line-only signature for consumers that want strict
    location-based dedup; merge has its own slightly stricter
    key that keeps vuln-class information visible.
    """
    base = _dedup_key(finding)
    return base + (finding.get("vuln_type", ""),)


# Status progression: higher rank = more information about the finding.
# When merging across runs, prefer the finding with the highest-ranked status
# so that a correct ruling from one run isn't overwritten by stale data from
# another run (e.g. one that hit a pipeline bug or where the LLM got it wrong).
_STATUS_RANK = {
    "exploitable": 7,
    "confirmed_constrained": 6,
    "confirmed_blocked": 6,
    "confirmed_unverified": 5,
    "confirmed": 5,
    "ruled_out": 4,
    "disproven": 4,
    "false_positive": 4,
    "test_code": 4,
    "dead_code": 4,
    "mitigated": 4,
    "unreachable": 4,
    "poc_success": 3,
    "not_disproven": 2,
}


def _status_rank(finding: Dict[str, Any]) -> int:
    """Return a rank for how far a finding has progressed through validation."""
    status = finding.get("final_status") or finding.get("status") or ""
    return _STATUS_RANK.get(status, 0)


def merge_findings(run_dirs: List[Path]) -> List[Dict[str, Any]]:
    """Merge findings from multiple runs. Deduplicate by (file, function, line).

    When the same finding appears in multiple runs, prefer the version with the
    most progressed status (e.g. "confirmed" beats "not_disproven"). Among equal
    statuses, the latest run wins.

    Args:
        run_dirs: Ordered list of run directories (later entries override earlier).

    Returns:
        Deduplicated list of findings.
    """
    merged: Dict[tuple, Dict[str, Any]] = {}

    for run_dir in run_dirs:
        findings = _load_findings_from_dir(Path(run_dir))
        for finding in findings:
            key = _finding_key(finding)
            existing = merged.get(key)
            if existing is None or _status_rank(finding) >= _status_rank(existing):
                merged[key] = finding

    return list(merged.values())


def verify_merge(merged_findings: List, source_findings_count: int,
                 unique_count: int) -> bool:
    """Verify merged count >= expected deduplicated count.

    Args:
        merged_findings: The merged findings list.
        source_findings_count: Total findings across all source runs.
        unique_count: Expected number of unique finding IDs.

    Returns:
        True if the merge looks valid.
    """
    return len(merged_findings) >= unique_count


def merge_runs(run_dirs: List[Path], output_dir: Path) -> Dict[str, Any]:
    """Merge findings and artefacts from multiple run directories.

    Args:
        run_dirs: Ordered list of run directories to merge.
        output_dir: Destination directory for merged output.

    Returns:
        Stats dict with merge summary.
    """
    run_dirs = [Path(d) for d in run_dirs]
    output_dir = Path(output_dir)

    # Safety: don't merge into an existing run directory
    if output_dir.exists() and any((output_dir / f).exists() for f in ("findings.json", ".raptor-run.json")):
        raise ValueError(f"Output directory {output_dir} already contains data. Use an empty directory.")

    if output_dir.resolve() in {d.resolve() for d in run_dirs}:
        raise ValueError("output_dir cannot be one of the source run directories")

    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Merge findings ---
    total_findings = 0
    all_keys: set = set()
    for run_dir in run_dirs:
        findings = _load_findings_from_dir(run_dir)
        total_findings += len(findings)
        for f in findings:
            all_keys.add(_finding_key(f))

    merged = merge_findings(run_dirs)
    unique_count = len(all_keys)

    if not verify_merge(merged, total_findings, unique_count):
        logger.warning(
            f"Merge verification warning: {len(merged)} merged findings "
            f"< {unique_count} unique IDs"
        )

    if merged:
        save_json(output_dir / "findings.json", {"findings": merged})

    # --- Merge SARIF ---
    sarif_paths: List[str] = []
    for run_dir in run_dirs:
        for sarif_file in run_dir.glob("*.sarif"):
            sarif_paths.append(str(sarif_file))

    sarif_files_merged = len(sarif_paths)
    if sarif_paths:
        merged_sarif = merge_sarif(sarif_paths)
        save_json(output_dir / "merged.sarif", merged_sarif)

    # --- Copy unknown artefacts ---
    artefacts_preserved = 0
    for run_dir in run_dirs:
        if not run_dir.is_dir():
            continue
        for item in run_dir.iterdir():
            if item.is_dir():
                continue
            if _is_known_file(item.name):
                continue

            dest = output_dir / item.name
            if dest.exists():
                # Rename on collision: append source date, then a
                # numeric counter if the date-tagged path itself
                # collides. Pre-fix the date-only rename collided
                # silently when two source runs shared the same
                # date_tag (two runs the same day, or two runs
                # sharing a content-derived hash from
                # `_extract_date_from_dir`'s fallback) — `shutil.copy2`
                # then OVERWROTE the earlier-renamed file without
                # warning, losing the first run's artefact.
                stem = item.stem
                suffix = item.suffix
                date_tag = _extract_date_from_dir(run_dir)
                dest = _uniquify(output_dir, stem, date_tag, suffix)

            shutil.copy2(str(item), str(dest))
            artefacts_preserved += 1

    # Copy unknown subdirectories
    for run_dir in run_dirs:
        if not run_dir.is_dir():
            continue
        for item in run_dir.iterdir():
            if not item.is_dir():
                continue
            if item.name.startswith("."):
                continue
            dest = output_dir / item.name
            if dest.exists():
                # Rename on collision: same date-tag-then-counter
                # uniquifier as the file path above. Pre-fix the
                # date-only rename collided with the previous
                # iteration's renamed dir; the `if not dest.exists()`
                # guard then SILENTLY DROPPED the copy — the source
                # dir's content disappeared from the merged output
                # entirely.
                date_tag = _extract_date_from_dir(run_dir)
                dest = _uniquify(output_dir, item.name, date_tag, "")
            shutil.copytree(str(item), str(dest))
            artefacts_preserved += 1

    vuln_count = _count_vulns(merged)

    stats = {
        "runs_merged": len(run_dirs),
        "total_findings": total_findings,
        "unique_findings": len(merged),
        "unique_vulns": vuln_count,
        "sarif_files_merged": sarif_files_merged,
        "artefacts_preserved": artefacts_preserved,
    }

    findings_label = f"{len(merged)} findings"
    if vuln_count != len(merged):
        findings_label = f"{vuln_count} findings"

    logger.info(
        f"Merged {len(run_dirs)} runs: {findings_label}, "
        f"{sarif_files_merged} SARIF files, {artefacts_preserved} artefacts"
    )

    return stats
