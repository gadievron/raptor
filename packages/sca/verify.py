"""``raptor-sca verify`` — confirm a ``proposed/`` patch from ``fix`` actually
clears the findings it claimed to fix.

Workflow:

    raptor-sca <target> --out base
    raptor-sca fix --findings base/findings.json --out fix
    # `fix/proposed/` contains rewritten manifests
    raptor-sca verify <target> --proposed fix/proposed [--findings base/findings.json]

The verifier copies ``target`` into a scratch directory (vendored trees
skipped), overlays every file from ``proposed/`` at its corresponding
relative path, runs the analyse pipeline against the overlay, and
diffs the result against the original baseline. The exit code reflects
whether the patch is safe to apply:

    0 — proposed/ resolves the open advisories without introducing new ones
    1 — net regression: at least one new advisory is present after the
        patch (or some advisory the operator expected to clear didn't)
    2 — invalid arguments
    3 — internal error during pipeline run
    4 — verdict unavailable: an analyse run behind the delta carries the
        ``sca:scan_health:osv_lookup_degraded`` row, so advisory coverage
        was incomplete and "resolved"/"new" counts cannot be trusted

Outputs (under ``--out``):

    verify-before/findings.json   if we had to re-run analyse on the original
    verify-after/findings.json    analyse result on the overlay
    delta.md                      markdown summary of the change
    delta.json                    structured shape (same as `raptor-sca diff --json`)

Caveats:

- The whole target is copied so reachability gets accurate input. Skip
  the same vendored dirs discovery skips so node_modules / .venv /
  etc. don't blow up the copy. Large monorepos will pay the I/O cost.
- The analyse runs use the same cache as the original; OSV/KEV/EPSS
  hits are warm. No extra network beyond the first scan.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import JsonCache, load_json, save_json

# findings.json artifacts are RAPTOR-written run output — the
# findings-class budget.
_MAX_FINDINGS_BYTES = 64 * 1024 * 1024
from . import SCA_CACHE_ROOT
from .diff import compute_delta, md_cell
from .findings import severity_rank
from . import default_client
from .pipeline import RunOptions, run_sca

if TYPE_CHECKING:
    from core.http import HttpClient
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


# Vendored / build-output directories we don't bother copying.
# DERIVED from discovery's exclusion list, not hand-mirrored: the
# hand-copied version drifted (no ``.out``, ``.claude``,
# ``codeql_dbs`` / ``codeql_db``), so every verify overlay copied
# CodeQL database caches (10K+ files) and agent worktree state into
# the scratch tree on every run. Anything discovery skips, the
# overlay skips — a dir discovery won't scan contributes nothing to
# the verify delta.
from .discovery import EXCLUDED_DIR_NAMES as _DISCOVERY_EXCLUDED

_SKIP_DIR_NAMES: set[str] = set(_DISCOVERY_EXCLUDED)


def main(
    argv: Sequence[str],
    *,
    http: HttpClient | None = None,
    cache: JsonCache | None = None,
) -> int:
    from .cli import _configure_logging

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    target = Path(args.target).resolve()
    proposed = Path(args.proposed).resolve()
    if not target.is_dir():
        print(f"raptor-sca verify: target not a directory: {target}", file=sys.stderr)
        return 2
    if not proposed.is_dir():
        print(f"raptor-sca verify: --proposed dir not found: {proposed}",
              file=sys.stderr)
        return 2

    if cache is None:
        cache = JsonCache(root=Path(args.cache_root) if args.cache_root else SCA_CACHE_ROOT)
    if http is None:
        http = default_client()

    out_dir = _resolve_out(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    overlay_dir = out_dir / "overlay"
    try:
        shutil.rmtree(overlay_dir, ignore_errors=True)
        _copy_target(target, overlay_dir)
        applied = _apply_overlay(proposed, overlay_dir)
    except OSError as e:
        print(f"raptor-sca verify: cannot prepare overlay: {e}", file=sys.stderr)
        return 3
    if not applied:
        print(f"raptor-sca verify: --proposed dir contains no files; nothing to "
              f"verify ({proposed})", file=sys.stderr)
        return 2
    logger.info("raptor-sca verify: applied %d proposed file(s) to overlay",
                len(applied))

    options = RunOptions(
        offline=args.offline,
        no_cache=args.no_cache,
        cache_root=Path(args.cache_root) if args.cache_root else None,
        enable_kev=not args.no_kev,
        enable_epss=not args.no_epss,
    )

    after_dir = out_dir / "verify-after"
    try:
        after = run_sca(target=overlay_dir, output_dir=after_dir,
                        options=options, http=http, cache=cache)
    except Exception as e:                 # noqa: BLE001
        print(f"raptor-sca verify: analyse on overlay failed: {e}", file=sys.stderr)
        return 3

    if args.findings:
        before_findings = Path(args.findings).resolve()
        if not before_findings.exists():
            print(f"raptor-sca verify: --findings file not found: {before_findings}",
                  file=sys.stderr)
            return 2
    else:
        before_dir = out_dir / "verify-before"
        try:
            before = run_sca(target=target, output_dir=before_dir,
                             options=options, http=http, cache=cache)
        except Exception as e:             # noqa: BLE001
            print(f"raptor-sca verify: analyse on target failed: {e}", file=sys.stderr)
            return 3
        before_findings = before.findings_path

    try:
        rows_before = load_json(
            before_findings, strict=True, max_bytes=_MAX_FINDINGS_BYTES,
        )
        rows_after = load_json(
            after.findings_path, strict=True, max_bytes=_MAX_FINDINGS_BYTES,
        )
        if rows_before is None or rows_after is None:
            # Strict load_json soft-returns None for a MISSING file —
            # a vanished findings file must stay a hard error, not a
            # zero-delta success.
            raise FileNotFoundError(
                before_findings if rows_before is None
                else after.findings_path)
        delta = compute_delta(rows_before, rows_after)
    except (OSError, ValueError) as e:
        print(f"raptor-sca verify: cannot parse findings: {e}", file=sys.stderr)
        return 3

    summary, exit_code = _verdict(delta, severity_floor=args.fail_on_severity,
                                  applied=applied, overlay_root=overlay_dir)
    osv_degraded = (_rows_osv_degraded(rows_before)
                    or _rows_osv_degraded(rows_after))
    delta_md = _render_markdown(target, proposed, applied, delta, summary,
                                osv_degraded=osv_degraded)
    if osv_degraded:
        # A degraded analyse run cannot answer "does proposed/ resolve
        # the findings": failed OSV slots make advisories invisible, so
        # the delta reads them as resolved/absent and a network outage
        # would wave an unverified patch through this gate with exit 0.
        # Refuse to conclude — the artifacts above stay for inspection.
        delta_md += (
            "\n## OSV lookups degraded — verdict unavailable\n\n"
            "An analyse run behind this delta carries the "
            "`sca:scan_health:osv_lookup_degraded` row: advisory "
            "coverage was incomplete, so the resolved/new counts above "
            "cannot be trusted. Re-run when the network/OSV recovers.\n"
        )
        exit_code = 4
    from ._atomic import atomic_write_text
    atomic_write_text(out_dir / "delta.md", delta_md)
    save_json(
        out_dir / "delta.json",
        {
            "applied": [str(p) for p in applied],
            "summary": summary,
            "new": delta.new,
            "resolved": delta.resolved,
            "suppression_added": delta.suppression_added,
            "suppression_lifted": delta.suppression_lifted,
        },
    )

    sys.stdout.write(delta_md)
    if not delta_md.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()
    return exit_code


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca verify",
        description="Apply a proposed/ patch to a copy of the target, "
                    "re-run analyse, and report whether the patch resolves "
                    "the open findings without regression.",
    )
    p.add_argument("target", help="path to the project the proposed/ "
                                  "patch was generated against")
    p.add_argument("--proposed", required=True,
                   help="proposed/ directory from `raptor-sca fix`")
    p.add_argument("--findings",
                   help="baseline findings.json (default: re-run analyse "
                        "on the unmodified target)")
    p.add_argument("--out", help="output dir for verify-{before,after} + "
                                 "delta.md/delta.json")
    p.add_argument("--fail-on-severity", default="high",
                   choices=("info", "low", "medium", "high", "critical"),
                   help="severity threshold for the regression check "
                        "(default: high)")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--no-kev", action="store_true")
    p.add_argument("--no-epss", action="store_true")
    p.add_argument("--cache-root")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def _resolve_out(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Path("out") / f"sca-verify-{ts}"


# ---------------------------------------------------------------------------
# Overlay construction
# ---------------------------------------------------------------------------

def _copy_target(src: Path, dst: Path) -> None:
    """Mirror the target into ``dst``, skipping vendored / build dirs.

    Walks with ``os.walk(..., followlinks=False)`` — NOT ``rglob``:
    before Python 3.13 ``Path.rglob`` recurses THROUGH directory
    symlinks, so a hostile repo's ``docs -> ~/.ssh`` link pulled
    operator files into the overlay (which is then scanned and lands
    in delta artifacts); a cyclic symlink additionally recursed
    unboundedly. Files are copied through the resolvers' lstat-gated,
    size-bounded ``copy_regular_file`` so symlinked / non-regular /
    oversized entries are refused with a log line instead of followed.
    """
    from .resolvers._safe_io import copy_regular_file

    dst.mkdir(parents=True, exist_ok=False)
    src = src.resolve()
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        # In-place prune: neither descends into nor recreates the
        # vendored/build dirs. Symlinked directories are listed in
        # ``dirnames`` but never walked (followlinks=False) and never
        # recreated (only walked dirpaths get a mkdir below).
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
        cur = Path(dirpath)
        target_dir = dst / cur.relative_to(src)
        target_dir.mkdir(parents=True, exist_ok=True)
        for fn in filenames:
            path = cur / fn
            if path.is_symlink():
                continue        # never follow, silently (matches discovery)
            copy_regular_file(path, target_dir / fn)


def _apply_overlay(proposed: Path, overlay: Path) -> list[Path]:
    """Copy every file from ``proposed/`` onto its same-named relative
    path in the overlay. Returns the list of relative paths applied.
    """
    applied: list[Path] = []
    proposed = proposed.resolve()
    for src in sorted(proposed.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(proposed)
        dst = overlay / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        applied.append(rel)
    return applied


# ---------------------------------------------------------------------------
# Verdict + rendering
# ---------------------------------------------------------------------------

def _rows_osv_degraded(rows: Any) -> bool:
    """True when a findings.json row set carries the pipeline's
    OSV-degradation scan-health row (see ``pipeline`` step 4 — the row
    is the machine-readable "advisory coverage was incomplete" signal
    CI consumers key on)."""
    from .kinds import SCAN_HEALTH_PREFIX
    degraded_type = f"{SCAN_HEALTH_PREFIX}osv_lookup_degraded"
    if not isinstance(rows, list):
        return False
    return any(
        isinstance(r, dict) and r.get("vuln_type") == degraded_type
        for r in rows
    )

def _verdict(
    delta, *, severity_floor: str, applied: list[Path] | None = None,
    overlay_root: Path | None = None,
) -> tuple[dict[str, Any], int]:
    floor = severity_rank(severity_floor)
    triggering = [
        r for r in delta.new
        if severity_rank(r.get("severity", "info")) >= floor
    ]
    persistent_above = [
        r for r in delta.persistent
        if severity_rank(r.get("severity", "info")) >= floor
    ]
    # Advisories the operator expected to clear: persistent findings in
    # files the proposed/ patch actually rewrote. A high finding that
    # survives in a patched manifest means the patch did NOT resolve
    # the open advisories — the documented exit-1 contract. Persistent
    # findings in files the patch never touched don't gate (a targeted
    # ``fix --fix=<adv>`` must not fail on unrelated backlog).
    not_cleared = _not_cleared_in_applied(
        persistent_above, applied, overlay_root=overlay_root)
    summary = {
        "resolved": len(delta.resolved),
        "new": len(delta.new),
        "regressing_above_threshold": len(triggering),
        "persistent_above_threshold": len(persistent_above),
        "not_cleared_above_threshold": len(not_cleared),
        "suppression_added": len(delta.suppression_added),
        "suppression_lifted": len(delta.suppression_lifted),
        "severity_threshold": severity_floor,
    }
    exit_code = 1 if (triggering or not_cleared) else 0
    return summary, exit_code


def _not_cleared_in_applied(
    rows: list[dict[str, Any]], applied: list[Path] | None,
    *, overlay_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Subset of ``rows`` whose ``file`` is one of the overlaid
    (patched) relative paths. Finding rows carry overlay-absolute
    paths; ``applied`` carries proposed/-relative paths — relativise
    the row path against the overlay root and require EXACT set
    membership. A basename/suffix match here false-failed targeted
    ``fix --fix=<adv>`` runs on any monorepo where an untouched
    manifest's overlay path merely ends with a patched one's relative
    path (``x/sub/package.json`` vs applied ``sub/package.json``)."""
    if not applied:
        return []
    rels = {str(p) for p in applied}
    root = overlay_root.resolve() if overlay_root is not None else None
    out: list[dict[str, Any]] = []
    for r in rows:
        f = r.get("file")
        if not isinstance(f, str):
            continue
        rel = f
        if root is not None:
            try:
                rel = str(Path(f).resolve().relative_to(root))
            except (ValueError, OSError):
                # Row path outside the overlay (or already relative
                # and unresolvable against it): fall through to the
                # exact-string check below.
                rel = f
        if rel in rels:
            out.append(r)
    return out


def _render_markdown(
    target: Path,
    proposed: Path,
    applied: list[Path],
    delta,
    summary: dict[str, Any],
    *,
    osv_degraded: bool = False,
) -> str:
    lines: list[str] = []
    lines.append(f"# sca verify — `{target}` ⇐ `{proposed}`\n")
    if osv_degraded:
        # The human-readable verdict must reflect the degradation — a
        # "clean"/"pass" line above the exit-4 refusal section would
        # contradict it. The counts below stay for inspection.
        lines.append(
            "**Verdict: unavailable** — OSV lookups degraded during "
            "the analyse run(s); the resolved/new counts below cannot "
            "be trusted.\n"
        )
    elif summary["regressing_above_threshold"]:
        lines.append(
            f"**Verdict: regression** — proposed/ introduces "
            f"{summary['regressing_above_threshold']} new finding(s) "
            f"at or above {summary['severity_threshold']} severity.\n"
        )
    elif summary.get("not_cleared_above_threshold"):
        lines.append(
            f"**Verdict: not cleared** — "
            f"{summary['not_cleared_above_threshold']} finding(s) at or "
            f"above {summary['severity_threshold']} severity persist in "
            f"file(s) the patch rewrote.\n"
        )
    elif summary["new"]:
        lines.append(
            f"**Verdict: pass with caveats** — "
            f"{summary['new']} new finding(s) below the "
            f"{summary['severity_threshold']} threshold; "
            f"{summary['resolved']} resolved.\n"
        )
    else:
        lines.append(
            f"**Verdict: clean** — {summary['resolved']} finding(s) "
            "resolved, none regressed.\n"
        )

    lines.append(f"- Files in proposed/: **{len(applied)}**")
    lines.append(f"- Resolved: **{summary['resolved']}**")
    lines.append(f"- New: **{summary['new']}**")
    if summary["suppression_added"] or summary["suppression_lifted"]:
        lines.append(
            f"- Suppression added: **{summary['suppression_added']}**, "
            f"lifted: **{summary['suppression_lifted']}**"
        )
    lines.append("")

    if delta.new:
        lines.append("## New (after applying proposed/)")
        lines.append("")
        lines.append("| Severity | Finding | KEV | EPSS |")
        lines.append("|---|---|---|---|")
        lines.extend(_row_line(r) for r in delta.new)
        lines.append("")

    if delta.resolved:
        lines.append("## Resolved (cleared by proposed/)")
        lines.append("")
        lines.append("| Severity | Finding | KEV | EPSS |")
        lines.append("|---|---|---|---|")
        lines.extend(_row_line(r) for r in delta.resolved)
        lines.append("")
    return "\n".join(lines) + "\n"


def _row_line(r: dict[str, Any]) -> str:
    # Every interpolated cell is findings.json content that downstream
    # carries registry / manifest bytes — the same trust boundary
    # ``diff.md_cell`` was built for. Unescaped pipes / newlines /
    # ``</details>`` in a crafted package name or advisory id would
    # break the delta.md table, forge report rows, or land terminal
    # escapes on stdout.
    sev = md_cell((r.get("severity") or "info").title())
    sca = r.get("sca") or {}
    eco = sca.get("ecosystem") or ""
    name = sca.get("name") or ""
    version = sca.get("version") or ""
    adv = sca.get("advisory") or {}
    adv_id = (adv.get("id") or "") if isinstance(adv, dict) else ""
    finding = md_cell(f"{eco}:{name}@{version} {adv_id}".strip())
    kev = "yes" if sca.get("in_kev") else ""
    epss_val = sca.get("epss")
    epss = f"{epss_val:.2f}" if isinstance(epss_val, (int, float)) else ""
    return f"| {sev} | {finding} | {kev} | {epss} |"


__all__ = ["main"]
