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
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from core.json import JsonCache
from . import SCA_CACHE_ROOT
from .diff import compute_delta
from .findings import severity_rank
from core.http import HttpClient
from . import default_client
from .pipeline import RunOptions, run_sca

logger = logging.getLogger(__name__)


# Vendored / build-output directories we don't bother copying.
# Mirrors discovery.EXCLUDED_DIR_NAMES and the supply-chain artefact
# walk's skiplist.
_SKIP_DIR_NAMES: Set[str] = {
    "node_modules", "vendor", "bower_components",
    ".git", ".svn", ".hg",
    "target", "build", "dist", "out", "_build",
    "__pycache__", ".tox", ".venv", "venv", ".env",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".gradle", ".idea", ".vscode",
    ".angular", ".next", ".nuxt", ".cache", ".turbo",
    "site-packages",
}


def main(
    argv: Sequence[str],
    *,
    http: Optional[HttpClient] = None,
    cache: Optional[JsonCache] = None,
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
    if overlay_dir.exists():
        shutil.rmtree(overlay_dir)
    try:
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

    rows_before = json.loads(before_findings.read_text(encoding="utf-8"))
    rows_after = json.loads(after.findings_path.read_text(encoding="utf-8"))
    delta = compute_delta(rows_before, rows_after)

    summary, exit_code = _verdict(delta, severity_floor=args.fail_on_severity)
    delta_md = _render_markdown(target, proposed, applied, delta, summary)
    (out_dir / "delta.md").write_text(delta_md, encoding="utf-8")
    (out_dir / "delta.json").write_text(
        json.dumps({
            "applied": [str(p) for p in applied],
            "summary": summary,
            "new": delta.new,
            "resolved": delta.resolved,
            "suppression_added": delta.suppression_added,
            "suppression_lifted": delta.suppression_lifted,
        }, indent=2),
        encoding="utf-8",
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


def _resolve_out(explicit: Optional[str]) -> Path:
    if explicit:
        return Path(explicit).resolve()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Path("out") / f"sca-verify-{ts}"


# ---------------------------------------------------------------------------
# Overlay construction
# ---------------------------------------------------------------------------

def _copy_target(src: Path, dst: Path) -> None:
    """Mirror the target into ``dst``, skipping vendored / build dirs.

    ``shutil.copytree(..., ignore=...)`` would be neat but its ``ignore``
    callback sees lists of names and we want a name-based predicate; the
    direct walk is simpler and lets us handle symlinks the same way
    discovery does (don't follow).
    """
    dst.mkdir(parents=True, exist_ok=False)
    src = src.resolve()
    for path in src.rglob("*"):
        if any(part in _SKIP_DIR_NAMES for part in path.relative_to(src).parts):
            continue
        target_path = dst / path.relative_to(src)
        if path.is_dir() and not path.is_symlink():
            target_path.mkdir(parents=True, exist_ok=True)
        elif path.is_file() and not path.is_symlink():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target_path)
        # symlinks: skip (we don't want to follow)


def _apply_overlay(proposed: Path, overlay: Path) -> List[Path]:
    """Copy every file from ``proposed/`` onto its same-named relative
    path in the overlay. Returns the list of relative paths applied.
    """
    applied: List[Path] = []
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

def _verdict(
    delta, *, severity_floor: str,
) -> "tuple[Dict[str, Any], int]":
    floor = severity_rank(severity_floor)
    triggering = [
        r for r in delta.new
        if severity_rank(r.get("severity", "info")) >= floor
    ]
    summary = {
        "resolved": len(delta.resolved),
        "new": len(delta.new),
        "regressing_above_threshold": len(triggering),
        "suppression_added": len(delta.suppression_added),
        "suppression_lifted": len(delta.suppression_lifted),
        "severity_threshold": severity_floor,
    }
    exit_code = 1 if triggering else 0
    return summary, exit_code


def _render_markdown(
    target: Path,
    proposed: Path,
    applied: List[Path],
    delta,
    summary: Dict[str, Any],
) -> str:
    lines: List[str] = []
    lines.append(f"# sca verify — `{target}` ⇐ `{proposed}`\n")
    if summary["regressing_above_threshold"]:
        lines.append(
            f"**Verdict: regression** — proposed/ introduces "
            f"{summary['regressing_above_threshold']} new finding(s) "
            f"at or above {summary['severity_threshold']} severity.\n"
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
        for r in delta.new:
            lines.append(_row_line(r))
        lines.append("")

    if delta.resolved:
        lines.append("## Resolved (cleared by proposed/)")
        lines.append("")
        lines.append("| Severity | Finding | KEV | EPSS |")
        lines.append("|---|---|---|---|")
        for r in delta.resolved:
            lines.append(_row_line(r))
        lines.append("")
    return "\n".join(lines) + "\n"


def _row_line(r: Dict[str, Any]) -> str:
    sev = (r.get("severity") or "info").title()
    sca = r.get("sca") or {}
    eco = sca.get("ecosystem") or ""
    name = sca.get("name") or ""
    version = sca.get("version") or ""
    adv = sca.get("advisory") or {}
    adv_id = adv.get("id") if isinstance(adv, dict) else ""
    finding = f"{eco}:{name}@{version} {adv_id}".strip()
    kev = "yes" if sca.get("in_kev") else ""
    epss = f"{sca['epss']:.2f}" if sca.get("epss") is not None else ""
    return f"| {sev} | {finding} | {kev} | {epss} |"


__all__ = ["main"]
