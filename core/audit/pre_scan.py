"""Opt-in bounded semgrep baseline pass for /audit.

When no prior scan SARIF exists — neither in the audit run's own
``scan/`` dir nor in sibling runs — the SARIF corroboration channels
(sarif-clean budget reallocation, per-gap corroboration rescues,
"ran and was silent") starve. With ``--pre-scan`` the audit runs ONE
bounded semgrep pass over the scoped target using RAPTOR's local rule
library (no registry fetch, no network) and writes the SARIF into
``<out_dir>/scan/`` where ``SarifCache.from_directory`` already looks.

Reuses the existing scan machinery (``packages.semgrep.runner``) —
the same runner the sweep engine and negative-control checks use.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# One whole-target semgrep pass; generous but bounded.
PRE_SCAN_TIMEOUT_S = 900
# Scoped runs get one pass per scope path, capped.
MAX_SCOPE_TARGETS = 5

PRE_SCAN_SARIF_PREFIX = "semgrep_prescan"


def _scan_targets(
    target_path: Path,
    scope: list[str] | None,
) -> list[tuple[str, Path]]:
    """Resolve (label, path) scan targets under containment."""
    target_resolved = Path(target_path).resolve()
    if not scope:
        return [("root", target_resolved)]
    targets: list[tuple[str, Path]] = []
    for entry in scope[:MAX_SCOPE_TARGETS]:
        candidate = (target_resolved / str(entry)).resolve()
        try:
            candidate.relative_to(target_resolved)
        except ValueError:
            logger.warning("pre-scan: scope %r escapes target — skipped", entry)
            continue
        if candidate.exists():
            label = str(entry).replace("/", "_").strip("_") or "root"
            targets.append((label, candidate))
    return targets or [("root", target_resolved)]


def run_baseline_pre_scan(
    target_path: Path,
    out_dir: Path,
    *,
    scope: list[str] | None = None,
    timeout: int = PRE_SCAN_TIMEOUT_S,
    rules_dir: Path | None = None,
    run_rule_fn: Any = None,
) -> list[Path]:
    """Run the bounded baseline pass; returns written SARIF paths.

    Empty list when semgrep or the local rule library is unavailable,
    or the pass produced no SARIF. Never raises.
    """
    try:
        from packages.semgrep.runner import is_available, run_rule
    except ImportError:
        logger.debug("pre-scan: semgrep runner unavailable", exc_info=True)
        return []
    run_rule_fn = run_rule_fn or run_rule

    if rules_dir is None:
        try:
            from core.config import RaptorConfig

            rules_dir = Path(RaptorConfig.SEMGREP_RULES_DIR)
        except Exception:
            logger.debug("pre-scan: config unavailable", exc_info=True)
            return []
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        logger.info("pre-scan: no local rule library at %s — skipped", rules_dir)
        return []
    if run_rule_fn is run_rule and not is_available():
        logger.info("pre-scan: semgrep not installed — skipped")
        return []

    scan_dir = Path(out_dir) / "scan"
    written: list[Path] = []
    for label, target in _scan_targets(Path(target_path), scope):
        try:
            result = run_rule_fn(
                target,
                str(rules_dir),
                name=f"prescan_{label}",
                timeout=timeout,
            )
        except Exception:
            logger.warning("pre-scan failed for %s", target, exc_info=True)
            continue
        sarif_text = getattr(result, "sarif", "") or ""
        if not sarif_text:
            errors = getattr(result, "errors", None)
            if errors:
                logger.info("pre-scan: %s", "; ".join(map(str, errors))[:200])
            continue
        scan_dir.mkdir(parents=True, exist_ok=True)
        path = scan_dir / f"{PRE_SCAN_SARIF_PREFIX}_{label}.sarif"
        try:
            path.write_text(sarif_text, encoding="utf-8")
        except OSError:
            logger.debug("pre-scan: SARIF write failed", exc_info=True)
            continue
        written.append(path)
        logger.info(
            "pre-scan: baseline SARIF written for %s → %s "
            "(%d findings)",
            target,
            path.name,
            len(getattr(result, "findings", []) or []),
        )
    return written
