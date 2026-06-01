"""Shared CLI plumbing for binary-oracle ``--binary`` / ``--binary-auto``
/ ``--binary-edges`` flags across ``raptor_codeql.py`` + ``raptor_agentic.py``.

Adversarial review P1-D-4: both CLIs duplicated ~50 LOC of wiring and
were diverging in subtle places (print messages, target_kind resolution,
how active-project binaries were layered in, what `added` actually
counted). Pull the canonical wiring here and have both CLIs call it.

Also fixes:
  * P1-D-1 — explicit ``--binary`` paths are validated up-front (file
    must exist) rather than silently filtered deep inside the
    enrichment pass.
  * P1-D-3 — auto-detect coverage extended to ``out/``, ``dist/``,
    ``bin/``, ``Debug/``, ``Release/``, ``target/*/release``,
    ``bazel-bin``, ``builddir/`` so common Bazel / Meson / Visual
    Studio / Xcode / Rust-cross / Go / Java / generic-dist layouts
    aren't silently skipped.
  * P1-D-6 — auto-detect cap-truncation is warned loudly so the
    operator sees they need to pass ``--binary`` explicitly when
    they have more than the cap.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


def add_binary_args(parser, *, include_edges: bool = True) -> None:
    """Attach the three binary-oracle flags to an argparse parser.
    Both CLIs (raptor_codeql.py + raptor_agentic.py) declare them
    identically; call this helper to keep them in sync."""
    parser.add_argument(
        "--binary", action="append", default=None,
        help=(
            "Path to a debug binary for binary-oracle enrichment of "
            "the inventory (DWARF-joined per-function classification). "
            "Repeatable for hybrid targets (e.g. ``--target-kind=hybrid``"
            ": ``--binary lib.so --binary app``); a function is then "
            "classified ``absent`` only when EVERY declared binary "
            "lacks it. The path is validated at CLI parse time — a "
            "typo errors out rather than silently dropping the binary."
        ),
    )
    parser.add_argument(
        "--binary-auto", action="store_true",
        help=(
            "Auto-detect debug binaries under the target tree's common "
            "build dirs (build/, target/release/, cmake-build-*/, "
            "bazel-bin/, _build/, builddir/, Debug/, Release/, out/, "
            "dist/, bin/) and pass each to binary-oracle. Combined "
            "with explicit ``--binary`` values (auto-detected are "
            "appended). Stripped binaries fall back to symbol-only "
            "tier with conservative ``earns_suppression`` downgrade."
        ),
    )
    if include_edges:
        parser.add_argument(
            "--binary-edges", action="store_true",
            help=(
                "Inc 2b Tier 1 opt-in: extract direct call edges from "
                "each --binary (via r2) and annotate inventory items "
                "with binary-found callers. Affirmative reachability "
                "evidence — a function with binary-confirmed callers "
                "gets the ``binary_call_edge`` REACHABLE verdict. "
                "Slow on big binaries (~10-30s per binary). Requires "
                "--binary or --binary-auto."
            ),
        )


def _validate_explicit_paths(
    paths: Optional[List[str]], parser=None,
) -> List[Path]:
    """Resolve operator-supplied ``--binary`` paths AND verify each
    file exists. A typo'd path currently dies silently inside the
    enrichment pass (``Path.resolve()`` doesn't require existence);
    fail-fast here so the operator sees the typo immediately."""
    if not paths:
        return []
    resolved: List[Path] = []
    for p in paths:
        rp = Path(p).expanduser().resolve()
        if not rp.is_file():
            msg = (f"--binary path does not exist or is not a file: "
                   f"{p} (resolved to {rp})")
            if parser is not None:
                parser.error(msg)
            else:
                raise FileNotFoundError(msg)
        resolved.append(rp)
    return resolved


def _autodetect_binaries(
    repo: Path, target_kind: str,
) -> List[Path]:
    """Walk the target tree for debug binaries; warn the operator if
    we hit the result cap (they likely want to pass ``--binary``
    explicitly) or find nothing."""
    from core.inventory.binary_oracle_autodetect import (
        DEFAULT_MAX_RESULTS, detect_binaries,
    )
    detected = detect_binaries(repo, target_kind)
    if detected:
        print(f"--binary-auto detected {len(detected)} binary(s):")
        for b in detected:
            print(f"  {b}")
        if len(detected) >= DEFAULT_MAX_RESULTS:
            logger.warning(
                "--binary-auto: result cap (%d) reached — there may be "
                "additional debug binaries under this target tree that "
                "auto-detect did not return. Pass --binary explicitly "
                "to include specific binaries beyond the cap.",
                DEFAULT_MAX_RESULTS,
            )
    else:
        print(
            "--binary-auto: no debug binaries found under build/, "
            "target/release/, cmake-build-*/, bazel-bin/, etc. "
            "Build the target first or pass --binary explicitly.",
        )
    return detected


def _project_binaries() -> Tuple[List[Path], Optional[str]]:
    """Layer in any binaries persisted on the active project. Returns
    ``(paths, project_name)``. Best-effort — a missing project /
    schema mismatch returns ``([], None)`` rather than crashing the
    run."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = mgr.get_active()
        if not active:
            return [], None
        proj = mgr.load(active)
        if not proj or not getattr(proj, "binaries", None):
            return [], active
        return [Path(b).expanduser().resolve() for b in proj.binaries], active
    except Exception:  # noqa: BLE001
        return [], None


def resolve_binary_paths(args, repo: Path, target_kind: str,
                         parser=None) -> Tuple[str, ...]:
    """Compose the final tuple of binary paths from all three
    sources: ``--binary`` (explicit), ``--binary-auto`` (detected),
    and the active project's persisted ``binaries``. Deduplicated,
    order preserved (explicit first, then auto, then project).

    Always returns SOMETHING — even an empty tuple — so the caller
    can unconditionally assign to ``RaptorConfig.BINARY_ORACLE_PATHS``
    and never leak a prior run's value (adversarial review P0-117)."""
    seen: dict = {}  # path → True for stable de-dupe (insertion order)

    for p in _validate_explicit_paths(
            getattr(args, "binary", None), parser=parser):
        seen.setdefault(str(p), True)

    if getattr(args, "binary_auto", False):
        for p in _autodetect_binaries(repo, target_kind):
            seen.setdefault(str(p), True)

    proj_paths, proj_name = _project_binaries()
    added = 0
    for p in proj_paths:
        if str(p) not in seen:
            seen[str(p)] = True
            added += 1
    if proj_name and added:
        print(f"--project '{proj_name}' contributes {added} binary(s) "
              f"from /project binary store.")

    return tuple(seen.keys())


def resolve_target_kind(args) -> str:
    """Same env-var / arg precedence both CLIs used. Env wins so
    ``RAPTOR_TARGET_KIND`` set in CI / scripts can override CLI."""
    from core.config import RaptorConfig
    return (os.environ.get(RaptorConfig.ENV_TARGET_KIND)
            or getattr(args, "target_kind", "auto") or "auto")


def apply_to_config(args, repo: Path, parser=None) -> Tuple[str, ...]:
    """Resolve binary paths AND mutate ``RaptorConfig``. Single call
    site for both CLIs so they can't diverge."""
    from core.config import RaptorConfig
    paths = resolve_binary_paths(
        args, repo, resolve_target_kind(args), parser=parser,
    )
    # ALWAYS assign — never gate on truthiness — so a prior run's
    # value cannot leak into this one in long-lived processes
    # (Claude Code, library use, chained pytest).
    RaptorConfig.BINARY_ORACLE_PATHS = paths
    RaptorConfig.BINARY_ORACLE_EDGES = bool(
        getattr(args, "binary_edges", False))
    return paths


__all__ = [
    "add_binary_args",
    "apply_to_config",
    "resolve_binary_paths",
    "resolve_target_kind",
]
