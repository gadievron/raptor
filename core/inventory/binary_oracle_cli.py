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
    parser.add_argument(
        "--no-binary-oracle", action="store_true",
        dest="no_binary_oracle",
        help=(
            "Disable binary-oracle reachability filtering for this run. "
            "Default behaviour auto-detects locally-built debug binaries "
            "(untracked by git — repo-committed binaries skipped as "
            "unverified provenance) and uses them to filter dead-code "
            "findings. Pass this flag for library-only targets with no "
            "main binary, runs where you want every finding unfiltered "
            "for review, or when a build mismatch is causing the oracle "
            "to over-suppress. Overrides --binary / --binary-auto with "
            "a warning if combined."
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


def _filter_locally_built(
    repo: Path, candidates: List[Path],
) -> Tuple[List[Path], List[Path]]:
    """Split ``candidates`` into ``(locally_built, repo_committed)``
    using git's tracking-set as the provenance signal.

    ``git ls-files --error-unmatch`` returns 0 when a path is tracked
    (i.e., the binary came with the source — could be attacker-
    controlled if the repo is untrusted, or just stale if the upstream
    last rebuilt months ago). Untracked candidates are almost
    certainly the operator's own build output: a fresh ``make`` /
    ``cargo build`` produces gitignored artifacts under ``build/`` /
    ``target/release/`` / etc.

    Why this matters: binary-oracle uses ``absent`` verdicts to
    suppress findings from /agentic analysis. A planted or stale
    binary that's missing functions silently steers RAPTOR away from
    code the attacker doesn't want analysed — the
    1952/1952 + 187/187 precision calibration was measured on
    harness-built binaries and doesn't extend to repo-committed ones.

    When the target isn't a git repo at all (extracted tarball,
    monorepo without git), provenance is unverifiable: return
    ``([], candidates)`` — the operator can explicitly opt back in
    via ``--binary`` or ``--binary-auto`` when they know their builds
    are trustworthy.
    """
    if not candidates:
        return [], []
    import subprocess
    try:
        # ``git ls-files --error-unmatch <path>...`` returns non-zero
        # if ANY path is untracked. Run per-path so we can split.
        # Cheap: cap=8 means ≤8 git invocations.
        locally_built: List[Path] = []
        repo_committed: List[Path] = []
        for c in candidates:
            try:
                rel = c.resolve().relative_to(repo.resolve())
            except ValueError:
                # Candidate escapes the repo (symlink target outside);
                # autodetect already filters these but defend in depth.
                continue
            proc = subprocess.run(
                ["git", "-C", str(repo), "ls-files",
                 "--error-unmatch", "--", str(rel)],
                capture_output=True, text=True, check=False,
            )
            if proc.returncode == 0:
                repo_committed.append(c)
            elif proc.returncode == 1:
                # ``--error-unmatch`` returns 1 specifically for
                # untracked-but-present paths. Other non-zero codes
                # mean git failed (not a repo, command-not-found,
                # permissions) — in that case we can't verify
                # provenance, treat the candidate as repo_committed
                # so the conservative path fires.
                stderr = (proc.stderr or "").lower()
                if "did not match" in stderr or "no such file" in stderr:
                    locally_built.append(c)
                else:
                    repo_committed.append(c)
            else:
                # Not a git repo, or git unavailable / errored.
                # Treat ALL candidates as unverifiable for this run.
                return [], candidates
        return locally_built, repo_committed
    except FileNotFoundError:
        # ``git`` not on PATH — provenance unverifiable.
        return [], candidates


def _autodetect_binaries(
    repo: Path, target_kind: str, *, explicit: bool = False,
) -> List[Path]:
    """Walk the target tree for debug binaries, then filter to those
    the operator built locally (untracked by git). Repo-committed
    binaries are dropped — they could be attacker-planted or stale
    pre-built artifacts that lie about what functions are present,
    silently steering binary-oracle's ``absent`` verdict to suppress
    findings the operator should see.

    ``explicit`` controls the verbosity of the nothing-found path:
    the louder message fires when the operator asked via
    ``--binary-auto``; the soft hint fires on the default-on path so
    library-only / unbuildable / tarball-extracted targets don't see
    noise on every run.
    """
    from core.inventory.binary_oracle_autodetect import (
        DEFAULT_MAX_RESULTS, detect_binaries,
    )
    detected = detect_binaries(repo, target_kind)
    locally_built, repo_committed = _filter_locally_built(repo, detected)
    if repo_committed:
        logger.warning(
            "binary-oracle: %d repo-committed binary(s) ignored "
            "(provenance unverified — could be planted or stale): %s. "
            "Pass --binary <path> to use them anyway when you know "
            "they were built fresh.",
            len(repo_committed),
            ", ".join(str(p) for p in repo_committed[:3])
            + ("..." if len(repo_committed) > 3 else ""),
        )
    if locally_built:
        print(
            f"binary-oracle: auto-detected {len(locally_built)} "
            f"locally-built binary(s):"
        )
        for b in locally_built:
            print(f"  {b}")
        if len(locally_built) >= DEFAULT_MAX_RESULTS:
            logger.warning(
                "binary-oracle: auto-detect result cap (%d) reached — "
                "there may be additional debug binaries under this "
                "target tree that auto-detect did not return. Pass "
                "--binary explicitly to include specific binaries "
                "beyond the cap.",
                DEFAULT_MAX_RESULTS,
            )
    elif explicit:
        print(
            "binary-oracle: no locally-built debug binaries found "
            "under build/, target/release/, cmake-build-*/, bazel-bin/, "
            "etc. Build the target first or pass --binary explicitly.",
        )
    else:
        print(
            "binary-oracle: no locally-built debug binaries detected; "
            "running unfiltered. Build the target or pass --binary "
            "<path> for dead-code filtering (--no-binary-oracle to silence).",
        )
    return locally_built


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
    """Compose the final tuple of binary paths from three sources:
    ``--binary`` (explicit), auto-detect, and the active project's
    persisted ``binaries``. Deduplicated, order preserved (explicit
    first, then auto, then project).

    Default behaviour (no flags): auto-detect runs and filters to
    locally-built binaries only (untracked by git; repo-committed
    binaries get dropped as unverified provenance). Explicit
    ``--binary <path>`` suppresses default auto-detect — operator
    told us exactly what they want.

    Opt-out: ``--no-binary-oracle`` returns the empty tuple — the
    inventory sees no oracle paths and skips reachability annotation
    entirely. Overrides ``--binary`` / ``--binary-auto`` if
    combined, with a stderr warning. Use when a build mismatch is
    causing the oracle to over-suppress, or for library-only /
    no-build targets.

    Always returns SOMETHING — even an empty tuple — so the caller
    can unconditionally assign to ``RaptorConfig.BINARY_ORACLE_PATHS``
    and never leak a prior run's value (adversarial review P0-117)."""
    explicit_binary = getattr(args, "binary", None)
    explicit_auto = bool(getattr(args, "binary_auto", False))
    opted_out = bool(getattr(args, "no_binary_oracle", False))

    if opted_out:
        if explicit_binary or explicit_auto:
            logger.warning(
                "binary-oracle: --no-binary-oracle overrides "
                "--binary / --binary-auto for this run; oracle "
                "filtering disabled."
            )
        return ()

    seen: dict = {}  # path → True for stable de-dupe (insertion order)

    for p in _validate_explicit_paths(explicit_binary, parser=parser):
        seen.setdefault(str(p), True)

    # Auto-detect runs when the operator explicitly asked
    # (--binary-auto) OR when no --binary was supplied (default-on).
    # Default-on uses the softer "nothing found" message.
    should_autodetect = explicit_auto or not explicit_binary
    if should_autodetect:
        for p in _autodetect_binaries(
                repo, target_kind, explicit=explicit_auto):
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
