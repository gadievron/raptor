"""Consumption of per-project trust markers by run entry points.

Mirrors the persisted-binaries loading path
(``core.analysis.binary_oracle_cli._project_binaries``): at /agentic
and /codeql start the active project's trust markers are loaded and
resolved against the per-run flags.

Resolution (per marker, both directions):

    explicit negative flag  >  explicit positive flag
                            >  project marker  >  default (off)

SECURITY:
- Markers are operator assertions persisted in the project JSON under
  the RAPTOR projects dir (``~/.raptor/projects``) — NEVER read from
  anywhere inside the scanned repo, NEVER auto-set from detection
  heuristics.
- A marker may only loosen gates the corresponding per-run flag can
  already loosen — this module introduces no new authority:
    config  → the ``--trust-repo`` umbrella (cc_trust + codeql_trust)
    build   → ``--traced-build`` C/C++ CodeQL extraction
    dynamic → ``config.dynamic_validation`` (Frida / target execution)
- ``build`` does NOT imply ``config`` — the markers are resolved
  independently, matching the per-run-flag independence pinned by
  ``TestTracedBuildTrustIndependence``.
- Trust state must never be invisible: when a marker affects a run,
  a single banner line is printed at start.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.project.project import VALID_TRUST_MARKERS


def active_project_trust() -> tuple[dict[str, str], str | None]:
    """Load the active project's trust markers. Returns
    ``(markers, project_name)``. Best-effort — a missing project or
    schema mismatch returns ``({}, None)`` rather than crashing the
    run (mirrors ``binary_oracle_cli._project_binaries``)."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = mgr.get_active()
        if not active:
            return {}, None
        proj = mgr.load(active)
        if not proj:
            return {}, active
        raw = getattr(proj, "trust", None) or {}
        markers = {
            m: str(ts) for m, ts in raw.items()
            if m in VALID_TRUST_MARKERS and isinstance(ts, str) and ts
        }
        return markers, active
    except Exception:  # noqa: BLE001 — trust loading must never break a run
        return {}, None


def active_project_target() -> str | None:
    """The active project's target path, or ``None``. Best-effort,
    same failure posture as :func:`active_project_trust`."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = mgr.get_active()
        if not active:
            return None
        proj = mgr.load(active)
        if not proj:
            return None
        return getattr(proj, "target", None) or None
    except Exception:  # noqa: BLE001 — trust loading must never break a run
        return None


def run_target_matches_project(target_path: str | Path | None) -> bool:
    """True when the run's target IS the active project's target or
    lives inside it (resolved-path comparison).

    Fail-closed: an unknown run target, an unknown project target, or
    an unresolvable path all return ``False`` — a trust marker is an
    assertion about ONE target, so when the run's target cannot be
    shown to be that target the marker must not apply.
    """
    project_target = active_project_target()
    if not project_target or not target_path:
        return False
    try:
        run_res = Path(target_path).resolve()
        proj_res = Path(project_target).resolve()
    except OSError:
        return False
    return run_res == proj_res or proj_res in run_res.parents


def _derive_run_target(args) -> str | None:
    """The run's target path from the entry point's parsed args
    (``--repo`` for /agentic and /codeql, ``--target``/positional for
    /sca), falling back to ``RAPTOR_CALLER_DIR`` — the same signal
    ``get_output_dir`` uses for its project target check."""
    for attr in ("repo", "target", "target_path", "path"):
        val = getattr(args, attr, None)
        if val:
            return str(val)
    return os.environ.get("RAPTOR_CALLER_DIR") or None


def _emit_marker_target_mismatch(markers: list[str],
                                 run_target: str | None) -> None:
    """Loud notice when persisted markers are IGNORED because the run
    targets a different tree than the project. Trust state must never
    be invisible — silently dropping the markers would read as a
    marker that mysteriously stopped working."""
    shown = run_target or "<unknown>"
    print(
        f"[*] project trust: {', '.join(sorted(markers))} marker(s) "
        f"IGNORED — run target {shown} is not the active project's "
        f"target (markers assert trust for one target only)"
    )


def resolve_trust_flag(
    negative: bool, positive: bool, marker_set: bool, default: bool = False,
) -> bool:
    """Single-marker precedence: explicit negative > explicit positive
    > project marker > default(off)."""
    if negative:
        return False
    if positive:
        return True
    if marker_set:
        return True
    return default


def emit_trust_banner(affecting: list[str]) -> None:
    """One line at run start whenever a project marker changed the
    run's behaviour. Trust state must never be invisible."""
    if affecting:
        print(f"[*] project trust: {', '.join(affecting)} "
              f"(per-run flags override)")


def apply_project_trust_flags(
    args, *, banner: bool = True, target_path: str | Path | None = None,
) -> list[str]:
    """Resolve the ``config`` and ``build`` markers into
    ``args.trust_repo`` / ``args.traced_build`` for the /agentic and
    /codeql entry points.

    Mutates ``args`` in place to the *effective* values so downstream
    consumers (the ``set_trust_override`` block, the ``--traced-build``
    forwarding) stay unchanged. Returns the list of markers that
    actually affected this run (marker present AND no explicit per-run
    flag in either direction).

    Markers only apply when the run's target matches the project's
    target (resolved-path comparison; ``--out`` runs included — the
    output-dir gate never fires for those). A marker asserts trust for
    ONE target; pre-fix ``--repo /untrusted/x --out /tmp/o`` with any
    project active silently ran with that project's trust. A mismatch
    drops the markers with a loud notice; explicit per-run flags are
    unaffected either way.

    ``dynamic`` is deliberately NOT handled here — it is consumed where
    ``config.dynamic_validation`` is built (see
    :func:`resolve_dynamic_validation`).
    """
    markers, _name = active_project_trust()
    if markers:
        run_target = target_path or _derive_run_target(args)
        if not run_target_matches_project(run_target):
            _emit_marker_target_mismatch(list(markers), run_target and str(run_target))
            markers = {}
    affecting: list[str] = []

    neg_trust = bool(getattr(args, "no_trust_repo", False))
    pos_trust = bool(getattr(args, "trust_repo", False))
    if hasattr(args, "trust_repo"):
        args.trust_repo = resolve_trust_flag(
            neg_trust, pos_trust, "config" in markers)
        if "config" in markers and not neg_trust and not pos_trust:
            affecting.append("config")

    neg_build = bool(getattr(args, "no_traced_build", False))
    pos_build = bool(getattr(args, "traced_build", False))
    if hasattr(args, "traced_build"):
        args.traced_build = resolve_trust_flag(
            neg_build, pos_build, "build" in markers)
        if "build" in markers and not neg_build and not pos_build:
            affecting.append("build")

    if banner:
        emit_trust_banner(affecting)
    return affecting


def resolve_dynamic_validation(
    explicit: bool | None, *, banner: bool = True,
    target_path: str | Path | None = None,
) -> bool:
    """Resolve ``config.dynamic_validation`` for /audit-/validate-side
    consumers: explicit per-run choice (True/False from ``--dynamic`` /
    ``--no-dynamic``) wins; else the project's ``dynamic`` marker; else
    off.

    The marker only applies when *target_path* matches the active
    project's target (same one-target rule as
    :func:`apply_project_trust_flags`; ``RAPTOR_CALLER_DIR`` is the
    fallback signal when the caller passes none).
    """
    if explicit is not None:
        return bool(explicit)
    markers, _name = active_project_trust()
    if "dynamic" in markers:
        run_target = target_path or os.environ.get("RAPTOR_CALLER_DIR")
        if not run_target_matches_project(run_target):
            _emit_marker_target_mismatch(["dynamic"], run_target and str(run_target))
            return False
        if banner:
            emit_trust_banner(["dynamic"])
        return True
    return False


__all__ = [
    "active_project_target",
    "active_project_trust",
    "apply_project_trust_flags",
    "emit_trust_banner",
    "resolve_dynamic_validation",
    "resolve_trust_flag",
    "run_target_matches_project",
]
