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

import logging
import os
from pathlib import Path

from core.project.project import VALID_TRUST_MARKERS

logger = logging.getLogger(__name__)


def _context_project_name(run_dir: str | Path | None = None) -> str | None:
    """The project whose state governs THIS context:
    inside a run, the RUN PIN (resolved by walking up from *run_dir*)
    — a mid-session /project switch must never move an in-flight
    run's trust posture; outside a run, the layered ambient
    resolution (argv override > session binding > symlink)."""
    if run_dir is not None:
        from core.run.pin import resolve_run_pin
        return resolve_run_pin(run_dir).project
    try:
        from core.run.pin import (
            ARGV_NONE,
            _validate_argv_project,
            get_process_project,
        )
    except Exception:  # noqa: BLE001 — pin module unavailable: ambient
        get_process_project = None  # type: ignore[assignment]
    if get_process_project is not None:
        override = get_process_project()
        if override is not None:
            if override == ARGV_NONE:
                return None
            # Same hard-error contract as start-time resolution: a
            # bogus/deleted --project must never silently degrade to
            # "no trust" — the operator asked for a specific project
            # and gets told when that ask cannot be honoured.
            _validate_argv_project(override)
            return override
    from core.project.project import ProjectManager
    return ProjectManager().get_active()


def active_project_trust(
    run_dir: str | Path | None = None,
) -> tuple[dict[str, str], str | None]:
    """Load the governing project's trust markers — the RUN PIN's
    project when *run_dir* is given, the ambient layers otherwise.
    Returns ``(markers, project_name)``. Best-effort — a missing
    project or schema mismatch returns ``({}, None)`` rather than
    crashing the run (mirrors ``binary_oracle_cli._project_binaries``)."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = _context_project_name(run_dir)
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
    except Exception as exc:  # noqa: BLE001 — trust loading must never break a run
        # ...except for the argv hard-error contract: a bogus/deleted
        # --project must never silently degrade to "no trust" — the
        # blanket swallow contradicted _context_project_name's own
        # promise. Everything else degrades, but VISIBLY: a silent
        # `{}, None` hid real registry corruption from operators.
        from core.run.pin import ProjectArgvError
        if isinstance(exc, ProjectArgvError):
            raise
        logger.warning(
            "trust: marker resolution failed (%s) — proceeding with no "
            "trust markers", exc)
        return {}, None


def active_project_target(run_dir: str | Path | None = None) -> str | None:
    """The governing project's target path, or ``None``. Best-effort,
    same failure posture as :func:`active_project_trust`."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = _context_project_name(run_dir)
        if not active:
            return None
        proj = mgr.load(active)
        if not proj:
            return None
        return getattr(proj, "target", None) or None
    except Exception:  # noqa: BLE001 — trust loading must never break a run
        return None


def run_target_matches_project(target_path: str | Path | None,
                               run_dir: str | Path | None = None) -> bool:
    """True when the run's target IS the governing project's target or
    lives inside it (resolved-path comparison), or — for a project
    whose target is an ARCHIVE — when the run's target is that
    archive's extraction (see :func:`_archive_target_equivalent`).

    Fail-closed: an unknown run target, an unknown project target, or
    an unresolvable path all return ``False`` — a trust marker is an
    assertion about ONE target, so when the run's target cannot be
    shown to be that target the marker must not apply.
    """
    project_target = active_project_target(run_dir)
    if not project_target or not target_path:
        return False
    # URL targets are OPAQUE strings (/web runs): never Path-resolve
    # them — "https://x" resolved against the cwd becomes
    # "<cwd>/https:/x" and can fail OPEN inside a project tree. URL vs
    # filesystem is never the same target; URL vs URL compares
    # trailing-slash-tolerant, like _check_target_mismatch.
    from core.run.output import _URL_SCHEME_RE
    run_is_url = bool(_URL_SCHEME_RE.match(str(target_path)))
    proj_is_url = bool(_URL_SCHEME_RE.match(str(project_target)))
    if run_is_url or proj_is_url:
        if run_is_url and proj_is_url:
            return (str(target_path).rstrip("/")
                    == str(project_target).rstrip("/"))
        return False
    try:
        run_res = Path(target_path).resolve()
        proj_res = Path(project_target).resolve()
    except OSError:
        return False
    if run_res == proj_res or proj_res in run_res.parents:
        return True
    return _archive_target_equivalent(run_res, proj_res, run_dir)


#: Content-identity memo for project ARCHIVE targets: resolved path ->
#: ((st_mtime_ns, st_ctime_ns, st_size), snapshot). The one-target
#: gate fires on every pin-keyed privileged write (findings merge,
#: coverage snapshot, journal-index merge — several per run
#: completion) and each check would otherwise re-hash the whole
#: archive — that cost is why the memo exists. The validity key is why
#: it is safe ENOUGH, not absolutely safe: an ordinary replacement
#: (new bytes written to the path) changes mtime/ctime/size and
#: re-hashes; a deliberate same-size content swap with a forged
#: utime() mtime still misses because unprivileged utime() cannot set
#: ctime. An actor who controls the clock or rewrites filesystem
#: metadata outright can still serve a stale identity — the memo
#: accepts that residual in exchange for not re-hashing per
#: privileged write (tests clear the dict for forced re-reads).
_ARCHIVE_SNAP_MEMO: dict[str, tuple[tuple[int, int, int], dict]] = {}


def _archive_snapshot_memoised(archive_path: Path) -> dict | None:
    """``core.run.provenance.archive_snapshot`` behind the
    mtime/ctime/size memo above. None when the file is not a
    recognised archive or is unreadable (callers fail closed on
    None)."""
    from core.run.provenance import archive_snapshot
    key = str(archive_path)
    try:
        st = archive_path.stat()
        validity = (st.st_mtime_ns, st.st_ctime_ns, st.st_size)
    except OSError:
        return None
    cached = _ARCHIVE_SNAP_MEMO.get(key)
    if cached is not None and cached[0] == validity:
        return cached[1]
    snap = archive_snapshot(archive_path)
    if snap is not None:
        _ARCHIVE_SNAP_MEMO[key] = (validity, snap)
    return snap


def _run_archive_identity(
    run_dir: str | Path,
) -> tuple[dict | None, str | None]:
    """The run's sealed acquisition stamp (``manifest.target`` from the
    run marker the pin resolver answers with) plus the marker's
    recorded ``target_path``, when the stamp records an archive
    acquisition. ``(None, None)`` otherwise — absence fails closed."""
    from core.run.metadata import load_run_metadata
    from core.run.pin import resolve_run_pin
    from core.run.provenance import run_target
    marker_dir = resolve_run_pin(run_dir).run_dir
    if marker_dir is None:
        return None, None
    meta = load_run_metadata(Path(marker_dir))
    stamp = run_target(meta)
    if isinstance(stamp, dict) and stamp.get("source") == "archive":
        recorded = meta.get("target_path") if isinstance(meta, dict) else None
        if isinstance(recorded, str) and recorded:
            return stamp, recorded
        return stamp, None
    return None, None


def _archive_target_equivalent(run_res: Path, proj_res: Path,
                               run_dir: str | Path | None) -> bool:
    """Archive equivalence for the one-target gate: a project whose
    target is an archive is an assertion about the archive's CONTENT,
    and runs against it record — and scan — the content-addressed
    extraction (``_sources/<name>-<sha>/``), never the archive file
    itself. A pure resolved-path compare therefore mismatched every
    such run, silently suppressing all its project-store writes and
    dropping its trust markers.

    Two witnesses, both bound to the archive's CURRENT bytes (sha256),
    both fail-closed on any missing/unreadable identity:

    1. The run's sealed acquisition stamp: ``manifest.target`` in the
       run marker records ``{source: "archive", archive_sha256}`` at
       start — equal shas mean the run extracted exactly the bytes the
       project target holds now, AND the vetted target must be (or
       live inside) the marker's recorded ``target_path``, so the
       predicate answers the caller's question about THIS path rather
       than "this run had a matching stamp". (A replaced archive
       yields a different sha and the gate stays closed — as it must:
       the run's verdicts describe the OLD bytes.)
    2. The project's own extraction cache: the run target is (or lives
       inside) ``<project output dir>/_sources/<name>-<sha>/`` for the
       archive's current sha — the dir name is content-addressed by
       construction (``core.archive.safe_cache_name``), covering runs
       whose marker is unavailable to the caller.
    """
    try:
        from core.archive import is_archive, safe_cache_name
        if not proj_res.is_file() or not is_archive(proj_res):
            return False
        snap = _archive_snapshot_memoised(proj_res)
        if snap is None:
            return False
        sha = snap["archive_sha256"]
        if run_dir is not None:
            stamp, recorded = _run_archive_identity(run_dir)
            if stamp is not None and stamp.get("archive_sha256") == sha:
                # The stamp witnesses the RUN; bind the answer to the
                # CALLER's question too: the target being vetted must
                # be (or live inside) the marker's recorded
                # target_path. Without this the arm answered True for
                # ANY path once the run carried a matching stamp — a
                # silent contract broadening no current caller relied
                # on. No/unresolvable recorded target: this witness
                # abstains (fall through to the cache-dir witness).
                if recorded is not None:
                    try:
                        rec_res = Path(recorded).resolve()
                        if run_res == rec_res or rec_res in run_res.parents:
                            return True
                    except OSError:
                        pass
        from core.project.project import ProjectManager
        active = _context_project_name(run_dir)
        if not active:
            return False
        proj = ProjectManager().load(active)
        out_dir = getattr(proj, "output_dir", None) if proj else None
        if not out_dir:
            return False
        canonical = (Path(out_dir) / "_sources"
                     / safe_cache_name(snap["archive_name"], sha)).resolve()
        return run_res == canonical or canonical in run_res.parents
    except Exception as exc:  # noqa: BLE001 — equivalence is a widening; fail closed
        # The argv hard-error contract still propagates (same posture
        # as active_project_trust).
        from core.run.pin import ProjectArgvError
        if isinstance(exc, ProjectArgvError):
            raise
        logger.debug("trust: archive equivalence probe failed",
                     exc_info=True)
        return False


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
    run_dir: str | Path | None = None,
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
    markers, _name = active_project_trust(run_dir)
    if "dynamic" in markers:
        run_target = target_path or os.environ.get("RAPTOR_CALLER_DIR")
        if not run_target_matches_project(run_target, run_dir):
            _emit_marker_target_mismatch(["dynamic"], run_target and str(run_target))
            return False
        if banner:
            emit_trust_banner(["dynamic"])
        return True
    return False


def resolve_repo_trust(
    explicit: bool | None, *, banner: bool = True,
    target_path: str | Path | None = None,
    run_dir: str | Path | None = None,
) -> bool:
    """Resolve the repo-trust assertion for /audit-side consumers
    (trust-gated witnesses): explicit per-run choice wins; else the
    project's ``config`` marker — the same --trust-repo umbrella the
    /agentic and /codeql entry points consume; else off.

    Same one-target rule as :func:`resolve_dynamic_validation`: the
    marker asserts trust for the active project's target only.
    """
    if explicit is not None:
        return bool(explicit)
    markers, _name = active_project_trust(run_dir)
    if "config" in markers:
        run_target = target_path or os.environ.get("RAPTOR_CALLER_DIR")
        if not run_target_matches_project(run_target, run_dir):
            _emit_marker_target_mismatch(["config"], run_target and str(run_target))
            return False
        if banner:
            emit_trust_banner(["config"])
        return True
    return False


def active_project_sandbox_floor(
    run_dir: str | Path | None = None,
) -> str | None:
    """The governing project's ``sandbox-floor`` setting (tier label
    string), or ``None``. Best-effort, same failure posture as
    :func:`active_project_trust` — a missing project or schema
    mismatch resolves to no consent (the fail-closed default floor),
    never a crash."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = _context_project_name(run_dir)
        if not active:
            return None
        proj = mgr.load(active)
        if not proj:
            return None
        label = proj.get_setting("sandbox-floor")
        return label if isinstance(label, str) and label else None
    except Exception as exc:  # noqa: BLE001 — consent loading must never break a run
        from core.run.pin import ProjectArgvError
        if isinstance(exc, ProjectArgvError):
            raise
        logger.warning(
            "sandbox-floor: project setting resolution failed (%s) — "
            "proceeding with the default untrusted floor", exc)
        return None


def apply_project_sandbox_floor(
    args=None, *, banner: bool = True,
    target_path: str | Path | None = None,
    run_dir: str | Path | None = None,
) -> str | None:
    """Consume the active project's ``sandbox-floor`` setting at run
    start — the project surface of the untrusted containment-floor
    consent chain (per-run ``--sandbox-floor`` flag > this setting >
    the legacy env var > default-refuse).

    Mirrors :func:`apply_project_trust_flags`: the setting is an
    operator assertion persisted in the project JSON under the RAPTOR
    projects dir — never read from the scanned repo, never from cwd —
    and it only applies when the run's target matches the project's
    target (a consent to weaker containment is a statement about ONE
    target's work). A mismatch drops it with a loud notice.

    Plumbs the validated label into ``core.sandbox`` state
    (``set_project_sandbox_floor``); precedence against the per-run
    flag and the env var is resolved per call inside the sandbox
    (context.resolve_untrusted_floor), so the flag wins in both
    directions and disagreements banner there. Returns the applied
    label, or ``None`` when no setting applies.

    Consent state must never be invisible: prints one banner line
    when the setting is loaded and no per-run flag was passed (the
    flag case banners from the sandbox side, naming both surfaces on
    disagreement).
    """
    try:
        from core.sandbox import state as _sandbox_state
        if _sandbox_state._cli_sandbox_disabled:
            # Operator-explicit sandbox-off (--sandbox none /
            # --no-sandbox) is globally authoritative — a floor
            # consent is moot, and printing its banner would claim a
            # consent the disable overrides. Skip quietly.
            return None
    except Exception:  # noqa: BLE001 — consent loading must never break a run
        pass
    label = active_project_sandbox_floor(run_dir)
    if not label:
        return None
    run_target = target_path or (
        _derive_run_target(args) if args is not None
        else os.environ.get("RAPTOR_CALLER_DIR") or None)
    if not run_target_matches_project(run_target, run_dir):
        notice = (
            f"[*] project sandbox-floor: '{label}' IGNORED — run "
            f"target {run_target or '<unknown>'} is not the active "
            f"project's target (floor consent is asserted for one "
            f"target only)"
        )
        if banner:
            print(notice)
        else:
            # banner=False callers have machine-parsed stdout
            # (libexec dispatch helpers) — keep the drop visible on
            # the log stream instead.
            logger.warning("%s", notice)
        return None
    try:
        from core.sandbox.cli import set_project_sandbox_floor
        set_project_sandbox_floor(label)
    except ValueError as exc:
        # Invalid label on disk (schema drift, hand-edited project
        # file) or a Linux tier on macOS: fail CLOSED to the default
        # floor, loudly — never guess a consent.
        logger.warning(
            "sandbox-floor: project setting not applied (%s) — "
            "proceeding with the default untrusted floor", exc)
        return None
    if banner and getattr(args, "sandbox_floor", None) is None:
        print(f"[*] project sandbox-floor: {label} "
              f"(per-run --sandbox-floor overrides)")
    return label


def resolve_build_execution(
    explicit: bool | None, *, banner: bool = True,
    target_path: str | Path | None = None,
    run_dir: str | Path | None = None,
) -> bool:
    """Resolve build-execution consent for consumers that must RUN a
    target's build system (env build-on-demand): explicit per-run
    choice wins; else the project's ``build`` marker; else off.

    Building a repo executes repo-influenced code, so this rides the
    same operator assertion traced-build extraction uses — including
    the one-target rule (the marker never authorises building a tree
    that is not the active project's target).
    """
    if explicit is not None:
        return bool(explicit)
    markers, _name = active_project_trust(run_dir)
    if "build" in markers:
        run_target = target_path or os.environ.get("RAPTOR_CALLER_DIR")
        if not run_target_matches_project(run_target, run_dir):
            _emit_marker_target_mismatch(["build"], run_target and str(run_target))
            return False
        if banner:
            emit_trust_banner(["build"])
        return True
    return False


__all__ = [
    "active_project_sandbox_floor",
    "active_project_target",
    "active_project_trust",
    "apply_project_sandbox_floor",
    "apply_project_trust_flags",
    "emit_trust_banner",
    "resolve_build_execution",
    "resolve_dynamic_validation",
    "resolve_repo_trust",
    "resolve_trust_flag",
    "run_target_matches_project",
]
