"""Run-scoped project pinning.

A run is pinned to one project IDENTITY for its whole lifetime: the
resolved project name and the layer that produced it are recorded in
``.raptor-run.json`` at the first ``start_run`` and never re-resolved
ambiently afterwards — in-run consumers read the pin through the run
dir. This is what makes a mid-session ``/project use`` (or another
session's activity) unable to move trust markers, persisted binaries,
IRIS stores, graduated rules, journal merges, or threat models under a
run that is already in flight.

Two halves:

* **Start-time resolution** (:func:`resolve_pin_for_start`): the layer
  precedence — explicit ``--project`` argv (process-scoped, set by the
  entry points), then the session binding, then the ``.active``
  symlink, then none. ``--project -`` is the explicit bound-to-none
  argv. The pin value for "no project" is JSON ``null`` — NEVER the
  string ``"none"``, which is a legal project name.
* **In-run resolution** (:func:`resolve_run_pin`): walk UP from an
  explicit run-dir handle (an argument or a config ``out_dir`` — never
  the cwd) to the nearest ``.raptor-run.json`` and apply the state
  table:

  ========================================  =================================
  pin ``project=P``, P exists               P, authoritative
  pin ``project=null``                      authoritative none — containment
                                            inference FORBIDDEN
  pin ``project=P``, P deleted/renamed      loud warn + authoritative none
  no ``.raptor-run.json`` found             legacy fallback: containment
                                            inference — READS ONLY
  ========================================  =================================

  The legacy containment fallback (pre-series run dirs) authorizes
  READS only: privilege-bearing writes (engine-rules graduation,
  domain-model promotion, journal-index merges, threat-model writes)
  require a real pin and are suppressed without one.

Walk-up safety: the walk stops at the first marker, a known project
output dir, ``$HOME``, a filesystem boundary, or depth 8 — and a
marker is IGNORED when its directory is not owned by the current uid
or is group/world-writable, so a planted ``/tmp/.raptor-run.json``
can never capture privilege-bearing writes.
"""

from __future__ import annotations

import logging
import os
import stat as stat_mod
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

RUN_METADATA_FILE = ".raptor-run.json"

#: The pin's provenance enum (``project_source`` in run metadata).
PIN_SOURCES = ("argv", "session", "symlink", "none", "adopted", "merged")

#: Explicit bound-to-none argv value (``--project -``): special-cased
#: BEFORE name validation at every consumer.
ARGV_NONE = "-"

_WALK_DEPTH = 8

#: Process-scoped ``--project`` override. Set exactly once by an entry
#: point's arg parsing; children receive the value by explicit argv
#: threading, never ambiently. Thread-safety relies on GIL-atomic
#: reads/writes of these two names: writers run at entry-point/
#: bootstrap time before worker pools spawn, and no compound
#: check-then-set exists on the read paths.
_process_project: str | None = None
_process_project_set = False


@dataclass(frozen=True)
class RunPin:
    """Resolved pin for a run dir.

    ``project`` — the pinned project name, or None (standalone /
    unresolvable). ``source`` — the pin's provenance (one of
    PIN_SOURCES, or ``"containment"`` for the legacy fallback,
    ``"unresolved"`` when nothing matched). ``run_dir`` — the dir whose
    marker answered, when one did. ``authoritative`` — True when the
    answer came from a real pin (never from containment inference).
    ``writes_allowed`` — False on the legacy fallback: containment
    inference authorizes reads only.
    """

    project: str | None
    source: str
    run_dir: Path | None
    authoritative: bool
    writes_allowed: bool


def set_process_project(value: str | None) -> None:
    """Record the entry point's ``--project`` argv (``'-'`` = explicit
    bound-to-none; None = flag not given). Validation against the
    project registry happens at resolution (hard error, never a
    fallback)."""
    global _process_project, _process_project_set
    _process_project = value
    _process_project_set = value is not None


def get_process_project() -> str | None:
    return _process_project if _process_project_set else None


class ProjectArgvError(ValueError):
    """``--project`` revalidation failure — a hard error by contract
   : never a fallback to any ambient layer."""


def _machine_project_expired(name: str) -> bool:
    """True when *name* is a machine-generated project past its
    auto-expiry (the get_active vet, applied at start-time pin
    resolution too). Operator projects never expire."""
    try:
        from core.project.project import (
            ProjectManager,
            is_machine_project_name,
        )
        if not is_machine_project_name(name):
            return False
        project = ProjectManager().load(name)
        return (project is not None
                and project.is_expired_machine_project())
    except Exception:  # noqa: BLE001 — vet failure = not expired
        logger.debug("pin: machine-expiry vet failed", exc_info=True)
        return False


def _project_exists(name: str) -> bool:
    try:
        from core.project.project import ProjectManager
        return ProjectManager().load(name) is not None
    except Exception:  # noqa: BLE001 — registry unreadable = not found
        logger.debug("pin: project existence check failed", exc_info=True)
        return False


def _validate_argv_project(value: str) -> None:
    from core.project.sessions import _NAME_RE
    if not _NAME_RE.match(value):
        msg = f"--project: invalid project name {value!r}"
        raise ProjectArgvError(msg)
    if not _project_exists(value):
        msg = f"--project: project {value!r} does not exist"
        raise ProjectArgvError(msg)


def resolve_pin_for_start() -> tuple[str | None, str]:
    """The (project, source) pair ``start_run`` records.

    Precedence: argv override > session binding > symlink > none.
    An invalid argv value raises :class:`ProjectArgvError` (hard
    error). A stale session binding (project deleted) resolves as
    authoritative none with a loud warning, never symlink fallthrough.
    """
    override = get_process_project()
    if override is not None:
        if override == ARGV_NONE:
            return None, "argv"
        _validate_argv_project(override)
        return override, "argv"

    from core.project.sessions import session_binding
    name, state = session_binding()
    if state == "bound":
        if name is not None and _project_exists(name):
            if _machine_project_expired(name):
                # Same machine-project auto-expiry vet (and same
                # layer-scoped remediation) get_active applies: an
                # expired machine project must not silently pin a
                # fresh run just because a stale binding names it.
                logger.warning(
                    "pin: session-bound machine project %r is past its "
                    "auto-expiry — clearing this session's binding; "
                    "run starts projectless. '/project use %s' "
                    "re-activates it (clearing the expiry).",
                    name, name)
                try:
                    from core.project.sessions import bind_session
                    bind_session(None)
                except Exception:  # noqa: BLE001 — remediation only
                    logger.debug("pin: expiry re-bind failed",
                                 exc_info=True)
                return None, "session"
            return name, "session"
        logger.warning(
            "pin: session binding names missing project %r — "
            "authoritatively projectless for this run", name)
        return None, "session"
    if state == "none":
        return None, "session"

    # advisory / absent → symlink layer (with the machine-expiry vet
    # applied by get_active itself).
    try:
        from core.project.project import ProjectManager
        active = ProjectManager().get_active()
    except Exception:  # noqa: BLE001 — resolution failure = standalone
        logger.debug("pin: symlink resolution failed", exc_info=True)
        active = None
    if active:
        return active, "symlink"
    return None, "none"


# ---------------------------------------------------------------------------
# in-run resolution
# ---------------------------------------------------------------------------

def _marker_trustworthy(directory: Path) -> bool:
    """A marker only counts when its directory is ours and not open to
    other writers — a world-writable ancestor (``/tmp``!) could carry a
    planted marker that captures privilege-bearing writes.

    Group-writable is accepted ONLY for our own primary group: on
    user-private-group systems (umask 002) every dir we create is
    0775 with a group containing just us — rejecting those would
    disable pinning wholesale. A shared group is a real second writer
    and stays rejected. Known residuals: on shared-primary-group
    systems (e.g. a common ``users`` gid) other members' dirs pass
    this check, and POSIX ACLs granting write are invisible to the
    mode bits — the ledger pin witness is the backstop for both.
    """
    try:
        st = directory.stat()
    except OSError:
        return False
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        return False
    if st.st_mode & stat_mod.S_IWOTH:
        return False
    if st.st_mode & stat_mod.S_IWGRP and hasattr(os, "getgid") \
            and st.st_gid != os.getgid():
        return False
    return True


def _walk_boundary(directory: Path, start_dev: int | None) -> bool:
    """Should the walk stop AT (before examining) *directory*?"""
    try:
        if directory == Path.home() or directory == directory.parent:
            return True
    except OSError:
        return True
    if start_dev is not None:
        try:
            if directory.stat().st_dev != start_dev:
                return True  # filesystem boundary
        except OSError:
            return True
    try:
        from core.config import RaptorConfig
        if directory == Path(RaptorConfig.get_out_dir()).resolve():
            # Stop AT the out-root: runs live under it, never at it, so
            # a marker planted at out/ itself must not become the
            # outermost pin of every standalone run beneath it.
            return True
    except Exception:  # noqa: BLE001 — out-root unknown: other stops apply
        pass
    return False


def _containment_project(start_dir: Path) -> str | None:
    """Legacy fallback: the project whose output dir contains
    *start_dir* — today's shape inference, reads only."""
    try:
        from core.project.project import ProjectManager
        resolved = start_dir.resolve()
        for project in ProjectManager().list_projects():
            try:
                out = Path(project.output_dir).resolve()
            except (OSError, ValueError):
                continue
            if out in resolved.parents or out == resolved:
                return project.name
    except Exception:  # noqa: BLE001 — registry unreadable = standalone
        logger.debug("pin: containment inference failed", exc_info=True)
    return None


#: Process-scoped pin freeze (the memoization the design mandates):
#: populated at start_run / bootstrap time, BEFORE any child spawns,
#: so a mid-run rewrite of the on-disk marker — the run dir root is
#: the sandbox WRITE GRANT handed to prompt-injectable children —
#: cannot move this process's consumers. Keyed by the resolved run
#: root. Never invalidated within a process: a run dir is pinned once.
#: Thread-safety: single-bytecode dict ops only (get/setitem/
#: setdefault — GIL-atomic); worker threads read, writers run before
#: pools spawn.
_frozen_pins: dict[str, RunPin] = {}


def freeze_run_pin(run_dir: str | os.PathLike[str], project: str | None,
                   source: str) -> None:
    """Record the just-written pin in the process freeze cache."""
    try:
        key = str(Path(run_dir).resolve())
    except (OSError, ValueError):
        return
    _frozen_pins[key] = RunPin(project, source, Path(key), True, True)


def resolve_run_pin(start_dir: str | os.PathLike[str]) -> RunPin:
    """Resolve the project pin governing *start_dir* (state table in
    the module docstring). *start_dir* must be an explicit run-dir
    handle — an argument or config out_dir — NEVER the cwd.

    Resolution prefers, in order: the process FREEZE CACHE (the value
    sealed at start_run, immune to on-disk rewrites by sandboxed
    children whose write grant includes the run dir); then the
    OUTERMOST trustworthy marker on the walk (nearest-wins let a child
    plant a marker in its own writable subdir — e.g. the AFL output
    dir — and capture consumers resolving from below it; legitimate
    runs are never nested inside other runs, the run-ownership
    doctrine forbids it); then containment inference, reads only.
    """
    try:
        current = Path(start_dir).resolve()
    except (OSError, ValueError):
        return RunPin(None, "unresolved", None, False, False)
    try:
        start_dev: int | None = current.stat().st_dev
    except OSError:
        start_dev = None

    marker_dirs: list[Path] = []
    probe = current
    for _ in range(_WALK_DEPTH):
        frozen = _frozen_pins.get(str(probe))
        if frozen is not None:
            return frozen
        marker = probe / RUN_METADATA_FILE
        try:
            has_marker = marker.is_file()
        except OSError:
            if probe == current:
                # The handle's own marker is unreadable (an in-grant
                # child can chmod its run root): indistinguishable
                # from tampering — fail closed rather than degrade to
                # containment inference.
                return RunPin(None, "unresolved", None, False, False)
            has_marker = False
        if has_marker:
            if _marker_trustworthy(probe):
                marker_dirs.append(probe)
            else:
                logger.warning(
                    "pin: ignoring untrustworthy run marker in %s "
                    "(not owned by us, or group/world-writable)", probe)
        parent = probe.parent
        if parent == probe or _walk_boundary(parent, start_dev):
            break
        try:
            from core.project.project import is_project_output_dir
            if is_project_output_dir(parent, exact=True):
                break  # never walk above a project output dir ITSELF
                # (descendant matching stopped the walk at the first
                # parent inside project dirs — nearest-marker capture)
        except Exception:  # noqa: BLE001 — boundary probe only
            pass
        probe = parent

    if marker_dirs:
        outermost = marker_dirs[-1]
        frozen = _frozen_pins.get(str(outermost))
        if frozen is not None:
            return frozen
        return _pin_from_marker(outermost)

    # No marker: legacy containment fallback — READS ONLY.
    name = _containment_project(current)
    return RunPin(name, "containment", None, False, False)


#: Byte budget for run-marker reads — the file sits inside sandbox
#: write grants (train convention: bounded loaders for this class).
_MAX_RUN_META_BYTES = 1024 * 1024


def _pin_from_marker(run_dir: Path) -> RunPin:
    from core.json import load_json
    meta = load_json(run_dir / RUN_METADATA_FILE,
                     max_bytes=_MAX_RUN_META_BYTES)
    if not isinstance(meta, dict):
        return RunPin(None, "unresolved", run_dir, False, False)
    if "project" not in meta:
        # Legacy (pre-series) run dir: containment inference, reads only.
        name = _containment_project(run_dir)
        return RunPin(name, "containment", run_dir, False, False)
    project = meta.get("project")
    source = str(meta.get("project_source") or "none")
    if source not in PIN_SOURCES:
        source = "none"
    if project is None:
        return RunPin(None, source, run_dir, True, True)
    if not isinstance(project, str):
        # A pin is a string or null by construction — anything else is
        # corruption/tampering. str()-coercing it made THIS resolver
        # disagree with start_run's prior-pin reader on the same dir
        # (a marker {"project": 123} resolved here as project "123").
        logger.warning(
            "pin: run %s has non-string project %r — authoritatively "
            "projectless; the marker may have been tampered with",
            run_dir, project)
        return RunPin(None, source, run_dir, True, True)
    if not _project_exists(project):
        logger.warning(
            "pin: run %s is pinned to missing project %r — "
            "authoritatively projectless (was it deleted/renamed?)",
            run_dir, project)
        return RunPin(None, source, run_dir, True, True)
    return RunPin(project, source, run_dir, True, True)


def legacy_probe_allowed(pin: RunPin) -> bool:
    """May a consumer fall through to its pre-series topology probe
    (parent checklist.json / project.json shape checks)?

    ONLY for genuine pre-series shapes: a marker without a
    ``project`` key, or no marker at all (metadata-less legacy dirs
    the adoption path admits). An UNPARSEABLE marker is refused —
    every series run writes a valid pin at start, so garbage there is
    tamper evidence from a child inside the sandbox write grant, and
    degrading it to topology inference would route privileged writes
    to whatever project physically contains the run. Marker DELETION
    is indistinguishable from never-had-one here; the session run
    ledger's pin witness (written at start, outside the sandbox
    write grant) closes that hole where a session exists.
    """
    return not pin.authoritative and pin.source == "containment"


def bootstrap_process_pin(out_dir: str | os.PathLike[str] | None) -> None:
    """Child-process pin bootstrap: a run's
    child process (scan/codeql/analysis workers spawned with an
    ``--out`` under the run dir) adopts the OWNING RUN's pin as its
    process-scoped project override, so every ambient consumer in the
    child — trust resolvers, IRIS store, exemplar pools, threat model,
    verified outcomes — follows the pin with zero per-site threading.

    Only AUTHORITATIVE pins bootstrap (a real ``project`` key in the
    owning run's metadata): the legacy containment fallback authorizes
    reads only, and promoting it to a process override would authorize
    privilege-bearing writes. An explicit ``--project`` argv set by the
    entry point always wins (never overwritten here).
    """
    if out_dir is None:
        return
    override = get_process_project()
    pin = resolve_run_pin(out_dir)
    if override is not None:
        # Both an explicit --project AND a pinned --out: they must
        # AGREE, or the process would run split — override for the
        # ambient consumers, pin for the run-dir consumers.
        if pin.authoritative:
            wanted = None if override == ARGV_NONE else override
            if wanted != pin.project:
                msg = (
                    f"--project {override!r} conflicts with the run's "
                    f"existing pin {pin.project!r} in {out_dir} — a "
                    "run dir is pinned to one project for its whole "
                    "lifetime"
                )
                raise ProjectArgvError(msg)
            # Agreement: STILL seal the freeze cache. The children
            # that receive the pin threaded as --project + --out are
            # exactly the processes most exposed to sandboxed marker
            # rewrites; skipping the seal left their whole lifetime
            # re-reading the disk marker.
            if pin.run_dir is not None:
                _frozen_pins.setdefault(str(pin.run_dir), pin)
        return
    if not pin.authoritative:
        return
    # The marker the pin came from is CHILD-WRITABLE (the run dir root
    # is the sandbox write grant): consult the session ledger's
    # out-of-grant pin witness before adopting it as this process's
    # project override. A witness that DISAGREES wins outright — the
    # marker was rewritten under us; a witness that agrees makes the
    # adoption sealable. No witness (pre-witness runs, sessionless
    # contexts) keeps the adoption for compatibility but never SEALS
    # it into the freeze cache — an unwitnessed marker must stay
    # re-verifiable, not laundered into trusted frozen state.
    witnessed_ok = False
    try:
        from core.project.sessions import ledger_pin_witness
        found, witnessed, wit_source = ledger_pin_witness(
            pin.run_dir if pin.run_dir is not None else out_dir)
        if found:
            if witnessed != pin.project:
                logger.warning(
                    "pin: bootstrap for %s — run marker resolves %r but "
                    "the session ledger witnessed %r at start; using the "
                    "witness (the marker may have been tampered with)",
                    out_dir, pin.project, witnessed)
                pin = RunPin(witnessed, wit_source or "session",
                             pin.run_dir, True, True)
            witnessed_ok = True
    except Exception:  # noqa: BLE001 — witness is best-effort
        logger.debug("pin: bootstrap witness check failed", exc_info=True)
    set_process_project(pin.project if pin.project is not None
                        else ARGV_NONE)
    # Seal the resolved pin in the process freeze cache: consumers in
    # THIS process resolving the same run dir later must see the value
    # read at bootstrap, not whatever a sandboxed child rewrote the
    # on-disk marker to in between. Witnessed adoptions only — sealing
    # an unwitnessed marker would promote a possibly-forged
    # .raptor-run.json to unrevisable trusted state for the whole
    # process lifetime.
    if witnessed_ok and pin.run_dir is not None:
        _frozen_pins.setdefault(str(pin.run_dir), pin)


def pinned_write_target_ok(out_dir: str | os.PathLike[str],
                           target: str | os.PathLike[str] | None = None,
                           ) -> bool:
    """ONE-TARGET GATE for pin-keyed privileged writes (engine-rules
    graduation, domain-model promotion, journal-index merges, coverage
    snapshots): the run's target must BE the pinned project's target
    (or live inside it) before the run may write into the project's
    durable stores. A pin names a project; the project is an assertion
    about ONE target — a run whose target is some other tree must not
    steer that project's cross-run state, whether the divergence is an
    operator mistake (``--project P --repo other``) or a forged
    marker. Callers pass the target they independently know when they
    have one; otherwise the run's recorded ``target_path`` is used.
    Runs with no recorded target (legacy dirs) pass — the gate must
    not regress pre-series projections.
    """
    if target is None:
        try:
            from core.json import load_json
            meta = load_json(Path(out_dir) / RUN_METADATA_FILE,
                             max_bytes=_MAX_RUN_META_BYTES)
            target = (meta or {}).get("target_path")
        except Exception:  # noqa: BLE001 — unreadable metadata: no target
            target = None
        if target is not None and not isinstance(target, str):
            # target_path is a string by construction — a list/number
            # is tamper, not legacy tolerance. Fail closed.
            logger.warning(
                "pin: run %s records a non-string target_path %r — "
                "suppressing the project-store write", out_dir, target)
            return False
    if not target:
        return True
    try:
        from core.project.trust import run_target_matches_project
        ok = run_target_matches_project(str(target), str(out_dir))
    except Exception:  # noqa: BLE001 — gate guards privileged writes
        logger.warning(
            "pin: one-target gate resolver failed for %s — suppressing "
            "the project-store write (fail closed)", out_dir,
            exc_info=True)
        return False
    if not ok:
        logger.warning(
            "pin: SUPPRESSED project-store write for %s — the run's "
            "target (%s) is not the pinned project's target. A project "
            "is an assertion about one target.", out_dir, target)
    return ok


def pin_project_dir(out_dir: str | os.PathLike[str] | None,
                    for_write: bool = False) -> Path | None:
    """The pinned project's OUTPUT DIR for a run dir, or None.

    The drop-in replacement for the ``out_dir.parent``-shape
    heuristics: a run pinned to project P yields P's output dir
    wherever the run dir physically sits (--out runs included); a
    standalone run (pin null) yields None — containment must NOT
    re-capture it. ``for_write=True`` additionally requires an
    AUTHORITATIVE pin: the legacy containment fallback authorizes
    reads only, so privilege-bearing writes (engine-rules graduation,
    domain-model promotion, journal merges, threat-model writes) are
    suppressed for pre-series run dirs.
    """
    if out_dir is None:
        return None
    pin = resolve_run_pin(out_dir)
    if pin.project is None:
        return None
    if for_write and not pin.writes_allowed:
        logger.info(
            "pin: suppressing project-level write for %s — legacy "
            "(pin-less) run dir; containment inference authorizes "
            "reads only", out_dir)
        return None
    try:
        from core.project.project import ProjectManager
        project = ProjectManager().load(pin.project)
        if project is None:
            return None
        return Path(project.output_dir)
    except Exception:  # noqa: BLE001 — registry unreadable = standalone
        logger.debug("pin: project dir lookup failed", exc_info=True)
        return None
