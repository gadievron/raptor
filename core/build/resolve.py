"""Resolve the build command for a target — the operator-first chain.

``/project set build-command`` (with per-language ``build-command.<lang>``
slots) has existed as a registry-validated setting with no reader; this
module is that reader, with the precedence every consumer shares:

1. the active project's ``build-command.<lang>`` slot (when ``lang`` is
   given), else its ``default`` slot — the operator's word wins;
2. :class:`core.build.build_detector.BuildDetector` synthesis;
3. ``None`` — the caller keeps its no-build behaviour.

The returned ``source`` string (``"project-setting:<slot>"`` /
``"detected:<build-system>"``) is provenance for reports: consumers
must surface WHICH chain link produced the command, so an operator can
tell "my setting ran" from "RAPTOR guessed".

An operator setting is a SEED, not a pin: consumers may adapt when the
command fails in their execution context, but the deviation must be
reported, never silent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, NamedTuple

logger = logging.getLogger(__name__)


class ResolvedBuild(NamedTuple):
    """A resolved build command plus where to run it.

    ``subdir`` is the working directory RELATIVE to the target root
    ("" = the root itself). Detector synthesis populates it when the
    build system lives in a subdirectory (GNU screen's autotools live
    in src/); operator settings always get "" — the operator's command
    runs at the root exactly as before, and can embed its own ``cd``.
    Consumers that execute the command MUST honour it: running a
    subdir-detected command at the root is guaranteed to fail
    (``autoreconf: error: 'configure.ac' is required``).
    """

    command: str
    source: str
    subdir: str = ""


def resolve_build_command(
    target: Path | str,
    lang: str | None = None,
    *,
    settings: dict[str, Any] | None = None,
    run_dir: Path | str | None = None,
) -> ResolvedBuild | None:
    """The build command for *target*, or ``None`` when nothing resolves.

    ``settings`` is the project settings mapping (the ``settings`` key
    of the project JSON); when omitted, the active project's settings
    are loaded — and only apply when *target* matches that project's
    target (the one-target rule trust markers follow: a setting made
    for project A must not steer a run against tree B).

    Returns :class:`ResolvedBuild` — ``(command, source, subdir)``.
    """
    slots = _build_command_slots(settings, target, run_dir)
    if slots:
        if lang and slots.get(lang):
            return ResolvedBuild(str(slots[lang]), f"project-setting:{lang}")
        if slots.get("default"):
            return ResolvedBuild(str(slots["default"]),
                                 "project-setting:default")
        # No default and no (or unmatched) lang: a project with exactly
        # ONE populated language slot still expressed an operator
        # intent — honour it rather than reporting "no setting".
        populated = [(k, v) for k, v in slots.items() if v]
        if len(populated) == 1:
            slot, command = populated[0]
            if lang and slot != lang:
                # Deliberate (an operator with exactly one slot
                # expressed intent), but a cross-language serve is
                # worth an operator-visible note: `mvn package`
                # answering a cpp request is a real possibility of
                # this mechanism.
                logger.warning(
                    "build-command: lone populated slot %r serves the "
                    "%r request (set build-command.%s or default to "
                    "silence this)", slot, lang, lang,
                )
            return ResolvedBuild(str(command), f"project-setting:{slot}")

    detected = _detect(target, lang)
    if detected is not None:
        return detected
    return None


def _build_command_slots(
    settings: dict[str, Any] | None, target: Path | str,
    run_dir: Path | str | None = None,
) -> dict[str, Any]:
    """The ``build-command`` slot dict, honouring the one-target rule.
    In-run callers pass *run_dir* so the setting comes from the RUN
    PIN's project, never a mid-run ambient re-read."""
    if settings is not None:
        raw = settings.get("build-command")
        return raw if isinstance(raw, dict) else {}
    try:
        from core.json import load_json
        from core.project.trust import (
            _context_project_name,
            run_target_matches_project,
        )
        from core.startup import PROJECTS_DIR

        name = _context_project_name(run_dir)
        if not name:
            return {}
        if not run_target_matches_project(target, run_dir):
            return {}
        data = load_json(PROJECTS_DIR / f"{name}.json")
        if not isinstance(data, dict):
            return {}
        raw = (data.get("settings") or {}).get("build-command")
        return raw if isinstance(raw, dict) else {}
    except Exception:  # noqa: BLE001 — resolution is best-effort by contract
        logger.debug("resolve_build_command: project settings load failed",
                     exc_info=True)
        return {}


def _detect(target: Path | str, lang: str | None) -> ResolvedBuild | None:
    """Detector synthesis (chain link 2). Best-effort, never raises."""
    try:
        from core.build.build_detector import BuildDetector

        detector = BuildDetector(Path(target))
        # The hinted language first, then the native chain: a hint
        # must narrow the ORDER, never the coverage. ("c" is now a
        # real table key — an alias of cpp — so a C hint scans
        # directly instead of warning "no build system detection".)
        languages = ["cpp"]
        if lang:
            languages = [lang] + [c for c in languages if c != lang]
        for candidate in languages:
            bs = detector.detect_build_system(candidate)
            if bs is not None and bs.command:
                return ResolvedBuild(str(bs.command), f"detected:{bs.type}",
                                     _rel_subdir(bs.working_dir, target))
    except Exception:  # noqa: BLE001 — resolution is best-effort by contract
        logger.debug("resolve_build_command: detector synthesis failed",
                     exc_info=True)
    return None


def _rel_subdir(working_dir: Path | str, target: Path | str) -> str:
    """*working_dir* relative to *target* root, "" for the root itself.

    The detector guards against out-of-tree working dirs already; if
    one slips through anyway, "" (build at the root) is the safe
    degrade — same behaviour as before subdir threading existed.
    """
    try:
        rel = Path(working_dir).resolve().relative_to(Path(target).resolve())
    except (ValueError, OSError):
        return ""
    posix = rel.as_posix()
    return "" if posix == "." else posix
