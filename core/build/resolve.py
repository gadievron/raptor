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
from typing import Any

logger = logging.getLogger(__name__)


def resolve_build_command(
    target: Path | str,
    lang: str | None = None,
    *,
    settings: dict[str, Any] | None = None,
) -> tuple[str, str] | None:
    """The build command for *target*, or ``None`` when nothing resolves.

    ``settings`` is the project settings mapping (the ``settings`` key
    of the project JSON); when omitted, the active project's settings
    are loaded — and only apply when *target* matches that project's
    target (the one-target rule trust markers follow: a setting made
    for project A must not steer a run against tree B).

    Returns ``(command, source)``.
    """
    slots = _build_command_slots(settings, target)
    if slots:
        if lang and slots.get(lang):
            return str(slots[lang]), f"project-setting:{lang}"
        if slots.get("default"):
            return str(slots["default"]), "project-setting:default"
        # No default and no (or unmatched) lang: a project with exactly
        # ONE populated language slot still expressed an operator
        # intent — honour it rather than reporting "no setting".
        populated = [(k, v) for k, v in slots.items() if v]
        if len(populated) == 1:
            slot, command = populated[0]
            return str(command), f"project-setting:{slot}"

    detected = _detect(target, lang)
    if detected is not None:
        return detected
    return None


def _build_command_slots(
    settings: dict[str, Any] | None, target: Path | str,
) -> dict[str, Any]:
    """The ``build-command`` slot dict, honouring the one-target rule."""
    if settings is not None:
        raw = settings.get("build-command")
        return raw if isinstance(raw, dict) else {}
    try:
        from core.json import load_json
        from core.project.trust import run_target_matches_project
        from core.startup import PROJECTS_DIR, get_active_name

        name = get_active_name()
        if not name:
            return {}
        if not run_target_matches_project(target):
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


def _detect(target: Path | str, lang: str | None) -> tuple[str, str] | None:
    """Detector synthesis (chain link 2). Best-effort, never raises."""
    try:
        from core.build.build_detector import BuildDetector

        detector = BuildDetector(Path(target))
        # The hinted language first, then the native chain: the
        # detector's language table is sparse (e.g. no "c" key — cpp
        # covers Makefile/CMake/autotools projects), so a hint must
        # narrow the ORDER, never the coverage.
        languages = ["cpp", "c"]
        if lang:
            languages = [lang] + [c for c in languages if c != lang]
        for candidate in languages:
            bs = detector.detect_build_system(candidate)
            if bs is not None and bs.command:
                return str(bs.command), f"detected:{bs.type}"
    except Exception:  # noqa: BLE001 — resolution is best-effort by contract
        logger.debug("resolve_build_command: detector synthesis failed",
                     exc_info=True)
    return None
