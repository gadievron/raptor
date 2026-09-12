"""Runtime configuration for raptor-studio.

Studio adopts raptor's own conventions instead of inventing parallel
ones: the repo root is derived from this file's location (studio ships
in-tree), the project registry and default output base come from
``core/project``, and the models config honours ``RAPTOR_CONFIG`` —
raptor's existing models.json override. The only new environment knobs
are ``STUDIO_``-prefixed and affect studio alone.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.project.project import DEFAULT_OUTPUT_BASE, PROJECTS_DIR

# Repo root — packages/studio/config.py → packages/ → repo root; the same
# self-location convention raptor's libexec scripts use.
RAPTOR_HOME = Path(__file__).resolve().parents[2]

# Raptor's canonical project registry (core/project is the source of
# truth). STUDIO_PROJECTS_DIR is a studio-side view override for demo and
# test registries; it never redirects raptor itself, so jobs launched
# from a demo registry still write to raptor's real locations.
RAPTOR_PROJECTS_DIR = Path(os.environ.get("STUDIO_PROJECTS_DIR") or PROJECTS_DIR)

# Default base for new projects' output dirs — raptor's own default.
# Current raptor exports it absolute (anchored at RaptorConfig's out/
# dir); older raptor exported a repo-relative path, so anchor those at
# the repo root.
RAPTOR_OUTPUT_BASE = (
    DEFAULT_OUTPUT_BASE if DEFAULT_OUTPUT_BASE.is_absolute()
    else RAPTOR_HOME / DEFAULT_OUTPUT_BASE
)

STUDIO_DATA_DIR = Path(
    os.environ.get("STUDIO_DATA_DIR", Path.home() / ".raptor-studio")
)

# Raptor's per-role LLM config; RAPTOR_CONFIG is raptor's existing
# override for the models.json path (see docs/llm.md).
RAPTOR_MODELS_CONFIG = Path(
    os.environ.get("RAPTOR_CONFIG", Path.home() / ".config" / "raptor" / "models.json")
)

APP_TITLE = "raptor studio"
APP_TAGLINE = "See through the code."
