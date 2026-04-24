"""Runtime configuration for raptor-studio.

All paths are overridable via environment variables so the same code works
both as a standalone companion repo and absorbed inside raptor's tree.
"""

from __future__ import annotations

import os
from pathlib import Path

RAPTOR_PROJECTS_DIR = Path(
    os.environ.get("RAPTOR_PROJECTS_DIR", Path.home() / ".raptor" / "projects")
)

RAPTOR_HOME = Path(
    os.environ.get("RAPTOR_HOME", Path.home() / "Projects" / "raptor")
)

RAPTOR_OUTPUT_BASE = Path(
    os.environ.get("RAPTOR_OUTPUT_BASE", RAPTOR_HOME / "out" / "projects")
)

STUDIO_DATA_DIR = Path(
    os.environ.get("STUDIO_DATA_DIR", Path.home() / ".raptor-studio")
)

RAPTOR_MODELS_CONFIG = Path(
    os.environ.get("RAPTOR_MODELS_CONFIG", Path.home() / ".config" / "raptor" / "models.json")
)

APP_TITLE = "raptor studio"
APP_TAGLINE = "See through the code."
