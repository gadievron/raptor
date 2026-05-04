"""OpenAnt integration — path discovery and run configuration.

Discovers the OpenAnt core library via:
  1. OPENANT_CORE environment variable (explicit path)
  2. $RAPTOR_DIR/../libs/openant-core  (sibling heuristic)
  3. raptor_dir/../libs/openant-core   (caller-supplied raptor_dir)
  4. RuntimeError with clear diagnostic

No sys.path manipulation here; that happens in scanner.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

OPENANT_CORE_ENV = "OPENANT_CORE"
OPENANT_MODEL_ENV = "OPENANT_MODEL"
OPENANT_LEVEL_ENV = "OPENANT_LEVEL"

_SENTINEL = Path("/does/not/exist")
_CORE_MARKER = "core/scanner.py"


@dataclass
class OpenAntConfig:
    core_path: Path
    model: str = "sonnet"
    level: str = "reachable"
    enhance: bool = True
    verify: bool = False
    workers: int = 4
    timeout_seconds: int = 1800
    language: str = "auto"

    def validate(self) -> None:
        marker = self.core_path / _CORE_MARKER
        if not marker.exists():
            raise RuntimeError(
                f"OpenAnt core not found at {self.core_path!r}: "
                f"expected {_CORE_MARKER} to exist. "
                f"Set OPENANT_CORE to the libs/openant-core directory."
            )

    @classmethod
    def from_env(cls, raptor_dir: Optional[Path] = None) -> "OpenAntConfig":
        core_path = _discover_core(raptor_dir)
        model = os.environ.get(OPENANT_MODEL_ENV, "sonnet")
        level = os.environ.get(OPENANT_LEVEL_ENV, "reachable")
        config = cls(core_path=core_path, model=model, level=level)
        config.validate()
        return config


def _discover_core(raptor_dir: Optional[Path]) -> Path:
    explicit = os.environ.get(OPENANT_CORE_ENV)
    if explicit:
        return Path(explicit)

    raptor_env = os.environ.get("RAPTOR_DIR")
    if raptor_env:
        candidate = Path(raptor_env).parent / "libs" / "openant-core"
        if (candidate / _CORE_MARKER).exists():
            return candidate

    if raptor_dir is not None:
        candidate = raptor_dir.parent / "libs" / "openant-core"
        if (candidate / _CORE_MARKER).exists():
            return candidate

    raise RuntimeError(
        "OpenAnt core library not found. Set one of:\n"
        f"  {OPENANT_CORE_ENV}=/path/to/libs/openant-core\n"
        "  RAPTOR_DIR=/path/to/raptor  (OpenAnt expected at ../libs/openant-core)\n"
    )


def get_config(raptor_dir: Optional[Path] = None) -> OpenAntConfig:
    """Return a validated OpenAntConfig, raising RuntimeError if unavailable."""
    return OpenAntConfig.from_env(raptor_dir)


def is_available() -> bool:
    """Return True if OpenAnt can be located (non-fatal check)."""
    try:
        get_config()
        return True
    except RuntimeError:
        return False
