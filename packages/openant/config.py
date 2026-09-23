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
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

OPENANT_CORE_ENV = "OPENANT_CORE"
OPENANT_MODEL_ENV = "OPENANT_MODEL"
OPENANT_LEVEL_ENV = "OPENANT_LEVEL"

# Single source for the two operator-knob choice universes. These
# existed spelled out three times (here, raptor_openant.py argparse,
# raptor_agentic.py argparse); a divergence would let one surface
# accept what another validates away.
OPENANT_MODEL_CHOICES: tuple[str, ...] = ("opus", "sonnet")
OPENANT_MODEL_DEFAULT = "sonnet"
OPENANT_LEVEL_CHOICES: tuple[str, ...] = (
    "all", "reachable", "codeql", "exploitable")
OPENANT_LEVEL_DEFAULT = "reachable"

# Supply-chain pin for the external OpenAnt checkout. Pin by commit
# id, not tag or branch name: refs are movable, git object ids are
# not. This is the upstream master commit the bridge's schema
# contract (the translator's stage-1/stage-2 verdict enumeration,
# documented against OpenAnt's core/reporter.py) was verified
# against. Staleness note: a checkout at any other commit still runs
# — the scan records and loudly warns EVERY non-pinned provenance
# shape (mismatched commit AND unverifiable non-git / unexpected-
# layout checkouts) instead of refusing — but advance this pin
# deliberately and re-verify the
# translator's verdict enumeration when you do; a renamed verdict in
# a newer OpenAnt degrades findings to level=note (warned, never
# silently dropped).
OPENANT_UPSTREAM_URL = "https://github.com/knostic/OpenAnt"
OPENANT_PINNED_COMMIT = "abd1dcf416a1ca329441c4bf8ebb68f70dd0f3cf"


def env_choice(env_var: str, choices: tuple[str, ...], fallback: str) -> str:
    """Env-seeded argparse default with EXPLICIT validation.

    argparse does not validate string ``default=`` values against
    ``choices`` — an invalid env value would silently steer the run.
    Invalid values warn on stderr and fall back; the explicit flag
    always wins over whatever this returns.
    """
    value = os.environ.get(env_var)
    if value is None or value == "":
        return fallback
    if value in choices:
        return value
    import sys

    from core.security.log_sanitisation import sanitise_for_terminal
    print(
        f"⚠️  Ignoring invalid {env_var}={sanitise_for_terminal(value, max_len=60)!r} "
        f"(choices: {', '.join(choices)}); using {fallback}",
        file=sys.stderr,
    )
    return fallback

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
    # Enriched provenance record from enforce_core_consent when the
    # --openant-core flag surface gated this run: the scan persists
    # THIS record (worktree survey verdict + consent route) instead of
    # re-deriving a content-blind one. None on the env / auto-detect
    # lanes, where no gate runs.
    gate_provenance: Optional[dict] = None
    # True when the gate admitted this core as a CLEAN PINNED checkout
    # (no operator consent on file): the scanner re-verifies that
    # content right before spawning — the gate runs at argv parse, the
    # spawn can be an entire pattern-scan phase later, and unconsented
    # execution must not rest on a minutes-old verdict. Consented runs
    # skip the recheck (the operator accepted non-pinned content).
    expect_clean_pinned: bool = False

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
        # Env knobs route through env_choice like the argparse
        # surfaces: raw os.environ reads sat one import away from the
        # module's own validator, and any get_config() consumer that
        # did not overwrite from validated argparse inherited the
        # unvalidated lane (both current callers masked it).
        core_path = _discover_core(raptor_dir)
        model = env_choice(
            OPENANT_MODEL_ENV, OPENANT_MODEL_CHOICES, OPENANT_MODEL_DEFAULT)
        level = env_choice(
            OPENANT_LEVEL_ENV, OPENANT_LEVEL_CHOICES, OPENANT_LEVEL_DEFAULT)
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
