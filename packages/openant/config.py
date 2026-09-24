"""OpenAnt integration — path discovery and run configuration.

Discovers the OpenAnt core library via:
  1. OPENANT_CORE environment variable (explicit path)
  2. $RAPTOR_DIR/../libs/openant-core  (sibling heuristic)
  3. raptor_dir/../libs/openant-core   (caller-supplied raptor_dir)
  4. RuntimeError with clear diagnostic

Env-boundary note: through the raptor.py dispatch lane the launcher
scripts (raptor_openant.py / raptor_agentic.py) run under a child
environment rebuilt from the safe-env allowlist, and OPENANT_CORE /
OPENANT_MODEL / OPENANT_LEVEL are deliberately NOT on it (OPENANT_CORE
names a directory whose Python EXECUTES with network access and the
Anthropic API key — the exec-path class the allowlist exists to keep
out; the flag surface is consent-gated for the same reason). Surface 1
therefore only applies to direct invocations from an unscrubbed shell;
operator-facing guidance should name the --openant-core flag and the
sibling layout (2/3 — RAPTOR_DIR is allowlisted).

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

def gateway_budget_arg(value: str) -> float:
    """argparse type for the per-run gateway spend-cap override:
    any finite USD amount > 0.

    Refusals happen at parse time, before any lifecycle state exists.
    No upper ceiling: the flag is operator argv — how much one run
    may spend is the operator's call. No uncapped spelling either
    (``0`` in the /audit resume ``--max-cost`` convention, or
    ``inf``): the dispatcher's child-token contract requires a finite
    budget > 0 by design — an uncapped token would present as capped
    while enforcing nothing — so the request is refused honestly with
    that reason instead of being translated into a made-up huge
    number. Zero/negative would otherwise mint an instantly-exhausted
    token, and nan flows through every budget comparison as
    effectively-uncapped. Budgets so large that the proportional
    request-cap scaling overflows float range (~1e305 dollars and up)
    refuse here too — see the inline comment.
    """
    import argparse
    import math
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid float value: {value!r}") from exc
    if budget == 0 or budget == math.inf:
        raise argparse.ArgumentTypeError(
            "uncapped gateway spend is not supported: dispatcher "
            "child tokens carry a finite budget by contract — pass "
            "the dollar amount this run may spend")
    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError(
            "gateway budget must be a positive finite dollar amount")
    # The mint scales the anti-runaway request cap proportionally
    # with the budget (scanner._mint_gateway_credentials); a budget
    # large enough that the scaled cap overflows float range would
    # crash there — refuse it here instead, keeping the contract
    # that refusals happen at parse time. No spend intent lives in
    # that range (~1e305 dollars); the import is lazy to keep this
    # module free of the scanner's heavier import graph.
    from .scanner import _GATEWAY_BUDGET_USD, _GATEWAY_REQUEST_BUDGET
    if not math.isfinite(
            _GATEWAY_REQUEST_BUDGET * budget / _GATEWAY_BUDGET_USD):
        raise argparse.ArgumentTypeError(
            f"gateway budget ${budget:g} is too large to scale the "
            f"anti-runaway request cap — pass a smaller value")
    return budget


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
    # Per-run operator raise of the dispatcher-gateway spend cap.
    # None = the scanner's shipped constants ($25 / 10k requests).
    # Always finite: the dispatcher's child-token contract has no
    # uncapped representation (allocate_child refuses non-finite
    # budgets by design), so "uncapped" is refused at the CLI
    # boundary (gateway_budget_arg), never smuggled through here.
    # Argv-only by design: no env twin (a spend authority must never
    # be steerable from anything the scanned repo or a child process
    # can influence). Only the gateway posture's mint reads it —
    # direct-credential and dispatcher-less runs ignore it with a
    # loud note (the operator's own key and its limits apply there).
    gateway_budget_usd: Optional[float] = None

    def validate(self) -> None:
        marker = self.core_path / _CORE_MARKER
        if not marker.exists():
            raise RuntimeError(
                f"OpenAnt core not found at {self.core_path!r}: "
                f"expected {_CORE_MARKER} to exist. "
                f"Pass --openant-core /path/to/libs/openant-core, or "
                f"install the checkout at <raptor-parent>/libs/openant-core."
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
        "OpenAnt core library not found. Either:\n"
        "  pass --openant-core /path/to/libs/openant-core, or\n"
        "  install the checkout at <raptor-parent>/libs/openant-core "
        "(auto-detected; a symlink works)\n"
        f"  ({OPENANT_CORE_ENV}=<path> also works, but only for direct "
        "raptor_openant.py invocations from an unscrubbed shell — the "
        "raptor.py dispatch lane rebuilds the child environment from "
        "the safe-env allowlist, which excludes it)\n"
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
