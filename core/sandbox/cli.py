"""Command-line flags for sandbox control.

The ONLY legitimate way for a user to downgrade sandbox isolation is
via `--sandbox <profile>` or `--no-sandbox`, parsed by an entry script's
argparse. No env var, config file, or target-repo content reaches these
functions — that's the prompt-injection-safety requirement.

Every RAPTOR entry point that runs subprocesses should call `add_cli_args`
during parser construction and `apply_cli_args` right after `parse_args`.
"""

import logging

from . import state
from .profiles import PROFILES

logger = logging.getLogger(__name__)


def _set_cli_state(profile: str) -> None:
    """Internal: update both CLI-state flags coherently. No logging.

    Single source of truth for transitions so disable_from_cli() and
    set_cli_profile() can't desync the two globals.
    """
    if profile not in PROFILES:
        raise ValueError(
            f"Unknown sandbox profile {profile!r}. "
            f"Valid profiles: {sorted(PROFILES)}."
        )
    state._cli_sandbox_profile = profile
    state._cli_sandbox_disabled = (profile == "none")


def disable_from_cli():
    """Called by command entry points when `--no-sandbox` is passed.

    Produces the same post-condition as `set_cli_profile('none')` — both
    routes call `_set_cli_state('none')` under the hood. The difference
    is the WARNING log line: this function logs "Sandboxing disabled by
    --no-sandbox flag" naming the specific CLI flag the user passed, so
    audit logs attribute the disable to `--no-sandbox` rather than
    `--sandbox none`. Call sites should match the flag users typed.
    """
    logger.warning("Sandboxing disabled by --no-sandbox flag")
    _set_cli_state("none")


def set_cli_profile(profile: str) -> None:
    """Called by entry points when `--sandbox <profile>` is passed.

    Forces every subsequent `sandbox()` / `run()` invocation in the process
    to use the named profile regardless of what the code requests. This is
    the granular alternative to `--no-sandbox`: users can pick `full`,
    `network-only`, or `none` instead of a binary on/off.

    Called only from CLI-parsed argparse values — never from env, config,
    or target repo content — to keep the sandbox unescapable by prompt
    injection.
    """
    logger.warning(f"Sandbox profile forced to {profile!r} by CLI --sandbox flag")
    _set_cli_state(profile)


def add_cli_args(parser) -> None:
    """Attach `--sandbox {full,network-only,none}` and `--no-sandbox` to an
    argparse parser. Every RAPTOR entry point should call this so users get
    a consistent sandbox-control surface regardless of which command they
    launched.

    Granularity: the profile lets users loosen one layer without disabling
    everything — e.g. `--sandbox network-only` keeps namespace network
    block but drops Landlock, useful when a build script trips Landlock
    but network isolation is still desired.

    The two flags are mutually exclusive at the argparse level — users who
    pass both get a clear error at parse time rather than silent tie-
    breaking.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--sandbox", choices=sorted(PROFILES.keys()), default=None,
        help="Force sandbox profile "
             "(full | debug | network-only | none). "
             "Overrides any profile chosen in code. "
             "Use 'debug' for gdb/rr work (allows ptrace), "
             "'network-only' if Landlock or seccomp is breaking your "
             "build, 'none' only as last resort.",
    )
    group.add_argument(
        "--no-sandbox", action="store_true", dest="no_sandbox",
        help="Alias for --sandbox none. Disables all subprocess isolation.",
    )


def apply_cli_args(args) -> None:
    """Called right after argparse parsing to propagate the user's choice
    into the sandbox module state. Safe to call when neither flag was
    passed (no-op in that case).

    The two flags are mutually exclusive at argparse time (see
    `add_cli_args`), so this function never has to arbitrate between them.

    Not idempotent with respect to logs — calling twice produces two
    WARNING lines. In normal use this is called once per process.
    """
    if getattr(args, "no_sandbox", False):
        disable_from_cli()
    elif getattr(args, "sandbox", None) is not None:
        set_cli_profile(args.sandbox)
