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
    """Attach `--sandbox {full,debug,network-only,none}`, `--no-sandbox`,
    `--audit`, and `--audit-verbose` to an argparse parser. Every RAPTOR
    entry point should call this so users get a consistent sandbox-
    control surface regardless of which command they launched.

    Profile (`--sandbox` or `--no-sandbox`) sets ENFORCEMENT strictness.
    `--audit` is ORTHOGONAL — it engages audit mode on the active
    profile (proxy log-and-allow + SCMP_ACT_TRACE + tracer subprocess
    that records would-be-blocked events). `--audit-verbose` is
    meaningful only with `--audit` — it flips the tracer from filtered
    (would-be-blocked only) to strace-style (every traced syscall).
    The flag name is namespaced (`--audit-verbose` rather than plain
    `--verbose`) to avoid collision with entry-points that may have
    their own `--verbose` for log-level control.

    Granularity: the profile lets users loosen one layer without
    disabling everything — e.g. `--sandbox network-only` keeps
    namespace network block but drops Landlock, useful when a build
    script trips Landlock but network isolation is still desired.

    `--sandbox` and `--no-sandbox` are mutually exclusive at the
    argparse level — users who pass both get a clear error at parse
    time rather than silent tie-breaking.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--sandbox", choices=sorted(PROFILES.keys()), default=None,
        help="Force sandbox profile "
             "(debug | full | network-only | none). "
             "Overrides any profile chosen in code. "
             "'debug' for gdb/rr work (allows ptrace). "
             "'network-only' if Landlock or seccomp is breaking your "
             "build, 'none' only as last resort. "
             "Combine with --audit to log what enforcement WOULD have "
             "blocked instead of actually blocking.",
    )
    group.add_argument(
        "--no-sandbox", action="store_true", dest="no_sandbox",
        help="Alias for --sandbox none. Disables all subprocess isolation.",
    )
    parser.add_argument(
        "--audit", action="store_true", dest="audit",
        help="Engage audit mode: workflow runs to completion AND records "
             "what enforcement would have blocked (filtered to would-be-"
             "denied events). Composes with --sandbox: `--sandbox debug "
             "--audit` runs gdb-friendly + audit; `--sandbox full --audit` "
             "is the typical 'audit' use case. Incoherent with "
             "`--sandbox none` / `--no-sandbox`.",
    )
    parser.add_argument(
        "--audit-verbose", action="store_true", dest="audit_verbose",
        help="With --audit: log EVERY traced syscall (strace-style "
             "diagnostic), not just would-be-blocked. Higher record "
             "volume — expect thousands of records per run. Requires "
             "--audit. Distinct from any entry-point's own --verbose "
             "flag (which controls log level, not audit output).",
    )


def apply_cli_args(args, parser=None) -> None:
    """Called right after argparse parsing to propagate the user's choice
    into the sandbox module state. Safe to call when neither flag was
    passed (no-op in that case).

    The two `--sandbox` / `--no-sandbox` flags are mutually exclusive at
    argparse time (see `add_cli_args`), so this function never has to
    arbitrate between them.

    Validates incoherent audit combinations:
    - `--audit-verbose` without `--audit` is meaningless.
    - `--audit` with `--sandbox none` / `--no-sandbox` has nothing to
      audit against (no enforcement layers active).

    On invalid combinations:
    - If `parser` is provided (CLI entry-points pass it), validation
      errors trigger `parser.error()` which prints a clean usage
      message and exits with code 2 — operators see argparse-style
      output, not a Python traceback.
    - If `parser` is None (library callers / tests), validation
      errors raise `ValueError` so they can be caught programmatically.

    Not idempotent with respect to logs — calling twice produces two
    WARNING lines. In normal use this is called once per process.
    """
    audit = bool(getattr(args, "audit", False))
    verbose = bool(getattr(args, "audit_verbose", False))
    no_sandbox = bool(getattr(args, "no_sandbox", False))
    profile = getattr(args, "sandbox", None)

    def _fail(msg: str) -> None:
        if parser is not None:
            parser.error(msg)  # exits with code 2, clean UX
        raise ValueError(msg)

    # Validate audit combinations BEFORE mutating state.
    if verbose and not audit:
        _fail(
            "--audit-verbose requires --audit (audit-verbose only "
            "controls audit-mode tracer output)"
        )
    if audit and (no_sandbox or profile == "none"):
        _fail(
            "--audit is incoherent with --sandbox none / --no-sandbox: "
            "no enforcement layers active means there's nothing to "
            "compare against. Use --sandbox full --audit (default) "
            "to engage audit mode."
        )

    if no_sandbox:
        disable_from_cli()
    elif profile is not None:
        set_cli_profile(profile)
    if audit:
        state._cli_sandbox_audit = True
        logger.warning(
            "Sandbox audit mode engaged via --audit "
            "(workflow runs but enforcement events are logged not blocked)"
        )
    if verbose:
        state._cli_sandbox_audit_verbose = True
