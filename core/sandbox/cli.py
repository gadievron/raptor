"""Command-line flags for sandbox control.

The ONLY legitimate way for a user to downgrade sandbox isolation is
via `--sandbox <profile>` or `--no-sandbox`, parsed by an entry script's
argparse. No env var, config file, or target-repo content reaches these
functions — that's the prompt-injection-safety requirement.

Every RAPTOR entry point that runs subprocesses should call `add_cli_args`
during parser construction and `apply_cli_args` right after `parse_args`.
"""

import argparse
import logging
import sys

from . import state
from . import tiers as _tiers
from .profiles import PROFILES

logger = logging.getLogger(__name__)

# The --sandbox-floor vocabulary: the consentable tier labels plus
# "none". "none" parses so the misuse is refused LOUDLY at the point
# it would matter (an untrusted-class call) with a message naming the
# real surface (--sandbox none / --no-sandbox) — see
# tiers.resolve_call_floor's never-BARE-by-consent arm.
SANDBOX_FLOOR_CHOICES = (*_tiers.CONSENTABLE_FLOOR_LABELS, "none")


def _set_cli_state(profile: str) -> None:
    """Internal: update both CLI-state flags coherently. No logging.

    Single source of truth for transitions so disable_from_cli() and
    set_cli_profile() can't desync the two globals.
    """
    if profile not in PROFILES:
        msg = (
            f"Unknown sandbox profile {profile!r}. "
            f"Valid profiles: {sorted(PROFILES)}."
        )
        raise ValueError(msg)
    state._cli_sandbox_profile = profile
    state._cli_sandbox_disabled = (profile == "none")


def disable_from_cli() -> None:
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
    logger.warning("Sandbox profile forced to %r by CLI --sandbox flag", profile)
    _set_cli_state(profile)


def _validate_floor_label(label: str, *, surface: str,
                          allow_none: bool) -> None:
    """Shared validation for the two floor-consent setters.

    Linux tier labels are refused on macOS rather than mapped:
    cross-platform tier comparability is refused by design (see
    core/sandbox/tiers.py) — the untrusted contract on macOS is the
    seatbelt tier, and RAPTOR_ALLOW_DEGRADED_UNTRUSTED remains the
    only documented lowering surface there.
    """
    valid = (SANDBOX_FLOOR_CHOICES if allow_none
             else _tiers.CONSENTABLE_FLOOR_LABELS)
    if label not in valid:
        msg = (
            f"Unknown sandbox floor {label!r} for {surface}. "
            f"Valid values: {', '.join(valid)}."
        )
        raise ValueError(msg)
    if sys.platform == "darwin" and label != "none":
        msg = (
            f"{surface}={label!r} names a Linux containment tier — "
            f"not applicable on macOS, where the untrusted contract "
            f"is the seatbelt tier (cross-platform tier comparison "
            f"is refused, not fudged). On macOS "
            f"RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 remains the only "
            f"lowering surface."
        )
        raise ValueError(msg)


def set_cli_sandbox_floor(label: str) -> None:
    """Called by entry points when `--sandbox-floor <tier>` is passed.

    Sets the per-run untrusted containment floor — the highest-
    precedence consent surface (flag > project setting > legacy env
    var > default-refuse). Works in BOTH directions: lowering
    (`landlock` accepts Landlock/seccomp-only containment for
    untrusted work on this run) and raising (`mount-ns` pins the full
    contract, overriding a project setting or the env waiver).

    Same prompt-injection contract as set_cli_profile(): called only
    from CLI-parsed argparse values — never from env, config, or
    target repo content.
    """
    _validate_floor_label(label, surface="--sandbox-floor",
                          allow_none=True)
    logger.warning(
        "Sandbox untrusted containment floor set to %r by CLI "
        "--sandbox-floor flag", label,
    )
    state._cli_sandbox_floor = label


def set_project_sandbox_floor(label: str) -> None:
    """Project-surface twin of set_cli_sandbox_floor().

    Called ONLY by the run-start project consumption path
    (core.project.trust.apply_project_sandbox_floor) with the active
    project's registry-validated ``sandbox-floor`` setting —
    operator-written on-disk config under the RAPTOR projects dir,
    never content from the scanned repo or the cwd. The per-run
    ``--sandbox-floor`` flag beats it in both directions at floor
    resolution (core.sandbox.context.resolve_untrusted_floor).

    ``none`` is refused here outright: a standing bare floor is not a
    project-consentable value (the registry never stores it either) —
    untrusted work never runs bare by consent.
    """
    _validate_floor_label(label, surface="project setting sandbox-floor",
                          allow_none=False)
    logger.info(
        "Sandbox untrusted containment floor set to %r by the active "
        "project's sandbox-floor setting (per-run --sandbox-floor "
        "overrides)", label,
    )
    state._project_sandbox_floor = label


def set_cli_readable_paths(paths: list) -> None:
    """Called by entry points when `--sandbox-readable-path` is passed.

    Extends `readable_paths` on every subsequent `sandbox()` / `run()`
    in the process. Loosens isolation, so the set_cli_profile() rule
    applies with extra force: called only from CLI-parsed argparse
    values — never from env, config, or target repo content.
    """
    logger.warning(
        "Sandbox read allowlist extended via --sandbox-readable-path: %s",
        ", ".join(paths),
    )
    state._cli_sandbox_readable_paths = list(paths)


def set_cli_tool_paths(paths: list) -> None:
    """Called by entry points when `--sandbox-tool-path` is passed.

    Extends `tool_paths` (read allowlist + mount-ns read-only bind) on
    every subsequent `sandbox()` / `run()` in the process. Same
    CLI-parsed-values-only contract as set_cli_readable_paths().
    """
    logger.warning(
        "Sandbox tool paths extended via --sandbox-tool-path: %s",
        ", ".join(paths),
    )
    state._cli_sandbox_tool_paths = list(paths)


def add_cli_args(parser: argparse.ArgumentParser) -> None:
    """Attach `--sandbox {full,debug,network-only,none}`, `--no-sandbox`,
    `--audit`, `--audit-verbose`, `--audit-budget`,
    `--sandbox-readable-path`, and `--sandbox-tool-path` to an argparse
    parser. Every RAPTOR entry point should call this so users get a
    consistent sandbox-control surface regardless of which command they
    launched.

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
             "(full | strict | debug | target_run | frida | "
             "network-only | none). "
             "Overrides any profile chosen in code. "
             "'strict' = full that FAILS rather than degrades when a "
             "backend is missing, plus read restriction ($HOME denied) "
             "by default — use for hostile code when silent downgrade "
             "is unacceptable. "
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
    parser.add_argument(
        "--sandbox-floor", choices=list(SANDBOX_FLOOR_CHOICES),
        default=None, dest="sandbox_floor", metavar="TIER",
        help="Per-run consent for the UNTRUSTED containment floor "
             "(mount-ns | mountless-ns | ns-only | landlock | none). "
             "Untrusted-class work (attacker-derived payloads, PoC "
             "execution, target binaries) refuses to run below this "
             "tier; lanes at or above it are admitted. Lowering "
             "(e.g. 'landlock' on a host without user namespaces) "
             "accepts exactly the named tier and nothing below it; "
             "raising (e.g. 'mount-ns') pins the full contract, "
             "overriding the project's sandbox-floor setting and "
             "the RAPTOR_ALLOW_DEGRADED_UNTRUSTED env var "
             "(precedence: this flag > project setting > env var > "
             "default-refuse; a banner names both surfaces on "
             "disagreement). 'none' is NOT a consentable untrusted "
             "floor — untrusted work never runs bare by consent; "
             "use the authoritative --sandbox none / --no-sandbox "
             "for the global sandbox-off. Orthogonal to --sandbox "
             "(profile = enforcement strictness; floor = minimum "
             "delivered containment tier). The degraded-NETWORK "
             "acceptance stays env-var-only (network is a separate "
             "axis, not a tier); no tier waives a missing libseccomp "
             "(every tier includes the filter), and an explicit "
             "floor withdraws the env waiver's filterless "
             "acceptance. The construction-time Landlock-"
             "enforceability acceptance follows the same chain for "
             "ALL calls (the env var's existing host-wide reach), so "
             "a raised floor also refuses it for trusted "
             "policy-bearing calls on Landlock-less kernels.",
    )
    parser.add_argument(
        "--sandbox-readable-path", action="append", default=None,
        dest="sandbox_readable_paths", metavar="PATH",
        help="Extend the sandbox read allowlist with PATH (repeatable; "
             "file or directory). Only meaningful under read-restricting "
             "runs ('strict', or call sites setting restrict_reads) — "
             "the self-service fix when a tool inside the sandbox is "
             "denied a read it legitimately needs (diagnose with "
             "--audit; sandbox-summary.json names the path). This "
             "LOOSENS isolation: prefer the narrowest path that fixes "
             "the denial, never $HOME itself.",
    )
    parser.add_argument(
        "--sandbox-tool-path", action="append", default=None,
        dest="sandbox_tool_paths", metavar="DIR",
        help="Make an operator-installed tool directory visible inside "
             "the sandbox (repeatable): added to the read allowlist and "
             "bind-mounted read-only in mount-namespace mode. For "
             "toolchains outside the system dirs — pip --user, pyenv, "
             "~/.cargo/bin, /usr/local installs. This LOOSENS "
             "isolation: pass the tool's bin/prefix dir, not $HOME.",
    )
    parser.add_argument(
        "--audit-budget", type=int, dest="audit_budget", default=None,
        metavar="N",
        help="With --audit: override the global audit-record cap "
             "(default 10000). Per-category and per-PID sub-caps "
             "scale proportionally — set higher for long-running "
             "workloads under --audit-verbose, lower for quick "
             "diagnostic runs where you only want the first few "
             "events. The budget protects the JSONL from a chatty "
             "target generating gigabytes of records.",
    )


def apply_cli_args(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser | None = None,
) -> None:
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
    budget = getattr(args, "audit_budget", None)
    no_sandbox = bool(getattr(args, "no_sandbox", False))
    profile = getattr(args, "sandbox", None)
    readable = getattr(args, "sandbox_readable_paths", None)
    tool_dirs = getattr(args, "sandbox_tool_paths", None)
    floor = getattr(args, "sandbox_floor", None)

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
    if budget is not None:
        if not audit:
            _fail(
                "--audit-budget requires --audit (the budget only "
                "applies to audit-mode JSONL output)"
            )
        if budget <= 0:
            _fail(
                f"--audit-budget must be a positive integer; got "
                f"{budget!r}. Use a small value (e.g. 100) for "
                f"quick diagnostic runs, the default 10000 for "
                f"normal use, or a larger value for long-running "
                f"--audit-verbose sessions."
            )
        # Upper clamp: 10M records at the average ~200 bytes/record
        # bound (cmd + path + serialised args) is ~2GB of JSONL.
        # Anything past that almost certainly indicates an
        # operator typo (one extra zero) rather than a real
        # intent — fail loud rather than letting a runaway audit
        # eat /tmp.
        _AUDIT_BUDGET_MAX = 10_000_000
        if budget > _AUDIT_BUDGET_MAX:
            _fail(
                f"--audit-budget={budget} exceeds the upper clamp "
                f"({_AUDIT_BUDGET_MAX}). At ~200 bytes per record "
                f"that's ~2GB of JSONL — almost certainly a typo. "
                f"Lower the value or split into multiple shorter "
                f"runs."
            )
    if audit and (no_sandbox or profile == "none"):
        _fail(
            "--audit is incoherent with --sandbox none / --no-sandbox: "
            "no enforcement layers active means there's nothing to "
            "compare against. Use --sandbox full --audit (default) "
            "to engage audit mode."
        )
    if floor is not None:
        if no_sandbox or profile == "none":
            _fail(
                "--sandbox-floor is incoherent with --sandbox none / "
                "--no-sandbox: with the sandbox globally disabled "
                "(the authoritative operator surface) there is no "
                "containment floor to hold. Drop --sandbox-floor, or "
                "drop the disable."
            )
        if sys.platform == "darwin" and floor != "none":
            _fail(
                f"--sandbox-floor {floor} names a Linux containment "
                f"tier — not applicable on macOS, where the untrusted "
                f"contract is the seatbelt tier (cross-platform tier "
                f"comparison is refused, not fudged). On macOS "
                f"RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 remains the only "
                f"lowering surface."
            )
    # Allowlist extensions: validate existence up-front (a typo'd path
    # would otherwise surface later as the very read-denial the flag
    # was meant to fix), and reject the incoherent no-sandbox combo.
    _validated_readable: list | None = None
    _validated_tools: list | None = None
    if readable or tool_dirs:
        if no_sandbox or profile == "none":
            _fail(
                "--sandbox-readable-path / --sandbox-tool-path are "
                "incoherent with --sandbox none / --no-sandbox: with "
                "no sandbox there is no allowlist to extend."
            )
        from pathlib import Path as _Path
        if readable:
            _validated_readable = []
            for p in readable:
                rp = _Path(p).expanduser().resolve()
                if not rp.exists():
                    _fail(
                        f"--sandbox-readable-path does not exist: {p} "
                        f"(resolved to {rp})"
                    )
                _validated_readable.append(str(rp))
        if tool_dirs:
            _validated_tools = []
            for p in tool_dirs:
                rp = _Path(p).expanduser().resolve()
                if not rp.is_dir():
                    _fail(
                        f"--sandbox-tool-path is not a directory: {p} "
                        f"(resolved to {rp})"
                    )
                _validated_tools.append(str(rp))

    if no_sandbox:
        disable_from_cli()
    elif profile is not None:
        set_cli_profile(profile)
    if floor is not None:
        set_cli_sandbox_floor(floor)
    if audit:
        state._cli_sandbox_audit = True
        logger.warning(
            "Sandbox audit mode engaged via --audit "
            "(workflow runs but enforcement events are logged not blocked)"
        )
    if verbose:
        state._cli_sandbox_audit_verbose = True
    if budget is not None:
        state._cli_sandbox_audit_budget = int(budget)
    if _validated_readable:
        set_cli_readable_paths(_validated_readable)
    if _validated_tools:
        set_cli_tool_paths(_validated_tools)
