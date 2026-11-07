"""CLI entry point for ``raptor-sandbox-calibrate``.

Operator-facing surface for the generic binary calibrator. Three
modes:

  raptor-sandbox-calibrate --bin /usr/local/bin/claude
      Run the probe (or skip if cached & fresh) and print the
      profile in human-readable form.

  raptor-sandbox-calibrate --bin /usr/local/bin/claude --json
      Same, but emit the profile as JSON for piping into jq /
      tooling.

  raptor-sandbox-calibrate --bin /usr/local/bin/claude --show
      Print the cached profile WITHOUT spawning. Errors if no
      cache entry exists for the binary's current sha + env.

  raptor-sandbox-calibrate --bin /usr/local/bin/claude --clear
  raptor-sandbox-calibrate --clear-all
      Drop one or every cache entry. ``--clear-all`` is the
      operator's nuclear "forget everything" knob.

  raptor-sandbox-calibrate --bin /usr/local/bin/claude --force
      Ignore the cache and recalibrate. Useful after operator-side
      config changes that aren't covered by ``--env-key``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


_USAGE_EX = 64       # EX_USAGE
_SOFTWARE_EX = 70    # EX_SOFTWARE
_TIMEOUT_EX = 124    # timeout(1) convention


def _build_parser() -> argparse.ArgumentParser:
    from core.detectors.budget import positive_seconds

    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Home expansion failures and missing binaries exit 64. "
            "Input inspection failures exit 70. "
            "Cache cleanup exits 70 if an operation fails, including partial "
            "cleanup. Entry failures do not stop other entries.\n\n"
            "Examples:\n"
            "  raptor-sandbox-calibrate --bin /usr/bin/true --json --timeout 15\n"
            "  raptor-sandbox-calibrate --bin /usr/bin/true --show"
        ),
        prog="raptor-sandbox-calibrate",
        description=(
            "Probe a binary under sandbox(observe=True) and cache "
            "its filesystem + network reach for downstream allowlists."
        ),
    )
    p.add_argument(
        "--bin", metavar="PATH",
        help=(
            "Path to the binary to calibrate. Required except with "
            "--clear-all."
        ),
    )
    p.add_argument(
        "--probe-args", metavar="ARGS",
        default="--version",
        help=(
            "Argv for the probe, space-separated string. Default: "
            "``--version`` — every well-mannered CLI supports it "
            "and the version handler typically exercises the same "
            "startup paths as a real run. Use ``--probe-args=''`` "
            "for a no-arg probe (some binaries dump help on no "
            "args, which exercises broader paths)."
        ),
    )
    p.add_argument(
        "--env-key", metavar="KEY", action="append", default=[],
        dest="env_keys",
        help=(
            "Environment variable name whose value should affect "
            "the cache key. Repeatable. Tools with multi-provider "
            "configs (claude → CLAUDE_CODE_USE_BEDROCK + "
            "ANTHROPIC_BASE_URL; pip → PIP_INDEX_URL) want each "
            "discriminator listed here so the cache disambiguates "
            "per-config."
        ),
    )
    p.add_argument(
        "--timeout", type=positive_seconds, default=30.0, metavar="SECONDS",
        help="Positive finite wall-clock cap on the probe. Default: 30s.",
    )
    p.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Emit the profile as JSON (instead of human-readable).",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--show", action="store_true",
        help=(
            "Print the cached profile without spawning. Errors if "
            "no fresh cache entry exists for this binary."
        ),
    )
    mode.add_argument(
        "--force", action="store_true",
        help="Ignore the cache and re-run the probe.",
    )
    mode.add_argument(
        "--clear", action="store_true",
        help=(
            "Drop every cache entry for the named binary (across "
            "every ``--env-key`` variant). Use --clear-all to drop "
            "every entry for every binary."
        ),
    )
    mode.add_argument(
        "--clear-all", action="store_true",
        help="Drop every cache entry for every binary.",
    )
    return p


def _format_human(profile, *, cached: bool) -> str:
    """Pretty multi-line summary.

    Observed paths/hosts are chosen by the PROBED binary (it decides
    what to open/connect to) — escape them before the operator's
    terminal like every other foreign-derived print surface.
    """
    from core.security.log_sanitisation import (
        sanitise_for_terminal as _sft,
    )
    SAMPLE = 15
    lines = []
    lines.append(f"binary: {_sft(str(profile.binary_path), max_len=200)}")
    lines.append(f"  sha256:        {_sft(profile.binary_sha256[:16])}…")
    lines.append(f"  env signature: {_sft(profile.env_signature[:16])}…")
    lines.append(f"  captured at:   {_sft(str(profile.captured_at), max_len=200)}")
    lines.append(f"  source:        {'cache' if cached else 'fresh probe'}")
    lines.append(f"  probe argv:    {_sft(str(profile.probe_args), max_len=200)}")

    def _section(label, items, sample=SAMPLE) -> None:
        lines.append(f"\n{label} ({len(items)}):")
        if not items:
            lines.append("  (empty)")
            return
        lines.extend(f"  {_sft(str(x), max_len=300)}" for x in items[:sample])
        if len(items) > sample:
            lines.append(f"  ... (+{len(items) - sample} more)")

    _section("paths read", profile.paths_read)
    _section("paths written", profile.paths_written)
    _section("paths stat'd", profile.paths_stat)
    _section("proxy hosts", profile.proxy_hosts)
    if profile.connect_targets:
        lines.append(f"\nconnect targets ({len(profile.connect_targets)}):")
        lines.extend(
            f"  {_sft(str(t.ip), max_len=64)}:{t.port} ({_sft(str(t.family), max_len=32)})"
            for t in profile.connect_targets[:SAMPLE]
        )
        if len(profile.connect_targets) > SAMPLE:
            lines.append(
                f"  ... (+{len(profile.connect_targets) - SAMPLE} more)"
            )
    return "\n".join(lines)


def _profile_to_json(profile) -> str:
    """Stable JSON output for tooling consumers."""
    return profile.to_json()


def _print_clear_result(
    cleared: int, errors: list[tuple[Path, OSError]], *, bin_path: Path | None = None,
) -> int:
    """Report successful removals and any incomplete cleanup separately."""
    from core.security.log_sanitisation import (
        sanitise_exception_message,
        sanitise_for_terminal as _sft,
    )

    suffix = f" for {_sft(str(bin_path))}" if bin_path is not None else ""
    sys.stdout.write(f"cleared {cleared} profile(s){suffix}\n")
    if not errors:
        return 0
    path, error = errors[0]
    sys.stderr.write(
        f"raptor-sandbox-calibrate: {len(errors)} cache operation(s) failed; "
        f"first failure for {_sft(str(path))}: {sanitise_exception_message(error)}\n"
    )
    return _SOFTWARE_EX


def _cli_main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    from core.security.log_sanitisation import (
        sanitise_exception_message,
        sanitise_for_terminal as _sft,
    )
    from core.sandbox.errors import (
        SANDBOX_ENGAGE_EXIT_CODE,
        SandboxDisableRefusedError,
        SandboxSetupError,
    )

    # Lazy import — keep --help fast.
    from core.sandbox import calibrate as cal

    # --clear-all takes the bin-less path.
    if args.clear_all:
        errors: list[tuple[Path, OSError]] = []
        try:
            n = cal.clear_cache(None, errors=errors)
        except OSError as exc:
            sys.stderr.write(
                f"raptor-sandbox-calibrate: cannot clear profiles: {sanitise_exception_message(exc)}\n"
            )
            return _SOFTWARE_EX
        return _print_clear_result(n, errors)

    if not args.bin:
        parser.error("--bin is required (except with --clear-all)")

    try:
        bin_path = Path(args.bin).expanduser()
    except RuntimeError as exc:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: cannot expand binary path {_sft(str(args.bin))}: {sanitise_exception_message(exc)}\n"
        )
        return _USAGE_EX
    try:
        bin_exists = bin_path.exists()
    except OSError as exc:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: cannot inspect {_sft(str(bin_path))}: {sanitise_exception_message(exc)}\n"
        )
        return _SOFTWARE_EX
    if not bin_exists:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: {_sft(str(bin_path))}: not found\n"
        )
        return _USAGE_EX

    if args.clear:
        errors = []
        try:
            n = cal.clear_cache(bin_path, errors=errors)
        except OSError as exc:
            sys.stderr.write(
                f"raptor-sandbox-calibrate: cannot clear profiles for {_sft(str(bin_path))}: {sanitise_exception_message(exc)}\n"
            )
            return _SOFTWARE_EX
        return _print_clear_result(n, errors, bin_path=bin_path)

    probe_args = (
        tuple(args.probe_args.split()) if args.probe_args else ()
    )
    env_keys = tuple(args.env_keys or ())

    if args.show:
        # Cache-only path. Compute the fingerprint and look it up.
        try:
            bin_sha = cal._sha256_file(bin_path.resolve())
        except OSError as exc:
            sys.stderr.write(
                f"raptor-sandbox-calibrate: cannot hash {_sft(str(bin_path))}: {sanitise_exception_message(exc)}\n"
            )
            return _SOFTWARE_EX
        env_sig = cal._env_signature(env_keys)
        cached_profile = cal._load_matching_cache(bin_sha, env_sig, probe_args)
        if cached_profile is None:
            sys.stderr.write(
                f"raptor-sandbox-calibrate: no cached profile for "
                f"{_sft(str(bin_path))} (env keys: "
                f"{_sft(str(list(env_keys) or '(none)'))}). Run without --show "
                f"to create one.\n"
            )
            return _SOFTWARE_EX
        if args.json_output:
            sys.stdout.write(_profile_to_json(cached_profile) + "\n")
        else:
            sys.stdout.write(_format_human(cached_profile, cached=True) + "\n")
        return 0

    # Spawn path: load_or_calibrate handles cache hit / miss /
    # force.
    try:
        # Trace whether this run hit the cache or spawned. Two
        # observable side effects: load_or_calibrate returns the
        # cached profile when fresh; calibrate_binary writes a
        # fresh captured_at. We compare to detect.
        try:
            bin_sha = cal._sha256_file(bin_path.resolve())
        except OSError:
            bin_sha = None  # type: ignore[assignment]
        env_sig = cal._env_signature(env_keys)
        before = (
            cal._load_matching_cache(bin_sha, env_sig, probe_args)
            if bin_sha is not None and not args.force else None
        )
        profile = cal.load_or_calibrate(
            bin_path, probe_args=probe_args,
            env_keys=env_keys, force=args.force,
            timeout=args.timeout,
        )
        cached: bool = (
            before is not None
            and before.captured_at == profile.captured_at
        )
    except SandboxSetupError as exc:
        message = "; ".join(_sft(part)
                            for part in (exc.reason, exc.instructions) if part)
        if isinstance(exc, SandboxDisableRefusedError):
            parser.error(message)
        sys.stderr.write(f"raptor-sandbox-calibrate: {message}\n")
        return SANDBOX_ENGAGE_EXIT_CODE
    except FileNotFoundError as exc:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: {sanitise_exception_message(exc)}\n"
        )
        return _USAGE_EX
    except subprocess.TimeoutExpired:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: probe did not finish within "
            f"--timeout {args.timeout}s and was killed; no profile cached.\n"
        )
        return _TIMEOUT_EX
    except (RuntimeError, OSError) as exc:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: {sanitise_exception_message(exc)}\n"
        )
        return _SOFTWARE_EX

    if args.json_output:
        sys.stdout.write(_profile_to_json(profile) + "\n")
    else:
        sys.stdout.write(_format_human(profile, cached=cached) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
