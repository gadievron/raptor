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
import json
import sys
from pathlib import Path
from typing import Optional, Sequence


_USAGE_EX = 64       # EX_USAGE
_SOFTWARE_EX = 70    # EX_SOFTWARE


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
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
        "--timeout", type=float, default=30.0, metavar="SECONDS",
        help="Wall-clock cap on the probe. Default: 30s.",
    )
    p.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Emit the profile as JSON (instead of human-readable).",
    )
    p.add_argument(
        "--show", action="store_true",
        help=(
            "Print the cached profile without spawning. Errors if "
            "no fresh cache entry exists for this binary."
        ),
    )
    p.add_argument(
        "--force", action="store_true",
        help="Ignore the cache and re-run the probe.",
    )
    p.add_argument(
        "--clear", action="store_true",
        help=(
            "Drop every cache entry for the named binary (across "
            "every ``--env-key`` variant). Use --clear-all to drop "
            "every entry for every binary."
        ),
    )
    p.add_argument(
        "--clear-all", action="store_true",
        help="Drop every cache entry for every binary.",
    )
    return p


def _format_human(profile, *, cached: bool) -> str:
    """Pretty multi-line summary."""
    SAMPLE = 15
    lines = []
    lines.append(f"binary: {profile.binary_path}")
    lines.append(f"  sha256:        {profile.binary_sha256[:16]}…")
    lines.append(f"  env signature: {profile.env_signature[:16]}…")
    lines.append(f"  captured at:   {profile.captured_at}")
    lines.append(f"  source:        {'cache' if cached else 'fresh probe'}")
    lines.append(f"  probe argv:    {profile.probe_args}")

    def _section(label, items, sample=SAMPLE):
        lines.append(f"\n{label} ({len(items)}):")
        if not items:
            lines.append("  (empty)")
            return
        for x in items[:sample]:
            lines.append(f"  {x}")
        if len(items) > sample:
            lines.append(f"  ... (+{len(items) - sample} more)")

    _section("paths read", profile.paths_read)
    _section("paths written", profile.paths_written)
    _section("paths stat'd", profile.paths_stat)
    _section("proxy hosts", profile.proxy_hosts)
    if profile.connect_targets:
        lines.append(f"\nconnect targets ({len(profile.connect_targets)}):")
        for t in profile.connect_targets[:SAMPLE]:
            lines.append(f"  {t.ip}:{t.port} ({t.family})")
        if len(profile.connect_targets) > SAMPLE:
            lines.append(
                f"  ... (+{len(profile.connect_targets) - SAMPLE} more)"
            )
    return "\n".join(lines)


def _profile_to_json(profile) -> str:
    """Stable JSON output for tooling consumers."""
    return profile.to_json()


def _cli_main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Lazy import — keep --help fast.
    from core.sandbox import calibrate as cal

    # --clear-all takes the bin-less path.
    if args.clear_all:
        n = cal.clear_cache(None)
        sys.stdout.write(f"cleared {n} profile(s)\n")
        return 0

    if not args.bin:
        parser.error("--bin is required (except with --clear-all)")
        return _USAGE_EX

    bin_path = Path(args.bin).expanduser()
    if not bin_path.exists():
        sys.stderr.write(
            f"raptor-sandbox-calibrate: {bin_path}: not found\n"
        )
        return _USAGE_EX

    if args.clear:
        n = cal.clear_cache(bin_path)
        sys.stdout.write(
            f"cleared {n} profile(s) for {bin_path}\n"
        )
        return 0

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
                f"raptor-sandbox-calibrate: cannot hash {bin_path}: {exc}\n"
            )
            return _SOFTWARE_EX
        env_sig = cal._env_signature(env_keys)
        fp = cal._fingerprint(bin_sha, env_sig)
        cached = cal._load_from_cache(fp)
        if cached is None:
            sys.stderr.write(
                f"raptor-sandbox-calibrate: no cached profile for "
                f"{bin_path} (env keys: "
                f"{list(env_keys) or '(none)'}). Run without --show "
                f"to create one.\n"
            )
            return _SOFTWARE_EX
        if args.json_output:
            sys.stdout.write(_profile_to_json(cached) + "\n")
        else:
            sys.stdout.write(_format_human(cached, cached=True) + "\n")
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
            bin_sha = None
        env_sig = cal._env_signature(env_keys)
        fp = (cal._fingerprint(bin_sha, env_sig)
              if bin_sha is not None else None)
        before = (
            cal._load_from_cache(fp) if (fp and not args.force) else None
        )
        profile = cal.load_or_calibrate(
            bin_path, probe_args=probe_args,
            env_keys=env_keys, force=args.force,
            timeout=args.timeout,
        )
        cached = (
            before is not None
            and before.captured_at == profile.captured_at
        )
    except FileNotFoundError as exc:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: {exc}\n"
        )
        return _USAGE_EX
    except RuntimeError as exc:
        sys.stderr.write(
            f"raptor-sandbox-calibrate: {exc}\n"
        )
        return _SOFTWARE_EX

    if args.json_output:
        sys.stdout.write(_profile_to_json(profile) + "\n")
    else:
        sys.stdout.write(_format_human(profile, cached=cached) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
