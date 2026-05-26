"""``raptor-sca fingerprint`` subcommand.

Operator-facing CLI over :mod:`core.binary`'s fingerprint
primitive + baseline store. Three modes:

1. **Compute + print** — default. ``raptor-sca fingerprint
   /path/to/binary`` prints the fingerprint JSON to stdout.
2. **Save baseline** — ``--save`` writes the fingerprint to the
   store under the supplied ref. Subsequent scans / drift
   checks compare against this baseline.
3. **Check drift** — ``--check`` loads the previously-saved
   baseline (if any), computes the current fingerprint, prints
   the drift summary. Exits non-zero when drift is detected.

The input can be either a local file path (any binary) OR an
OCI image ref (``docker.io/library/alpine:3.18``) — for image
refs the main binary is fetched via the same extractor the
scan + bump pipelines use.

Co-Authored-By: Natalie Somersall <natalie.somersall@gmail.com>
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import SCA_CACHE_ROOT

logger = logging.getLogger(__name__)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = _parse_args(list(argv) if argv is not None else None)
    target = args.target

    # Resolve: local path or image ref?
    local_path = Path(target)
    if local_path.is_file():
        fp_input = ("path", local_path)
    else:
        fp_input = ("image_ref", target)

    cache_root = Path(args.cache_root) if args.cache_root else SCA_CACHE_ROOT
    store_dir = cache_root / "fingerprints"

    if args.check:
        return _cmd_check(fp_input, args, store_dir=store_dir)
    if args.save:
        return _cmd_save(fp_input, args, store_dir=store_dir)
    return _cmd_print(fp_input, args)


# ---------------------------------------------------------------------------
# Sub-modes
# ---------------------------------------------------------------------------


def _cmd_print(fp_input, args) -> int:
    """Default: compute the fingerprint, print as JSON."""
    fp = _fingerprint(fp_input, args)
    if fp is None:
        print(
            f"raptor-sca fingerprint: could not fingerprint "
            f"{fp_input[1]}",
            file=sys.stderr,
        )
        return 3
    return _emit_json(fp.to_dict(), args.out)


def _cmd_save(fp_input, args, *, store_dir: Path) -> int:
    """Save as baseline. The ``--ref`` flag specifies the store
    key (defaults to the input identifier — image ref or path)."""
    from core.binary import save_fingerprint

    fp = _fingerprint(fp_input, args)
    if fp is None:
        print(
            f"raptor-sca fingerprint: could not fingerprint "
            f"{fp_input[1]}",
            file=sys.stderr,
        )
        return 3
    ref = args.ref or str(fp_input[1])
    written = save_fingerprint(store_dir, ref, fp)
    if written is None:
        print(
            f"raptor-sca fingerprint: store write failed under "
            f"{store_dir}",
            file=sys.stderr,
        )
        return 3
    print(f"baseline saved: {ref}")
    return 0


def _cmd_check(fp_input, args, *, store_dir: Path) -> int:
    """Compare current fingerprint against stored baseline. Prints
    the drift summary and exits:
      * 0 — no baseline OR no drift
      * 1 — drift detected (use for CI gates)
      * 3 — fingerprinting failed (infrastructure error,
            distinguishable from drift)
    """
    from core.binary import detect_drift, load_fingerprint

    fp = _fingerprint(fp_input, args)
    if fp is None:
        print(
            f"raptor-sca fingerprint: could not fingerprint "
            f"{fp_input[1]}",
            file=sys.stderr,
        )
        return 3
    ref = args.ref or str(fp_input[1])
    baseline = load_fingerprint(store_dir, ref)
    if baseline is None:
        print(
            f"raptor-sca fingerprint: no baseline for {ref!r}; "
            f"use --save to seed one",
            file=sys.stderr,
        )
        return 0

    drift = detect_drift(baseline, fp)
    if drift.is_empty():
        print(f"no drift detected for {ref}")
        return 0

    summary = {
        "ref": ref,
        "high_severity": drift.high_severity(),
        "added_buckets": drift.added_buckets(),
        "removed_buckets": drift.removed_bucket_names(),
        "new_dangerous_imports": drift.new_buckets,
        "removed_dangerous_imports": drift.removed_buckets,
        "arch_changed": drift.arch_changed,
        "bits_changed": drift.bits_changed,
        "format_changed": drift.format_changed,
    }
    # An emit failure (e.g. --out points to a non-writable path)
    # demotes the drift signal to an infra-failure exit code (3)
    # because the operator can't have seen the drift JSON.
    emit_rc = _emit_json(summary, args.out)
    if emit_rc != 0:
        return emit_rc
    return 1


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------


def _fingerprint(fp_input, args):
    """Compute the fingerprint for either a local path or an
    image ref. Lazily imports the OCI extractor so the CLI
    starts fast when called with a local path."""
    from core.binary import capability_fingerprint

    kind, value = fp_input
    if kind == "path":
        return capability_fingerprint(value)

    # image_ref path — extract first
    return _fingerprint_image_ref(value, args)


def _fingerprint_image_ref(ref: str, args):
    """Pull the image, extract the main binary, fingerprint it.
    Reuses the bumper's OCI extractor."""
    from core.binary import capability_fingerprint
    from core.http import default_client
    from core.oci.client import OciRegistryClient
    from .bump.image_binary_extract import fetch_image_binary

    try:
        http = default_client()
        client = OciRegistryClient(http=http)
    except Exception as e:                            # noqa: BLE001
        logger.warning(
            "fingerprint_cli: OCI client construction failed: %s", e,
        )
        return None
    binary = fetch_image_binary(ref, client=client)
    if binary is None:
        return None
    try:
        return capability_fingerprint(binary)
    finally:
        try:
            binary.unlink()
        except OSError:
            pass


def _emit_json(payload, out_path: Optional[str]) -> int:
    """Print to stdout or write to ``out_path``. Returns 0 on
    success, 3 on I/O failure (matches the CLI's infra-failure
    exit code so CI gates can differentiate write errors from
    drift / no-drift)."""
    text = json.dumps(payload, sort_keys=True, indent=2)
    if not out_path:
        print(text)
        return 0
    try:
        Path(out_path).write_text(text + "\n")
    except OSError as e:
        print(
            f"raptor-sca fingerprint: --out write failed "
            f"({out_path!r}): {e}",
            file=sys.stderr,
        )
        return 3
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca fingerprint",
        description=(
            "Compute the capability fingerprint of a binary or OCI "
            "image's main binary. Use --save to seed a baseline, "
            "--check to compare against the stored baseline (exits "
            "1 on drift — suitable for CI gates)."
        ),
    )
    p.add_argument(
        "target",
        help=(
            "Either a local binary path OR an OCI image ref "
            "(e.g. ``docker.io/library/alpine:3.18``). Paths that "
            "exist as files take precedence over ref-shaped strings."
        ),
    )
    p.add_argument(
        "--out",
        help=(
            "Write JSON to this file. Default: stdout. Applies to "
            "both the default 'print fingerprint' mode and "
            "``--check`` drift output."
        ),
    )
    p.add_argument(
        "--ref",
        help=(
            "Store key under which to save / look up the baseline. "
            "Defaults to the target argument verbatim. Use this "
            "when you want one baseline to represent multiple "
            "paths (e.g. the same binary extracted to different "
            "tempdirs across CI runs)."
        ),
    )
    p.add_argument(
        "--cache-root",
        help=(
            "Override the cache root directory. Default: SCA "
            "cache root (``~/.raptor/cache/sca``). Fingerprint "
            "store lives at ``<cache_root>/fingerprints/``."
        ),
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--save", action="store_true",
        help=(
            "Save the computed fingerprint as the baseline for "
            "``--ref`` (or the target identifier). Replaces any "
            "previous baseline."
        ),
    )
    mode.add_argument(
        "--check", action="store_true",
        help=(
            "Compare current fingerprint against the stored "
            "baseline. Exits 0 when no drift, 1 on drift "
            "(CI gate semantic). Prints drift summary JSON to "
            "stdout / --out when drift is detected."
        ),
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
