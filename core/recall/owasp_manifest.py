"""Generate a recall manifest from the pinned OWASP Benchmark clone.

Converts OWASP's own ground truth (``expectedresults-1.2.csv``: every
``BenchmarkTestNNNNN`` labelled real-or-not per CWE) into the recall
manifest format:

* real vulnerabilities become ``expected`` entries (file-level — the
  suite labels whole test files, not lines);
* not-real cases (same pattern with a sanitizer applied) become
  ``clean_regions`` — findings there count as FPs on labelled-clean
  code, never as recall.

The Benchmark itself is NOT bundled; this generator reads the
operator-acquired clone pinned in ``core/dataflow/corpus/SOURCES.md``
and refuses to run against any other sha (labels are sha-bound).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from core.dataflow.owasp_corpus_generator import parse_expected_results

from core.recall.manifest import SCHEMA_VERSION

#: Must match core/dataflow/corpus/SOURCES.md.
OWASP_REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava"
OWASP_PINNED_SHA = "b06d6efaebd577a327514364951916e7df3290b4"
OWASP_DEFAULT_CLONE = "out/dataflow-corpus-fixtures/owasp-benchmark-java"
# Retained for operators who explicitly want a traced build (trusted
# clone): the historical Benchmark package command.
OWASP_BUILD_COMMAND = "mvn -B -DskipTests clean package"
_TESTCODE_DIR = "src/main/java/org/owasp/benchmark/testcode"
_EXPECTED_CSV = "expectedresults-1.2.csv"

_ACQUIRE_HINT = (
    "clone instructions live in core/dataflow/corpus/SOURCES.md "
    "(offline hosts: clone on a connected machine and copy the tree)"
)


class OwaspManifestError(RuntimeError):
    pass


def _verify_clone(clone_dir: Path) -> None:
    if not clone_dir.is_dir():
        msg = (
            f"OWASP Benchmark clone not found at {clone_dir} — "
            f"{_ACQUIRE_HINT}"
        )
        raise OwaspManifestError(msg)
    csv_path = clone_dir / _EXPECTED_CSV
    if not csv_path.is_file():
        msg = (
            f"{csv_path} missing — the clone is incomplete; "
            f"{_ACQUIRE_HINT}"
        )
        raise OwaspManifestError(msg)
    try:
        proc = subprocess.run(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        head = proc.stdout.strip().lower()
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"cannot sha-verify {clone_dir}: {exc}"
        raise OwaspManifestError(msg) from exc
    if proc.returncode != 0 or not head:
        msg = f"cannot sha-verify {clone_dir}: {proc.stderr.strip()}"
        raise OwaspManifestError(msg)
    if head != OWASP_PINNED_SHA:
        msg = (
            f"{clone_dir} is at {head[:12]}, labels are pinned to "
            f"{OWASP_PINNED_SHA[:12]} — re-checkout the pin "
            f"({_ACQUIRE_HINT})"
        )
        raise OwaspManifestError(msg)


def _entry(test_name: str, cwe: int) -> dict:
    return {
        "id": test_name,
        "file": f"{_TESTCODE_DIR}/{test_name}.java",
        "line_start": None,
        "line_end": None,
        "cwe": f"CWE-{cwe}",
        "provenance": {
            "kind": "benchmark",
            "suite": "owasp-benchmark-java",
            "case": test_name,
        },
    }


def generate_manifest(clone_dir: Path, *, cwes: list[int] | None = None,
                      limit: int | None = None) -> dict:
    """Build the manifest dict from the verified clone.

    ``cwes`` filters to specific CWE numbers (default: all in the
    suite); ``limit`` caps expected entries per CWE (deterministic:
    sorted by test name) for cheap smoke measurements.
    """
    _verify_clone(clone_dir)
    labels = parse_expected_results(clone_dir / _EXPECTED_CSV)
    if not labels:
        msg = (
            f"no labelled test cases parsed from "
            f"{clone_dir / _EXPECTED_CSV}"
        )
        raise OwaspManifestError(msg)

    wanted = set(cwes) if cwes else None
    expected: list[dict] = []
    clean: list[dict] = []
    per_cwe_count: dict[int, int] = {}
    for test_name in sorted(labels):
        cwe, is_real = labels[test_name]
        if wanted is not None and cwe not in wanted:
            continue
        if is_real:
            if limit is not None:
                n = per_cwe_count.get(cwe, 0)
                if n >= limit:
                    continue
                per_cwe_count[cwe] = n + 1
            expected.append(_entry(test_name, cwe))
        else:
            clean.append(_entry(test_name, cwe))

    if not expected:
        msg = "no expected entries survived the CWE filter"
        raise OwaspManifestError(msg)

    return {
        "schema_version": SCHEMA_VERSION,
        "name": "owasp-benchmark-java",
        "target": {
            "repo_url": OWASP_REPO_URL,
            "pinned_sha": OWASP_PINNED_SHA,
            "local_path": str(clone_dir),
        },
        "language": "java",
        # No build_command: Java databases extract buildless by default
        # (--build-mode=none), and a traced Maven build cannot fetch
        # dependencies under the network-blocked create sandbox anyway —
        # emitting one only buys a doomed traced attempt before the
        # buildless fallback fires.
        "profile": "scan-codeql",
        "tolerance": {"line_drift": 0, "cwe_family_match": True},
        "expected": expected,
        "clean_regions": clean,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-recall-measure owasp-manifest",
        description=__doc__.splitlines()[0],
    )
    p.add_argument("--clone-dir", type=Path,
                   default=Path(OWASP_DEFAULT_CLONE))
    p.add_argument("--out", type=Path, required=True,
                   help="manifest JSON output path")
    p.add_argument("--cwe", action="append", type=int, default=[],
                   help="restrict to CWE number (repeatable)")
    p.add_argument("--limit", type=int, default=None,
                   help="cap expected entries per CWE (sorted, "
                        "deterministic)")
    args = p.parse_args(argv)

    try:
        manifest = generate_manifest(
            args.clone_dir, cwes=args.cwe or None, limit=args.limit)
    except OwaspManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n",
                        encoding="utf-8")
    print(f"manifest: {args.out} "
          f"({len(manifest['expected'])} expected, "
          f"{len(manifest['clean_regions'])} clean regions)")
    return 0
