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

``--per-cwe`` splits the same ground truth into one manifest per CWE
class (the suite spans several), so each class can be run, scored,
and compared on its own; a class whose every case is labelled
not-real becomes an ``fp-only`` manifest.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.dataflow.owasp_corpus_generator import parse_expected_results
from core.json import save_json
from core.recall.manifest import SCHEMA_VERSION
from core.recall.pinned_clone import verify_pinned_clone

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
    verify_pinned_clone(clone_dir, OWASP_PINNED_SHA,
                        error_cls=OwaspManifestError,
                        hint=_ACQUIRE_HINT)


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


def generate_per_cwe_manifests(
        clone_dir: Path, *, cwes: list[int] | None = None,
        limit: int | None = None) -> dict[int, dict]:
    """Split the Benchmark's ground truth into one manifest per CWE.

    The suite spans several CWE classes; per-CWE manifests let each
    class be run and compared on its own. Entry dicts are carried
    VERBATIM from the combined manifest (never rebuilt), so any keys
    a future label shape adds pass through unchanged. A CWE whose
    every case is labelled not-real becomes an ``fp-only`` manifest
    (clean regions are the measurement); a CWE with no cases at all
    emits nothing.
    """
    combined = generate_manifest(clone_dir, cwes=cwes, limit=limit)
    by_cwe: dict[int, dict] = {}

    def _shell(cwe: int) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "name": f"owasp-benchmark-java-cwe{cwe}",
            "target": dict(combined["target"]),
            "language": combined["language"],
            "profile": combined["profile"],
            "tolerance": dict(combined["tolerance"]),
            "expected": [],
            "clean_regions": [],
        }

    for key in ("expected", "clean_regions"):
        for entry in combined[key]:
            cwe = int(entry["cwe"].split("-", 1)[1])
            by_cwe.setdefault(cwe, _shell(cwe))[key].append(entry)
    for manifest in by_cwe.values():
        if not manifest["expected"]:
            manifest["corpus_kind"] = "fp-only"
    return by_cwe


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="recall-measure owasp-manifest",
        description=__doc__.splitlines()[0],
    )
    p.add_argument("--clone-dir", type=Path,
                   default=Path(OWASP_DEFAULT_CLONE))
    p.add_argument("--out", type=Path, default=None,
                   help="manifest JSON output path (single-manifest "
                        "mode)")
    p.add_argument("--cwe", action="append", type=int, default=[],
                   help="restrict to CWE number (repeatable)")
    p.add_argument("--limit", type=int, default=None,
                   help="cap expected entries per CWE (sorted, "
                        "deterministic)")
    p.add_argument("--per-cwe", action="store_true",
                   help="emit one manifest per CWE class instead of "
                        "the combined manifest")
    p.add_argument("--out-dir", type=Path, default=None,
                   help="output directory for --per-cwe manifests")
    args = p.parse_args(argv)
    if args.per_cwe:
        if args.out_dir is None or args.out is not None:
            p.error("--per-cwe writes multiple manifests: pass "
                    "--out-dir (and not --out)")
    elif args.out is None:
        p.error("--out is required (or use --per-cwe --out-dir)")

    try:
        if args.per_cwe:
            manifests = generate_per_cwe_manifests(
                args.clone_dir, cwes=args.cwe or None, limit=args.limit)
        else:
            manifest = generate_manifest(
                args.clone_dir, cwes=args.cwe or None, limit=args.limit)
    except OwaspManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.per_cwe:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for cwe in sorted(manifests):
            m = manifests[cwe]
            path = args.out_dir / f"{m['name']}.json"
            save_json(path, m)
            kind = (" [fp-only]" if m.get("corpus_kind") == "fp-only"
                    else "")
            print(f"manifest: {path} "
                  f"({len(m['expected'])} expected, "
                  f"{len(m['clean_regions'])} clean regions){kind}")
        return 0

    save_json(args.out, manifest)
    print(f"manifest: {args.out} "
          f"({len(manifest['expected'])} expected, "
          f"{len(manifest['clean_regions'])} clean regions)")
    return 0
