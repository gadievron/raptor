"""Generate corpus entries from OWASP Benchmark Java + a CodeQL SARIF file.

OWASP Benchmark ships per-test-case ground truth in
``expectedresults-1.2.csv`` — every ``BenchmarkTestNNNNN`` is labelled
TP-or-FP, with FPs being the same code pattern as a TP sibling but
with a sanitizer applied. That makes it the canonical fixture set for
``missing_sanitizer_model`` measurement.

This generator:

1. Reads OWASP's expected-results CSV into a ``test_name → (cwe, is_tp)`` map.
2. Reads a SARIF file produced by running CodeQL against the benchmark.
3. Converts each dataflow ``result`` into a :class:`Finding` via the
   CodeQL adapter, attributes it to its OWASP test case, looks up the
   ground truth, and writes the matching :class:`GroundTruth`.
4. Optionally subsamples to a target count, attempting TP/FP balance.

Output: paired ``<finding_id>.json`` + ``<finding_id>.label.json``
files in the requested output directory.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from core.dataflow.adapters.codeql import from_sarif_result
from core.dataflow.finding import Finding
from core.dataflow.label import (
    FP_MISSING_SANITIZER_MODEL,
    GroundTruth,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)


_TESTNAME_RE = re.compile(r"BenchmarkTest\d{5}")


def parse_expected_results(csv_path: Path) -> Dict[str, Tuple[int, bool]]:
    """Return ``test_name -> (cwe, is_real_vulnerability)``.

    Skips ``#``-prefixed comment lines (OWASP's CSV format starts with
    one) and any row that doesn't begin with ``BenchmarkTest``.
    """
    mapping: Dict[str, Tuple[int, bool]] = {}
    with csv_path.open() as f:
        for raw_line in f:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            row = next(csv.reader([raw_line]))
            if len(row) < 4:
                continue
            test_name, _category, real, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            if not test_name.startswith("BenchmarkTest"):
                continue
            try:
                mapping[test_name] = (int(cwe), real.lower() == "true")
            except ValueError:
                continue
    return mapping


def _test_name_for_finding(finding: Finding) -> Optional[str]:
    """Locate the BenchmarkTestNNNNN this finding belongs to.

    Searches source then sink then intermediate steps for the first
    file_path matching the OWASP naming convention.
    """
    for step in (finding.source, finding.sink, *finding.intermediate_steps):
        m = _TESTNAME_RE.search(step.file_path)
        if m:
            return m.group(0)
    return None


def _rewrite_finding_paths_and_snippets(
    finding: Finding,
    repo_relative_prefix: str,
    repo_root: Path,
) -> Finding:
    """Rewrite every step's file_path to start with the given prefix
    (repo-relative path to the OWASP clone) and populate empty snippets
    from the actual source line.

    SARIF emits paths relative to the source-root passed at DB-create;
    we want them relative to the RAPTOR repo root so the corpus
    integrity test can resolve them. CodeQL's SARIF snippet field is
    optional, so we backfill from the source file when it's empty —
    otherwise the corpus loses signal and the snippet-drift test
    passes vacuously.
    """
    from dataclasses import replace

    def _fix_path(p: str) -> str:
        if p.startswith(repo_relative_prefix):
            return p
        return f"{repo_relative_prefix.rstrip('/')}/{p.lstrip('/')}"

    line_cache: Dict[Path, List[str]] = {}

    def _read_line(rel_path: str, line: int) -> Optional[str]:
        full = repo_root / rel_path
        if full not in line_cache:
            try:
                line_cache[full] = full.read_text().splitlines()
            except OSError:
                line_cache[full] = []
        lines = line_cache[full]
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return None

    def _fix_step(s: Step) -> Step:
        new_path = _fix_path(s.file_path)
        new_snippet = s.snippet
        if not new_snippet.strip():
            from_source = _read_line(new_path, s.line)
            if from_source:
                new_snippet = from_source
        return replace(s, file_path=new_path, snippet=new_snippet)

    return Finding(
        finding_id=finding.finding_id,
        producer=finding.producer,
        rule_id=finding.rule_id,
        message=finding.message,
        source=_fix_step(finding.source),
        sink=_fix_step(finding.sink),
        intermediate_steps=tuple(_fix_step(s) for s in finding.intermediate_steps),
        raw=finding.raw,
    )


def _balance_subsample(
    findings_with_labels: Sequence[Tuple[Finding, GroundTruth]],
    target: int,
    *,
    seed: int = 0,
) -> List[Tuple[Finding, GroundTruth]]:
    """Pick target entries with TP/FP balance close to 50/50."""
    tps = [(f, l) for f, l in findings_with_labels if l.verdict == VERDICT_TRUE_POSITIVE]
    fps = [(f, l) for f, l in findings_with_labels if l.verdict == VERDICT_FALSE_POSITIVE]
    n_tp = min(len(tps), target // 2)
    n_fp = min(len(fps), target - n_tp)
    n_tp = min(len(tps), target - n_fp)
    rng = random.Random(seed)
    chosen_tps = rng.sample(tps, n_tp) if n_tp <= len(tps) else tps
    chosen_fps = rng.sample(fps, n_fp) if n_fp <= len(fps) else fps
    chosen = chosen_tps + chosen_fps
    chosen.sort(key=lambda x: x[0].finding_id)
    return chosen


def generate(
    *,
    sarif_path: Path,
    expected_results_csv: Path,
    repo_relative_prefix: str,
    repo_root: Path,
    target_count: int = 30,
    cwe_filter: Optional[int] = 78,
    seed: int = 0,
    labeler: str = "owasp-benchmark-generator",
    labeled_at: str = "2026-05-10",
) -> List[Tuple[Finding, GroundTruth]]:
    expected = parse_expected_results(expected_results_csv)

    sarif = json.loads(sarif_path.read_text())
    runs = sarif.get("runs", [])
    if not runs:
        return []

    pairs: List[Tuple[Finding, GroundTruth]] = []
    seen_ids: set = set()
    for run in runs:
        for result in run.get("results", []):
            try:
                finding = from_sarif_result(result)
            except ValueError:
                continue
            if finding is None:
                continue

            test_name = _test_name_for_finding(finding)
            if test_name is None or test_name not in expected:
                continue
            cwe, is_tp = expected[test_name]
            if cwe_filter is not None and cwe != cwe_filter:
                continue

            finding = _rewrite_finding_paths_and_snippets(
                finding, repo_relative_prefix, repo_root
            )
            new_id = f"owasp_{test_name}_{finding.finding_id}"
            finding = Finding(
                finding_id=new_id,
                producer=finding.producer,
                rule_id=finding.rule_id,
                message=finding.message,
                source=finding.source,
                sink=finding.sink,
                intermediate_steps=finding.intermediate_steps,
                raw=finding.raw,
            )
            if finding.finding_id in seen_ids:
                continue
            seen_ids.add(finding.finding_id)

            if is_tp:
                label = GroundTruth(
                    finding_id=finding.finding_id,
                    verdict=VERDICT_TRUE_POSITIVE,
                    rationale=(
                        f"OWASP Benchmark {test_name} is marked as a real "
                        f"CWE-{cwe} vulnerability in expectedresults-1.2.csv. "
                        "Source flows to sink without a sanitizer."
                    ),
                    labeler=labeler,
                    labeled_at=labeled_at,
                )
            else:
                label = GroundTruth(
                    finding_id=finding.finding_id,
                    verdict=VERDICT_FALSE_POSITIVE,
                    fp_category=FP_MISSING_SANITIZER_MODEL,
                    rationale=(
                        f"OWASP Benchmark {test_name} is marked NOT a real "
                        f"CWE-{cwe} vulnerability in expectedresults-1.2.csv. "
                        "OWASP design: every FP test case is a TP sibling with "
                        "a sanitizer added. CodeQL flagging it means the "
                        "sanitizer is not modelled in the producer's catalog "
                        "(canonical missing_sanitizer_model class)."
                    ),
                    labeler=labeler,
                    labeled_at=labeled_at,
                )
            pairs.append((finding, label))

    return _balance_subsample(pairs, target_count, seed=seed)


def write_corpus(pairs: Sequence[Tuple[Finding, GroundTruth]], out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    for finding, label in pairs:
        (out_dir / f"{finding.finding_id}.json").write_text(
            finding.to_json(indent=2)
        )
        (out_dir / f"{finding.finding_id}.label.json").write_text(
            label.to_json(indent=2)
        )
    return len(pairs)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--expected-results", type=Path, required=True)
    parser.add_argument(
        "--repo-relative-prefix",
        default="out/dataflow-corpus-fixtures/owasp-benchmark-java",
        help="Repo-relative path to the OWASP clone; rewrites SARIF paths so corpus integrity test can resolve them.",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--target-count", type=int, default=30)
    parser.add_argument("--cwe", type=int, default=78, help="Filter to one CWE (default 78). Set to 0 to disable filter.")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    pairs = generate(
        sarif_path=args.sarif,
        expected_results_csv=args.expected_results,
        repo_relative_prefix=args.repo_relative_prefix,
        repo_root=Path(__file__).resolve().parents[2],
        target_count=args.target_count,
        cwe_filter=None if args.cwe == 0 else args.cwe,
        seed=args.seed,
    )
    n = write_corpus(pairs, args.out_dir)
    print(f"Wrote {n} corpus entries to {args.out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
