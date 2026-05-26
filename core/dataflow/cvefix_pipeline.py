"""Orchestrate: run CodeQL on a CVE fix pair → labeled trust-corpus entries.

Wires the shipped CodeQL runner (:mod:`core.dataflow.codeql_augmented_run`)
to the generator (:mod:`core.dataflow.cvefix_corpus_generator`). Runs the
*same* (stock) queries on the pre- and post-fix CodeQL databases — the
diff in what's flagged is what the generator labels (post-fix-still-flagged
→ FP candidate, pre-fix → TP). See ``~/design/trust-witness.md``.

This is corpus *generation*, distinct from the sound-tier *measurement*
(baseline vs custom-``.ql`` isBarrier on the same post-fix DB) which uses the
same ``analyze`` entry point with a different query + an additional pack.

The CodeQL ``runner`` is injectable (forwarded to ``analyze``), so the whole
flow is unit-testable with a stub that returns canned SARIF — no CodeQL CLI,
no database build, no dataset download.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from core.dataflow.codeql_augmented_run import DEFAULT_CODEQL_BIN, RunnerFn, analyze
from core.dataflow.cvefix_corpus_generator import generate_from_sarif, write_corpus
from core.dataflow.finding import Finding
from core.dataflow.label import GroundTruth


def generate_corpus_for_pair(
    before_db: Path,
    after_db: Path,
    queries: Sequence[str],
    *,
    cve_id: str,
    cwe: str,
    labeled_at: str,
    out_dir: Path,
    fix_touched_files: Optional[Iterable[str]] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    runner: Optional[RunnerFn] = None,
    write: bool = True,
) -> List[Tuple[Finding, GroundTruth]]:
    """Run ``queries`` on the pre- and post-fix CodeQL DBs and emit labeled
    corpus entries for one CVE.

    SARIF is written under ``out_dir/sarif/``; when ``write`` is True the
    corpus pairs are also written under ``out_dir/corpus/`` via
    :func:`write_corpus`. Returns the (Finding, GroundTruth) pairs.
    """
    sarif_dir = out_dir / "sarif"
    a_before = analyze(
        before_db, queries, sarif_dir / "before.sarif",
        codeql_bin=codeql_bin, runner=runner,
    )
    a_after = analyze(
        after_db, queries, sarif_dir / "after.sarif",
        codeql_bin=codeql_bin, runner=runner,
    )
    before_sarif = json.loads(Path(a_before.sarif_path).read_text())
    after_sarif = json.loads(Path(a_after.sarif_path).read_text())

    pairs = generate_from_sarif(
        before_sarif, after_sarif,
        cve_id=cve_id, cwe=cwe, labeled_at=labeled_at,
        fix_touched_files=fix_touched_files,
    )
    if write:
        write_corpus(pairs, out_dir / "corpus")
    return pairs


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before_db", type=Path, help="CodeQL DB of the pre-fix source")
    p.add_argument("after_db", type=Path, help="CodeQL DB of the post-fix source")
    p.add_argument("--query", action="append", dest="queries", required=True,
                   metavar="SPEC", help="CodeQL query spec (repeatable)")
    p.add_argument("--cve", required=True, help="CVE id, e.g. CVE-2021-1234")
    p.add_argument("--cwe", required=True, help="CWE id, e.g. CWE-89")
    p.add_argument("--out", type=Path, required=True, help="Output dir (sarif/ + corpus/)")
    p.add_argument("--fix-touched-file", action="append", dest="fix_touched_files",
                   metavar="PATH", help="A file the fix changed (repeatable). "
                   "Strongly recommended — localizes labels to the CVE.")
    p.add_argument("--labeled-at", default=datetime.date.today().isoformat(),
                   help="ISO date for the labels (default: today)")
    args = p.parse_args(argv)

    pairs = generate_corpus_for_pair(
        args.before_db, args.after_db, args.queries,
        cve_id=args.cve, cwe=args.cwe, labeled_at=args.labeled_at,
        out_dir=args.out, fix_touched_files=args.fix_touched_files,
    )
    fp = sum(1 for _, gt in pairs if gt.verdict == "false_positive")
    tp = len(pairs) - fp
    print(f"{args.cve}: {len(pairs)} corpus entries ({tp} TP / {fp} FP candidate) "
          f"-> {args.out / 'corpus'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
