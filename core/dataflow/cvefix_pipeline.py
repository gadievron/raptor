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

import json
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
