"""Sound-tier barrier synthesis: LLM proposes an isBarrier, CodeQL adjudicates.

The loop (see ``~/design/trust-witness.md`` §9 — the validated mechanism):

  1. A ``proposer`` (the LLM) is handed a flagged FP + its source context and
     returns a CodeQL ``guardChecks`` predicate recognizing the project
     sanitizer.
  2. We assemble that predicate into a CWE-class taint query (reusing the stock
     source/sink + the proposed barrier).
  3. CodeQL ADJUDICATES: the query is compiled + run. A valid barrier SUPPRESSES
     the FP on the post-fix DB; the pre-fix DB still flags the real TP.

Soundness rests on the split: the LLM only PROPOSES (heuristic); CodeQL
compiles + runs the predicate (mechanical). A malformed predicate fails to
compile; an over-broad one is caught by the corpus check (it would suppress a
TP). The LLM is never on the suppress path — it can't silently create an FN.

The ``proposer`` and the CodeQL ``runner`` are both injectable, so the loop is
unit-testable with stubs (no LLM, no CodeQL).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from core.dataflow.codeql_augmented_run import DEFAULT_CODEQL_BIN, RunnerFn, analyze

# sink-class -> (customizations module, module name exposing Source/Sink/Sanitizer)
_CUSTOMIZATIONS = {
    "cmdi": ("semmle.python.security.dataflow.CommandInjectionCustomizations", "CommandInjection"),
    "sqli": ("semmle.python.security.dataflow.SqlInjectionCustomizations", "SqlInjection"),
    "pathtrav": ("semmle.python.security.dataflow.PathInjectionCustomizations", "PathInjection"),
}


@dataclass(frozen=True)
class BarrierProposal:
    """Context handed to the proposer for one flagged FP."""

    sink_class: str          # "cmdi" | "sqli" | "pathtrav"
    finding_id: str
    sink_snippet: str
    source_context: str      # the function/path source the LLM reasons over


# proposer(proposal) -> a CodeQL guardChecks predicate named ``proposedGuard``:
#   predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) { ... }
BarrierProposer = Callable[[BarrierProposal], str]


@dataclass(frozen=True)
class SynthResult:
    query_ql: str
    after_count: int     # findings on the post-fix DB with the barrier (want 0)
    before_count: int    # findings on the pre-fix DB with the barrier (want >=1)

    @property
    def suppressed_fp(self) -> bool:
        return self.after_count == 0

    @property
    def preserved_tp(self) -> bool:
        return self.before_count >= 1

    @property
    def is_sound(self) -> bool:
        """The proposed barrier suppressed the FP AND kept the TP."""
        return self.suppressed_fp and self.preserved_tp


def assemble_barrier_query(proposed_guard: str, *, sink_class: str, query_id: str) -> str:
    """Wrap a proposed ``proposedGuard`` predicate into a runnable CWE-class
    taint query (the validated §9 template)."""
    if sink_class not in _CUSTOMIZATIONS:
        raise ValueError(f"unknown sink_class {sink_class!r}; "
                         f"known: {sorted(_CUSTOMIZATIONS)}")
    if "proposedGuard" not in proposed_guard:
        raise ValueError("proposer must define a `proposedGuard` predicate")
    module_import, module_name = _CUSTOMIZATIONS[sink_class]
    return f"""/**
 * @name Synthesized barrier ({sink_class})
 * @kind problem
 * @problem.severity error
 * @id {query_id}
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import {module_import}

{proposed_guard.strip()}

module Cfg implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{ n instanceof {module_name}::Source }}
  predicate isSink(DataFlow::Node n) {{ n instanceof {module_name}::Sink }}
  predicate isBarrier(DataFlow::Node n) {{
    n instanceof {module_name}::Sanitizer or
    n = DataFlow::BarrierGuard<proposedGuard/3>::getABarrierNode()
  }}
}}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "synthesized-barrier {sink_class}"
"""


def _count_sarif_results(sarif_path: Path) -> int:
    data = json.loads(Path(sarif_path).read_text())
    return sum(len(r.get("results", [])) for r in data.get("runs", []))


def adjudicate(
    query_ql: str,
    db_path: Path,
    *,
    work_dir: Path,
    search_path: Optional[str] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    runner: Optional[RunnerFn] = None,
) -> int:
    """Compile + run ``query_ql`` against ``db_path`` via CodeQL; return the
    finding count. Writes the query + a minimal qlpack into ``work_dir``."""
    pack = work_dir
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "qlpack.yml").write_text(
        'name: raptor/barrier-synth\nversion: 0.0.1\n'
        'dependencies:\n  codeql/python-all: "*"\n'
    )
    ql = pack / "SynthBarrier.ql"
    ql.write_text(query_ql)
    extra = ["--additional-packs", search_path] if search_path else []
    result = analyze(
        db_path, [str(ql)], pack / "out.sarif",
        codeql_bin=codeql_bin, runner=runner, extra_args=extra,
    )
    return _count_sarif_results(Path(result.sarif_path))


def run_synthesis_loop(
    proposal: BarrierProposal,
    after_db: Path,
    before_db: Path,
    *,
    proposer: BarrierProposer,
    work_dir: Path,
    search_path: Optional[str] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    runner: Optional[RunnerFn] = None,
) -> SynthResult:
    """Propose a barrier, assemble it, and let CodeQL adjudicate on both DBs."""
    proposed = proposer(proposal)
    query_ql = assemble_barrier_query(
        proposed, sink_class=proposal.sink_class,
        query_id=f"raptor/synth/{proposal.finding_id}",
    )
    after_count = adjudicate(query_ql, after_db, work_dir=work_dir / "after",
                             search_path=search_path, codeql_bin=codeql_bin, runner=runner)
    before_count = adjudicate(query_ql, before_db, work_dir=work_dir / "before",
                              search_path=search_path, codeql_bin=codeql_bin, runner=runner)
    return SynthResult(query_ql=query_ql, after_count=after_count, before_count=before_count)
