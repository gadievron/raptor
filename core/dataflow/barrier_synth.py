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

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from core.dataflow.codeql_augmented_run import (
    DEFAULT_CODEQL_BIN,
    CodeQLRunError,
    RunnerFn,
    analyze,
)

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


# proposer(proposal, prior_error) -> a CodeQL guardChecks predicate named
# ``proposedGuard``: predicate proposedGuard(DataFlow::GuardNode g,
# ControlFlowNode node, boolean branch) { ... }
# ``prior_error`` is None on the first attempt; on a retry it carries the
# compile/validation error from the previous attempt so the proposer (LLM)
# can correct it.
BarrierProposer = Callable[[BarrierProposal, Optional[str]], str]


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
    max_attempts: int = 1,
) -> Optional[SynthResult]:
    """Propose a barrier, assemble it, and let CodeQL adjudicate on both DBs.

    Retries up to ``max_attempts``: if assembly rejects the proposal or CodeQL
    fails to compile/run the query, the error is fed back to the proposer for a
    corrected attempt. Returns ``None`` if no attempt produced a runnable query
    (the proposer never emitted compilable QL) — the LLM still can't suppress
    anything it can't get past the compiler.
    """
    prior_error: Optional[str] = None
    for attempt in range(1, max_attempts + 1):
        try:
            proposed = proposer(proposal, prior_error)
            query_ql = assemble_barrier_query(
                proposed, sink_class=proposal.sink_class,
                query_id=f"raptor/synth/{proposal.finding_id}/{attempt}",
            )
            after_count = adjudicate(
                query_ql, after_db, work_dir=work_dir / f"after-{attempt}",
                search_path=search_path, codeql_bin=codeql_bin, runner=runner)
            before_count = adjudicate(
                query_ql, before_db, work_dir=work_dir / f"before-{attempt}",
                search_path=search_path, codeql_bin=codeql_bin, runner=runner)
        except (ValueError, CodeQLRunError) as exc:
            prior_error = f"{type(exc).__name__}: {exc}"
            continue
        return SynthResult(query_ql=query_ql, after_count=after_count, before_count=before_count)
    return None


# ---------------------------------------------------------------------------
# LLM proposer — the production "propose" step
# ---------------------------------------------------------------------------

# complete(system_prompt, user_prompt) -> model reply text. Injectable so the
# proposer is testable with a stub and the real LLM is wired lazily.
Completer = Callable[[str, str], str]

_SYSTEM_PROMPT = (
    "You are a CodeQL expert. A taint-analysis finding has been flagged as a "
    "false positive because a PROJECT-SPECIFIC validator/sanitizer on the path "
    "neutralizes the attacker input — but the analyzer doesn't model it. Your "
    "job: emit a CodeQL guard predicate that recognizes that validator so the "
    "false positive is suppressed.\n\n"
    "Output ONLY a CodeQL predicate, exactly this signature and name:\n"
    "  predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch)\n"
    "Semantics: `g` is the guard (the validator call/comparison); `node` is the "
    "cfg node of the value it checks; `branch` is the boolean value of `g` on "
    "which `node` is safe. `python`, `DataFlow`, and the relevant security "
    "customizations module are already imported. No prose, no markdown fences."
)


def _build_prompt(proposal: BarrierProposal, prior_error: Optional[str]) -> str:
    parts = [
        f"sink class: {proposal.sink_class}",
        f"flagged sink: {proposal.sink_snippet}",
        "source (the function/path the finding flows through):",
        proposal.source_context,
        "",
        "Emit the `proposedGuard` predicate recognizing the validator on this path.",
    ]
    if prior_error:
        parts += [
            "",
            "Your PREVIOUS attempt failed — fix it. Error:",
            prior_error,
        ]
    return "\n".join(parts)


def _extract_ql(reply: str) -> str:
    """Pull the QL predicate out of a model reply, tolerating markdown fences."""
    text = (reply or "").strip()
    if "```" in text:
        # take the first fenced block's body
        block = text.split("```", 2)[1]
        if "\n" in block:  # drop an optional language tag on the fence line
            block = block.split("\n", 1)[1]
        text = block.strip()
    return text


def make_llm_proposer(complete: Completer) -> BarrierProposer:
    """Build a proposer backed by an LLM ``complete`` callable."""
    def propose(proposal: BarrierProposal, prior_error: Optional[str]) -> str:
        return _extract_ql(complete(_SYSTEM_PROMPT, _build_prompt(proposal, prior_error)))
    return propose


def default_completer() -> Completer:
    """Wire a Completer onto the real LLM client (imported lazily so tests and
    the harness don't need the client unless a live run is requested)."""
    from core.llm.client import LLMClient

    client = LLMClient()

    def _complete(system_prompt: str, user_prompt: str) -> str:
        resp = client.generate(user_prompt, system_prompt=system_prompt)
        text = getattr(resp, "content", None)
        return text if text is not None else str(resp)

    return _complete


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before_db", type=Path, help="CodeQL DB of the pre-fix (vulnerable) source")
    p.add_argument("after_db", type=Path, help="CodeQL DB of the post-fix (sanitized) source")
    p.add_argument("--sink-class", required=True, choices=sorted(_CUSTOMIZATIONS))
    p.add_argument("--finding-id", required=True)
    p.add_argument("--sink", required=True, help="flagged sink snippet/description")
    p.add_argument("--source-file", type=Path, required=True,
                   help="source the LLM reasons over (the function/path)")
    p.add_argument("--search-path", help="codeql query-pack search path (--additional-packs)")
    p.add_argument("--max-attempts", type=int, default=3)
    p.add_argument("--work-dir", type=Path, default=Path("/tmp/trust-synth-work"))
    args = p.parse_args(argv)

    proposal = BarrierProposal(
        sink_class=args.sink_class, finding_id=args.finding_id,
        sink_snippet=args.sink, source_context=args.source_file.read_text(encoding="utf-8"),
    )
    res = run_synthesis_loop(
        proposal, args.after_db, args.before_db,
        proposer=make_llm_proposer(default_completer()),
        work_dir=args.work_dir, search_path=args.search_path,
        max_attempts=args.max_attempts,
    )
    if res is None:
        print(f"{args.finding_id}: no compilable barrier after {args.max_attempts} attempts",
              file=sys.stderr)
        return 1
    print(f"{args.finding_id}: sound={res.is_sound} "
          f"(after={res.after_count}, before={res.before_count})", file=sys.stderr)
    print(res.query_ql)
    return 0 if res.is_sound else 2


if __name__ == "__main__":
    sys.exit(main())
