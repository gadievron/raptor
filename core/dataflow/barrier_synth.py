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

# sink-class -> (customizations module, module name exposing Source/Sink/Sanitizer).
# Python: each module imports Concepts/RemoteFlowSources/BarrierGuards and
# defines its concrete Source/Sink subclasses in-file, so importing the
# customizations module alone registers sources + sinks for the taint flow.
_CUSTOMIZATIONS = {
    "cmdi": ("semmle.python.security.dataflow.CommandInjectionCustomizations", "CommandInjection"),
    "sqli": ("semmle.python.security.dataflow.SqlInjectionCustomizations", "SqlInjection"),
    "pathtrav": ("semmle.python.security.dataflow.PathInjectionCustomizations", "PathInjection"),
    "xss": ("semmle.python.security.dataflow.ReflectedXSSCustomizations", "ReflectedXss"),
    # Added 2026-05-31 for the CWE-94/918 walk: matches cvefix_bridge._CWE_SINK.
    "codeinjection": ("semmle.python.security.dataflow.CodeInjectionCustomizations", "CodeInjection"),
    "ssrf": ("semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations", "ServerSideRequestForgery"),
}

# JavaScript/TypeScript equivalents. JS uses the legacy TaintTracking::Configuration
# class API (the new ConfigSig/BarrierGuard the Python dialect uses is unused in the
# JS libs), so barriers go through `isSanitizerGuard` + a SanitizerGuardNode subclass
# rather than a flat `proposedGuard/3` predicate — a different proposer contract.
_JS_CUSTOMIZATIONS = {
    "cmdi": ("semmle.javascript.security.dataflow.CommandInjectionCustomizations", "CommandInjection"),
    "sqli": ("semmle.javascript.security.dataflow.SqlInjectionCustomizations", "SqlInjection"),
    "pathtrav": ("semmle.javascript.security.dataflow.TaintedPathCustomizations", "TaintedPath"),
    "xss": ("semmle.javascript.security.dataflow.ReflectedXssCustomizations", "ReflectedXss"),
    # SSRF: JS pack names the module ``RequestForgery`` (no "ServerSide" prefix),
    # unlike Python/Ruby; module file follows the same convention.
    "codeinjection": ("semmle.javascript.security.dataflow.CodeInjectionCustomizations", "CodeInjection"),
    "ssrf": ("semmle.javascript.security.dataflow.RequestForgeryCustomizations", "RequestForgery"),
}

# Ruby. Like Python it uses the new ConfigSig/BarrierGuard API (the legacy
# Configuration class is deprecated), so the Ruby dialect mirrors the Python
# template — but with Ruby imports and a Ruby guard signature
# (proposedGuard(CfgNodes::AstCfgNode g, CfgNode node, boolean branch)). Source/
# Sink/Sanitizer are pulled in unqualified via `import <file>::<module>`.
_RB_CUSTOMIZATIONS = {
    "cmdi": ("codeql.ruby.security.CommandInjectionCustomizations", "CommandInjection"),
    "sqli": ("codeql.ruby.security.SqlInjectionCustomizations", "SqlInjection"),
    "pathtrav": ("codeql.ruby.security.PathInjectionCustomizations", "PathInjection"),
    "xss": ("codeql.ruby.security.XSS", "ReflectedXss"),
    "codeinjection": ("codeql.ruby.security.CodeInjectionCustomizations", "CodeInjection"),
    "ssrf": ("codeql.ruby.security.ServerSideRequestForgeryCustomizations", "ServerSideRequestForgery"),
}

# Java. New ConfigSig/BarrierGuard API like Python/Ruby, guard sig uses a
# boolean branch (proposedGuard(Guard g, Expr e, boolean branch)) — so the
# dialect is Python-shaped with Java imports. Unlike the others Java has no
# uniform <X>::Source/Sink module: the source is always RemoteFlowSource and the
# sink is a per-CWE class/predicate. Map: sink_class -> (sink import, isSink body).
_JAVA_SINKS = {
    "sqli": ("semmle.code.java.security.QueryInjection", "n instanceof QueryInjectionSink"),
    "cmdi": ("semmle.code.java.security.CommandLineQuery", "n instanceof CommandInjectionSink"),
    "xss": ("semmle.code.java.security.XSS", "n instanceof XssSink"),
    "pathtrav": ("semmle.code.java.dataflow.ExternalFlow", 'sinkNode(n, "path-injection")'),
    # SSRF: Java's RequestForgery.qll exposes an abstract ``RequestForgerySink``
    # class with concrete URL-sink subclasses; instanceof matches all of them.
    # codeinjection deliberately omitted: Java's pack has no generic
    # CodeInjectionSink — only framework-specific queries (SpEL/MVEL/Groovy/
    # JEXL/Template), matching cvefix_walk's Java CWE-94 omission.
    "ssrf": ("semmle.code.java.security.RequestForgery", "n instanceof RequestForgerySink"),
}

# Go. Uses the new ConfigSig/BarrierGuard API like Python/Ruby (with the
# legacy TaintTracking::Configuration also available but deprecated).
# Guard sig is ``(DataFlow::Node g, Expr e, boolean branch)`` — Expr (not
# ControlFlowNode like Python) for the value-being-checked, mirroring Java.
# codeinjection deliberately omitted: Go's pack has no CodeInjection.ql or
# CodeInjectionCustomizations.qll — matches cvefix_walk's Go CWE-94 omission.
_GO_CUSTOMIZATIONS = {
    "cmdi": ("semmle.go.security.CommandInjectionCustomizations", "CommandInjection"),
    "sqli": ("semmle.go.security.SqlInjectionCustomizations", "SqlInjection"),
    "pathtrav": ("semmle.go.security.TaintedPathCustomizations", "TaintedPath"),
    "xss": ("semmle.go.security.ReflectedXssCustomizations", "ReflectedXss"),
    "ssrf": ("semmle.go.security.RequestForgeryCustomizations", "RequestForgery"),
}

# language -> the CodeQL standard-library pack the assembled query depends on.
_LANG_PACK = {
    "python": "codeql/python-all",
    "javascript": "codeql/javascript-all",
    "ruby": "codeql/ruby-all",
    "java": "codeql/java-all",
    "go": "codeql/go-all",
}


@dataclass(frozen=True)
class BarrierProposal:
    """Context handed to the proposer for one flagged FP."""

    sink_class: str          # "cmdi" | "sqli" | "pathtrav" | "xss" | "codeinjection" | "ssrf"
    finding_id: str
    sink_snippet: str
    source_context: str      # the function/path source the LLM reasons over
    language: str = "python"  # "python" | "javascript" (selects the QL dialect)


# proposer(proposal, prior_error) -> a CodeQL guardChecks predicate named
# ``proposedGuard``: predicate proposedGuard(DataFlow::GuardNode g,
# ControlFlowNode node, boolean branch) { ... }
# ``prior_error`` is None on the first attempt; on a retry it carries the
# compile/validation error from the previous attempt so the proposer (LLM)
# can correct it.
# `BarrierProposer` is called as ``proposer(proposal, prior_error)`` in the
# baseline path (compile-retry only) and ``proposer(proposal, prior_error,
# refine_context=RefineContext(...))`` in the soundness-refine path. The
# Callable[..., str] alias is intentionally wide: 2-arg lambdas in tests
# still match when refinement is off (the loop only passes the kwarg when
# refine budget > 0). Refinement-aware proposers should accept the kwarg
# (and may inspect it to nudge the prompt with the prior verdict).
BarrierProposer = Callable[..., str]


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

    @property
    def failure_mode(self) -> str:
        """One-word classification of WHY a non-sound result failed, for
        feeding back into the proposer on refinement.

        ``suppress_fp_failed`` — guard wasn't restrictive enough (post-fix
            DB still flags the value).
        ``preserve_tp_failed`` — guard was too restrictive (pre-fix DB no
            longer flags the real vuln).
        ``both`` — guard moved nothing in either direction.
        ``ok`` — for completeness; never used for refinement.
        """
        if self.is_sound:
            return "ok"
        if not self.suppressed_fp and not self.preserved_tp:
            return "both"
        if not self.suppressed_fp:
            return "suppress_fp_failed"
        return "preserve_tp_failed"


@dataclass(frozen=True)
class RefineContext:
    """Adjudication-failure context fed back to the proposer for refinement.

    Built by :func:`run_synthesis_loop` when a successfully-compiled barrier
    runs against both DBs but fails the soundness check. The proposer sees
    this on the next attempt and can adjust its guard — same proposal,
    same source context, but with the prior attempt's verdict in hand.

    ``surviving_finding_summary`` (added for the counterexample-driven
    refinement work) carries a short, LLM-legible description of the
    SPECIFIC tainted flow the prior guard failed to gate — file:line of
    the surviving sink, the codeFlow path summary, and the source/sink
    expressions.  Optional because the helper falls back gracefully when
    the SARIF doesn't carry usable detail (older codeql versions, etc.).

    The :attr:`refine_attempt` counter is 1-indexed (first refinement is
    attempt 1) so the prompt can address the attempt count naturally
    ("On your previous (1st) refinement attempt, ...").
    """
    prior_query_ql: str
    after_count: int
    before_count: int
    failure_mode: str
    refine_attempt: int
    surviving_finding_summary: str = ""


def assemble_barrier_query(
    proposed_guard: str, *, sink_class: str, query_id: str, language: str = "python",
) -> str:
    """Wrap a proposed barrier into a runnable CWE-class taint query.

    ``language`` selects the QL dialect: ``python`` uses the new
    ``ConfigSig``/``BarrierGuard<proposedGuard/3>`` API (§9 template); ``javascript``
    uses the legacy ``TaintTracking::Configuration`` + a ``ProposedGuard``
    SanitizerGuardNode subclass (the only API the JS libs expose)."""
    if language == "python":
        return _assemble_python(proposed_guard, sink_class, query_id)
    if language == "javascript":
        return _assemble_javascript(proposed_guard, sink_class, query_id)
    if language == "ruby":
        return _assemble_ruby(proposed_guard, sink_class, query_id)
    if language == "java":
        return _assemble_java(proposed_guard, sink_class, query_id)
    if language == "go":
        return _assemble_go(proposed_guard, sink_class, query_id)
    raise ValueError(
        f"unknown language {language!r}; known: {sorted(_LANG_PACK)}")


def _assemble_python(proposed_guard: str, sink_class: str, query_id: str) -> str:
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


def _assemble_javascript(proposed_guard: str, sink_class: str, query_id: str) -> str:
    if sink_class not in _JS_CUSTOMIZATIONS:
        raise ValueError(f"unknown sink_class {sink_class!r}; "
                         f"known: {sorted(_JS_CUSTOMIZATIONS)}")
    if "ProposedGuard" not in proposed_guard:
        raise ValueError(
            "proposer must define a `ProposedGuard` SanitizerGuardNode subclass")
    module_import, module_name = _JS_CUSTOMIZATIONS[sink_class]
    return f"""/**
 * @name Synthesized barrier ({sink_class}) [js]
 * @kind problem
 * @problem.severity error
 * @id {query_id}
 */
import javascript
import {module_import}::{module_name}

{proposed_guard.strip()}

class SynthConfig extends TaintTracking::Configuration {{
  SynthConfig() {{ this = "raptor-synth-{sink_class}" }}
  override predicate isSource(DataFlow::Node n) {{ n instanceof Source }}
  override predicate isSink(DataFlow::Node n) {{ n instanceof Sink }}
  override predicate isSanitizer(DataFlow::Node n) {{
    super.isSanitizer(n) or n instanceof Sanitizer
  }}
  override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode g) {{
    g instanceof ProposedGuard
  }}
}}

from SynthConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "synthesized-barrier {sink_class} [js]"
"""


def _assemble_ruby(proposed_guard: str, sink_class: str, query_id: str) -> str:
    if sink_class not in _RB_CUSTOMIZATIONS:
        raise ValueError(f"unknown sink_class {sink_class!r}; "
                         f"known: {sorted(_RB_CUSTOMIZATIONS)}")
    if "proposedGuard" not in proposed_guard:
        raise ValueError("proposer must define a `proposedGuard` predicate")
    module_import, module_name = _RB_CUSTOMIZATIONS[sink_class]
    return f"""/**
 * @name Synthesized barrier ({sink_class}) [rb]
 * @kind problem
 * @problem.severity error
 * @id {query_id}
 */
import codeql.ruby.AST
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.CFG
import {module_import}::{module_name}

{proposed_guard.strip()}

module Cfg implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{ n instanceof Source }}
  predicate isSink(DataFlow::Node n) {{ n instanceof Sink }}
  predicate isBarrier(DataFlow::Node n) {{
    n instanceof Sanitizer or
    n = DataFlow::BarrierGuard<proposedGuard/3>::getABarrierNode()
  }}
}}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "synthesized-barrier {sink_class} [rb]"
"""


def _assemble_java(proposed_guard: str, sink_class: str, query_id: str) -> str:
    if sink_class not in _JAVA_SINKS:
        raise ValueError(f"unknown sink_class {sink_class!r}; "
                         f"known: {sorted(_JAVA_SINKS)}")
    if "proposedGuard" not in proposed_guard:
        raise ValueError("proposer must define a `proposedGuard` predicate")
    sink_import, sink_expr = _JAVA_SINKS[sink_class]
    return f"""/**
 * @name Synthesized barrier ({sink_class}) [java]
 * @kind problem
 * @problem.severity error
 * @id {query_id}
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.controlflow.Guards
import {sink_import}

{proposed_guard.strip()}

module Cfg implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{ n instanceof RemoteFlowSource }}
  predicate isSink(DataFlow::Node n) {{ {sink_expr} }}
  predicate isBarrier(DataFlow::Node n) {{
    n = DataFlow::BarrierGuard<proposedGuard/3>::getABarrierNode()
  }}
}}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "synthesized-barrier {sink_class} [java]"
"""


def _assemble_go(proposed_guard: str, sink_class: str, query_id: str) -> str:
    """Go QL template.  Uses the new ``ConfigSig`` / ``BarrierGuard`` API
    (the legacy ``TaintTracking::Configuration`` still works but is
    deprecated).  Guard signature is ``(DataFlow::Node g, Expr e,
    boolean branch)`` — ``Expr`` for the value-being-checked (mirrors
    Java), distinct from Python's ``ControlFlowNode``.

    The per-sink-class import + module name come from
    :data:`_GO_CUSTOMIZATIONS`.  Each module exposes the standard
    ``Source`` / ``Sink`` / ``Sanitizer`` shape so the ConfigSig
    predicates are identical across sink classes."""
    if sink_class not in _GO_CUSTOMIZATIONS:
        raise ValueError(f"unknown sink_class {sink_class!r}; "
                         f"known: {sorted(_GO_CUSTOMIZATIONS)}")
    if "proposedGuard" not in proposed_guard:
        raise ValueError("proposer must define a `proposedGuard` predicate")
    module_import, module_name = _GO_CUSTOMIZATIONS[sink_class]
    return f"""/**
 * @name Synthesized barrier ({sink_class}) [go]
 * @kind problem
 * @problem.severity error
 * @id {query_id}
 */
import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking
import {module_import}::{module_name}

{proposed_guard.strip()}

module Cfg implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{ n instanceof Source }}
  predicate isSink(DataFlow::Node n) {{ n instanceof Sink }}
  predicate isBarrier(DataFlow::Node n) {{
    n instanceof Sanitizer or
    n = DataFlow::BarrierGuard<proposedGuard/3>::getABarrierNode()
  }}
}}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "synthesized-barrier {sink_class} [go]"
"""


def _count_sarif_results(sarif_path: Path, target_uri: Optional[str] = None,
                         target_line: Optional[int] = None) -> int:
    """Count SARIF results. With ``target_uri`` (+ optional ``target_line``),
    count only findings at that file (and line) — so the suppress check can be
    scoped to the SPECIFIC flagged finding rather than all findings in the file
    (a file with N unrelated findings shouldn't make a correct single-flow
    barrier look unsound). The preserve check stays file-scoped (the pre-fix vuln
    sits at a different line after the patch's line shifts)."""
    data = json.loads(Path(sarif_path).read_text())
    if target_uri is None:
        return sum(len(r.get("results", [])) for r in data.get("runs", []))
    n = 0
    for run in data.get("runs", []):
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                if phys.get("artifactLocation", {}).get("uri") != target_uri:
                    continue
                if target_line is not None and phys.get("region", {}).get("startLine") != target_line:
                    continue
                n += 1
                break  # count each result at most once
    return n


def _summarise_surviving_finding(
    sarif_path: Path, target_uri: Optional[str] = None,
    target_line: Optional[int] = None,
) -> str:
    """One-line summary of a SARIF result that survived the proposed
    barrier, formatted for the LLM refinement prompt.

    Picks the first result matching ``target_uri`` (+ optional
    ``target_line``) — same scoping logic as :func:`_count_sarif_results`
    so the summary describes the SPECIFIC finding the synth was scoped
    to.  Returns ``""`` on missing file, parse error, no matching result,
    or empty codeFlows.  Conservative by design — a noisy summary
    would mislead the proposer; an empty one falls back to the existing
    generic nudge.

    Shape:
      ``"surviving flow: <source-file>:<line> <msg> -> ... -> <sink-file>:<line> <sink-snippet>"``
    """
    try:
        data = json.loads(Path(sarif_path).read_text())
    except (OSError, ValueError):
        return ""

    def _result_uri(res):
        for loc in res.get("locations", []):
            phys = loc.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri")
            line = phys.get("region", {}).get("startLine")
            if uri:
                return uri, line
        return None, None

    for run in data.get("runs", []):
        for res in run.get("results", []):
            uri, line = _result_uri(res)
            if target_uri is not None and uri != target_uri:
                continue
            if target_line is not None and line != target_line:
                continue
            # We have the surviving result — describe it.
            cfs = res.get("codeFlows", [])
            steps = (cfs[0].get("threadFlows", [{}])[0].get("locations", [])
                     if cfs else [])
            chain = []
            for step in steps:
                node = step.get("location", {})
                phys = node.get("physicalLocation", {})
                s_uri = phys.get("artifactLocation", {}).get("uri", "?")
                s_line = phys.get("region", {}).get("startLine", "?")
                s_msg = node.get("message", {}).get("text", "").strip()
                chain.append(f"{Path(s_uri).name}:{s_line}"
                             + (f" {s_msg}" if s_msg else ""))
            sink_msg = res.get("message", {}).get("text", "").strip()
            sink_part = f"{Path(uri).name}:{line}" if uri else "?"
            if sink_msg:
                sink_part += f" — {sink_msg}"
            if chain:
                return ("surviving flow: " + " -> ".join(chain)
                        + (f"\n  (sink scope: {sink_part})" if not chain[-1].startswith(sink_part) else ""))
            return f"surviving finding at {sink_part}"
    return ""


def adjudicate(
    query_ql: str,
    db_path: Path,
    *,
    work_dir: Path,
    language: str = "python",
    search_path: Optional[str] = None,
    target_uri: Optional[str] = None,
    target_line: Optional[int] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    runner: Optional[RunnerFn] = None,
) -> int:
    """Compile + run ``query_ql`` against ``db_path`` via CodeQL; return the
    finding count. Writes the query + a minimal qlpack into ``work_dir``."""
    pack = work_dir
    pack.mkdir(parents=True, exist_ok=True)
    dep = _LANG_PACK.get(language)
    if dep is None:
        raise ValueError(f"unknown language {language!r}; known: {sorted(_LANG_PACK)}")
    (pack / "qlpack.yml").write_text(
        'name: raptor/barrier-synth\nversion: 0.0.1\n'
        f'dependencies:\n  {dep}: "*"\n'
    )
    ql = pack / "SynthBarrier.ql"
    ql.write_text(query_ql)
    extra = ["--additional-packs", search_path] if search_path else []
    result = analyze(
        db_path, [str(ql)], pack / "out.sarif",
        codeql_bin=codeql_bin, runner=runner, extra_args=extra,
    )
    return _count_sarif_results(Path(result.sarif_path), target_uri, target_line)


def run_synthesis_loop(
    proposal: BarrierProposal,
    after_db: Path,
    before_db: Path,
    *,
    proposer: BarrierProposer,
    work_dir: Path,
    search_path: Optional[str] = None,
    target_uri: Optional[str] = None,
    target_line: Optional[int] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    runner: Optional[RunnerFn] = None,
    max_attempts: int = 1,
    max_refine_attempts: int = 0,
    diag: Optional[dict] = None,
) -> Optional[SynthResult]:
    """Propose a barrier, assemble it, and let CodeQL adjudicate on both DBs.

    Two retry axes:

      * **Compile retries (``max_attempts``)** — if assembly rejects the
        proposal or CodeQL fails to compile/run the query, the error is
        fed back to the proposer for a corrected attempt. Returns
        ``None`` if no compile attempt produced a runnable query.

      * **Soundness refinement (``max_refine_attempts``, default 0)** —
        when a barrier compiles and runs but isn't sound, the adjudication
        verdict (after/before counts + failure mode) is wrapped in a
        :class:`RefineContext` and fed back to the proposer for another
        full compile-and-adjudicate cycle.  Each refinement cycle has
        its own compile-retry budget (``max_attempts``).  Default ``0``
        preserves the pre-existing behaviour (return the first
        compilable result, sound or not).

    When ``diag`` is supplied, it records ``last_error`` (assembly /
    compile), ``attempts`` (compile budget used in the last cycle),
    and ``refine_attempts`` (soundness refinements used).
    """
    refine_ctx: Optional[RefineContext] = None
    refine_attempts_used = 0
    last_compile_error: Optional[str] = None
    last_compile_attempts = 0

    while True:
        prior_error: Optional[str] = None
        cycle_result: Optional[SynthResult] = None
        for attempt in range(1, max_attempts + 1):
            last_compile_attempts = attempt
            try:
                # Only thread refine_context when we have one — keeps 2-arg
                # proposers (no refinement awareness) usable at default
                # max_refine_attempts=0.
                if refine_ctx is not None:
                    proposed = proposer(proposal, prior_error, refine_context=refine_ctx)
                else:
                    proposed = proposer(proposal, prior_error)
                query_ql = assemble_barrier_query(
                    proposed, sink_class=proposal.sink_class,
                    query_id=(
                        f"raptor/synth/{proposal.finding_id}/"
                        f"r{refine_attempts_used}-{attempt}"
                    ),
                    language=proposal.language,
                )
                # Suppress check (after): scope to the SPECIFIC flagged
                # finding (uri+line). Preserve check (before): file-scoped
                # only — the pre-fix vuln is at a different line after the
                # patch's line shifts.
                after_count = adjudicate(
                    query_ql, after_db,
                    work_dir=work_dir / f"after-r{refine_attempts_used}-{attempt}",
                    language=proposal.language, target_uri=target_uri,
                    target_line=target_line,
                    search_path=search_path, codeql_bin=codeql_bin, runner=runner)
                before_count = adjudicate(
                    query_ql, before_db,
                    work_dir=work_dir / f"before-r{refine_attempts_used}-{attempt}",
                    language=proposal.language, target_uri=target_uri,
                    search_path=search_path, codeql_bin=codeql_bin, runner=runner)
            except (ValueError, CodeQLRunError) as exc:
                prior_error = f"{type(exc).__name__}: {exc}"
                last_compile_error = prior_error
                continue
            cycle_result = SynthResult(
                query_ql=query_ql, after_count=after_count, before_count=before_count,
            )
            break

        if cycle_result is None:
            # All compile attempts in this cycle failed — no_barrier.
            if diag is not None:
                diag["last_error"] = last_compile_error
                diag["attempts"] = last_compile_attempts
                diag["refine_attempts"] = refine_attempts_used
            return None

        if cycle_result.is_sound:
            if diag is not None:
                diag["refine_attempts"] = refine_attempts_used
            return cycle_result

        if refine_attempts_used >= max_refine_attempts:
            # Exhausted refinement budget — surface the not_sound result so
            # the caller can record it as diagnostic material.
            if diag is not None:
                diag["refine_attempts"] = refine_attempts_used
            return cycle_result

        # Refine: feed the verdict back to the proposer for another cycle.
        refine_attempts_used += 1
        # Counterexample-driven refinement: extract the SPECIFIC surviving
        # finding from the after-DB's SARIF so the proposer sees the
        # concrete flow that wasn't gated.  Only meaningful for
        # ``suppress_fp_failed`` (the after-DB still has the FP); the
        # ``preserve_tp_failed`` case has the after-DB clean and the
        # before-DB SARIF is what's relevant, but the existing
        # before-DB SARIF lives at ``before-r*`` per iteration so the
        # same pattern would apply.  Keep scoped to the after path for
        # now — it's the dominant failure mode.
        surviving_summary = ""
        if cycle_result.failure_mode == "suppress_fp_failed":
            surviving_sarif = (
                work_dir / f"after-r{refine_attempts_used - 1}-"
                f"{last_compile_attempts}" / "out.sarif"
            )
            surviving_summary = _summarise_surviving_finding(
                surviving_sarif, target_uri=target_uri, target_line=target_line,
            )
        refine_ctx = RefineContext(
            prior_query_ql=cycle_result.query_ql,
            after_count=cycle_result.after_count,
            before_count=cycle_result.before_count,
            failure_mode=cycle_result.failure_mode,
            refine_attempt=refine_attempts_used,
            surviving_finding_summary=surviving_summary,
        )


# ---------------------------------------------------------------------------
# Corpus-level aggregate — run synthesis over many FPs, report suppression rate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusSynthItem:
    """One flagged FP to synthesize a barrier for, with its before/after DBs."""

    proposal: BarrierProposal
    after_db: Path
    before_db: Path


@dataclass(frozen=True)
class CorpusSynthReport:
    total: int
    sound: int          # sound barrier synthesized (FP suppressed, TP preserved)
    not_sound: int      # compiled but failed the soundness check (no suppress / killed TP)
    no_barrier: int     # no compilable barrier after retries
    per_finding: tuple  # ((finding_id, status), ...); status in sound/not_sound/no_barrier

    @property
    def suppression_rate(self) -> Optional[float]:
        """Fraction of FPs for which a sound barrier was synthesized — the
        headline scale metric ("how much addressable FP can we suppress")."""
        return None if self.total == 0 else self.sound / self.total


def synthesize_over_corpus(
    items,
    *,
    proposer: BarrierProposer,
    work_dir: Path,
    search_path: Optional[str] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    runner: Optional[RunnerFn] = None,
    max_attempts: int = 1,
) -> CorpusSynthReport:
    """Run the synthesis loop over a corpus of flagged FPs and aggregate."""
    sound = not_sound = no_barrier = 0
    per: list = []
    for item in items:
        res = run_synthesis_loop(
            item.proposal, item.after_db, item.before_db,
            proposer=proposer, work_dir=work_dir / item.proposal.finding_id,
            search_path=search_path, codeql_bin=codeql_bin, runner=runner,
            max_attempts=max_attempts,
        )
        if res is None:
            status, no_barrier = "no_barrier", no_barrier + 1
        elif res.is_sound:
            status, sound = "sound", sound + 1
        else:
            status, not_sound = "not_sound", not_sound + 1
        per.append((item.proposal.finding_id, status))
    return CorpusSynthReport(
        total=len(per), sound=sound, not_sound=not_sound,
        no_barrier=no_barrier, per_finding=tuple(per),
    )


def render_corpus_report(r: CorpusSynthReport) -> str:
    rate = "n/a" if r.suppression_rate is None else f"{r.suppression_rate * 100:.0f}%"
    return (
        f"Trust barrier synthesis over {r.total} FP(s)\n"
        f"  sound barrier:   {r.sound}  ({rate} of FPs suppressed, zero TP loss)\n"
        f"  not sound:       {r.not_sound}  (compiled but failed the soundness check)\n"
        f"  no barrier:      {r.no_barrier}  (no compilable barrier after retries)"
    )


# ---------------------------------------------------------------------------
# LLM proposer — the production "propose" step
# ---------------------------------------------------------------------------

# complete(system_prompt, user_prompt) -> model reply text. Injectable so the
# proposer is testable with a stub and the real LLM is wired lazily.
Completer = Callable[[str, str], str]

_PY_SYSTEM_PROMPT = (
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
    "customizations module are already imported. No prose, no markdown fences.\n\n"
    "CRITICAL RULES:\n"
    "1. `node` must be the VALUE BEING VALIDATED, NOT the guard call/expression itself.\n"
    "2. Choose the QL node type that matches the validator's SHAPE — this is the most "
    "common failure mode: writing `CallNode` for a comparison or a variable check.\n"
    "3. Determine `branch` from the safe path: if the validator failure raises/returns, "
    "the SAFE branch is the one that DOESN'T fail.\n\n"
    "SHAPE 1: call-shaped validator (`if is_safe(p): use(p)` / `if not is_safe(p): return`):\n"
    "  predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {\n"
    "    exists(CallNode call | g = call and\n"
    "      call.getFunction().(NameNode).getId() = \"is_safe\" and\n"
    "      node = call.getArg(0) and branch = true)\n"
    "  }\n\n"
    "SHAPE 2: comparison-shaped validator (`if value != expected: return`).  Real "
    "working example from CVE-2016-2512 (host == expected_host gates the value):\n"
    "  predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {\n"
    "    exists(CompareNode cmp | g = cmp and\n"
    "      cmp.operands(node, any(Eq eq), _) and\n"
    "      branch = false)\n"
    "  }\n"
    "Use `CompareNode` and `cmp.operands(value_node, op, other)` — the `value_node` "
    "IS `node`.  `branch = false` is correct when the safe path is the EQUAL branch "
    "of `!=` (i.e., the unequal-condition is False).\n\n"
    "SHAPE 3: variable-presence guard (`if user_supplied_var: use(user_supplied_var)`).  "
    "Real working example from CVE-2021-25926 — the variable's truthy branch is safe:\n"
    "  predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {\n"
    "    exists(NameNode v | v.getId() = \"srcallback\" and\n"
    "      g = v and node = v and branch = true)\n"
    "  }\n"
    "Use `NameNode` when the guard IS the variable itself (no call, no comparison) — "
    "`g = v` AND `node = v` (same node both roles)."
)

_JS_SYSTEM_PROMPT = (
    "You are a CodeQL expert. A JavaScript taint-analysis finding has been flagged "
    "as a false positive because a PROJECT-SPECIFIC validator/sanitizer on the path "
    "neutralizes the attacker input — but the analyzer doesn't model it. Your job: "
    "emit a CodeQL SanitizerGuardNode subclass that recognizes that validator.\n\n"
    "Output ONLY a CodeQL class, exactly this name and shape:\n"
    "  class ProposedGuard extends TaintTracking::SanitizerGuardNode {\n"
    "    ProposedGuard() { /* select the guard node: the validator call/comparison */ }\n"
    "    override predicate sanitizes(boolean outcome, Expr e) "
    "{ /* `e` is safe on the `outcome` branch */ }\n"
    "  }\n"
    "Semantics: the constructor selects the guard DataFlow node; `sanitizes(outcome, e)` "
    "holds when expression `e` is neutralized on the `outcome` branch of the guard. "
    "`javascript`, `DataFlow`, `TaintTracking`, and the relevant security "
    "customizations module are already imported. No prose, no markdown fences.\n\n"
    "CRITICAL RULES:\n"
    "1. `e` must be the VALUE BEING VALIDATED, NOT the guard call node.  The most "
    "common failure mode is binding `e = c` (the call) instead of `e = "
    "c.getReceiver().asExpr()` or `e = c.getArgument(N).asExpr()`.\n"
    "2. The `getReceiver()` is `x` in `x.method(...)`; `getArgument(N)` is the Nth arg.  "
    "Pick the one that holds the user-controlled value.\n"
    "3. `outcome` is the branch on which the value is SAFE.  Negated guards "
    "(`if (!validate(x)) throw`) make the safe outcome `false`.\n\n"
    "SHAPE 1: receiver-validates-via-string-arg (`if (!path.startsWith('..')) safe`).  "
    "Real working example from CVE-2024-24756 — note `outcome = false` because the "
    "guard is negated:\n"
    "  class ProposedGuard extends TaintTracking::SanitizerGuardNode {\n"
    "    DataFlow::CallNode c;\n"
    "    ProposedGuard() { c.getCalleeName() = \"startsWith\" and "
    "c.getArgument(0).getStringValue() = \"..\" and this = c }\n"
    "    override predicate sanitizes(boolean outcome, Expr e) "
    "{ outcome = false and e = c.getReceiver().asExpr() }\n"
    "  }\n\n"
    "SHAPE 2: receiver-validates-via-runtime-arg (`if (filePath.includes(workspaceDir)) safe`).  "
    "Real working example from CVE-2020-7758 — `outcome = true` because the receiver "
    "is safe when the includes check passes:\n"
    "  class ProposedGuard extends TaintTracking::SanitizerGuardNode {\n"
    "    DataFlow::CallNode c;\n"
    "    ProposedGuard() { c.getCalleeName() = \"includes\" and this = c }\n"
    "    override predicate sanitizes(boolean outcome, Expr e) "
    "{ outcome = true and e = c.getReceiver().asExpr() }\n"
    "  }\n\n"
    "SHAPE 3: argument-validates-via-named-helper (`if (isValidHost(host)) safe`).  "
    "Real working example from CVE-2021-46704 — the ARGUMENT (not receiver) is the "
    "validated value, `outcome = true`:\n"
    "  class ProposedGuard extends TaintTracking::SanitizerGuardNode {\n"
    "    DataFlow::CallNode c;\n"
    "    ProposedGuard() { c.getCalleeName() = \"isValidHost\" and this = c }\n"
    "    override predicate sanitizes(boolean outcome, Expr e) "
    "{ outcome = true and e = c.getArgument(0).asExpr() }\n"
    "  }"
)

_RB_SYSTEM_PROMPT = (
    "You are a CodeQL expert. A Ruby taint-analysis finding has been flagged as a "
    "false positive because a PROJECT-SPECIFIC validator/sanitizer on the path "
    "neutralizes the attacker input — but the analyzer doesn't model it. Your job: "
    "emit a CodeQL guard predicate that recognizes that validator.\n\n"
    "Output ONLY a CodeQL predicate, exactly this signature and name:\n"
    "  predicate proposedGuard(CfgNodes::AstCfgNode g, CfgNode node, boolean branch)\n"
    "Semantics: `g` is the guard (the validator call/comparison); `node` is the CFG "
    "node of the value it checks; `branch` is the boolean value of `g` on which "
    "`node` is safe. `codeql.ruby.AST`, `DataFlow`, `TaintTracking`, `CFG`, and the "
    "relevant security customizations module are already imported. No prose, no fences.\n\n"
    "CRITICAL: `node` must be the VALUE BEING VALIDATED (the argument), NOT the guard "
    "call. Worked example for a validator `safe_path?(p)`:\n"
    "  predicate proposedGuard(CfgNodes::AstCfgNode g, CfgNode node, boolean branch) {\n"
    "    exists(CfgNodes::ExprNodes::MethodCallCfgNode call | g = call and\n"
    "      call.getExpr().(MethodCall).getMethodName() = \"safe_path?\" and\n"
    "      node = call.getArgument(0) and branch = true)\n"
    "  }\n\n"
    "Determine `branch` from how the validator is USED in the source: if it is "
    "negated (e.g. `raise unless safe_path?(p)`), the safe branch is `false`; choose "
    "the branch that continues to normal use, not the one that errors/returns/raises."
)

_JAVA_SYSTEM_PROMPT = (
    "You are a CodeQL expert. A Java taint-analysis finding has been flagged as a "
    "false positive because a PROJECT-SPECIFIC validator/sanitizer on the path "
    "neutralizes the attacker input — but the analyzer doesn't model it. Your job: "
    "emit a CodeQL guard predicate that recognizes that validator.\n\n"
    "Output ONLY a CodeQL predicate, exactly this signature and name:\n"
    "  predicate proposedGuard(Guard g, Expr e, boolean branch)\n"
    "Semantics: `g` is the guard (the validator call/comparison); `e` is the "
    "expression it checks; `branch` is the boolean value of `g` on which `e` is "
    "safe. `java`, `DataFlow`, `TaintTracking`, `Guards`, and the relevant security "
    "module are already imported. No prose, no markdown fences.\n\n"
    "CRITICAL: `e` must be the VALUE BEING VALIDATED (the argument the check guards), "
    "NOT the guard call itself. Worked example for a validator `isSafe(p)`:\n"
    "  predicate proposedGuard(Guard g, Expr e, boolean branch) {\n"
    "    exists(MethodCall call | g = call and\n"
    "      call.getMethod().hasName(\"isSafe\") and\n"
    "      e = call.getArgument(0) and branch = true)\n"
    "  }\n\n"
    "Determine `branch` from how the validator is USED in the source: if it is "
    "negated (e.g. `if (!isSafe(p)) throw`), the safe branch is `false`; choose "
    "the branch that continues to normal use, not the one that throws/returns."
)

_GO_SYSTEM_PROMPT = (
    "You are a CodeQL expert. A Go taint-analysis finding has been flagged as a "
    "false positive because a PROJECT-SPECIFIC validator/sanitizer on the path "
    "neutralizes the attacker input — but the analyzer doesn't model it. Your "
    "job: emit a CodeQL guard predicate that recognizes that validator.\n\n"
    "Output ONLY a CodeQL predicate, exactly this signature and name:\n"
    "  predicate proposedGuard(DataFlow::Node g, Expr e, boolean branch)\n"
    "Semantics: `g` is the guard (the validator call/comparison); `e` is the "
    "expression it checks; `branch` is the boolean value of `g` on which `e` is "
    "safe. `go`, `DataFlow`, `TaintTracking`, and the relevant security "
    "customizations module are already imported. No prose, no markdown fences.\n\n"
    "CRITICAL: `e` must be the VALUE BEING VALIDATED (the argument the check "
    "guards), NOT the guard call itself.  Worked example for a validator "
    "`IsSafe(p)`:\n"
    "  predicate proposedGuard(DataFlow::Node g, Expr e, boolean branch) {\n"
    "    exists(DataFlow::CallNode call | g = call and\n"
    "      call.getCalleeName() = \"IsSafe\" and\n"
    "      e = call.getArgument(0).asExpr() and branch = true)\n"
    "  }\n\n"
    "Go-specific notes:\n"
    "  * Use `DataFlow::CallNode` (not `MethodCall`) — Go represents calls as "
    "DataFlow nodes.\n"
    "  * `getCalleeName()` matches both package-level functions (`IsSafe`) "
    "and method values (`x.IsSafe`); for stricter matching use "
    "`getCalleeIncludingExternals()` + `getName()`.\n"
    "  * `call.getArgument(N).asExpr()` gives the Nth argument as an Expr.\n\n"
    "Determine `branch` from how the validator is USED in the source: if it is "
    "negated (e.g. `if !IsSafe(p) { return }`), the safe branch is `false`; "
    "choose the branch that continues to normal use, not the one that errors/"
    "returns/panics."
)

_SYSTEM_PROMPTS = {
    "python": _PY_SYSTEM_PROMPT,
    "javascript": _JS_SYSTEM_PROMPT,
    "ruby": _RB_SYSTEM_PROMPT,
    "java": _JAVA_SYSTEM_PROMPT,
    "go": _GO_SYSTEM_PROMPT,
}


# Sink-class-specific validator-shape hints appended to the user prompt.
#
# Why: the per-language system prompts teach the QL DIALECT and a small set
# of structural shapes (call-shaped, comparison-shaped, name-presence).
# They are sink-class-agnostic — they don't tell the proposer what KIND of
# validator typically protects each vuln class.  In the v3 Go + fresh-CVE
# synth runs, 18 of 18 testable cases came back ``not_sound`` with the
# dominant ``suppress_fp_failed`` failure: the LLM's guard was wrong-
# shaped for the sink class (e.g. trying a literal-string check on an
# SSRF whose actual validator was a DNS-resolve + IP-range gate).
#
# These hints surface the CANONICAL validator shapes for each sink class
# so the proposer has the right prior.  Language-agnostic (the shapes
# generalise across languages; the per-language system prompt translates
# the QL syntax).  Keep each entry to 2-3 concrete idioms — more confuses
# the LLM with noise.
_SINK_CLASS_HINTS = {
    "pathtrav": (
        "Pathtrav validators commonly look like ONE of:\n"
        "  (a) prefix check: `normalized.startsWith(base)` AFTER `path.resolve(p)` "
        "normalizes traversal.  Without normalisation the prefix check is unsound; "
        "look for both steps before binding.\n"
        "  (b) traversal-segment reject: `!p.includes('..')`, "
        "`!p.startsWith('..')`, regex `\\.\\.` blocked.\n"
        "  (c) named-helper: `safe_join(base, p)`, `secure_filename(p)`, "
        "`isRepositoryGitPath(p)` — the helper's return value or its "
        "boolean check is the gate."
    ),
    "cmdi": (
        "Cmdi validators commonly look like ONE of:\n"
        "  (a) allowlist via charset regex: `/^[a-zA-Z0-9_.-]+$/.test(arg)` — only "
        "shell-safe chars permitted.\n"
        "  (b) named shell-quote helper: `shlex.quote(arg)`, `connection.escape(arg)` "
        "— the return value carries the sanitized form.\n"
        "  (c) command-allowlist branch: `if (cmd === 'expected' || cmd === 'other')` "
        "— ONLY known commands proceed."
    ),
    "sqli": (
        "Sqli validators commonly look like ONE of:\n"
        "  (a) parameterised-query: `PreparedStatement.setString(i, v)` / "
        "`cursor.execute(query, (v,))` — the value is bound as a parameter, "
        "not interpolated.\n"
        "  (b) named SQL-escape: `connection.escape(v)`, `mysql_real_escape_string(v)` "
        "— the return value is safe to interpolate.\n"
        "  (c) identifier allowlist: `if (tableName === 'orders' || ...)` for "
        "cases where the value is a table/column name (escapes don't help there)."
    ),
    "xss": (
        "Xss validators commonly look like ONE of:\n"
        "  (a) HTML-context escape call: `escape(v)`, `escapeHtml(v)`, "
        "`encodeForHTML(v)`, `DOMPurify.sanitize(v)`, `bleach.clean(v)` — the "
        "return value is safe to insert into HTML.\n"
        "  (b) Markup wrapper: `markupsafe.escape(v)`, `Markup(v)` — wraps with "
        "an HTML-safe marker class.\n"
        "  (c) charset allowlist on the value's character class — narrower; "
        "common for IDs but not for free-form HTML content."
    ),
    "ssrf": (
        "Ssrf validators commonly look like ONE of:\n"
        "  (a) host-allowlist: `allowedHosts.includes(url.hostname)` / "
        "`url.host === 'expected.example'` — only known external hosts proceed.\n"
        "  (b) IP-range gate (DNS-resolve + classification): "
        "`isResolvingToUnicastOnly(host)` / `parseIP(host).range() === 'unicast'` "
        "— filter to externally-routable IPs.  Watch for ASYNC: many shapes "
        "are `await someCheck(host)`.\n"
        "  (c) protocol allowlist: `url.protocol === 'https:'` — common when "
        "the worry is `file://` / `gopher://`."
    ),
    "codeinjection": (
        "Code-injection validators commonly look like ONE of:\n"
        "  (a) charset allowlist: `/^[A-Za-z0-9_]+$/.test(name)` — only safe "
        "identifier chars, blocks parens/dots/string-literals.\n"
        "  (b) explicit allowlist branch: `if (action in ALLOWED_ACTIONS)` "
        "selecting from a fixed set of safe values.\n"
        "  (c) sandboxed evaluator wrap: `vm.runInNewContext(code, sandbox)` or "
        "equivalent — the value flows into a restricted interpreter rather "
        "than the host's eval."
    ),
}


def _build_prompt(
    proposal: BarrierProposal, prior_error: Optional[str],
    refine_context: Optional[RefineContext] = None,
) -> str:
    emit = (
        "Emit the `ProposedGuard` SanitizerGuardNode subclass recognizing the "
        "validator on this path."
        if proposal.language == "javascript"
        else "Emit the `proposedGuard` predicate recognizing the validator on this path."
    )
    parts = [
        f"sink class: {proposal.sink_class}",
        f"language: {proposal.language}",
        f"flagged sink: {proposal.sink_snippet}",
        "source (the function/path the finding flows through):",
        proposal.source_context,
    ]
    sink_hint = _SINK_CLASS_HINTS.get(proposal.sink_class)
    if sink_hint:
        parts += ["", "Canonical validator shapes for this sink class:",
                  sink_hint]
    parts += ["", emit]
    if prior_error:
        parts += [
            "",
            "Your PREVIOUS attempt failed — fix it. Error:",
            prior_error,
        ]
    if refine_context is not None:
        # Skeleton-level prompt: surface the verdict + the prior QL and a
        # one-line nudge per failure mode. Intentionally minimal — the
        # corpus run will tell us whether richer context (e.g. flagged
        # variable name, full SARIF snippet) moves the needle, at which
        # point this block can grow without changing the loop's
        # interface.
        nudge = {
            "suppress_fp_failed": (
                "Your guard compiled and ran but DIDN'T suppress the "
                "post-fix finding (the value is still flagged at the "
                "sink). The guard is too narrow — refine it so it "
                "ACTUALLY matches the validator on the path the value "
                "takes."
            ),
            "preserve_tp_failed": (
                "Your guard compiled and ran but ALSO killed the pre-fix "
                "finding (the real vuln on the unsanitized code path). "
                "The guard is too broad / matches the wrong thing — "
                "tighten it so it only neutralises the sanitized value, "
                "not the tainted one."
            ),
            "both": (
                "Your guard compiled and ran but moved nothing — neither "
                "suppressed the FP nor killed the TP. The guard isn't "
                "binding on either flow. Re-examine the validator's "
                "structure on the path."
            ),
        }.get(refine_context.failure_mode, "Refine the guard.")
        parts += [
            "",
            f"REFINEMENT (attempt {refine_context.refine_attempt}). "
            f"{nudge}",
            f"Verdict: after={refine_context.after_count} "
            f"before={refine_context.before_count} "
            f"({refine_context.failure_mode}).",
        ]
        if refine_context.surviving_finding_summary:
            # Counterexample-driven refinement: the proposer sees the
            # SPECIFIC tainted flow that survived its guard, not just a
            # generic "your guard was too narrow" line.  Helps the LLM
            # target the actual validator the fix added rather than
            # guess from the original source context.
            parts += [
                "Concrete counterexample (the flow your guard didn't gate):",
                refine_context.surviving_finding_summary,
            ]
        parts += [
            "Prior attempt's QL was:",
            refine_context.prior_query_ql,
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
    """Build a proposer backed by an LLM ``complete`` callable.

    Accepts an optional ``refine_context`` kwarg (passed by
    :func:`run_synthesis_loop` when ``max_refine_attempts > 0`` and a
    prior attempt was not_sound).  Forwarded into :func:`_build_prompt`
    so the LLM sees the prior verdict + its prior QL on refinement.
    """
    def propose(
        proposal: BarrierProposal, prior_error: Optional[str],
        refine_context: Optional[RefineContext] = None,
    ) -> str:
        system_prompt = _SYSTEM_PROMPTS.get(proposal.language, _PY_SYSTEM_PROMPT)
        return _extract_ql(complete(
            system_prompt,
            _build_prompt(proposal, prior_error, refine_context=refine_context),
        ))
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


def model_completer(model_name: str) -> Completer:
    """A Completer pinned to a specific model (e.g. ``claude-opus-4-7``), so the
    proposer can use a strong code model rather than the auto-selected one.

    ``pinned_model=model_name`` makes LLMClient build a minimal LLMConfig
    targeted at the inferred provider only — the thinking-model
    auto-resolution path is bypassed entirely, so its log lines never
    fire and no operator-default model gets resolved + advertised when
    every call here passes ``model_config=`` anyway.
    """
    from core.llm.client import LLMClient

    client = LLMClient(pinned_model=model_name)
    # client.config.primary_model is already the pinned + credentialed config
    # (see _pinned_llm_config) — no further candidate-cloning needed.
    model_config = client.config.primary_model

    def _complete(system_prompt: str, user_prompt: str) -> str:
        resp = client.generate(user_prompt, system_prompt=system_prompt,
                               model_config=model_config)
        text = getattr(resp, "content", None)
        return text if text is not None else str(resp)

    return _complete


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before_db", type=Path, help="CodeQL DB of the pre-fix (vulnerable) source")
    p.add_argument("after_db", type=Path, help="CodeQL DB of the post-fix (sanitized) source")
    p.add_argument("--sink-class", required=True, choices=sorted(_CUSTOMIZATIONS))
    p.add_argument("--language", default="python", choices=sorted(_LANG_PACK))
    p.add_argument("--finding-id", required=True)
    p.add_argument("--sink", required=True, help="flagged sink snippet/description")
    p.add_argument("--source-file", type=Path, required=True,
                   help="source the LLM reasons over (the function/path)")
    p.add_argument("--search-path", help="codeql query-pack search path (--additional-packs)")
    p.add_argument("--max-attempts", type=int, default=3)
    p.add_argument("--work-dir", type=Path, default=Path("/tmp/trust-synth-work"))
    args = p.parse_args(argv)

    proposal = BarrierProposal(
        sink_class=args.sink_class, finding_id=args.finding_id, language=args.language,
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
