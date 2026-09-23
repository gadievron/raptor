"""IRIS-style CodeQL dataflow validation for /audit hypotheses.

When the LLM claims "input flows from source to sink" but no
existing CodeQL finding confirms the path, generate a targeted
CodeQL query to test the claim. Uses the existing CodeQL
augmented-run substrate.

Integration:
- review_fn generates a hypothesis with evidence_tool="codeql"
- orchestrator calls validate_dataflow_claim() with the hypothesis
- Result strengthens or refutes the finding

This converts ungrounded LLM opinions into tool-verified dataflow.

SMT path pruning: before a synthesized query's SARIF matches count as
confirmation, each match's thread-flow path is run through the SMT
path-feasibility machinery (same substrate /agentic's Tier 4 uses —
``packages.exploit_feasibility.smt_path.validate_path`` over
``core.smt_solver.path_feasibility``). Branch conditions are harvested
mechanically from the guards enclosing each path step; a match whose
every conditioned path is UNSAT is an incidental (vacuous-checker)
match and is pruned with a receipt. Complements condition_smt.py:
that checks hypothesis conditions, this checks per-dataflow-path
satisfiability.
"""

from __future__ import annotations

import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from core.source import open_regular
from typing import Any

from core.sarif.parser import load_sarif
from core.source.lines import split_lines

from ._util import is_valid_identifier

logger = logging.getLogger(__name__)


@dataclass
class DataflowClaim:
    source_file: str
    source_function: str
    sink_file: str
    sink_function: str
    source_type: str = ""
    sink_type: str = ""
    description: str = ""


@dataclass
class ValidationResult:
    claim: DataflowClaim
    confirmed: bool | None = None
    sarif_matches: int = 0
    reasoning: str = ""
    error: str = ""
    query_text: str = ""
    smt_pruned: int = 0
    smt_receipts: list[dict[str, Any]] = field(default_factory=list)


_CPP_IDENT_RE = re.compile(
    r"^~?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:::[A-Za-z_~][A-Za-z0-9_]*)*"
    r"(?:<[A-Za-z0-9_:,\s*&]*>)?$"
)


def _validate_identifier(name: str, label: str) -> None:
    if not name:
        msg = f"{label} must be non-empty"
        raise ValueError(msg)
    if not is_valid_identifier(name) and not _CPP_IDENT_RE.match(name):
        msg = f"{label} must be a valid identifier (got {name!r})"
        raise ValueError(msg)


def _codeql_base_name(name: str) -> str:
    """The unqualified, template-arg-free form CodeQL's ``getName()``
    reports (`ns::f<T>` -> `f`, `f<T>::g` -> `g`)."""
    return name.rsplit("::", 1)[-1].split("<", 1)[0]


def generate_taint_query(claim: DataflowClaim, *, language: str = "cpp") -> str:
    """Generate a targeted CodeQL taint-tracking query for a claim.

    Produces a minimal QL query that checks whether data flows from
    the claimed source to the claimed sink. Currently supports C/C++
    (language="cpp"). Raises ValueError for unsupported languages
    or invalid function names.
    """
    _validate_identifier(claim.source_function, "source_function")
    _validate_identifier(claim.sink_function, "sink_function")

    if language != "cpp":
        msg = f"unsupported language for CodeQL validation: {language}"
        raise ValueError(msg)

    # CodeQL's getName() is unqualified and template-arg-free: a
    # qualified (`ns::f`) or template (`f<T>`) spelling interpolated
    # verbatim can never equal it, so every such claim came back a
    # vacuous confirmed=False.
    source_fn = _codeql_base_name(claim.source_function)
    sink_fn = _codeql_base_name(claim.sink_function)

    return f"""\
/**
 * @name Audit hypothesis: dataflow {source_fn} -> {sink_fn}
 * @description Tests whether data flows from {source_fn} to {sink_fn}
 * @kind path-problem
 * @problem.severity warning
 * @id raptor/audit-hypothesis
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

module AuditHypothesisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node source) {{
    exists(FunctionCall fc |
      fc.getTarget().getName() = "{source_fn}" and
      source.asExpr() = fc
    )
    or
    exists(Function f |
      f.getName() = "{source_fn}" and
      source.asParameter() = f.getAParameter()
    )
  }}

  predicate isSink(DataFlow::Node sink) {{
    exists(FunctionCall fc |
      fc.getTarget().getName() = "{sink_fn}" and
      sink.asExpr() = fc.getAnArgument()
    )
  }}
}}

module AuditHypothesisFlow = TaintTracking::Global<AuditHypothesisConfig>;

import AuditHypothesisFlow::PathGraph

from AuditHypothesisFlow::PathNode source, AuditHypothesisFlow::PathNode sink
where AuditHypothesisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Data flows from {source_fn} to {sink_fn}"
"""


def validate_dataflow_claim(
    claim: DataflowClaim,
    *,
    db_path: Path | None = None,
    codeql_bin: str = "codeql",
    timeout_seconds: int = 300,
    target_path: Path | None = None,
) -> ValidationResult:
    """Run a CodeQL query to validate a dataflow claim.

    Generates a taint-tracking query for the claim, runs it against
    the CodeQL database, and checks whether any paths are found.
    When ``target_path`` is given, each match's thread-flow path is
    additionally SMT-checked (branch-condition satisfiability); a
    match whose paths are all provably infeasible is pruned before it
    can confirm the claim — with per-path receipts on the result.
    """
    if db_path is None:
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error="no CodeQL database path provided",
        )

    if not db_path.exists():
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error=f"CodeQL database not found: {db_path}",
        )

    try:
        query_text = generate_taint_query(claim)
    except ValueError as exc:
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error=str(exc),
        )

    try:
        from core.dataflow.codeql_augmented_run import analyze
    except ImportError:
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error="codeql_augmented_run not available",
            query_text=query_text,
        )

    try:
        with tempfile.TemporaryDirectory(prefix="audit-codeql-") as tmpdir:
            tmpdir_path = Path(tmpdir)
            query_file = tmpdir_path / "audit-hypothesis.ql"
            query_file.write_text(query_text)
            output_path = tmpdir_path / "results.sarif"

            result = analyze(
                db_path=db_path,
                queries=[str(query_file)],
                output_path=output_path,
                codeql_bin=codeql_bin,
                timeout_seconds=timeout_seconds,
            )

            if result.sarif_path.exists():
                # Bounded canonical loader (100 MiB stat gate before
                # the read): the SARIF is CodeQL output over the
                # analysed target, which can inflate it through paths
                # and snippets.
                sarif_data = load_sarif(result.sarif_path)
                if sarif_data is None:
                    return ValidationResult(
                        claim=claim,
                        confirmed=None,
                        error=(
                            "SARIF output unreadable or over the "
                            "100 MiB size cap"
                        ),
                        query_text=query_text,
                    )
                match_count = _count_codeflow_results(sarif_data)
                smt_pruned = 0
                smt_receipts: list[dict[str, Any]] = []
                if match_count > 0 and target_path is not None:
                    try:
                        match_count, smt_pruned, smt_receipts = (
                            _smt_prune_sarif_matches(
                                sarif_data, target_path,
                            )
                        )
                    except Exception:
                        logger.debug(
                            "smt prune pass failed", exc_info=True,
                        )
                if match_count > 0:
                    reasoning = f"CodeQL found {match_count} dataflow path(s)"
                    if smt_pruned:
                        reasoning += (
                            f" ({smt_pruned} match(es) pruned:"
                            " path conditions unsatisfiable)"
                        )
                elif smt_pruned:
                    reasoning = (
                        f"CodeQL matched but SMT proved all {smt_pruned}"
                        " match path(s) infeasible — vacuous checker"
                        " match"
                    )
                else:
                    reasoning = "CodeQL found no dataflow paths"
                return ValidationResult(
                    claim=claim,
                    confirmed=match_count > 0,
                    sarif_matches=match_count,
                    reasoning=reasoning,
                    query_text=query_text,
                    smt_pruned=smt_pruned,
                    smt_receipts=smt_receipts,
                )
            return ValidationResult(
                claim=claim,
                confirmed=None,
                error="no SARIF output produced",
                query_text=query_text,
            )

    except Exception as exc:  # noqa: BLE001 — degrade to inconclusive
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error=str(exc),
            query_text=query_text,
        )


def _count_codeflow_results(sarif: dict[str, Any]) -> int:
    """Count the number of results with codeFlows in SARIF output.

    NOT a plain result count (that is core.sarif.parser.count_results)
    — a result without a codeFlow proves nothing about dataflow here,
    so only flow-carrying results count toward validation evidence.
    """
    count = 0
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if result.get("codeFlows"):
                count += 1
    return count


# ── SMT path pruning ─────────────────────────────────────────────────
# Bounded like /agentic's Tier 4: few paths per match, few steps per
# path, few conditions per solver call, short per-call timeout. The
# solver wrapper degrades to feasible=None when z3 is absent — unknown
# never prunes.
_MAX_SMT_PATHS_PER_RESULT = 3
_MAX_SMT_PATH_STEPS = 20
_MAX_SMT_CONDITIONS = 16

# Hard cap on a single target-source read in the guard-condition
# harvester. Matches core/audit/context._MAX_SOURCE_FILE_BYTES: real
# source files sit far below this; anything past it is a planted
# blob whose only effect is memory exhaustion.
_MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
_SMT_PRUNE_TIMEOUT_MS = 2000
_GUARD_LOOKBACK_LINES = 3

_GUARD_KW_RE = re.compile(r"\b(if|while|for)\s*\(")


def _guard_condition_on_line(text: str) -> str | None:
    """Branch condition on a source line, or None.

    ``if (...)`` / ``while (...)`` take the whole (balanced) group;
    ``for (init; cond; step)`` takes the middle clause. Purely
    textual and single-line — multi-line conditions are skipped
    rather than guessed.
    """
    _kind, group, _tail = _guard_on_line(text)
    return group


def _guard_on_line(text: str) -> tuple[str, str | None, str]:
    """``(keyword, condition, tail-after-close-paren)`` for a guard
    on one source line, or ``("", None, "")``.

    Same extraction as :func:`_guard_condition_on_line` plus the
    facts polarity analysis needs: which guard keyword matched, what
    (if anything) follows the closing paren on the line, and whether
    the guard is chained (``else if``) or a preprocessor directive —
    both return no condition, since their truth cannot be tied to
    the fall-through path textually.
    """
    m = _GUARD_KW_RE.search(text)
    if not m:
        return "", None, ""
    prefix = text[:m.start()]
    if prefix.lstrip().startswith("#") or re.search(r"\belse\s*$", prefix):
        # `#if` conditions are compile-time, not path conditions;
        # an `else if` arm's fall-through can come from an EARLIER
        # taken arm, so neither polarity is assertable.
        return "", None, ""
    open_idx = m.end() - 1
    depth = 0
    start: int | None = None
    end: int | None = None
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "(":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start is not None:
                end = i
                break
    if end is None or start is None:
        return "", None, ""
    group = text[start:end]
    if m.group(1) == "for":
        parts = group.split(";")
        group = parts[1] if len(parts) == 3 else ""
    group = group.strip()
    return m.group(1), (group or None), text[end + 1:]


#: Statement shapes that leave the enclosing flow — a guard whose arm
#: ENDS in one of these makes the fall-through path require the guard
#: condition to be FALSE (the ubiquitous C early-exit idiom).
# Seed set (<= 9 names, C control flow + libc noreturn): a missing
# spelling only drops a negation opportunity — the condition is then
# dropped entirely, which weakens the prune toward keep.
_EXIT_STMT_RE = re.compile(
    r"^(?:return\b|goto\s+\w|break$|continue$"
    r"|(?:exit|abort|longjmp|panic)\s*\()"
)


#: Statement-leading label (goto target / case arm). `(?!:)` keeps
#: C++ scope tokens (`std::x`) from matching.
#: The case-arm expression is gated to end on non-whitespace
#: ((?:[^:]*[^:\s])?) so the trailing ``\s*`` owns the whitespace run
#: alone — ``[^:]*\s*`` overlapped on spaces: quadratic on a
#: 'case'-opening line ending in a space run with no ':'.
_LABEL_RE = re.compile(r"^\s*(?:case\b(?:[^:]*[^:\s])?|[A-Za-z_]\w*)\s*:(?!:)")


def _exit_only_body(body: str) -> bool:
    """True when the guarded body's last statement leaves the flow."""
    stmts = [s.strip() for s in body.split(";") if s.strip()]
    if not stmts:
        return False
    return _EXIT_STMT_RE.match(stmts[-1]) is not None


#: C/C++ raw-string opener: its delimiter grammar defeats a quote
#: scanner, so a region carrying one is not brace-censusable.
_RAW_STRING_RE = re.compile(r'\b(?:u8|[uUL])?R"')


def _blank_c_literals(parts: list[str]) -> tuple[list[str], bool]:
    """Blank C string/char literals and comments out of source-line
    texts (single linear pass, comment state carried across lines;
    contents become spaces so brace and statement positions
    survive).  The polarity census counts braces and reads exit
    statements from these texts — a ``{`` inside ``log("{")`` or a
    comment is DATA, and counting it flips the arm/step judgment
    back to the inverted-polarity assertion this census exists to
    prevent.

    Returns ``(blanked, censusable)`` — ``censusable`` is False when
    the text cannot be blanked faithfully: a raw string opens, a
    string/char literal runs off its line (ill-formed C), or a block
    comment is still open at the end.  Callers must abstain, never
    census the raw text.
    """
    out: list[str] = []
    state = ""  # "" | "str" | "chr" | "blk"
    for text in parts:
        if state != "blk" and _RAW_STRING_RE.search(text):
            return parts, False
        buf: list[str] = []
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if state in ("str", "chr"):
                if ch == "\\":
                    buf.append("  ")
                    i += 2
                    continue
                if ch == ('"' if state == "str" else "'"):
                    state = ""
                    buf.append(ch)
                else:
                    buf.append(" ")
                i += 1
                continue
            if state == "blk":
                if ch == "*" and i + 1 < n and text[i + 1] == "/":
                    state = ""
                    buf.append("  ")
                    i += 2
                    continue
                buf.append(" ")
                i += 1
                continue
            if ch in ('"', "'"):
                state = "str" if ch == '"' else "chr"
                buf.append(ch)
                i += 1
                continue
            if ch == "/" and i + 1 < n:
                if text[i + 1] == "/":
                    break  # line comment: the rest of THIS line
                if text[i + 1] == "*":
                    state = "blk"
                    buf.append("  ")
                    i += 2
                    continue
            buf.append(ch)
            i += 1
        if state in ("str", "chr"):
            # A literal cannot span source lines in well-formed C.
            return parts, False
        out.append("".join(buf))
    return out, state == ""


def _step_guard_polarity(
    kind: str,
    tail: str,
    between: list[str],
    step_line: str,
) -> str | None:
    """Polarity with which a guard binds the step that follows it.

    ``"positive"`` — the step is provably inside the guarded arm;
    ``"negated"`` — the arm is an exit-only ``if`` body, so the
    fall-through step requires the condition FALSE (early-exit
    guard); ``None`` — the arm/step relation is textually
    undecidable, so the condition must not be asserted in either
    direction (an unprovable polarity weakens the prune toward
    keep — it never manufactures an infeasibility receipt).

    ``step_line`` is the step's OWN source line: an arm can close on
    it, BEFORE the step statement (``if (c) { return; } step;`` —
    K&R-compact / minified / generated C).  That closure is invisible
    to tail+between inspection, and judging the step "inside the
    arm" asserts the guard with INVERTED polarity — the one shape
    that lets a trivially-live path prove "mutually exclusive" and
    mint a proof-grade infeasibility receipt.  Only the line's
    leading close-braces are read; when they leave the arm/step
    relation ambiguous the polarity is dropped, never guessed.

    The brace census runs on literal/comment-blanked text (a ``{``
    inside ``log("{")`` or a comment is data, and counting it
    re-mints the inverted-polarity assertion); a region that cannot
    be blanked faithfully is not censused — it abstains.
    """
    if any(_LABEL_RE.match(ln) for ln in between):
        # A label between the guard and the step is a goto target:
        # another path can reach the step without evaluating the
        # guard, so neither polarity is assertable.
        return None
    lead_closers = 0
    i = 0
    while i < len(step_line) and step_line[i] in " \t}":
        if step_line[i] == "}":
            lead_closers += 1
        i += 1
    if lead_closers and _LABEL_RE.match(step_line[i:]):
        # `} out: step;` — the brace prefix hides the label from a
        # line-start label check, but it is still a goto target:
        # another path reaches the step with the guard TRUE.
        return None
    blanked, censusable = _blank_c_literals([tail, *between])
    if not censusable:
        # Raw string / unterminated literal / comment running past
        # the region: the brace census would count data as code.
        return None
    region = " ".join(
        p.strip() for p in blanked if p.strip()
    ).strip()
    if re.search(r"\belse\b", region):
        return None
    if region.startswith("{"):
        if "}" not in region:
            depth = region.count("{")
            if lead_closers < depth:
                # Brace opened and never closed before the step;
                # any step-line closers close NESTED opens — the
                # guard's arm is still open at the step.
                return "positive"
            if (lead_closers == depth and kind == "if"
                    and _exit_only_body(region[1:])):
                # The arm closes on the step line before the step:
                # the step is the fall-through of an exit-only arm,
                # so the condition holds NEGATED.
                return "negated"
            # Arm closed at the step line with a non-exit body (the
            # arm may or may not have run), or more closers than
            # opens (the relation is not linear text): drop it.
            return None
        body, _, after = region[1:].partition("}")
        if after.strip():
            return None
        if lead_closers:
            # The guard's arm already closed inside *between*; the
            # step line's leading `}` closes an OUTER scope opened
            # before the guard — the guard→step relation is not a
            # linear fall-through.
            return None
        if kind == "if" and _exit_only_body(body):
            return "negated"
        return None
    if lead_closers:
        # Braceless arm / bare fall-through with a `}` before the
        # step: the brace closes a scope opened BEFORE the guard (a
        # loop or switch body), so the step can be reached from
        # iterations whose last guard evaluation is unknowable.
        return None
    if not region:
        # Nothing between the guard and the step line: the step IS
        # the (braceless) arm.
        return "positive"
    if kind == "if" and _exit_only_body(region):
        # `if (err) return; …step` / `if (err)\n\treturn;\n…step` —
        # only `if` earns the negation: falling out of a loop body
        # via break does NOT falsify the loop condition.
        return "negated"
    return None


def _sarif_result_paths(
    result: dict[str, Any],
) -> list[list[tuple]]:
    """(uri, line) step lists for a SARIF result's thread flows."""
    paths: list[list[tuple]] = []
    for cf in result.get("codeFlows", []):
        for tf in cf.get("threadFlows", []):
            steps: list[tuple] = []
            for loc in tf.get("locations", [])[:_MAX_SMT_PATH_STEPS]:
                phys = (
                    loc.get("location", {}).get("physicalLocation", {})
                )
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                if uri and isinstance(line, int) and line > 0:
                    steps.append((uri, line))
            if steps:
                paths.append(steps)
            if len(paths) >= _MAX_SMT_PATHS_PER_RESULT:
                return paths
    return paths


def _load_source_lines(
    uri: str,
    target_path: Path,
    cache: dict[str, list[str] | None],
) -> list[str] | None:
    if uri in cache:
        return cache[uri]
    lines: list[str] | None = None
    try:
        from core.paths import confine

        # Path-containment: SARIF uris are attacker-influenced text.
        # ``confine`` is separator-aware — the previous bare-prefix
        # startswith accepted sibling directories like
        # ``/repo-evil`` for target ``/repo``.
        candidate = confine(target_path, uri.lstrip("/"))
        if candidate is not None and candidate.is_file():
            # Size-gate BEFORE the read: the file lives in the
            # scanned — attacker-controlled — tree, and this loop
            # runs per SARIF path step. A planted blob must be
            # refused, not buffered. Capped read + re-check closes
            # the stat/read growth race (house pattern, see
            # core/audit/context._read_source_span).
            if candidate.stat().st_size > _MAX_SOURCE_FILE_BYTES:
                logger.warning(
                    "codeql_validation: refusing oversize source file "
                    "%s (> %d bytes)", candidate, _MAX_SOURCE_FILE_BYTES,
                )
            else:
                fh = open_regular(candidate, "rb")
                if fh is None:
                    raise OSError(f"not a readable regular file: {candidate}")
                with fh:
                    raw = fh.read(_MAX_SOURCE_FILE_BYTES + 1)
                if len(raw) > _MAX_SOURCE_FILE_BYTES:
                    logger.warning(
                        "codeql_validation: source file %s grew past "
                        "%d bytes during read; refusing",
                        candidate, _MAX_SOURCE_FILE_BYTES,
                    )
                else:
                    # \n-model split (core.source.lines contract):
                    # the indexing line numbers are CodeQL SARIF's,
                    # which count \n only — a splitlines() view let
                    # one form feed inside a comment shift the
                    # guard-harvest window onto attacker-chosen
                    # lines.
                    lines = split_lines(raw.decode(errors="replace"))
    except (OSError, ValueError):
        lines = None
    cache[uri] = lines
    return lines


def _path_conditions(
    steps: list[tuple],
    target_path: Path,
    cache: dict[str, list[str] | None],
) -> list[dict[str, Any]]:
    """Harvest enclosing-guard conditions along one thread-flow path.

    Polarity discipline: a condition is asserted positively only when
    the step is provably inside the guarded arm; the early-exit guard
    idiom (``if (err) return; …step``) asserts the NEGATION — the
    real path condition of the fall-through; every other arm/step
    relation drops the condition. A guard on the step line itself is
    never harvested (the step may be the condition expression, not
    the arm). Wrong-polarity assertion was the one shape that let a
    trivially-live path prove "mutually exclusive" and mint a
    refutation-grade receipt.
    """
    conditions: list[dict[str, Any]] = []
    seen: set[tuple[str, bool]] = set()
    for step_index, (uri, line) in enumerate(steps):
        lines = _load_source_lines(uri, target_path, cache)
        if not lines or line > len(lines):
            continue
        if _LABEL_RE.match(lines[line - 1]):
            # A goto-target label on the step's OWN line: another
            # path reaches the step without evaluating any guard
            # above it — no polarity is assertable for this step.
            continue
        for j in range(line - 1, max(line - 1 - _GUARD_LOOKBACK_LINES, 0), -1):
            kind, cond, tail = _guard_on_line(lines[j - 1])
            if cond is None:
                continue
            between = lines[j:line - 1]
            polarity = _step_guard_polarity(
                kind, tail, between, lines[line - 1],
            )
            if polarity is not None:
                negated = polarity == "negated"
                if (cond, negated) not in seen:
                    seen.add((cond, negated))
                    conditions.append({
                        "text": cond,
                        "step_index": step_index,
                        "negated": negated,
                    })
            # Nearest guard decides for this step — an undecidable
            # one contributes nothing rather than letting a farther
            # guard mis-bind.
            break
        if len(conditions) >= _MAX_SMT_CONDITIONS:
            break
    return conditions


def _smt_prune_sarif_matches(
    sarif: dict[str, Any],
    target_path: Path,
) -> tuple:
    """SMT-check each match's path conditions; prune UNSAT-only matches.

    Returns ``(surviving_count, pruned_count, receipts)``. A match is
    pruned only when every thread-flow path yielded conditions AND the
    solver proved every one of them jointly unsatisfiable — an
    incidental match of a vacuous checker. Unknown/unavailable/
    condition-free paths always keep the match (fail-open).
    """
    try:
        from packages.exploit_feasibility.smt_path import validate_path
    except ImportError:
        return _count_codeflow_results(sarif), 0, []

    kept = 0
    pruned = 0
    receipts: list[dict[str, Any]] = []
    cache: dict[str, list[str] | None] = {}

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if not result.get("codeFlows"):
                continue
            paths = _sarif_result_paths(result)
            path_receipts: list[dict[str, Any]] = []
            all_unsat = bool(paths)
            for steps in paths:
                conditions = _path_conditions(steps, target_path, cache)
                if not conditions:
                    all_unsat = False
                    continue
                try:
                    # profile=None: the guards are raw source text
                    # harvested with no type information, so their
                    # signedness is a GUESS — validate_path then
                    # reports infeasible only when BOTH signedness
                    # profiles agree. A pinned "uint64" asserted
                    # knowledge this harvester doesn't have: the
                    # ubiquitous C signed error check (ret < 0)
                    # encodes as ULT(ret, 0), unsat, and pruned a
                    # live dataflow match outright.
                    res = validate_path(
                        conditions,
                        profile=None,
                        timeout_ms=_SMT_PRUNE_TIMEOUT_MS,
                    )
                except Exception:
                    logger.debug("smt path prune failed", exc_info=True)
                    all_unsat = False
                    continue
                if res.get("feasible") is False:
                    path_receipts.append({
                        "conditions": conditions,
                        "reasoning": res.get("reasoning", ""),
                        "unsatisfied": res.get("unsatisfied", []),
                    })
                else:
                    all_unsat = False

            if all_unsat and path_receipts:
                pruned += 1
                loc = (
                    result.get("locations", [{}])[0]
                    .get("physicalLocation", {})
                )
                receipts.append({
                    "file": (
                        loc.get("artifactLocation", {}).get("uri", "")
                    ),
                    "line": loc.get("region", {}).get("startLine", 0),
                    "rule_id": result.get("ruleId", ""),
                    "verdict": "smt_path_infeasible",
                    "paths": path_receipts,
                })
            else:
                kept += 1

    return kept, pruned, receipts


def extract_claims_from_review(
    review_result: dict[str, Any],
) -> list[DataflowClaim]:
    """Extract dataflow claims from a review result.

    Looks for structured claim data in the review result. The LLM
    should populate these fields when evidence_tool="codeql":
    - dataflow_source: {file, function}
    - dataflow_sink: {file, function}
    """
    claims = []

    source = review_result.get("dataflow_source", {})
    sink = review_result.get("dataflow_sink", {})

    if source and sink and source.get("function") and sink.get("function"):
        claims.append(DataflowClaim(
            source_file=source.get("file", review_result.get("file", "")),
            source_function=source.get("function", ""),
            sink_file=sink.get("file", review_result.get("file", "")),
            sink_function=sink.get("function", ""),
            source_type=source.get("type", ""),
            sink_type=sink.get("type", ""),
            description=review_result.get("hypothesis", ""),
        ))

    return claims
