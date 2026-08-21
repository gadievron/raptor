"""Z3 string-theory prescreen for LIVE injection findings.

:mod:`core.dataflow.smt_barrier` proves that a fix-added charset
validator neutralises an injection sink (regex-language-intersection
emptiness, single-digit-ms per query) — but only for PATCH
verification. The same proof applies to a finding that is still open:
when the finding's own dataflow path crosses a validator whose pattern
the mechanical extractor can lift, and the validator's accepted
language shares no string with the sink's danger language, the path is
provably neutralised BEFORE any LLM call is spent on it.

Verdict semantics mirror the SMT-unsat handling in the CodeQL
dataflow validator: a refuted finding is demoted (confidence-capped
non-exploitable with the barrier evidence attached), never silently
dropped, and a finding with several (codeFlow, threadFlow) paths is
refuted only when EVERY path is individually neutralised — one
unliftable path means no signal for the whole finding.

Soundness posture (a false "refuted" here suppresses a real bug):

* Extraction reuses ``smt_barrier``'s deliberately conservative
  extractor — anchored whole-string charset ``re.match``/``fullmatch``
  (or single-line guard-and-exit shapes for JS/TS/Java/Ruby) and the
  same-identifier ``re.sub`` strip form. Anything else — partial
  matches, ``re.search``, unanchored patterns, shorthand classes,
  negated classes — is NOT liftable and yields no signal.
* Dominance reuses the same AST machinery the patch flow earned its
  soundness receipts with: same-function + source-order +
  exit-on-fail for guards, no-reassignment for substitutions, and the
  variable/data-dependency chain check that the validated value is
  what reaches the sink. The validator step and the sink must be in
  the SAME file; cross-file paths yield no signal.
* The proof is ``smt_barrier.prove_neutralizes`` — Z3
  regex-intersection emptiness (with a hard per-query timeout; a
  timeout reads as unknown, never as refuted) or finite-set inclusion
  for the substitution form.

Layering: this module sits beside ``smt_barrier`` (whose machinery it
reuses) in ``core.dataflow`` and imports only downward (core.smt_solver,
core.inventory). The pipeline hook lives in
``packages/codeql/dataflow_validator.py``.
"""

from __future__ import annotations

import ast
import re as _re
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.dataflow.sanitizer_catalog import sink_classes_for_cwe
from core.dataflow.smt_barrier import (
    _DANGER_CHARS,
    _STR_LITERAL,
    ValidatorSpec,
    _crosses_function_boundary,
    _python_chain_reaches_sink,
    _lexical_var_reaches_sink,
    extract_validator_from_line,
    extractor_languages,
    prove_neutralizes,
    substitution_dominates_sink,
    validator_dominates_sink,
)
from core.inventory.languages import LANGUAGE_MAP
from core.logging import get_logger
from core.smt_solver import z3_available as _z3_available

logger = get_logger()

# Hard per-Z3-query bound. smt_barrier's PoC corpus finishes in 7-9 ms;
# 2000 ms is orders of magnitude of headroom while guaranteeing a
# pathological charset can't stall the validation pipeline. A timeout
# surfaces as z3 `unknown` -> not sound -> no signal.
SOLVER_TIMEOUT_MS = 2000

# A finding is refuted only when EVERY path is neutralised, so the
# per-finding work is bounded by the path count. Beyond this cap the
# prescreen declines (no signal) rather than checking a subset — a
# partial check can never justify a whole-finding refutation.
MAX_PRESCREEN_PATHS = 16

# rule_id -> sink_class, covering both CodeQL query-id and Semgrep
# rule-name spellings for the four injection classes smt_barrier
# carries danger models for. Deliberately word-bounded seed patterns;
# a miss just means no prescreen (the CWE fallback below and the
# normal LLM validation still run).
_RULE_SINK_CLASS_PATTERNS: list[tuple] = [
    (_re.compile(
        r"path[-_]?injection|path[-_]?traversal|tainted[-_]?path"
        r"|directory[-_]?traversal|zip[-_]?slip",
        _re.IGNORECASE), "pathtrav"),
    (_re.compile(
        r"command[-_]?(?:line[-_]?)?injection|os[-_]?command"
        r"|shell[-_]?injection|unsafe[-_]?shell[-_]?command",
        _re.IGNORECASE), "cmdi"),
    (_re.compile(r"sql[-_]?injection|\bsqli\b", _re.IGNORECASE), "sqli"),
    (_re.compile(
        r"\bxss\b|cross[-_]?site[-_]?scripting", _re.IGNORECASE), "xss"),
]


# ---------------------------------------------------------------------------
# Strict-lift layer.
#
# The patch-flow extractor was tuned for fix DIFFS, where the author
# just added the validator and the surrounding controls (fix-mutant,
# ground truth) catch a bad lift. A live-finding refutation has no such
# net, so three shapes the diff extractor accepts must be re-checked
# here and refused:
#
#   * Python calls with trailing arguments. ``re.sub(pat, '', x, 1)``
#     (count) strips only the FIRST occurrence — later danger chars
#     survive; ``re.match(pat, x, re.MULTILINE)`` turns ``^``/``$``
#     into line anchors, so the "whole-string" charset claim is false.
#     Require the call to close immediately after the subject variable.
#   * Python ``re.match`` with ``$`` anchoring. Python's ``$`` also
#     matches just before ONE trailing newline, so ``^[a-z]+$`` accepts
#     ``"abc\n"`` — unsound exactly for danger models containing
#     ``"\n"`` (cmdi). ``re.fullmatch`` has no such quirk. The lift is
#     marked ``accepts_trailing_newline`` and refused for any in-play
#     sink class whose danger set contains a newline.
#   * Ruby guard lifts. Ruby's ``^``/``$`` are ALWAYS line anchors
#     (whole-string anchors are ``\A``/``\z``), so ``/^[a-z]+$/``
#     matches the first line of ``"abc\n/evil"`` — the whole-string
#     charset claim never holds. Refused unconditionally.
# ---------------------------------------------------------------------------

_PY_STRICT_MATCH = _re.compile(
    r"re\.(?P<kind>match|fullmatch)\s*\(\s*"
    rf"{_STR_LITERAL}"
    r"\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"
)

_PY_STRICT_SUB = _re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*re\.sub\s*\(\s*"
    rf"{_STR_LITERAL}"
    r"\s*,\s*(?:''|\"\")\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"
)


def _strict_lift(
    line: str, spec: ValidatorSpec, language: str,
    sink_classes: frozenset,
) -> bool:
    """Final acceptance gate on a lifted validator (see block comment
    above). True only when the lift's language claim is exact for the
    live-finding use."""
    if language == "python":
        if spec.kind == "charset_sub":
            # Call must close right after the subject — a count or
            # flags argument changes the stripping semantics.
            return _PY_STRICT_SUB.search(line) is not None
        m = _PY_STRICT_MATCH.search(line)
        if m is None:
            return False
        if m.group("kind") == "match":
            # `$` tolerates one trailing newline under re.match —
            # refuse when any in-play danger model contains "\n".
            for sink_class in sink_classes:
                if "\n" in _DANGER_CHARS.get(sink_class, []):
                    return False
        return True
    if language == "ruby":
        return False
    # JS/TS guard regexes already refuse flagged literals (a flag char
    # between the closing slash and `.test`/`)` breaks the extractor
    # match); Java String.matches is whole-region with no flags
    # overload.
    return True


@dataclass
class PrescreenVerdict:
    """Structured outcome of one prescreen run over a finding.

    ``refuted`` is True only when every path was neutralised by a
    lifted charset barrier. ``evidence`` then holds one entry per
    path: {path_index, validator_file, validator_line, kind, pattern,
    sink_class, reasoning}. ``solver_ms`` is the summed wall time of
    the Z3/inclusion proofs.
    """
    refuted: bool
    paths_checked: int
    evidence: list[dict] = field(default_factory=list)
    reason: str = ""
    solver_ms: float = 0.0


@dataclass
class PrescreenStats:
    """Per-process telemetry counters (attempted = prescreen entered
    with a mapped sink class and supported language)."""
    attempted: int = 0
    lifted: int = 0          # >=1 validator lifted from some path step
    refuted: int = 0         # whole finding refuted (every path)
    no_signal: int = 0

    def as_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "lifted": self.lifted,
            "refuted": self.refuted,
            "no_signal": self.no_signal,
        }


_STATS = PrescreenStats()


def snapshot_stats() -> dict:
    """Copy of the per-process prescreen counters (for diagnostics)."""
    return _STATS.as_dict()


def sink_classes_for_rule(rule_id: str, cwe: str | None = None) -> frozenset:
    """Map a scanner rule id (and optional explicit CWE) to the
    smt_barrier sink classes it concerns. Empty frozenset = the
    prescreen does not apply (no danger model)."""
    classes: set = set()
    for pattern, sink_class in _RULE_SINK_CLASS_PATTERNS:
        if pattern.search(rule_id or ""):
            classes.add(sink_class)
    if cwe:
        classes |= set(sink_classes_for_cwe(cwe))
    return frozenset(classes)


def _language_for_path(sink_file: str) -> str | None:
    """Extractor language from the sink file's extension. ``tsx``
    normalises to ``typescript`` (same guard grammar); anything the
    extractor table doesn't cover returns None (no signal)."""
    ext = Path(sink_file).suffix.lower()
    lang = LANGUAGE_MAP.get(ext)
    if lang == "tsx":
        lang = "typescript"
    if lang in extractor_languages():
        return lang
    return None


def _read_source(repo_root: Path, rel_path: str) -> str | None:
    """Read a repo file with containment (SARIF-derived paths are
    target-controlled — refuse anything resolving outside the root)."""
    try:
        resolved = (repo_root / rel_path.lstrip("/")).resolve()
        resolved.relative_to(repo_root.resolve())
    except (ValueError, OSError):
        return None
    if not resolved.is_file():
        return None
    try:
        return resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _line_text(source_text: str, line: int) -> str:
    lines = source_text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


def _spec_neutralizes_all(
    spec: ValidatorSpec, sink_classes: frozenset,
) -> tuple[bool, str, float]:
    """Prove the lifted validator against EVERY sink class the rule
    concerns. Returns (sound_for_all, reasoning, solver_ms)."""
    reasons = []
    total_ms = 0.0
    for sink_class in sorted(sink_classes):
        t0 = time.monotonic()
        verdict = prove_neutralizes(
            spec, sink_class, timeout_ms=SOLVER_TIMEOUT_MS,
        )
        total_ms += (time.monotonic() - t0) * 1000.0
        if not verdict.sound:
            return False, verdict.reasoning, total_ms
        reasons.append(verdict.reasoning)
    return True, "; ".join(reasons), total_ms


def _step_refutes_path(
    *,
    spec: ValidatorSpec,
    step_file: str,
    step_line: int,
    sink_file: str,
    sink_line: int,
    source_text: str,
    language: str,
    sink_classes: frozenset,
) -> tuple[bool, str, float]:
    """Full soundness pipeline for one lifted validator on one path:
    dominance (same file, patch-flow AST machinery), value-chain
    reach, then the language-emptiness proof for every sink class."""
    if step_file != sink_file:
        return False, "validator and sink in different files", 0.0
    if spec.kind == "charset_sub":
        dominates = substitution_dominates_sink(
            source_text, step_line, sink_line, spec.var_name,
        )
    elif language == "python":
        dominates = validator_dominates_sink(
            source_text, step_line, sink_line,
        )
    else:
        # Non-Python guard shapes carry exit-on-fail in the matched
        # line itself; source order + no intervening function boundary
        # is the remaining dominance evidence (same as the patch flow).
        dominates = step_line < sink_line and not _crosses_function_boundary(
            source_text, step_line, sink_line, language,
        )
    if not dominates:
        return False, "validator does not dominate the sink", 0.0

    # The validated variable (or a value derived from it) must be what
    # reaches the sink — mirrors the patch flow's Bug-15 guard.
    sink_line_text = _line_text(source_text, sink_line)
    if language == "python":
        try:
            tree = ast.parse(source_text)
        except SyntaxError:
            return False, "sink file does not parse", 0.0
        var_reaches = _python_chain_reaches_sink(
            tree, spec.var_name, step_line, sink_line, sink_line_text,
        )
    else:
        var_reaches = _lexical_var_reaches_sink(
            spec.var_name, source_text, step_line, sink_line,
            sink_line_text,
        )
    if not var_reaches:
        return False, (
            f"validated variable {spec.var_name!r} not in the sink's "
            "value chain"
        ), 0.0

    return _spec_neutralizes_all(spec, sink_classes)


def prescreen_finding(
    *,
    paths: list,
    repo_root: Path,
    rule_id: str,
    cwe: str | None = None,
) -> PrescreenVerdict | None:
    """Prescreen a live injection finding's dataflow paths.

    ``paths`` is the full list of (codeFlow, threadFlow) paths of the
    SARIF result — each an object with ``.source`` / ``.sink`` /
    ``.intermediate_steps`` where steps carry ``.file_path`` /
    ``.line`` (the CodeQL validator's ``DataflowPath`` shape, accepted
    duck-typed so this module keeps its downward-only imports).

    Returns None when the prescreen does not apply (no danger model
    for the rule, unsupported language, too many paths) or found no
    signal; a :class:`PrescreenVerdict` with ``refuted=True`` only
    when EVERY path is provably neutralised by a lifted validator.
    """
    sink_classes = sink_classes_for_rule(rule_id, cwe)
    if not sink_classes or not paths:
        return None
    # The charset (guard) proof needs z3's string theory; the
    # substitution proof is finite-set inclusion. Rather than split
    # behaviour by kind, require z3 for the whole prescreen — the
    # patch flow gates identically, and a missing solver then can
    # never change verdict shape between kinds.
    if not _z3_available():
        return None
    language = _language_for_path(paths[0].sink.file_path)
    if language is None:
        return None
    if len(paths) > MAX_PRESCREEN_PATHS:
        logger.debug(
            "injection prescreen: %d paths exceeds cap %d — no signal",
            len(paths), MAX_PRESCREEN_PATHS,
        )
        return None

    _STATS.attempted += 1
    evidence: list[dict] = []
    any_lifted = False
    total_ms = 0.0
    for path_index, path in enumerate(paths):
        sink = path.sink
        path_refuted = False
        for step in path.intermediate_steps:
            source_text = _read_source(repo_root, step.file_path)
            if source_text is None:
                continue
            line_text = _line_text(source_text, step.line)
            spec = extract_validator_from_line(line_text, language)
            if spec is None:
                continue
            if not _strict_lift(line_text, spec, language, sink_classes):
                continue
            any_lifted = True
            ok, reasoning, ms = _step_refutes_path(
                spec=spec,
                step_file=step.file_path,
                step_line=step.line,
                sink_file=sink.file_path,
                sink_line=sink.line,
                source_text=source_text,
                language=language,
                sink_classes=sink_classes,
            )
            total_ms += ms
            if ok:
                evidence.append({
                    "path_index": path_index,
                    "validator_file": step.file_path,
                    "validator_line": step.line,
                    "kind": spec.kind,
                    "pattern": (
                        spec.charset if spec.kind == "charset"
                        else spec.forbidden
                    ),
                    "sink_classes": sorted(sink_classes),
                    "reasoning": reasoning,
                })
                path_refuted = True
                break
        if not path_refuted:
            if any_lifted:
                _STATS.lifted += 1
            _STATS.no_signal += 1
            return None

    _STATS.lifted += 1
    _STATS.refuted += 1
    return PrescreenVerdict(
        refuted=True,
        paths_checked=len(paths),
        evidence=evidence,
        reason=(
            f"every dataflow path ({len(paths)}) crosses a charset "
            f"validator whose accepted language provably excludes all "
            f"{'/'.join(sorted(sink_classes))} danger characters"
        ),
        solver_ms=total_ms,
    )
