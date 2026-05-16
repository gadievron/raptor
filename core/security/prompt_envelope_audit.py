"""AST-based lint rule for prompt-envelope discipline.

Walks Python source for f-string / .format() interpolations of fields
that carry attacker-influenced content (scanner messages, target source,
external advisory bodies, etc.) and flags any that aren't routed through
RAPTOR's canonical defenses:

  * ``UntrustedBlock`` + ``build_prompt`` (full envelope: tags, nonce,
    datamarking, profile-based hardening)
  * ``neutralize_tag_forgery`` (tag-forgery defang only — partial)
  * ``_sanitize_for_prompt`` (alias for tag-forgery in
    dataflow_validation)

The rule is **opt-in per file**: only files in
:data:`_PROMPT_CONSTRUCTION_FILES` are audited. Adding a new
prompt-builder requires adding the file to that list, which forces an
explicit security review at file-add time.

Allowlist (:data:`_ALLOWLIST`) carries explicit pre-approved
``(file, func_name, attr, expr_text)`` quadruples — each entry must
include an ``audit_note`` string explaining why the interpolation is
safe (trusted source, surrounding envelope, etc.). Without the note
the rule rejects the entry; this prevents silent grandfathering. Key
is content-based so the allowlist survives unrelated edits to the
file (e.g. lines added before the interpolation); a deliberate
change to the call site itself stops matching and re-fires the
audit, which is the desired behaviour.

Threat model: an attacker who can publish a package, file a hostile
GitHub issue, supply CVE metadata, or commit attacker text in a
target repo gets text into RAPTOR's prompt context. Tag-forgery
defenses (envelope close-tag escape, datamarking) are layered atop
the operator's prompt; bypassing the defenses lets the attacker forge
envelope structure or inject role-confusion content.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


# Repository root (this file lives at core/security/prompt_envelope_audit.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]


# Attribute names whose values typically carry attacker-influenced
# content. A bare interpolation of these into a prompt-construction
# context fires the rule. The list is conservative — false positives
# get explicit allowlist entries.
_UNTRUSTED_ATTRS = frozenset({
    # Source-code-derived
    "vulnerable_code", "code", "snippet", "surrounding_context",
    # Scanner / finding metadata
    "rule_id", "rule_name", "message", "level",
    "file_path", "start_line", "end_line",
    # External advisories / package metadata
    "description", "summary", "body", "title", "changelog",
    # Prior-LLM output (semi-untrusted)
    "reasoning", "claim", "context", "content", "text",
    "stdout", "stderr", "output",
    # Hypothesis / claim
    "hypothesis", "claims",
})


# Files whose prompts may carry untrusted external content. The audit
# only walks these — a new prompt-builder file needs an explicit add
# (forcing a security review at file-add time).
_PROMPT_CONSTRUCTION_FILES = (
    # /agentic and downstream
    "packages/llm_analysis/agent.py",
    "packages/llm_analysis/dataflow_validation.py",
    "packages/llm_analysis/orchestrator.py",
    "packages/llm_analysis/prefilter.py",
    "packages/llm_analysis/tasks.py",
    "packages/llm_analysis/crash_agent.py",
    "packages/llm_analysis/prompts/analysis.py",
    "packages/llm_analysis/prompts/exploit.py",
    "packages/llm_analysis/prompts/patch.py",
    # Hypothesis validation
    "packages/hypothesis_validation/runner.py",
    # CodeQL
    "packages/codeql/autonomous_analyzer.py",
    "packages/codeql/dataflow_validator.py",
    "packages/codeql/build_detector.py",
    # Web fuzzer
    "packages/web/fuzzer.py",
    # Autonomous dialogue
    "packages/autonomous/dialogue.py",
    # Multi-model substrate
    "core/llm/multi_model/prompt_helpers.py",
    # cve-diff agent (uses its own ResilientLLMClient)
    "packages/cve_diff/cve_diff/agent/loop.py",
    "packages/cve_diff/cve_diff/agent/prompt.py",
    "packages/cve_diff/cve_diff/analysis/analyzer.py",
)


# Function names whose bodies are prompt-construction surface — we
# weight their content more heavily. (Heuristic only; the rule fires
# on ANY untrusted attribute interpolation in the audited files,
# regardless of containing function.)
_PROMPT_FUNCTION_HINTS = frozenset({
    "build", "prompt", "system", "user", "envelope", "render",
    "format", "compose",
})


@dataclass(frozen=True)
class Violation:
    file: str               # relative path from repo root
    line: int
    attr: str               # e.g. "message" from finding.message
    expr_text: str          # text of the f-string snippet
    func_name: str          # enclosing function (best-effort)


@dataclass(frozen=True)
class AllowlistEntry:
    """A pre-approved interpolation. Each entry MUST carry an
    ``audit_note`` explaining why this specific call site is safe.

    Key shape: ``(file, func_name, attr, expr_text)`` — content-based,
    deliberately NOT line-based. A line-keyed allowlist breaks every
    time anything earlier in the file gains or loses a line; a
    content-keyed allowlist survives those churn events and only
    re-fires when the actual interpolation site changes (which is
    when re-audit IS the right outcome).

    ``expr_text`` is the literal text of the interpolation as the
    AST round-trips it (``ast.unparse``), e.g. ``"{vuln.rule_id}"``
    or ``"{finding.message}"``. Truncated at 80 chars matching the
    Violation's ``expr_text``.
    """
    file: str
    func_name: str
    attr: str
    expr_text: str
    audit_note: str


# Pre-approved interpolations. Each entry carries an audit note —
# a one-line explanation of why this specific call site is safe
# despite firing the heuristic. New entries require the same
# audit-note discipline so reviewers can sanity-check the rationale.
#
# Maintenance: when a real call site changes (e.g. operator wraps it
# in ``neutralize_tag_forgery``), the entry stops matching. Run
# ``python -m core.security.prompt_envelope_audit --update`` to
# regenerate the literal — operator reviews the diff (which surfaces
# any TODO entries for genuinely-new violations) and commits.
_ALLOWLIST: Tuple[AllowlistEntry, ...] = (
    # ----- packages/codeql/autonomous_analyzer.py -----
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_vulnerability',
        attr='rule_id',
        expr_text='{finding.rule_id}',
        audit_note=(
            'f-string builds the scorecard cell name '
            '(``codeql:<rule_id>``) for the prefilter producer — the '
            'value is consumed by ModelScorecard.record_event, not '
            'interpolated into an LLM prompt'
        ),
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_vulnerability',
        attr='reasoning',
        expr_text='{dataflow_validation.reasoning}',
        audit_note=(
            'f-string output flows into ``UntrustedBlock(content=...)`` '
            'via the dataflow_text variable; ``_content_for_envelope`` '
            'applies neutralize_tag_forgery at envelope render time'
        ),
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='rule_id',
        expr_text='{finding.rule_id}',
        audit_note='filename construction (DataflowVisualizer finding_id), not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='start_line',
        expr_text='{finding.start_line}',
        audit_note='filename construction (DataflowVisualizer finding_id), not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='rule_id',
        expr_text='{finding.rule_id}',
        audit_note=(
            'ID passed to validator.validate_exploit (subprocess '
            'invocation), not LLM'
        ),
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='start_line',
        expr_text='{finding.start_line}',
        audit_note=(
            'ID passed to validator.validate_exploit (subprocess '
            'invocation), not LLM'
        ),
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='rule_id',
        expr_text='{finding.rule_id}',
        audit_note='filename for analysis JSON output (out_dir / ...), not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='start_line',
        expr_text='{finding.start_line}',
        audit_note='filename for analysis JSON output (out_dir / ...), not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='rule_id',
        expr_text='{finding.rule_id}',
        audit_note='filename / artifact identifier, not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/codeql/autonomous_analyzer.py',
        func_name='AutonomousCodeQLAnalyzer.analyze_finding_autonomous',
        attr='start_line',
        expr_text='{finding.start_line}',
        audit_note='filename / artifact identifier, not LLM prompt',
    ),
    # ----- packages/codeql/dataflow_validator.py -----
    AllowlistEntry(
        file='packages/codeql/dataflow_validator.py',
        func_name='DataflowValidator.validate_dataflow_path',
        attr='reasoning',
        expr_text='{smt_result.reasoning}',
        audit_note=(
            'f-string builds DataflowValidation.reasoning return field '
            '(operator-displayed in reports). The source '
            'smt_result.reasoning is RAPTOR-internal SMT output, not '
            'attacker-controlled'
        ),
    ),
    AllowlistEntry(
        file='packages/codeql/dataflow_validator.py',
        func_name='DataflowValidator.validate_dataflow_path',
        attr='rule_id',
        expr_text='{dataflow.rule_id}',
        audit_note='builds scorecard cell name (codeql:<rule_id>), not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/codeql/dataflow_validator.py',
        func_name='DataflowValidator.validate_dataflow_path',
        attr='reasoning',
        expr_text='{smt_result.reasoning}',
        audit_note=(
            'DataflowValidation.reasoning return field; smt_result '
            'source is RAPTOR-internal'
        ),
    ),
    # ----- packages/hypothesis_validation/runner.py -----
    AllowlistEntry(
        file='packages/hypothesis_validation/runner.py',
        func_name='_evaluate',
        attr='summary',
        expr_text='{evidence.summary}',
        audit_note=(
            'exception-path return value (verdict, reasoning) for '
            'operator display; reasoning is not directly fed back into '
            'an LLM prompt by callers'
        ),
    ),
    AllowlistEntry(
        file='packages/hypothesis_validation/runner.py',
        func_name='_evaluate',
        attr='summary',
        expr_text='{evidence.summary}',
        audit_note=(
            'exception-path return value (verdict, reasoning) for '
            'operator display; reasoning is not directly fed back into '
            'an LLM prompt by callers'
        ),
    ),
    # ----- packages/llm_analysis/agent.py -----
    AllowlistEntry(
        file='packages/llm_analysis/agent.py',
        func_name='AutonomousSecurityAgentV2.generate_patch',
        attr='rule_id',
        expr_text='{vuln.rule_id}',
        audit_note=(
            'patch_content_formatted is markdown saved to disk for '
            'operator review (.../patches/<id>_patch.md), not an LLM '
            'prompt'
        ),
    ),
    AllowlistEntry(
        file='packages/llm_analysis/agent.py',
        func_name='AutonomousSecurityAgentV2.generate_patch',
        attr='file_path',
        expr_text='{vuln.file_path}',
        audit_note='markdown for disk (operator review file), not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/llm_analysis/agent.py',
        func_name='AutonomousSecurityAgentV2.generate_patch',
        attr='start_line',
        expr_text='{vuln.start_line}',
        audit_note='markdown for disk, not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/llm_analysis/agent.py',
        func_name='AutonomousSecurityAgentV2.generate_patch',
        attr='end_line',
        expr_text='{vuln.end_line}',
        audit_note='markdown for disk, not LLM prompt',
    ),
    AllowlistEntry(
        file='packages/llm_analysis/agent.py',
        func_name='AutonomousSecurityAgentV2.generate_patch',
        attr='level',
        expr_text='{vuln.level}',
        audit_note='markdown for disk, not LLM prompt',
    ),
)


def audit_file(path: Path) -> List[Violation]:
    """Walk one Python file's AST and return violations: f-string
    formatted-value nodes whose expression is an Attribute with name
    in :data:`_UNTRUSTED_ATTRS`.

    Skips ``FormattedValue`` whose value is wrapped in a known
    sanitiser call: ``neutralize_tag_forgery(x)``, ``_sanitize_for_prompt(x)``,
    ``escape_for_envelope(x)``, ``escape_nonprintable(x)``,
    ``UntrustedBlock(content=x, ...)``.
    """
    if not path.exists():
        return []
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    # Relative-to-repo path for the violation report. Fall back to
    # the absolute path when the file isn't under the repo root —
    # supports test fixtures and ad-hoc invocations outside the tree.
    try:
        rel = str(path.relative_to(_REPO_ROOT))
    except ValueError:
        rel = str(path)
    violations: List[Violation] = []

    # Walk function definitions to track enclosing context for
    # better violation reports.
    def _attr_name(node: ast.AST) -> Optional[str]:
        """Return the attribute name if ``node`` is an Attribute
        access (e.g. ``finding.message`` → ``"message"``). Walks
        through Subscript, NamedExpr (walrus), and a few wrapper
        nodes to surface the meaningful name.

        Walrus is unwrapped so ``f"{(x := finding.message)}"``
        registers as an interpolation of ``message`` — pre-walrus,
        the audit returned None for the NamedExpr and missed the
        attribute access entirely.
        """
        cur = node
        while True:
            if isinstance(cur, ast.Attribute):
                return cur.attr
            if isinstance(cur, ast.Subscript):
                cur = cur.value
                continue
            if isinstance(cur, ast.NamedExpr):
                # Walrus: ``(x := expr)``. The interpolated value IS
                # ``expr`` (the assignment leaves it as the expression's
                # result), so unwrap and look at the assigned value.
                cur = cur.value
                continue
            return None

    def _is_sanitised(node: ast.AST) -> bool:
        """Return True if this expression is wrapped in a call that's
        known to neutralise injection (tag-forgery defang or
        envelope wrap)."""
        if not isinstance(node, ast.Call):
            return False
        # Function name resolution.
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            return False
        return name in {
            "neutralize_tag_forgery",
            "_sanitize_for_prompt",
            "_escape_for_envelope",
            "escape_for_envelope",
            "escape_nonprintable",
            "_xml_attr_escape",
            "TaintedString",
            "UntrustedBlock",
            "wrap_tool_result",
        }

    # Functions whose f-string args are logged/displayed, not sent to
    # the LLM. Walking the parent stack to detect "is the enclosing
    # call to one of these?" lets us skip the dominant false-positive
    # class (logger.info(f"finding {rule_id}...") etc.) without
    # hand-allowlisting every such line.
    _NON_LLM_CALLS = frozenset({
        # logging
        "debug", "info", "warning", "error", "critical", "exception",
        "log", "_log",
        # display / output
        "print", "print_warning", "print_error", "print_status",
        "echo", "fprintf",
        # raises (error messages, not LLM prompts)
        "format_exception", "format_exc",
        # progress
        "set_description", "write",
    })

    # Constructors that carry the untrusted-content envelope contract.
    # An f-string passed as a kwarg to one of these is being captured
    # as labelled metadata (UntrustedBlock origin/kind, TaintedString
    # value) and gets routed through ``_xml_attr_escape`` /
    # ``_content_for_envelope`` at render time. Safe by construction.
    _ENVELOPE_CONSTRUCTORS = frozenset({
        "UntrustedBlock", "TaintedString",
        "MessagePart",  # content is a kwarg of MessagePart too
        "wrap_tool_result",
    })

    def _is_in_non_llm_call(parent_stack: List[ast.AST]) -> bool:
        for parent in reversed(parent_stack):
            if isinstance(parent, ast.Call):
                func = parent.func
                if isinstance(func, ast.Name) and func.id in _NON_LLM_CALLS:
                    return True
                if isinstance(func, ast.Attribute) and func.attr in _NON_LLM_CALLS:
                    return True
                # First enclosing Call settles it — don't keep walking.
                return False
        return False

    def _is_in_envelope_constructor(parent_stack: List[ast.AST]) -> bool:
        """Return True if the f-string is an argument to one of the
        envelope-aware constructors. Those constructors take the
        responsibility of escape/sanitisation themselves at render
        time, so the raw f-string is not a violation."""
        for parent in reversed(parent_stack):
            if isinstance(parent, ast.Call):
                func = parent.func
                if isinstance(func, ast.Name) and func.id in _ENVELOPE_CONSTRUCTORS:
                    return True
                if isinstance(func, ast.Attribute) and func.attr in _ENVELOPE_CONSTRUCTORS:
                    return True
                return False
        return False

    class _Walker(ast.NodeVisitor):
        def __init__(self) -> None:
            # Track both class and function frames so func_name on the
            # emitted Violation is qualified by enclosing class(es).
            # Without the class qualifier, two methods named
            # ``build_prompt`` in different classes within the same
            # audited file would emit identical func_name and the
            # content-keyed allowlist would collapse them — masking a
            # legitimate per-class audit decision. Frames are
            # ``(kind, name)`` so the ``_qualified_func_name`` builder
            # can reconstruct dotted paths like
            # ``AnalysisTask.build_prompt``.
            self._fn_stack: List[Tuple[str, str]] = []  # (kind, name)
            self._parent_stack: List[ast.AST] = []

        def _enter(self, kind: str, name: str) -> None:
            self._fn_stack.append((kind, name))

        def _leave(self) -> None:
            if self._fn_stack:
                self._fn_stack.pop()

        def generic_visit(self, node: ast.AST) -> None:
            self._parent_stack.append(node)
            try:
                super().generic_visit(node)
            finally:
                self._parent_stack.pop()

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._enter("class", node.name)
            self.generic_visit(node)
            self._leave()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._enter("function", node.name)
            self.generic_visit(node)
            self._leave()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._enter("function", node.name)
            self.generic_visit(node)
            self._leave()

        def visit_Lambda(self, node: ast.Lambda) -> None:
            # ``ast.Lambda`` is a separate node type from FunctionDef, so
            # the existing FunctionDef visitor doesn't push a frame for
            # lambdas. Without a frame, an interpolation inside a lambda
            # bound to a class attribute would emit func_name as the
            # enclosing class — making per-lambda audit decisions
            # collide. Push ``<lambda>`` so the dotted path becomes e.g.
            # ``A.<lambda>`` and per-lambda allowlist entries stay
            # distinct from per-method ones.
            self._enter("function", "<lambda>")
            self.generic_visit(node)
            self._leave()

        def _qualified_func_name(self) -> str:
            """Build a dotted path from the active class+function stack.
            Module-level interpolations get ``<module>``; standalone
            functions emit just the function name; methods emit
            ``ClassName.method`` (or ``Outer.Inner.method`` for nested).
            """
            if not self._fn_stack:
                return "<module>"
            return ".".join(name for _kind, name in self._fn_stack)

        def _emit(self, node: ast.AST, attr: str) -> None:
            try:
                src = ast.unparse(node)
            except (AttributeError, ValueError):
                src = f"<{attr}>"
            violations.append(Violation(
                file=rel,
                line=node.lineno,
                attr=attr,
                expr_text=src[:80],
                func_name=self._qualified_func_name(),
            ))

        def visit_FormattedValue(self, node: ast.FormattedValue) -> None:
            attr = _attr_name(node.value)
            if (attr in _UNTRUSTED_ATTRS
                    and not _is_sanitised(node.value)
                    and not _is_in_non_llm_call(self._parent_stack)
                    and not _is_in_envelope_constructor(self._parent_stack)):
                self._emit(node, attr)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            """Catch two patterns the f-string check misses:

              1. ``prompt_parts.append(x.attr)`` — list-append on a
                 prompt-builder receiver. The append'd value gets
                 joined into a prompt downstream; bypassing the
                 envelope here lets the attribute land in the prompt
                 raw.

              2. ``template.format(claim=x.attr)`` — ``.format()``
                 calls with kwargs whose values are untrusted
                 attributes.
            """
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr
                receiver_name = (
                    node.func.value.id
                    if isinstance(node.func.value, ast.Name)
                    else ""
                )
                # Pattern 1: append-on-prompt-builder receiver.
                if method == "append" and node.args:
                    if any(
                        token in receiver_name.lower()
                        for token in (
                            "prompt", "message", "context", "block",
                            "part", "section", "instruction",
                        )
                    ):
                        for arg in node.args:
                            attr = _attr_name(arg)
                            if (attr in _UNTRUSTED_ATTRS
                                    and not _is_sanitised(arg)):
                                self._emit(arg, attr)
                # Pattern 2: ``.format(...)`` with kwargs.
                elif method == "format":
                    for kw in node.keywords:
                        if kw.value is None:
                            continue
                        attr = _attr_name(kw.value)
                        if (attr in _UNTRUSTED_ATTRS
                                and not _is_sanitised(kw.value)):
                            self._emit(kw.value, attr)
            self.generic_visit(node)

        def visit_BinOp(self, node: ast.BinOp) -> None:
            """Catch old-style %-formatting:

              * ``"prefix %s" % finding.attr``     — single value
              * ``"%s %s" % (a.attr, b.attr)``     — tuple of values
              * ``"%(k)s" % {"k": finding.attr}``  — dict of values

            Same threat as `.format()` and f-strings: untrusted-attr
            text lands in a string that downstream code may feed to an
            LLM. Plain `+` concatenation is NOT caught here — that has
            a high FP rate without dataflow and is documented as a
            known limitation. %-formatting is narrow enough (must be a
            string-literal left side) that we can flag it cleanly.
            """
            if not isinstance(node.op, ast.Mod):
                self.generic_visit(node)
                return
            # Only fire when the left side is a string literal — the
            # `%` operator is also numeric modulo, and a numeric
            # ``x % y`` shouldn't be flagged.
            left = node.left
            is_string = (
                (isinstance(left, ast.Constant) and isinstance(left.value, str))
                or isinstance(left, ast.JoinedStr)  # f-string with %
            )
            if not is_string:
                self.generic_visit(node)
                return
            # Right side: extract candidate value nodes.
            right = node.right
            candidates: List[ast.AST] = []
            if isinstance(right, ast.Tuple):
                candidates.extend(right.elts)
            elif isinstance(right, ast.Dict):
                candidates.extend(v for v in right.values if v is not None)
            else:
                candidates.append(right)
            for cand in candidates:
                attr = _attr_name(cand)
                if (attr in _UNTRUSTED_ATTRS
                        and not _is_sanitised(cand)
                        and not _is_in_non_llm_call(self._parent_stack)
                        and not _is_in_envelope_constructor(self._parent_stack)):
                    self._emit(cand, attr)
            self.generic_visit(node)

    _Walker().visit(tree)
    return violations


def audit_repo(
    files: Iterable[str] = _PROMPT_CONSTRUCTION_FILES,
) -> List[Violation]:
    """Audit every file in ``files`` (relative to repo root). Returns
    a flat list of violations across all files."""
    out: List[Violation] = []
    for rel in files:
        out.extend(audit_file(_REPO_ROOT / rel))
    return out


def filter_allowlisted(
    violations: Iterable[Violation],
    allowlist: Tuple[AllowlistEntry, ...] = _ALLOWLIST,
) -> List[Violation]:
    """Drop violations that match an allowlist entry. Match key:
    ``(file, func_name, attr, expr_text)`` quadruple — content-based,
    not line-based, so unrelated edits don't trigger re-audit."""
    keys = {(e.file, e.func_name, e.attr, e.expr_text) for e in allowlist}
    return [
        v for v in violations
        if (v.file, v.func_name, v.attr, v.expr_text) not in keys
    ]


def render_violations(violations: Iterable[Violation]) -> str:
    """Pretty-print a violations list for the test failure message."""
    by_file: dict[str, List[Violation]] = {}
    for v in violations:
        by_file.setdefault(v.file, []).append(v)
    lines: List[str] = []
    for file in sorted(by_file):
        lines.append(f"\n  {file}:")
        for v in sorted(by_file[file], key=lambda v: v.line):
            lines.append(
                f"    L{v.line:<5} attr={v.attr!r:<20} "
                f"in {v.func_name}(): {v.expr_text}"
            )
    return "\n".join(lines)


def render_allowlist(
    violations: Iterable[Violation],
    allowlist: Tuple[AllowlistEntry, ...] = _ALLOWLIST,
) -> str:
    """Re-emit the ``_ALLOWLIST`` literal as a Python source fragment.

    Strategy: **purely additive**. Existing entries are carried
    over verbatim (preserving each entry's specific audit_note even
    when several entries share the same content key — multiple call
    sites in one function with the same f-string can have legitimately
    different rationales). Violations that don't match ANY existing
    entry by content key are appended as new entries with a
    ``TODO: audit_note required`` placeholder; the audit then rejects
    these until the operator fills in a real note.

    Stale entries (allowlist entries whose content key no longer
    appears in the audit) are dropped — that's the actual cleanup
    benefit of running ``--update`` after a deliberate refactor.

    Used by the ``--update`` CLI mode below.
    """
    import textwrap as _tw
    # Set of keys present in the current code.
    live_keys = {(v.file, v.func_name, v.attr, v.expr_text) for v in violations}
    # Set of keys already covered by an allowlist entry.
    covered_keys = {(e.file, e.func_name, e.attr, e.expr_text) for e in allowlist}

    def _emit_entry(file: str, func_name: str, attr: str,
                    expr_text: str, note: str, lines: List[str]) -> None:
        lines.append("    AllowlistEntry(")
        lines.append(f"        file={file!r},")
        lines.append(f"        func_name={func_name!r},")
        lines.append(f"        attr={attr!r},")
        lines.append(f"        expr_text={expr_text!r},")
        if len(note) < 70:
            lines.append(f"        audit_note={note!r},")
        else:
            wrapped = _tw.wrap(note, width=58)
            lines.append("        audit_note=(")
            for i, line in enumerate(wrapped):
                suffix = "" if i == len(wrapped) - 1 else " "
                lines.append(f"            {(line + suffix)!r}")
            lines.append("        ),")
        lines.append("    ),")

    # Bucket existing entries by file (preserves authoring order).
    existing_by_file: dict[str, List[AllowlistEntry]] = {}
    for e in allowlist:
        # Drop entries whose call site no longer exists in current
        # code — that's the cleanup half of `--update`.
        if (e.file, e.func_name, e.attr, e.expr_text) not in live_keys:
            continue
        existing_by_file.setdefault(e.file, []).append(e)

    # Bucket genuinely-new violations by file (deduped by content key).
    new_by_file: dict[str, List[Violation]] = {}
    seen_new: set = set()
    for v in violations:
        key = (v.file, v.func_name, v.attr, v.expr_text)
        if key in covered_keys or key in seen_new:
            continue
        seen_new.add(key)
        new_by_file.setdefault(v.file, []).append(v)

    out: List[str] = ["_ALLOWLIST: Tuple[AllowlistEntry, ...] = ("]
    files = sorted(set(existing_by_file) | set(new_by_file))
    for file in files:
        out.append(f"    # ----- {file} -----")
        for e in existing_by_file.get(file, []):
            _emit_entry(e.file, e.func_name, e.attr, e.expr_text,
                        e.audit_note, out)
        for v in new_by_file.get(file, []):
            _emit_entry(v.file, v.func_name, v.attr, v.expr_text,
                        "TODO: audit_note required — explain why this site is safe",
                        out)
    out.append(")")
    return "\n".join(out)


def _update_allowlist_in_source(source_path: Path) -> int:
    """In-place rewrite of the ``_ALLOWLIST`` literal in
    ``source_path``, preserving everything before/after it. Returns
    the number of violations the new allowlist covers.

    The rewrite locates the ``_ALLOWLIST: Tuple`` line and the
    matching closing ``)`` at column 0, replacing the slice between
    them. That's sufficient because the literal is always formatted
    with the closing paren on its own column-0 line.

    Atomic write: produces the new content in a sibling tempfile and
    then ``os.replace`` swaps it into place. Without this an
    interrupted ``--update`` (Ctrl-C, OOM kill, sandbox preempt) could
    leave the audit module half-written on disk and break every
    subsequent import — including the audit's own test, blocking
    recovery via the same CLI.
    """
    import os
    import tempfile
    text = source_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith("_ALLOWLIST: Tuple"):
            start = i
            break
    if start is None:
        raise RuntimeError("could not locate `_ALLOWLIST: Tuple` in source")
    end = None
    for j in range(start + 1, len(lines)):
        if lines[j] == ")":
            end = j
            break
    if end is None:
        raise RuntimeError("could not locate closing `)` of _ALLOWLIST")

    violations = audit_repo()
    new_block = render_allowlist(violations).splitlines()
    out_lines = lines[:start] + new_block + lines[end + 1 :]
    new_text = "\n".join(out_lines) + "\n"

    # Atomic write: write to a sibling tempfile, then os.replace.
    # NamedTemporaryFile with delete=False so we can keep the path
    # alive past the ``with`` block; cleanup-on-error handled below.
    fd, tmp_path = tempfile.mkstemp(
        prefix=source_path.name + ".",
        suffix=".tmp",
        dir=source_path.parent,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        os.replace(tmp_path, source_path)
    except Exception:
        # If anything went wrong before the replace, drop the partial
        # tempfile so it doesn't litter the source tree.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return len(violations)


def _main(argv: Optional[List[str]] = None) -> int:
    """``python -m core.security.prompt_envelope_audit [--update]``

    Without ``--update``: prints the current violation set + which
    entries the allowlist already covers vs which are unmatched.
    Useful for a quick "what would CI see right now?" check.

    With ``--update``: regenerates the ``_ALLOWLIST`` literal in this
    module's own source. Operator reviews the diff (any new violations
    appear with a ``TODO: audit_note`` placeholder that the audit
    rejects until filled in) and commits.
    """
    import argparse
    parser = argparse.ArgumentParser(
        prog="prompt_envelope_audit",
        description="Run / regenerate the prompt-envelope audit allowlist.",
    )
    parser.add_argument(
        "--update", action="store_true",
        help="Regenerate the _ALLOWLIST literal in-place from current "
             "code (carries existing audit_notes forward, marks new "
             "entries with a TODO).",
    )
    args = parser.parse_args(argv)

    if args.update:
        n = _update_allowlist_in_source(Path(__file__))
        print(f"Updated _ALLOWLIST: {n} entries written.")
        return 0
    violations = audit_repo()
    remaining = filter_allowlisted(violations)
    print(f"Audited {len(_PROMPT_CONSTRUCTION_FILES)} files; "
          f"found {len(violations)} interpolations, "
          f"{len(violations) - len(remaining)} allowlisted, "
          f"{len(remaining)} unmatched.")
    if remaining:
        print(render_violations(remaining))
        return 1
    return 0


__all__ = [
    "Violation",
    "AllowlistEntry",
    "audit_file",
    "audit_repo",
    "filter_allowlisted",
    "render_allowlist",
    "render_violations",
]


if __name__ == "__main__":
    import sys
    sys.exit(_main())
