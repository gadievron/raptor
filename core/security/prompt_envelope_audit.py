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
``(file, line, attr)`` triples — each entry must include an
``audit_note`` string explaining why the interpolation is safe (trusted
source, surrounding envelope, etc.). Without the note the rule rejects
the entry; this prevents silent grandfathering.

Threat model: an attacker who can publish a package, file a hostile
GitHub issue, supply CVE metadata, or commit attacker text in a
target repo gets text into RAPTOR's prompt context. Tag-forgery
defenses (envelope close-tag escape, datamarking) are layered atop
the operator's prompt; bypassing the defenses lets the attacker forge
envelope structure or inject role-confusion content.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
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
    ``audit_note`` explaining why this specific call site is safe."""
    file: str
    line: int
    attr: str
    audit_note: str


# Pre-approved interpolations. Each entry carries an audit note —
# a one-line explanation of why this specific call site is safe
# despite firing the heuristic. New entries require the same
# audit-note discipline so reviewers can sanity-check the rationale.
_ALLOWLIST: Tuple[AllowlistEntry, ...] = (
    # ----- packages/codeql/autonomous_analyzer.py -----
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=607,
        attr="rule_id",
        audit_note=(
            "f-string builds the scorecard cell name "
            "(``codeql:<rule_id>``) for the prefilter producer — "
            "the value is consumed by ModelScorecard.record_event, "
            "not interpolated into an LLM prompt"
        ),
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=672,
        attr="reasoning",
        audit_note=(
            "f-string output flows into ``UntrustedBlock(content=...)`` "
            "via the dataflow_text variable; ``_content_for_envelope`` "
            "applies neutralize_tag_forgery at envelope render time"
        ),
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=964,
        attr="rule_id",
        audit_note="filename construction (DataflowVisualizer finding_id), not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=964,
        attr="start_line",
        audit_note="filename construction (DataflowVisualizer finding_id), not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=1048,
        attr="rule_id",
        audit_note="ID passed to validator.validate_exploit (subprocess invocation), not LLM",
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=1048,
        attr="start_line",
        audit_note="ID passed to validator.validate_exploit (subprocess invocation), not LLM",
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=1066,
        attr="rule_id",
        audit_note="filename for analysis JSON output (out_dir / ...), not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=1066,
        attr="start_line",
        audit_note="filename for analysis JSON output (out_dir / ...), not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=1103,
        attr="rule_id",
        audit_note="filename / artifact identifier, not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/codeql/autonomous_analyzer.py", line=1103,
        attr="start_line",
        audit_note="filename / artifact identifier, not LLM prompt",
    ),
    # ----- packages/codeql/dataflow_validator.py -----
    AllowlistEntry(
        file="packages/codeql/dataflow_validator.py", line=575,
        attr="reasoning",
        audit_note=(
            "f-string builds DataflowValidation.reasoning return "
            "field (operator-displayed in reports). The source "
            "smt_result.reasoning is RAPTOR-internal SMT output, "
            "not attacker-controlled"
        ),
    ),
    AllowlistEntry(
        file="packages/codeql/dataflow_validator.py", line=593,
        attr="rule_id",
        audit_note="builds scorecard cell name (codeql:<rule_id>), not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/codeql/dataflow_validator.py", line=619,
        attr="reasoning",
        audit_note=(
            "DataflowValidation.reasoning return field; smt_result "
            "source is RAPTOR-internal"
        ),
    ),
    # ----- packages/hypothesis_validation/runner.py -----
    AllowlistEntry(
        file="packages/hypothesis_validation/runner.py", line=385,
        attr="summary",
        audit_note=(
            "exception-path return value (verdict, reasoning) for "
            "operator display; reasoning is not directly fed back "
            "into an LLM prompt by callers"
        ),
    ),
    AllowlistEntry(
        file="packages/hypothesis_validation/runner.py", line=402,
        attr="summary",
        audit_note=(
            "exception-path return value (verdict, reasoning) for "
            "operator display; reasoning is not directly fed back "
            "into an LLM prompt by callers"
        ),
    ),
    # ----- packages/llm_analysis/agent.py -----
    AllowlistEntry(
        file="packages/llm_analysis/agent.py", line=967,
        attr="rule_id",
        audit_note=(
            "patch_content_formatted is markdown saved to disk for "
            "operator review (.../patches/<id>_patch.md), not an "
            "LLM prompt"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/agent.py", line=969,
        attr="file_path",
        audit_note="markdown for disk (operator review file), not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/llm_analysis/agent.py", line=970,
        attr="start_line",
        audit_note="markdown for disk, not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/llm_analysis/agent.py", line=970,
        attr="end_line",
        audit_note="markdown for disk, not LLM prompt",
    ),
    AllowlistEntry(
        file="packages/llm_analysis/agent.py", line=971,
        attr="level",
        audit_note="markdown for disk, not LLM prompt",
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
        through Subscript and Call to surface the meaningful name."""
        cur = node
        while True:
            if isinstance(cur, ast.Attribute):
                return cur.attr
            if isinstance(cur, ast.Subscript):
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
            self._fn_stack: List[str] = []
            self._parent_stack: List[ast.AST] = []

        def _enter_fn(self, name: str) -> None:
            self._fn_stack.append(name)

        def _leave_fn(self) -> None:
            if self._fn_stack:
                self._fn_stack.pop()

        def generic_visit(self, node: ast.AST) -> None:
            self._parent_stack.append(node)
            try:
                super().generic_visit(node)
            finally:
                self._parent_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._enter_fn(node.name)
            self.generic_visit(node)
            self._leave_fn()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._enter_fn(node.name)
            self.generic_visit(node)
            self._leave_fn()

        def _emit(self, node: ast.AST, attr: str) -> None:
            try:
                src = ast.unparse(node)
            except (AttributeError, ValueError):
                src = f"<{attr}>"
            fn_name = self._fn_stack[-1] if self._fn_stack else "<module>"
            violations.append(Violation(
                file=rel,
                line=node.lineno,
                attr=attr,
                expr_text=src[:80],
                func_name=fn_name,
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
    ``(file, line, attr)`` triple. Pre-approved entries with an
    ``audit_note`` describing why they're safe."""
    keys = {(e.file, e.line, e.attr) for e in allowlist}
    return [v for v in violations if (v.file, v.line, v.attr) not in keys]


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


__all__ = [
    "Violation",
    "AllowlistEntry",
    "audit_file",
    "audit_repo",
    "filter_allowlisted",
    "render_violations",
]
