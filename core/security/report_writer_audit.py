"""AST-based lint rule for report-writer output sanitisation.

Companion to :mod:`core.security.prompt_envelope_audit` (input side).
Where the envelope audit stops attacker text from reaching LLM prompts
raw, this audit stops LLM-returned text from reaching rendered report /
terminal surfaces raw. The canonical defence is
:mod:`core.security.prompt_output_sanitise` (``sanitise_string`` /
``sanitise_code``) plus the per-module single-line helpers built on it
(``_line`` / ``_cell`` / ``_prose`` / ``_md_heading`` /
``_md_escape_inline`` / ``_md_table_cell`` / ``_fence``).

Mechanism — deliberately explicit and low-maintenance:

* **Registry of audited writers** (:data:`_REPORT_WRITER_FILES`): only
  files registered here are walked. A new report writer must be added
  explicitly, which forces a security review at file-add time — the
  same opt-in discipline as ``_PROMPT_CONSTRUCTION_FILES`` in the
  envelope audit.
* **Known-LLM-derived value detection** (:data:`_LLM_DERIVED_KEYS`):
  the rule looks for reads of free-text fields that carry LLM output
  (``title``, ``claim``, ``body``, ``reasoning``, ...) via attribute
  access (``entry.body``), string-key subscript (``f["title"]``),
  ``.get("title")`` calls, and ``getattr(x, "body")``.
* **Write-sink detection**: a violation fires only when such a value
  reaches a write sink — ``print(...)``, ``.write(...)`` /
  ``.write_text(...)``, ``.append(...)`` / ``.extend(...)`` on a
  report-line accumulator (receiver name containing ``lines`` /
  ``rows`` / ``sections`` / ``parts``), or a ``ReportSection(...)``
  constructor — without passing through a recognised sanitiser call
  (:data:`_SANITISERS`).
* **One-level local taint**: ``x = f.get("title")`` marks ``x`` tainted
  within the enclosing function (also through ``for x in <tainted>``),
  so the common assign-then-emit pattern is caught. Cross-function
  dataflow is out of scope (documented limitation, same as the envelope
  audit).
* **Mermaid fence rule** (:data:`_MERMAID_FENCE_FILES`): in the diagram
  renderer, any f-string interpolation *inside* a ```` ```mermaid ````
  fence must be a sanitiser call (``_fence`` / ``sanitise_code``) so a
  generated diagram string cannot terminate the fence and spill live
  markdown.

Extending:

* New report writer → append its repo-relative path to
  :data:`_REPORT_WRITER_FILES` and route every LLM-derived value
  through ``core.security.prompt_output_sanitise`` (free text) or a
  single-line helper (headings / labels / table cells).
* New LLM-derived field name → add to :data:`_LLM_DERIVED_KEYS`.
* New sanitising helper → add its (function) name to
  :data:`_SANITISERS`; the helper must itself call
  ``sanitise_string`` / ``sanitise_code``.
* Genuinely-safe call site that fires anyway → add an
  :class:`AllowlistEntry` with a one-line ``audit_note`` explaining why
  (same discipline as the envelope audit; the test rejects empty / TODO
  notes).
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Repository root (this file lives at core/security/report_writer_audit.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]


# Free-text field names whose values carry LLM output (journal entries,
# findings, hypotheses, annotations, stage reviews). Reads of these via
# attribute / subscript / .get() / getattr() are treated as LLM-derived.
# Deliberately excludes ubiquitous label fields (``file``, ``function``,
# ``status``, ``severity``) — those are sanitised in the fixed writers
# too, but auditing them mechanically would drown the rule in noise from
# non-report code paths. The free-text fields are where markup/autofetch
# injection lives.
_LLM_DERIVED_KEYS = frozenset({
    "title",
    "claim",
    "body",
    "reasoning",
    "summary",
    "description",
    "remediation",
    "attack_scenario",
    "prediction",
    "rationale",
    "hypothesis",
    "stage_f_review",
    "stage_f_summary",
    "error",
})


# Calls recognised as neutralising a value for report / terminal
# rendering. A subtree rooted at one of these calls is considered
# sanitised. ``escape_nonprintable`` is intentionally NOT in this set:
# it kills ANSI/control bytes but does not strip autofetch markup or
# defang markdown — the report layer requires the full
# prompt_output_sanitise pipeline.
_SANITISERS = frozenset({
    "sanitise_string",
    "sanitise_code",
    # Per-module single-line / cell / prose helpers built on the above.
    "_line",
    "_cell",
    "_prose",
    "_fence",
    "_err",
    "_md_heading",
    "_md_escape_inline",
    "_md_table_cell",
    "_render_detail",
})


# Write sinks.
_SINK_FUNCTIONS = frozenset({"print"})
_SINK_METHODS = frozenset({"write", "write_text"})
_ACCUMULATE_METHODS = frozenset({"append", "extend"})
_ACCUMULATOR_TOKENS = ("lines", "rows", "sections", "parts")
_REPORT_CONSTRUCTORS = frozenset({"ReportSection"})


# Files whose job is writing operator-facing report / terminal output
# from LLM-derived data. The audit only walks these — a new report
# writer needs an explicit add (forcing a security review at file-add
# time).
_REPORT_WRITER_FILES = (
    "core/audit/report.py",
    "core/project/report.py",
    "core/reporting/findings.py",
    "packages/exploitability_validation/report.py",
    "packages/llm_analysis/patch_gate.py",
    "libexec/raptor-review",
    "libexec/raptor-annotate",
)


# Files that embed generated Mermaid diagram strings inside markdown
# fences. Interpolations inside a ```mermaid fence must be sanitiser
# calls (``_fence`` / ``sanitise_code``).
_MERMAID_FENCE_FILES = (
    "packages/diagram/renderer.py",
)


@dataclass(frozen=True)
class Violation:
    file: str        # relative path from repo root
    line: int
    kind: str        # "unsanitised_llm_value" | "unsanitised_mermaid_embed"
    detail: str      # key name or expression text
    func_name: str   # enclosing function (best-effort, dotted)


@dataclass(frozen=True)
class AllowlistEntry:
    """A pre-approved sink interpolation. Each entry MUST carry an
    ``audit_note`` explaining why this specific call site is safe.
    Content-keyed (file, func_name, kind, detail) — survives unrelated
    line churn, re-fires when the call site itself changes.
    """
    file: str
    func_name: str
    kind: str
    detail: str
    audit_note: str


# Pre-approved sink interpolations. Each entry carries an audit_note —
# a one-line explanation of why the call site is safe despite firing
# the heuristic. New entries require the same discipline (enforced by
# the test suite: empty / TODO notes are rejected).
_ALLOWLIST: tuple[AllowlistEntry, ...] = (
    AllowlistEntry(
        file="core/reporting/findings.py",
        func_name="findings_summary_line",
        kind="unsanitised_llm_value",
        detail="error",
        audit_note=(
            "counts['error'] is an integer statistics counter (number of "
            "error-status findings), not LLM text — the summary line "
            "interpolates the count, never a message"
        ),
    ),
)


def _call_name(node: ast.AST) -> str | None:
    """Return the called function's short name for a Call node."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    return None


def _key_expr(node: ast.AST) -> str | None:
    """Return the LLM-derived key name if ``node`` reads one.

    Recognises ``x.title``, ``x["title"]``, ``x.get("title", ...)``,
    and ``getattr(x, "title", ...)``.
    """
    if isinstance(node, ast.Attribute) and node.attr in _LLM_DERIVED_KEYS:
        return node.attr
    if isinstance(node, ast.Subscript):
        sl = node.slice
        if (isinstance(sl, ast.Constant) and isinstance(sl.value, str)
                and sl.value in _LLM_DERIVED_KEYS):
            return sl.value
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "get" and node.args:
            a0 = node.args[0]
            if (isinstance(a0, ast.Constant) and isinstance(a0.value, str)
                    and a0.value in _LLM_DERIVED_KEYS):
                return a0.value
        if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                and len(node.args) >= 2):
            a1 = node.args[1]
            if (isinstance(a1, ast.Constant) and isinstance(a1.value, str)
                    and a1.value in _LLM_DERIVED_KEYS):
                return a1.value
    return None


def _naked_keys(
    node: ast.AST,
    tainted: frozenset,
) -> list[tuple[int, str]]:
    """Return (line, key) pairs for LLM-derived reads in ``node`` that
    are NOT inside a recognised sanitiser call. ``tainted`` names count
    as LLM-derived reads too (one-level local taint)."""
    out: list[tuple[int, str]] = []

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.Call) and _call_name(n) in _SANITISERS:
            return  # sanitised subtree — everything below is defanged
        key = _key_expr(n)
        if key is not None:
            out.append((getattr(n, "lineno", 0), key))
        if isinstance(n, ast.Name) and n.id in tainted:
            out.append((getattr(n, "lineno", 0), n.id))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            # A method reference (`severity.title()`, `text.strip()`) is
            # not a field read — skip the func Attribute itself but keep
            # walking the receiver and the arguments.
            walk(n.func.value)
            for child in list(n.args) + [kw.value for kw in n.keywords
                                         if kw.value is not None]:
                walk(child)
            return
        for child in ast.iter_child_nodes(n):
            walk(child)

    walk(node)
    return out


def _target_names(target: ast.AST) -> list[str]:
    """Flatten assignment / loop targets into plain names."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


class _Scanner(ast.NodeVisitor):
    """Walk one module, tracking function frames and one-level taint."""

    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.violations: list[Violation] = []
        self._fn_stack: list[str] = []
        self._tainted_stack: list[set] = [set()]

    # -- frames -------------------------------------------------------

    @property
    def _tainted(self) -> set:
        return self._tainted_stack[-1]

    def _qualified_func_name(self) -> str:
        return ".".join(self._fn_stack) if self._fn_stack else "<module>"

    def _enter_frame(self, name: str) -> None:
        self._fn_stack.append(name)
        # Nested scopes inherit the enclosing taint view (closures read
        # outer locals); a copy keeps inner additions from leaking out.
        self._tainted_stack.append(set(self._tainted))

    def _leave_frame(self) -> None:
        self._fn_stack.pop()
        self._tainted_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_frame(node.name)
        self.generic_visit(node)
        self._leave_frame()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_frame(node.name)
        self.generic_visit(node)
        self._leave_frame()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._fn_stack.append(node.name)
        self.generic_visit(node)
        self._fn_stack.pop()

    # -- taint --------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        if _naked_keys(node.value, frozenset(self._tainted)):
            for target in node.targets:
                for name in _target_names(target):
                    self._tainted.add(name)
        else:
            # A sanitised (or unrelated) re-assignment clears the taint —
            # `body = _prose(body)` makes later uses of `body` safe.
            for target in node.targets:
                for name in _target_names(target):
                    self._tainted.discard(name)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if _naked_keys(node.iter, frozenset(self._tainted)):
            for name in _target_names(node.target):
                self._tainted.add(name)
        self.generic_visit(node)

    # -- sinks --------------------------------------------------------

    def _sink_args(self, node: ast.Call) -> list[ast.AST] | None:
        """Return the argument expressions if ``node`` is a write sink."""
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in _SINK_FUNCTIONS or func.id in _REPORT_CONSTRUCTORS:
                return list(node.args) + [kw.value for kw in node.keywords
                                          if kw.value is not None]
            return None
        if isinstance(func, ast.Attribute):
            if func.attr in _REPORT_CONSTRUCTORS:
                return list(node.args) + [kw.value for kw in node.keywords
                                          if kw.value is not None]
            if func.attr in _SINK_METHODS:
                return list(node.args)
            if func.attr in _ACCUMULATE_METHODS:
                receiver = func.value
                receiver_name = receiver.id if isinstance(receiver, ast.Name) else ""
                if any(tok in receiver_name.lower() for tok in _ACCUMULATOR_TOKENS):
                    return list(node.args)
            return None
        return None

    def visit_Call(self, node: ast.Call) -> None:
        args = self._sink_args(node)
        if args is not None:
            tainted = frozenset(self._tainted)
            for arg in args:
                for line, key in _naked_keys(arg, tainted):
                    self.violations.append(Violation(
                        file=self.rel,
                        line=line or node.lineno,
                        kind="unsanitised_llm_value",
                        detail=key,
                        func_name=self._qualified_func_name(),
                    ))
        self.generic_visit(node)


def _mermaid_scan(tree: ast.AST, rel: str) -> list[Violation]:
    """Flag f-string interpolations inside ```mermaid fences that are
    not sanitiser calls."""
    out: list[Violation] = []
    # Track enclosing function names for the report.
    parents: dict = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def _func_of(node: ast.AST) -> str:
        names: list[str] = []
        cur = parents.get(node)
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(cur.name)
            cur = parents.get(cur)
        return ".".join(reversed(names)) or "<module>"

    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        in_fence = False
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                text = part.value
                if in_fence and "```" in text:
                    in_fence = False
                if "```mermaid" in text:
                    in_fence = True
            elif isinstance(part, ast.FormattedValue) and in_fence:
                if _call_name(part.value) not in _SANITISERS:
                    try:
                        src = ast.unparse(part.value)
                    except (AttributeError, ValueError):
                        src = "<expr>"
                    out.append(Violation(
                        file=rel,
                        line=part.lineno,
                        kind="unsanitised_mermaid_embed",
                        detail=src[:80],
                        func_name=_func_of(node),
                    ))
    return out


def audit_source(source: str, rel: str = "<snippet>") -> list[Violation]:
    """Audit a source string. Used by the self-tests and by
    :func:`audit_file`."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    scanner = _Scanner(rel)
    scanner.visit(tree)
    violations = scanner.violations
    violations.extend(_mermaid_scan(tree, rel))
    return violations


def audit_file(path: Path) -> list[Violation]:
    """Audit one file on disk (Python source; libexec scripts parse the
    same way despite having no ``.py`` suffix)."""
    if not path.exists():
        return []
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        rel = str(path.relative_to(_REPO_ROOT))
    except ValueError:
        rel = str(path)
    return audit_source(source, rel)


def audit_repo(
    files: Iterable[str] = _REPORT_WRITER_FILES + _MERMAID_FENCE_FILES,
) -> list[Violation]:
    """Audit every registered writer (relative to repo root)."""
    out: list[Violation] = []
    for rel in files:
        out.extend(audit_file(_REPO_ROOT / rel))
    return out


def filter_allowlisted(
    violations: Iterable[Violation],
    allowlist: tuple[AllowlistEntry, ...] = _ALLOWLIST,
) -> list[Violation]:
    """Drop violations matching an allowlist entry (content-keyed)."""
    keys = {(e.file, e.func_name, e.kind, e.detail) for e in allowlist}
    return [
        v for v in violations
        if (v.file, v.func_name, v.kind, v.detail) not in keys
    ]


def render_violations(violations: Iterable[Violation]) -> str:
    """Pretty-print a violations list for the test failure message."""
    by_file: dict = {}
    for v in violations:
        by_file.setdefault(v.file, []).append(v)
    lines: list[str] = []
    for file in sorted(by_file):
        lines.append(f"\n  {file}:")
        for v in sorted(by_file[file], key=lambda v: v.line):
            lines.append(
                f"    L{v.line:<5} {v.kind} detail={v.detail!r:<20} "
                f"in {v.func_name}()"
            )
    return "\n".join(lines)


__all__ = [
    "AllowlistEntry",
    "Violation",
    "audit_file",
    "audit_repo",
    "audit_source",
    "filter_allowlisted",
    "render_violations",
]
