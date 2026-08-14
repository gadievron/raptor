"""Detect transform-sequencing errors in sanitization pipelines.

Finds functions that apply multiple transforms to the same data and
checks whether the ordering is correct.  A sanitizer pipeline that
runs steps in the wrong order can be bypassed — e.g. stripping
invisible Unicode *after* a markdown-defanging regex allows a ZWS
to defeat the regex.

Two modes:

1. **Catalog-matched** (mechanical): a static table of known ordering
   constraints produces high-confidence violations with no LLM.
2. **Candidate extraction**: multi-step transform sequences with
   security-relevant names are surfaced for LLM review.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .prompt_defence import sanitise_for_prompt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TransformStep:
    """One step in a transform chain."""

    call_name: str
    line: int
    args_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "call_name": self.call_name,
            "line": self.line,
            "args_summary": self.args_summary,
        }


@dataclass
class TransformSequence:
    """An ordered chain of transforms applied to the same data."""

    file: str
    function: str
    variable: str
    steps: List[TransformStep] = field(default_factory=list)

    @property
    def line_span(self) -> Tuple[int, int]:
        if not self.steps:
            return (0, 0)
        return (self.steps[0].line, self.steps[-1].line)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "function": self.function,
            "variable": self.variable,
            "steps": [s.to_dict() for s in self.steps],
            "line_span": list(self.line_span),
        }


@dataclass
class TransformOrderViolation:
    """A detected ordering violation in a transform chain."""

    file: str
    function: str
    line: int
    sequence: List[str]
    violation: str
    fix: str
    confidence: str
    catalog_rule: Optional[str] = None
    siblings_correct: int = 0
    sibling_locations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "sequence": self.sequence,
            "violation": self.violation,
            "fix": self.fix,
            "confidence": self.confidence,
            "catalog_rule": self.catalog_rule,
        }
        if self.siblings_correct:
            d["siblings_correct"] = self.siblings_correct
            d["sibling_locations"] = self.sibling_locations
        return d


# ---------------------------------------------------------------------------
# Ordering catalog
# ---------------------------------------------------------------------------

@dataclass
class _OrderingRule:
    """A must-precede ordering constraint."""

    name: str
    must_precede_patterns: List[re.Pattern[str]]
    must_follow_patterns: List[re.Pattern[str]]
    reason: str
    fix_template: str

    def matches_precede(self, call_name: str) -> bool:
        return any(p.search(call_name) for p in self.must_precede_patterns)

    def matches_follow(self, call_name: str) -> bool:
        return any(p.search(call_name) for p in self.must_follow_patterns)


def _pat(*patterns: str) -> List[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


ORDERING_RULES: List[_OrderingRule] = [
    _OrderingRule(
        name="unicode_before_regex",
        must_precede_patterns=_pat(
            r"unicode.*norm", r"nfkc|nfkd|nfc|nfd",
            r"strip.*(?:invisible|zero.?width|control)",
            r"remove.*(?:invisible|zero.?width|bidi|control)",
        ),
        must_follow_patterns=_pat(
            r"re\.sub", r"re\.match", r"re\.search", r"re\.findall",
            r"defang", r"neutrali[sz]e",
            r"regex.*(?:replace|match|filter)",
        ),
        reason="Unicode normalization/stripping must precede regex matching — "
               "invisible chars can defeat regex anchors and patterns",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="decode_before_path_check",
        must_precede_patterns=_pat(
            r"url.*decode", r"unquote", r"percent.*decode",
            r"urllib.*unquote",
        ),
        must_follow_patterns=_pat(
            r"path.*(?:check|valid|travers|saniti)",
            r"(?:check|valid|saniti).*path",
            r"os\.path\.(?:basename|normpath|realpath)",
            r"is_safe_path", r"check_path",
        ),
        reason="URL-encoded traversal sequences (..%2F) bypass path checks "
               "unless decoded first",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="entity_decode_before_xss_filter",
        must_precede_patterns=_pat(
            r"html.*(?:unescape|decode|entity)",
            r"unescape.*html",
            r"(?:decode|parse).*entit",
        ),
        must_follow_patterns=_pat(
            r"(?:xss|html).*(?:filter|sanitiz|clean|strip|escape)",
            r"(?:filter|sanitiz|clean|strip).*(?:xss|html|tag)",
            r"bleach", r"html\.escape", r"markupsafe",
        ),
        reason="HTML-entity-encoded characters (&#60;) bypass XSS filters "
               "unless decoded first",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="case_normalize_before_blocklist",
        must_precede_patterns=_pat(
            r"\.lower\b", r"\.upper\b", r"\.casefold\b",
            r"case.*norm", r"to_?lower", r"to_?upper",
        ),
        must_follow_patterns=_pat(
            r"block.?list", r"deny.?list", r"banned", r"forbidden",
            r"disallow", r"reject.*(?:name|word|term)",
        ),
        reason="Mixed-case input bypasses case-sensitive blocklist checks",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="null_strip_before_extension_check",
        must_precede_patterns=_pat(
            r"(?:strip|remove|replace).*(?:null|\\x00|\x00|\\0)",
            r"\.replace\(.*(?:null|\\x00|\\0)",
        ),
        must_follow_patterns=_pat(
            r"(?:check|valid|allow).*(?:ext|suffix|file.?type)",
            r"\.endswith\b", r"splitext\b", r"file.*extension",
        ),
        reason="Null bytes truncate filenames in some APIs, bypassing "
               "extension checks",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="backslash_normalize_before_path_check",
        must_precede_patterns=_pat(
            r"\.replace\(.*(?:\\\\|backslash).*(?:/|slash)",
            r"backslash.*norm", r"normalize.*(?:sep|slash|path)",
        ),
        must_follow_patterns=_pat(
            r"path.*(?:check|valid|travers|saniti)",
            r"\.startswith\(.*(?:/|\\\\)",
        ),
        reason="Backslash path separators bypass forward-slash-only "
               "traversal checks",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="whitespace_strip_before_header_parse",
        must_precede_patterns=_pat(
            r"\.strip\b", r"\.lstrip\b",
            r"strip.*(?:whitespace|space|ws)",
        ),
        must_follow_patterns=_pat(
            r"(?:parse|split).*header",
            r"header.*(?:parse|split|extract)",
            r"content.?type.*parse",
        ),
        reason="Leading whitespace confuses header parsers and can cause "
               "request smuggling",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="crlf_strip_before_header_inject",
        must_precede_patterns=_pat(
            r"(?:strip|remove|replace).*(?:crlf|\\r\\n|\\n|newline|cr|lf)",
            r"\.replace\(.*(?:\\r|\\n)",
        ),
        must_follow_patterns=_pat(
            r"(?:set|add|write).*header",
            r"header.*(?:set|add|inject|write)",
            r"response\.header",
        ),
        reason="CRLF characters in header values enable header injection",
        fix_template="move {precede} before {follow}",
    ),
    _OrderingRule(
        name="percent_decode_before_sql_filter",
        must_precede_patterns=_pat(
            r"url.*decode", r"unquote", r"percent.*decode",
        ),
        must_follow_patterns=_pat(
            r"sql.*(?:filter|sanitiz|escape|param)",
            r"(?:filter|sanitiz|escape).*sql",
            r"quote.*(?:literal|string|ident)",
        ),
        reason="Percent-encoded quotes (%27) bypass SQL sanitization",
        fix_template="move {precede} before {follow}",
    ),
]


# ---------------------------------------------------------------------------
# Double-encoding detection
# ---------------------------------------------------------------------------
# Transform classes where applying the same decode/encode twice in a chain
# indicates potential double-encoding bypass: an intermediate security check
# saw the still-encoded form while the final consumer sees the decoded form.

_DOUBLE_ENCODE_CLASSES: List[Tuple[str, re.Pattern[str]]] = [
    ("url_decode", re.compile(
        r"url.*decode|unquote|percent.*decode|decodeURI|"
        r"urllib.*unquote|url\.QueryUnescape|url\.PathUnescape",
        re.IGNORECASE,
    )),
    ("html_decode", re.compile(
        r"html.*(?:unescape|decode|entity)|unescape.*html|"
        r"(?:decode|parse).*entit|html_entity_decode|he\.decode",
        re.IGNORECASE,
    )),
    ("base64_decode", re.compile(
        r"base64.*decode|b64decode|atob|Base64\.decode",
        re.IGNORECASE,
    )),
    ("url_encode", re.compile(
        r"url.*encode|urllib.*quote|percent.*encode|encodeURI|"
        r"url\.QueryEscape|url\.PathEscape|"
        r"(?:percent|url|uri|path).*quote|quote_plus",
        re.IGNORECASE,
    )),
]


def _check_duplicate_transforms(
    seq: TransformSequence,
) -> List[TransformOrderViolation]:
    """Flag sequences where the same transform appears twice.

    Two detection modes:
    1. Encoding-class: double URL-decode, double base64-decode, etc.
       (bypass risk when a security check sits between them).
    2. Exact-name: same function called twice on the same variable
       (likely copy-paste error or redundant processing).
    """
    violations: List[TransformOrderViolation] = []
    step_names = [s.call_name for s in seq.steps]

    encoding_flagged: set = set()

    for class_name, pattern in _DOUBLE_ENCODE_CLASSES:
        positions = [i for i, name in enumerate(step_names) if pattern.search(name)]
        if len(positions) < 2:
            continue

        encoding_flagged.update(positions)
        violations.append(TransformOrderViolation(
            file=seq.file,
            function=seq.function,
            line=seq.steps[positions[0]].line,
            sequence=step_names,
            violation=(
                f"double {class_name}: '{step_names[positions[0]]}' and "
                f"'{step_names[positions[1]]}' in the same chain — "
                f"if a security check runs between them, it sees the "
                f"still-encoded form while the final consumer sees "
                f"the decoded form"
            ),
            fix=(
                f"verify no security-relevant check runs between "
                f"'{step_names[positions[0]]}' and "
                f"'{step_names[positions[1]]}'"
            ),
            confidence="medium",
            catalog_rule="double_encoding",
        ))

    seen: Dict[str, int] = {}
    for i, name in enumerate(step_names):
        if i in encoding_flagged:
            continue
        if name in seen and seen[name] not in encoding_flagged:
            violations.append(TransformOrderViolation(
                file=seq.file,
                function=seq.function,
                line=seq.steps[i].line,
                sequence=step_names,
                violation=(
                    f"duplicate transform: '{name}' applied twice to "
                    f"`{seq.variable}` (steps {seen[name] + 1} and {i + 1}) — "
                    f"likely copy-paste error or redundant processing"
                ),
                fix=f"verify '{name}' is intentionally applied twice",
                confidence="medium",
                catalog_rule="duplicate_transform",
            ))
            break
        seen[name] = i

    return violations


# Names that mark a transform as security-relevant.
_SECURITY_TRANSFORM_RE = re.compile(
    r"(?:sanitiz|strip|escape|encode|decode|filter|clean|normaliz|"
    r"valid|defang|neutraliz|purif|bleach|quote|unquote|urlencode|"
    r"urldecode|htmlescape|sqlescape|xss|crlf|inject|travers)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# AST-based sequence extraction (Python)
# ---------------------------------------------------------------------------

def _first_arg_summary(node: ast.Call) -> str:
    """Best-effort string summary of a call's first argument."""
    if not node.args:
        return ""
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        val = arg.value
        if len(val) > 50:
            val = val[:47] + "..."
        return val
    return ""


class _SequenceExtractor(ast.NodeVisitor):
    """Extract transform sequences from a single function body."""

    def __init__(self, file: str, func_name: str, func_lineno: int) -> None:
        self.file = file
        self.func_name = func_name
        self.func_lineno = func_lineno
        self.sequences: List[TransformSequence] = []
        self._reassign_chains: Dict[str, List[TransformStep]] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) != 1:
            self.generic_visit(node)
            return
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            self.generic_visit(node)
            return

        var_name = target.id
        call_name, args_summary = self._call_name(node.value)
        if call_name:
            chain = self._reassign_chains.setdefault(var_name, [])
            chain.append(TransformStep(
                call_name=call_name,
                line=node.lineno,
                args_summary=args_summary,
            ))
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute):
                obj = call.func.value
                if isinstance(obj, ast.Name):
                    var_name = obj.id
                    method_name = call.func.attr
                    chain = self._reassign_chains.setdefault(var_name, [])
                    chain.append(TransformStep(
                        call_name=f".{method_name}",
                        line=node.lineno,
                        args_summary=_first_arg_summary(call),
                    ))
        self.generic_visit(node)

    def _call_name(self, node: ast.expr) -> Tuple[str, str]:
        """Extract the call name and first-arg summary from an expression."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id, _first_arg_summary(node)
            if isinstance(node.func, ast.Attribute):
                parts = self._dotted_name(node.func)
                return parts, _first_arg_summary(node)
            return "", ""

        # Method chain: x.strip().lower().replace(...)
        # Walk leftward collecting the chain.
        if isinstance(node, ast.Call):
            pass  # handled above
        return "", ""

    @staticmethod
    def _dotted_name(node: ast.Attribute) -> str:
        parts = [node.attr]
        obj = node.value
        while isinstance(obj, ast.Attribute):
            parts.append(obj.attr)
            obj = obj.value
        if isinstance(obj, ast.Name):
            parts.append(obj.id)
        return ".".join(reversed(parts))

    def _extract_method_chain(self, node: ast.expr) -> Optional[TransformSequence]:
        """Extract a method chain like x.strip().lower().replace(...)."""
        steps: List[TransformStep] = []
        var_name = ""
        current = node

        while isinstance(current, ast.Call):
            if isinstance(current.func, ast.Attribute):
                steps.append(TransformStep(
                    call_name=f".{current.func.attr}",
                    line=current.lineno,
                    args_summary=_first_arg_summary(current),
                ))
                current = current.func.value
            else:
                break

        if isinstance(current, ast.Name):
            var_name = current.id

        if len(steps) < 2:
            return None

        steps.reverse()
        return TransformSequence(
            file=self.file,
            function=self.func_name,
            variable=var_name,
            steps=steps,
        )

    def visit_Call(self, node: ast.Call) -> None:
        # Check for method chains
        chain = self._extract_method_chain(node)
        if chain:
            self.sequences.append(chain)
        self.generic_visit(node)

    def finalize(self) -> List[TransformSequence]:
        """Flush reassignment chains into sequences."""
        for var_name, steps in self._reassign_chains.items():
            if len(steps) >= 2:
                self.sequences.append(TransformSequence(
                    file=self.file,
                    function=self.func_name,
                    variable=var_name,
                    steps=steps,
                ))
        return self.sequences


def _extract_sequences_python(
    file_path: str, source: str,
) -> List[TransformSequence]:
    """Extract transform sequences from Python source via AST."""
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    all_seqs: List[TransformSequence] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            extractor = _SequenceExtractor(file_path, node.name, node.lineno)
            extractor.visit(node)
            all_seqs.extend(extractor.finalize())

    return all_seqs


# ---------------------------------------------------------------------------
# Regex-based sequence extraction (C/C++/Go/JS)
# ---------------------------------------------------------------------------

_C_EXTS = frozenset((".c", ".h", ".cc", ".cpp", ".cxx", ".go", ".js", ".ts"))

_FUNC_HEADER_RE = re.compile(
    r"^\s*(?:(?:static|inline|void|int|char|unsigned|const|auto|"
    r"func|function|export|async|public|private|protected|"
    r"internal|override|virtual|abstract|final|synchronized|"
    r"fn|def)\s+)*"
    r"(?:\([^)]*\)\s+)?"  # Go method receiver: func (s *Server) Handle(
    r"(?:\w+\s+)*"         # return type(s): int, *Item, []byte
    r"(\w+)\s*\(",
    re.MULTILINE,
)

_CALL_RE = re.compile(
    r"(\w+(?:\.\w+)*)\s*\(",
)


def _extract_sequences_c(
    file_path: str, source: str,
) -> List[TransformSequence]:
    """Extract transform sequences in C/Go/JS/TS/Java via tree-sitter.

    Falls back to regex when tree-sitter is unavailable.
    """
    try:
        from .ts_extract import extract_call_chains
    except ImportError:
        return _extract_sequences_c_regex(file_path, source)

    chains = extract_call_chains(file_path, source)
    if chains is None:
        return _extract_sequences_c_regex(file_path, source)

    all_seqs: List[TransformSequence] = []
    for chain in chains:
        steps = [
            TransformStep(
                call_name=s.call_name,
                line=s.line,
                args_summary=s.first_arg,
            )
            for s in chain.steps
        ]
        if len(steps) >= 2:
            all_seqs.append(TransformSequence(
                file=chain.file,
                function=chain.function,
                variable=chain.variable,
                steps=steps,
            ))
    return all_seqs


def _extract_sequences_c_regex(
    file_path: str, source: str,
) -> List[TransformSequence]:
    """Regex fallback for transform-sequence extraction."""
    all_seqs: List[TransformSequence] = []
    lines = source.splitlines()
    current_func = "<module>"
    var_chains: Dict[str, List[TransformStep]] = {}

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1
        fm = _FUNC_HEADER_RE.match(line)
        if fm:
            for var, steps in var_chains.items():
                if len(steps) >= 2:
                    all_seqs.append(TransformSequence(
                        file=file_path,
                        function=current_func,
                        variable=var,
                        steps=steps,
                    ))
            var_chains = {}
            current_func = fm.group(1)
            continue

        assign_m = re.match(
            r"\s*(?:(?:const|let|var)\s+)?"  # JS declarations
            r"(\w+)\s*(?::=|=)\s*"           # LHS and = or :=
            r"(\w+(?:\.\w+)*)\s*\(",         # RHS call
            line,
        )
        if assign_m:
            var = assign_m.group(1)
            call = assign_m.group(2)
            rest = line[assign_m.end():]
            chain = var_chains.setdefault(var, [])
            first_arg = ""
            str_m = re.search(r'"([^"]{1,50})"', rest)
            if str_m:
                first_arg = str_m.group(1)
            chain.append(TransformStep(
                call_name=call, line=lineno, args_summary=first_arg,
            ))

    for var, steps in var_chains.items():
        if len(steps) >= 2:
            all_seqs.append(TransformSequence(
                file=file_path,
                function=current_func,
                variable=var,
                steps=steps,
            ))

    return all_seqs


# ---------------------------------------------------------------------------
# Violation checking against catalog
# ---------------------------------------------------------------------------

def _check_sequence_against_catalog(
    seq: TransformSequence,
) -> List[TransformOrderViolation]:
    """Check one sequence against all ordering rules."""
    violations: List[TransformOrderViolation] = []
    step_names = [s.call_name for s in seq.steps]

    for rule in ORDERING_RULES:
        # Find all positions where must_precede and must_follow match
        precede_positions: List[int] = []
        follow_positions: List[int] = []

        for i, name in enumerate(step_names):
            if rule.matches_precede(name):
                precede_positions.append(i)
            if rule.matches_follow(name):
                follow_positions.append(i)

        if not precede_positions or not follow_positions:
            continue

        # Violation: a must_follow step appears BEFORE a must_precede step
        for fi in follow_positions:
            for pi in precede_positions:
                if fi < pi:
                    violations.append(TransformOrderViolation(
                        file=seq.file,
                        function=seq.function,
                        line=seq.steps[fi].line,
                        sequence=step_names,
                        violation=(
                            f"'{step_names[pi]}' must precede "
                            f"'{step_names[fi]}': {rule.reason}"
                        ),
                        fix=rule.fix_template.format(
                            precede=step_names[pi],
                            follow=step_names[fi],
                        ),
                        confidence="high",
                        catalog_rule=rule.name,
                    ))

    return violations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_transform_sequences(
    source_text: Dict[str, str],
    *,
    extra_security_names: Optional[frozenset] = None,
) -> List[TransformSequence]:
    """Extract all multi-step transform sequences from source files.

    Returns sequences with ≥2 steps where at least 2 steps have
    security-relevant names.  Intended for LLM review injection.

    *extra_security_names*: additional function names considered
    security-relevant (e.g. from IRIS spec store).
    """
    extra = extra_security_names or frozenset()
    all_seqs: List[TransformSequence] = []

    for file_path, source in source_text.items():
        if file_path.endswith(".py"):
            seqs = _extract_sequences_python(file_path, source)
        elif any(file_path.endswith(e) for e in _C_EXTS):
            seqs = _extract_sequences_c(file_path, source)
        else:
            continue

        for seq in seqs:
            security_count = sum(
                1 for s in seq.steps
                if (_SECURITY_TRANSFORM_RE.search(s.call_name)
                    or s.call_name in extra)
            )
            if security_count >= 2:
                all_seqs.append(seq)

    return all_seqs


def detect_transform_order_violations(
    source_text: Dict[str, str],
    *,
    extra_security_names: Optional[frozenset] = None,
) -> List[TransformOrderViolation]:
    """Detect ordering violations in transform sequences.

    Runs all extraction heuristics and checks each sequence against
    the ordering catalog.  Returns only catalog-matched violations
    (high confidence, no LLM needed).

    Each violation is annotated with how many sibling sequences use
    the same transform pair in the *correct* order, plus their
    locations.  This helps the LLM compare the anomaly against the
    codebase norm.

    *extra_security_names*: passed through for future sequence
    filtering (currently ordering checks run on all sequences).
    """
    all_seqs: List[TransformSequence] = []
    violations: List[TransformOrderViolation] = []

    for file_path, source in source_text.items():
        if file_path.endswith(".py"):
            seqs = _extract_sequences_python(file_path, source)
        elif any(file_path.endswith(e) for e in _C_EXTS):
            seqs = _extract_sequences_c(file_path, source)
        else:
            continue
        all_seqs.extend(seqs)

    for seq in all_seqs:
        violations.extend(_check_sequence_against_catalog(seq))
        violations.extend(_check_duplicate_transforms(seq))

    _annotate_sibling_counts(violations, all_seqs)

    violations.sort(key=lambda v: (v.file, v.line))
    return violations


def _annotate_sibling_counts(
    violations: List[TransformOrderViolation],
    all_seqs: List[TransformSequence],
) -> None:
    """Annotate each violation with the count of sibling sequences
    that apply the same rule's transforms in the correct order."""
    for v in violations:
        if not v.catalog_rule:
            continue
        rule = None
        for r in ORDERING_RULES:
            if r.name == v.catalog_rule:
                rule = r
                break
        if rule is None:
            continue

        correct: List[str] = []
        for seq in all_seqs:
            if seq.file == v.file and seq.function == v.function:
                continue
            step_names = [s.call_name for s in seq.steps]
            has_precede = any(rule.matches_precede(n) for n in step_names)
            has_follow = any(rule.matches_follow(n) for n in step_names)
            if not (has_precede and has_follow):
                continue
            precede_pos = [i for i, n in enumerate(step_names) if rule.matches_precede(n)]
            follow_pos = [i for i, n in enumerate(step_names) if rule.matches_follow(n)]
            if all(fp > pp for fp in follow_pos for pp in precede_pos):
                correct.append(f"{seq.file}:{seq.function}")

        v.siblings_correct = len(correct)
        v.sibling_locations = correct[:5]


def format_transform_sequences_for_prompt(
    sequences: Sequence[TransformSequence],
) -> str:
    """Format extracted sequences for injection into an LLM review prompt."""
    if not sequences:
        return ""

    parts = ["### Transform sequences (check ordering correctness)\n"]
    for seq in sequences:
        safe_file = sanitise_for_prompt(seq.file, content_type="path")
        safe_func = sanitise_for_prompt(seq.function, content_type="name")
        safe_var = sanitise_for_prompt(seq.variable, content_type="name")
        steps_str = " → ".join(
            f"`{sanitise_for_prompt(s.call_name, content_type='name')}`"
            + (f" ({sanitise_for_prompt(s.args_summary, content_type='string')})" if s.args_summary else "")
            for s in seq.steps
        )
        parts.append(
            f"- **{safe_file}:{safe_func}** on `{safe_var}`: {steps_str}"
        )
    return "\n".join(parts)
