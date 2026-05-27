"""Language-aware code item extraction.

Extracts functions, globals, macros, and classes from source files.
AST-based for Python, tree-sitter when available, regex fallback.

Security metadata (decorators, annotations, visibility, types) is captured
in FunctionMetadata. See docs/design-inventory-metadata.md for design rationale.
"""

import ast
import re
import logging
import warnings
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# Item kinds — what type of code construct this represents
KIND_FUNCTION = "function"
KIND_GLOBAL = "global"
KIND_MACRO = "macro"
KIND_CLASS = "class"
KIND_TOP_LEVEL = "top_level"        # module-scope executable code (runs at import)
KIND_INTERSTITIAL = "interstitial"  # residue not yet classified — trends to glue
                                    # (whitespace/braces/comments) as kinds fill in


@dataclass
class CodeItem:
    """A code construct in the inventory (function, global, macro, class).

    Base class for all inventory items. FunctionInfo inherits from this
    for backwards compatibility with code that expects function-specific fields.
    """
    name: str
    kind: str = KIND_FUNCTION
    line_start: int = 0
    line_end: Optional[int] = None
    checked_by: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise for checklist.json."""
        return {
            "name": self.name,
            "kind": self.kind,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "checked_by": list(self.checked_by),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CodeItem":
        """Deserialise from checklist.json."""
        kind = d.get("kind", KIND_FUNCTION)
        # If it has function-specific fields, return a FunctionInfo
        if kind == KIND_FUNCTION or "signature" in d or "metadata" in d:
            return FunctionInfo.from_dict(d)
        return cls(
            name=d.get("name", ""),
            kind=kind,
            line_start=d.get("line_start", 0),
            line_end=d.get("line_end"),
            checked_by=d.get("checked_by", []),
        )


@dataclass
class FunctionMetadata:
    """Security-relevant metadata extracted from function definitions.

    Language-agnostic — same fields for all languages, language-specific values.
    See docs/design-inventory-metadata.md for field semantics.
    """
    class_name: Optional[str] = None
    visibility: Optional[str] = None      # public/private/protected/static/exported/extern
    attributes: List[str] = field(default_factory=list)  # decorators AND annotations
    return_type: Optional[str] = None
    parameters: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    # Annotations on the ENCLOSING class (Java only): a method carries its
    # class's stereotype annotations (@Service / @Component / …) so reachability
    # can treat public methods of a container-managed bean as framework entries.
    class_attributes: List[str] = field(default_factory=list)


@dataclass
class FunctionInfo(CodeItem):
    """A function or method in the inventory.

    Inherits from CodeItem. Adds signature and metadata fields.
    kind is always KIND_FUNCTION.
    """
    signature: Optional[str] = None
    metadata: Optional[FunctionMetadata] = None

    def to_dict(self) -> dict:
        """Serialise for checklist.json."""
        d = {
            "name": self.name,
            "kind": self.kind,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "signature": self.signature,
            "checked_by": list(self.checked_by),
        }
        if self.metadata:
            d["metadata"] = asdict(self.metadata)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FunctionInfo":
        """Deserialise from checklist.json."""
        metadata = None
        raw = d.get("metadata")
        if isinstance(raw, dict):
            # Convert parameter lists back to tuples
            params = raw.get("parameters", [])
            if params:
                raw["parameters"] = [tuple(p) for p in params]
            from dataclasses import fields as dc_fields
            valid = {f.name for f in dc_fields(FunctionMetadata)}
            metadata = FunctionMetadata(**{k: v for k, v in raw.items() if k in valid})
        return cls(
            name=d.get("name", ""),
            line_start=d.get("line_start", 0),
            line_end=d.get("line_end"),
            signature=d.get("signature"),
            checked_by=d.get("checked_by", []),
            metadata=metadata,
        )


class PythonExtractor:
    """Extract functions from Python files using AST.

    Captures metadata: decorators, class_name, parameters (with type
    annotations), return_type. Always available — uses stdlib ast.
    """

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(content)
            self._walk(tree, functions, class_name=None)
            functions.extend(self._top_level_items(tree))
        except SyntaxError as e:
            logger.warning(f"Failed to parse {filepath}: {e}")
            functions = self._regex_fallback(content)

        return functions

    def _top_level_items(self, tree: ast.AST) -> List["CodeItem"]:
        """Module-scope executable statements that run at import — a bare
        expression statement containing a call (e.g. ``os.system(...)``,
        ``eval(...)``). Captured as ``top_level`` so it's a named, reviewable,
        reachability-eligible unit instead of anonymous interstitial.
        Assignments are globals; defs/classes/imports are their own kinds."""
        out: List[CodeItem] = []
        for node in getattr(tree, "body", []):
            if isinstance(node, ast.Expr) and any(
                isinstance(n, ast.Call) for n in ast.walk(node)
            ):
                out.append(CodeItem(
                    name=f"top_level:{node.lineno}",
                    kind=KIND_TOP_LEVEL,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", None) or node.lineno,
                ))
        return out

    def _walk(self, node: ast.AST, functions: List[FunctionInfo],
              class_name: Optional[str]) -> None:
        """Walk AST collecting functions with metadata."""
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                self._walk(child, functions, class_name=child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(self._extract_function(child, class_name))
                # Walk into nested functions/classes
                self._walk(child, functions, class_name=class_name)
            else:
                # Descend into compound statements (if / try / with /
                # for / while / match) so functions nested inside them
                # are still captured. tree-sitter extraction already
                # does this; the stdlib fallback previously stopped at
                # the first non-class/def node, so functions inside
                # e.g. ``if False:`` guards, ``try/except`` import
                # fallbacks, or context managers were invisible to
                # inventory + reachability on tree-sitter-less
                # environments. class_name is preserved — these nodes
                # don't open a class scope. Only FunctionDef nodes are
                # collected, so recursing through expression children
                # is harmless (lambdas are ast.Lambda, not FunctionDef).
                self._walk(child, functions, class_name=class_name)

    def _extract_function(self, node: ast.AST, class_name: Optional[str]) -> FunctionInfo:
        """Extract a single function with full metadata."""
        args = node.args.args
        # Build signature
        arg_strs = []
        for arg in args:
            s = arg.arg
            if arg.annotation:
                s += f": {ast.unparse(arg.annotation)}"
            arg_strs.append(s)
        signature = f"def {node.name}({', '.join(arg_strs)})"
        if isinstance(node, ast.AsyncFunctionDef):
            signature = "async " + signature
        if node.returns:
            signature += f" -> {ast.unparse(node.returns)}"

        # Parameters as (name, type) tuples
        parameters = []
        for arg in args:
            type_str = ast.unparse(arg.annotation) if arg.annotation else None
            parameters.append((arg.arg, type_str))

        # Return type
        return_type = ast.unparse(node.returns) if node.returns else None

        # Decorators
        attributes = []
        for dec in node.decorator_list:
            attributes.append(ast.unparse(dec))

        return FunctionInfo(
            name=node.name,
            line_start=node.lineno,
            line_end=node.end_lineno if hasattr(node, 'end_lineno') else None,
            signature=signature,
            metadata=FunctionMetadata(
                class_name=class_name,
                attributes=attributes,
                return_type=return_type,
                parameters=parameters,
            ),
        )

    def _regex_fallback(self, content: str) -> List[FunctionInfo]:
        """Regex fallback for unparseable Python."""
        functions = []
        pattern = r'^(?:async\s+)?def\s+(\w+)\s*\('
        for i, line in enumerate(content.split('\n'), 1):
            match = re.match(pattern, line.strip())
            if match:
                functions.append(FunctionInfo(
                    name=match.group(1),
                    line_start=i,
                ))
        return functions


class JavaScriptExtractor:
    """Extract functions from JavaScript/TypeScript files using regex.

    Metadata: visibility (export). Missing without tree-sitter: class methods,
    parameters, decorators. Class method detection needs brace-depth tracking.
    """

    PATTERNS = [
        r'(?:async\s+)?function\s+(\w+)\s*\(',
        r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(',
        r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>',
        r'^\s+(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{',
        r'(\w+)\s*:\s*(?:async\s+)?(?:function\s*)?\([^)]*\)\s*(?:=>)?\s*\{',
    ]
    # Several patterns repeat `\s*` between optional tokens. On a long
    # whitespace-only run that fails the structural part, the engine
    # backtracks each `\s*` separately. Cap line length before applying
    # any of the JS patterns. Real JS is rarely linted to >120 chars;
    # 16 KB allows minified single-line modules through up to a
    # reasonable bound while refusing pathological input (a single
    # 100 MB minified bundle would otherwise sit in this loop).
    _MAX_JS_LINE = 16 * 1024

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        seen = set()

        for i, line in enumerate(content.split('\n'), 1):
            if len(line) > self._MAX_JS_LINE:
                continue
            for pattern in self.PATTERNS:
                match = re.search(pattern, line)
                if match:
                    name = match.group(1)
                    if name not in seen and name not in ('if', 'for', 'while', 'switch', 'catch'):
                        exported = line.lstrip().startswith('export ')
                        functions.append(FunctionInfo(
                            name=name, line_start=i,
                            metadata=FunctionMetadata(
                                visibility="exported" if exported else None,
                            ),
                        ))
                        seen.add(name)
                    break

        return functions


class CExtractor:
    """Extract functions from C/C++ files using regex.

    Handles both ANSI C and K&R style function definitions.
    Metadata: visibility (static/extern), return_type. Missing without
    tree-sitter: parameters (would need regex capture group changes that
    risk breaking existing extraction).
    """

    # `[\w\s\*]+` is greedy and overlaps the following `\s+` (both match
    # space). On a line that's a long run of word/space chars without a
    # following `{` or `(`, the engine must try every backtrack position
    # before declaring no-match. Pathological input
    # (e.g. `"a" * 50000 + "\n"`) made `re.match` quadratic in line
    # length. C source lines aren't longer than ~10 KB in practice (per
    # most house style guides); cap the per-line input at `_MAX_C_LINE`
    # before running the matcher so a stray minified file or a
    # generated source dump (single-line concatenated declarations)
    # can't hang inventory.
    # Compile with `re.ASCII` so the `\w` captures match only ASCII
    # word chars. C identifiers are ASCII per the language spec; without
    # the flag, Python's `\w` admits Unicode word characters that would
    # be captured as the function name and surfaced into the inventory
    # under a homoglyph that visually matches a real ASCII identifier
    # — confusing greps and downstream cross-references.
    ANSI_PATTERN = r'(?a)^(?:[\w\s\*]+)\s+(\w+)\s*\([^;]*\)\s*\{'
    ANSI_SPLIT_PATTERN = r'(?a)^(?:[\w\s\*]+)\s+(\w+)\s*\([^;{]*\)\s*$'
    _MAX_C_LINE = 16 * 1024
    KNR_FUNCNAME = r'(?a)^(\w+)\s*\([\w\s,]*\)\s*$'
    FUNCNAME_OPEN_PAREN = r'(?a)^(\w+)\s*\([^)]*$'

    # Multi-line function-definition opener cases the single-line
    # patterns above miss (surfaced by source_intel E2E on curl,
    # openssl, and linux kernel):
    #
    #  1. Args span multiple lines:
    #       static CURLcode do_sendmsg(struct Curl_cfilter *cf,
    #                                  struct Curl_easy *data,
    #                                  ...)
    #       {
    #     ANSI_PATTERN needs `{` on the close-paren line; ANSI_SPLIT_PATTERN
    #     needs both args and close-paren on one line. Neither fires.
    #
    #  2. Pointer-return with no space between `*` and name:
    #       struct page *selinux_kernel_status_page(void)
    #     ANSI_PATTERN's `\s+(\w+)` requires whitespace before the name,
    #     which `*name` doesn't satisfy.
    #
    #  3. Combination of the above with split type + name:
    #       static char *
    #       minstrel_ht_stats_csv_dump(struct minstrel_ht_sta *mi,
    #                                  int i, char *p)
    #       {
    #     KNR_FUNCNAME's prev-line heuristic catches some split cases
    #     but bails when the args span multiple lines.
    #
    # MULTILINE_OPENER_PREFIX is a CHEAP trigger — matches any line
    # that starts with `<word>...<word> <name>(` (with possible
    # pointer sigils between type and name) OR starts with `<name>(`
    # alone (split-type case where type is on the previous line).
    # When triggered, the walker forward-joins lines until paren
    # balance, then validates with MULTILINE_OPENER_FULL.
    # Type-prefixed openers may indent slightly (function-like
    # macros in older code); name-only openers (split-type case)
    # MUST start at column 0 to avoid burning the 50-line walker on
    # every indented call site like `    printf("hi");`. C function
    # definitions live at top-level scope, so column-0 anchoring is
    # accurate.
    MULTILINE_OPENER_PREFIX = re.compile(
        r'(?a)^(?:'
        r'\s{0,4}(?:[A-Za-z_][A-Za-z_0-9]*[\s*&]+)+[A-Za-z_][A-Za-z_0-9]*\s*\('
        r'|'
        r'[A-Za-z_][A-Za-z_0-9]*\s*\('
        r')'
    )
    MULTILINE_OPENER_FULL = re.compile(
        r'(?a)^\s*(?:[A-Za-z_][A-Za-z_0-9]*[\s*&]+)*'
        r'(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*\([^;{]*?\)\s*\{?'
    )
    # Type-only previous line (for split type + name decls):
    # `static char *`, `struct page *`, `static __always_inline u64`.
    # Anchored: must start with a word, end without `(`, `)`, `;`, `:`.
    TYPE_ONLY_LINE = re.compile(
        r'(?a)^\s*[A-Za-z_][A-Za-z_0-9]*[A-Za-z_0-9*&\s]*$'
    )

    C_TYPE_HINTS = frozenset({
        'void', 'int', 'char', 'short', 'long', 'float', 'double',
        'unsigned', 'signed', 'static', 'extern', 'inline',
        'register', 'const', 'volatile', 'struct', 'union', 'enum',
    })

    KEYWORDS = frozenset({
        'if', 'for', 'while', 'switch', 'return', 'sizeof', 'typeof',
        'case', 'default', 'goto', 'break', 'continue', 'do',
    })

    STORAGE_CLASSES = frozenset({'static', 'extern', 'inline'})

    def _c_metadata(self, line: str, name: str) -> Optional[FunctionMetadata]:
        """Extract return type and storage class from the text before the function name."""
        try:
            prefix = line.split(name)[0].strip() if name in line else ""
            words = prefix.split()
            storage = set()
            type_words = []
            for w in words:
                w = w.strip("*")
                if w in self.STORAGE_CLASSES:
                    storage.add(w)
                elif w in self.C_TYPE_HINTS or w not in self.KEYWORDS:
                    type_words.append(w)
            # Linkage is the entry signal. `static` (internal linkage) is
            # load-bearing and must not be masked by `inline` (not a linkage
            # class) — `static inline` is still internal. `extern` wins: it is
            # external linkage, and the invalid `extern static` combo is
            # treated as external (never under-claim reachability).
            if "extern" in storage:
                visibility = "extern"
            elif "static" in storage:
                visibility = "static"
            else:
                visibility = None
            return_type = " ".join(type_words) if type_words else None
            return FunctionMetadata(visibility=visibility, return_type=return_type)
        except Exception:
            return None

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        seen = set()
        lines = content.split('\n')

        i = 0
        while i < len(lines):
            line = lines[i]

            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                i += 1
                continue

            # Cap line length before regex match — see ANSI_PATTERN
            # comment for the ReDoS rationale.
            if len(line) > self._MAX_C_LINE:
                i += 1
                continue

            match = re.match(self.ANSI_PATTERN, line)
            if match:
                name = match.group(1)
                if name not in self.KEYWORDS and name not in seen:
                    functions.append(FunctionInfo(
                        name=name, line_start=i + 1,
                        metadata=self._c_metadata(line, name),
                    ))
                    seen.add(name)
                i += 1
                continue

            split_match = re.match(self.ANSI_SPLIT_PATTERN, line)
            if split_match:
                name = split_match.group(1)
                if name not in self.KEYWORDS and name not in seen:
                    for j in range(i + 1, min(i + 3, len(lines))):
                        fwd = lines[j].strip()
                        if fwd == '{':
                            functions.append(FunctionInfo(name=name, line_start=i + 1))
                            seen.add(name)
                            break
                        if fwd and fwd != '{':
                            break
                i += 1
                continue

            knr_match = (
                re.match(self.KNR_FUNCNAME, stripped)
                or re.match(self.FUNCNAME_OPEN_PAREN, stripped)
            )
            if knr_match:
                name = knr_match.group(1)
                if name not in self.KEYWORDS and name not in seen:
                    prev_idx = i - 1
                    while prev_idx >= 0 and not lines[prev_idx].strip():
                        prev_idx -= 1
                    if prev_idx >= 0:
                        prev_line = lines[prev_idx].strip()
                        prev_stripped = prev_line.rstrip('*').strip()
                        prev_words = prev_stripped.split()
                        looks_like_type = (
                            prev_words
                            and not prev_line.endswith(';')
                            and not prev_line.endswith('{')
                            and not prev_line.endswith(')')
                            and len(prev_words) <= 4
                            and not any(w in self.KEYWORDS for w in prev_words)
                        )
                        if looks_like_type:
                            for j in range(i + 1, min(i + 40, len(lines))):
                                fwd_stripped = lines[j].strip()
                                if fwd_stripped == '{':
                                    functions.append(FunctionInfo(name=name, line_start=i + 1))
                                    seen.add(name)
                                    break
                                if fwd_stripped.startswith('#'):
                                    break

            # Multi-line opener path — handles the three cases
            # documented at MULTILINE_OPENER_PREFIX. Cheap prefix
            # match first; on hit, forward-join until paren balance,
            # then validate against the full pattern.
            if (name := self._multiline_opener_match(lines, i, seen)) is not None:
                functions.append(FunctionInfo(
                    name=name, line_start=i + 1,
                    metadata=self._c_metadata(lines[i], name),
                ))
                seen.add(name)

            i += 1

        return functions

    def _multiline_opener_match(
        self, lines: list, i: int, seen: set,
    ) -> Optional[str]:
        """Try matching a multi-line function-definition opener
        starting at ``lines[i]``. Returns the function name on a
        valid match (and the body opener `{` is found within a few
        lines after the close paren), else ``None``.

        Two opener shapes accepted by ``MULTILINE_OPENER_PREFIX``:
          * `<type>... <name>(...` — standard with type prefix on
            this line. Args may span multiple lines.
          * `<name>(...` with no type prefix — checked against the
            previous line being a type-only return-type line
            (``TYPE_ONLY_LINE``).

        Forward-joins up to 50 lines until paren balance. Inline
        ``/* ... */`` block comments are stripped per-line so paren
        counts aren't fooled by literal parens inside comments.
        """
        line = lines[i]
        if not self.MULTILINE_OPENER_PREFIX.match(line):
            return None

        # Determine which opener shape this is. If the line has no
        # type prefix (starts directly with `<name>(`), require the
        # previous non-blank line to be a type-only line.
        has_type_on_line = bool(re.match(
            r'(?a)^\s*[A-Za-z_][A-Za-z_0-9]*[\s*&]+[A-Za-z_]',
            line,
        ))
        if not has_type_on_line:
            prev_idx = i - 1
            while prev_idx >= 0 and not lines[prev_idx].strip():
                prev_idx -= 1
            if prev_idx < 0:
                return None
            prev = lines[prev_idx].rstrip()
            prev_stripped = re.sub(r'/\*.*?\*/', '', prev)
            prev_stripped = re.sub(r'//.*$', '', prev_stripped)
            if any(c in prev_stripped for c in '();:'):
                return None
            if prev_stripped.lstrip().startswith(('#', '/*', '//', '*')):
                return None
            if not self.TYPE_ONLY_LINE.match(prev_stripped):
                return None

        # Join forward until paren balance. Strip inline block
        # comments so literal `(` / `)` inside comments don't
        # corrupt the depth count.
        depth = 0
        pieces: list = []
        terminator: Optional[int] = None
        for j in range(i, min(i + 50, len(lines))):
            text = lines[j].rstrip()
            if len(text) > self._MAX_C_LINE:
                return None
            text_clean = re.sub(r'/\*.*?\*/', '', text)
            text_clean = re.sub(r'//.*$', '', text_clean)
            pieces.append(text_clean)
            for ch in text_clean:
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
            saw_paren = sum(p.count('(') for p in pieces) > 0
            if saw_paren and depth <= 0 and j >= i:
                terminator = j
                break
        if terminator is None:
            return None

        joined = ' '.join(p.strip() for p in pieces)
        m = self.MULTILINE_OPENER_FULL.match(joined)
        if not m:
            return None
        name = m.group('name')
        if name in self.KEYWORDS or name in seen:
            return None

        # Body-definition check: look for `{` within a few lines of
        # the terminator. A `;` instead means it's a declaration
        # (prototype), not a definition — skip.
        for k in range(terminator, min(terminator + 5, len(lines))):
            tail = lines[k]
            if k == terminator:
                # Strip up through the close paren to inspect what
                # follows on the same line.
                idx = tail.find(')')
                if idx >= 0:
                    after = tail[idx + 1:].lstrip()
                    if after.startswith('{'):
                        return name
                    if after.startswith(';'):
                        return None
            else:
                t = tail.strip()
                if t.startswith('{'):
                    return name
                if t.startswith(';'):
                    return None
                if t and not t.startswith(('//', '/*', '*')):
                    # First non-comment, non-empty line wasn't `{`
                    # or `;` — not a clean definition opener.
                    return None
        return None


class JavaExtractor:
    """Extract methods from Java files using regex.

    Metadata: class_name, visibility, return_type, parameters (typed).
    Missing without tree-sitter: annotations (@RequestMapping etc).
    """

    # `((?:public|private|protected|static|\s)+)` — `\s` is in the
    # alternation AND repeated, so a long whitespace run before any
    # method-shaped tail must be backtracked one space at a time on a
    # failed match. Combined with the `(?:throws\s+[\w,\s]+)?` tail
    # also consuming `\s`, a degenerate Java line like
    # `"public " + " " * 50000 + ";\n"` (no trailing `{`) hits the
    # backtracking. Cap line length before regex match. Real Java
    # method headers are well under 8 KB; 16 KB leaves headroom for
    # generated annotations / generics-heavy signatures while
    # refusing pathological input.
    PATTERN = r'((?:public|private|protected|static|\s)+)([\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
    _MAX_JAVA_LINE = 16 * 1024

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        current_class = None

        for i, line in enumerate(content.split('\n'), 1):
            # Track class scope
            class_match = re.search(r'class\s+(\w+)', line)
            if class_match:
                current_class = class_match.group(1)

            # Cap line length before regex match — see PATTERN comment
            # for the ReDoS rationale.
            if len(line) > self._MAX_JAVA_LINE:
                continue

            match = re.search(self.PATTERN, line)
            if match:
                modifiers = match.group(1).strip()
                return_type = match.group(2)
                name = match.group(3)
                params_str = match.group(4).strip()

                if name not in ('if', 'for', 'while', 'switch', 'try', 'catch'):
                    visibility = None
                    for v in ('public', 'private', 'protected'):
                        if v in modifiers:
                            visibility = v
                            break

                    # Parse parameters
                    parameters = []
                    if params_str:
                        for p in params_str.split(','):
                            parts = p.strip().split()
                            if len(parts) >= 2:
                                pname = parts[-1]
                                ptype = " ".join(parts[:-1])
                                parameters.append((pname, ptype))

                    functions.append(FunctionInfo(
                        name=name, line_start=i,
                        metadata=FunctionMetadata(
                            class_name=current_class,
                            visibility=visibility,
                            return_type=return_type,
                            parameters=parameters,
                        ),
                    ))

        return functions


class GoExtractor:
    """Extract functions from Go files using regex.

    Metadata: class_name (receiver type), visibility (exported/unexported).
    Missing without tree-sitter: parameters (Go's `a, b int` shared-type
    syntax can't be parsed reliably with regex), return types.
    """

    # `(?a)` (re.ASCII) so `\w` matches only ASCII identifiers. Go's
    # language spec restricts identifiers to ASCII; without `re.ASCII`,
    # Python's `\w` admits Unicode word characters and would capture
    # a Cyrillic homoglyph as a "function name", surfacing into the
    # inventory under a name that visually matches a real ASCII
    # identifier — confusing greps and downstream cross-references.
    PATTERN = r'(?a)^func\s+(?:\((\w+)\s+(\*?\w+)\)\s+)?(\w+)\s*\('

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []

        for i, line in enumerate(content.split('\n'), 1):
            match = re.match(self.PATTERN, line)
            if match:
                # match.group(1) is the receiver variable name (e.g. "s"); unused
                receiver_type = match.group(2)  # e.g. "*Server"
                name = match.group(3)
                class_name = receiver_type.lstrip("*") if receiver_type else None
                exported = name[0].isupper() if name else False
                functions.append(FunctionInfo(
                    name=name, line_start=i,
                    metadata=FunctionMetadata(
                        class_name=class_name,
                        visibility="exported" if exported else None,
                    ),
                ))

        return functions


class GenericExtractor:
    """Generic fallback extractor using common patterns."""

    PATTERNS = [
        r'(?:function|def|func|fn|sub)\s+(\w+)\s*\(',
        r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*\{',
    ]

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        seen = set()

        for i, line in enumerate(content.split('\n'), 1):
            for pattern in self.PATTERNS:
                match = re.search(pattern, line)
                if match:
                    name = match.group(1)
                    if name not in seen:
                        functions.append(FunctionInfo(name=name, line_start=i))
                        seen.add(name)
                    break

        return functions


# ---------------------------------------------------------------------------
# Tree-sitter extractor (optional — rich metadata for all languages)
# ---------------------------------------------------------------------------

try:
    from tree_sitter import Language, Parser as TSParser
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False


# Per-language Parser cache. Pre-cache, ``TreeSitterExtractor(lang)``
# constructed a fresh ``TSParser(ts_language)`` on every instance —
# which is per-file in ``_extract_with_tree_sitter``. The grammar
# is immutable across the program's lifetime so a single Parser
# per language can be reused across every parse. Cache by the
# language NAME (not Language object identity) because
# ``_ts_language`` wraps a new Language per call.
_TS_PARSER_BY_LANG: Dict[str, Any] = {}


def _ts_language(lang: str):
    """Load tree-sitter language grammar. Returns None if not installed."""
    try:
        if lang == "python":
            import tree_sitter_python as ts
        elif lang == "java":
            import tree_sitter_java as ts
        elif lang == "javascript":
            import tree_sitter_javascript as ts
        elif lang in ("typescript", "tsx"):
            # Pre-2026-05-26 this branch loaded ``tree_sitter_javascript``,
            # which can't parse TS type annotations / interfaces / enums /
            # access modifiers / decorators — a typed file produced ERROR
            # nodes and extracted ZERO functions (the same class of bug the
            # cpp branch had with tree_sitter_c). ``.ts`` and ``.tsx`` need
            # DIFFERENT grammars: ``language_typescript`` parses ``<T>x`` casts
            # but errors on JSX; ``language_tsx`` parses JSX but errors on the
            # cast syntax. Pick by the language (``.tsx`` → ``tsx``).
            import tree_sitter_typescript as ts
            ts_fn = ts.language_tsx if lang == "tsx" else ts.language_typescript
            return Language(ts_fn())
        elif lang == "c":
            import tree_sitter_c as ts
        elif lang == "cpp":
            # Pre-2026-05-16 this branch loaded ``tree_sitter_c``,
            # which can't parse class / method / template / namespace
            # / qualified-id shapes. Inline class methods and
            # out-of-line destructors were silently dropped from
            # ``extract_functions`` output. Using the cpp-specific
            # grammar gives the extractor the right node types
            # (``class_specifier``, ``destructor_name``, etc.).
            import tree_sitter_cpp as ts
        elif lang == "go":
            import tree_sitter_go as ts
        elif lang == "csharp":
            import tree_sitter_c_sharp as ts
        elif lang == "ruby":
            import tree_sitter_ruby as ts
        else:
            return None
        return Language(ts.language())
    except ImportError:
        return None


def _ts_parser_for(lang: str):
    """Return a cached ``TSParser`` for ``lang``, or None if the
    grammar isn't installed. Mirrors ``_get_ts_parser`` in
    ``core/inventory/call_graph.py`` but keyed by language NAME so
    repeated ``TreeSitterExtractor(lang)`` constructions across
    many files share one Parser per grammar.
    """
    cached = _TS_PARSER_BY_LANG.get(lang)
    if cached is not None:
        return cached
    ts_lang = _ts_language(lang)
    if ts_lang is None:
        return None
    parser = TSParser(ts_lang)
    _TS_PARSER_BY_LANG[lang] = parser
    return parser


class TreeSitterExtractor:
    """Extract functions with rich metadata using tree-sitter.

    Language-agnostic tree walking with language-specific node type mappings.
    Falls back gracefully when a grammar isn't installed.
    """

    # Node types that represent functions/methods per language
    _FUNC_TYPES = {
        "python": ("function_definition",),
        "java": ("method_declaration", "constructor_declaration"),
        "javascript": ("function_declaration", "method_definition", "arrow_function"),
        "typescript": ("function_declaration", "method_definition", "arrow_function"),
        "tsx": ("function_declaration", "method_definition", "arrow_function"),
        "c": ("function_definition",),
        "cpp": ("function_definition",),
        "go": ("function_declaration", "method_declaration"),
        "csharp": ("method_declaration", "constructor_declaration",
                   "local_function_statement"),
        "ruby": ("method", "singleton_method"),
    }

    _CLASS_TYPES = {
        "python": ("class_definition",),
        "java": ("class_declaration", "interface_declaration"),
        "javascript": ("class_declaration",),
        "typescript": ("class_declaration", "abstract_class_declaration"),
        "tsx": ("class_declaration", "abstract_class_declaration"),
        "c": (),
        "cpp": ("class_specifier", "struct_specifier"),
        "go": (),
        "csharp": ("class_declaration", "interface_declaration",
                   "struct_declaration", "record_declaration"),
        "ruby": ("class", "module"),
    }

    def __init__(self, language: str):
        self.language = language
        self.func_types = self._FUNC_TYPES.get(language, ())
        self.class_types = self._CLASS_TYPES.get(language, ())
        parser = _ts_parser_for(language)
        if parser is None:
            raise RuntimeError(f"tree-sitter grammar not available for {language}")
        self.parser = parser

    def extract(self, filepath: str, content: str, _tree=None) -> List[FunctionInfo]:
        if _tree is None:
            try:
                _tree = self.parser.parse(content.encode())
            except Exception as e:
                logger.warning(f"tree-sitter parse failed for {filepath}: {e}")
                return []  # Caller will fall back to regex extractor
        functions = []
        self._walk(_tree.root_node, functions, class_name=None, class_attributes=())
        return functions

    def _class_annotations(self, node) -> List[str]:
        """Annotations / attributes declared on a class/interface.

        Java: the ``modifiers`` block holds ``marker_annotation`` / ``annotation``.
        C#: ``attribute_list`` children hold ``[Attr]`` attributes. Other
        languages put neither here, so this returns ``[]`` for them.
        """
        out: List[str] = []
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type in ("marker_annotation", "annotation"):
                        out.append(mod.text.decode().lstrip("@"))
            elif child.type == "attribute_list":
                out.extend(self._csharp_attr_names(child))
            elif child.type == "superclass":
                # Ruby: ``class X < ApplicationController`` — base is a
                # ``constant`` / ``scope_resolution``. Java: ``extends Foo`` —
                # base is a ``type_identifier`` / ``generic_type``. Capture both.
                for sc in child.children:
                    if sc.type in ("constant", "scope_resolution"):
                        out.append(sc.text.decode())          # Ruby
                out.extend(self._java_base_names(child))       # Java (no-op for Ruby)
            elif child.type in ("super_interfaces", "extends_interfaces"):
                # Java: ``implements Bar`` / interface ``extends Baz`` — record
                # the base type names so framework bases (JpaRepository →
                # Spring Data, Validator → a framework-dispatched interface)
                # can mark the class's methods as entries.
                out.extend(self._java_base_names(child))
        return out

    @staticmethod
    def _java_base_names(node) -> List[str]:
        """Base type tail-names from a Java ``superclass`` / ``super_interfaces``
        / ``extends_interfaces`` node (``JpaRepository<Owner,Integer>`` →
        ``JpaRepository``; ``org.x.Validator`` → ``Validator``). Iterates the
        individual type nodes (a ``type_list`` separates them with ``,`` tokens)
        so a generic's inner comma isn't mistaken for a type separator."""
        _TYPE_NODES = ("type_identifier", "scoped_type_identifier", "generic_type")
        out: List[str] = []

        def add(tn) -> None:
            base = tn.text.decode().split("<")[0].strip().split(".")[-1].strip()
            if base:
                out.append(base)

        for n in node.children:
            if n.type == "type_list":
                for tn in n.children:
                    if tn.type in _TYPE_NODES:
                        add(tn)
            elif n.type in _TYPE_NODES:
                add(n)
        return out

    @staticmethod
    def _csharp_attr_names(attribute_list_node) -> List[str]:
        """Attribute names in one C# ``attribute_list`` (``[HttpGet, Route(\"x\")]``
        → ``["HttpGet", "Route"]``). The name is the ``attribute`` node's leading
        identifier / qualified_name; reachability tail-matches it."""
        out: List[str] = []
        for a in attribute_list_node.children:
            if a.type != "attribute":
                continue
            for ac in a.children:
                if ac.type in ("identifier", "qualified_name"):
                    out.append(ac.text.decode())
                    break
        return out

    def _csharp_attributes(self, node) -> List[str]:
        """C# attributes on a method/ctor — its ``attribute_list`` children."""
        if self.language != "csharp":
            return []
        out: List[str] = []
        for child in node.children:
            if child.type == "attribute_list":
                out.extend(self._csharp_attr_names(child))
        return out

    # Sibling node types allowed between a TS/JS decorator and the
    # declaration it decorates (keywords / modifiers / punctuation).
    _TS_DECORATOR_SKIP = frozenset({
        "export", "default", "abstract", "async", "static", "readonly",
        "accessibility_modifier", "comment", "override",
    })

    def _ts_decorators(self, node) -> List[str]:
        """Decorators on a JS/TS class or method. tree-sitter-typescript
        places ``@Foo(...)`` as a preceding SIBLING of the decorated node
        (inside class_body / export_statement), not a wrapper as Python does.
        Walk back over decorators + intervening keywords, stopping at the
        first real node. Stored ``@``-stripped (e.g. ``Controller('x')``),
        like Java annotations, so reachability tail-matching works uniformly.
        Gated to JS-family languages so Python's decorated_definition path
        (handled separately) isn't double-counted.
        """
        if self.language not in ("javascript", "typescript", "tsx"):
            return []
        out: List[str] = []
        sib = node.prev_sibling
        while sib is not None:
            if sib.type == "decorator":
                out.append(sib.text.decode().lstrip("@").strip())
            elif sib.is_named and sib.type not in self._TS_DECORATOR_SKIP:
                break  # a real declaration / statement — decorators stop here
            sib = sib.prev_sibling
        out.reverse()
        return out

    def _walk(self, node, functions: List[FunctionInfo], class_name: Optional[str],
              class_attributes: Sequence[str] = ()) -> None:
        for child in node.children:
            if child.type in self.class_types:
                cname = self._get_name(child)
                # Class-level stereotype signal: Java modifier annotations
                # OR JS/TS class decorators (@Controller / @Injectable /
                # @Entity / @Component …) attached as preceding siblings.
                cattrs = self._ts_decorators(child) + self._class_annotations(child)
                self._walk(child, functions, class_name=cname,
                           class_attributes=cattrs)
            elif child.type == "public_field_definition":
                # TS class property holding an arrow / function expression —
                # ``handler = (x) => {...}`` (Angular/NestJS/event handlers).
                # A real function the inventory must see; not a method_definition.
                arrow = self._find_child(child, ("arrow_function", "function"))
                name = self._get_name(child)
                if arrow and name:
                    fattrs = self._ts_decorators(child)
                    functions.append(FunctionInfo(
                        name=name,
                        line_start=child.start_point[0] + 1,
                        line_end=child.end_point[0] + 1,
                        signature=child.text.decode()[:200].split("{")[0].strip(),
                        metadata=FunctionMetadata(
                            class_name=class_name,
                            visibility=self._ts_member_visibility(child),
                            attributes=fattrs,
                            parameters=self._extract_parameters(arrow),
                            class_attributes=list(class_attributes),
                        ),
                    ))
                self._walk(child, functions, class_name=class_name,
                           class_attributes=class_attributes)
                continue
            elif child.type in ("lexical_declaration", "variable_declaration"):
                # JS/TS: const foo = () => {} — arrow function inside variable declaration
                self._walk(child, functions, class_name=class_name,
                           class_attributes=class_attributes)
                continue
            elif child.type == "variable_declarator":
                # JS/TS: const bar = () => {} or const bar = function() {}
                arrow = self._find_child(child, ("arrow_function", "function"))
                if arrow:
                    name = self._get_name(child)  # Name from the variable
                    if name:
                        params = self._extract_parameters(arrow)
                        exported = child.parent and child.parent.parent and \
                                   child.parent.parent.type == "export_statement"
                        functions.append(FunctionInfo(
                            name=name,
                            line_start=child.start_point[0] + 1,
                            line_end=child.end_point[0] + 1,
                            signature=child.text.decode()[:200].split("{")[0].strip(),
                            metadata=FunctionMetadata(
                                class_name=class_name,
                                visibility="exported" if exported else None,
                                parameters=params,
                            ),
                        ))
                    continue
                self._walk(child, functions, class_name=class_name,
                           class_attributes=class_attributes)
                continue
            elif child.type in self.func_types:
                # JS/TS: method/function decorators are preceding siblings
                # (@Get() / @Cron() …). Python: a decorated_definition wrapper.
                # C#: ``[HttpGet]`` attribute_list children (gathered here).
                attrs = self._ts_decorators(child) + self._csharp_attributes(child)
                parent = child.parent
                if parent and parent.type == "decorated_definition":
                    for sib in parent.children:
                        if sib.type == "decorator":
                            attrs.append(sib.text.decode().lstrip("@"))
                    child = self._find_child(parent, self.func_types) or child

                try:
                    fi = self._extract_function(child, class_name, attrs, class_attributes)
                    if fi:
                        functions.append(fi)
                except Exception as e:
                    logger.debug(f"tree-sitter: failed to extract function at line {child.start_point[0]+1}: {e}")
                self._walk(child, functions, class_name=class_name,
                           class_attributes=class_attributes)
            elif child.type == "decorated_definition":
                # Python: walk into decorated definitions
                self._walk(child, functions, class_name=class_name,
                           class_attributes=class_attributes)
            else:
                self._walk(child, functions, class_name=class_name,
                           class_attributes=class_attributes)

    def _extract_function(self, node, class_name: Optional[str],
                          attrs: List[str],
                          class_attributes: Sequence[str] = ()) -> Optional[FunctionInfo]:
        name = self._get_name(node)
        if not name:
            return None

        visibility, class_name = self._extract_visibility(node, name, class_name, attrs)
        parameters = self._extract_parameters(node)
        return_type = self._extract_return_type(node)

        param_strs = [f"{n}: {t}" if t else n for n, t in parameters]
        sig = f"{name}({', '.join(param_strs)})"
        if return_type:
            sig += f" -> {return_type}"

        return FunctionInfo(
            name=name,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            signature=sig[:200],  # Truncate long signatures
            metadata=FunctionMetadata(
                class_name=class_name,
                visibility=visibility,
                attributes=attrs,
                return_type=return_type,
                parameters=parameters,
                class_attributes=list(class_attributes),
            ),
        )

    def _ts_member_visibility(self, node) -> Optional[str]:
        """TS/JS class-member visibility from an ``accessibility_modifier``
        child (``private`` / ``protected`` / ``public``). TS members are
        PUBLIC by default, so absence ⇒ ``public`` — which is what the
        framework-entry stereotype rule keys on (public methods of a
        container-managed / serialised class are reachable)."""
        if self.language not in ("javascript", "typescript", "tsx"):
            return None
        for child in node.children:
            if child.type == "accessibility_modifier":
                return child.text.decode().strip()
        return "public"

    def _extract_visibility(self, node, name: str, class_name: Optional[str],
                            attrs: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """Extract visibility and update class_name. Returns (visibility, class_name)."""
        visibility = None

        # TS/JS class members: accessibility_modifier (default public).
        if node.type == "method_definition":
            visibility = self._ts_member_visibility(node)

        # C#: ``modifier`` children carry access keywords; members default to
        # ``private`` (the framework-entry rule keys on public action methods).
        if self.language == "csharp" and node.type in (
            "method_declaration", "constructor_declaration",
        ):
            visibility = "private"
            for child in node.children:
                if child.type == "modifier" and child.text.decode() in (
                    "public", "private", "protected", "internal",
                ):
                    visibility = child.text.decode()
                    break

        # Java: modifiers block contains annotations and access keywords
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type in ("marker_annotation", "annotation"):
                        attrs.append(mod.text.decode().lstrip("@"))
                    elif mod.type in ("public", "private", "protected", "static"):
                        text = mod.text.decode()
                        if text in ("public", "private", "protected"):
                            visibility = text
                        elif text == "static":
                            visibility = (visibility or "") + " static"
                            visibility = visibility.strip()

        # C/C++: storage class specifier. Linkage is the entry signal:
        # `static` = internal linkage (not externally callable). It is
        # load-bearing and must NOT be masked by a following `inline` (not a
        # linkage class) — `static inline` is still internal. `extern` takes
        # priority: it means external linkage, and the invalid `extern static`
        # combo is treated as external (the reachability-conservative choice —
        # never under-claim reachability on malformed input).
        specs = [c.text.decode() for c in node.children
                 if c.type == "storage_class_specifier"]
        if "extern" in specs:
            visibility = "extern"
        elif "static" in specs:
            visibility = "static"

        # Go: exported from capitalisation, receiver as class_name
        if self.language == "go":
            if name and name[0].isupper():
                visibility = "exported"
            name_byte = None
            for child in node.children:
                if child.type == "field_identifier" or \
                   (child.type == "identifier" and child.text.decode() == name):
                    name_byte = child.start_byte
                    break
            if name_byte is not None:
                for child in node.children:
                    if child.type == "parameter_list" and child.start_byte < name_byte:
                        receiver_text = child.text.decode().strip("()")
                        parts = receiver_text.split()
                        if parts:
                            class_name = parts[-1].lstrip("*")

        # JS/TS: export statement wrapping
        parent = node.parent
        if parent and parent.type == "export_statement":
            visibility = "exported"

        return visibility, class_name

    def _get_name(self, node) -> Optional[str]:
        # C#: a method/ctor name is the identifier immediately BEFORE the
        # ``parameter_list`` — the identifiers before THAT are the return type
        # (``IActionResult GetAll()`` → ``GetAll``, not ``IActionResult``).
        if self.language == "csharp" and node.type in (
            "method_declaration", "constructor_declaration",
            "local_function_statement",
        ):
            plist = next(
                (c for c in node.children if c.type == "parameter_list"), None)
            sib = plist.prev_sibling if plist is not None else None
            while sib is not None:
                if sib.type in ("identifier", "name"):
                    return sib.text.decode()
                sib = sib.prev_sibling
        # ``type_identifier`` names a TS class/interface — but in a Java/TS
        # method it's the RETURN TYPE (``public String handle()``), which
        # precedes the method name, so only accept it on a class declaration.
        is_class_decl = node.type in (
            "class_declaration", "abstract_class_declaration",
            "interface_declaration",
            "class", "module",          # Ruby
        )
        for child in node.children:
            if child.type in ("identifier", "name"):
                return child.text.decode()
            # Ruby class/module name is a ``constant`` (the first one; a
            # superclass constant is nested inside the ``superclass`` node).
            if child.type == "constant" and is_class_decl:
                return child.text.decode()
            # JS/TS class method names are ``property_identifier`` (safe in any
            # node — no language puts a return type there). Without this, every
            # JS/TS class METHOD was silently dropped from the inventory.
            if child.type == "property_identifier":
                return child.text.decode()
            if child.type == "type_identifier" and is_class_decl:
                return child.text.decode()
            # C/C++: name is inside function_declarator
            if child.type == "function_declarator":
                return self._get_name(child)
            # C/C++: pointer-return functions wrap the
            # function_declarator inside a pointer_declarator. Without
            # this case, every `static char *foo(...)`-style decl is
            # silently dropped from the inventory — surfaced by
            # source_intel E2E on linux net/ (rc80211_minstrel_ht_debugfs.c
            # `minstrel_ht_stats_csv_dump`).
            if child.type == "pointer_declarator":
                return self._get_name(child)
            # Go: name is inside field_identifier for methods.
            # C++: same node type covers in-class method declarations
            # (``void f();`` inside a class body has its name as
            # field_identifier rather than identifier).
            if child.type == "field_identifier":
                return child.text.decode()
            # C++: out-of-line method definitions wrap the name in a
            # ``qualified_identifier`` (``Foo::bar``); return the
            # trailing component.
            if child.type == "qualified_identifier":
                # Walk to the rightmost name token. The grammar models
                # nested qualified_identifier with a trailing
                # identifier / field_identifier / destructor_name.
                last_name = None
                cur = child
                while cur is not None:
                    found_nested = False
                    for c in cur.children:
                        if c.type in ("identifier", "field_identifier"):
                            last_name = c.text.decode()
                        elif c.type == "destructor_name":
                            last_name = c.text.decode()
                        elif c.type == "qualified_identifier":
                            cur = c
                            found_nested = True
                            break
                    if not found_nested:
                        break
                if last_name:
                    return last_name
            # C++: destructor declaration / definition. ``~Foo()`` —
            # the declarator's child is a ``destructor_name`` whose
            # text includes the tilde.
            if child.type == "destructor_name":
                return child.text.decode()
            # C/C++: pointer return types wrap the declarator in
            # ``pointer_declarator``. Recurse to find the inner name.
            # Same for parenthesized_declarator used in some
            # complex C declarations.
            if child.type in ("pointer_declarator", "parenthesized_declarator"):
                inner = self._get_name(child)
                if inner:
                    return inner
        return None

    def _find_child(self, node, types: tuple):
        for child in node.children:
            if child.type in types:
                return child
        return None

    def _extract_parameters(self, node) -> List[Tuple[str, Optional[str]]]:
        params = []
        for child in node.children:
            if child.type in ("parameters", "formal_parameters", "parameter_list"):
                for param in child.children:
                    name, ptype = self._parse_param(param)
                    if name and name not in ("(", ")", ",", "self", "this"):
                        params.append((name, ptype))
            # C/C++: params are inside function_declarator → parameter_list
            if child.type == "function_declarator":
                params.extend(self._extract_parameters(child))
        return params

    def _parse_param(self, node) -> Tuple[Optional[str], Optional[str]]:
        """Extract (name, type) from a parameter node."""
        name = None
        ptype = None
        for child in node.children:
            if child.type in ("identifier", "name"):
                name = child.text.decode()
            elif child.type in ("type", "type_identifier", "generic_type",
                                "pointer_type", "array_type", "scoped_type_identifier",
                                "type_annotation", "primitive_type", "sized_type_specifier"):
                ptype = child.text.decode().lstrip(": ")
            # C: pointer declarator wraps the identifier
            elif child.type == "pointer_declarator":
                name = self._get_name(child)
                if ptype:
                    ptype += "*"
        # Fallback: parse the full text for typed params like "String data", "const char *buf"
        if not name and node.type in ("formal_parameter", "parameter_declaration"):
            text = node.text.decode().strip().rstrip(",")
            # Last token is the name (possibly with * prefix)
            parts = text.replace("*", "* ").split()
            if len(parts) >= 2:
                name = parts[-1].lstrip("*")
                ptype = " ".join(parts[:-1]).replace("  ", " ")
        # Anonymous parameter (e.g. C `void *` with no identifier,
        # `int(*)(void)` function-pointer typedef, or a forward-
        # declared function whose param has only a type). Pre-fix
        # `name` stayed as the empty string returned by the
        # tree-sitter walk, and downstream callers stored
        # `name=""` into the inventory's parameters list. The
        # resulting param record looked like
        # `{"name": "", "type": "void *"}` — call-graph lookups
        # then string-matched on `param["name"]` and matched the
        # empty-string param against any caller's empty-string
        # arg position, mis-pairing references.
        #
        # Use a positional sentinel `_anon` so consumers can tell
        # "anonymous" apart from "missing field" without a custom
        # null check at every callsite. Multiple anonymous params
        # in the same signature each get the same sentinel — that
        # matches the C semantic (they're indistinguishable
        # without re-emitting positional indices, which we don't
        # do here to keep the parameter shape stable).
        if not name and ptype:
            name = "_anon"
        return name, ptype

    def _extract_return_type(self, node) -> Optional[str]:
        # C/C++: return type is a sibling before the function_declarator
        func_decl_pos = None
        for i, child in enumerate(node.children):
            if child.type in ("function_declarator",):
                func_decl_pos = i
                break

        for i, child in enumerate(node.children):
            # Type node before the function declarator = return type
            if func_decl_pos is not None and i < func_decl_pos:
                if child.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                    return child.text.decode()
            # Java/Python/Go: type after params
            if child.type in ("type", "return_type"):
                return child.text.decode().lstrip(": ")
            if func_decl_pos is None and child.type in ("type_identifier", "generic_type",
                                                          "void_type", "pointer_type", "array_type"):
                params_seen = any(c.type in ("parameters", "formal_parameters", "parameter_list")
                                  for c in node.children if c.start_byte < child.start_byte)
                if params_seen:
                    return child.text.decode()
        return None


_cached_ts_languages: Optional[List[str]] = None


def _get_ts_languages() -> List[str]:
    """Return list of languages with tree-sitter grammars installed. Cached."""
    global _cached_ts_languages
    if _cached_ts_languages is not None:
        return _cached_ts_languages
    if not _TS_AVAILABLE:
        _cached_ts_languages = []
        return []
    available = []
    for lang in ("python", "java", "javascript", "c", "go"):
        if _ts_language(lang):
            available.append(lang)
    _cached_ts_languages = available
    return available


# ---------------------------------------------------------------------------
# Extractor registry and dispatch
# ---------------------------------------------------------------------------

# Regex-based extractors (always available)
_REGEX_EXTRACTORS = {
    'python': PythonExtractor(),
    'javascript': JavaScriptExtractor(),
    'typescript': JavaScriptExtractor(),
    'tsx': JavaScriptExtractor(),
    'csharp': GenericExtractor(),
    'ruby': GenericExtractor(),
    'c': CExtractor(),
    'cpp': CExtractor(),
    'java': JavaExtractor(),
    'go': GoExtractor(),
}


def extract_functions(filepath: str, language: str, content: str) -> List[FunctionInfo]:
    """Extract functions from a file using the best available extractor.

    Priority: tree-sitter (rich metadata) → Python AST → regex (basic).
    """
    # Try tree-sitter first (rich metadata for all languages)
    if _TS_AVAILABLE:
        try:
            extractor = TreeSitterExtractor(language)
            results = extractor.extract(filepath, content)
            if results:  # Empty = parse failed, fall through
                return results
        except RuntimeError:
            pass  # Grammar not installed for this language

    # Python AST (always available, has metadata)
    if language == "python":
        return PythonExtractor().extract(filepath, content)

    # Regex fallback (basic metadata)
    extractor = _REGEX_EXTRACTORS.get(language, GenericExtractor())
    return extractor.extract(filepath, content)


def compute_interstitial_items(
    items: List[CodeItem], content: str,
) -> List[CodeItem]:
    """Synthesise ``interstitial`` items for line ranges NOT inside any
    extracted item — the safety net that makes "every meaningful line belongs
    to a CodeItem" true (coverage-layer Decision #2), so non-function code
    (top-level statements, missed globals, file-scope logic) is never invisible
    to coverage. One item per contiguous gap; gaps with no non-blank line are
    skipped (pure blank-line runs aren't worth a coverage unit). Line numbers
    are 1-based, matching the extractors.
    """
    lines = content.splitlines()
    total = len(lines)
    if total == 0:
        return []
    covered = [False] * (total + 2)  # 1-based; index 0 and total+1 unused
    for it in items:
        lo = max(1, it.line_start or 0)
        hi = it.line_end if it.line_end is not None else it.line_start or lo
        for ln in range(lo, min(total, hi) + 1):
            covered[ln] = True

    out: List[CodeItem] = []
    ln = 1
    while ln <= total:
        if covered[ln]:
            ln += 1
            continue
        start = ln
        while ln <= total and not covered[ln]:
            ln += 1
        end = ln - 1
        if any(lines[i - 1].strip() for i in range(start, end + 1)):
            out.append(CodeItem(
                name=f"interstitial:{start}-{end}",
                kind=KIND_INTERSTITIAL,
                line_start=start,
                line_end=end,
            ))
    return out


def extract_items(filepath: str, language: str, content: str,
                  _tree_cache: dict = None) -> List[CodeItem]:
    """Extract all code items (functions + globals + macros) from a file.

    Parses with tree-sitter once (if available) and extracts functions,
    globals, and macros from the same parse tree. Falls back to
    AST/regex for functions if tree-sitter is unavailable.

    Args:
        _tree_cache: If provided, the parsed tree is stored under
            _tree_cache["tree"] for reuse by count_sloc.
    """
    items: List[CodeItem] = []

    # Try tree-sitter: single parse for functions + globals
    ts_parsed = False
    tree = None
    if _TS_AVAILABLE:
        try:
            extractor = TreeSitterExtractor(language)
            tree = extractor.parser.parse(content.encode())
            ts_parsed = True
        except (RuntimeError, Exception):
            pass

    if tree is not None:
        # Cache tree for reuse by count_sloc
        if _tree_cache is not None:
            _tree_cache["tree"] = tree

        # Functions from the parse tree
        try:
            functions = extractor.extract(filepath, content, _tree=tree)
            if functions:
                items.extend(functions)
        except Exception:
            pass  # Fall through to AST/regex fallback

        # Globals + module-scope executable code from the same parse tree
        try:
            items.extend(_extract_globals_ts(tree.root_node, language))
        except Exception:
            pass
        try:
            items.extend(_extract_top_level_ts(tree.root_node, language))
        except Exception:
            pass

    # Fallback: functions from AST/regex if tree-sitter didn't produce any
    if not ts_parsed or not any(i.kind == KIND_FUNCTION for i in items):
        if language == "python":
            # PythonExtractor (AST) re-derives functions AND top_level; drop any
            # tree-sitter-derived ones first to avoid duplicates (keep globals).
            items = [i for i in items
                     if i.kind not in (KIND_FUNCTION, KIND_TOP_LEVEL)]
            items.extend(PythonExtractor().extract(filepath, content))
        else:
            items = [i for i in items if i.kind != KIND_FUNCTION]
            extractor = _REGEX_EXTRACTORS.get(language, GenericExtractor())
            items.extend(extractor.extract(filepath, content))

    # C/C++ macro extraction (regex — tree-sitter doesn't parse preprocessor)
    if language in ("c", "cpp"):
        items.extend(_extract_macros_regex(content))

    return items


_TOP_LEVEL_LANGS = ("python", "javascript", "typescript", "tsx")
_CALL_NODE_TYPES = ("call", "call_expression")
_ASSIGN_NODE_TYPES = ("assignment", "assignment_expression", "augmented_assignment")


def _ts_contains_call(node, depth: int = 0) -> bool:
    if node.type in _CALL_NODE_TYPES:
        return True
    if depth > 5:
        return False
    return any(_ts_contains_call(c, depth + 1) for c in node.children)


def _extract_top_level_ts(root_node, language: str) -> List[CodeItem]:
    """Module-scope executable statements (run at import) as ``top_level`` items
    — a root-level ``expression_statement`` containing a call but not an
    assignment (assignments are globals). Captures the security-relevant case
    (``os.system(...)`` / ``eval(...)`` at module scope) as a named, reviewable
    unit instead of anonymous interstitial. Script-like languages only."""
    if language not in _TOP_LEVEL_LANGS:
        return []
    out: List[CodeItem] = []
    for child in root_node.children:
        if child.type != "expression_statement":
            continue
        if any(c.type in _ASSIGN_NODE_TYPES for c in child.children):
            continue
        if _ts_contains_call(child):
            out.append(CodeItem(
                name=f"top_level:{child.start_point[0] + 1}",
                kind=KIND_TOP_LEVEL,
                line_start=child.start_point[0] + 1,
                line_end=child.end_point[0] + 1,
            ))
    return out


def _extract_globals_ts(root_node, language: str) -> List[CodeItem]:
    """Extract global variables/constants from a tree-sitter parse tree."""
    globals_found = []

    # Node types for global declarations per language
    global_types = {
        "python": ("expression_statement", "assignment"),
        "javascript": ("lexical_declaration", "variable_declaration"),
        "typescript": ("lexical_declaration", "variable_declaration"),
        "tsx": ("lexical_declaration", "variable_declaration"),
        "c": ("declaration",),
        "cpp": ("declaration",),
        "java": ("field_declaration",),
        "go": ("var_declaration", "const_declaration"),
    }

    target_types = global_types.get(language, ())

    # Java field_declarations live INSIDE class_body, not at the root.
    # Pre-fix iterating `root_node.children` and matching against
    # `field_declaration` returned ZERO Java fields — every Java
    # source's class fields were silently absent from the inventory.
    # Walk into class/interface bodies to find them. Other languages
    # (C/C++/Go/Python/JS/TS) declare globals at file scope, so the
    # default direct-children walk is correct for them.
    if language == "java":
        scan_nodes = []
        for top in root_node.children:
            if top.type in ("class_declaration", "interface_declaration",
                             "enum_declaration", "record_declaration"):
                # Find the body node and walk its children for fields.
                body = next(
                    (c for c in top.children if c.type in ("class_body", "interface_body",
                                                            "enum_body", "record_body")),
                    None,
                )
                if body is not None:
                    scan_nodes.extend(body.children)
            else:
                scan_nodes.append(top)
    else:
        scan_nodes = root_node.children

    for child in scan_nodes:
        if child.type not in target_types:
            continue

        # Only top-level declarations (not inside functions/classes).
        # Emit ONE CodeItem per spec for languages that allow grouped
        # declarations. Pre-fix `_global_name` returned a single
        # name even for `var ( a int; b string; c bool )` — only
        # `a` made it into the inventory; `b`, `c` were silently
        # dropped. `_global_names` (plural) yields every name in
        # the declaration. Falls back to the single-name path for
        # languages where multi-spec isn't a thing.
        names = _global_names(child, language)
        for name in names:
            if name:
                globals_found.append(CodeItem(
                    name=name,
                    kind=KIND_GLOBAL,
                    line_start=child.start_point[0] + 1,
                    line_end=child.end_point[0] + 1,
                ))

    return globals_found


def _global_names(node, language: str):
    """Yield every global name in a declaration node.

    Most languages only declare one global per node — for those, the
    legacy `_global_name` single-result is fine. Go's `var ( ... )`
    and `const ( ... )` blocks declare multiple specs in a single
    syntactic node; this helper yields every spec's name.

    Python's chained assignment (`A = B = 1`) is a single
    `assignment` node with multiple identifier children on the LHS
    before the value. Pre-fix `_global_name` returned only the first
    identifier ("A"), so chained constants were silently
    half-recorded — `B` never made the inventory and downstream
    coverage / lookup tools couldn't find it.
    """
    if language == "go":
        for child in node.children:
            if child.type == "var_spec" or child.type == "const_spec":
                for sub in child.children:
                    if sub.type == "identifier":
                        yield sub.text.decode()
        return

    if language == "python":
        # Unwrap expression_statement → assignment if needed.
        target = node
        if target.type == "expression_statement":
            target = next(
                (c for c in target.children if c.type == "assignment"),
                None,
            )
        if target is not None and target.type == "assignment":
            # Tree-sitter Python represents chained assignment
            # `A = B = C = 1` as NESTED assignments (NOT flat):
            #   assignment(identifier "A", "=",
            #     assignment(identifier "B", "=",
            #       assignment(identifier "C", "=", integer "1")))
            #
            # Pre-fix this code assumed a FLAT shape and only saw
            # the FIRST identifier. Walk the chain recursively:
            # at each nesting level, yield the leading identifier
            # children (the LHS targets), then descend into the
            # RHS if it's another assignment node. Stops when the
            # RHS is the actual value (integer / call / etc.).
            current = target
            while current is not None and current.type == "assignment":
                # Collect identifiers BEFORE the first `=` — these
                # are the LHS targets at THIS nesting level.
                # Apply the same uppercase/TitleCase filter as
                # `_global_name` to avoid emitting locals.
                next_assignment = None
                for c in current.children:
                    if c.type == "identifier":
                        nm = c.text.decode()
                        if nm and (nm.isupper() or (nm[0].isupper() and not nm.islower())):
                            yield nm
                    elif c.type == "assignment":
                        # Found the nested chain RHS — descend.
                        next_assignment = c
                        break
                current = next_assignment
            return

    # Other languages: defer to the single-name function.
    name = _global_name(node, language)
    if name:
        yield name


def _c_declarator_name(node, depth: int = 0) -> Optional[str]:
    """Descend C/C++ declarator wrappers to the declared identifier. Returns the
    first identifier found, or None.

    For ``init_declarator`` only the declarator side is followed, never the RHS
    init value — otherwise ``int (*handler)(int) = foo;`` would return the
    initializer ``foo`` (the declared name ``handler`` is nested in the
    function-pointer declarator). The pointer/parenthesized recursion still
    reaches the real name (function-pointer *variables* declare a name;
    plain function prototypes are rejected earlier by the function_declarator
    guard on the declaration's direct children)."""
    if depth > 6:
        return None
    if node.type == "identifier":            # the declarator IS the name
        return node.text.decode()
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode()
        if child.type == "init_declarator":
            decl = child.child_by_field_name("declarator")
            if decl is None and child.children:
                decl = child.children[0]
            name = _c_declarator_name(decl, depth + 1) if decl is not None else None
            if name:
                return name
        elif child.type in ("array_declarator", "pointer_declarator",
                            "parenthesized_declarator", "function_declarator"):
            name = _c_declarator_name(child, depth + 1)
            if name:
                return name
    return None


def _global_name(node, language: str) -> Optional[str]:
    """Extract the name from a global declaration node."""
    if language == "python":
        # assignment: NAME = ...
        # Heuristic: only capture ALL_CAPS (constants like MAX_SIZE) and
        # TitleCase (class-like globals like MyConfig). Lowercase assignments
        # (x = 1) are too noisy — most are local-style module variables.
        if node.type == "expression_statement":
            for child in node.children:
                if child.type == "assignment":
                    return _global_name(child, language)
        if node.type == "assignment":
            left = node.children[0] if node.children else None
            if left and left.type == "identifier":
                name = left.text.decode()
                if name.isupper() or (name[0].isupper() and not name.islower()):
                    return name
        return None

    if language in ("javascript", "typescript", "tsx"):
        for child in node.children:
            if child.type == "variable_declarator":
                for sub in child.children:
                    if sub.type in ("identifier", "name"):
                        return sub.text.decode()
        return None

    if language in ("c", "cpp"):
        # declaration: type name = ...; or type name;
        # Skip function declarations (have a function_declarator child)
        for child in node.children:
            if child.type == "function_declarator":
                return None
        # Descend declarator wrappers to the identifier. Pre-fix this only
        # handled init_declarator/bare identifier, so array globals
        # (`char g_buf[8]` → array_declarator) and pointer globals
        # (`char *p` → pointer_declarator) were missed and fell to
        # interstitial. Recursion catches the common wrapped forms; exotic
        # shapes (multi-declarator, function-pointer) remain unclassified.
        return _c_declarator_name(node)

    if language == "java":
        for child in node.children:
            if child.type == "variable_declarator":
                for sub in child.children:
                    if sub.type == "identifier":
                        return sub.text.decode()
        return None

    if language == "go":
        for child in node.children:
            if child.type == "var_spec" or child.type == "const_spec":
                for sub in child.children:
                    if sub.type == "identifier":
                        return sub.text.decode()
        return None

    return None


def _extract_macros_regex(content: str) -> List[CodeItem]:
    """Extract C/C++ #define macros via regex.

    Captures all #define directives including include guards. Include guards
    are legitimate code items — they're part of the file's structure.
    """
    macros = []
    # `re.ASCII` so `\w` matches only ASCII word chars. C identifiers
    # are ASCII per the spec; without the flag, Python's `\w` admits
    # Unicode word characters (Cyrillic, Greek, etc.). A hostile or
    # confused source dropping a non-ASCII identifier through a
    # `#define` would have its name captured here and surfaced into
    # the inventory under a homoglyph that matches a real ASCII
    # identifier — confusing greps + downstream cross-references.
    _DEFINE_RE = re.compile(r'^\s*#\s*define\s+(\w+)', re.ASCII)
    for i, line in enumerate(content.splitlines(), 1):
        m = _DEFINE_RE.match(line)
        if m:
            macros.append(CodeItem(
                name=m.group(1),
                kind=KIND_MACRO,
                line_start=i,
                line_end=i,
            ))
    return macros


# ---------------------------------------------------------------------------
# SLOC counting
# ---------------------------------------------------------------------------

def count_sloc(content: str, language: str, _tree=None) -> int:
    """Count source lines of code (non-blank, non-comment).

    Uses tree-sitter to identify comments when available,
    falls back to regex-based comment detection.

    Args:
        _tree: Optional pre-parsed tree-sitter tree (from extract_items).
    """
    lines = content.splitlines()
    total = len(lines)
    blank = sum(1 for line in lines if not line.strip())

    # Use cached tree if provided
    if _tree is not None:
        comment_lines = _count_comment_lines_ts(_tree.root_node)
        return max(0, total - blank - comment_lines)

    if _TS_AVAILABLE:
        try:
            parser = _ts_parser_for(language)
            if parser is not None:
                tree = parser.parse(content.encode())
                comment_lines = _count_comment_lines_ts(tree.root_node)
                return max(0, total - blank - comment_lines)
        except Exception:
            pass

    # Regex fallback
    comment_lines = _count_comment_lines_regex(content, language)
    return max(0, total - blank - comment_lines)


def _count_comment_lines_ts(node) -> int:
    """Count lines occupied by comment nodes in a tree-sitter tree."""
    comment_lines = set()
    _collect_comment_lines(node, comment_lines)
    return len(comment_lines)


def _collect_comment_lines(node, comment_lines: set, code_lines: set = None) -> None:
    """Recursively collect line numbers that are comment-only.

    A line counts as comment-only if it contains a comment but no code.
    Lines like `int x = 1; // init` are code lines, not comment lines.
    """
    if code_lines is None:
        code_lines = set()
        # First pass: collect all lines that have non-comment nodes
        _collect_code_lines(node, code_lines)

    if node.type in ("comment", "line_comment", "block_comment"):
        for line in range(node.start_point[0], node.end_point[0] + 1):
            if line not in code_lines:
                comment_lines.add(line)
    for child in node.children:
        _collect_comment_lines(child, comment_lines, code_lines)


def _collect_code_lines(node, code_lines: set) -> None:
    """Collect line numbers that have non-comment, non-whitespace nodes."""
    if node.type not in ("comment", "line_comment", "block_comment") and not node.children:
        # Leaf node that isn't a comment — it's code
        if node.text and node.text.strip():
            for line in range(node.start_point[0], node.end_point[0] + 1):
                code_lines.add(line)
    for child in node.children:
        _collect_code_lines(child, code_lines)


def _count_comment_lines_regex(content: str, language: str) -> int:
    """Count comment lines using regex. Best-effort fallback.

    Limitations: does not detect Python triple-quoted docstrings as
    non-code. Tree-sitter handles this correctly — use it when available.
    """
    count = 0
    in_block = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if language == "python":
            if stripped.startswith("#"):
                count += 1
        elif language in ("c", "cpp", "java", "javascript", "typescript", "tsx", "go"):
            # State-machine comment-walk per line so the in_block
            # state tracks every `/*` open and `*/` close on the
            # line, including the `*/ /* still open` shape where a
            # line closes a block and immediately opens a new one.
            # Pre-fix the simple `if "*/" in stripped` close-check
            # missed the re-open: in_block became False at line end,
            # then every subsequent code line (which was actually
            # inside the new block) was mis-counted as code until
            # the eventual real `*/` arrived. Wallclock-cheap: each
            # line scan is O(line_length).
            entered_in_block = in_block
            i = 0
            while i < len(stripped):
                if in_block:
                    j = stripped.find("*/", i)
                    if j < 0:
                        break
                    in_block = False
                    i = j + 2
                else:
                    j = stripped.find("/*", i)
                    if j < 0:
                        break
                    in_block = True
                    i = j + 2
            # Count the line iff it starts inside a block, starts
            # with `//`, or starts with `/*`.
            if (entered_in_block
                or stripped.startswith("//")
                or stripped.startswith("/*")):
                count += 1
    return count
