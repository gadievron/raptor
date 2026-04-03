"""Language-aware function extraction.

AST-based for Python, tree-sitter when available, regex fallback.

Security metadata (decorators, annotations, visibility, types) is captured
in FunctionMetadata. See docs/design-inventory-metadata.md for design rationale.
"""

import ast
import re
import logging
import warnings
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


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


@dataclass
class FunctionInfo:
    """Information about an extracted function."""
    name: str
    line_start: int
    line_end: Optional[int] = None
    signature: Optional[str] = None
    checked_by: List[str] = field(default_factory=list)
    metadata: Optional[FunctionMetadata] = None

    def to_dict(self) -> dict:
        """Serialise for checklist.json."""
        d = {
            "name": self.name,
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
        except SyntaxError as e:
            logger.warning(f"Failed to parse {filepath}: {e}")
            functions = self._regex_fallback(content)

        return functions

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

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        seen = set()

        for i, line in enumerate(content.split('\n'), 1):
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

    ANSI_PATTERN = r'^(?:[\w\s\*]+)\s+(\w+)\s*\([^;]*\)\s*\{'
    ANSI_SPLIT_PATTERN = r'^(?:[\w\s\*]+)\s+(\w+)\s*\([^;{]*\)\s*$'
    KNR_FUNCNAME = r'^(\w+)\s*\([\w\s,]*\)\s*$'
    FUNCNAME_OPEN_PAREN = r'^(\w+)\s*\([^)]*$'

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
            visibility = None
            type_words = []
            for w in words:
                w = w.strip("*")
                if w in self.STORAGE_CLASSES:
                    visibility = w
                elif w in self.C_TYPE_HINTS or w not in self.KEYWORDS:
                    type_words.append(w)
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

            i += 1

        return functions


class JavaExtractor:
    """Extract methods from Java files using regex.

    Metadata: class_name, visibility, return_type, parameters (typed).
    Missing without tree-sitter: annotations (@RequestMapping etc).
    """

    PATTERN = r'((?:public|private|protected|static|\s)+)([\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{'

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        current_class = None

        for i, line in enumerate(content.split('\n'), 1):
            # Track class scope
            class_match = re.search(r'class\s+(\w+)', line)
            if class_match:
                current_class = class_match.group(1)

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

    PATTERN = r'^func\s+(?:\((\w+)\s+(\*?\w+)\)\s+)?(\w+)\s*\('

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []

        for i, line in enumerate(content.split('\n'), 1):
            match = re.match(self.PATTERN, line)
            if match:
                receiver_name = match.group(1)  # e.g. "s"
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


def _ts_language(lang: str):
    """Load tree-sitter language grammar. Returns None if not installed."""
    try:
        if lang == "python":
            import tree_sitter_python as ts
        elif lang == "java":
            import tree_sitter_java as ts
        elif lang in ("javascript", "typescript"):
            import tree_sitter_javascript as ts
        elif lang in ("c", "cpp"):
            import tree_sitter_c as ts
        elif lang == "go":
            import tree_sitter_go as ts
        else:
            return None
        return Language(ts.language())
    except ImportError:
        return None


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
        "c": ("function_definition",),
        "cpp": ("function_definition",),
        "go": ("function_declaration", "method_declaration"),
    }

    _CLASS_TYPES = {
        "python": ("class_definition",),
        "java": ("class_declaration", "interface_declaration"),
        "javascript": ("class_declaration",),
        "typescript": ("class_declaration",),
        "c": (),
        "cpp": ("class_specifier", "struct_specifier"),
        "go": (),
    }

    def __init__(self, language: str):
        self.language = language
        self.func_types = self._FUNC_TYPES.get(language, ())
        self.class_types = self._CLASS_TYPES.get(language, ())
        ts_lang = _ts_language(language)
        if not ts_lang:
            raise RuntimeError(f"tree-sitter grammar not available for {language}")
        self.parser = TSParser(ts_lang)

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        try:
            tree = self.parser.parse(content.encode())
        except Exception as e:
            logger.warning(f"tree-sitter parse failed for {filepath}: {e}")
            return []  # Caller will fall back to regex extractor
        functions = []
        self._walk(tree.root_node, functions, class_name=None)
        return functions

    def _walk(self, node, functions: List[FunctionInfo], class_name: Optional[str]) -> None:
        for child in node.children:
            if child.type in self.class_types:
                cname = self._get_name(child)
                self._walk(child, functions, class_name=cname)
            elif child.type in ("lexical_declaration", "variable_declaration"):
                # JS/TS: const foo = () => {} — arrow function inside variable declaration
                self._walk(child, functions, class_name=class_name)
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
                self._walk(child, functions, class_name=class_name)
                continue
            elif child.type in self.func_types:
                # Check for decorated_definition wrapper (Python)
                attrs = []
                parent = child.parent
                if parent and parent.type == "decorated_definition":
                    for sib in parent.children:
                        if sib.type == "decorator":
                            attrs.append(sib.text.decode().lstrip("@"))
                    child = self._find_child(parent, self.func_types) or child

                try:
                    fi = self._extract_function(child, class_name, attrs)
                    if fi:
                        functions.append(fi)
                except Exception as e:
                    logger.debug(f"tree-sitter: failed to extract function at line {child.start_point[0]+1}: {e}")
                self._walk(child, functions, class_name=class_name)
            elif child.type == "decorated_definition":
                # Python: walk into decorated definitions
                self._walk(child, functions, class_name=class_name)
            else:
                self._walk(child, functions, class_name=class_name)

    def _extract_function(self, node, class_name: Optional[str],
                          attrs: List[str]) -> Optional[FunctionInfo]:
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
            ),
        )

    def _extract_visibility(self, node, name: str, class_name: Optional[str],
                            attrs: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """Extract visibility and update class_name. Returns (visibility, class_name)."""
        visibility = None

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

        # C/C++: storage class specifier
        for child in node.children:
            if child.type == "storage_class_specifier":
                visibility = child.text.decode()

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
        for child in node.children:
            if child.type in ("identifier", "name"):
                return child.text.decode()
            # C/C++: name is inside function_declarator
            if child.type == "function_declarator":
                return self._get_name(child)
            # Go: name is inside field_identifier for methods
            if child.type == "field_identifier":
                return child.text.decode()
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
