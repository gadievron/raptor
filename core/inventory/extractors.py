"""Language-aware function extraction.

AST-based for Python, regex-based for other languages.
"""

import ast
import re
import logging
import warnings
from typing import List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    """Information about an extracted function."""
    name: str
    line_start: int
    line_end: Optional[int] = None
    signature: Optional[str] = None
    checked_by: List[str] = field(default_factory=list)


class PythonExtractor:
    """Extract functions from Python files using AST."""

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = [arg.arg for arg in node.args.args]

                    signature = f"def {node.name}({', '.join(args)})"
                    if isinstance(node, ast.AsyncFunctionDef):
                        signature = "async " + signature

                    functions.append(FunctionInfo(
                        name=node.name,
                        line_start=node.lineno,
                        line_end=node.end_lineno if hasattr(node, 'end_lineno') else None,
                        signature=signature,
                    ))
        except SyntaxError as e:
            logger.warning(f"Failed to parse {filepath}: {e}")
            functions = self._regex_fallback(content)

        return functions

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
    """Extract functions from JavaScript/TypeScript files using regex."""

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
                        functions.append(FunctionInfo(name=name, line_start=i))
                        seen.add(name)
                    break

        return functions


class CExtractor:
    """Extract functions from C/C++ files using regex.

    Handles both ANSI C and K&R style function definitions.
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
                    functions.append(FunctionInfo(name=name, line_start=i + 1))
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
    """Extract methods from Java files using regex."""

    PATTERN = r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []

        for i, line in enumerate(content.split('\n'), 1):
            match = re.search(self.PATTERN, line)
            if match:
                name = match.group(1)
                if name not in ('if', 'for', 'while', 'switch', 'try', 'catch'):
                    functions.append(FunctionInfo(name=name, line_start=i))

        return functions


class GoExtractor:
    """Extract functions from Go files using regex."""

    PATTERN = r'^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\('

    def extract(self, filepath: str, content: str) -> List[FunctionInfo]:
        functions = []

        for i, line in enumerate(content.split('\n'), 1):
            match = re.match(self.PATTERN, line)
            if match:
                functions.append(FunctionInfo(name=match.group(1), line_start=i))

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


# Extractor registry
EXTRACTORS = {
    'python': PythonExtractor(),
    'javascript': JavaScriptExtractor(),
    'typescript': JavaScriptExtractor(),
    'c': CExtractor(),
    'cpp': CExtractor(),
    'java': JavaExtractor(),
    'go': GoExtractor(),
}


def extract_functions(filepath: str, language: str, content: str) -> List[FunctionInfo]:
    """Extract functions from a file using the appropriate language extractor."""
    extractor = EXTRACTORS.get(language, GenericExtractor())
    return extractor.extract(filepath, content)
