"""Test discovery for spec inference.

Maps functions to their test cases by scanning test directories for
naming patterns and call references. Tests are executable specifications:
the assertions encode postconditions.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Sequence

logger = logging.getLogger(__name__)

_TEST_DIR_PATTERNS = ("test_", "tests", "test", "spec", "specs")
_TEST_FILE_PATTERNS = re.compile(r"(?:test_\w+|_test)\.\w+$")
_ASSERT_PATTERN = re.compile(
    r"^\s*(?:assert(?:Equal|True|False|Raises|In|NotIn|Is|IsNot|Greater|Less"
    r"|Regex|Almost|Count|Contains|Not)?|self\.assert\w+|expect\(|assert )"
    r"(.+)",
    re.MULTILINE,
)
_TEST_FUNC_PATTERN = re.compile(
    r"(?:def|function|fn|func)\s+(test_\w+)",
)


@dataclass
class TestCase:
    """A test case that exercises a target function."""

    test_file: str
    test_function: str
    target_function: str
    assertions: List[str] = field(default_factory=list)


def discover_tests(
    target_path: Path,
) -> Dict[str, List[TestCase]]:
    """Discover test cases and map them to target functions.

    Walks test directories and finds tests by:
    (a) test_<function_name> naming convention
    (b) direct function call references in test bodies

    Returns {function_name → [TestCase]} map.
    """
    target = Path(target_path).resolve()
    if not target.is_dir():
        return {}

    test_files = _find_test_files(target)
    if not test_files:
        return {}

    result: Dict[str, List[TestCase]] = {}

    for test_file in test_files:
        rel_path = str(test_file.relative_to(target))
        try:
            source = test_file.read_text(errors="replace")
        except OSError:
            continue

        test_funcs = _extract_test_functions(source)
        for test_func_name, test_body in test_funcs:
            targets = _infer_target_functions(test_func_name, test_body)
            assertions = _extract_assertions(test_body)

            for target_fn in targets:
                tc = TestCase(
                    test_file=rel_path,
                    test_function=test_func_name,
                    target_function=target_fn,
                    assertions=assertions[:10],
                )
                result.setdefault(target_fn, []).append(tc)

    logger.info(
        "test_discovery: found %d test cases for %d functions in %d files",
        sum(len(v) for v in result.values()),
        len(result),
        len(test_files),
    )

    return result


def format_tests_for_context(
    tests: Sequence[TestCase],
    depth: str = "oneline",
) -> str:
    """Render test case summaries for LLM context injection."""
    if not tests:
        return ""

    if depth == "oneline":
        assertion_count = sum(len(t.assertions) for t in tests)
        return (
            f"{len(tests)} test(s) found "
            f"({assertion_count} assertions total)."
        )

    lines = [f"**{len(tests)} test(s):**"]
    for t in tests[:5]:
        lines.append(f"- `{t.test_function}` in `{t.test_file}`")
        for a in t.assertions[:3]:
            lines.append(f"  - assert: {a}")

    return "\n".join(lines)


def _find_test_files(target: Path) -> List[Path]:
    """Find test files under the target directory."""
    test_files: List[Path] = []

    for root, dirs, files in os.walk(str(target)):
        root_path = Path(root)
        rel = root_path.relative_to(target)
        parts = rel.parts

        if any(p.startswith(".") for p in parts):
            continue
        if "node_modules" in parts or "vendor" in parts:
            continue

        is_test_dir = any(
            any(part.startswith(pat) or part == pat for pat in _TEST_DIR_PATTERNS)
            for part in parts
        )

        for fname in files:
            if not fname.endswith((".py", ".js", ".ts", ".go", ".rs", ".rb", ".java")):
                continue
            if is_test_dir or _TEST_FILE_PATTERNS.search(fname):
                fpath = root_path / fname
                if fpath.stat().st_size < 500_000:
                    test_files.append(fpath)

    return test_files[:500]


def _extract_test_functions(source: str) -> List[tuple]:
    """Extract test function names and their bodies from source."""
    results = []

    func_starts = list(_TEST_FUNC_PATTERN.finditer(source))
    for i, match in enumerate(func_starts):
        name = match.group(1)
        start = match.start()
        end = func_starts[i + 1].start() if i + 1 < len(func_starts) else len(source)
        body = source[start:min(end, start + 5000)]
        results.append((name, body))

    return results


def _infer_target_functions(
    test_name: str,
    test_body: str,
) -> List[str]:
    """Infer which function(s) a test exercises.

    Uses naming convention: test_<function_name>[_suffix].
    """
    targets = []

    stripped = test_name
    if stripped.startswith("test_"):
        stripped = stripped[5:]

    for suffix in ("_success", "_failure", "_error", "_empty",
                   "_null", "_valid", "_invalid", "_basic",
                   "_edge_case", "_boundary", "_negative"):
        if stripped.endswith(suffix):
            stripped = stripped[:len(stripped) - len(suffix)]
            break

    if stripped and len(stripped) >= 2:
        targets.append(stripped)

    calls = re.findall(r"(\w{2,})\s*\(", test_body)
    for call in calls:
        if (
            call in test_body
            and not call.startswith("test_")
            and not call.startswith("assert")
            and not call.startswith("self")
            and call not in ("print", "len", "str", "int", "list",
                             "dict", "set", "range", "type", "isinstance",
                             "hasattr", "getattr", "setattr", "super",
                             "True", "False", "None", "mock", "patch",
                             "fixture", "parametrize", "raises", "warns",
                             "mark", "skip", "xfail")
            and call not in targets
        ):
            targets.append(call)
            if len(targets) >= 5:
                break

    return targets


def _extract_assertions(body: str) -> List[str]:
    """Extract assertion statements from a test body."""
    assertions = []

    for match in _ASSERT_PATTERN.finditer(body):
        assertion_text = match.group(0).strip()
        assertion_text = assertion_text[:120]
        assertions.append(assertion_text)
        if len(assertions) >= 10:
            break

    return assertions
