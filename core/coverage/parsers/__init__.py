"""External/runtime coverage parsers (Phase 4).

Each parser reads a runtime-coverage artifact and returns
``{source_path: set(executed_line_numbers)}``. The importer
(:func:`core.coverage.importer.import_runtime`) normalises those paths to the
inventory's keys and marks them in the store under a runtime tool label, so the
``runtime`` category/depth in the unified report lights up.

Formats: ``coverage.py`` (the ``coverage json`` report), ``gcov`` (raw
``.gcov``), ``lcov`` (``.info``). AFL bitmap→source is a planned follow-on.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set

from .coverage_py import parse_coverage_py
from .gcov import parse_gcov, parse_lcov

# format name -> (parser, default tool label)
_PARSERS = {
    "coverage.py": (parse_coverage_py, "coverage.py"),
    "gcov": (parse_gcov, "gcov"),
    "lcov": (parse_lcov, "lcov"),
}


def detect_format(path) -> Optional[str]:
    """Best-effort format detection from a file or directory path. None when
    nothing recognisable is present."""
    p = Path(path)
    if p.is_dir():
        if (p / "coverage.json").exists():
            return "coverage.py"
        if any(p.glob("*.gcov")):
            return "gcov"
        if any(p.glob("*.info")):
            return "lcov"
        return None
    name = p.name
    if name == "coverage.json":
        return "coverage.py"
    if name.endswith(".gcov"):
        return "gcov"
    if name.endswith(".info"):
        return "lcov"
    return None


def parse(path, fmt: Optional[str] = None) -> Dict[str, Set[int]]:
    """Parse ``path`` (auto-detecting the format if not given) into
    ``{source_path: set(executed_lines)}``. ``{}`` if unrecognised."""
    fmt = fmt or detect_format(path)
    if fmt not in _PARSERS:
        return {}
    return _PARSERS[fmt][0](path)


def default_tool(fmt: Optional[str]) -> Optional[str]:
    """The default store tool label for a format (runtime-category)."""
    return _PARSERS[fmt][1] if fmt in _PARSERS else None


def available_formats() -> List[str]:
    return sorted(_PARSERS)
