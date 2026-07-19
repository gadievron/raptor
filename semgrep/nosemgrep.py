"""Extract nosemgrep inline-suppression annotations from source files.

Semgrep's ``# nosemgrep`` comments let developers suppress specific rules
on a per-line basis.  RAPTOR always scans with ``--disable-nosem`` so
that suppressed findings still reach the SARIF output.  This module
post-annotates those results with the developer's suppression metadata so
downstream consumers (Claude, /validate, external SARIF viewers) can see
that a finding was developer-suppressed — and optionally read the
justification text.

Public API:

    annotate_sarif(sarif_data, repo_root)
        Mutates *sarif_data* in place: each result whose source line (or the
        line above) carries a nosemgrep comment gets a ``properties.nosemgrep``
        dict with ``suppressed``, ``rule_ids``, ``justification``, and
        ``comment_line``.  Returns the count of annotated results.

    extract_nosemgrep(file_path, line)
        Low-level: check a single source location for a nosemgrep comment.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Matches nosemgrep comments in any common style:
#   # nosemgrep: rule-id1, rule-id2 justification text
#   // nosemgrep: rule-id
#   /* nosemgrep */
#   // nosemgrep
_NOSEMGREP_RE = re.compile(
    r"""(?://|[#]|/\*)       # comment opener
        \s*nosemgrep         # keyword
        (?::[ \t]*           # optional colon + rule list
          ([\w.:,/-]+)       # group 1: comma-separated rule IDs
        )?
        (?:[ \t]+(.+?))?     # group 2: justification text
        (?:\s*\*/)?          # optional block-comment closer
        \s*$""",
    re.VERBOSE,
)

# Cache: path → list-of-lines (avoids re-reading the same file for
# multiple findings in it).  Scoped to a single annotate_sarif() call
# via the _FileCache helper.
_MAX_CACHE_FILES = 512


class _FileCache:
    """LRU-ish file cache for source lines, scoped to one annotation pass."""

    __slots__ = ("_store",)

    def __init__(self) -> None:
        self._store: Dict[str, Optional[List[str]]] = {}

    def lines(self, path: str) -> Optional[List[str]]:
        if path in self._store:
            return self._store[path]
        if len(self._store) >= _MAX_CACHE_FILES:
            # Evict oldest entry (insertion-order dict).
            self._store.pop(next(iter(self._store)))
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            result = text.splitlines()
        except OSError:
            result = None
        self._store[path] = result
        return result


def extract_nosemgrep(
    file_path: Path,
    line: int,
    *,
    _lines: Optional[List[str]] = None,
) -> Optional[dict]:
    """Check whether *line* (1-indexed) in *file_path* has a nosemgrep comment.

    Checks the flagged line itself and the line immediately above it (both
    are valid nosemgrep positions per Semgrep's spec).

    Returns a dict ``{suppressed, rule_ids, justification, comment_line}``
    if found, ``None`` otherwise.
    """
    if _lines is None:
        try:
            _lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None

    for offset in (0, -1):
        idx = line - 1 + offset  # 1-indexed → 0-indexed
        if 0 <= idx < len(_lines):
            m = _NOSEMGREP_RE.search(_lines[idx])
            if m:
                # A nosemgrep on the line ABOVE only suppresses the line
                # below when it's a standalone comment (no code before it).
                # Inline nosemgrep (code + comment on same line) only
                # suppresses that line itself.
                if offset == -1:
                    stripped = _lines[idx].lstrip()
                    if not (
                        stripped.startswith("#")
                        or stripped.startswith("//")
                        or stripped.startswith("/*")
                    ):
                        continue
                raw_ids = m.group(1) or ""
                justification = (m.group(2) or "").strip() or None
                rule_ids = [
                    r.strip() for r in raw_ids.split(",") if r.strip()
                ]
                return {
                    "suppressed": True,
                    "rule_ids": rule_ids,
                    "justification": justification,
                    "comment_line": idx + 1,
                }
    return None


def annotate_sarif(sarif_data: dict, repo_root: str) -> int:
    """Annotate SARIF results in place with nosemgrep suppression metadata.

    For each result whose source line carries a ``# nosemgrep`` comment,
    sets ``result["properties"]["nosemgrep"]`` to a dict with:
      - ``suppressed`` (bool): always True
      - ``rule_ids`` (list[str]): rule IDs named in the comment, or []
      - ``justification`` (str | null): free-text after the rule IDs
      - ``comment_line`` (int): 1-indexed line of the comment

    Returns the number of results annotated.
    """
    root = Path(repo_root)
    cache = _FileCache()
    annotated = 0

    for run in sarif_data.get("runs", []):
        if not isinstance(run, dict):
            continue
        # nosemgrep is Semgrep-specific — skip CodeQL/Coccinelle runs.
        tool_name = (
            run.get("tool", {}).get("driver", {}).get("name", "")
        ).lower()
        if tool_name and "semgrep" not in tool_name:
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            if not locations:
                continue
            loc = locations[0]
            if not isinstance(loc, dict):
                continue
            phys = loc.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)
            if not uri or not line:
                continue

            # Resolve the file path against repo root.
            if uri.startswith("file://"):
                abs_path = uri[7:]
            else:
                abs_path = str(root / uri)

            lines = cache.lines(abs_path)
            if lines is None:
                continue

            info = extract_nosemgrep(Path(abs_path), line, _lines=lines)
            if info:
                props = result.setdefault("properties", {})
                props["nosemgrep"] = info
                annotated += 1

    if annotated:
        logger.info(
            "nosemgrep: annotated %d SARIF result(s) as developer-suppressed",
            annotated,
        )
    return annotated
