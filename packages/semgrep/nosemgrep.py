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

from core.paths import confine, strip_file_uri
from core.source import read_text_capped

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
        self._store: dict[str, list[str] | None] = {}

    def lines(self, path: str) -> list[str] | None:
        if path in self._store:
            return self._store[path]
        if len(self._store) >= _MAX_CACHE_FILES:
            # Evict oldest entry (insertion-order dict).
            self._store.pop(next(iter(self._store)))
        # Capped read (shared 10 MB default): a pathological
        # generated/planted file yields its truncated prefix instead
        # of loading whole per annotation pass.
        got = read_text_capped(path)
        result = None if got is None else got[0].splitlines()
        self._store[path] = result
        return result


def extract_nosemgrep(
    file_path: Path,
    line: int,
    *,
    _lines: list[str] | None = None,
) -> dict | None:
    """Check whether *line* (1-indexed) in *file_path* has a nosemgrep comment.

    Checks the flagged line itself and the line immediately above it (both
    are valid nosemgrep positions per Semgrep's spec).

    Returns a dict ``{suppressed, rule_ids, justification, comment_line}``
    if found, ``None`` otherwise.
    """
    if _lines is None:
        # Same capped read as the annotate_sarif path's _FileCache —
        # the standalone entry point read files unbounded, the
        # uncapped-read shape the shared reader exists to close.
        got = read_text_capped(file_path)
        if got is None:
            return None
        _lines = got[0].splitlines()

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
                        stripped.startswith(("#", "//", "/*"))
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

    def _dget(container: object, key: str) -> dict:
        """Nested SARIF lookup tolerating explicit nulls / wrong types.

        The SARIF is tool-written but merge inputs vary; one result
        carrying ``"physicalLocation": null`` used to raise
        AttributeError out of the whole merge (the caller then fell
        back to per-file annotation). Malformed nodes read as empty.
        """
        v = container.get(key) if isinstance(container, dict) else None
        return v if isinstance(v, dict) else {}

    runs = sarif_data.get("runs", [])
    if not isinstance(runs, list):
        runs = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        # nosemgrep is Semgrep-specific — skip CodeQL/Coccinelle runs.
        tool_name = str(
            _dget(_dget(run, "tool"), "driver").get("name", "") or ""
        ).lower()
        if tool_name and "semgrep" not in tool_name:
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            if not isinstance(locations, list) or not locations:
                continue
            loc = locations[0]
            if not isinstance(loc, dict):
                continue
            phys = _dget(loc, "physicalLocation")
            uri = _dget(phys, "artifactLocation").get("uri", "")
            line = _dget(phys, "region").get("startLine", 0)
            if not isinstance(uri, str) or not uri:
                continue
            if not isinstance(line, int) or isinstance(line, bool) or not line:
                continue

            # Resolve the file path against the repo root,
            # containment-checked: the URI comes from SARIF produced
            # over an untrusted repo, so a file:// / absolute URI or
            # traversal shape would otherwise read arbitrary host
            # files and quote them into properties.nosemgrep (the
            # codeql siblings' read_source_context /
            # read_vulnerable_code enforce the same root).
            resolved = confine(root, strip_file_uri(uri))
            if resolved is None:
                continue
            abs_path = str(resolved)

            lines = cache.lines(abs_path)
            if lines is None:
                continue

            info = extract_nosemgrep(Path(abs_path), line, _lines=lines)
            if info:
                # A non-dict properties value can't take the
                # annotation; skip rather than clobber or crash.
                props = result.setdefault("properties", {})
                if not isinstance(props, dict):
                    continue
                props["nosemgrep"] = info
                annotated += 1

    if annotated:
        logger.info(
            "nosemgrep: annotated %d SARIF result(s) as developer-suppressed",
            annotated,
        )
    return annotated
