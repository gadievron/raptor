"""Persistent coverage store (Phase 3).

Phase 2 wrote one immutable ``coverage-record.json`` per tool per run and
unioned them at query time. Phase 3 adds ``CoverageStore`` + a persistent
``coverage.json``: a (file, line-interval)-keyed record of which tool
examined which lines, surviving across pipeline stages and runs. Tools
report what they examined via :meth:`mark`; consumers query it.

Coverage is keyed by *tool label* (e.g. ``semgrep``, ``claude:audit``,
``gcov:campaign-1``). The label both names the producer and -- via the
tool registry (a later step) -- its depth on the
scanned -> analysed -> dataflow-traced -> runtime-tested ladder. The
store treats the label as an opaque string; categorisation lives in the
registry, not here.

This is the (file,function)-keyed coverage sink. Per-run provenance
(tool version, resolved model, timestamp, target identity) is sourced
separately from the run manifest (``.raptor-run.json``) and joined in by
callers -- coverage does not embed it, and keys on file *content* SHA
(via the inventory), so it is identical whether the target arrived as a
git clone or a zip extraction. See ``~/design/coverage-layer.md``.

Intervals are inclusive ``[lo, hi]`` line ranges, kept sorted and
coalesced per tool. (Bitmap fallback for files with very many intervals
-- sparse runtime/gcov data -- is a later optimisation; the public API
does not change when it lands.)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .registry import category_of

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                      # non-POSIX (Windows)
    _HAS_FCNTL = False

COVERAGE_STORE_FILE = "coverage.json"
SCHEMA_VERSION = 1

Interval = List[int]  # [lo, hi], inclusive


@contextlib.contextmanager
def coverage_store_lock(coverage_path):
    """Cross-process exclusive lock guarding a ``coverage.json``
    read-modify-write window.

    The durable store is mutated by two best-effort paths that each
    load -> mutate -> save: a run's completion snapshot and ``/project clean``'s
    snapshot. Without a lock, two racing (a run finishing during a clean, or
    several parallel runs completing at once) last-writer-wins and one
    snapshot's contribution is dropped. Hold this across the WHOLE window:
    acquire BEFORE constructing the store and release AFTER ``save()``.

    Locks a sibling ``.lock`` file (not ``coverage.json`` itself, which
    ``save()`` atomically replaces). No-op without fcntl (non-POSIX) —
    degrades to the prior last-writer-wins, no regression.
    """
    if not _HAS_FCNTL:
        yield
        return
    path = Path(coverage_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _coalesce(intervals: List[Interval]) -> List[Interval]:
    """Sort and merge overlapping or adjacent inclusive intervals."""
    if not intervals:
        return []
    ordered = sorted([lo, hi] if lo <= hi else [hi, lo] for lo, hi in intervals)
    merged: List[Interval] = [list(ordered[0])]
    for lo, hi in ordered[1:]:
        last = merged[-1]
        if lo <= last[1] + 1:          # overlapping or adjacent
            last[1] = max(last[1], hi)
        else:
            merged.append([lo, hi])
    return merged


def _covered_count(intervals: List[Interval]) -> int:
    return sum(hi - lo + 1 for lo, hi in intervals)


def _overlap_count(intervals: List[Interval], lo: int, hi: int) -> int:
    """Lines in ``[lo, hi]`` already present in ``intervals``."""
    total = 0
    for a, b in intervals:
        left, right = max(a, lo), min(b, hi)
        if left <= right:
            total += right - left + 1
    return total


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def content_identity(checklist: Dict[str, Any]) -> Optional[str]:
    """A deterministic content-equivalence id over the inventory's analyzed
    source: ``sha256`` of the sorted ``(relpath, content_sha256)`` set.

    Equal iff the analyzed file content is byte-identical — so a git checkout
    and a zip of the same source resolve to the SAME id (``git-X ≡ zip-X``),
    while CRLF / file-selection drift correctly yields different ids. Derived
    from the inventory, which already excludes ``.git`` / archive container /
    build artifacts — NOT from any acquisition hash (that's the run manifest's
    loose per-method stamp). Returns ``None`` for an empty inventory.
    """
    entries = [
        f"{fe['path']}\0{fe['sha256']}"
        for fe in checklist.get("files", [])
        if fe.get("path") and fe.get("sha256")
    ]
    if not entries:
        return None
    digest = hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()
    return f"content:{digest[:16]}"


def file_line_count(fe: Dict[str, Any]) -> Optional[int]:
    """Total line count from an inventory file entry. The inventory emits
    ``lines``; hand-built / legacy checklists may use ``total_lines``. This is
    what whole-file scanner coverage (``files_examined``) is placed against, so
    reading the wrong key silently drops all file-level coverage."""
    return fe.get("lines") or fe.get("total_lines")


def iter_inventory_functions(
    checklist: Dict[str, Any],
) -> Iterator[Tuple[str, str, int, Optional[int], str]]:
    """Yield ``(file, name, line_start, line_end, kind)`` for every inventory
    item.

    Handles the ``items`` key with ``functions`` fallback (matching
    ``core.inventory``). ``line_end`` may be ``None`` when the extractor
    couldn't determine it. ``kind`` defaults to ``"function"`` for legacy
    entries lacking it.
    """
    for fe in checklist.get("files", []):
        path = fe.get("path")
        if not path:
            continue
        for fn in fe.get("items", fe.get("functions", [])):
            yield (
                path,
                fn.get("name"),
                fn.get("line_start", 0),
                fn.get("line_end"),
                fn.get("kind", "function"),
            )


class CoverageStore:
    """Persistent, line-interval coverage keyed by file and tool label.

    Load on construction, mutate via :meth:`mark` / :meth:`set_file_meta`
    / :meth:`link_finding`, persist with :meth:`save`.
    """

    def __init__(self, coverage_path: Path, target: str | None = None):
        self.path = Path(coverage_path)
        self.target = target
        self.content_id: Optional[str] = None
        self.version = SCHEMA_VERSION
        self._files: Dict[str, Dict[str, Any]] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.version = data.get("version", SCHEMA_VERSION)
            # Constructor-supplied target wins only when the store is new.
            self.target = data.get("target") or target
            self.content_id = data.get("content_id")
            self._files = data.get("files", {}) or {}

    # --- mutation ---------------------------------------------------------

    def _entry(self, file: str) -> Dict[str, Any]:
        return self._files.setdefault(
            file,
            {
                "total_lines": None, "sloc": None,
                "tools": {}, "findings": [], "provenance": {},
            },
        )

    def mark(self, file: str, start: int, end: int, tool: str) -> int:
        """Record that ``tool`` examined lines ``[start, end]`` of ``file``.

        Returns the number of *newly* covered lines for that tool (the
        delta) -- 0 means the range was already fully covered by it.
        """
        if start > end:
            start, end = end, start
        entry = self._entry(file)
        existing = entry["tools"].get(tool, [])
        newly = (end - start + 1) - _overlap_count(existing, start, end)
        entry["tools"][tool] = _coalesce(existing + [[start, end]])
        return newly

    def set_file_meta(
        self, file: str, total_lines: int | None = None, sloc: int | None = None,
    ) -> None:
        """Record line counts (from the inventory) so coverage % is defined."""
        entry = self._entry(file)
        if total_lines is not None:
            entry["total_lines"] = total_lines
        if sloc is not None:
            entry["sloc"] = sloc

    def link_finding(
        self,
        file: str,
        finding_id: str,
        line: Optional[int] = None,
        retained: bool = True,
    ) -> None:
        """Link a finding to a file.

        ``line`` (when known) lets the finding be attributed to a function
        for verdict computation. ``retained`` is whether the finding's
        bulky detail is still on disk; ``/project clean`` flips it to
        ``False`` when it deletes the only run that held the detail, which
        turns the function's verdict into ``found_then_lost``. Dedup by id;
        a later call refreshes ``line``/``retained``.
        """
        entry = self._entry(file)
        for f in entry["findings"]:
            if f["id"] == finding_id:
                if line is not None:
                    f["line"] = line
                f["retained"] = retained
                return
        entry["findings"].append(
            {"id": finding_id, "line": line, "retained": retained}
        )

    def stamp_coverage(self, file: str, tool: str, **provenance: Any) -> None:
        """Attach provenance (engine version / resolved model / timestamp /
        acquisition target / framework_sha / run) to a ``(file, tool)``
        contribution — the who/what-version/when that makes a durable
        coverage entry self-substantiating. Read from the run manifest at
        import time. Latest stamp wins (a re-examination refreshes it);
        ``None`` values are dropped so they don't clobber a known value."""
        entry = self._entry(file)
        slot = entry["provenance"].setdefault(tool, {})
        slot.update({k: v for k, v in provenance.items() if v is not None})

    # --- queries (file/line level; inventory-join queries come next step) -

    def tool_provenance(self, file: str, tool: str) -> Dict[str, Any]:
        """The provenance stamp for a ``(file, tool)`` contribution, or ``{}``."""
        entry = self._files.get(file)
        if not entry:
            return {}
        return dict(entry.get("provenance", {}).get(tool, {}))

    def provenance_summary(self) -> Dict[str, Any]:
        """Aggregate provenance across the store for reporting: distinct engine
        versions per tool, distinct resolved models, and the newest run
        timestamp seen. ``{}``-ish when nothing is stamped."""
        tools: Dict[str, set] = {}
        models: set = set()
        newest: Optional[str] = None
        for entry in self._files.values():
            for tool, p in entry.get("provenance", {}).items():
                versions = tools.setdefault(tool, set())
                if p.get("version"):
                    versions.add(p["version"])
                for m in p.get("models") or []:
                    models.add(m)
                ts = p.get("timestamp")
                if ts and (newest is None or ts > newest):
                    newest = ts
        return {
            "tools": {t: sorted(vs) for t, vs in sorted(tools.items())},
            "models": sorted(models),
            "newest": newest,
        }

    def who_checked(self, file: str, line: int) -> List[str]:
        """Tool labels whose intervals cover ``line`` of ``file``."""
        entry = self._files.get(file)
        if not entry:
            return []
        return sorted(
            tool for tool, ivs in entry["tools"].items()
            if any(lo <= line <= hi for lo, hi in ivs)
        )

    def covered_lines(self, file: str) -> List[Interval]:
        """Union of all tools' intervals for ``file`` (coalesced)."""
        entry = self._files.get(file)
        if not entry:
            return []
        return _coalesce(
            [iv for ivs in entry["tools"].values() for iv in ivs]
        )

    def file_coverage(self, file: str) -> float:
        """Percent of ``file``'s lines covered by at least one tool.

        Returns 0.0 when the file is unknown or its ``total_lines`` has
        not been set from the inventory yet.
        """
        entry = self._files.get(file)
        if not entry or not entry.get("total_lines"):
            return 0.0
        return _covered_count(self.covered_lines(file)) / entry["total_lines"] * 100.0

    def finding_ids(self, file: str) -> List[str]:
        entry = self._files.get(file)
        return [f["id"] for f in entry["findings"]] if entry else []

    def _findings(self, file: str) -> List[Dict[str, Any]]:
        entry = self._files.get(file)
        return entry["findings"] if entry else []

    def files(self) -> List[str]:
        return sorted(self._files)

    # --- inventory-join queries (function level) --------------------------

    def tool_coverage_of_range(
        self, file: str, lo: int, hi: int,
    ) -> Dict[str, int]:
        """``{tool: covered_line_count}`` over ``[lo, hi]`` (only tools that
        cover at least one line)."""
        entry = self._files.get(file)
        if not entry:
            return {}
        out: Dict[str, int] = {}
        for tool, ivs in entry["tools"].items():
            n = _overlap_count(ivs, lo, hi)
            if n:
                out[tool] = n
        return out

    def who_checked_function(
        self, file: str, lo: int, hi: int,
    ) -> Dict[str, str]:
        """``{tool: 'full' | 'partial (N%)'}`` for a function's line range."""
        total = hi - lo + 1
        if total <= 0:                       # malformed range (hi < lo)
            return {}
        out: Dict[str, str] = {}
        for tool, n in self.tool_coverage_of_range(file, lo, hi).items():
            out[tool] = "full" if n >= total else f"partial ({n / total * 100:.0f}%)"
        return out

    def function_covered(
        self, file: str, lo: int, hi: int, category: Optional[str] = None,
    ) -> bool:
        """True if any tool covers a line of ``[lo, hi]``. When ``category``
        is given, only tools of that category count (e.g. ``"llm"`` -> has
        any LLM examined this function?)."""
        for tool in self.tool_coverage_of_range(file, lo, hi):
            if category is None or category_of(tool) == category:
                return True
        return False

    def unchecked_functions(
        self, checklist: Dict[str, Any], category: Optional[str] = None,
    ) -> List[Tuple[str, str, int]]:
        """Inventory functions with no coverage (the gap). When ``category``
        is given, functions with no coverage *by that category* -- e.g.
        ``category="llm"`` is the gap ``/audit`` fills. Returns
        ``[(file, name, line_start)]``."""
        gaps: List[Tuple[str, str, int]] = []
        for file, name, lo, hi, _kind in iter_inventory_functions(checklist):
            # No line_end -> probe the single declaration line.
            high = hi if hi is not None else lo
            if not self.function_covered(file, lo, high, category):
                gaps.append((file, name, lo))
        return gaps

    def import_inventory_meta(self, checklist: Dict[str, Any]) -> None:
        """Populate per-file ``total_lines`` / ``sloc`` from the inventory so
        :meth:`file_coverage` is defined."""
        for fe in checklist.get("files", []):
            path = fe.get("path")
            if path:
                self.set_file_meta(path, file_line_count(fe), fe.get("sloc"))

    def set_content_id(self, checklist: Dict[str, Any]) -> Optional[str]:
        """Set the store's content-equivalence id from the inventory (see
        :func:`content_identity`). Two acquisitions of identical source —
        a git checkout and a zip — get the same id, so coverage is recognised
        as being for the same target regardless of how it was acquired."""
        cid = content_identity(checklist)
        if cid is not None:
            self.content_id = cid
        return self.content_id

    # --- verdict-bearing coverage (the three states) ----------------------

    def function_verdict(self, file: str, lo: int, hi: int) -> str:
        """One of: ``unexamined`` / ``clean`` / ``open`` / ``found_then_lost``.

        - open:            a finding lands in it and its detail is retained.
        - found_then_lost: a finding landed in it but its detail was deleted
                           (the run that held it was cleaned). Kept as a fact;
                           does NOT count as covered -- it's a re-review gap.
        - clean:           examined (a tool covered it), no finding lands in it.
        - unexamined:      no finding and no tool examined the range.

        Findings are checked FIRST: a finding *is* examination evidence (a tool
        flagged this code), so a function with a finding is never ``unexamined``
        even if no whole-file coverage record happens to cover its line. The
        safe direction — surface the finding rather than bury it as a gap.

        Findings linked without a ``line`` can't be attributed to a function,
        so they don't affect a function verdict (they remain a file-level
        signal via ``finding_ids``).
        """
        in_range = [
            f for f in self._findings(file)
            if f.get("line") is not None and lo <= f["line"] <= hi
        ]
        if in_range:
            if any(f.get("retained", True) for f in in_range):
                return "open"
            return "found_then_lost"
        if not self.tool_coverage_of_range(file, lo, hi):
            return "unexamined"
        return "clean"

    def function_verdicts(
        self, checklist: Dict[str, Any],
    ) -> List[Tuple[str, str, int, str]]:
        """``(file, name, line_start, verdict)`` for every inventory function."""
        out: List[Tuple[str, str, int, str]] = []
        for file, name, lo, hi, _kind in iter_inventory_functions(checklist):
            high = hi if hi is not None else lo
            out.append((file, name, lo, self.function_verdict(file, lo, high)))
        return out

    def review_gap(
        self, checklist: Dict[str, Any],
    ) -> List[Tuple[str, str, int, str]]:
        """Functions needing (re-)review: ``unexamined`` or ``found_then_lost``.

        Returns ``(file, name, line_start, verdict)``. ``found_then_lost`` is
        the case where a previously-found finding's detail was discarded --
        surfaced here so it's re-examined rather than silently skipped.
        """
        return [
            row for row in self.function_verdicts(checklist)
            if row[3] in ("unexamined", "found_then_lost")
        ]

    # --- persistence ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": _now_iso(),
            "target": self.target,
            "content_id": self.content_id,
            "files": self._files,
        }

    def save(self) -> Path:
        """Atomically write ``coverage.json`` (tempfile + os.replace)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True)
        fd, tmp = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".coverage-", suffix=".json.tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return self.path
