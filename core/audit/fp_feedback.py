"""Mine historical annotations and journal entries for false-positive feedback.

When a human operator overrides an LLM verdict to ``clean``, that's a
false-positive signal.  This module cross-references human annotations
(Layer 3) against LLM review journal entries (Layer 2), extracts the
pattern (CWE, hypothesis, human rationale), and formats them as prompt
warnings so future LLM review passes can avoid repeating the same
mistakes.

Human overrides live in ``core.annotations`` (operator notes).
LLM verdicts live in ``core.coverage.journal`` (review journal JSONL).
"""

from __future__ import annotations

import fnmatch
import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FPPattern:
    """One observed false-positive pattern from annotation history.

    Attributes:
        file_pattern: glob pattern describing which files the FP
            applies to (e.g. ``*.py``, or a specific filename).
        function: function name where the override was recorded.
        cwe: CWE class from the original LLM annotation (empty string
            if not specified).
        hypothesis_snippet: key phrase from the LLM's hypothesis
            (extracted from metadata or body).
        human_note: the human operator's rationale (the override body).
    """

    file_pattern: str
    function: str
    cwe: str
    hypothesis_snippet: str
    human_note: str


def _file_extension_glob(source_file: str) -> str:
    """Derive a ``*.<ext>`` glob from a source file path."""
    ext = Path(source_file).suffix
    return f"*{ext}" if ext else source_file


def _first_line(text: str, *, max_len: int = 120) -> str:
    """Extract the first non-empty, non-heading line, capped."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            if len(stripped) > max_len:
                return stripped[: max_len - 3] + "..."
            return stripped
    return ""


def scan_fp_patterns(
    annotations_dir: Path,
    *,
    journal_dir: Optional[Path] = None,
    min_overrides: int = 1,
) -> List[FPPattern]:
    """Find false-positive patterns by cross-referencing human annotations
    against LLM review journal entries.

    A false positive is detected when:
    1. A human annotation marks a function ``clean`` (Layer 3), AND
    2. A journal entry for the same function has verdict ``finding`` or
       ``suspicious`` (Layer 2), or the human annotation itself carries
       CWE/hypothesis metadata or a ``lesson`` exists in the journal.

    Args:
        annotations_dir: path to the human annotations directory.
        journal_dir: path to the output directory containing
            ``review-journal.jsonl``.  When ``None``, only
            annotation-internal metadata (CWE, hypothesis) can trigger
            detection — journal cross-referencing is skipped.
        min_overrides: minimum number of overrides for the same
            ``(cwe, file_pattern)`` before the pattern is emitted.
    """
    if not annotations_dir.is_dir():
        return []

    try:
        from core.annotations.storage import iter_all_annotations
    except ImportError:
        logger.debug("core.annotations not available; falling back to no FP patterns")
        return []

    journal_index: Dict[str, "_JournalSummary"] = {}
    if journal_dir:
        journal_index = _load_journal_index(journal_dir)

    human_overrides: Dict[str, list] = defaultdict(list)
    for ann in iter_all_annotations(annotations_dir):
        src = ann.metadata.get("source", "")
        status = ann.metadata.get("status", "")
        if src == "human" and status == "clean":
            key = f"{ann.file}:{ann.function}"
            human_overrides[key].append(ann)

    raw_patterns: List[FPPattern] = []
    for key, anns in human_overrides.items():
        for ann in anns:
            pattern = _detect_fp(ann, journal_index.get(key))
            if pattern is not None:
                raw_patterns.append(pattern)

    if min_overrides > 1:
        raw_patterns = _apply_min_overrides(raw_patterns, min_overrides)

    raw_patterns.sort(key=lambda p: (p.cwe, p.file_pattern, p.function))
    return raw_patterns


@dataclass
class _JournalSummary:
    """Condensed journal state for one file:function key."""
    verdict: str
    cwe: str
    body: str
    lesson: str


def _load_journal_index(journal_dir: Path) -> Dict[str, "_JournalSummary"]:
    """Load journal entries and keep the latest per file:function."""
    try:
        from core.coverage.journal import load_entries
    except ImportError:
        logger.debug("core.coverage.journal not available")
        return {}

    index: Dict[str, _JournalSummary] = {}
    for entry in load_entries(journal_dir):
        index[entry.key] = _JournalSummary(
            verdict=entry.verdict,
            cwe=entry.cwe or "",
            body=entry.body,
            lesson=entry.lesson or "",
        )
    return index


def _detect_fp(
    human_ann,
    journal: Optional["_JournalSummary"],
) -> Optional[FPPattern]:
    """Check whether a human-clean annotation contradicts a journal
    finding/suspicious verdict, signalling a false-positive pattern."""
    source_file = human_ann.file

    if journal is not None and journal.verdict in ("finding", "suspicious"):
        return FPPattern(
            file_pattern=_file_extension_glob(source_file),
            function=human_ann.function,
            cwe=journal.cwe,
            hypothesis_snippet=_first_line(journal.body),
            human_note=human_ann.body,
        )

    cwe = human_ann.metadata.get("cwe", "")
    hypothesis = human_ann.metadata.get("hypothesis", "")
    has_lesson = journal is not None and bool(journal.lesson)

    if cwe or hypothesis or has_lesson:
        snippet = hypothesis
        if not snippet and has_lesson:
            snippet = _first_line(journal.lesson)  # type: ignore[union-attr]
        if not snippet:
            snippet = _first_line(human_ann.body)
        return FPPattern(
            file_pattern=_file_extension_glob(source_file),
            function=human_ann.function,
            cwe=cwe or (journal.cwe if journal else ""),
            hypothesis_snippet=snippet,
            human_note=human_ann.body,
        )

    return None


def _apply_min_overrides(
    patterns: List[FPPattern], threshold: int,
) -> List[FPPattern]:
    from collections import Counter

    counts: Counter[tuple[str, str]] = Counter()
    for p in patterns:
        counts[(p.cwe, p.file_pattern)] += 1

    return [
        p for p in patterns
        if counts[(p.cwe, p.file_pattern)] >= threshold
    ]


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------

def format_fp_warnings(
    patterns: List[FPPattern],
    file_path: str,
    cwe: str = "",
) -> Optional[str]:
    """Format relevant FP patterns as a prompt warning block.

    Filters to patterns matching the file's extension and optionally CWE.
    Returns a multi-line string or None if no relevant patterns.
    """
    relevant = _filter_patterns(patterns, file_path, cwe)
    if not relevant:
        return None

    lines = ["Previous false positives in this codebase:"]
    for p in relevant:
        parts: List[str] = []
        if p.cwe:
            parts.append(p.cwe)
        if p.hypothesis_snippet:
            parts.append(f'"{p.hypothesis_snippet}"')
        if p.function:
            parts.append(f"in {p.function}")

        note = _first_line(p.human_note, max_len=100)
        entry = " ".join(part for part in parts if part).strip()
        if note:
            entry = f'{entry} was overridden: "{note}"'
        else:
            entry = f"{entry} was overridden to clean"

        lines.append(f"- {entry}")

    return "\n".join(lines)


def _filter_patterns(
    patterns: List[FPPattern],
    file_path: str,
    cwe: str,
) -> List[FPPattern]:
    file_name = Path(file_path).name
    out: List[FPPattern] = []
    for p in patterns:
        if not fnmatch.fnmatch(file_name, p.file_pattern):
            if not fnmatch.fnmatch(file_path, p.file_pattern):
                continue
        if cwe and p.cwe and p.cwe != cwe:
            continue
        out.append(p)
    return out


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_fp_patterns(patterns: List[FPPattern], out_dir: Path) -> None:
    """Save patterns to ``fp-patterns.json`` (atomic write)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "fp-patterns.json"
    data = [asdict(p) for p in patterns]
    tmp = dest.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        tmp.replace(dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def load_fp_patterns(out_dir: Path) -> List[FPPattern]:
    """Load patterns from ``fp-patterns.json``. Empty list if missing."""
    src = out_dir / "fp-patterns.json"
    if not src.exists():
        return []
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Cannot load fp-patterns.json: %s", exc)
        return []
    if not isinstance(data, list):
        logger.warning("fp-patterns.json is not a list")
        return []
    patterns: List[FPPattern] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            patterns.append(FPPattern(
                file_pattern=str(item.get("file_pattern", "")),
                function=str(item.get("function", "")),
                cwe=str(item.get("cwe", "")),
                hypothesis_snippet=str(item.get("hypothesis_snippet", "")),
                human_note=str(item.get("human_note", "")),
            ))
        except (TypeError, ValueError):
            continue
    return patterns
