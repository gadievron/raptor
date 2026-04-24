"""Read OSS forensics run artifacts.

A `/oss-forensics` run emits artifacts to `.out/oss-forensics-<timestamp>/`
(from .claude/commands/oss-forensics.md):

    evidence.json                        # all collected evidence (EvidenceStore)
    evidence-verification-report.md      # verification results
    hypothesis-*.md                      # analysis iterations
    forensic-report.md                   # final report: timeline, attribution, IOCs

Plus investigator-specific sub-artifacts that we surface generically.

This reader lets the UI walk a user through the investigation: research
question → evidence → hypothesis iterations → verification → final report.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_HYPOTHESIS_ORDER_RE = re.compile(r"hypothesis[-_](\d+)", re.IGNORECASE)


@dataclass
class HypothesisIteration:
    filename: str
    content: str
    order: int  # extracted from filename; ``hypothesis-002.md`` → 2
    title: str  # first markdown heading or first line
    status: str  # "confirmed" / "revision-requested" / "unknown" from filename hint

    @property
    def excerpt(self) -> str:
        lines = [l for l in self.content.splitlines() if l.strip()][:4]
        return "\n".join(lines)


@dataclass
class ForensicsBundle:
    run_dir: Path
    evidence: Optional[dict] = None
    evidence_verification: Optional[str] = None
    hypotheses: list[HypothesisIteration] = field(default_factory=list)
    forensic_report: Optional[str] = None
    other_markdown: list[tuple[str, str]] = field(default_factory=list)

    @property
    def has_any(self) -> bool:
        return any([
            self.evidence, self.evidence_verification,
            self.hypotheses, self.forensic_report,
        ])

    @property
    def evidence_summary(self) -> list[tuple[str, int]]:
        """``[(source_name, count), …]`` — best-effort from evidence.json structure."""
        if not isinstance(self.evidence, dict):
            return []
        out: list[tuple[str, int]] = []
        for key, val in self.evidence.items():
            if isinstance(val, list):
                out.append((key, len(val)))
            elif isinstance(val, dict):
                # Nested: count top-level items
                out.append((key, len(val)))
        return out

    @property
    def research_question(self) -> Optional[str]:
        """Best-effort extraction from the first hypothesis or evidence.json."""
        if isinstance(self.evidence, dict):
            for key in ("research_question", "question", "prompt"):
                val = self.evidence.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        if self.hypotheses:
            first = self.hypotheses[0]
            # Look for a line like "## Research Question" or the first non-heading line
            for line in first.content.splitlines():
                if line.strip() and not line.startswith("#"):
                    return line.strip()[:240]
        return None


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text()
    except OSError:
        return None


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _parse_hypothesis(path: Path) -> HypothesisIteration:
    content = path.read_text(errors="replace")

    match = _HYPOTHESIS_ORDER_RE.search(path.stem)
    order = int(match.group(1)) if match else 0

    title = path.stem
    for line in content.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if stripped:
            title = stripped[:160]
            break

    stem = path.stem.lower()
    if "confirmed" in stem:
        status = "confirmed"
    elif "rebuttal" in stem or "rejected" in stem or "revision" in stem:
        status = "rejected"
    else:
        status = "unknown"

    return HypothesisIteration(
        filename=path.name,
        content=content,
        order=order,
        title=title,
        status=status,
    )


def load_forensics_bundle(run_dir: Path) -> ForensicsBundle:
    bundle = ForensicsBundle(run_dir=run_dir)
    if not run_dir.is_dir():
        return bundle

    bundle.evidence = _read_json(run_dir / "evidence.json")
    bundle.evidence_verification = _read_text(run_dir / "evidence-verification-report.md")
    bundle.forensic_report = _read_text(run_dir / "forensic-report.md")

    hypothesis_files = list(run_dir.glob("hypothesis-*.md")) + list(run_dir.glob("hypothesis_*.md"))
    seen: set[str] = set()
    for f in hypothesis_files:
        if f.name in seen:
            continue
        seen.add(f.name)
        bundle.hypotheses.append(_parse_hypothesis(f))
    bundle.hypotheses.sort(key=lambda h: (h.order, h.filename))

    # Other markdown that isn't the known headers (investigator raw outputs, etc.)
    known = {"evidence-verification-report.md", "forensic-report.md"}
    for md in sorted(run_dir.glob("*.md")):
        if md.name in known or md.name in seen:
            continue
        text = _read_text(md)
        if text is not None:
            bundle.other_markdown.append((md.name, text))

    return bundle


def is_forensics_run_dir(run_dir: Path) -> bool:
    """Heuristic — a run is OSS-forensics if it has evidence.json or forensic-report.md."""
    return (run_dir / "evidence.json").is_file() or (run_dir / "forensic-report.md").is_file()
