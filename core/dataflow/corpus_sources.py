"""Pinned upstream sources for the dataflow corpus, parsed from
``corpus/SOURCES.md``.

The corpus labels are written against exact upstream commits; a
drifted clone silently mis-scores every validator measured against
the corpus. ``SOURCES.md`` is the single home of each pin (name,
sha, local clone path) — this module parses it so consumers verify
against THE documented pin rather than a hand-copied constant, and
:func:`verify_present_pinned_clones` is the enforcement step the
corpus runner calls before proceeding (sha check via the shared
:func:`core.recall.pinned_clone.verify_pinned_clone` chokepoint).

Clones are on-demand and gitignored; a source whose local clone is
ABSENT is skipped (findings referencing it simply have no fixture
tree — the in-tree iris fixtures need no clone at all). A PRESENT
clone at the wrong sha is a hard error: labels are invalid against
that tree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


class CorpusPinError(RuntimeError):
    """A pinned fixture clone is present but not at its pinned sha,
    or SOURCES.md is unparseable."""


# "Pinned sha:" with an optional qualifier — the source_intel CVE
# entries pin the VULNERABLE commit and spell it
# "Pinned sha (vulnerable):". "Fix sha:" lines deliberately do not
# match: the clone is pinned at the vulnerable commit.
_SHA_LINE = re.compile(
    r"^-\s*Pinned sha(?:\s*\([^)]*\))?:\s*`([0-9a-fA-F]{7,40})`",
)
_PATH_LINE = re.compile(r"^-\s*Local path:\s*`?([^`\s]+?)/?`?\s*$")
# Level-2 and level-3 headings both delimit entries (the CVE fixtures
# are ### subsections).
_SECTION = re.compile(r"^#{2,3}\s+(.+?)\s*$")


@dataclass(frozen=True)
class PinnedSource:
    """One pinned upstream fixture source."""

    name: str
    pinned_sha: str
    local_path: str  # repo-root-relative clone directory


def sources_md_path() -> Path:
    return Path(__file__).resolve().parent / "corpus" / "SOURCES.md"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def parse_pinned_sources(text: str) -> list[PinnedSource]:
    """Parse ``## <name>`` sections carrying ``Pinned sha`` and
    ``Local path`` bullet lines. A section with a sha but no path (or
    vice versa) is a documentation error and raises — a half-parsed
    pin that silently verified nothing would defeat the point."""
    out: list[PinnedSource] = []
    name: str | None = None
    sha: str | None = None
    path: str | None = None

    def _flush() -> None:
        nonlocal sha, path
        if name is None:
            return
        if (sha is None) != (path is None):
            msg = (
                f"SOURCES.md section {name!r} has "
                f"{'a pin but no local path' if path is None else 'a local path but no pin'}"
            )
            raise CorpusPinError(msg)
        if sha is not None and path is not None:
            out.append(PinnedSource(name=name, pinned_sha=sha,
                                    local_path=path))
        sha = path = None

    for line in text.split("\n"):  # line-model: RAPTOR-owned SOURCES.md, universal-newline read
        m = _SECTION.match(line)
        if m:
            _flush()
            name = m.group(1)
            continue
        m = _SHA_LINE.match(line)
        if m:
            sha = m.group(1).lower()
            continue
        m = _PATH_LINE.match(line)
        if m and name is not None and sha is not None and path is None:
            path = m.group(1)
    _flush()
    return out


def load_pinned_sources() -> list[PinnedSource]:
    """Pins from the in-tree SOURCES.md."""
    return parse_pinned_sources(
        sources_md_path().read_text(encoding="utf-8"),
    )


def verify_present_pinned_clones(
    repo_root: Path | None = None,
) -> list[str]:
    """Verify every pinned clone that exists on disk; return the
    verified source names. Raises :class:`CorpusPinError` when a
    present clone's HEAD does not match its pin."""
    from core.recall.pinned_clone import verify_pinned_clone

    root = repo_root if repo_root is not None else _repo_root()
    verified: list[str] = []
    for src in load_pinned_sources():
        clone_dir = root / src.local_path
        if not clone_dir.is_dir():
            continue
        verify_pinned_clone(
            clone_dir, src.pinned_sha, error_cls=CorpusPinError,
            hint=(" — re-clone per the instructions in "
                  "core/dataflow/corpus/SOURCES.md"),
        )
        verified.append(src.name)
    return verified
