"""Crash-analysis rr instructions must use contained mechanical launchers."""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]


def _doc_files() -> list[Path]:
    docs = []
    claude = REPO / ".claude"
    for directory, children, names in os.walk(claude):
        if Path(directory) == claude:
            # Other checkouts and their generated output are not our docs.
            children[:] = [name for name in children if name != "worktrees"]
        docs.extend(Path(directory) / name for name in names if name.endswith(".md"))
    return sorted(p for p in docs if p.is_file())


def test_doc_scan_excludes_other_worktrees(tmp_path, monkeypatch):
    monkeypatch.setitem(globals(), "REPO", tmp_path)
    own_doc = tmp_path / ".claude" / "skills" / "owned" / "SKILL.md"
    own_doc.parent.mkdir(parents=True)
    own_doc.write_text("rr replay trace -- -nx -iex 'set auto-load off' "
                       "-iex 'set auto-load safe-path /dev/null'\n")
    foreign = tmp_path / ".claude" / "worktrees" / "other" / "docs" / "replay.md"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("rr replay trace\n")
    assert _doc_files() == [own_doc]


_BARE_RR = re.compile(r"(?<![\w-])rr[ \t]+(?:record|pack|replay)(?![\w-])")


class RrReplayHardeningTests(unittest.TestCase):
    def test_docs_exist(self):
        self.assertGreater(len(_doc_files()), 1)

    def test_rr_instructions_use_contained_helpers(self):
        problems = []
        covered = set()
        for doc in _doc_files():
            text = doc.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                if 'libexec/raptor-rr ' in line:
                    covered.add(str(doc.relative_to(REPO)))
                if _BARE_RR.search(line):
                    problems.append(f"{doc.relative_to(REPO)}:{i}: {line.strip()}")
        self.assertTrue({'.claude/agents/crash-analysis-agent.md',
                         '.claude/agents/crash-analyzer-agent.md',
                         '.claude/skills/crash-analysis/rr-debugger/SKILL.md'} <= covered)
        self.assertEqual(problems, [],
                         'rr workflow commands must use the contained helper:\n' + '\n'.join(problems))


if __name__ == "__main__":
    unittest.main()
