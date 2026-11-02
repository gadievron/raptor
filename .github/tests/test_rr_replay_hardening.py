"""Crash-analysis replay instructions must use the contained shared launcher.

GDB init/auto-load suppression remains in the runner, but flags alone do not
confine replayed code. Refuse a return to bare rr replay instructions.
"""

from __future__ import annotations

import os
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


class RrReplayHardeningTests(unittest.TestCase):
    def test_docs_exist(self):
        self.assertGreater(len(_doc_files()), 1)

    def test_rr_replay_invocations_carry_hardening(self):
        problems = []
        contained = set()
        for doc in _doc_files():
            text = doc.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                if 'crash_trace.py' in line and '--interactive' in line:
                    contained.add(str(doc.relative_to(REPO)))
                if "rr replay" not in line:
                    continue
                # Prose mentions of the bare command name (backtick
                # `rr replay` with nothing after, or "rr replay ..."
                # placeholders inside example descriptions) still
                # count when they template a runnable command line:
                # anything showing an invocation must show the
                # hardened one. Only lines that also name a gdb
                # command or stand alone as the command are checked.
                stripped = line.strip().strip("`")
                is_invocation = (
                    stripped.startswith("rr replay")
                    or "rr replay <trace>" in line
                    or "rr replay ..." in line
                    or "rr replay rr-trace" in line
                )
                if not is_invocation:
                    continue
                # Hardened GDB flags alone no longer suffice: they do
                # not provide filesystem or network containment.
                if is_invocation:
                    problems.append(
                        f"{doc.relative_to(REPO)}:{i}: {line.strip()}")
        self.assertTrue({'.claude/agents/crash-analyzer-agent.md',
                         '.claude/skills/crash-analysis/rr-debugger/SKILL.md'} <= contained,
                        'replay instructions must use the contained mechanical launcher')
        self.assertEqual(
            problems, [],
            msg=(
                "manual rr replay instructions must use crash_trace.py --interactive; "
                "GDB auto-load flags alone do not sandbox the recording:\n"
                + "\n".join(problems)
            ),
        )


if __name__ == "__main__":
    unittest.main()
