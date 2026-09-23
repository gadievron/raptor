"""Doc-lint: no `python3 -c` invocations in instruction-file shell blocks.

Why this test exists
--------------------
Skill/command markdown bodies are executed literally by the model
(SLASH-COMMAND DISPATCH rule 3: placeholders are substituted
verbatim). A double-quoted ``python3 -c "..."`` block with a
``<placeholder>`` inside is therefore a command-injection surface:
the shell expands ``$(...)`` and backticks carried in the pasted
value — operator arguments, resolved target paths, or scanned-repo
bytes quoted into JSON — before python ever runs. This is the
CLAUDE.md SECURITY file-path-injection rule ("never interpolate ...
into shell command strings") applied to the instruction lane.

The sanctioned patterns are argv-data invocations: a
``libexec/raptor-*`` shim taking the values as arguments, or a
script file written with the Write tool and run with ``sys.argv``
arguments. Fenced shell blocks in instruction files must therefore
never contain ``python3 -c`` (or ``python -c``) at all — the census
is exclusion-free by design; prose mentions and ``python`` fences
(source the model writes to a file) are out of scope.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]

# Fence info strings that mean "the model runs these lines in a shell".
_SHELL_LANGS = {"", "bash", "sh", "shell", "console", "zsh"}

_FENCE_RE = re.compile(r"^\s*```(\S*)")
_PY_C_RE = re.compile(r"\bpython3?\s+-c\b")


def _doc_files() -> list[Path]:
    docs = [REPO / "CLAUDE.md"]
    docs += sorted((REPO / ".claude").rglob("*.md"))
    docs += sorted((REPO / "tiers").rglob("*.md"))
    return [p for p in docs if p.is_file()]


def _shell_block_hits(text: str) -> list[tuple[int, str]]:
    """(line_no, line) for every python -c inside a shell fence."""
    hits: list[tuple[int, str]] = []
    in_fence = False
    fence_is_shell = False
    for i, line in enumerate(text.splitlines(), 1):
        m = _FENCE_RE.match(line)
        if m:
            if in_fence:
                in_fence = False
                fence_is_shell = False
            else:
                in_fence = True
                fence_is_shell = m.group(1).lower() in _SHELL_LANGS
            continue
        if in_fence and fence_is_shell and _PY_C_RE.search(line):
            hits.append((i, line.strip()))
    return hits


class InstructionPythonCCensusTests(unittest.TestCase):
    def test_docs_exist(self):
        """Sanity — the doc set must not silently shrink to nothing."""
        self.assertGreater(len(_doc_files()), 1,
                           msg="doc set unexpectedly empty")

    def test_no_python_c_in_shell_blocks(self):
        problems = []
        for doc in _doc_files():
            text = doc.read_text(encoding="utf-8", errors="replace")
            for line_no, line in _shell_block_hits(text):
                problems.append(
                    f"{doc.relative_to(REPO)}:{line_no}: {line}")
        self.assertEqual(
            problems, [],
            msg=(
                "instruction-file shell blocks must not invoke "
                "`python3 -c` — placeholder values pasted into a "
                "double-quoted program are shell-expanded before "
                "python runs. Pass values as argv to a libexec shim "
                "or write the snippet to a file (Write tool) and pass "
                "sys.argv arguments:\n" + "\n".join(problems)
            ),
        )


if __name__ == "__main__":
    unittest.main()
