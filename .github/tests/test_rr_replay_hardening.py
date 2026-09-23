"""Doc-lint: manual `rr replay` instruction lanes carry gdb hardening.

Why this test exists
--------------------
`rr replay` drops into gdb against a recording of an UNTRUSTED binary.
The scripted lane (crash-analysis/rr-debugger/scripts/crash_trace.py)
passes real command-line hardening flags (`-nx`, auto-load off, no
trusted safe-path directory) before gdb sources init files or loads
any objfile; the manual instruction lanes told the model to run a bare
`rr replay`, leaving a config-conditional gap: with an operator
`~/.gdbinit` that widened `auto-load safe-path` (the exact line gdb's
own decline warning coaches users to add), the bare lane executes
python the analysed binary embeds (.debug_gdb_scripts) or plants
beside itself (*-gdb.py). The hardened spelling costs nothing, so
every documented invocation must carry it — this pins the sibling
lanes to the script's posture.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]

_RR_REPLAY_RE = re.compile(r"^\s*(?:\d\.\s*)?.*\brr replay\b(?!`)")
_REQUIRED = ("-nx", "set auto-load off", "set auto-load safe-path /dev/null")


def _doc_files() -> list[Path]:
    return [p for p in sorted((REPO / ".claude").rglob("*.md"))
            if p.is_file()]


class RrReplayHardeningTests(unittest.TestCase):
    def test_docs_exist(self):
        self.assertGreater(len(_doc_files()), 1)

    def test_rr_replay_invocations_carry_hardening(self):
        problems = []
        found_any = False
        for doc in _doc_files():
            text = doc.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
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
                found_any = True
                if not all(tok in line for tok in _REQUIRED):
                    problems.append(
                        f"{doc.relative_to(REPO)}:{i}: {line.strip()}")
        self.assertTrue(found_any,
                        "no rr replay invocation lines found — the "
                        "detector regressed or the lanes moved")
        self.assertEqual(
            problems, [],
            msg=(
                "manual rr replay invocations must carry the gdb "
                "auto-load hardening flags (`-- -nx -iex 'set "
                "auto-load off' -iex 'set auto-load safe-path "
                "/dev/null'`) — the recording is of an untrusted "
                "binary and a widened operator gdb config executes "
                "scripts it plants:\n" + "\n".join(problems)
            ),
        )


if __name__ == "__main__":
    unittest.main()
