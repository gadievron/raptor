"""Closure: instruction-referenced libexec commands vs the settings allowlist.

Why this test exists
--------------------
Instruction files (.claude/**/*.md, CLAUDE.md) direct the model to run
``libexec/raptor-*`` commands verbatim, and several explicitly promise
pre-approval. The allowlist in ``.claude/settings.json`` was
hand-picked, so it drifted from that referenced surface: the may-ask
gate itself prompted for permission before it could decide whether
asking is allowed, and the MAP-5j imports enricher prompted mid-chain
(denied-and-skipped in dispatched contexts while the skill forbids
manual import enumeration).

The universe is DERIVED, not enumerated: every ``libexec/raptor-<x>``
name referenced by an instruction file that exists as a script on disk
must either match an allowlist entry or appear in one of the two
adjudication tables below — ``PROMPT_INTENDED`` (commands that execute
or instrument the target, where the per-run permission prompt IS the
consent step) or ``PENDING_OPERATOR_DECISION`` (the drift worklist:
referenced commands whose pre-approval is an operator call that has
not been made; adding a permission grant is a consent decision, so
this test pins the worklist instead of silently widening the
allowlist). A new instruction reference fails here until it is
adjudicated into one of the three places; a stale table row (name no
longer referenced, or since allowlisted) fails too, so neither table
can rot.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]

_REF_RE = re.compile(r"libexec/(raptor-[a-z0-9-]+[a-z0-9])")

# Referenced commands whose permission prompt is the consent step —
# they execute, instrument, or fuzz the analysed target, and the
# instruction files themselves frame the prompt as appropriate
# (map.md MAP-7: "expect a permission prompt — appropriate, since the
# probe executes the target binary").
PROMPT_INTENDED: dict[str, str] = {
    "raptor-sandbox-observe": "runtime probe executes the target "
                              "binary; per-run operator consent",
    "raptor-frida": "dynamic instrumentation attaches to / spawns "
                    "target processes; per-run operator consent",
    "raptor-frida-patch-verify": "runs the patched target under "
                                 "instrumentation; per-run operator "
                                 "consent",
    "raptor-binary": "black-box investigation executes the target "
                     "(trace/fuzz modes); per-run operator consent",
}

# Referenced commands the hand-picked allowlist drifted away from.
# Each row is a dispatched-surface command that hits a permission
# prompt mid-chain (denied-and-skipped in dispatched contexts).
# Pre-approving one is a standing permission grant — an operator
# decision, owed and tracked here, not made by this test. Moving a
# name out of this table = adding its settings.json entry in the
# same reviewed change. Empty today: the accumulated worklist was
# adjudicated by the operator and shipped as grants; the table
# stays as the intake point for the next reference this test
# catches.
PENDING_OPERATOR_DECISION: dict[str, str] = {}


def _doc_files() -> list[Path]:
    docs = [REPO / "CLAUDE.md"]
    docs += sorted((REPO / ".claude").rglob("*.md"))
    return [p for p in docs if p.is_file()]


def _referenced_commands() -> set[str]:
    """Every libexec/raptor-* name referenced by an instruction file
    that exists as a script on disk (prose fragments like a trailing
    hyphen or an elided family name resolve to no file and drop)."""
    names: set[str] = set()
    for doc in _doc_files():
        text = doc.read_text(encoding="utf-8", errors="replace")
        names.update(_REF_RE.findall(text))
    return {n for n in names if (REPO / "libexec" / n).is_file()}


def _allowlisted_commands() -> set[str]:
    settings = json.loads(
        (REPO / ".claude" / "settings.json").read_text(encoding="utf-8"))
    allowed: set[str] = set()
    for rule in settings.get("permissions", {}).get("allow", []):
        m = re.fullmatch(r"Bash\(libexec/(raptor-[a-z0-9-]+)(?: \*)?\)",
                         rule)
        if m:
            allowed.add(m.group(1))
    return allowed


class SettingsLibexecAllowlistClosureTests(unittest.TestCase):
    def test_universe_is_nonempty(self):
        """Sanity — the derivation must not silently collapse."""
        self.assertGreater(len(_referenced_commands()), 10)
        self.assertGreater(len(_allowlisted_commands()), 10)

    def test_every_referenced_command_is_adjudicated(self):
        referenced = _referenced_commands()
        allowed = _allowlisted_commands()
        missing = sorted(
            referenced - allowed - set(PROMPT_INTENDED)
            - set(PENDING_OPERATOR_DECISION))
        self.assertEqual(
            missing, [],
            msg=(
                "instruction files reference libexec commands that are "
                "neither allowlisted in .claude/settings.json nor "
                "adjudicated prompt-intended — dispatched runs will "
                "stall or silently skip on a permission prompt: "
                f"{missing}"
            ),
        )

    def test_prompt_intended_rows_are_live(self):
        """The exception table must not rot: every row must still be
        referenced by an instruction file, still exist on disk, and
        not ALSO be allowlisted (which would contradict the
        adjudication)."""
        referenced = _referenced_commands()
        allowed = _allowlisted_commands()
        for name, rationale in PROMPT_INTENDED.items():
            self.assertTrue(rationale.strip(), name)
            self.assertIn(
                name, referenced,
                f"{name}: prompt-intended row no longer referenced by "
                "any instruction file — retire the row")
            self.assertNotIn(
                name, allowed,
                f"{name}: adjudicated prompt-intended but also "
                "allowlisted — resolve the contradiction")

    def test_pending_rows_are_live(self):
        """The operator-owed worklist must not rot either: every row
        must still be referenced, still exist on disk, and not
        already be allowlisted (then the decision was made — remove
        the row)."""
        referenced = _referenced_commands()
        allowed = _allowlisted_commands()
        for name, rationale in PENDING_OPERATOR_DECISION.items():
            self.assertTrue(rationale.strip(), name)
            self.assertIn(
                name, referenced,
                f"{name}: pending row no longer referenced by any "
                "instruction file — retire the row")
            self.assertNotIn(
                name, allowed,
                f"{name}: allowlisted — the pending decision was "
                "made; remove the worklist row")

    def test_allowlist_names_resolve_to_scripts(self):
        """Every allowlisted libexec name must exist on disk — a
        deleted or renamed script must take its grant with it."""
        gone = sorted(
            n for n in _allowlisted_commands()
            if not (REPO / "libexec" / n).is_file()
        )
        self.assertEqual(gone, [],
                         msg=f"allowlist grants for missing scripts: {gone}")


if __name__ == "__main__":
    unittest.main()
