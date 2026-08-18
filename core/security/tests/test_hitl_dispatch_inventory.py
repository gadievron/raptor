"""Inventory guard: no in-repo code dispatches HITL-required agents.

HITL-required agents (``core.security.rule_of_two.HITL_REQUIRED_AGENTS``)
span all three Rule-of-Two legs and must never be dispatched headlessly.
Today no programmatic dispatcher exists — the agents are .claude/agents
definitions launched via the Task tool from an interactive session,
where Claude Code's permission prompt is the human in the loop. This
suite keeps it that way by construction: it walks the programmatic
surface (``libexec/``, ``core/``, ``packages/``, ``raptor.py``) and
fails on any reference to a HITL-required agent name outside the files
explicitly allowlisted as non-dispatch.

If a future dispatcher legitimately needs to launch one of these
agents, it must call
``core.security.rule_of_two.require_human_for_agent_dispatch(<name>)``
before dispatch and then be added to the allowlist below — the failure
message says exactly that, so the gate cannot be skipped silently.
"""

import unittest
from pathlib import Path

from core.security.rule_of_two import HITL_REQUIRED_AGENTS

_REPO = Path(__file__).resolve().parents[3]

# Directories that make up the programmatic (potentially headless)
# dispatch surface. .claude/agents and docs are prompts/documentation,
# not dispatchers, and are intentionally out of scope.
_SCAN_DIRS = ("libexec", "core", "packages")
_SCAN_FILES = ("raptor.py",)

# Known references that are NOT dispatch sites. Each entry must state
# why it is safe. Paths are repo-relative POSIX strings.
_NON_DISPATCH_ALLOWLIST = {
    # The registry + gate definition itself.
    "core/security/rule_of_two.py",
    # Gate behaviour tests (mock the helpers; never dispatch).
    "core/security/tests/test_rule_of_two.py",
    # This inventory guard.
    "core/security/tests/test_hitl_dispatch_inventory.py",
    # Frontmatter pin suite: names offsec-specialist as the WebFetch
    # hook exemption; reads .md files only.
    "core/security/tests/test_agent_capability_pins.py",
    # SAGE metadata registration: stores a descriptive directory entry
    # ("raptor-offsec-specialist"); does not launch the agent.
    "core/sage/scripts/register_agents.py",
}

_SKIP_DIR_NAMES = {"__pycache__", ".git", "node_modules", ".venv", "venv"}


def _candidate_files():
    """Yield the files that constitute the programmatic dispatch surface.

    libexec/ scripts have no extension, so every regular file there is
    scanned; under core/ and packages/ only Python files can dispatch.
    """
    for name in _SCAN_FILES:
        path = _REPO / name
        if path.is_file():
            yield path
    libexec = _REPO / "libexec"
    if libexec.is_dir():
        for path in sorted(libexec.iterdir()):
            if path.is_file():
                yield path
    for dirname in ("core", "packages"):
        root = _REPO / dirname
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            yield path


def _references(agent_name):
    """Repo-relative paths of surface files mentioning ``agent_name``."""
    hits = []
    for path in _candidate_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if agent_name in text:
            hits.append(path.relative_to(_REPO).as_posix())
    return hits


class TestRegistrySelfConsistency(unittest.TestCase):

    def test_registry_is_not_empty(self):
        self.assertTrue(HITL_REQUIRED_AGENTS,
                        "HITL registry must name at least one agent")

    def test_every_registered_agent_definition_exists(self):
        for name in HITL_REQUIRED_AGENTS:
            path = _REPO / ".claude" / "agents" / f"{name}.md"
            self.assertTrue(
                path.is_file(),
                f"HITL_REQUIRED_AGENTS names '{name}' but "
                f"{path.relative_to(_REPO)} does not exist")

    def test_allowlist_entries_exist(self):
        # A renamed/deleted file must be pruned from the allowlist, or
        # the list silently rots into a wildcard for future paths.
        for rel in sorted(_NON_DISPATCH_ALLOWLIST):
            self.assertTrue((_REPO / rel).is_file(),
                            f"allowlisted file no longer exists: {rel}")

    def test_scan_detects_known_references(self):
        # Self-test that the walk actually sees agent-name references:
        # the registry module itself names every registered agent and
        # sits inside the scanned surface, so it must always be found.
        for name in HITL_REQUIRED_AGENTS:
            self.assertIn("core/security/rule_of_two.py",
                          _references(name),
                          f"scan failed to find the registry's own "
                          f"reference to '{name}' — the guard is blind")


class TestNoUngatedDispatch(unittest.TestCase):

    def test_no_surface_file_references_hitl_agents_outside_allowlist(self):
        offenders = {}
        for name in sorted(HITL_REQUIRED_AGENTS):
            extra = [rel for rel in _references(name)
                     if rel not in _NON_DISPATCH_ALLOWLIST]
            if extra:
                offenders[name] = extra
        self.assertFalse(
            offenders,
            "HITL-required agent name referenced outside the allowlisted "
            "non-dispatch files. If this is a new dispatcher it MUST call "
            "core.security.rule_of_two.require_human_for_agent_dispatch("
            "<agent name>) before dispatch, then add the file to "
            f"_NON_DISPATCH_ALLOWLIST with a justification: {offenders}")


if __name__ == "__main__":
    unittest.main()
