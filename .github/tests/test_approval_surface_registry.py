"""Approval-surface registry — closure test for operator-authorization
display integrity.

An approval surface is a place where an interactive prompt asks the
operator to authorize something (y/N reads, choice menus, structured
AskUserQuestion instructions). Content rendered AT such a prompt can
use terminal controls (or, on the instruction lane, harness-rendered
markup) to blind the operator at exactly the moment display integrity
IS the control — so every surface must be adjudicated:

* ``sanitised``  — code lane; external/target/server-derived content
  reaches the prompt only through the terminal sanitiser
  (``core.security.log_sanitisation``). The registry pins call-site
  wire tokens (the exact interpolation / pipe spelling at each render
  site) as a mechanical tripwire: a call-site-only revert that keeps
  the helper defined fails here. The tokens check textual presence
  only — each surface's behavioral display-integrity tests (hostile
  ANSI/CSI/OSC fixtures in its own suite) remain the primary revert
  oracle.
* ``clean``      — adjudicated: the prompt renders no external content
  (constants, charset-constrained names, anchored-regex extractions).
* ``doctrine-pending`` — instruction lane (agent-rendered
  AskUserQuestion text). The mechanism fix is a CLAUDE.md
  INTERACTIVE PROMPTS display-integrity rule plus per-surface wording,
  delivered as an operator-gated proposal; until the operator lands
  it, these rows are the open worklist, not a pass.

The enumeration is mechanical, and bounded: Python ``input()`` /
typer-click ``confirm()`` call sites as literal AST calls
(dynamically-built prompts — ``exec``-constructed code,
``getattr(builtins, ...)``, aliasing like ``ask = input`` — are
outside it: this is a net for honestly-written prompts, not an
adversarial-in-repo-author defense), bash ``read`` invocations
carrying a ``-p`` prompt flag in any legal flag-grammar spelling
(``-p``, ``-rp``, ``-pr``, ``-r -p``, ``-t 5 -p`` …), and markdown
files instructing AskUserQuestion use. A NEW prompt surface anywhere
in the tree fails this test until it is adjudicated into the
registry. Render-lane entries (``lane="render"``) feed a prompt that
lives in another file and are pinned here without being enumerated.
"""

from __future__ import annotations

import ast
import subprocess
import unittest
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_CONFIRM_OWNERS = {"typer", "click"}

# bash ``read`` flag grammar (builtins/read.def): -e/-r/-s take no
# argument; -a/-d/-i/-n/-N/-t/-u (and -p itself) consume the rest of
# their flag group, or the next word when the group ends at the flag.
# A prompt is present when option scanning reaches ``p`` as a flag
# letter — in any group position or order (``-p``, ``-rp``, ``-pr``,
# ``-ersp"x"``, ``-t 5 -p``) — and absent when a ``p`` is only some
# other flag's argument (``-d p``, ``-dp``).
_BASH_READ_NOARG_FLAGS = frozenset("ers")
_BASH_READ_ARG_FLAGS = frozenset("adinNtu")  # arg-taking flags except -p


def _bash_read_has_prompt(line: str) -> bool:
    """True when ``line`` is a ``read`` builtin invocation whose flags
    include ``-p`` under bash's real option grammar (see above)."""
    words = line.split()
    if not words or words[0] != "read":
        return False
    skip_next = False
    for word in words[1:]:
        if skip_next:
            skip_next = False
            continue
        if word == "--" or word == "-" or not word.startswith("-"):
            return False  # options ended (first operand) — no -p seen
        for i, ch in enumerate(word[1:]):
            if ch == "p":
                return True
            if ch in _BASH_READ_ARG_FLAGS:
                # Consumes the rest of this group as its argument, or
                # the next word when nothing is attached.
                skip_next = i + 2 == len(word)
                break
            if ch not in _BASH_READ_NOARG_FLAGS:
                break  # not read's grammar; scan the next word
    return False


@dataclass(frozen=True)
class Entry:
    lane: str            # "code" | "render" | "instruction"
    status: str          # "sanitised" | "clean" | "doctrine-pending"
    note: str
    members: tuple[str, ...] = ()   # display-integrity member ids
    wire_tokens: tuple[str, ...] = field(default=())


# The 12 approval surfaces adjudicated as rendering external
# content. Every id must appear on exactly one registry entry's
# ``members`` (M10 spans three instruction files and appears on each).
MEMBER_IDS = (
    "M01-sage-setup-authorize-displays",
    "M02-boot-payload-review-compare",
    "M03-stage-a-sandbox-consent",
    "M04-sage-drift-review-ask",
    "M05-binary-oracle-provenance-consent",
    "M06-volatile-target-gate",
    "M07-codeql-trust-consent",
    "M08-exploit-next-steps-fork",
    "M09-map-trace-followup",
    "M10-completion-forks",
    "M11-project-destructive-confirms",
    "M12-startup-check-mismatch-menu",
)


REGISTRY: dict[str, Entry] = {
    # ── code lane ────────────────────────────────────────────────
    "libexec/raptor-sage-setup": Entry(
        lane="code", status="sanitised",
        members=("M01-sage-setup-authorize-displays",),
        note="boot-payload authorize y/N + review a/r prompts; both "
             "payload displays route through the nested "
             "_render_payload_display helper (display-only, "
             "fail-closed); the review-lane diff is sanitised inside "
             "boot_payload_review.py",
        # The render is UNBOUNDED escape_nonprintable with a "| "
        # frame prefix and a line-count refusal: an approval display
        # must show everything it stamps (a length cap once elided
        # long-line tails that were stamped sight-unseen).
        wire_tokens=('"$payload_diff" | _render_payload_display',
                     '"$payload" | _render_payload_display',
                     '"| " + escape_nonprintable(line)'),
    ),
    "core/sage/boot_payload_review.py": Entry(
        lane="render", status="sanitised",
        members=("M02-boot-payload-review-compare",),
        note="compare display feeding sage-setup's approve/reject "
             "prompt; diff lines pass sanitise_for_terminal via _line; "
             "also registered in _REPORT_WRITER_FILES",
        wire_tokens=("{_line(line)}",
                     ".sanitise_for_terminal(s, max_len=2000)"),
    ),
    "libexec/raptor-startup-check": Entry(
        lane="code", status="sanitised",
        members=("M12-startup-check-mismatch-menu",),
        note="project-mismatch menu before input(); target paths are "
             "unconstrained external input, rendered escaped",
        wire_tokens=('sanitise_for_terminal(str(active["target"]))',
                     "sanitise_for_terminal(str(caller_dir))",
                     "({shown_target})", "({shown_caller})"),
    ),
    "core/project/cli.py": Entry(
        lane="code", status="clean",
        note="destructive-command _confirm prompts render "
             "operator/machine-named content only (project names are "
             "_validate_name-constrained)",
    ),
    "packages/cve_diff/cve_diff/cli/main.py": Entry(
        lane="code", status="clean",
        note="budget-extension typer.confirm; the rendered reason is "
             "an anchored-alternation regex extraction "
             "(_BUDGET_REASON_RE), never free error text",
    ),
    # ── instruction lane: members (doctrine-pending) ─────────────
    "CLAUDE.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M05-binary-oracle-provenance-consent",
                 "M06-volatile-target-gate"),
        note="provenance-drop consent quotes attacker-chosen binary "
             "paths; volatile-target gate quotes target paths",
    ),
    "core/sage/CLAUDE.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M04-sage-drift-review-ask",),
        note="drift-review approve/reject question filled with "
             "hostile-SAGE-server diff facts",
    ),
    ".claude/skills/exploitability-validation/stage-a-oneshot.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M03-stage-a-sandbox-consent",),
        note="sandbox-removal consent shown the PoC/target's own "
             "stderr — highest-authority instruction member",
    ),
    ".claude/commands/codeql.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M07-codeql-trust-consent",),
        note="trust consent quotes run-output hint text",
    ),
    "tiers/exploit-guidance.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M08-exploit-next-steps-fork",),
        note="next-steps fork quotes chain_breaks/constraints, which "
             "carry raw bytes from executing the hostile binary",
    ),
    ".claude/skills/code-understanding/map.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M09-map-trace-followup",),
        note="trace follow-up labels options with entry-point "
             "names/paths from the scanned target",
    ),
    ".claude/commands/agentic.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M10-completion-forks",),
        note="completion fork fills descriptions with finding "
             "ids/paths",
    ),
    ".claude/commands/validate.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M10-completion-forks",),
        note="completion fork fills descriptions with finding "
             "ids/paths",
    ),
    ".claude/skills/exploitability-validation/stage-1-outputs.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M10-completion-forks",),
        note="post-run fork fills descriptions with finding "
             "ids/files/statuses",
    ),
    ".claude/commands/project.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M11-project-destructive-confirms",),
        note="clean/adopt confirms preview arbitrary directory "
             "listings",
    ),
    # ── instruction lane: adjudicated clean ──────────────────────
    "tiers/recovery.md": Entry(
        lane="instruction", status="clean",
        note="remedy fork options are RAPTOR-authored constants "
             "(sandbox tier labels, RAPTOR's own refusal text)",
    ),
    ".claude/skills/oss-forensics/orchestration/SKILL.md": Entry(
        lane="instruction", status="clean",
        note="clarify questions ask for missing operator input; no "
             "external content rendered",
    ),
    ".claude/skills/oss-forensics/github-archive/SKILL.md": Entry(
        lane="instruction", status="clean",
        note="BigQuery cost-threshold asks render numeric dry-run "
             "estimates",
    ),
    "docs/environment.md": Entry(
        lane="instruction", status="clean",
        note="end-user documentation describing the interactivity "
             "gate; not an agent instruction surface",
    ),
}


def _git_files() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.splitlines()


def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    return ("tests" in parts or "fixtures" in parts
            or parts[-1].startswith("test_") or parts[-1] == "conftest.py")


def _python_prompts(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in ("input", "confirm"):
            return True
        if (isinstance(fn, ast.Attribute) and fn.attr == "confirm"
                and isinstance(fn.value, ast.Name)
                and fn.value.id in _CONFIRM_OWNERS):
            return True
    return False


def enumerate_surfaces() -> set[str]:
    """Every git-tracked file carrying an interactive approval prompt:
    Python ``input()``/``confirm()`` call sites and bash ``read -p``
    in runtime code, plus markdown files instructing AskUserQuestion
    use."""
    found: set[str] = set()
    for rel in _git_files():
        if _is_test_path(rel):
            continue
        path = REPO_ROOT / rel
        if rel.endswith(".md"):
            try:
                if "AskUserQuestion" in path.read_text(encoding="utf-8"):
                    found.add(rel)
            except (OSError, UnicodeDecodeError):
                continue
            continue
        if not (rel.endswith(".py") or rel.startswith(("libexec/", "bin/"))):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            if _python_prompts(ast.parse(text)):
                found.add(rel)
        except SyntaxError:
            # Not Python — bash/other script: any read-with-prompt line.
            if any(_bash_read_has_prompt(ln) for ln in text.splitlines()):
                found.add(rel)
    return found


class TestApprovalSurfaceRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.enumerated = enumerate_surfaces()
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise unittest.SkipTest("not a git checkout (or git unavailable)")

    def test_every_prompt_surface_is_adjudicated(self):
        missing = sorted(self.enumerated - set(REGISTRY))
        self.assertFalse(
            missing,
            "unadjudicated approval surface(s) — a new interactive "
            "prompt must be added to the approval-surface registry "
            "with a sanitised/clean/doctrine-pending adjudication: "
            f"{missing}",
        )

    def test_no_stale_registry_rows(self):
        stale = sorted(
            rel for rel, entry in REGISTRY.items()
            if entry.lane != "render" and rel not in self.enumerated
        )
        self.assertFalse(
            stale,
            "registry rows whose file no longer carries a prompt "
            f"surface — retire or re-adjudicate: {stale}",
        )

    def test_registry_files_exist(self):
        gone = sorted(
            rel for rel in REGISTRY if not (REPO_ROOT / rel).is_file()
        )
        self.assertFalse(gone, f"registry rows for missing files: {gone}")

    def test_all_class_members_are_registered(self):
        covered = {
            m for entry in REGISTRY.values() for m in entry.members
        }
        self.assertEqual(
            sorted(covered), sorted(MEMBER_IDS),
            "the registry must carry every approval-surface class "
            "member exactly as enumerated (and no unknown ids)",
        )

    def test_sanitised_entries_are_wired(self):
        """A ``sanitised`` adjudication must keep its pinned call-site
        wire tokens — the exact interpolation / pipe spelling at each
        render site — so a call-site-only revert (helper kept, call
        removed) fails mechanically. Textual presence only: the
        behavioral display-integrity tests in each surface's own suite
        are the primary revert oracle; this is the registry-local
        tripwire that forces re-adjudication on any respelling."""
        for rel, entry in REGISTRY.items():
            if entry.status != "sanitised":
                continue
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            for token in entry.wire_tokens:
                self.assertIn(
                    token, text,
                    f"{rel}: adjudicated sanitised but wire token "
                    f"{token!r} is gone — the sanitiser call was "
                    "removed or renamed; re-adjudicate",
                )

    def test_entries_carry_real_notes(self):
        for rel, entry in REGISTRY.items():
            self.assertTrue(
                entry.note.strip() and "TODO" not in entry.note,
                f"{rel}: registry adjudications need a real note",
            )
            self.assertIn(entry.status,
                          ("sanitised", "clean", "doctrine-pending"))
            self.assertIn(entry.lane, ("code", "render", "instruction"))

    def test_bash_read_prompt_grammar_is_covered(self):
        """The bash-lane detector must cover ``read``'s real option
        grammar, not particular spellings — a planted
        ``read -rp "Authorize? [y/N] " ans`` surface evaded an earlier
        ``-p``/``-r -p``-only pattern."""
        prompting = (
            'read -p "Continue? [y/N] " ans',
            'read -r -p "Authorize? [y/N] " ans',
            'read -rp "Authorize? [y/N] " ans',   # the planted bypass
            "read -pr ans",                       # prompt is the text "r"
            'read -ersp "prompt " ans',
            '    read -srp"Approve? " ans',
            'read -t 5 -p "quick? " ans',
            'read -u 3 -rp "fd prompt " ans',
            'read -n 1 -p "one key: " k',
            'read -d "" -p "null-delim: " v',
            'read -i default -e -p "edit: " v',
            'read -a words -p "list: " ignored',
        )
        for line in prompting:
            self.assertTrue(_bash_read_has_prompt(line), line)
        promptless = (
            "read -r line",
            "read ans",
            "read -d p var",    # p is -d's argument, not a prompt
            "read -dp var",     # attached spelling of the same
            "read -t 5 var",
            "read -- -p",       # options ended before the -p word
            "readarray -t arr",
            '# read -p "commented out" ans',
            'echo "read -p"',
        )
        for line in promptless:
            self.assertFalse(_bash_read_has_prompt(line), line)

    def test_sanitised_status_only_on_code_lanes(self):
        """Instruction surfaces cannot be code-sanitised — their fix
        is the operator-gated doctrine rule; refuse a category error
        that would mark one 'sanitised' without a mechanism."""
        for rel, entry in REGISTRY.items():
            if entry.lane == "instruction":
                self.assertIn(entry.status, ("clean", "doctrine-pending"),
                              f"{rel}: instruction lanes are clean or "
                              "doctrine-pending, never 'sanitised'")


if __name__ == "__main__":
    unittest.main()
