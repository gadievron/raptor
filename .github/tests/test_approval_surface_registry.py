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
files instructing an interactive structured choice. The bash lane
spans EVERY tracked shell file — a shell suffix or an sh-family
shebang, anywhere in the tree — not just ``libexec/``/``bin/``: a
``read -rp`` planted in a tracked ``.sh`` under ``core/`` passed an
earlier walk whose bash lane only covered those two roots, silently
narrowing this docstring's closure claim. The markdown lane keys on
the INTERACTIVE PROMPTS doctrine's shape (the AskUserQuestion tool
name, the doctrine's own "structured choice" vocabulary, an
offer-the-user-choices instruction, or a rendered ``[Y/n/...]``
consent menu), not on one tool-name token: two live consent
instructions spelled without the literal ``AskUserQuestion``
(create-skill's persistent-skill confirm, exploit's next-steps fork)
were invisible to a token-keyed walk. A NEW prompt surface anywhere
in the tree fails this test until it is adjudicated into the
registry.
Render-lane entries (``lane="render"``) feed a prompt that lives in
another file and are pinned here without being enumerated.
"""

from __future__ import annotations

import ast
import re
import subprocess
import unittest
from dataclasses import dataclass, field
from pathlib import Path

import pytest

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


# Shell lane universe: every tracked shell file, tree-wide. Suffix
# spellings plus sh-family shebang detection for extensionless
# scripts (plugins/coverage/libexec/..., subsystem scripts/ dirs).
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
_SHELL_INTERPRETERS = frozenset({"sh", "bash", "dash", "ksh", "zsh"})


def _shebang_interpreter(first_line: str) -> str:
    """Interpreter basename named by a ``#!`` line ('' when none) —
    resolves the ``env`` indirection (``#!/usr/bin/env bash``)."""
    if not first_line.startswith("#!"):
        return ""
    words = first_line[2:].split()
    if not words:
        return ""
    interp = words[0].rsplit("/", 1)[-1]
    if interp == "env":
        for w in words[1:]:
            if not w.startswith("-"):
                return w.rsplit("/", 1)[-1]
        return ""
    return interp


def _shell_lane_member(rel: str, first_line: str) -> bool:
    """True when a tracked file joins the tree-wide bash prompt lane:
    a shell suffix, or an sh-family shebang. ``libexec/``/``bin/``
    launchers are handled separately (Python parse with a bash
    fallback); this predicate is the rest-of-tree net whose absence
    let a ``read -rp`` in a tracked ``.sh`` outside those roots pass
    the closure test."""
    return rel.endswith(_SHELL_SUFFIXES) or (
        _shebang_interpreter(first_line) in _SHELL_INTERPRETERS
    )


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


# The 13 approval surfaces adjudicated as rendering external
# content. Every id must appear on at least one registry entry's
# ``members`` (M10 spans three instruction files, M08 two, and each
# appears on every file carrying it).
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
    "M13-create-skill-persist-consent",
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
    ".claude/commands/exploit.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M08-exploit-next-steps-fork",),
        note="command file instructing the same next-steps fork as "
             "tiers/exploit-guidance.md — options built from "
             "mitigation-analysis output (alternative_targets, chain "
             "breaks) derived from the analysed hostile binary",
    ),
    ".claude/commands/create-skill.md": Entry(
        lane="instruction", status="doctrine-pending",
        members=("M13-create-skill-persist-consent",),
        note="'Create this skill?' confirm authorizes writing a "
             "persistent .claude/skills/*/SKILL.md that auto-loads "
             "into future sessions (a standing-instruction grant); "
             "the preview shown at the consent moment is LLM-authored "
             "from session content, which in a scan session carries "
             "target-derived text",
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
    "docs/sandbox.md": Entry(
        lane="instruction", status="clean",
        note="end-user documentation describing the sandbox-floor "
             "remedy fork (the tiers/recovery.md surface); not an "
             "agent instruction surface",
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


# Markdown lane: a file instructs an interactive structured choice
# when it names the AskUserQuestion tool, speaks the INTERACTIVE
# PROMPTS doctrine's own vocabulary ("structured choice", an
# offer-the-user/operator-choices instruction), or renders a
# bracketed consent menu ("[Y/n/Customize]", "[y/N]"). Derived from
# the doctrine SHAPE, not one tool-name token: a consent instruction
# spelled without the literal "AskUserQuestion" must still join the
# universe. The prose alternates are matched case-insensitively —
# sentence-initial casing ("Offer the user choices ...") must not
# drop an instruction — while the tool name and the consent-menu
# capitalisation grammar stay case-exact. Residue (honestly bounded):
# a consent instruction written in a wholly novel spelling — no tool
# name, no doctrine phrase, no menu — stays outside the net until a
# reviewer adds its spelling.
_MD_PROMPT_EXACT_RE = re.compile(
    r"AskUserQuestion"
    r"|\[[Yy]/[Nn](?:/[A-Za-z][^\]]*)?\]"
    r"|\[[Nn]/[Yy]\]"
)
_MD_PROMPT_PROSE_RE = re.compile(
    r"structured choice|offer the (?:user|operator) choices",
    re.IGNORECASE,
)


def _md_prompt_instruction(text: str) -> bool:
    return bool(_MD_PROMPT_EXACT_RE.search(text)
                or _MD_PROMPT_PROSE_RE.search(text))


# Call-shaped mention of a prompt callee: the exact identifier at a
# word boundary, whitespace (newlines included — parenthesised
# continuations), then the argument list.
_PY_PROMPT_MENTION = re.compile(r"\b(?:input|confirm)\s*\(")


def _may_carry_python_prompt(text: str) -> bool:
    """Smoke-subset prescreen for the Python prompt lane: does the raw
    text carry a call-shaped mention of a prompt callee?

    Used ONLY to pick which files the default-tier enumeration parses —
    it is NOT full coverage. Identifiers (unlike string literals)
    appear verbatim in honestly-written source, so every honest
    ``input()``/``confirm()`` call site matches (``input(x)``,
    ``input (x)``, split across lines inside parentheses, any
    attribute owner). The residue: an NFKC-normalised identifier
    spelling (``𝗂𝗇𝗉𝗎𝗍(...)`` parses to the ``input`` name with no
    ``input`` in the text), a backslash line continuation between
    callee and argument list, or a comment wedged there — squarely
    the adversarial-in-repo-author class this net's docstring already
    scopes out — and the nightly full enumeration owns it (see
    test_full_enumeration_matches_smoke).
    """
    return _PY_PROMPT_MENTION.search(text) is not None


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


def enumerate_surfaces(full: bool = False) -> set[str]:
    """Every git-tracked file carrying an interactive approval prompt:
    Python ``input()``/``confirm()`` call sites, bash ``read -p`` in
    any tracked shell file tree-wide, plus markdown files instructing
    an interactive structured choice (see _md_prompt_instruction).

    Default (smoke) mode parses only files that pass the cheap text
    prescreens — the bash line scan plus _may_carry_python_prompt —
    which cover every honestly-written prompt spelling; the AST parse
    + walk of every tracked runtime module breached the default tier's
    per-test budget on contended CI runners. ``full=True`` (nightly)
    parses everything and owns the NFKC-identifier residue; the
    equivalence of the two modes on the real tree is pinned nightly in
    test_full_enumeration_matches_smoke. The bash and markdown lanes
    are mode-independent (their detectors ARE their prescreens).
    """
    found: set[str] = set()
    for rel in _git_files():
        if _is_test_path(rel):
            continue
        path = REPO_ROOT / rel
        if rel.endswith(".md"):
            try:
                if _md_prompt_instruction(path.read_text(encoding="utf-8")):
                    found.add(rel)
            except (OSError, UnicodeDecodeError):
                continue
            continue
        if not (rel.endswith(".py") or rel.startswith(("libexec/", "bin/"))):
            # Shell lane, tree-wide: any tracked shell file (suffix or
            # sh-family shebang) is scanned for prompting reads. The
            # shebang sniff reads one line so the whole-tree walk
            # stays cheap; only shell files get the full-text scan.
            first = ""
            if not rel.endswith(_SHELL_SUFFIXES):
                try:
                    with path.open("rb") as fh:
                        head = fh.readline(256)
                except OSError:
                    continue
                try:
                    first = head.decode("utf-8")
                except UnicodeDecodeError:
                    continue
            if not _shell_lane_member(rel, first):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if any(_bash_read_has_prompt(ln) for ln in text.splitlines()):
                found.add(rel)
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # The bash lane's own detector doubles as its prescreen — the
        # line scan is cheap; only the Python parse is not.
        bash_hit = any(
            _bash_read_has_prompt(ln) for ln in text.splitlines())
        if not full and not bash_hit and not _may_carry_python_prompt(text):
            # Neither lane can match: no prompting read line exists,
            # and an honest input()/confirm() call site would have hit
            # the identifier prescreen (see _may_carry_python_prompt
            # for the NFKC residue the nightly full mode owns).
            continue
        try:
            if _python_prompts(ast.parse(text)):
                found.add(rel)
        except SyntaxError:
            # Not Python — bash/other script: any read-with-prompt line.
            if bash_hit:
                found.add(rel)
    return found


# Enumeration is lazy and cached per mode: only the two closure tests
# read it, and computing it in setUpClass made every registry-only test
# in the class pay the whole-tree walk as setup (once per xdist worker
# that drew any test from the class).
_ENUM_CACHE: dict[bool, frozenset[str]] = {}


def _enumerated(full: bool = False) -> frozenset[str]:
    if full not in _ENUM_CACHE:
        try:
            _ENUM_CACHE[full] = frozenset(enumerate_surfaces(full=full))
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise unittest.SkipTest(
                "not a git checkout (or git unavailable)")
    return _ENUM_CACHE[full]


class TestApprovalSurfaceRegistry(unittest.TestCase):
    def test_every_prompt_surface_is_adjudicated(self):
        missing = sorted(_enumerated() - set(REGISTRY))
        self.assertFalse(
            missing,
            "unadjudicated approval surface(s) — a new interactive "
            "prompt must be added to the approval-surface registry "
            "with a sanitised/clean/doctrine-pending adjudication: "
            f"{missing}",
        )

    def test_no_stale_registry_rows(self):
        enumerated = _enumerated()
        stale = sorted(
            rel for rel, entry in REGISTRY.items()
            if entry.lane != "render" and rel not in enumerated
        )
        self.assertFalse(
            stale,
            "registry rows whose file no longer carries a prompt "
            f"surface — retire or re-adjudicate: {stale}",
        )

    def test_smoke_prescreen_contract(self):
        """The prescreen must pass every honestly-written prompt
        spelling to the parser, and — pinned here so the docstring
        stays true — it does NOT see the wedge-class residue (an
        NFKC-normalised identifier, a backslash continuation between
        callee and argument list): that residue is exactly why the
        nightly full enumeration exists and must never be re-labelled
        as covered by the smoke. The detector itself DOES flag each
        residue spelling once parsed, keeping the detection pinned
        daily."""
        honest = (
            'ans = input("Authorize? [y/N] ")',
            'ans = input ("spaced call")',
            'ok = confirm("Proceed?")',
            'typer.confirm("Delete runs?")',
            'click.confirm("Apply patch?")',
            'v = (input\n("split across lines"))',
        )
        for src in honest:
            self.assertTrue(_may_carry_python_prompt(src), src)
            self.assertTrue(_python_prompts(ast.parse(src)), src)
        residue = (
            '𝗂𝗇𝗉𝗎𝗍("Approve? ")',           # NFKC-normalised identifier
            'v = input \\\n("continued")',   # backslash continuation
        )
        for src in residue:
            self.assertFalse(_may_carry_python_prompt(src), src)
            self.assertTrue(_python_prompts(ast.parse(src)), src)
        # Non-call and non-boundary mentions stay out of the smoke
        # subset — and out of the detector, so the two never diverge
        # on them.
        for src in ("x = read_text()", "user_input(y)"):
            self.assertFalse(_may_carry_python_prompt(src), src)
            self.assertFalse(_python_prompts(ast.parse(src)), src)

    # Full enumeration: genuinely heavy (an AST parse + walk of every
    # tracked runtime module; as class setup it breached the default
    # tier's per-test warning band on contended CI runners), so it runs
    # in the nightly tier. Trade-off, both directions: unmarking it
    # puts the whole-tree parse back in every PR run; marking it
    # WITHOUT the smoke-mode closure tests above would leave a new
    # prompt surface invisible until the next nightly. The smoke
    # enumeration covers every honestly-spelled surface on every PR;
    # only NFKC-identifier spellings wait for nightly, where this
    # equivalence check surfaces them as a smoke/full divergence.
    @pytest.mark.slow
    def test_full_enumeration_matches_smoke(self):
        self.assertEqual(
            _enumerated(full=True), _enumerated(),
            "full enumeration found surface(s) the smoke prescreen "
            "skipped (or vice versa) — adjudicate the divergent "
            "file(s) and keep the prescreen honest",
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

    def test_shell_lane_spans_the_whole_tree(self):
        """Shell files join the bash lane by suffix or sh-family
        shebang at ANY path — the closure must not depend on the file
        living under libexec/ or bin/ (a ``read -rp`` planted in a
        tracked .sh under core/ passed the earlier two-root walk)."""
        members = (
            ("core/security/_dangerous_env_strip.sh", ""),
            ("core/sandbox/scripts/feature-matrix/run-matrix.sh", ""),
            ("some/dir/helper.bash", ""),
            ("some/dir/helper.zsh", ""),
            ("some/dir/helper.ksh", ""),
            ("plugins/coverage/libexec/raptor-hook-read",
             "#!/usr/bin/env bash"),
            ("tools/entry", "#!/bin/sh"),
            ("x/y/z", "#! /usr/bin/dash"),
        )
        for rel, first in members:
            self.assertTrue(_shell_lane_member(rel, first), rel)
        non_members = (
            ("core/x/notes.txt", ""),
            ("core/x/gen", "#!/usr/bin/env python3"),
            ("core/x/data.json", "{"),
            ("core/x/perl-thing", "#!/usr/bin/perl"),
            ("core/x/no-shebang", "set -euo pipefail"),
        )
        for rel, first in non_members:
            self.assertFalse(_shell_lane_member(rel, first), rel)

    def test_md_lane_keys_on_doctrine_shape_not_tool_token(self):
        """The markdown lane derives from the INTERACTIVE PROMPTS
        doctrine shape — a consent instruction spelled without the
        literal ``AskUserQuestion`` (create-skill's ``[Y/n/Customize]``
        confirm, exploit's offer-the-user-choices fork) must still
        join the universe; ordinary markdown must not."""
        matching = (
            "use the AskUserQuestion tool",
            "present a structured choice (see INTERACTIVE PROMPTS)",
            "offer the user choices:",
            "offer the operator choices at the run boundary",
            # sentence-initial casing must not drop an instruction —
            # the prose vocabulary is case-insensitive
            "Offer the user choices before proceeding.",
            "Structured choice: pick exactly one option.",
            "Create this skill? [Y/n/Customize]",
            "Proceed? [y/N]",
            "[N/y] inverted default",
        )
        for text in matching:
            self.assertTrue(_md_prompt_instruction(text), text)
        inert = (
            "compare [a/b] table columns",
            "an ask-user question is a different phrase",
            "choices offered elsewhere in the doc",
            "[Y/X] is not a consent menu",
            "structured data, choice of encoding",
        )
        for text in inert:
            self.assertFalse(_md_prompt_instruction(text), text)

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
