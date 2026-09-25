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
  (constants, charset-constrained names, anchored-regex extractions),
  or — instruction lane — the file instructs the CLAUDE.md
  INTERACTIVE PROMPTS display-integrity rule (external content
  rendered with non-printables escaped, long excerpts bounded) with
  per-surface wording at each fill site.
* ``doctrine-pending`` — instruction lane (agent-rendered
  AskUserQuestion text) that does not yet carry the display-integrity
  wording. Such rows are an open worklist, not a pass: a NEW
  instruction surface enters the registry here until its per-surface
  wording lands and the row is re-adjudicated ``clean``.

The enumeration is mechanical, and bounded: Python ``input()`` /
typer-click ``confirm()`` call sites as literal AST calls
(dynamically-built prompts — ``exec``-constructed code,
``getattr(builtins, ...)``, aliasing like ``ask = input`` — are
outside it: this is a net for honestly-written prompts, not an
adversarial-in-repo-author defense), bash ``read`` invocations
carrying a ``-p`` prompt flag in any legal flag-grammar spelling
(``-p``, ``-rp``, ``-pr``, ``-r -p``, ``-t 5 -p`` …) at any
simple-command position (line start, after ``&&``/``||``/``;``/``|``
connectors, behind ``IFS=``-style assignment words or
``while``/``if`` keywords — the canonical safe-read idioms prefix
the command, and a line-start-only anchor missed them), and markdown
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


# ``read`` is a prompt surface wherever it sits at simple-command
# position, not only at column zero of the line: the canonical safe
# spellings prefix it with an assignment (``IFS= read -rp``), a
# compound keyword (``while read -rp "> " cmd; do``), or a connector
# (``ok && read -p ...``). A words[0]=="read" anchor was blind to all
# three idioms — the very next honestly-written prompt spelled
# ``IFS= read -rp`` would have re-opened the closure with CI green.
_BASH_CMD_CONNECTOR_RE = re.compile(r"&&|\|\||[;|&]")
_BASH_CMD_PREFIX_KEYWORDS = frozenset(
    {"if", "while", "until", "then", "do", "else", "elif", "!", "time"}
)
_BASH_ASSIGNMENT_WORD_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?="
)


def _bash_read_has_prompt(line: str) -> bool:
    """True when ``line`` carries a ``read`` builtin invocation at any
    simple-command position whose flags include ``-p`` under bash's
    real option grammar (see above).

    Command positions covered: the line start, after the ``&&`` /
    ``||`` / ``;`` / ``|`` / ``&`` connectors, and behind leading
    ``NAME=value`` assignment words or compound-command keywords
    (``while``/``if``/``until``/``then``/``do``/``else``/``elif``/
    ``!``/``time``). The split is textual, not a shell parse —
    connectors inside quoted strings can create junk segments, which
    fail the ``read``-at-head test and never false-positive; a
    ``read`` whose own prompt string contains a connector is still
    caught via the pre-connector segment."""
    for segment in _BASH_CMD_CONNECTOR_RE.split(line):
        words = segment.split()
        while words and (
            words[0] in _BASH_CMD_PREFIX_KEYWORDS
            or _BASH_ASSIGNMENT_WORD_RE.match(words[0])
        ):
            words.pop(0)
        if not words or words[0] != "read":
            continue
        if _read_flag_words_have_prompt(words[1:]):
            return True
    return False


def _read_flag_words_have_prompt(words: list[str]) -> bool:
    """Bash option-grammar walk over the words following ``read``."""
    skip_next = False
    for word in words:
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
    # Code lane only: pinned number of prompt call sites in the file.
    # The file-keyed adjudication alone let a SECOND input() added to
    # an already-registered file inherit the file's adjudication
    # unreviewed (probe-proven on the fp-ceremony surface); the count
    # pin makes any new prompt in a registered file fail closure
    # until the entry is re-adjudicated with the new count.
    prompts: int | None = None


# The 14 approval surfaces adjudicated as rendering external
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
    "M14-openant-core-consent",
    "M15-validation-recovery-fork",
    "M16-crash-fetch-host-consent",
    "M17-wsl-consent-grant-ceremony",
    "M18-wsl-floor-refusal-offer",
    "M19-review-fp-ceremony",
)


REGISTRY: dict[str, Entry] = {
    # ── code lane ────────────────────────────────────────────────
    "libexec/raptor-sage-setup": Entry(
        lane="code", status="sanitised", prompts=3,
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
        lane="code", status="sanitised", prompts=1,
        members=("M12-startup-check-mismatch-menu",),
        note="project-mismatch menu before input(); target paths are "
             "unconstrained external input, rendered escaped",
        wire_tokens=('sanitise_for_terminal(str(active["target"]))',
                     "sanitise_for_terminal(str(caller_dir))",
                     "({shown_target})", "({shown_caller})"),
    ),
    "core/project/cli.py": Entry(
        lane="code", status="clean", prompts=1,
        note="destructive-command _confirm prompts render "
             "operator/machine-named content only (project names are "
             "_validate_name-constrained)",
    ),
    "libexec/raptor-wsl-consent": Entry(
        lane="code", status="sanitised", prompts=1,
        members=("M17-wsl-consent-grant-ceremony",),
        note="host-consent grant ceremony: the typed-confirmation "
             "prompt follows a display of file-derived evidence "
             "(kernel identity and family from /proc, marker paths, "
             "record fields), all routed through the _esc helper "
             "(sanitise_for_terminal); the prompt string itself is a "
             "RAPTOR-authored constant",
        wire_tokens=("{_esc(evidence['kernel_identity'])}",
                     "{_esc(evidence['kernel_family'])}",
                     "sanitise_for_terminal(str(text), max_len=256)"),
    ),
    "libexec/raptor-review": Entry(
        lane="code", status="sanitised", prompts=1,
        members=("M19-review-fp-ceremony",),
        note="fp --ceremony typed-consent prompt: the evidence "
             "display renders finding-derived text (title, recorded "
             "provenance stamp fields) through the _line sanitiser, "
             "and the finding id joins the typed phrase only when it "
             "matches the conservative ceremony charset (ASCII "
             "subset, bounded — confusables refuse); the prompt "
             "string itself is RAPTOR-authored",
        wire_tokens=("_CEREMONY_ID_RE.fullmatch(fid)",
                     "{_line(title, max_chars=200)}",
                     "parents={_line(str(ctx.get(PARENTS_KEY) or ''), "
                     "max_chars=120)}"),
    ),
    "packages/cve_diff/cve_diff/cli/main.py": Entry(
        lane="code", status="clean", prompts=1,
        note="budget-extension typer.confirm; the rendered reason is "
             "an anchored-alternation regex extraction "
             "(_BUDGET_REASON_RE), never free error text",
    ),
    # ── instruction lane: members (clean — each file instructs the
    #    display-integrity rule at its fill site; the note names the
    #    external content each surface renders) ────────────────────
    "CLAUDE.md": Entry(
        lane="instruction", status="clean",
        members=("M05-binary-oracle-provenance-consent",
                 "M06-volatile-target-gate"),
        note="provenance-drop consent quotes attacker-chosen binary "
             "paths; volatile-target gate quotes target paths",
        wire_tokens=("quoting the warning's paths with non-printables "
                     "escaped",
                     "render any quoted target path with non-printables "
                     "escaped"),
    ),
    "core/sage/CLAUDE.md": Entry(
        lane="instruction", status="clean",
        members=("M04-sage-drift-review-ask",),
        note="drift-review approve/reject question filled with "
             "hostile-SAGE-server diff facts",
        wire_tokens=("rendered inert first",
                     "(its display lane already escapes non-printables)"),
    ),
    ".claude/skills/exploitability-validation/stage-a-oneshot.md": Entry(
        lane="instruction", status="clean",
        members=("M03-stage-a-sandbox-consent",),
        note="sandbox-removal consent shown the PoC/target's own "
             "stderr — highest-authority instruction member",
        wire_tokens=("escape non-printable/control bytes before display",
                     "only with the escaped excerpt"),
    ),
    ".claude/commands/codeql.md": Entry(
        lane="instruction", status="clean",
        members=("M07-codeql-trust-consent",),
        note="trust consent quotes run-output hint text",
        wire_tokens=("with non-printables escaped",),
    ),
    "tiers/exploit-guidance.md": Entry(
        lane="instruction", status="clean",
        members=("M08-exploit-next-steps-fork",),
        note="next-steps fork quotes chain_breaks/constraints, which "
             "carry raw bytes from executing the hostile binary",
        wire_tokens=("Escape non-printables when quoting",),
    ),
    ".claude/commands/exploit.md": Entry(
        lane="instruction", status="clean",
        members=("M08-exploit-next-steps-fork",),
        note="command file instructing the same next-steps fork as "
             "tiers/exploit-guidance.md — options built from "
             "mitigation-analysis output (alternative_targets, chain "
             "breaks) derived from the analysed hostile binary",
        wire_tokens=("escape non-printables",),
    ),
    ".claude/commands/openant.md": Entry(
        lane="instruction", status="clean",
        members=("M14-openant-core-consent",),
        note="--openant-core consent-gate refusal offered as a "
             "run-boundary trust choice; the quoted refusal text "
             "carries the unconstrained argv core path, and the "
             "instruction requires non-printables escaped at the "
             "fill site",
        wire_tokens=("non-printables escaped",),
    ),
    ".claude/commands/create-skill.md": Entry(
        lane="instruction", status="clean",
        members=("M13-create-skill-persist-consent",),
        note="'Create this skill?' confirm authorizes writing a "
             "persistent .claude/skills/*/SKILL.md that auto-loads "
             "into future sessions (a standing-instruction grant); "
             "the preview shown at the consent moment is LLM-authored "
             "from session content, which in a scan session carries "
             "target-derived text",
        wire_tokens=("render it with non-printables escaped",),
    ),
    ".claude/skills/code-understanding/map.md": Entry(
        lane="instruction", status="clean",
        members=("M09-map-trace-followup",),
        note="trace follow-up labels options with entry-point "
             "names/paths from the scanned target",
        wire_tokens=("render them with non-printables escaped",),
    ),
    ".claude/commands/agentic.md": Entry(
        lane="instruction", status="clean",
        members=("M10-completion-forks",),
        note="completion fork fills descriptions with finding "
             "ids/paths",
        wire_tokens=("render them with non-printables escaped.",),
    ),
    ".claude/commands/validate.md": Entry(
        lane="instruction", status="clean",
        members=("M10-completion-forks",),
        note="completion fork fills descriptions with finding "
             "ids/paths",
        wire_tokens=("render them with non-printables escaped.",),
    ),
    ".claude/skills/exploitability-validation/stage-1-outputs.md": Entry(
        lane="instruction", status="clean",
        members=("M10-completion-forks",),
        note="post-run fork fills descriptions with finding "
             "ids/files/statuses",
        wire_tokens=("render them with non-printables escaped",),
    ),
    ".claude/commands/project.md": Entry(
        lane="instruction", status="clean",
        members=("M11-project-destructive-confirms",),
        note="clean/adopt confirms preview arbitrary directory "
             "listings",
        wire_tokens=("render entries with non-printables escaped and "
                     "cap the listing length explicitly",),
    ),
    "tiers/validation-recovery.md": Entry(
        lane="instruction", status="clean",
        members=("M15-validation-recovery-fork",),
        note="recovery-outcome fork offered at the completion fork "
             "quotes failure/error excerpts from the target and "
             "tooling; mid-pipeline recovery itself is report-and-"
             "continue, never a blocking ask",
        wire_tokens=("render them with non-printables escaped",
                     "gate with `libexec/raptor-may-ask` first",
                     "Non-interactive fallback",),
    ),
    ".claude/agents/crash-analysis-agent.md": Entry(
        lane="instruction", status="clean",
        members=("M16-crash-fetch-host-consent",),
        note="denied-attachment-host consent quotes a hostname and "
             "denial excerpt derived from the hostile tracker page; "
             "non-interactive fallback keeps the denial",
        wire_tokens=("with non-printables escaped",
                     "Gate with `libexec/raptor-may-ask`",
                     "Non-interactive fallback",),
    ),
    "docs/wsl.md": Entry(
        lane="instruction", status="clean",
        members=("M18-wsl-floor-refusal-offer",),
        note="refusal-boundary offer quotes the floor refusal text "
             "(carries kernel-derived detail); the option commands "
             "are RAPTOR-authored constants, the grant is executed "
             "only by the operator at their own TTY, and the "
             "non-interactive fallback is the already-printed "
             "refusal",
        wire_tokens=("Quote the refusal",
                     "non-printables escaped",
                     "libexec/raptor-may-ask",
                     "Non-interactive fallback",),
    ),
    # ── instruction lane: adjudicated clean (no external content) ─
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
    ".claude/commands/scorecard.md": Entry(
        lane="instruction", status="clean",
        note="model-name clarify question asks for missing operator "
             "input (the ambiguous name the operator themselves "
             "typed); no external content rendered",
    ),
    ".claude/agents/oss-investigator-gh-archive-agent.md": Entry(
        lane="instruction", status="clean",
        note="doctrine-compliant mention only: the file states the "
             "dispatched subagent CANNOT ask and names the "
             "github-archive skill's non-interactive fallback it "
             "applies instead",
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
    r"structured choice|offer the (?:user|operator) choices"
    # Escaped-member spellings found live in the validation lane: an
    # instruction can direct an ask as "ask (the) user" or as an
    # offer-N-options menu without ever speaking the doctrine's own
    # vocabulary — both must join the universe (doctrine-compliant
    # mentions like "cannot ask the user" join too and are
    # adjudicated clean).
    r"|\bask (?:the )?user"
    r"|offer \d+(?:-\d+)? options",
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


def _python_prompt_count(tree: ast.AST) -> int:
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in ("input", "confirm"):
            count += 1
        elif (isinstance(fn, ast.Attribute) and fn.attr == "confirm"
                and isinstance(fn.value, ast.Name)
                and fn.value.id in _CONFIRM_OWNERS):
            count += 1
    return count


def _python_prompts(tree: ast.AST) -> bool:
    return _python_prompt_count(tree) > 0


def _prompt_call_count(path: Path) -> int:
    """Prompt call sites in *path*, per the enumeration's own
    detectors: AST ``input()``/``confirm()`` calls for Python,
    prompting ``read`` lines for bash (the ``SyntaxError`` branch —
    same convention as :func:`enumerate_surfaces`)."""
    text = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return sum(
            1 for ln in text.splitlines() if _bash_read_has_prompt(ln))
    return _python_prompt_count(tree)


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

    def test_code_lane_prompt_counts_pinned(self):
        """File-keyed adjudication alone lets a SECOND prompt added to
        an already-registered file inherit the file's adjudication
        unreviewed (probe-proven on the fp-ceremony surface). Every
        code-lane entry pins its prompt-site count, so a new consent
        surface in a registered file fails closure until the entry is
        re-adjudicated with the new count (update ``prompts=`` and the
        note in the same reviewed change)."""
        problems = []
        for rel, entry in REGISTRY.items():
            if entry.lane != "code":
                continue
            if entry.prompts is None:
                problems.append(
                    f"{rel}: code-lane entry without a prompts= pin")
                continue
            actual = _prompt_call_count(REPO_ROOT / rel)
            if actual != entry.prompts:
                problems.append(
                    f"{rel}: {actual} prompt site(s) found, "
                    f"{entry.prompts} adjudicated — re-adjudicate the "
                    "entry for the new/removed surface")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_instruction_member_rows_pin_doctrine_wording(self):
        """Mirror of the sanitised-lane tripwire for the instruction
        lane, DERIVED from the registry shape rather than enumerated:
        every instruction-lane ``clean`` row that carries display-
        integrity members (external content reaches its prompt) must
        pin per-surface wording tokens, and each token must still be
        present in the file. Without this, deleting the
        display-integrity wording from a fill site (the exact
        approved-doctrine text the ``clean`` adjudication rests on)
        kept CI green — the row stayed enumerated and ``clean`` while
        the doctrine it certified was gone. Presence-only, like the
        sanitised lane: a file carrying the wording at one of several
        identical fill sites still passes here; the per-surface
        adjudication note remains the reviewer's map."""
        for rel, entry in REGISTRY.items():
            if entry.lane != "instruction" or not entry.members:
                continue
            self.assertTrue(
                entry.wire_tokens,
                f"{rel}: instruction row carries display-integrity "
                "members but pins no wording tokens — a wording revert "
                "would pass CI; pin the fill-site doctrine text",
            )
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            for token in entry.wire_tokens:
                self.assertIn(
                    token, text,
                    f"{rel}: adjudicated clean but display-integrity "
                    f"wording {token!r} is gone from the fill site — "
                    "re-adjudicate (clean rows rest on that wording)",
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
            # Command-prefixed idioms: the canonical safe-read
            # spellings put words before ``read`` — a
            # words[0]=="read" anchor missed all of these.
            'IFS= read -rp "Name? " ans',
            'while read -rp "> " cmd; do',
            'foo && read -p "sure? " a',
            'if read -p "ok? " a; then',
            '  LC_ALL=C IFS= read -rp "x: " v',
            'do_thing || read -p "retry? " r',
            'true; read -t 5 -p "quick? " ans',
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
            # ``read`` in argument position is not a command.
            "grep read -p file",
            "xargs -0 read -p",
            # Prefixed spellings without a prompt flag stay out.
            'IFS= read -r line',
            "while read line; do",
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
            # validation-lane escaped-member spellings
            "After 3 retries, ask user",
            "Only ask the user if no binaries can be discovered",
            "Always Offer 3-4 Options",
            "offer 2 options",
        )
        for text in matching:
            self.assertTrue(_md_prompt_instruction(text), text)
        inert = (
            "compare [a/b] table columns",
            "an ask-user question is a different phrase",
            "ask-the-user thresholds",   # hyphenated compound, not an ask
            "task the user runs next",   # word boundary: not an ask
            "choices offered elsewhere in the doc",
            "[Y/X] is not a consent menu",
            "structured data, choice of encoding",
            "offer options for recovery",   # no count — out of the menu net
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
