"""Context-family registry for the sanitizer-sufficiency witness.

Data-driven: each :class:`SinkContext` row carries the sink context's
breakout-payload corpus and its mechanical breakout predicate. Adding
a family is adding rows (plus executed ground-truth fixtures) — the
extraction / probe / verdict code paths never change per family.

Predicates run in PYTHON over the probe's decoded chain outputs: the
PHP probe only executes the extracted chain and marshals outputs, so
every predicate here is hermetically testable with no interpreter on
the host.

Only two families ship (the proven ones): HTML attribute/element
contexts vs. the htmlspecialchars/htmlentities family, and shell
command/argument contexts vs. escapeshellcmd/escapeshellarg. Glob
metacharacters (``*``/``?``), ``~`` expansion and ``#`` comments are
deliberately OUT of the shell corpus/predicate in this cut: their
injection power depends on filesystem/position context the witness
does not model, and a detection-grade confirm must not rest on them.
Growth rows, not gaps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

FAMILY_HTML = "html"
FAMILY_SHELL = "shell"

# HTML text context: a '<' opens markup only when followed by a tag
# name, '/', '!' or '?' (the HTML5 tag-open production) — a bare '<'
# before any other character stays character data, so flagging it
# would over-trigger insufficiency.
_HTML_TAG_OPEN_RE = re.compile(r"<[A-Za-z/!?]")


def _html_text_breakout(out: str) -> BreakoutCheck:
    if _HTML_TAG_OPEN_RE.search(out):
        return BreakoutCheck(
            True, "'<' + tag-open character survives the chain",
        )
    return BreakoutCheck(False)

#: Sanitizer names that anchor each family. Seed-sized by policy —
#: the channel only ever needs the names hypotheses actually cite.
FAMILY_SANITIZERS: dict[str, tuple[str, ...]] = {
    FAMILY_HTML: ("htmlspecialchars", "htmlentities"),
    FAMILY_SHELL: ("escapeshellarg", "escapeshellcmd"),
}


@dataclass(frozen=True)
class BreakoutCheck:
    """One payload's predicate result."""

    breakout: bool
    detail: str = ""


@dataclass(frozen=True)
class SinkContext:
    """One sink context class: corpus + breakout predicate."""

    context_id: str
    family: str
    description: str
    #: (payload_id, payload) pairs. Payloads are synthetic, ASCII,
    #: and small (<= 64 bytes) by construction — the caps below are
    #: asserted by the registry integrity test.
    corpus: tuple[tuple[str, str], ...]
    predicate: Callable[[str], BreakoutCheck]


#: Hard cap on payload bytes: the probe is time/memory capped and
#: literal-only target regexes run over these payloads, so small
#: inputs keep hostile-pattern blowup in the timeout->error lane.
#: Larger payloads buy nothing (every breakout class here is a
#: single-character survival question); smaller would cramp the
#: composite payloads. Registry test enforces it.
MAX_PAYLOAD_BYTES = 64


def _survives(char: str, label: str) -> Callable[[str], BreakoutCheck]:
    """Predicate factory: breakout when *char* survives in the output."""

    def check(out: str) -> BreakoutCheck:
        if char in out:
            return BreakoutCheck(True, f"{label} survives the chain")
        return BreakoutCheck(False)

    return check


def _unquoted_attr_breakout(out: str) -> BreakoutCheck:
    """Unquoted HTML attribute value: whitespace terminates the value
    (starting a new attribute) and ``>`` closes the tag. The HTML
    whitespace set includes carriage return."""
    for ch, label in (
        (" ", "space"), ("\t", "tab"), ("\n", "newline"),
        ("\r", "carriage return"), ("\x0c", "form feed"), (">", "'>'"),
    ):
        if ch in out:
            return BreakoutCheck(
                True, f"{label} survives — terminates the unquoted value",
            )
    return BreakoutCheck(False)


# ── POSIX-sh command-position scanner ────────────────────────────────
#
# Not shlex: shlex's posix mode raises/repairs on unterminated quotes,
# and an unterminated quote is a first-class breakout signal here (it
# re-contexts the remainder of the command the output is embedded in).
# The scanner models exactly what the predicate needs: field
# separation, active (unquoted + unescaped) metacharacters, and
# terminal quote state.

# Metacharacters that keep shell semantics when unquoted+unescaped.
_SH_ACTIVE = frozenset(";|&<>()`$\n")
# Inside double quotes these stay active unless backslash-escaped.
_SH_DQ_ACTIVE = frozenset('$`"')


@dataclass(frozen=True)
class ShellScan:
    fields: int
    active: tuple[str, ...]
    unterminated: str  # "" | "'" | '"' | "\\"


def scan_shell_word(text: str) -> ShellScan:
    """Scan *text* as it would be consumed in sh command position."""
    fields = 0
    active: list[str] = []
    in_field = False
    state = ""  # "" | "'" | '"'
    escaped = False
    for ch in text:
        if state == "'":
            if ch == "'":
                state = ""
            continue
        if escaped:
            escaped = False
            in_field = True
            continue
        if state == '"':
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                state = ""
            elif ch in _SH_DQ_ACTIVE:
                active.append(ch)
            continue
        # Unquoted state.
        if ch == "\\":
            escaped = True
            continue
        if ch == "'":
            state = "'"
            in_field = True
            continue
        if ch == '"':
            state = '"'
            in_field = True
            continue
        if ch in (" ", "\t", "\n"):
            if ch == "\n":
                active.append("\n")
            if in_field:
                fields += 1
                in_field = False
            continue
        if ch in _SH_ACTIVE:
            active.append(ch)
        in_field = True
    if in_field:
        fields += 1
    unterminated = state or ("\\" if escaped else "")
    return ShellScan(
        fields=fields,
        active=tuple(dict.fromkeys(active)),
        unterminated=unterminated,
    )


def _shell_command_breakout(out: str) -> BreakoutCheck:
    """Command/argument position: the output must stay ONE inert word."""
    scan = scan_shell_word(out)
    if scan.unterminated:
        return BreakoutCheck(
            True,
            f"unterminated {scan.unterminated!r} re-contexts the "
            "command tail",
        )
    if scan.active:
        pretty = ", ".join(repr(c) for c in scan.active)
        return BreakoutCheck(
            True, f"active shell metacharacter(s) survive: {pretty}",
        )
    if scan.fields > 1:
        return BreakoutCheck(
            True,
            f"field splitting yields {scan.fields} words — extra "
            "argument injected",
        )
    return BreakoutCheck(False)


def _shell_squote_breakout(out: str) -> BreakoutCheck:
    """Embedded inside target-authored single quotes: a single quote
    ALWAYS closes the context — sh single quotes have no escape
    character, so a backslash-prefixed ``\\'`` still breaks out."""
    if "'" in out:
        return BreakoutCheck(
            True,
            "single quote survives — closes the quoting context "
            "(backslash does not escape inside sh single quotes)",
        )
    return BreakoutCheck(False)


def _shell_dquote_breakout(out: str) -> BreakoutCheck:
    """Embedded inside target-authored double quotes."""
    escaped = False
    trailing_backslash = False
    for ch in out:
        if escaped:
            escaped = False
            trailing_backslash = False
            continue
        if ch == "\\":
            escaped = True
            trailing_backslash = True
            continue
        if ch in _SH_DQ_ACTIVE:
            label = {"$": "'$' expansion", "`": "backtick substitution",
                     '"': "'\"' closes the quoting context"}[ch]
            return BreakoutCheck(True, f"{label} survives unescaped")
    if trailing_backslash:
        return BreakoutCheck(
            True, "trailing backslash escapes the closing double quote",
        )
    return BreakoutCheck(False)


SINK_CONTEXTS: dict[str, SinkContext] = {
    ctx.context_id: ctx
    for ctx in (
        SinkContext(
            context_id="html-attr-squote",
            family=FAMILY_HTML,
            description="single-quoted HTML attribute value",
            corpus=(
                ("squote-bare", "'"),
                ("squote-attr", "x' onerror='y"),
                ("squote-mixed", "a'b<c"),
            ),
            predicate=_survives("'", "single quote"),
        ),
        SinkContext(
            context_id="html-attr-dquote",
            family=FAMILY_HTML,
            description="double-quoted HTML attribute value",
            corpus=(
                ("dquote-bare", '"'),
                ("dquote-attr", 'x" onerror="y'),
                ("dquote-mixed", 'a"b<c'),
            ),
            predicate=_survives('"', "double quote"),
        ),
        SinkContext(
            context_id="html-attr-unquoted",
            family=FAMILY_HTML,
            description="unquoted HTML attribute value",
            corpus=(
                ("space-attr", "x onmouseover=y"),
                ("tab-attr", "x\tonmouseover=y"),
                ("cr-attr", "x\ronmouseover=y"),
                ("gt-close", "x>y"),
            ),
            predicate=_unquoted_attr_breakout,
        ),
        SinkContext(
            context_id="html-text",
            family=FAMILY_HTML,
            description="HTML element/text content",
            corpus=(
                ("lt-open", "<i"),
                ("lt-tag", "</b><i>x"),
                ("lt-mixed", "a<b>c"),
            ),
            predicate=_html_text_breakout,
        ),
        SinkContext(
            context_id="shell-command",
            family=FAMILY_SHELL,
            description=(
                "sh command/argument position (the output is embedded "
                "unquoted in a command string)"
            ),
            corpus=(
                ("space-arg", "x --flag"),
                ("tab-arg", "x\t-y"),
                ("semi", "x;y"),
                ("pipe", "x|y"),
                ("amp", "x&y"),
                ("dollar-subst", "x$(y)"),
                ("backtick-subst", "x`y`"),
                ("newline", "x\ny"),
                ("redirect", "x>o"),
            ),
            predicate=_shell_command_breakout,
        ),
        SinkContext(
            context_id="shell-squote",
            family=FAMILY_SHELL,
            description=(
                "embedded inside target-authored sh single quotes"
            ),
            corpus=(
                ("squote-bare", "'"),
                ("squote-cmd", "x';y;'"),
                ("squote-escaped", "\\'"),
            ),
            predicate=_shell_squote_breakout,
        ),
        SinkContext(
            context_id="shell-dquote",
            family=FAMILY_SHELL,
            description=(
                "embedded inside target-authored sh double quotes"
            ),
            corpus=(
                ("dquote-bare", '"'),
                ("dollar-var", "$x"),
                ("backtick", "`y`"),
                ("backslash-tail", "x\\"),
            ),
            predicate=_shell_dquote_breakout,
        ),
    )
}


def contexts_for_family(family: str) -> tuple[SinkContext, ...]:
    return tuple(
        ctx for ctx in SINK_CONTEXTS.values() if ctx.family == family
    )
