"""Script-per-file handler classification — the ONE home.

For languages where file-scope statements ARE the program (classic
PHP request handlers — see ``SCRIPT_PER_FILE_LANGUAGES`` in
``core.inventory.languages``), an ``interstitial`` checklist item
whose content goes beyond include/require wiring is the request
handler, not extraction residue. This module owns that classification
end to end:

* the content classifier (``interstitial_is_handler``);
* the builder-side stamping helpers that persist the verdict on the
  checklist item at inventory time (``stamp_script_handler_items``),
  under the additive snake_case field ``script_handler``;
* the consumer-side reader (``script_handler_stamp``).

Consumers (gap selection, gap-for-site binding, coverage denominators,
function lookup, inventory diff, corpus credit) read the stamp — none
recomputes the classification from source. The single deliberate
exception is ``core.audit.gaps.compute_gaps``: on a checklist written
before the stamp existed (resumable runs) it recomputes from source —
full-fidelity, since it already hydrates the span — rather than
degrade. Stamp-less consumers without source access degrade to their
pre-stamp behavior instead; each states its direction at the read
site.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple

from .languages import SCRIPT_PER_FILE_LANGUAGES

#: The additive checklist-item field carrying the classification.
#: Stamped by the inventory builder on every ``interstitial`` item of
#: a script-per-file-language file; absent on older checklists and on
#: compiled/object-language items.
SCRIPT_HANDLER_FIELD = "script_handler"

# File-scope PHP statements that are wiring, not handler logic:
# namespace/strictness declarations and scope declarations. The
# include family is handled separately — it is wiring ONLY with a
# literal-string argument. Everything else (assignments, superglobal
# reads, echo/output, control flow, calls) counts as handler code.
#
# The declare arm is END-ANCHORED: PHP's declare accepts a statement
# body (``declare(ticks=1) f($x);`` runs f), so a bare prefix match
# let the body ride as "wiring". Only a whole ``declare(<directive>)``
# piece is wiring; a statement body, a block opener ``{``, or an
# unclosed paren classifies toward inclusion — a declare BLOCK's
# content and its closing ``}`` line classify independently anyway,
# so block-form files were never wiring-only.
#
# The global arm accepts ONLY a plain end-anchored variable list
# (``$name`` identifiers, comma-separated): ``global ${expr};``
# EVALUATES expr at runtime, so a brace-interpolated name is code,
# never wiring. ``$$var`` doesn't execute but is excluded too —
# including it would save one review slot at the cost of reasoning
# about every indirection shape; exclusion is the inclusion-biased
# direction. PHP identifiers allow bytes 0x80-0xff; the class covers
# the decoded Latin-1 range, and anything wider falls out of the
# match — toward inclusion, like every unrecognised piece.
# ``use``/``namespace`` stay prefix-anchored: their tails are
# compile-time-only syntax (imports incl. function/const/group forms;
# a namespace BLOCK's body classifies independently).
_PHP_WIRING_STMT_RE = re.compile(
    r"^(?:use|namespace)\b"
    r"|^global\s+\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
    r"(?:\s*,\s*\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)*\s*$"
    r"|^declare\s*\([^()]*\)\s*$",
)
_PHP_INCLUDE_KEYWORD_RE = re.compile(
    r"^(?:include|include_once|require|require_once)\b",
)
# ---------------------------------------------------------------------------
# Include-argument shape classification — the ONE include-literal
# decision, shared by two consumers:
#
#   * the wiring test below (a literal include is wiring; anything
#     else — variable, concatenation, constant prefix — is handler
#     code: ``include($_GET['page'] . '.php')`` is the classic
#     local-file-inclusion shape);
#   * the PHP call-graph walker's structured include edges
#     (``core.inventory.call_graph._PhpCallGraph``), which record the
#     shape census per edge.
#
# The classification is a SYNTACTIC census, never a resolution
# verdict: ``const_prefix`` says "constant then literal material",
# it does not say the constant resolves (shared library files
# inherit their prefix constant from the includer, so resolution is
# a per-entry concern, not a per-statement one).
# ---------------------------------------------------------------------------

#: Shape enum. ``config_bounded`` is reserved for enumerable loader
#: patterns resolved from machine-readable config (Composer PSR-4,
#: plugin registries) — no producer emits it yet; consumers must
#: treat it like ``dynamic``.
INCLUDE_SHAPES = ("literal", "const_prefix", "config_bounded", "dynamic")


class IncludeClassification(NamedTuple):
    """Shape census for one include/require argument expression.

    ``literal_tail`` is the trailing run of literal string material
    (after the last non-literal part), when any. ``literal_stem`` is
    the literal run immediately BEFORE the last non-literal part of a
    ``dynamic`` argument (``"modules/$MOD.mod"`` → stem ``modules/``,
    tail ``.mod``) — census/candidate material only.
    """

    shape: str
    const_name: str | None = None
    literal_tail: str | None = None
    literal_stem: str | None = None


_CONST_NAME_RE = re.compile(r"^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$")

# PHP string-interpolation hole openers inside a double-quoted string:
# $name, ${expr}, {$expr}.
_INTERP_VAR_RE = re.compile(
    r"\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*(?:\[[^\]]*\]|->[A-Za-z_]\w*)?"
    r"|\$\{[^}]*\}"
    r"|\{\$[^}]*\}",
)


# Prose-shape allowlist for star-led docblock slices (see the guard
# in ``php_interstitial_is_handler``). Enumerating what CODE needs
# (keywords, then capability characters) repeatedly left a next
# member — the sound direction is to enumerate what PROSE looks like
# and scan everything else. A star-led line is skippable prose only
# when it carries NONE of the characters that can form, feed, or
# terminate an expression statement:
#   `        shell execution
#   $        variables / superglobals
#   (        calls / grouping
#   ;        a terminator completes an executing statement
#   ' "      string literals (operands to include/require, string
#            arithmetic)
#   {        blocks / interpolation
#   ?>       close tag — re-enters markup/code mid-line
# AND no parenless expression-head keyword as a whole word: PHP
# executes ``new C`` / ``clone``-family / ``print`` / backtickless
# ``include``/``require`` (bare-constant operand) without any of the
# characters above when the terminator lands on a LATER line, so the
# word check is what closes the split-terminator family. Keywords are
# case-insensitive in PHP, so the match is too.
#
# Both directions of the trade, priced deliberately: prose that
# merely LOOKS code-capable — inline code spans in backticks,
# ``{@inheritdoc}``, a semicolon or quote in a sentence, or the
# English words "new" / "print" / "include" / "yield" — flips its
# span to one review slot (inclusion, the cheap direction). Tightening
# the allowlist back toward "skip more prose" re-opens force-False
# channels one spelling at a time; loosening further (dropping the
# skip entirely) is blocked only by the cost of writing every bare
# docblock slice into the review queue.
_PHP_STAR_PROSE_REJECT_CHARS = ("`", "$", "(", ";", "'", '"', "{", "?>")
_PHP_STAR_PROSE_REJECT_WORD_RE = re.compile(
    r"\b(?:new|clone|print|throw|yield|include|include_once|require|"
    r"require_once)\b",
    re.IGNORECASE,
)


def _php_star_line_is_prose(line: str) -> bool:
    """Whether a ``*``-led line is skippable docblock prose (the
    allowlist above): no code-capable characters, no parenless
    expression-head keywords."""
    body = line.lstrip("*").strip()
    if any(needle in body for needle in _PHP_STAR_PROSE_REJECT_CHARS):
        return False
    return not _PHP_STAR_PROSE_REJECT_WORD_RE.search(body)


def _strip_outer_parens(text: str) -> str:
    """Strip matched outer parentheses (repeatedly, whitespace-aware)."""
    s = text.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    balanced = False
                    break
        if not balanced or depth != 0:
            break
        s = s[1:-1].strip()
    return s


def _split_concat_parts(text: str) -> list[str] | None:
    """Split an expression on top-level ``.`` concatenation.

    Quote- and bracket-aware. Returns None when the text is not
    scannable (unterminated string, unbalanced brackets) — callers
    classify that as ``dynamic`` (inclusion-biased, same trade as the
    unrecognised-line rule above).
    """
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"":
            quote = ch
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    break
                j += 1
            if j >= n:
                return None  # unterminated string
            buf.append(text[i:j + 1])
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return None
        if ch == "." and depth == 0:
            # ``.=`` / floats can't appear at the top level of an
            # include argument; a bare top-level dot is concatenation.
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if depth != 0:
        return None
    parts.append("".join(buf))
    return parts


def _unescape_single(text: str) -> str:
    """PHP single-quote semantics: only ``\\'`` and ``\\\\`` escape."""
    return text.replace("\\\\", "\\").replace("\\'", "'")


def _unescape_double_literal(text: str) -> str:
    """Minimal double-quote unescape for path material."""
    return (
        text.replace("\\\\", "\\").replace('\\"', '"').replace("\\$", "$")
    )


def _atomize(part: str) -> list[tuple[str, str]]:
    """One concatenation operand → ``(kind, text)`` atoms.

    Kinds: ``lit`` (text = literal value), ``const`` (text = name),
    ``dyn`` (text = ""). A double-quoted string with interpolation
    holes expands into an alternating lit/dyn sequence.
    """
    s = part.strip()
    if not s:
        return [("dyn", "")]
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return [("lit", _unescape_single(s[1:-1]))]
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        body = s[1:-1]
        atoms: list[tuple[str, str]] = []
        pos = 0
        for m in _INTERP_VAR_RE.finditer(body):
            # An escaped ``\$`` is literal, not a hole.
            if m.start() > 0 and body[m.start() - 1] == "\\":
                continue
            if m.start() > pos:
                atoms.append(
                    ("lit", _unescape_double_literal(body[pos:m.start()])))
            atoms.append(("dyn", ""))
            pos = m.end()
        if pos < len(body):
            atoms.append(("lit", _unescape_double_literal(body[pos:])))
        return atoms or [("lit", "")]
    if _CONST_NAME_RE.match(s):
        return [("const", s)]
    return [("dyn", "")]


def classify_include_argument(arg: str) -> IncludeClassification:
    """Classify one include/require argument expression's shape.

    Never a resolution verdict — a ``const_prefix`` edge's constant
    may only bind under a specific entry's environment (phase-1b
    walk); ``literal`` means the whole argument is static string
    material. Unscannable input classifies ``dynamic`` (the safe
    census direction: nothing is silently treated as static).
    """
    s = _strip_outer_parens(arg.strip().rstrip(";").strip())
    if not s:
        return IncludeClassification("dynamic")
    parts = _split_concat_parts(s)
    if parts is None:
        return IncludeClassification("dynamic")
    atoms: list[tuple[str, str]] = []
    for p in parts:
        atoms.extend(_atomize(p))
    if not atoms:
        return IncludeClassification("dynamic")

    kinds = [k for k, _ in atoms]
    # Trailing literal run (tail) — census material for every shape.
    tail_atoms: list[str] = []
    for kind, text in reversed(atoms):
        if kind != "lit":
            break
        tail_atoms.append(text)
    tail = "".join(reversed(tail_atoms)) or None

    if all(k == "lit" for k in kinds):
        return IncludeClassification(
            "literal", literal_tail="".join(t for _, t in atoms))
    if (kinds[0] == "const" and len(kinds) > 1
            and all(k == "lit" for k in kinds[1:])):
        return IncludeClassification(
            "const_prefix", const_name=atoms[0][1], literal_tail=tail)

    # dynamic: record the first-position constant (if any) and the
    # literal run immediately before the LAST non-literal atom (the
    # candidate-matching stem, e.g. "modules/" in "modules/$MOD.mod").
    const_name = atoms[0][1] if kinds[0] == "const" else None
    last_nonlit = max(i for i, k in enumerate(kinds) if k != "lit")
    stem_atoms: list[str] = []
    for i in range(last_nonlit - 1, -1, -1):
        if kinds[i] != "lit":
            break
        stem_atoms.append(atoms[i][1])
    stem = "".join(reversed(stem_atoms)) or None
    return IncludeClassification(
        "dynamic", const_name=const_name, literal_tail=tail,
        literal_stem=stem)


def _php_wiring_statement(stmt: str) -> bool:
    """Whether one ``;``-delimited file-scope statement is wiring."""
    m = _PHP_INCLUDE_KEYWORD_RE.match(stmt)
    if m:
        # The include-literal decision is the shared classifier's —
        # one parser, two consumers (this wiring test and the
        # call-graph include edges). Literal → wiring; const_prefix /
        # dynamic → handler code (a request-controllable or
        # environment-dependent include is never boilerplate).
        return classify_include_argument(stmt[m.end():]).shape == "literal"
    return bool(_PHP_WIRING_STMT_RE.match(stmt))


def php_interstitial_is_handler(source: str | None) -> bool:
    """True when a PHP file-scope span carries statements beyond
    include/require-style boilerplate.

    Comment-aware, statement-wise (``;``-split, so a boilerplate
    keyword opening the line cannot swallow a second statement —
    ``global $x; $x = $_GET['q'];`` is handler code) classifier,
    deliberately biased toward inclusion: an unrecognised line
    (including raw markup — output surface) counts as handler code,
    as does a ``;`` inside a string literal splitting a wiring
    statement apart. The cost of a false positive is one review slot;
    a false negative writes off a request handler.

    Close tags terminate too: PHP ends the current statement AND any
    ``//`` / ``#`` line comment at ``?>``, resuming markup (and code
    again after the next open tag). Lines are therefore scanned per
    ``?>``-delimited segment — a prefix-anchored wiring keyword or a
    comment opener before a close tag cannot swallow what runs after
    it (``global $x ?><?php f($_GET['c']);`` and
    ``include 'a.php'; // x ?><?php f($_GET['c']);`` are handler
    code). ``/* */`` block comments deliberately keep swallowing
    ``?>`` — PHP does not close them at a close tag.
    """
    if not source:
        return False
    in_comment = False
    for raw in source.splitlines():
        line = raw.strip()
        if not line:
            continue
        if in_comment:
            end = line.find("*/")
            if end < 0:
                continue
            in_comment = False
            line = line[end + 2:].strip()
            if not line:
                continue
        # Peel a line-leading tag marker so ``<?php status_handler();``
        # classifies its statement (and ``<?= $x ?>`` its expression).
        for marker in ("<?php", "<?=", "<?"):
            if line.startswith(marker):
                line = line[len(marker):].strip()
                break
        if not line:
            continue
        if line.startswith("/*"):
            end = line.find("*/", 2)
            if end < 0:
                in_comment = True
                continue
            line = line[end + 2:].strip()
            if not line:
                continue
        if line.startswith("*") and _php_star_line_is_prose(line):
            # Docblock-body heuristic: span hydration can slice
            # mid-docblock, where in_comment was never armed, so a
            # ``*``-led line reads as comment prose. But ``*`` (and
            # ``**``) also begins a valid CONTINUATION of the
            # previous statement — arithmetic on an unterminated
            # ``include '1'`` — so a payload can live in the star
            # line itself. Only PROSE-SHAPED lines skip (see
            # ``_php_star_line_is_prose`` for the allowlist and the
            # priced trade); everything else takes the normal
            # statement/segment scan, which also handles any close
            # tag on the line (``?>`` is in the reject set).
            # ``*`` / ``**`` are the only continuation operators
            # skipped at all — ``/`` / ``+`` / ``%`` continuations
            # already classify True, and ``//`` / ``#`` really are
            # comments.
            continue
        for seg_index, segment in enumerate(line.split("?>")):
            segment = segment.strip()
            if not segment:
                continue
            if seg_index:
                # Text after a close tag is raw markup until an open
                # tag re-enters PHP. Markup is output surface —
                # handler code by the inclusion bias above.
                reentered = False
                for marker in ("<?php", "<?=", "<?"):
                    if segment.startswith(marker):
                        segment = segment[len(marker):].strip()
                        reentered = True
                        break
                if not reentered:
                    return True
                if not segment:
                    continue
            for stmt in segment.split(";"):
                stmt = stmt.strip()
                if not stmt:
                    continue
                if stmt.startswith(("//", "#")):
                    break  # comment: prose to the segment's end (the
                    #        close tag already ended it — PHP line
                    #        comments never cross ``?>``)
                if not _php_wiring_statement(stmt):
                    return True
    return False


# Per-language content classifiers. A language belongs in
# SCRIPT_PER_FILE_LANGUAGES only with an extractor that leaves its
# executable file scope inside interstitial spans; when one joins the
# set, add its classifier here. A set member WITHOUT a classifier
# stamps True (inclusion-biased, same trade as the PHP classifier's
# unrecognised-line rule: a false positive costs one review slot, a
# false negative writes off the code requests actually execute).
_CLASSIFIERS = {
    "php": php_interstitial_is_handler,
}


def interstitial_is_handler(language: str, source: str | None) -> bool:
    """Classify one interstitial span's content for ``language``.

    False for every language outside ``SCRIPT_PER_FILE_LANGUAGES``
    (compiled/object file scope is declarations-and-braces glue;
    Python/JS module scope is already extracted as ``top_level``).
    """
    lang = (language or "").lower()
    if lang not in SCRIPT_PER_FILE_LANGUAGES:
        return False
    classifier = _CLASSIFIERS.get(lang)
    if classifier is None:
        return True
    return classifier(source)


def script_handler_stamp(item: Any) -> bool | None:
    """The item's persisted classification: True / False, or None when
    the stamp is absent or not a genuine bool.

    The checklist is a run-dir JSON artifact (shapes and values are
    attacker-writable), so only a real JSON bool counts — a forged
    ``"script_handler": "yes"`` reads as None and the consumer's
    documented stamp-absent fallback applies.
    """
    if not isinstance(item, dict):
        return None
    value = item.get(SCRIPT_HANDLER_FIELD)
    if isinstance(value, bool):
        return value
    return None


def _span_source(
    source_lines: list[str], line_start: Any, line_end: Any,
) -> str | None:
    """The item's source span out of pre-split file lines, or None for
    an unusable span (mirrors the gap-side hydration guard: bools are
    not line numbers)."""
    if (
        not isinstance(line_start, int) or isinstance(line_start, bool)
        or line_start <= 0
    ):
        return None
    end = line_start
    if isinstance(line_end, int) and not isinstance(line_end, bool) and line_end:
        end = line_end
    return "\n".join(source_lines[line_start - 1:end])


def stamp_script_handler_items(
    items: list[dict[str, Any]],
    language: str,
    content: str,
) -> bool:
    """Stamp ``script_handler`` on every interstitial item of one
    script-per-file-language file record. Mutates the item dicts.

    Always re-derives from ``content`` — existing values are
    overwritten, never trusted. On the builder's SHA-256 reuse path
    this is the self-healing property: the checklist sits in a
    writable run/cache directory, so a tampered stamp on a
    content-unchanged file (and any stale verdict from an older
    classifier) converges back to the content's truth on the next
    build instead of persisting indefinitely; content is identical by
    construction, so the re-derivation equals the original parse's.
    Returns True when any item was stamped (informational — the
    builder call sites don't branch on it; the record dicts are
    mutated in place either way).
    """
    if (language or "").lower() not in SCRIPT_PER_FILE_LANGUAGES:
        return False
    source_lines: list[str] | None = None
    stamped = False
    for item in items:
        if not isinstance(item, dict) or item.get("kind") != "interstitial":
            continue
        if source_lines is None:
            source_lines = content.splitlines()
        span = _span_source(
            source_lines, item.get("line_start"), item.get("line_end"))
        item[SCRIPT_HANDLER_FIELD] = interstitial_is_handler(language, span)
        stamped = True
    return stamped
