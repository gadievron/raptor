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
from typing import Any

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
# include/require with a single literal-string argument (parens
# optional). A non-literal argument — variable, concatenation,
# constant — makes the statement a request-controllable dispatcher
# (``include($_GET['page'] . '.php')`` is the classic local-file-
# inclusion shape), which is exactly handler code, never wiring.
# The optional parens gate their own whitespace ((?:\(\s*)? /
# (?:\s*\))?): the naive \s*\(?\s* put two whitespace runs around
# an optional atom — quadratic on an "include"-opening statement
# ending in a long space run. Match set unchanged.
_PHP_LITERAL_INCLUDE_RE = re.compile(
    r"^(?:include|include_once|require|require_once)\b\s*(?:\(\s*)?"
    r"(?:'[^'\n]*'|\"[^\"\n]*\")(?:\s*\))?\s*$",
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


def _php_wiring_statement(stmt: str) -> bool:
    """Whether one ``;``-delimited file-scope statement is wiring."""
    if _PHP_INCLUDE_KEYWORD_RE.match(stmt):
        return bool(_PHP_LITERAL_INCLUDE_RE.match(stmt))
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
