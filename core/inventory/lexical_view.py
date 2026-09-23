"""Tokenizer-grade non-code blanking for the suppression-witness text
detectors.

Shared lexical substrate for :mod:`core.inventory.dead_scope` and
:mod:`core.inventory.module_load_abort` on the languages whose
witnesses (``lexical_dead`` / ``module_aborts``) are enforce-eligible
hard-suppress evidence but have no stdlib parser: JavaScript /
TypeScript / TSX, Rust, Ruby and PHP. Those detectors make
reachability rulings over TEXT, so their view of "what is code" must
match a real lexer's on every shape an untrusted repo can craft —
comments, strings, template literals, regex literals, heredocs /
nowdocs, and HTML text around PHP tags.

Hand-rolled lexing kept failing here: the per-language strippers and
the bespoke JS lexer each re-implemented a slice of their language's
lexical grammar and each shipped exploitable gaps (regex-vs-division
guessing, heredoc blindness, raw-text matching). This module replaces
all of them with the real thing: the tree-sitter grammar for the
language tokenizes the file, and :func:`blank_noncode` blanks every
non-code token span to spaces, preserving newlines so downstream line
arithmetic stays valid.

Refusal discipline (fail toward NO suppression):

* Grammar not installed → ``None``. The consumer bails on the file —
  no dead ranges, no abort. A heuristic fallback is deliberately NOT
  provided; a suppression-earning witness may not be minted from a
  guessed lexical view.
* Parse errors (``root_node.has_error`` — ERROR or MISSING anywhere)
  → :class:`LexicalRefusal`. Inside an unparsed region tree-sitter's
  token boundaries are recovery guesses, so string/comment content
  could leak into the "code" view; consumers bail on the whole file.
* Node-type drift: every table entry is verified against the
  installed grammar (``Language.id_for_node_kind``) once per process.
  A grammar upgrade that renames a lexical node type would otherwise
  silently stop blanking that class — the false-positive direction —
  so an unknown name disables the language entirely (``None``, loud
  log) until the table is updated. CI pins the same property via the
  node-type closure test.
* Table completeness (the LIVE direction): the grammar's own node-kind
  inventory is enumerated once per process, and every producible kind
  whose name matches the prose pattern must be classified — blanked or
  explicitly exempted with a reviewed rationale. An unclassified match
  (a grammar upgrade adding a prose kind, or a table regression)
  disables the language the same fail-closed way; CI mirrors the check
  as the completeness test.

Blanking is byte-based on the UTF-8 encoding (tree-sitter spans are
byte offsets); ``\\n`` / ``\\r`` bytes inside blanked spans are
preserved so line counts never shift. Two modes per node type:

* ``all`` — the whole span becomes spaces (comments, heredoc bodies,
  HTML text: nothing in them is evidence).
* ``edges`` — a BALANCED delimiter pair survives, everything else
  becomes spaces (quoted strings / regexes / templates: the
  delimiters keep the token in value position for downstream
  scanners — e.g. Ruby's ``raise "boom"`` must still read as
  raise-with-argument). The pair is the span's first and last byte
  when they are equal; for prefixed literals (Rust/PHP ``b"…"`` /
  ``r"…"`` / ``b'…'``) it is the closing quote plus the matching
  opening quote scanned past the prefix — the prefix itself is
  blanked. A span with no balanced pair (``?"`` char literals,
  ``%w{…}`` arrays, ``/re/flags`` regexes) blanks entirely: keeping
  the raw first/last bytes there leaves a lone unpaired quote or
  bracket that desynchronises every downstream string/brace skip —
  live code after the desync point reads as string interior, the
  false-suppression vector this module exists to kill.

A blanked node's children are never descended into: template / string
interpolation code is blanked with its literal. Interpolations hold
expressions, not statements, so no dead-``if`` header or abort
statement can be lost — while their contents (attacker-authored text
plus arbitrary nesting) can never desynchronise the code view.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING

from core.inventory import _ts_cache

if TYPE_CHECKING:
    from tree_sitter import Node

logger = logging.getLogger(__name__)


class LexicalRefusal(Exception):
    """The file cannot be blanked with confidence.

    Raised when the parse tree contains ERROR / MISSING nodes: token
    boundaries inside recovered regions are guesses, and a wrong guess
    can leak string/comment content into the code view (the
    false-suppression direction). Consumers making suppression rulings
    must catch this and bail on the whole file — report no dead ranges
    and no module-load abort — never fall back to a partial view.
    """


# Grammar routing: language name → (module, language-callable attr).
_GRAMMARS: dict[str, tuple[str, str]] = {
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "rust": ("tree_sitter_rust", "language"),
    "ruby": ("tree_sitter_ruby", "language"),
    "php": ("tree_sitter_php", "language_php"),
}

_BLANK_ALL = "all"
_BLANK_EDGES = "edges"

# Non-code node types per grammar → blank mode. Every name is verified
# producible by the installed grammar (id_for_node_kind) before use and
# by the closure test in CI — a dead or renamed entry fails loudly
# instead of silently un-blanking a lexical class.
_JS_FAMILY_MODES: dict[str, str] = {
    "comment": _BLANK_ALL,
    "html_comment": _BLANK_ALL,
    "string": _BLANK_EDGES,
    "template_string": _BLANK_EDGES,
    "regex": _BLANK_EDGES,
    # JSX text is display prose, not code (the PHP ``text`` analog).
    "jsx_text": _BLANK_ALL,
    # ``#!/usr/bin/env node`` — legal, idiomatic first line; its text
    # is interpreter routing, not code, and (being attacker-authored
    # prose that parses clean) it can carry abort statements or
    # unbalanced delimiters at apparent depth 0.
    "hash_bang_line": _BLANK_ALL,
}

# Type-level template literal text (``type T = `...`;``) is erased at
# compile time — its content is never executable, but it survives to
# depth 0 of the parse tree exactly like a value template. TS/TSX only:
# the JavaScript grammar cannot produce the node kind (and a
# non-producible entry would disable the language, so it must not be
# shared into the javascript table).
_TS_ONLY_MODES: dict[str, str] = {
    "template_literal_type": _BLANK_EDGES,
}

NONCODE_NODE_MODES: dict[str, dict[str, str]] = {
    "javascript": dict(_JS_FAMILY_MODES),
    "typescript": {**_JS_FAMILY_MODES, **_TS_ONLY_MODES},
    "tsx": {**_JS_FAMILY_MODES, **_TS_ONLY_MODES},
    "rust": {
        "line_comment": _BLANK_ALL,
        "block_comment": _BLANK_ALL,
        "string_literal": _BLANK_EDGES,
        "raw_string_literal": _BLANK_EDGES,
        "char_literal": _BLANK_EDGES,
        # rust-script shebang — same non-code prose as the JS
        # hash_bang_line.
        "shebang": _BLANK_ALL,
    },
    "ruby": {
        "comment": _BLANK_ALL,
        "string": _BLANK_EDGES,
        "chained_string": _BLANK_EDGES,
        "regex": _BLANK_EDGES,
        "heredoc_body": _BLANK_ALL,
        "subshell": _BLANK_EDGES,
        "string_array": _BLANK_EDGES,
        "symbol_array": _BLANK_EDGES,
        "delimited_symbol": _BLANK_EDGES,
        "character": _BLANK_EDGES,
        # ``__END__`` DATA section — never executed.
        "uninterpreted": _BLANK_ALL,
    },
    "php": {
        "comment": _BLANK_ALL,
        # HTML around / between the PHP tags is interpreter OUTPUT.
        "text": _BLANK_ALL,
        "text_interpolation": _BLANK_ALL,
        "string": _BLANK_EDGES,
        "encapsed_string": _BLANK_EDGES,
        "heredoc": _BLANK_ALL,
        "nowdoc": _BLANK_ALL,
        "shell_command_expression": _BLANK_EDGES,
    },
}

# --- Blank-table completeness oracle (the LIVE direction) ------------------
#
# The producibility check above (and the CI closure test) only proves
# listed names exist — the DEAD-entry direction. Nothing there notices
# a prose-bearing node kind the table misses entirely: ``hash_bang_line``
# was unlisted, so a one-line JS hashbang survived into the "code" view
# and minted a whole-file module-load abort on a live file. The oracle
# below closes the missing-member direction mechanically: every visible
# named node kind the installed grammar can produce whose NAME matches
# the prose pattern must be classified — blanked (in the table) or
# explicitly exempted with a reviewed rationale. An unclassified match
# disables the language (fail closed, loud log), exactly like table
# drift: better no witness than a witness minted over unblanked prose.
#
# The kind universe is derived from the grammar itself
# (``node_kind_count`` / ``node_kind_for_id``), so a grammar upgrade
# that ADDS a prose kind fails here instead of silently leaking its
# content into the code view. The pattern errs broad (``literal``
# matches numeric literals too); breadth costs only reviewed exempt
# entries, never soundness.
_PROSE_KIND_RE = re.compile(
    r"comment|string|te?xt|regex|template|heredoc|nowdoc|char|doc"
    r"|shebang|hash_bang|uninterpreted|symbol|literal|shell"
)

# Reviewed non-table classifications, per grammar. Two safe categories:
#
# * interior — the kind only occurs beneath a table-blanked span
#   (children of a blanked node are never descended, so it is blanked
#   with its parent);
# * constrained charset / code — the kind's content cannot carry
#   quotes, brackets, or prose (numeric literals, bare symbols), or it
#   is a code construct whose name merely collides with the pattern.
_PROSE_EXEMPT_KINDS: dict[str, frozenset[str]] = {
    "javascript": frozenset({
        "regex_pattern",          # interior of regex
        "regex_flags",            # interior of regex
        "string_fragment",        # interior of string / template_string
        "template_substitution",  # interior of template_string
        # ``&amp;`` — sibling of jsx_text in JSX children; token
        # charset is ``&[A-Za-z0-9#xX];`` — no quotes / brackets.
        "html_character_reference",
    }),
    "typescript": frozenset({
        "regex_pattern",
        "regex_flags",
        "string_fragment",
        "template_substitution",
        "template_type",          # interior of template_literal_type
        # Type-position wrapper (``type T = "a"``): a code node whose
        # prose content is its child string / template node, blanked
        # on descent.
        "literal_type",
    }),
    "tsx": frozenset({
        "regex_pattern",
        "regex_flags",
        "string_fragment",
        "template_substitution",
        "template_type",
        "literal_type",
        "html_character_reference",
    }),
    "rust": frozenset({
        "string_content",             # interior of string_literal
        "doc_comment",                # interior of line/block_comment
        "inner_doc_comment_marker",   # interior of line/block_comment
        "outer_doc_comment_marker",   # interior of line/block_comment
        # Numeric / boolean token charsets — digits, sign, suffixes.
        "boolean_literal",
        "integer_literal",
        "float_literal",
        "negative_literal",
    }),
    "ruby": frozenset({
        "string_content",     # interior of string / bare_string
        "heredoc_content",    # interior of heredoc_body
        "heredoc_end",        # interior of heredoc_body
        "bare_string",        # interior of string_array (%w[...])
        "bare_symbol",        # interior of symbol_array (%i[...])
        # ``<<~EOT`` / ``<<~'EOT'`` opener token — kept deliberately
        # as value-position evidence (``msg = <<~EOT`` still reads as
        # assignment-with-value); a quoted delimiter's quotes pair
        # WITHIN the token, so it can never desync a string skip.
        "heredoc_beginning",
        # ``:sym`` / ``key:`` — identifier charset, no delimiters.
        "simple_symbol",
        "hash_key_symbol",
    }),
    "php": frozenset({
        "string_content",   # interior of encapsed_string / heredoc_body
        "heredoc_start",    # interior of heredoc / nowdoc
        "heredoc_body",     # interior of heredoc
        "heredoc_end",      # interior of heredoc / nowdoc
        "nowdoc_body",      # interior of nowdoc
        "nowdoc_string",    # interior of nowdoc_body
        "list_literal",     # ``list($a, $b) = …`` — code construct
    }),
}


def _prose_completeness_gap(language: str, lang) -> list[str]:
    """Visible named node kinds the grammar can produce whose name
    matches the prose pattern but which are neither blanked nor
    exempted — each is a potential unblanked-prose leak."""
    table = NONCODE_NODE_MODES[language]
    exempt = _PROSE_EXEMPT_KINDS[language]
    gap = []
    for i in range(lang.node_kind_count):
        if not (lang.node_kind_is_named(i) and lang.node_kind_is_visible(i)):
            continue
        kind = lang.node_kind_for_id(i)
        if kind is None or not _PROSE_KIND_RE.search(kind):
            continue
        if kind not in table and kind not in exempt:
            gap.append(kind)
    return gap


# Languages whose table survived id_for_node_kind validation this
# process (value: the language object), or None when the grammar is
# absent / the table has drifted. Import- and thread-safe: worst case
# two threads validate concurrently and store the same result.
_VALIDATED: dict[str, object | None] = {}


def _language_for(language: str) -> object | None:
    """The validated tree_sitter Language for *language*, or ``None``
    when unavailable (grammar missing, runtime missing, or a table
    node-type name the installed grammar cannot produce)."""
    if language in _VALIDATED:
        return _VALIDATED[language]
    result: object | None = None
    route = _GRAMMARS.get(language)
    if route is not None:
        mod = _ts_cache.import_grammar(route[0])
        if mod is not None:
            try:
                from tree_sitter import Language
                lang = Language(getattr(mod, route[1])())
                unknown = [
                    name for name in NONCODE_NODE_MODES[language]
                    if not lang.id_for_node_kind(name, True)
                ]
                gap = _prose_completeness_gap(language, lang)
                if unknown:
                    # Fail CLOSED: a renamed node type would silently
                    # stop blanking its lexical class (the false-
                    # suppression direction). Disable the language.
                    logger.warning(
                        "lexical_view: %s grammar does not produce "
                        "%s — non-code blanking disabled for this "
                        "language (witnesses degrade to none)",
                        language, unknown,
                    )
                elif gap:
                    # Fail CLOSED on the LIVE direction too: the
                    # grammar produces a prose-named node kind the
                    # table does not classify (grammar upgrade adding
                    # a kind, or a table regression). Its content
                    # would survive into the "code" view.
                    logger.warning(
                        "lexical_view: %s grammar produces unclassified "
                        "prose node kind(s) %s — non-code blanking "
                        "disabled for this language (witnesses degrade "
                        "to none)",
                        language, gap,
                    )
                else:
                    result = lang
            except Exception:  # noqa: BLE001 — degrade, never crash
                logger.debug(
                    "lexical_view: %s language load failed", language,
                    exc_info=True,
                )
    _VALIDATED[language] = result
    return result


def _parser_for(language: str):
    lang = _language_for(language)
    if lang is None:
        return None
    # Key by validated-table identity so the per-thread parser cache
    # (shared with extractors/call_graph — disjoint key space) reuses
    # one Parser per language per thread.
    return _ts_cache.cached_parser(
        ("lexical_view", language), lambda: lang,
    )


# Successful blanked views, memoized so the two witness detectors
# (dead_scope, module_load_abort) share one parse per file: the
# inventory builder calls both back-to-back on the same content. Keyed
# on the validated Language object's identity as well, so revalidation
# (grammar install/removal, table change) can never serve a stale
# view. Small and bounded: refusals and grammar-absent results are
# never cached (they must stay loud and re-checkable).
_MEMO_MAX = 8
_memo: OrderedDict[tuple[str, int, str], str] = OrderedDict()
_memo_lock = threading.Lock()


def blank_noncode(language: str, content: str) -> str | None:
    """Blank every non-code token (comments, strings, templates,
    regexes, heredocs, HTML text) in *content* to spaces, preserving
    newlines. Returns the blanked view, ``None`` when no validated
    grammar is available for *language* (consumers bail — no witness),
    or raises :class:`LexicalRefusal` when the parse contains errors.
    """
    lang = _language_for(language)
    if lang is None:
        return None
    key = (language, id(lang), content)
    with _memo_lock:
        cached = _memo.get(key)
        if cached is not None:
            _memo.move_to_end(key)
            return cached
    view = _blank_noncode_uncached(language, content)
    if view is not None:
        with _memo_lock:
            _memo[key] = view
            while len(_memo) > _MEMO_MAX:
                _memo.popitem(last=False)
    return view


def _blank_noncode_uncached(language: str, content: str) -> str | None:
    parser = _parser_for(language)
    if parser is None:
        return None
    data = bytearray(content.encode("utf-8", errors="replace"))
    try:
        tree = parser.parse(bytes(data))
    except _ts_cache.ParseBudgetExceeded as exc:
        # Budget exhaustion is a REFUSAL, not grammar absence: None
        # here would read as "no validated grammar" and the file
        # silently drops out of every witness. LexicalRefusal keeps
        # the loud path — callers already treat it as "no vouched
        # view", and the chokepoint recorded the analysis gap.
        raise LexicalRefusal(
            f"{language}: {exc} — refusing to vouch a code view"
        ) from None
    except Exception:  # noqa: BLE001 — degrade toward no witness
        logger.debug("lexical_view: %s parse failed", language,
                     exc_info=True)
        return None
    root = tree.root_node
    if root.has_error:
        raise LexicalRefusal(
            f"{language}: parse errors — token boundaries in recovered "
            f"regions are guesses; refusing to vouch a code view"
        )
    modes = NONCODE_NODE_MODES[language]
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        mode = modes.get(node.type)
        if mode is not None:
            _blank_span(data, node.start_byte, node.end_byte, mode)
            continue  # children are part of the blanked literal
        stack.extend(node.children)
    return data.decode("utf-8", errors="replace")


# Quote delimiters an edges-mode span may keep when asymmetric: the
# closing byte identifies the opening byte to scan for. Bracket-family
# closers (``%w{…}`` / ``%w[…]``) are deliberately NOT included — their
# opener differs from the closer, so no surviving pair can balance for
# a naive scanner; those spans blank entirely.
_EDGE_QUOTES = frozenset(b"\"'`")


def _blank_span(data: bytearray, start: int, end: int, mode: str) -> None:
    keep_lo = keep_hi = -1
    if mode == _BLANK_EDGES and end - start >= 2:
        close = data[end - 1]
        if data[start] == close:
            # Symmetric token (plain string / template / regex): the
            # raw first/last bytes are already a balanced pair.
            keep_lo = start
        elif close in _EDGE_QUOTES:
            # Prefixed literal (``b"x"`` / ``r"y"`` / ``b'z'``): the
            # span starts at the prefix, so keeping the raw first byte
            # leaves the CLOSING quote unpaired — downstream quote
            # skips then pair it with a later literal's opener and
            # swallow real code. Keep the matching opening quote
            # instead (first occurrence of the closing byte; only
            # prefix bytes precede it in any real token) and blank
            # the prefix. No occurrence before end-1 (``?"`` char
            # literals) → no balanced pair → blank the whole span.
            pos = data.find(close, start, end - 1)
            if pos != -1:
                keep_lo = pos
        if keep_lo != -1:
            keep_hi = end - 1
    for i in range(start, end):
        if i == keep_lo or i == keep_hi:
            continue
        if data[i] not in (0x0A, 0x0D):
            data[i] = 0x20


__all__ = [
    "LexicalRefusal",
    "NONCODE_NODE_MODES",
    "blank_noncode",
]
