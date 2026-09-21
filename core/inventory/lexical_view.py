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
