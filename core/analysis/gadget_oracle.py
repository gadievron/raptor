"""PHP gadget-chain oracle — mechanical CWE-502 witness, both directions.

Enumerates PHP magic methods across a target tree via tree-sitter-php
and traces property flows from unserialize-reachable object state into
sinks (file ops, command execution, include, SQL, output). Both
directions of the gadget question become tool-grounded:

* **Found chain** — a witness exhibit (class, magic method, property
  path, sink line). WITNESS-GRADE, detection-role: it boosts and
  exhibits, it never confirms a finding alone (every stamp this
  channel mints is detection-grade by :func:`is_detection_rule_id` —
  the sanwit precedent). A gadget chain adjudicates gadget EXISTENCE,
  not the taint path from request data to the unserialize call.
* **Verified absence** — a refutation INPUT, not a refutation. In this
  increment absence renders as strong hint-tier evidence with a
  completeness census attached ("no gadget chains found in the N/M
  parseable PHP files; depth limits stated"). Absence-as-suppression
  follows the binary oracle's earned-suppression precedent: NO
  consumer hard-suppresses on this artifact until a measured corpus
  earns the promotion (a named follow-up — see the module constants
  ``ABSENCE_*`` and the channel's outcome mapping, which never emits
  ``refuted``).

Approximations — stated, never implied away:

* **Flow depth**: intra-method direct flows (property reads,
  straight-line local assignments, concatenation/interpolation, a
  small seed set of string-propagating builtins) plus exactly ONE
  level of same-class method-call indirection. No inheritance-resolved
  dispatch, no cross-class hops, no loop/branch sensitivity. A gadget
  needing a deeper chain is NOT found — which is why absence is
  census-qualified evidence, not proof.
* **Class availability**: PHP gadget classes must be loaded or
  autoloadable at the unserialize site. Statically knowable bases are
  recorded per chain (``same_file`` / ``autoload_registered`` /
  ``included_somewhere`` via a provided include-graph / the honest
  ``not_established``); none of them proves runtime availability.
* **Trigger conditions**: ``__destruct``/``__wakeup``/
  ``__unserialize`` fire from unserialize itself; ``__toString`` /
  ``__call`` / ``__get`` / ``__set`` chains carry an explicit
  ``trigger_requires`` describing the extra usage context they need.
* **Encoding**: name identity is judged over the at-rest bytes with
  ASCII-only casefolding (PHP's rule). A source stored in UTF-16 is
  outside the model: its ``<?php`` open tag is equally invisible to
  this parser and to a stock Zend lexer, but a deployment that
  TRANSCODES files at include time could execute code the census
  never parsed. Recorded gap, not modelled.

The oracle is pure static analysis — no LLM calls, no execution of
target code. Grammar absence is a recorded capability gap (the
channel returns ``skipped``, the artifact stamps
``capability.tree_sitter_php: false``), NEVER a silent pass.
"""

from __future__ import annotations

import bisect
import heapq
import logging
import os
import re
import string
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: PHP resolves class, method, and function names case-insensitively
#: over ASCII A-Z ONLY. Python's ``str.lower()`` folds full Unicode
#: (U+212A KELVIN SIGN becomes "k", U+0130 becomes a two-codepoint
#: sequence), which conflates DISTINCT PHP identifiers: an
#: ``extends`` naming a Kelvin-spelled parent must never match an
#: in-tree ASCII decoy while PHP autoloads the Kelvin-named class out
#: of tree (the false-absence direction). Every name-identity
#: casefold in this module goes through :func:`_ascii_lower`.
_ASCII_LOWER = str.maketrans(
    string.ascii_uppercase, string.ascii_lowercase)


def _ascii_lower(text: str) -> str:
    """ASCII-only casefold — PHP name identity, never Unicode."""
    return text.translate(_ASCII_LOWER)


PRODUCER_MODULE = "core.analysis.gadget_oracle"
PRODUCER_VERSION = 1
ARTIFACT_NAME = "gadget-chains.json"

#: Honesty note carried on the artifact itself.
ARTIFACT_NOTE = (
    "Hint-tier static derivation from hostile content. A listed chain "
    "is a witness exhibit to verify against source, never a "
    "confirmation by itself; an empty chain list is evidence of "
    "absence only modulo the census (parse failures, unscanned "
    "PHP-like files, size/count caps) and the stated flow depth. No "
    "verdict path may suppress on this artifact until absence "
    "precision is corpus-earned (named follow-up)."
)

# CWE family the channel joins via the audit fallback chain.
GADGET_ORACLE_CWES = frozenset({"CWE-502"})

# Rule-id stamps (all detection-grade — see is_detection_rule_id).
RULE_CHAIN = "gadget_oracle:chain"
RULE_CHAIN_CONDITIONAL = "gadget_oracle:chain-conditional"
RULE_ABSENCE = "gadget_oracle:no-gadgets"

# Enumerated reasons (each a distinct tested string).
REASON_GRAMMAR_UNAVAILABLE = "grammar-unavailable"
REASON_LANGUAGE_UNSUPPORTED = "language-unsupported"
REASON_TARGET_UNUSABLE = "target-unusable"
REASON_NO_GADGETS_COMPLETE = "no-gadgets-complete-census"
REASON_NO_GADGETS_DEGRADED = "no-gadgets-degraded-census"

#: suppressions.jsonl verdict string for the record-only absence rows.
ABSENCE_RECORD_VERDICT = "gadget_oracle_no_gadgets"

#: The named follow-up gate: absence stays hint-tier until a measured
#: corpus earns suppression authority (binary-oracle precedent). This
#: constant exists so the promotion, when it lands, is a one-line flip
#: with the corpus citation beside it — and so tests can pin that the
#: current increment never suppresses.
ABSENCE_EARNS_SUPPRESSION = False

# ── absence tiers ────────────────────────────────────────────────────
#
# Two absence claims with DIFFERENT epistemic strength; only the first
# is a candidate for corpus-earned suppression, and even it stays
# hint-tier while ABSENCE_EARNS_SUPPRESSION is False.

#: Census complete AND zero POP-relevant trigger surface anywhere in
#: the tree (no surface magic method, no declared
#: ``serialize``/``unserialize`` pair, no ``Serializable``
#: implementation, no eval-class dynamic-definition site) AND no
#: autoload-family registration (``spl_autoload_register``, legacy
#: ``__autoload``, ini ``unserialize_callback_func`` — plus the
#: fail-closed facts for what static naming cannot see: a dynamic
#: ``ini_set`` key, a dynamic callee, a non-literal
#: ``call_user_func`` target, a census family name spelled as an
#: intact string literal anywhere in the tree or as a fully-literal
#: concat chain folding to the name — flexible indented-closer
#: heredoc/nowdoc bodies dedented per PHP 7.3+ semantics first, a
#: body defeating that recovery counting fail-closed). This is a
#: depth-INDEPENDENT structural claim: a POP chain of any depth needs
#: an in-tree trigger, and none exists. Registration blocks the tier
#: because ``unserialize()`` hands the attacker-chosen class-name
#: string to the autoload chain BEFORE any object method is
#: consulted — an in-tree loader mapping names to include/require
#: paths executes in-tree top-level code with zero declared methods.
TIER_NO_GADGET_SURFACE = "no_gadget_surface"

#: Census complete, no chains found, but trigger surface EXISTS or
#: an autoload mechanism is registered. Depth-LIMITED and NEVER
#: promotable — the flow model under-approximates (real chains are
#: multi-hop and cross-class), and a registered loader's mappings
#: are unmodelled — so this tier is documentation, not authority.
TIER_NO_CHAINS_FOUND = "no_chains_found"

#: Degraded census, chains present, or malformed report: no absence
#: tier can be claimed (fail-closed).
TIER_NONE = "none"

#: POP trigger-SURFACE method names (casefolded — PHP resolves method
#: names case-insensitively). This is the suppression-blocking census
#: set: deliberately BROADER than the chain-finding tables
#: (``TRIGGER_METHODS`` / ``CONDITIONAL_TRIGGERS``), because a method
#: the flow model does not trace can still anchor a real chain.
#: ``__construct`` is deliberately absent: constructors never run on
#: unserialize, so they are not POP surface.
POP_SURFACE_METHODS = frozenset({
    "__destruct", "__wakeup", "__unserialize", "__tostring",
    "__call", "__callstatic", "__get", "__set", "__isset",
    "__unset", "__invoke", "__clone", "__debuginfo", "__set_state",
})

#: Surface-census names: the POP set plus Serializable's
#: ``serialize``/``unserialize`` pair. BOTH census sites count against
#: this set — direct ``method_declaration``s and trait-use alias
#: adaptations (``use T { cleanup as __destruct; }`` mints a live
#: method no declaration ever spells). The pair rides along at both
#: sites because ``unserialize()`` of a ``C:``-format payload calls
#: ``->unserialize($payload)`` on any class that is ``instanceof
#: Serializable`` at RUNTIME, and the binding that makes it so does
#: not have to spell ``Serializable`` in this class's own implements
#: clause: it can ride an import alias (``use Serializable as S``),
#: an in-tree interface that extends Serializable, or an interface
#: shipped outside the tree entirely — the ``serializable_impls``
#: terminal-name census cannot see any of those. Counting the
#: declared pair is the safe over-block for a suppression blocker;
#: resolving interface chains to prove a class is NOT Serializable
#: is exactly the fail-open direction this census refuses.
_SURFACE_CENSUS_NAMES = POP_SURFACE_METHODS | frozenset({
    "serialize", "unserialize",
})

#: PHP-internal base classes (casefolded — class names resolve
#: case-insensitively) whose method bodies are engine C code:
#: extending one cannot pull in-tree PHP trigger code into the child,
#: so an ``extends`` naming one of these never breaks census
#: completeness. Language facts (php.net class reference): the core
#: throwable hierarchy, the SPL exception family, and stdClass.
#: Anything NOT listed — including other internal classes such as
#: DateTime or ArrayObject — fails closed to ``unresolved-parents``:
#: over-blocking an exotic internal parent merely withholds the tier,
#: while under-blocking an out-of-tree USER parent falsely earns it
#: (the parent's inherited ``__destruct`` is invisible to the census).
_INTERNAL_BASE_CLASSES = frozenset({
    # core
    "stdclass",
    # throwable hierarchy (classes only — Throwable is an interface)
    "exception", "errorexception", "error", "argumentcounterror",
    "arithmeticerror", "assertionerror", "divisionbyzeroerror",
    "typeerror", "valueerror", "unhandledmatcherror",
    # SPL exception family
    "badfunctioncallexception", "badmethodcallexception",
    "domainexception", "invalidargumentexception", "lengthexception",
    "logicexception", "outofboundsexception", "outofrangeexception",
    "overflowexception", "rangeexception", "runtimeexception",
    "underflowexception", "unexpectedvalueexception",
})

#: String-literal node types (a string-form ``assert`` is
#: eval-equivalent on PHP < 8, so it counts as a dynamic-definition
#: site).
_STRING_NODE_TYPES = frozenset({
    "string", "encapsed_string", "heredoc", "nowdoc",
})

# Magic methods triggered by the unserialize lifecycle itself.
TRIGGER_METHODS = ("__destruct", "__wakeup", "__unserialize")

# Sink-relevant magic methods needing an extra usage context; the
# value is the honest trigger_requires prose carried on their chains.
CONDITIONAL_TRIGGERS: dict[str, str] = {
    "__toString": (
        "the injected object must reach a string-conversion context"
    ),
    "__call": (
        "an undefined method must be invoked on the injected object"
    ),
    "__get": (
        "an undefined/inaccessible property must be read from the "
        "injected object"
    ),
    "__set": (
        "an undefined/inaccessible property must be written on the "
        "injected object"
    ),
}

#: Lowercase → canonical spelling for the conditional-trigger table.
#: PHP method names are case-insensitive, so matching goes through
#: the lowercased form; the canonical key survives for display.
_CONDITIONAL_TRIGGERS_LOWER: dict[str, str] = {
    _ascii_lower(k): k for k in CONDITIONAL_TRIGGERS
}

# ── sink vocabulary (SEED-tier: canonical exemplars only — the
#    vocab-list policy; per-target vocabulary is the study loop's job,
#    never this tuple's) ──────────────────────────────────────────────

_FILE_SINKS = frozenset({
    "unlink", "file_put_contents", "file_get_contents", "fopen",
    "fwrite", "rename", "copy", "rmdir", "chmod", "readfile", "touch",
})
_EXEC_SINKS = frozenset({
    "exec", "system", "passthru", "shell_exec", "popen", "proc_open",
    "pcntl_exec", "eval", "assert", "create_function",
})
# Callable-injection sinks: the FIRST argument is the callable.
_CALLABLE_SINKS = frozenset({"call_user_func", "call_user_func_array"})
_SQL_FUNCTIONS = frozenset({
    "mysqli_query", "mysql_query", "pg_query", "sqlite_query",
})
# Receiver-method SQL sinks ($db->query($tainted)) — receiver type is
# unknown statically; hits are detection-grade witnesses by design.
_SQL_METHODS = frozenset({"query", "exec", "multi_query", "prepare"})

# String-shape propagators: a call to one of these with a tainted
# argument stays tainted. Seed set — direct-flow modelling only.
_PROPAGATORS = frozenset({
    "sprintf", "implode", "join", "str_replace", "trim", "strval",
    "strtolower", "strtoupper", "base64_decode", "urldecode",
    "rawurldecode", "stripslashes", "substr", "str_repeat",
})

_SINK_CATEGORY_BY_NAME: dict[str, str] = {}
for _n in _FILE_SINKS:
    _SINK_CATEGORY_BY_NAME[_n] = "file"
for _n in _EXEC_SINKS:
    _SINK_CATEGORY_BY_NAME[_n] = "exec"
for _n in _SQL_FUNCTIONS:
    _SINK_CATEGORY_BY_NAME[_n] = "sql"

# ── bounds (the tree is hostile content; every list it can grow is
#    capped, with the caps recorded in the census) ────────────────────

MAX_FILES = 50_000
MAX_FILE_BYTES = 8 * 1024 * 1024  # mirrors inventory MAX_FILE_BYTES
# Chain accumulation stops at MAX_CHAINS + 1 DURING the scan (the +1
# proves truncation), never after it: one hostile file can otherwise
# mint millions of one-hop chain dicts before a final slice would
# discard them (memory, not correctness). Lower loses real chains on
# gadget-dense trees; higher only raises the hostile-tree memory
# ceiling — the census carries chains_truncated either way.
MAX_CHAINS = 200
MAX_SINKS_PER_METHOD = 16
# Same-class call records per method, mirroring MAX_SINKS_PER_METHOD:
# each recorded call can fan out into callee-sink chains, so an
# unbounded list is a memory amplifier on hostile input. Lower drops
# real one-hop chains in call-heavy magic methods (absence stays
# census-qualified either way); higher re-opens the amplifier.
MAX_CALLS_PER_METHOD = 16
MAX_SITES_LISTED = 500
MAX_CENSUS_PATHS_LISTED = 50
MAX_EXCERPT_CHARS = 200
MAX_PROPERTY_PATH_CHARS = 120
MAX_REPORT_BYTES = 32 * 1024 * 1024

#: PHP extensions parsed unconditionally. Other files are probed for
#: an opening ``<?php`` tag and, when it is present, counted as
#: ``php_like_unscanned`` — completeness-breaking, never silently
#: ignored (a gadget class in an ``.inc`` module must not vanish from
#: the absence claim).
PHP_EXTENSIONS = (".php", ".phtml", ".php3", ".php4", ".php5")

#: VCS/metadata dirs never walked. NOTE: unlike the include-graph
#: walker, ``vendor/`` IS scanned — third-party libraries are exactly
#: where classic gadget chains live. Skipping is never SILENT for the
#: absence claim: each skipped dir is cheaply probed
#: (:func:`_skipped_dir_has_php`) and one that contains PHP-like
#: content breaks census completeness (``walk-skipped-dirs``) — a
#: gadget class parked in ``node_modules/`` or ``.git/hooks/`` must
#: not vanish from a tree-wide zero-surface claim.
_WALK_SKIP_DIRS = frozenset({".git", ".svn", ".hg", "__pycache__",
                             "node_modules"})

# Extensions the skipped-dir probe treats as PHP-like BY NAME (the
# main walk's PHP_EXTENSIONS plus the classic include-module ones a
# vendored payload actually ships under). Name checks are readdir-
# cheap, so this list is checked on EVERY entry.
_SKIP_PROBE_NAME_EXTENSIONS = frozenset(PHP_EXTENSIONS) | frozenset({
    ".inc", ".phar", ".module",
})

# Skipped-dir probe bounds. Name scanning is a readdir walk (cheap);
# the entry budget matches MAX_FILES so a skipped dir is never probed
# harder than the main walk would have walked it — exhaustion answers
# True (cannot rule PHP out: fail closed, tier withheld). Content
# probing opens only a bounded number of files, in walk order; binary
# heads are recognised by a NUL byte and never counted (PHP source
# cannot contain NUL — without this, zlib/loose-object bytes in
# ``.git`` would randomly match ``<?``). DECLARED residual: PHP
# content hidden under a non-PHP extension deeper than the content
# budget reaches is invisible to this probe — a bound stated here
# rather than silently absorbed, mirroring the ``php_probe_bytes``
# window. Lower bounds hide real PHP from the probe; higher ones only
# add I/O on hostile trees.
_SKIP_PROBE_MAX_ENTRIES = MAX_FILES
_SKIP_PROBE_MAX_CONTENT_FILES = 64
_SKIP_PROBE_BYTES = 4096


def _skipped_dir_has_php(path: str) -> bool:
    """Whether a walk-skipped dir contains PHP-like content: any
    entry with a PHP-like extension, or (within the content budget)
    any text file whose head carries an open tag. True on entry-
    budget exhaustion (fail closed — an unprobeable dir cannot
    support a completeness claim)."""
    entries = 0
    content_probes = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for fn in sorted(filenames):
            entries += 1
            if entries > _SKIP_PROBE_MAX_ENTRIES:
                return True
            suffix = _ascii_lower(os.path.splitext(fn)[1])
            if suffix in _SKIP_PROBE_NAME_EXTENSIONS:
                return True
            full = os.path.join(dirpath, fn)
            # Symlinks and non-files are never opened — they must not
            # consume the content budget (a symlink farm would shadow
            # a real PHP-like file sorted after it).
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            if content_probes >= _SKIP_PROBE_MAX_CONTENT_FILES:
                continue
            content_probes += 1
            try:
                with open(full, "rb") as fh:
                    head = fh.read(_SKIP_PROBE_BYTES)
            except OSError:
                continue
            if b"\0" in head:
                continue  # binary — cannot be PHP source
            if _PHP_OPEN_TAG_RE.search(head):
                return True
    return False

# PHP-tag probe window for non-PHP extensions. 64 KiB clears any
# plausible legitimate HTML/text preamble before an embedded open tag;
# a larger window mostly re-reads binary blobs on every walked file,
# a smaller one lets a long preamble hide a PHP-like file from the
# census. The bound is DECLARED in the census (php_probe_bytes) and in
# the qualifier prose — a file whose first open tag sits beyond it is
# invisible to the probe, so the bound must ride with the absence
# claim rather than be silently absorbed.
_PHP_PROBE_BYTES = 65536
#: Any ``<?`` opener counts as PHP-like EXCEPT a real XML declaration:
#: ``<?xml`` followed by whitespace and ``version``. Nothing looser is
#: safe — ``<?xml;`` is LIVE short-tag PHP (the parser reads a bare
#: ``xml`` constant; any class declared after it is compile-hoisted
#: even on 8.x where the constant then errors), so a word-boundary
#: exclusion (``<?xml\b``) lets a gadget class ride in under a
#: ``.xml``-looking opener. Processing instructions like
#: ``<?xml-stylesheet`` are over-counted by design: ``<?xml-…`` shapes
#: are live PHP pre-8 (constant subtraction warns, it does not
#: parse-error), and over-counting only degrades the census (the
#: fail-closed direction — the tier is withheld, never falsely
#: earned). PHP's open tag is case-insensitive (``<?PHP`` works) and
#: the short form ``<?`` is live wherever ``short_open_tag`` is on —
#: which is the COMPILED default in stock builds (the official docker
#: images ship no overriding php.ini) — so the probe must treat both
#: as PHP-like. The ``xml`` exclusion is deliberately lowercase-only:
#: a compliant XML declaration must be lowercase, and over-matching a
#: weird-cased ``<?XML`` merely degrades the census. Narrower
#: alternatives (``<?php\b|<\?=``) were measured to hide ``<?PHP`` and
#: short-tag files from the census, falsely earning the promotable
#: tier.
_PHP_OPEN_TAG_RE = re.compile(rb"<\?(?!xml\s+version)")

# Hypothesis shapes asserting a deserialization gadget claim (either
# direction — "a gadget chain exists" and "no gadgets in tree" both
# route here). Bounded gaps (hostile-text discipline).
_GADGET_HYPOTHESIS_RE = re.compile(
    r"(?:\bgadgets?\b|pop\s+chain|object\s+injection"
    r"|magic[\s_-]+method|__destruct|__wakeup|__tostring"
    r"|unseriali[sz]e|deseriali[sz]at)",
    re.IGNORECASE,
)


# ── grammar loading (clean degradation) ──────────────────────────────


_PARSER_LOCK = threading.Lock()
_PARSER_CACHE: list[Any] = []  # [] = unprobed, [None] = absent, [p]


def _php_parser() -> Any:
    """Cached tree-sitter-php parser, or ``None`` when the grammar or
    the tree_sitter runtime is not installed (capability-absent —
    recorded by every caller, never a silent pass).

    Mirrors :func:`core.inventory.call_graph.extract_call_graph_php`'s
    language resolution (``language_php`` attr vs ``language()``) and
    wraps the parser in the shared parse budget.
    """
    with _PARSER_LOCK:
        if _PARSER_CACHE:
            return _PARSER_CACHE[0]
        parser = None
        try:
            from core.inventory._ts_cache import bounded, import_grammar
            ts_php = import_grammar("tree_sitter_php")
            if ts_php is not None:
                from tree_sitter import Language, Parser
                lang_fn = (getattr(ts_php, "language_php", None)
                           or ts_php.language())
                if callable(lang_fn):
                    lang_fn = lang_fn()
                parser = bounded(Parser(Language(lang_fn)),
                                 label="gadget_oracle")
        except Exception as e:  # noqa: BLE001 — degradation, not crash
            logger.debug("gadget_oracle: php parser unavailable (%s)", e)
            parser = None
        _PARSER_CACHE.append(parser)
        return parser


def reset_parser_cache() -> None:
    """Test seam: forget the probed parser (grammar monkeypatching)."""
    with _PARSER_LOCK:
        _PARSER_CACHE.clear()


def php_grammar_available() -> bool:
    """Whether the tree-sitter-php substrate is usable right now."""
    return _php_parser() is not None


# ── per-file AST analysis ────────────────────────────────────────────


def _node_text(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace")


def _node_line(node: Any) -> int:
    return node.start_point[0] + 1


def _child_names(node: Any, type_name: str) -> list[Any]:
    return [c for c in node.named_children if c.type == type_name]


def _is_this(node: Any, src: bytes) -> bool:
    return (node.type == "variable_name"
            and _node_text(node, src) == "$this")


def _callee_name(fn: Any, src: bytes) -> str | None:
    """Casefolded global-callee name for a call's function node, or
    None when the callee is not a statically-named global function.

    PHP resolves function and method names case-insensitively
    (``SYSTEM(...)`` calls ``system``), so EVERY name comparison in
    this module goes through a lowercased form — byte-exact matching
    is a gadget-evasion hole, not a precision feature. A
    ``qualified_name`` whose only qualifier is a leading ``\\`` is the
    same global function written explicitly (``\\system``); a
    namespace-qualified name (``App\\system``) is a DIFFERENT symbol
    and must never match the global sink/propagator vocabulary.
    """
    if fn is None:
        return None
    if fn.type == "name":
        return _ascii_lower(_node_text(fn, src))
    if fn.type == "qualified_name":
        if any(c.type == "namespace_name" for c in fn.named_children):
            return None
        name = _ascii_lower(_node_text(fn, src).lstrip("\\"))
        return name if name and "\\" not in name else None
    return None


def _property_path(node: Any, src: bytes) -> str | None:
    """``$this->a`` → ``"a"``; ``$this->a->b`` → ``"a->b"``; None when
    the member access is not rooted at ``$this``. Depth-bounded by the
    render cap (a hostile 10k-hop chain renders truncated)."""
    parts: list[str] = []
    cur = node
    while cur is not None and cur.type == "member_access_expression":
        name = cur.child_by_field_name("name")
        parts.append(_node_text(name, src) if name is not None else "?")
        cur = cur.child_by_field_name("object")
    if cur is None or not _is_this(cur, src):
        return None
    path = "->".join(reversed(parts))
    return path[:MAX_PROPERTY_PATH_CHARS]


@dataclass
class _SinkHit:
    category: str
    callee: str
    line: int
    via: str          # property path (or param:<name> marker)
    excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "callee": self.callee,
            "line": self.line,
            "via": self.via,
            "excerpt": self.excerpt,
        }


@dataclass
class _SameClassCall:
    method: str
    line: int
    tainted_args: list[int] = field(default_factory=list)
    via: str = ""     # property path feeding the first tainted arg


@dataclass
class _MethodFlow:
    name: str
    line: int
    params: list[str] = field(default_factory=list)
    property_sinks: list[_SinkHit] = field(default_factory=list)
    param_sinks: list[_SinkHit] = field(default_factory=list)
    calls: list[_SameClassCall] = field(default_factory=list)


@dataclass
class _ClassFacts:
    name: str
    line: int
    methods: dict[str, _MethodFlow] = field(default_factory=dict)


@dataclass
class _FileFacts:
    classes: list[_ClassFacts] = field(default_factory=list)
    unserialize_sites: list[dict[str, Any]] = field(default_factory=list)
    #: Autoload-family registrations: ``(line, mechanism)`` pairs.
    #: Mechanisms: ``spl_autoload_register``, ``__autoload``,
    #: ``unserialize_callback_func`` (literal ini key),
    #: ``ini-dynamic-key`` (a dynamic ini_set/ini_alter key that
    #: cannot be proven NOT to be unserialize_callback_func —
    #: fail-closed, counted as registration), and ``dynamic-callee``
    #: (a call whose callee is not a statically named function —
    #: ``$f(...)``, ``('name')(...)``, a non-literal
    #: ``call_user_func``/``call_user_func_array`` target — which can
    #: invoke ANY function at runtime, the autoload family included;
    #: fail-closed, counted as registration), and
    #: ``family-literal-mention`` (a census family name spelled as an
    #: intact string literal ANYWHERE in the tree — call arguments,
    #: assignments, returns, default parameter values, initializers,
    #: attribute arguments — or as a fully-literal concat chain that
    #: folds to the name; PHP's callable-forwarding builtins
    #: (``array_map``, ``register_shutdown_function``, ...) and user
    #: forwarders can invoke any value that reaches them, so position
    #: never proves safety; fail-closed, counted as registration).
    autoload_sites: list[tuple[int, str]] = field(default_factory=list)
    parse_errors: bool = False
    #: ``use SomeTrait;`` clauses that do not resolve — by casefolded
    #: FQN under the file's namespace/import context — to a trait
    #: declared in this file. A trait can carry the magic method AND
    #: the sink, so every unresolved use breaks census completeness —
    #: the absence claim must never stay "complete" while
    #: trait-provided gadget surface went unmodelled.
    unresolved_trait_uses: int = 0
    #: POP trigger-surface census for this file (suppression-blocking
    #: direction — over-count is the safe error). Method counts are
    #: keyed by the casefolded name, cover the full
    #: :data:`_SURFACE_CENSUS_NAMES` set (the POP magic methods plus
    #: Serializable's declared pair), and include EVERY declaration
    #: site (class, trait, anonymous class, interface, enum,
    #: abstract): a bodiless declaration over-blocks, which is the
    #: chosen direction.
    pop_surface: dict[str, int] = field(default_factory=dict)
    #: Classes/enums/anonymous classes whose implements-clause carries
    #: a terminal identifier equal to ``serializable`` casefolded —
    #: qualified or not. ``App\\Serializable`` is a different interface
    #: under real name resolution, but the census counts it anyway
    #: (documented over-block: PHP name-resolution subtleties make the
    #: conservative match the right one for a suppression blocker).
    serializable_impls: int = 0
    #: ``eval(...)`` calls plus string-form ``assert(...)`` calls. An
    #: eval'd string can define a class the static census never sees,
    #: so any such site blocks the zero-surface claim.
    dynamic_definition_sites: int = 0
    #: Subset of the POP-surface method count declared inside
    #: anonymous-class bodies (counted in ``pop_surface`` too; kept
    #: separately so the tier predicate can fail closed on either).
    anonymous_class_methods: int = 0
    #: ``extends`` targets from class (and anonymous-class) base
    #: clauses as ``(kind, casefolded FQN)`` pairs from
    #: :func:`_classify_class_ref` — the FQN is resolved under the
    #: file's namespace/import context (a bare name inside a
    #: namespace means <namespace>\\<name>; an import alias redirects
    #: it). Resolution is TREE-wide: :func:`scan_tree` matches the
    #: FQN against every declared class, then — for ``_REF_GLOBAL``
    #: references ONLY — :data:`_INTERNAL_BASE_CLASSES`; whatever is
    #: left is an out-of-tree parent whose inherited trigger surface
    #: the census cannot see — completeness-breaking. Interface
    #: ``extends`` is exempt: interface methods carry no bodies in
    #: PHP (any version), so no trigger code can ride in. The same
    #: reasoning exempts ``implements`` — EXCEPT ``Serializable``,
    #: whose contract makes the implementing class's OWN
    #: ``unserialize()`` a trigger; that is censused separately via
    #: ``class_interface_clause``.
    extends_targets: list[tuple[str, str]] = field(default_factory=list)
    #: Casefolded FQNs of classes DECLARED in this file (namespace at
    #: the declaration site prepended; traits are excluded — a trait
    #: cannot be an ``extends`` target).
    declared_class_names: set[str] = field(default_factory=set)


_REQUEST_SUPERGLOBALS = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
                         "php://input", "$_SERVER")

_INCLUDE_NODE_TYPES = frozenset({
    "include_expression", "include_once_expression",
    "require_expression", "require_once_expression",
})


class _MethodWalker:
    """Single forward pass over one method body.

    Direct flows only: property reads root the taint set; straight-
    line local assignments, ``.=``, concatenation, interpolation,
    foreach-over-property and the propagator seed extend it; anything
    else (unknown calls, array gymnastics, control-flow joins) does
    NOT — the under-approximation the module docstring states.
    """

    def __init__(self, src: bytes, taint_params: list[str]):
        self.src = src
        # var name -> property-path (or param marker) it carries
        self.tainted: dict[str, str] = {
            p: f"param:{p}" for p in taint_params
        }
        self.property_sinks: list[_SinkHit] = []
        self.param_sinks: list[_SinkHit] = []
        self.calls: list[_SameClassCall] = []

    # -- taint predicate ---------------------------------------------

    def _taint_of(self, node: Any, depth: int = 0) -> str | None:
        """Property path (or param marker) the expression carries, or
        None when untainted under the direct-flow model."""
        if node is None or depth > 24:
            return None
        t = node.type
        if t == "member_access_expression":
            return _property_path(node, self.src)
        if t == "variable_name":
            return self.tainted.get(_node_text(node, self.src))
        if (t in ("parenthesized_expression", "cast_expression",
                  "unary_op_expression", "clone_expression",
                  "argument")
                or t in _INCLUDE_NODE_TYPES):
            for c in node.named_children:
                got = self._taint_of(c, depth + 1)
                if got:
                    return got
            return None
        if t in ("binary_expression", "encapsed_string",
                 "shell_command_expression", "augmented_assignment_expression",
                 "sequence_expression", "conditional_expression",
                 "array_creation_expression", "array_element_initializer"):
            for c in node.named_children:
                got = self._taint_of(c, depth + 1)
                if got:
                    return got
            return None
        if t == "function_call_expression":
            fn = node.child_by_field_name("function")
            if _callee_name(fn, self.src) in _PROPAGATORS:
                args = node.child_by_field_name("arguments")
                if args is not None:
                    return self._taint_of(args, depth + 1)
            return None
        if t == "arguments":
            for c in node.named_children:
                got = self._taint_of(c, depth + 1)
                if got:
                    return got
            return None
        return None

    # -- sink recording ----------------------------------------------

    def _record_sink(self, category: str, callee: str, node: Any,
                     via: str) -> None:
        hit = _SinkHit(
            category=category, callee=callee, line=_node_line(node),
            via=via,
            excerpt=_node_text(node, self.src)[:MAX_EXCERPT_CHARS],
        )
        bucket = (self.param_sinks if via.startswith("param:")
                  else self.property_sinks)
        if len(bucket) < MAX_SINKS_PER_METHOD:
            bucket.append(hit)

    def _tainted_args(self, args_node: Any) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        if args_node is None:
            return out
        idx = 0
        for c in args_node.named_children:
            if c.type != "argument":
                continue
            via = self._taint_of(c)
            if via:
                out.append((idx, via))
            idx += 1
        return out

    # -- statement walk ----------------------------------------------

    def walk(self, node: Any) -> None:
        t = node.type
        if t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "variable_name":
                via = self._taint_of(right)
                name = _node_text(left, self.src)
                if via:
                    self.tainted[name] = via
                else:
                    self.tainted.pop(name, None)  # strong update
            if right is not None:
                self.walk(right)
            return
        if t == "augmented_assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "variable_name":
                via = self._taint_of(right)
                if via:
                    self.tainted[_node_text(left, self.src)] = via
            if right is not None:
                self.walk(right)
            return
        if t == "foreach_statement":
            # foreach ($this->items as $k => $v): value var tainted.
            coll_via: str | None = None
            value_var: Any = None
            for c in node.named_children:
                if coll_via is None:
                    coll_via = self._taint_of(c)
                if c.type == "pair":
                    kids = _child_names(c, "variable_name")
                    value_var = kids[-1] if kids else None
                elif c.type == "variable_name":
                    value_var = c
                if c.type in ("compound_statement", "colon_block"):
                    break
            if coll_via and value_var is not None:
                self.tainted[_node_text(value_var, self.src)] = coll_via
            for c in node.named_children:
                if c.type in ("compound_statement", "colon_block"):
                    self.walk(c)
            return
        if t == "function_call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            name = _callee_name(fn, self.src)
            if name is not None:
                tainted = self._tainted_args(args)
                if name in _CALLABLE_SINKS:
                    first = [v for i, v in tainted if i == 0]
                    if first:
                        self._record_sink("exec", name, node, first[0])
                elif name in _SINK_CATEGORY_BY_NAME and tainted:
                    self._record_sink(
                        _SINK_CATEGORY_BY_NAME[name], name, node,
                        tainted[0][1],
                    )
        elif t in _INCLUDE_NODE_TYPES:
            via = self._taint_of(node)
            if via:
                self._record_sink(
                    "include", t.replace("_expression", ""), node, via)
            return
        elif t == "echo_statement":
            for c in node.named_children:
                via = self._taint_of(c)
                if via:
                    self._record_sink("echo", "echo", node, via)
                    break
        elif t == "print_intrinsic":
            via = self._taint_of(node.named_children[0]
                                 if node.named_children else None)
            if via:
                self._record_sink("echo", "print", node, via)
        elif t == "shell_command_expression":
            via = self._taint_of(node)
            if via:
                self._record_sink("exec", "shell_command", node, via)
        elif t == "member_call_expression":
            obj = node.child_by_field_name("object")
            name_node = node.child_by_field_name("name")
            args = node.child_by_field_name("arguments")
            mname = (_node_text(name_node, self.src)
                     if name_node is not None else "")
            tainted = self._tainted_args(args)
            if obj is not None and _is_this(obj, self.src):
                # $this->helper(...) — same-class one-hop candidate.
                # PHP method names are case-insensitive; store the
                # canonical lowercased form so chain assembly matches
                # the (also lowercased) method table.
                if len(self.calls) < MAX_CALLS_PER_METHOD:
                    self.calls.append(_SameClassCall(
                        method=_ascii_lower(mname),
                        line=_node_line(node),
                        tainted_args=[i for i, _ in tainted],
                        via=tainted[0][1] if tainted else "",
                    ))
            elif _ascii_lower(mname) in _SQL_METHODS and tainted:
                self._record_sink("sql", "->" + mname, node,
                                  tainted[0][1])
        elif t == "scoped_call_expression":
            scope = node.named_children[0] if node.named_children else None
            name_node = node.child_by_field_name("name")
            args = node.child_by_field_name("arguments")
            if (scope is not None and scope.type == "relative_scope"
                    and name_node is not None
                    and len(self.calls) < MAX_CALLS_PER_METHOD):
                tainted = self._tainted_args(args)
                self.calls.append(_SameClassCall(
                    method=_ascii_lower(
                        _node_text(name_node, self.src)),
                    line=_node_line(node),
                    tainted_args=[i for i, _ in tainted],
                    via=tainted[0][1] if tainted else "",
                ))
        # Nested definitions get their own walk; do not descend.
        if t in ("function_definition", "method_declaration",
                 "anonymous_function_creation_expression",
                 "arrow_function", "class_declaration"):
            return
        for c in node.named_children:
            self.walk(c)


def _method_params(method_node: Any, src: bytes) -> list[str]:
    params = method_node.child_by_field_name("parameters")
    out: list[str] = []
    if params is None:
        return out
    for c in params.named_children:
        for v in _child_names(c, "variable_name"):
            out.append(_node_text(v, src))
    return out


def _analyze_method(method_node: Any, src: bytes) -> _MethodFlow:
    name_node = method_node.child_by_field_name("name")
    name = _node_text(name_node, src) if name_node is not None else "?"
    flow = _MethodFlow(name=name, line=_node_line(method_node),
                       params=_method_params(method_node, src))
    body = method_node.child_by_field_name("body")
    if body is None:
        return flow
    walker = _MethodWalker(src, taint_params=flow.params)
    walker.walk(body)
    flow.property_sinks = walker.property_sinks
    flow.param_sinks = walker.param_sinks
    flow.calls = walker.calls
    return flow


def _argument_expr(node: Any, index: int) -> Any:
    """The expression node of a call's ``index``-th ``argument``
    (0-based), or None. The callable-string dispatch reads shifted
    positions: ``call_user_func('ini_set', <key>, ...)`` carries the
    target's first argument at position 1."""
    args = node.child_by_field_name("arguments")
    if args is None:
        return None
    seen = 0
    for c in args.named_children:
        if c.type == "argument":
            if seen == index:
                return c.named_children[0] if c.named_children else None
            seen += 1
    return None


def _in_anonymous_class(node: Any) -> bool:
    """Whether a ``method_declaration`` sits in an anonymous-class
    body (``anonymous_class`` — with older grammars falling back to an
    ``object_creation_expression`` carrying the declaration list)."""
    parent = node.parent
    if parent is None:
        return False
    grand = parent.parent
    return grand is not None and grand.type in (
        "anonymous_class", "object_creation_expression")


def _terminal_identifier(node: Any, src: bytes) -> str:
    """Casefolded terminal identifier of a ``name`` /
    ``qualified_name`` node (``App\\Serializable`` → ``serializable``)."""
    text = _node_text(node, src)
    return _ascii_lower(text.rsplit("\\", 1)[-1])


_DQ_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f",
    "e": "\x1b", "\\": "\\", "$": "$", '"': '"',
}


def _decode_escape_sequence(text: str, double_quoted: bool) -> str:
    """PHP semantics for one ``escape_sequence`` token. Single-quoted
    strings decode only ``\\\\`` and ``\\'``; double-quoted strings
    additionally decode the simple escapes, ``\\xHH``, ``\\u{...}``
    and octal — an unrecognised escape stays LITERAL (PHP keeps the
    backslash), which matters here: ``"\\x65"`` is a real ``e`` a
    modifier check must see, while ``'\\x65'`` is four raw chars."""
    if len(text) < 2 or text[0] != "\\":
        return text
    body = text[1:]
    if not double_quoted:
        if body in ("\\", "'"):
            return body
        return text
    if body in _DQ_SIMPLE_ESCAPES:
        return _DQ_SIMPLE_ESCAPES[body]
    try:
        if body[0] == "x" and 1 <= len(body) - 1 <= 2:
            return chr(int(body[1:], 16))
        if (body[0] == "u" and len(body) >= 4
                and body[1] == "{" and body[-1] == "}"):
            return chr(int(body[2:-1], 16))
        if 1 <= len(body) <= 3 and all(c in "01234567" for c in body):
            return chr(int(body, 8) & 0xFF)
    except (ValueError, OverflowError):
        return text
    return text


def _string_literal_content(node: Any, src: bytes) -> str | None:
    """The literal content of a ``string``/``encapsed_string`` node
    with escape sequences DECODED per the node's quote semantics, or
    ``None`` when it is not a plain literal (interpolation — the
    value is unknowable statically, so callers must not pretend to
    know it)."""
    if node is None or node.type not in ("string", "encapsed_string"):
        return None
    double_quoted = node.type == "encapsed_string"
    parts: list[str] = []
    for c in node.named_children:
        if c.type == "string_content":
            parts.append(_node_text(c, src))
        elif c.type == "escape_sequence":
            parts.append(_decode_escape_sequence(
                _node_text(c, src), double_quoted))
        else:
            return None  # interpolation — not a literal
    return "".join(parts)


def _preg_pattern_has_e(pattern: str) -> bool:
    """Whether a PCRE pattern literal carries the ``/e`` (eval)
    modifier — PHP <= 5.4's ``preg_replace`` evaluates the
    replacement as code, a dynamic-definition site. Modifiers are the
    text after the closing delimiter; ``e`` is matched exactly (PCRE
    modifiers are case-sensitive)."""
    if len(pattern) < 2:
        return False
    delim = pattern[0]
    if delim.isalnum() or delim.isspace() or delim == "\\":
        return False  # not a valid PCRE delimiter
    closer = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(delim, delim)
    end = pattern.rfind(closer)
    if end <= 0:
        return False
    return "e" in pattern[end + 1:]


# Class-name references are classified by HOW PHP would resolve them —
# the census must never let a namespaced or import-aliased bare name
# take the internal-base allowlist path (PHP classes have NO global
# fallback inside a namespace, and a ``use`` import rebinds the bare
# name inside its own namespace block from the declaration onward).
_REF_GLOBAL = "global"        # eligible for _INTERNAL_BASE_CLASSES
_REF_QUALIFIED = "qualified"  # in-tree FQN match only, fail closed

#: ``use function`` / ``use const`` imports never apply to class-name
#: resolution — their keyword tokens mark clauses to skip.
_NONCLASS_IMPORT_KEYWORDS = frozenset({"function", "const"})


class _WindowIndex:
    """Stabbing index over half-open byte windows ``[start, end)``.

    Answers "which window covers this byte" under the module's
    resolution rule: among covering windows the GREATEST start wins
    (innermost / latest-declared); on equal starts the
    earliest-added window wins. Built once with a boundary sweep —
    the covering set only changes at window starts/ends, so the
    winning value is constant on each inter-boundary segment and one
    ``bisect`` answers a query. The per-query linear scan this
    replaces was quadratic over a whole file (every reference paid
    O(windows)); a machine-generated file with tens of thousands of
    imports and references turned that into minutes of wall time.

    The index is a snapshot of the windows it was built from —
    callers build it only after the window table is final.
    """

    __slots__ = ("_bounds", "_values")

    def __init__(self,
                 windows: Iterable[tuple[int, int, Any]]) -> None:
        # Enumeration order breaks start ties (earliest added wins,
        # mirroring the strict ``start > best_start`` of the linear
        # scan this replaces); empty windows can never cover a byte.
        table = [(start, end, order, value)
                 for order, (start, end, value) in enumerate(windows)
                 if start < end]
        bounds = sorted({b for s, e, _o, _v in table for b in (s, e)})
        table.sort(key=lambda w: (w[0], w[2]))
        # Sweep: push windows as their starts arrive, lazily pop
        # expired ones; the heap top is the winner for the segment
        # beginning at this boundary. Heap entries are ordered by
        # (-start, order) — order is unique, so values never compare.
        heap: list[tuple[int, int, int, Any]] = []
        values: list[Any] = []
        i = 0
        for b in bounds:
            while i < len(table) and table[i][0] <= b:
                start, end, order, value = table[i]
                heapq.heappush(heap, (-start, order, end, value))
                i += 1
            while heap and heap[0][2] <= b:
                heapq.heappop(heap)
            values.append(heap[0][3] if heap else None)
        self._bounds = bounds
        self._values = values

    def at(self, byte: int) -> Any:
        """Value of the winning window covering ``byte``, or ``None``
        when no window covers it."""
        i = bisect.bisect_right(self._bounds, byte) - 1
        return self._values[i] if i >= 0 else None


@dataclass
class _NameContext:
    """Per-file name-resolution context.

    ``regions`` maps byte ranges to the casefolded namespace governing
    them (braced bodies, plus unbraced spans running to the next
    namespace declaration or EOF; the global namespace is ``""``).
    ``class_aliases`` is the ``use`` import table as byte-windowed
    entries ``(start, end, alias, fqn)``: PHP scopes an import to its
    OWN namespace block, from the declaration point onward. Honouring
    an alias outside that window is NOT fail-closed — it can move a
    reference ONTO an in-tree decoy while PHP resolves the reference
    under its own namespace and autoloads an out-of-tree class the
    census never parsed (the false-absence direction).

    ``function_aliases`` is the ``use function`` twin, windowed by
    the same rules. It exists so a laundered registration —
    ``use function spl_autoload_register as sar; sar($cb);`` — is
    seen for what PHP resolves it to; consult it via
    :meth:`function_alias_for`.

    Lookups go through :class:`_WindowIndex` instances built lazily
    on first use and cached: the context is append-complete before
    the first lookup (:func:`_build_name_context` finishes the
    tables before returning); mutating the tables after a lookup is
    unsupported."""

    regions: list[tuple[int, int, str]] = field(default_factory=list)
    class_aliases: list[tuple[int, int, str, str]] = field(
        default_factory=list)
    function_aliases: list[tuple[int, int, str, str]] = field(
        default_factory=list)
    _region_index: _WindowIndex | None = field(
        default=None, init=False, repr=False, compare=False)
    _alias_indexes: dict[str, _WindowIndex] | None = field(
        default=None, init=False, repr=False, compare=False)
    _fn_alias_indexes: dict[str, _WindowIndex] | None = field(
        default=None, init=False, repr=False, compare=False)

    def _regions_index(self) -> _WindowIndex:
        idx = self._region_index
        if idx is None:
            idx = _WindowIndex(
                (start, end, (start, end, ns))
                for start, end, ns in self.regions)
            self._region_index = idx
        return idx

    def namespace_at(self, byte: int) -> str:
        """Casefolded namespace governing this byte offset (innermost
        region wins; ``""`` = global)."""
        got = self._regions_index().at(byte)
        return got[2] if got is not None else ""

    @staticmethod
    def _lookup(table: list[tuple[int, int, str, str]],
                cache: dict[str, _WindowIndex] | None,
                name: str, byte: int,
                ) -> tuple[str | None, dict[str, _WindowIndex]]:
        if cache is None:
            grouped: dict[str, list[tuple[int, int, str]]] = {}
            for start, end, alias, fqn in table:
                grouped.setdefault(alias, []).append(
                    (start, end, fqn))
            cache = {alias: _WindowIndex(ws)
                     for alias, ws in grouped.items()}
        idx = cache.get(name)
        return (idx.at(byte) if idx is not None else None), cache

    def alias_for(self, name: str, byte: int) -> str | None:
        """Casefolded FQN the class alias ``name`` binds to at this
        byte offset, or ``None`` when no import window covers it
        (innermost / latest-declared window wins)."""
        got, self._alias_indexes = self._lookup(
            self.class_aliases, self._alias_indexes, name, byte)
        return got

    def function_alias_for(self, name: str, byte: int) -> str | None:
        """Casefolded FQN the ``use function`` alias ``name`` binds
        to at this byte offset, or ``None`` when no import window
        covers it."""
        got, self._fn_alias_indexes = self._lookup(
            self.function_aliases, self._fn_alias_indexes, name, byte)
        return got


def _import_keyword(node: Any) -> str | None:
    """The ``function``/``const`` keyword token riding on a use
    declaration or clause, or ``None`` for a class import."""
    for c in node.children:
        if c.type in _NONCLASS_IMPORT_KEYWORDS:
            return c.type
    return None


def _use_clause_alias(clause: Any, src: bytes,
                      prefix: str) -> tuple[str, str] | None:
    """(alias, fqn) — both casefolded — for one ``namespace_use_clause``.
    The implicit alias is the last name segment; ``prefix`` carries a
    group-use base. Kind filtering (class vs function vs const) is
    the CALLER's job — the clause shape is identical."""
    named = [c for c in clause.named_children
             if c.type in ("name", "qualified_name")]
    if not named:
        return None
    fqn = _ascii_lower(_node_text(named[0], src).lstrip("\\"))
    if not fqn:
        return None
    if prefix:
        fqn = f"{prefix}\\{fqn}"
    if len(named) >= 2 and named[-1].type == "name":
        alias = _ascii_lower(_node_text(named[-1], src))
    else:
        alias = fqn.rsplit("\\", 1)[-1]
    if not alias:
        return None
    return alias, fqn


def _build_name_context(root: Any, src: bytes) -> _NameContext:
    """One pass collecting namespace regions and the byte-windowed
    class-import and function-import alias tables for a file."""
    ctx = _NameContext()
    unbraced: list[tuple[int, str]] = []  # (span start, namespace)
    ns_starts: list[int] = []
    #: (use-decl start, use-decl end, alias, fqn) — windowed once the
    #: regions are final (an unbraced region is only known after the
    #: whole walk).
    pending: list[tuple[int, int, str, str]] = []
    pending_fn: list[tuple[int, int, str, str]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "namespace_definition":
            ns_starts.append(node.start_byte)
            name_node = node.child_by_field_name("name")
            ns = (_ascii_lower(_node_text(name_node, src))
                  if name_node is not None else "")
            body = node.child_by_field_name("body")
            if body is not None:
                ctx.regions.append((body.start_byte, body.end_byte, ns))
            else:
                unbraced.append((node.end_byte, ns))
        elif node.type == "namespace_use_declaration":
            # The declaration-level ``function``/``const`` keyword
            # sets every clause's kind; in mixed groups the keyword
            # rides per-clause and overrides. Class imports feed
            # class resolution; function imports feed CALL-name
            # resolution (a ``use function`` alias can launder an
            # autoload-family registration); const imports feed
            # neither.
            #
            # Known fail-closed over-block: importing a global
            # built-in (``use Exception;``) windows the bare name
            # onto FQN "exception", which no in-tree declaration
            # matches — the parent counts unresolved and the tier is
            # withheld. Modelling the engine's internal-class table
            # for imports is not worth the false-resolution risk.
            decl_kind = _import_keyword(node)
            prefix = ""
            clauses: list[Any] = []
            for c in node.named_children:
                if c.type == "namespace_name":
                    prefix = _ascii_lower(
                        _node_text(c, src).lstrip("\\"))
                elif c.type == "namespace_use_group":
                    clauses.extend(_child_names(
                        c, "namespace_use_clause"))
                elif c.type == "namespace_use_clause":
                    clauses.append(c)
            for clause in clauses:
                kind = _import_keyword(clause) or decl_kind
                got = _use_clause_alias(clause, src, prefix)
                if got is None:
                    continue
                row = (node.start_byte, node.end_byte, got[0], got[1])
                if kind is None:
                    pending.append(row)
                elif kind == "function":
                    pending_fn.append(row)
        stack.extend(node.named_children)
    ns_starts.sort()
    for start, ns in unbraced:
        # An unbraced span runs to the next namespace declaration
        # (the first start strictly beyond it), else EOF.
        nxt = bisect.bisect_right(ns_starts, start)
        end = ns_starts[nxt] if nxt < len(ns_starts) else len(src)
        ctx.regions.append((start, end, ns))
    # The regions table is final here; one index answers every
    # pending import's innermost-region lookup (the per-import
    # linear scan this replaces was quadratic against
    # machine-generated import walls). Built locally: the context's
    # own cached indexes are only minted after both tables are final.
    region_probe = _WindowIndex(
        (start, end, end) for start, end, _ns in ctx.regions)
    for table, rows in ((ctx.class_aliases, pending),
                        (ctx.function_aliases, pending_fn)):
        for decl_start, decl_end, alias, fqn in rows:
            # PHP applies an import from its declaration point
            # onward, inside its own namespace block only: the window
            # runs from the ``use`` declaration's end to the end of
            # the innermost region containing it. A ``use`` outside
            # every region (a file whose imports precede any
            # namespace declaration) binds to the next namespace
            # start, else EOF.
            #
            # A duplicate alias (``use X\One as P; use Y\Two as P;``
            # in one block, or the group-use twin) yields overlapping
            # same-name windows; lookups resolve latest-declared-
            # wins, same-start ties to the first-listed clause. PHP
            # itself fatals at compile time on that shape — the file
            # can never execute — so the census still counting its
            # surface is a harmless over-claim in the fail-closed
            # direction.
            window_end = region_probe.at(decl_start)
            if window_end is None:
                nxt = bisect.bisect_right(ns_starts, decl_start)
                window_end = (ns_starts[nxt] if nxt < len(ns_starts)
                              else len(src))
            table.append((decl_end, window_end, alias, fqn))
    return ctx


def _classify_class_ref(node: Any, src: bytes,
                        ctx: _NameContext) -> tuple[str, str] | None:
    """Resolve one class-name reference node to
    ``(_REF_GLOBAL | _REF_QUALIFIED, casefolded FQN)`` under the
    file's namespace/import context, or ``None`` for an empty name.

    Only global-context bare names (no import alias, global
    namespace) and single-segment leading-``\\`` references classify
    as ``_REF_GLOBAL`` — everything else must match an in-tree
    declaration by FQN or count as unresolved (fail closed)."""
    low = _ascii_lower(_node_text(node, src))
    if not low:
        return None
    if node.type == "name":
        alias = ctx.alias_for(low, node.start_byte)
        if alias is not None:
            return _REF_QUALIFIED, alias
        ns = ctx.namespace_at(node.start_byte)
        if not ns:
            return _REF_GLOBAL, low
        return _REF_QUALIFIED, f"{ns}\\{low}"
    if node.type == "qualified_name":
        if low.startswith("\\"):
            fqn = low.lstrip("\\")
            if not fqn:
                return None
            kind = _REF_QUALIFIED if "\\" in fqn else _REF_GLOBAL
            return kind, fqn
        first, _, rest = low.partition("\\")
        alias = ctx.alias_for(first, node.start_byte)
        if alias is not None and rest:
            return _REF_QUALIFIED, f"{alias}\\{rest}"
        ns = ctx.namespace_at(node.start_byte)
        return _REF_QUALIFIED, (f"{ns}\\{low}" if ns else low)
    if node.type == "relative_name":
        # ``namespace\X`` — explicitly the current namespace.
        rest = low.partition("\\")[2] or low
        ns = ctx.namespace_at(node.start_byte)
        return _REF_QUALIFIED, (f"{ns}\\{rest}" if ns else rest)
    return _REF_QUALIFIED, low.lstrip("\\")


def _declared_fqn(name_node: Any, src: bytes, ctx: _NameContext) -> str:
    """Casefolded FQN for a declaration's name node (namespace at the
    declaration site prepended)."""
    low = _ascii_lower(_node_text(name_node, src))
    ns = ctx.namespace_at(name_node.start_byte)
    return f"{ns}\\{low}" if ns else low


def _is_unconditional_toplevel(node: Any) -> bool:
    """True when a declaration binds unconditionally at PHP compile
    time: a direct child of the program, or a direct child of a
    (transitively top-level) namespace body. A class or trait nested
    in an ``if`` body or a never-called function only exists if that
    code RUNS — it must never satisfy parent/trait RESOLUTION (a
    same-name out-of-tree class is what PHP would autoload: the
    false-absence direction), though its trigger surface still
    over-counts (fail closed)."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "program":
        return True
    if parent.type in ("compound_statement", "declaration_list"):
        gp = parent.parent
        if gp is not None and gp.type == "namespace_definition":
            return _is_unconditional_toplevel(gp)
    return False


#: Callee node types that name a function STATICALLY. Every other
#: callee — ``$f(...)``, ``('name')(...)``, ``'name'(...)``, a
#: concat/interpolation-built name, a closure — resolves at runtime
#: and can invoke ANY function, the autoload family included, so it
#: is censused fail-closed (mechanism ``dynamic-callee``).
_STATIC_CALLEE_TYPES = frozenset({
    "name", "qualified_name", "relative_name",
})

#: Global function names the call census dispatches on. Doubles as
#: the ``use function`` rewrite allowlist: an aliased call is
#: rewritten to its import target ONLY when that target resolves to
#: one of these GLOBAL names. The rewrite never runs AWAY from a
#: family spelling (``use function App\x as spl_autoload_register``
#: leaves the spelled name censused — over-block, the safe error:
#: a decoy import must not launder the family name).
_CENSUS_CALL_NAMES = frozenset({
    "unserialize", "spl_autoload_register", "ini_set", "ini_alter",
    "eval", "assert", "create_function", "preg_replace",
    "call_user_func", "call_user_func_array",
})

#: Nested ``call_user_func('call_user_func', ...)`` dispatch bound;
#: beyond it the chain is censused fail-closed as ``dynamic-callee``
#: rather than walked (a machine-built thousand-hop chain must not
#: choose the census's recursion depth).
_MAX_CALLABLE_DISPATCH_DEPTH = 8

#: String-family node types the family-name literal backstop checks
#: wherever the tree walker meets one (see the mention arms in
#: :func:`_scan_toplevel`). The check is position-independent by
#: design: a family name stored ANYWHERE — a default parameter
#: value, an assignment, a return statement, a property or constant
#: initializer, an attribute argument, an anonymous-class
#: constructor argument, an array literal — can flow to a forwarder
#: or a dynamic callee the census cannot see, so only the literal's
#: VALUE decides, never its syntactic position.
_MENTION_LITERAL_TYPES = frozenset({
    "string", "encapsed_string", "heredoc", "nowdoc",
})


class _MalformedLiteral:
    """Marker type for :data:`_MALFORMED_LITERAL` — see there."""

    __slots__ = ()


#: Fail-closed marker :func:`_backstop_literal_content` returns when
#: a heredoc/nowdoc body defeats flexible-indentation recovery
#: (PHP 7.3+ strips the closing marker's indentation from every body
#: line; a non-whitespace body line lacking the closer's exact prefix
#: is a PHP compile error, so meeting one means either a file the
#: engine would reject or a grammar shape the recovery does not
#: understand). Distinct from ``None`` (interpolation — unknowable BY
#: DESIGN, the documented residual): the walker records a fail-closed
#: registration for this marker, because a value the recovery cannot
#: prove NOT to be a family name must withhold the promotable tier,
#: never earn it.
_MALFORMED_LITERAL = _MalformedLiteral()


def _heredoc_closer_indent(node: Any, src: bytes) -> str | None:
    """The flexible-syntax indentation of a heredoc/nowdoc closing
    marker: the horizontal-whitespace run immediately preceding the
    ``heredoc_end`` token, which PHP 7.3+ strips from every body
    line at compile time. ``None`` when the closer cannot be located
    at the start of its own line (no ``heredoc_end`` child, or a
    non-newline byte before the whitespace run) — an unexpected
    shape the caller must treat fail-closed, never as zero
    indentation."""
    end_tok = None
    for c in node.children:
        if c.type == "heredoc_end":
            end_tok = c
            break
    if end_tok is None:
        return None
    stop = end_tok.start_byte
    start = stop
    while start > 0 and src[start - 1:start] in (b" ", b"\t"):
        start -= 1
    if start > 0 and src[start - 1:start] != b"\n":
        return None
    return src[start:stop].decode("ascii")


def _strip_heredoc_indent(line: str, indent: str) -> str | None:
    """One heredoc/nowdoc body line minus the closer's indentation,
    per PHP 7.3+ flexible-heredoc semantics: the closer's exact
    prefix is removed (same characters — a tab never satisfies a
    space, matching the engine's mixing rule); a whitespace-only
    line shorter than the indent strips whole (the engine exempts
    such lines from the indentation requirement). ``None`` when the
    line carries neither — an "invalid body indentation level"
    compile error in PHP, fail-closed at the caller."""
    if line.startswith(indent):
        return line[len(indent):]
    if not line.strip(" \t") and indent.startswith(line):
        return ""
    return None


def _backstop_literal_content(
        node: Any, src: bytes) -> str | _MalformedLiteral | None:
    """Literal text of a string-family node for the mention
    backstop: plain/encapsed strings via
    :func:`_string_literal_content`, plus fully-literal
    heredoc/nowdoc bodies (both are string literals a PHP program
    can spell a callable with) with the closing marker's indentation
    stripped from every body line first — PHP 7.3+ flexible syntax
    makes an indented-closer body the DEDENTED value at runtime, so
    the census must compute that same value or an indented spelling
    of a family name launders past the whole-value match. ``None``
    for any interpolated form — the value is unknowable statically;
    :data:`_MALFORMED_LITERAL` when a body line defeats the
    indentation recovery (callers fail closed — see the marker's
    doc)."""
    if node.type in ("string", "encapsed_string"):
        return _string_literal_content(node, src)
    if node.type in ("heredoc", "nowdoc"):
        body = None
        for c in node.named_children:
            if c.type in ("heredoc_body", "nowdoc_body"):
                body = c
                break
        if body is None:
            return None  # empty body — no content, never a name
        indent = _heredoc_closer_indent(node, src)
        if indent is None:
            return _MALFORMED_LITERAL
        parts: list[str] = []
        for c in body.named_children:
            # Indentation stripping applies to SOURCE lines only —
            # the grammar emits one body token per physical line, so
            # a token is a line head exactly when a newline byte
            # precedes it (escape-decoded ``\n`` never is: PHP does
            # not strip after runtime newlines either).
            line_head = (indent != ""
                         and c.start_byte > 0
                         and src[c.start_byte - 1:c.start_byte]
                         == b"\n")
            # Grammar versions differ on the body-token name:
            # ``string_content`` (current) vs the older
            # ``heredoc_string``/``nowdoc_string``.
            if c.type in ("string_content", "heredoc_string",
                          "nowdoc_string"):
                text: str | None = _node_text(c, src)
                if line_head:
                    text = _strip_heredoc_indent(text, indent)
                    if text is None:
                        return _MALFORMED_LITERAL
                parts.append(text)
            elif c.type == "escape_sequence":
                if line_head:
                    # A body line opening directly with an escape
                    # has zero indentation under a non-zero closer
                    # indent — a PHP compile error.
                    return _MALFORMED_LITERAL
                # Heredoc bodies decode double-quoted escapes;
                # nowdoc bodies contain none, so this arm never
                # fires for them.
                parts.append(_decode_escape_sequence(
                    _node_text(c, src), True))
            else:
                return None  # interpolation
        # Newline-less join BY CONSTRUCTION: the grammar emits one
        # body token per physical line WITHOUT the separating
        # newline bytes, so a multi-line body joins butted.
        # Direction: family names contain no newline, so any value
        # that IS a name is single-line and joins exactly; a
        # multi-line value can only OVER-block, never under-match.
        # A change that inserts newlines here must re-derive that
        # boundary before moving it in the earn direction.
        return "".join(parts)
    return None


#: Longest census family name. A folded-chain summary keeps at most
#: this many characters of joined content (after leading
#: backslashes): a LONGER value can never equal a family name, so
#: keeping more would let a machine-built chain grow per-sub-chain
#: summaries toward the full joined string — quadratic bytes across
#: a chain's sub-chains, the memory twin of the per-node re-fold
#: this bound exists to kill; keeping LESS would truncate a real
#: family name mid-fold and let a split spelling of it earn the
#: promotable tier — a false absence. Derived from the name set, so
#: a census-name addition can never silently outgrow it.
_MAX_FAMILY_NAME_LEN = max(len(n) for n in _CENSUS_CALL_NAMES)


def _chain_leaf_summary(
        content: str | _MalformedLiteral | None,
) -> tuple[int, str] | None:
    """Bounded fold summary of one chain operand's literal content:
    ``(bs, rest)`` where the value is ``bs`` leading backslashes
    followed by the backslash-free, ASCII-lowered ``rest``
    (``len(rest) <= _MAX_FAMILY_NAME_LEN``), or ``None`` when the
    value can never fold into a family name — not statically known
    (``content is None``), malformed heredoc indentation
    (:data:`_MALFORMED_LITERAL` — the chain never matches, and the
    walker's descent into the unmatched chain still meets the
    heredoc node itself, where the mention arm records the
    fail-closed registration), an interior backslash (family names
    have none, and the mention match normalises only LEADING
    backslashes), or content already longer than any family name.
    ``None`` is absorbing through :func:`_chain_combine`: no parent
    chain can fold to a name through such an operand."""
    if not isinstance(content, str):
        return None
    lowered = _ascii_lower(content)
    rest = lowered.lstrip("\\")
    if "\\" in rest or len(rest) > _MAX_FAMILY_NAME_LEN:
        return None
    return (len(lowered) - len(rest), rest)


def _chain_combine(
        left: tuple[int, str] | None,
        right: tuple[int, str] | None) -> tuple[int, str] | None:
    """Fold summary of ``left . right`` from the operands' bounded
    summaries — the concatenation rule under the
    :func:`_chain_leaf_summary` representation. An all-backslash
    left operand merges its count into the right's leading run
    (``'\\\\' . '\\\\unserialize'`` and ``'\\\\\\\\unserialize'`` are
    the same joined value); any other backslash arriving after
    non-backslash content is interior and can never be a name."""
    if left is None or right is None:
        return None
    lbs, lrest = left
    rbs, rrest = right
    if lrest == "":
        return (lbs + rbs, rrest)
    if rbs:
        return None
    joined = lrest + rrest
    if len(joined) > _MAX_FAMILY_NAME_LEN:
        return None
    return (lbs, joined)


def _chain_folds_to_family(node: Any, src: bytes,
                           memo: dict[int, bool]) -> bool:
    """Does the ``.``-concat chain rooted at ``node`` fold, at PHP
    compile time, to a census family name?

    PHP folds adjacent literal concatenation at COMPILE time, so
    ``'spl_autoload' . '_register'`` is byte-for-byte the same
    program as the intact literal — the mention backstop must see
    both spellings identically. Parenthesized operands unwrap
    (comments skipped), operands read through
    :func:`_backstop_literal_content` so escape-spelled fragments
    decode before joining, and a non-``.`` operator or a non-literal
    operand makes the joined value unknowable statically: never a
    match, and the walker descends into the operands instead (each
    literal operand still gets its own whole-value mention check,
    and each interior sub-chain its own recorded verdict — an intact
    family-name operand or sub-chain blocks regardless of what it is
    glued to).

    One bottom-up pass at the FIRST visit — the chain's topmost
    binary node, since the walker meets parents before children —
    computes the verdict for EVERY ``.``-sub-chain of the skeleton
    into ``memo`` (walk-scoped, keyed by node id); descent reads
    interior verdicts back in O(1), so each maximal chain folds
    exactly once. Re-folding at every interior visit instead would
    make every interior node of an unmatched chain re-join its whole
    subtree: O(N**2) on a machine-built chain — minutes at 16,000
    operands, and MAX_FILE_BYTES admits ~1.4M — a planted-file CPU
    stall on the census. Summaries are bounded
    (:data:`_MAX_FAMILY_NAME_LEN`), so the pass is linear in TIME
    and BYTES alike; memoizing full joined strings would be the same
    blowup in memory. The stack machine is iterative — a
    machine-built thousand-operand chain must not choose the
    census's recursion depth."""
    cached = memo.get(node.id)
    if cached is not None:
        return cached
    #: Post-order stack machine over the ``.``-skeleton. Entries are
    #: ``(node, ready)``: not-ready entries classify (chain binary →
    #: expand, anything else → leaf summary), ready entries combine
    #: their operands' summaries off ``vals``.
    work: list[tuple[Any, bool]] = [(node, False)]
    vals: list[tuple[int, str] | None] = []
    verdict = False
    while work:
        n, ready = work.pop()
        if ready:
            right_v = vals.pop()
            left_v = vals.pop()
            summary = _chain_combine(left_v, right_v)
            verdict = (summary is not None
                       and summary[1] in _CENSUS_CALL_NAMES)
            memo[n.id] = verdict
            vals.append(summary)
            continue
        while n.type == "parenthesized_expression":
            inner = None
            for c in n.named_children:
                if c.type != "comment":
                    inner = c
                    break
            if inner is None:
                break
            n = inner
        if n.type == "binary_expression":
            op = n.child_by_field_name("operator")
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if (op is not None and left is not None
                    and right is not None
                    and _node_text(op, src) == "."):
                work.append((n, True))
                # Right pushed first so operands pop in source order.
                work.append((right, False))
                work.append((left, False))
                continue
        vals.append(_chain_leaf_summary(
            _backstop_literal_content(n, src)))
    # A root that is no ``.``-chain at all (a non-``.`` binary the
    # walker dispatched here) never enters ``memo``: its one leaf
    # summary can never match, and the O(1) re-classification on a
    # later visit is cheaper than growing the memo with dead ids.
    return verdict if node.id in memo else False


def _census_family_literal_mention(
        node: Any, value: str, facts: _FileFacts,
        consumed: set[tuple[int, int]]) -> None:
    """Fail-closed backstop over one statically-known string value:
    when its casefolded, namespace-normalised form is a census family
    name (:data:`_CENSUS_CALL_NAMES`), block the promotable tier as
    a ``family-literal-mention`` registration.

    Why it exists: the literal-target dispatch in
    :func:`_census_global_call` resolves only
    ``call_user_func``/``call_user_func_array`` — but PHP has an
    open-ended set of callable-forwarding builtins (``array_map``,
    ``array_walk``, ``array_filter``, ``register_shutdown_function``,
    ``iterator_apply``, ...) and user code adds its own forwarders,
    and a callable string reaches a forwarder from ANY storage
    position: an argument, a variable assigned two lines up, a
    default parameter value, a returned literal, a constant or
    property initializer, an attribute argument, an array element.
    Enumerating either the forwarders or the carrying positions is
    an allowlist that rots the moment a new shape ships; instead the
    family name itself, statically spelled anywhere in the tree, is
    treated as a possible registration. The deliberate fail-closed
    trade: a benign tree that carries a bare family-name string as
    ordinary data (say, logging the word ``assert``) loses the
    promotable tier — over-block, the safe error for a suppression
    blocker. Multi-segment literals (``'App\\unserialize'``,
    ``'Cls::method'``) name a DIFFERENT symbol and never block — the
    match is whole-value against the global family names only.

    ``consumed`` carries the byte spans of literals the precise
    dispatch already resolved, so
    ``call_user_func('spl_autoload_register', $cb)`` keeps its
    single precise census entry instead of gaining a duplicate.

    Known residual (documented, not caught): a family name whose
    fragments are carried to the assembly point OUTSIDE one
    expression — ANY shape where the name never appears whole in
    one literal or one pure-literal concat expression. The defining
    clause is the boundary; illustrative shapes include builtin
    assembly (``sprintf``, ``str_replace``, ``implode``/``join``,
    ``strtr``, ``strrev``, ``str_repeat``), interpolation with
    variables, and cross-statement fragment assembly — ``.=``
    append of literal fragments and ``.``-concat of
    literal-initialized variables, constants, or class constants
    (statically resolvable in principle, but only by
    assignment/constant flow tracking, a new engine with its own
    false-absence surface — the census claims single-expression
    static visibility only). Such a value reaches a forwarder only
    as a dynamic value; where it instead reaches a dynamic CALLEE,
    the dynamic-callee fact catches that shape independently.
    """
    resolved = _ascii_lower(value).lstrip("\\")
    if (resolved in _CENSUS_CALL_NAMES
            and (node.start_byte, node.end_byte) not in consumed):
        facts.autoload_sites.append(
            (_node_line(node), "family-literal-mention"))


def _census_global_call(node: Any, name: str, src: bytes,
                        facts: _FileFacts, *, arg_offset: int = 0,
                        args_opaque: bool = False,
                        depth: int = 0,
                        consumed: set[tuple[int, int]] | None = None,
                        ) -> None:
    """Apply the call census for a call of GLOBAL function ``name``
    whose own arguments start at ``arg_offset`` in ``node``'s
    argument list (the callable-string dispatch below shifts them).

    ``call_user_func``/``call_user_func_array`` with a LITERAL string
    target are PHP's documented indirection idioms and stay precisely
    resolvable: the literal always names a fully-qualified callable
    (callable strings never honour the file's namespace or imports),
    so a single-segment name IS the global function and is censused
    under that name's own rules. ``args_opaque`` marks an
    ``..._array`` dispatch: the target's arguments ride in a runtime
    array, so each per-argument check treats them exactly like a
    dynamic DIRECT argument — fail-closed where the direct rule
    fails closed (the ini key), uncounted where the direct rule
    leaves a dynamic argument uncounted (the assert string form, the
    preg_replace pattern).

    ``consumed`` (when the caller passes it) collects the byte spans
    of literal dispatch targets this walk resolved, so the
    family-literal-mention backstop can skip literals the precise
    dispatch already accounted for.
    """
    line = _node_line(node)
    if name == "unserialize":
        args = node.child_by_field_name("arguments")
        arg_text = (_node_text(args, src)[:MAX_EXCERPT_CHARS]
                    if args is not None else "")
        facts.unserialize_sites.append({
            "line": line,
            "excerpt": arg_text,
            "request_derived": any(
                g in arg_text
                for g in _REQUEST_SUPERGLOBALS),
        })
    elif name == "spl_autoload_register":
        facts.autoload_sites.append((line, "spl_autoload_register"))
    elif name in ("ini_set", "ini_alter"):
        # ini_set('unserialize_callback_func', <fn>)
        # registers a class-name callback that unserialize()
        # invokes for any not-yet-defined class BEFORE any
        # object method runs — autoload-family trigger
        # surface exactly like spl_autoload_register. The
        # KEY decides registration; the VALUE's dynamism is
        # irrelevant (the registration is real either way).
        # A literal key is matched casefolded — PHP ini
        # option names are case-sensitive, so a case-variant
        # spelling over-blocks, the safe direction for a
        # suppression blocker. A dynamic key (variable,
        # concat, interpolation, call, the ..._array runtime
        # array) cannot be proven NOT to be
        # unserialize_callback_func: fail-closed, counted as
        # registration. A zero-argument call is an
        # ArgumentCountError and registers nothing.
        # ini_restore() is out of scope by the tree-census
        # contract: it restores the php.ini master value,
        # which lives outside the tree this census claims
        # anything about.
        if args_opaque:
            facts.autoload_sites.append((line, "ini-dynamic-key"))
        else:
            first = _argument_expr(node, arg_offset)
            if first is not None:
                literal = _string_literal_content(first, src)
                if literal is None:
                    facts.autoload_sites.append(
                        (line, "ini-dynamic-key"))
                elif (_ascii_lower(literal)
                        == "unserialize_callback_func"):
                    facts.autoload_sites.append(
                        (line, "unserialize_callback_func"))
    elif name == "eval":
        facts.dynamic_definition_sites += 1
    elif name == "assert":
        # Only the string form is eval-equivalent; a boolean
        # assert defines nothing. An opaque argument mirrors the
        # direct non-string-node rule: uncounted.
        if not args_opaque:
            first = _argument_expr(node, arg_offset)
            if (first is not None
                    and first.type in _STRING_NODE_TYPES):
                facts.dynamic_definition_sites += 1
    elif name == "create_function":
        # PHP <= 7.4: the body string is eval'd and can
        # define a class the static census never sees.
        facts.dynamic_definition_sites += 1
    elif name == "preg_replace":
        # PHP <= 5.4: a /e-modified pattern evaluates the
        # replacement as code. Only a plain pattern LITERAL
        # is checkable; a dynamic (or opaque) pattern stays
        # uncounted (the eval/assert census above covers the
        # general dynamic-code shapes — this branch exists for
        # the literal legacy form).
        if not args_opaque:
            first = _argument_expr(node, arg_offset)
            literal = _string_literal_content(first, src)
            if literal is not None and _preg_pattern_has_e(literal):
                facts.dynamic_definition_sites += 1
    elif name in ("call_user_func", "call_user_func_array"):
        if args_opaque or depth >= _MAX_CALLABLE_DISPATCH_DEPTH:
            facts.autoload_sites.append((line, "dynamic-callee"))
            return
        target = _argument_expr(node, arg_offset)
        if target is None:
            # Zero-argument call: ArgumentCountError, calls nothing.
            return
        literal = _string_literal_content(target, src)
        if literal is None:
            # Variable/array/closure target — can be any function at
            # runtime: fail-closed.
            facts.autoload_sites.append((line, "dynamic-callee"))
            return
        resolved = _ascii_lower(literal).lstrip("\\")
        if not resolved or "\\" in resolved or "::" in resolved:
            # A namespaced function or a ``Cls::method`` static
            # callable — a DIFFERENT symbol, never the global
            # family; its body, when in tree, is censused where it
            # is declared.
            return
        if consumed is not None:
            consumed.add((target.start_byte, target.end_byte))
        _census_global_call(
            node, resolved, src, facts,
            arg_offset=arg_offset + 1,
            args_opaque=(name == "call_user_func_array"),
            depth=depth + 1, consumed=consumed)


def _scan_toplevel(root: Any, src: bytes, facts: _FileFacts,
                   ctx: _NameContext) -> None:
    """Collect unserialize sites, autoload registrations, and the POP
    trigger-surface census anywhere in the file (including inside
    functions/methods)."""
    #: Byte spans of string literals the precise
    #: call_user_func/call_user_func_array dispatch resolved on this
    #: walk. Hoisted to walk scope because the mention backstop
    #: checks literals at THEIR OWN visits, which happen after the
    #: enclosing call's visit (the walker visits parents before
    #: children), so the dispatch has always recorded its targets by
    #: the time the literal comes up.
    consumed: set[tuple[int, int]] = set()
    #: Per-``.``-chain fold verdicts, keyed by node id (see
    #: _chain_folds_to_family). Walk-scoped like ``consumed``: node
    #: ids are stable only for the life of one parsed tree, and the
    #: first visit of each chain's topmost binary fills in every
    #: interior verdict, so descent never re-folds a sub-chain.
    chain_memo: dict[int, bool] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_call_expression":
            fn = node.child_by_field_name("function")
            name = _callee_name(fn, src)
            if (name is None and fn is not None
                    and fn.type == "relative_name"
                    and not ctx.namespace_at(fn.start_byte)):
                # ``namespace\foo()`` in the GLOBAL namespace is the
                # global function spelled explicitly; inside a real
                # namespace it is a different symbol (handled below
                # as a static non-global callee).
                name = _terminal_identifier(fn, src)
            if name is None:
                if fn is None or fn.type not in _STATIC_CALLEE_TYPES:
                    # The callee is not a statically named function:
                    # ``$f(...)``, ``('name')(...)``, a
                    # concat/interpolation-built name. PHP resolves
                    # it at runtime, so it can be
                    # spl_autoload_register (or ini_set with the
                    # callback key) laundered past every name match
                    # above — fail-closed, counted as registration,
                    # mirroring the ini-dynamic-key precedent.
                    # Demotion-only: the fact can only WITHHOLD the
                    # promotable tier, never mint anything.
                    facts.autoload_sites.append(
                        (_node_line(node), "dynamic-callee"))
                # else: a namespace-qualified static name
                # (``App\foo()``) — a DIFFERENT function symbol,
                # never the global autoload family.
            else:
                if fn.type == "name":
                    resolved = ctx.function_alias_for(
                        name, fn.start_byte)
                    if (resolved is not None
                            and resolved in _CENSUS_CALL_NAMES):
                        # ``use function spl_autoload_register as
                        # sar; sar($cb);`` — resolve the alias to
                        # the global family name PHP calls. Rewrite
                        # only INTO the census set (see
                        # _CENSUS_CALL_NAMES).
                        name = resolved
                _census_global_call(node, name, src, facts,
                                    consumed=consumed)
        elif node.type in _MENTION_LITERAL_TYPES:
            # Position-independent mention backstop: an intact
            # family-name literal ANYWHERE — call argument, default
            # parameter value, assignment, return, initializer,
            # attribute argument, array element — can flow to a
            # forwarder or a dynamic callee the census cannot see.
            # The walker reaches every string node (anonymous-class
            # constructor arguments and attribute argument lists
            # included), so no per-position plumbing exists to
            # miss one.
            content = _backstop_literal_content(node, src)
            if isinstance(content, str):
                _census_family_literal_mention(
                    node, content, facts, consumed)
            elif content is _MALFORMED_LITERAL:
                # A heredoc/nowdoc body that defeated the flexible-
                # indentation recovery: either PHP would refuse to
                # compile the file, or the recovery met a grammar
                # shape it does not understand. Either way the
                # census cannot PROVE the value is not a family
                # name — fail-closed registration, mirroring the
                # dynamic-callee precedent. Demotion-only: the fact
                # can only WITHHOLD the promotable tier, never mint
                # anything.
                facts.autoload_sites.append(
                    (_node_line(node), "malformed-heredoc-indent"))
        elif node.type == "binary_expression":
            # PHP compile-time-folds adjacent literal concatenation:
            # 'spl_autoload' . '_register' is the intact name to the
            # engine and must be to the census too. On a match the
            # operand literals are not visited separately (the fact
            # would double-report); an unmatched or unfoldable chain
            # descends normally, so a family-name OPERAND still gets
            # its own mention check and a matching interior sub-chain
            # its own recorded verdict. The consumed-span guard
            # mirrors _census_family_literal_mention: spans in
            # ``consumed`` are precise-dispatch string targets, never
            # chain nodes, so it is belt-and-braces parity.
            if (_chain_folds_to_family(node, src, chain_memo)
                    and (node.start_byte, node.end_byte)
                    not in consumed):
                facts.autoload_sites.append(
                    (_node_line(node), "family-literal-mention"))
                continue
        elif node.type == "function_definition":
            fn_name = node.child_by_field_name("name")
            if (fn_name is not None
                    and _ascii_lower(_node_text(fn_name, src))
                    == "__autoload"):
                facts.autoload_sites.append(
                    (_node_line(node), "__autoload"))
        elif node.type == "method_declaration":
            # Censused against the full surface set, not just the POP
            # magic methods: a declared serialize/unserialize pair is
            # live trigger surface whenever the class is instanceof
            # Serializable at runtime, and that binding can be spelled
            # where the serializable_impls census cannot see it (an
            # import alias, an in-tree interface extending
            # Serializable, or an out-of-tree interface) — see
            # _SURFACE_CENSUS_NAMES.
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                low = _ascii_lower(_node_text(name_node, src))
                if low in _SURFACE_CENSUS_NAMES:
                    facts.pop_surface[low] = (
                        facts.pop_surface.get(low, 0) + 1)
                    if _in_anonymous_class(node):
                        facts.anonymous_class_methods += 1
        elif node.type == "class_interface_clause":
            for c in node.named_children:
                if (c.type in ("name", "qualified_name")
                        and _terminal_identifier(c, src)
                        == "serializable"):
                    facts.serializable_impls += 1
        elif node.type == "use_as_clause":
            # Trait-use adaptation: ``use T { cleanup as __destruct; }``
            # mints a live magic method no method_declaration ever
            # declares. The alias (the LAST ``name`` child — the
            # original is the first child, a ``name`` or a
            # ``T::method`` class_constant_access_expression, with an
            # optional visibility modifier between) counts as POP
            # surface when it lands on a surface name. A
            # visibility-only adaptation (``foo as protected;``) has
            # no trailing name and renames nothing.
            named = node.named_children
            if len(named) >= 2 and named[-1].type == "name":
                alias_low = _ascii_lower(_node_text(named[-1], src))
                if alias_low in _SURFACE_CENSUS_NAMES:
                    facts.pop_surface[alias_low] = (
                        facts.pop_surface.get(alias_low, 0) + 1)
        elif node.type == "class_declaration":
            name_node = node.child_by_field_name("name")
            # Resolution authority is restricted to unconditional
            # top-level declarations — see _is_unconditional_toplevel.
            if (name_node is not None
                    and _is_unconditional_toplevel(node)):
                facts.declared_class_names.add(
                    _declared_fqn(name_node, src, ctx))
        elif node.type == "base_clause":
            # ``extends`` — but only where a body can ride in:
            # interface extends imports signatures only (interface
            # methods have no bodies in PHP), so it is exempt; every
            # other host (class_declaration, anonymous_class, older-
            # grammar object_creation_expression) is counted
            # fail-closed. Targets carry their resolution kind: only
            # global-context references may take the internal-base
            # allowlist path in scan_tree.
            parent = node.parent
            if parent is not None and parent.type != "interface_declaration":
                for c in node.named_children:
                    if c.type in ("name", "qualified_name",
                                  "relative_name"):
                        ref = _classify_class_ref(c, src, ctx)
                        if ref is not None:
                            facts.extends_targets.append(ref)
        stack.extend(node.named_children)


def _trait_use_names(body: Any, src: bytes,
                     ctx: _NameContext) -> list[str]:
    """Candidate trait FQNs (casefolded, namespace/import-resolved)
    from a class/enum/anonymous-class body's ``use`` clauses. Trait
    ``use`` resolves by the SAME rules as ``extends`` — a bare name
    inside a namespace means <namespace>\\<name>, and an import alias
    redirects it — so the same-file trait table must be matched by
    FQN, never by bare terminal name."""
    out: list[str] = []
    for use in _child_names(body, "use_declaration"):
        for c in use.named_children:
            if c.type in ("name", "qualified_name", "relative_name"):
                ref = _classify_class_ref(c, src, ctx)
                if ref is not None:
                    out.append(ref[1])
    return out


def analyze_php_source(content: bytes) -> _FileFacts | None:
    """Parse one PHP source buffer; None when the grammar is absent."""
    parser = _php_parser()
    if parser is None:
        return None
    facts = _FileFacts()
    try:
        tree = parser.parse(content)
    except Exception as e:  # noqa: BLE001 — parse trouble is census data
        logger.debug("gadget_oracle: parse failed (%s)", e)
        facts.parse_errors = True
        return facts
    if tree is None:
        facts.parse_errors = True
        return facts
    root = tree.root_node
    try:
        facts.parse_errors = bool(root.has_error)
    except AttributeError:
        facts.parse_errors = True
    # One pathological file (a single machine-deep expression) must
    # degrade to a census'd parse error, never crash the tree scan:
    # the method walker recurses over expression depth.
    try:
        ctx = _build_name_context(root, content)
        _scan_toplevel(root, content, facts, ctx)
        # Trait table keyed by casefolded FQN (namespace at the
        # declaration site) — trait names resolve case-insensitively
        # too, but NEVER across namespaces by bare name.
        traits: dict[str, dict[str, _MethodFlow]] = {}
        pending: list[tuple[_ClassFacts, list[str]]] = []
        #: Trait uses from bodies without chain modelling (enums,
        #: anonymous classes) — still censused for resolution: an
        #: out-of-tree trait can carry the magic method AND the sink.
        deferred_uses: list[str] = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type in ("class_declaration", "trait_declaration"):
                name_node = node.child_by_field_name("name")
                name = (_node_text(name_node, content)
                        if name_node is not None else "?")
                body = node.child_by_field_name("body")
                methods: dict[str, _MethodFlow] = {}
                used: list[str] = []
                if body is not None:
                    for m in _child_names(body, "method_declaration"):
                        flow = _analyze_method(m, content)
                        # PHP method names are case-insensitive: key
                        # the table by the lowercased form so
                        # __DESTRUCT is the same method as __destruct.
                        methods[_ascii_lower(flow.name)] = flow
                    used = _trait_use_names(body, content, ctx)
                if node.type == "trait_declaration":
                    # Only an unconditional top-level trait may
                    # satisfy resolution; a dead-branch trait leaves
                    # its uses unresolved (fail closed — PHP does not
                    # compile-hoist it, so its same-name out-of-tree
                    # twin is what an autoloader would fetch).
                    if _is_unconditional_toplevel(node):
                        key = (_declared_fqn(name_node, content, ctx)
                               if name_node is not None
                               else _ascii_lower(name))
                        traits[key] = methods
                else:
                    cls = _ClassFacts(name=name, line=_node_line(node),
                                      methods=methods)
                    pending.append((cls, used))
            elif node.type in ("enum_declaration", "anonymous_class"):
                body = node.child_by_field_name("body")
                if body is not None:
                    deferred_uses.extend(
                        _trait_use_names(body, content, ctx))
            elif node.type == "object_creation_expression":
                # Older grammars inline the anonymous-class body as a
                # direct declaration_list child (no double count on
                # current grammars: they nest an anonymous_class node
                # instead).
                for body in _child_names(node, "declaration_list"):
                    deferred_uses.extend(
                        _trait_use_names(body, content, ctx))
            stack.extend(node.named_children)
        # Merge same-file trait methods (a trait can be declared after
        # its user, so merging happens once the walk is done). The
        # class's own method wins on collision — PHP precedence.
        for cls, used in pending:
            for tname in used:
                tmethods = traits.get(tname)
                if tmethods is None:
                    facts.unresolved_trait_uses += 1
                    continue
                for mname, flow in tmethods.items():
                    cls.methods.setdefault(mname, flow)
            facts.classes.append(cls)
        for tname in deferred_uses:
            if tname not in traits:
                facts.unresolved_trait_uses += 1
    except RecursionError:
        logger.debug("gadget_oracle: recursion limit hit — file "
                     "census'd as parse error")
        facts.parse_errors = True
    return facts


# ── chain assembly ───────────────────────────────────────────────────


def _chains_for_class(cls: _ClassFacts, rel_path: str,
                      budget: int) -> list[dict[str, Any]]:
    """Gadget chains rooted at this class's magic methods.

    Depth: the magic method's own property sinks, plus ONE same-class
    call hop — the callee's property-rooted sinks (reachable because
    the magic method invokes it) and its param-rooted sinks on
    parameters that received a tainted argument.

    ``budget`` is the caller's remaining chain allowance: assembly
    STOPS once it is spent, so a gadget-dense tree never materialises
    an unbounded chain list that a later slice would discard.
    """
    chains: list[dict[str, Any]] = []
    magic_names = list(TRIGGER_METHODS) + list(CONDITIONAL_TRIGGERS)
    for magic in magic_names:
        if len(chains) >= budget:
            return chains
        # The method table is keyed lowercase (PHP case-insensitivity);
        # ``magic`` keeps its canonical spelling for the exhibit.
        flow = cls.methods.get(_ascii_lower(magic))
        if flow is None:
            continue
        base = {
            "class": cls.name,
            "file": rel_path,
            "magic_method": magic,
            "line": flow.line,
            "trigger": ("unserialize" if magic in TRIGGER_METHODS
                        else "conditional"),
        }
        if magic in CONDITIONAL_TRIGGERS:
            base["trigger_requires"] = CONDITIONAL_TRIGGERS[magic]
        for hit in flow.property_sinks:
            if len(chains) >= budget:
                return chains
            chains.append({
                **base, "steps": [],
                "property_path": hit.via, "sink": hit.to_dict(),
            })
        for call in flow.calls:
            callee = cls.methods.get(call.method)
            if callee is None:
                continue
            step = [{"method": call.method, "line": callee.line,
                     "call_line": call.line}]
            for hit in callee.property_sinks:
                if len(chains) >= budget:
                    return chains
                chains.append({
                    **base, "steps": step,
                    "property_path": hit.via, "sink": hit.to_dict(),
                })
            if call.tainted_args:
                passed = {callee.params[i] for i in call.tainted_args
                          if i < len(callee.params)}
                for hit in callee.param_sinks:
                    pname = hit.via.removeprefix("param:")
                    if pname in passed:
                        if len(chains) >= budget:
                            return chains
                        chains.append({
                            **base, "steps": step,
                            "property_path": call.via or hit.via,
                            "sink": hit.to_dict(),
                        })
    return chains


# ── tree scan ────────────────────────────────────────────────────────


def _iter_tree_files(root: Path) -> tuple[list[tuple[str, Path]],
                                          dict[str, Any]]:
    """(rel_posix, abs) pairs for regular files, plus walk stats.

    Only REGULAR files are opened: a FIFO/socket/device in a hostile
    tree would block ``open()`` forever (the shared inventory walker's
    ``is_file()`` guard, mirrored here). Skips are never silent —
    symlinks (files AND directories, which ``os.walk`` does not
    follow) and special files are counted so the census can state
    exactly what the walk did not look at.
    """
    out: list[tuple[str, Path]] = []
    stats: dict[str, Any] = {
        "truncated": False,
        "symlink_skipped": 0,
        "special_skipped": 0,
        "skipped_dirs_with_php": 0,
        "skipped_dirs_with_php_listed": [],
    }
    root_s = str(root)
    for dirpath, dirnames, filenames in os.walk(root_s):
        kept: list[str] = []
        for d in sorted(dirnames):
            if d in _WALK_SKIP_DIRS:
                # Skipped, never silent: a skipped dir carrying
                # PHP-like content breaks census completeness (a
                # gadget in node_modules/ or .git/hooks/ must not
                # vanish from the absence claim).
                full_dir = os.path.join(dirpath, d)
                if os.path.islink(full_dir):
                    # A symlinked skip-dir is never probed (os.walk
                    # on a symlink root FOLLOWS it — potentially out
                    # of tree); count it with the other symlink
                    # skips so completeness still breaks.
                    stats["symlink_skipped"] += 1
                elif _skipped_dir_has_php(full_dir):
                    stats["skipped_dirs_with_php"] += 1
                    listed = stats["skipped_dirs_with_php_listed"]
                    if len(listed) < MAX_CENSUS_PATHS_LISTED:
                        listed.append(os.path.relpath(full_dir, root_s)
                                      .replace(os.sep, "/"))
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                stats["symlink_skipped"] += 1
                continue
            kept.append(d)
        dirnames[:] = kept
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                stats["symlink_skipped"] += 1
                continue
            if not os.path.isfile(full):
                stats["special_skipped"] += 1
                continue
            rel = os.path.relpath(full, root_s).replace(os.sep, "/")
            out.append((rel, Path(full)))
            if len(out) >= MAX_FILES:
                logger.warning(
                    "gadget_oracle: tree listing capped at %d files",
                    MAX_FILES)
                stats["truncated"] = True
                return out, stats
    return out, stats


def _availability_basis(
    class_file: str,
    site_files: set[str],
    autoload_registered: bool,
    include_graph: dict[str, Any] | None,
) -> str:
    """Best statically-knowable availability basis for a gadget class
    at the tree's unserialize sites. NONE of these proves runtime
    availability; ``not_established`` is the honest floor, never a
    reachability verdict."""
    if class_file in site_files:
        return "same_file"
    if autoload_registered:
        return "autoload_registered"
    if isinstance(include_graph, dict):
        files = include_graph.get("files")
        if isinstance(files, dict):
            entry = files.get(class_file)
            if isinstance(entry, dict):
                count = entry.get("includer_count")
                if isinstance(count, int) and count >= 1:
                    return "included_somewhere"
    return "not_established"


def scan_tree(
    target_root: str | Path,
    *,
    include_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan a tree for PHP gadget chains; returns the artifact dict.

    Mechanical only — no LLM anywhere, no target code executed. The
    census is the completeness contract: every file the scan could
    not read/parse/afford is COUNTED, so the absence direction is
    quotable only modulo those counts.
    """
    root = Path(target_root)
    generated_at = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "tier": "hint",
        "producer": {
            "module": PRODUCER_MODULE,
            "version": PRODUCER_VERSION,
            "generated_at": generated_at,
        },
        "note": ARTIFACT_NOTE,
        "target_path": str(root),
        "capability": {"tree_sitter_php": php_grammar_available()},
        "analysis_depth": {
            "property_flow": (
                "intra-method direct flows plus one same-class "
                "method-call hop"
            ),
            "flow_insensitive": True,
            "inheritance_resolved": False,
            "trigger_methods": list(TRIGGER_METHODS),
            "conditional_triggers": sorted(CONDITIONAL_TRIGGERS),
        },
    }
    if not root.is_dir():
        report["capability"]["target_usable"] = False
        report["census"] = {"complete": False,
                            "incomplete_reasons": ["target-unusable"]}
        report["chains"] = []
        report["unserialize_sites"] = []
        report["absence_tier"] = TIER_NONE
        return report
    report["target_path"] = str(root.resolve())
    if not report["capability"]["tree_sitter_php"]:
        report["census"] = {
            "complete": False,
            "incomplete_reasons": [REASON_GRAMMAR_UNAVAILABLE],
        }
        report["chains"] = []
        report["unserialize_sites"] = []
        report["absence_tier"] = TIER_NONE
        return report

    files, walk_stats = _iter_tree_files(root)
    php_files = 0
    parsed_clean = 0
    parse_error_count = 0
    read_error_count = 0
    oversized_count = 0
    php_like_unscanned_count = 0
    unresolved_trait_count = 0
    parse_error_files: list[str] = []
    read_error_files: list[str] = []
    oversized_files: list[str] = []
    php_like_listed: list[str] = []
    chains: list[dict[str, Any]] = []
    sites: list[dict[str, Any]] = []
    sites_total = 0
    site_files: set[str] = set()
    autoload_sites: list[dict[str, Any]] = []
    autoload_registered = False
    magic_counts: dict[str, int] = {}
    class_count = 0
    per_class_availability: list[tuple[dict[str, Any], str]] = []
    surface_counts: dict[str, int] = {}
    serializable_impls = 0
    dynamic_definition_sites = 0
    anonymous_class_methods = 0
    extends_targets: list[tuple[str, str]] = []
    declared_class_names: set[str] = set()

    for rel, full in files:
        suffix = _ascii_lower(os.path.splitext(rel)[1])
        is_php = suffix in PHP_EXTENSIONS
        try:
            if not is_php:
                with open(full, "rb") as fh:
                    head = fh.read(_PHP_PROBE_BYTES)
                if _PHP_OPEN_TAG_RE.search(head):
                    php_like_unscanned_count += 1
                    if len(php_like_listed) < MAX_CENSUS_PATHS_LISTED:
                        php_like_listed.append(rel)
                continue
            php_files += 1
            size = full.stat().st_size
            if size > MAX_FILE_BYTES:
                oversized_count += 1
                if len(oversized_files) < MAX_CENSUS_PATHS_LISTED:
                    oversized_files.append(rel)
                continue
            with open(full, "rb") as fh:
                content = fh.read(MAX_FILE_BYTES + 1)
        except OSError:
            if is_php:
                read_error_count += 1
                if len(read_error_files) < MAX_CENSUS_PATHS_LISTED:
                    read_error_files.append(rel)
            continue
        facts = analyze_php_source(content)
        if facts is None:
            # Grammar vanished mid-scan (test seams) — capability gap.
            report["capability"]["tree_sitter_php"] = False
            break
        if facts.parse_errors:
            parse_error_count += 1
            if len(parse_error_files) < MAX_CENSUS_PATHS_LISTED:
                parse_error_files.append(rel)
        else:
            parsed_clean += 1
        unresolved_trait_count += facts.unresolved_trait_uses
        for low, n in facts.pop_surface.items():
            surface_counts[low] = surface_counts.get(low, 0) + n
        serializable_impls += facts.serializable_impls
        dynamic_definition_sites += facts.dynamic_definition_sites
        anonymous_class_methods += facts.anonymous_class_methods
        extends_targets.extend(facts.extends_targets)
        declared_class_names |= facts.declared_class_names
        if facts.unserialize_sites:
            site_files.add(rel)
        for s in facts.unserialize_sites:
            sites_total += 1
            if len(sites) < MAX_SITES_LISTED:
                sites.append({"file": rel, **s})
        if facts.autoload_sites:
            autoload_registered = True
        for line, mechanism in facts.autoload_sites:
            if len(autoload_sites) >= MAX_CENSUS_PATHS_LISTED:
                break
            autoload_sites.append(
                {"file": rel, "line": line, "mechanism": mechanism})
        for cls in facts.classes:
            class_count += 1
            for m in cls.methods.values():
                low = _ascii_lower(m.name)
                if (low in TRIGGER_METHODS
                        or low in _CONDITIONAL_TRIGGERS_LOWER):
                    canon = _CONDITIONAL_TRIGGERS_LOWER.get(low, low)
                    magic_counts[canon] = magic_counts.get(canon, 0) + 1
            # Chain assembly stops at MAX_CHAINS + 1 (the +1 proves
            # truncation) DURING the walk; the census above continues
            # so magic/class counts stay complete after the budget is
            # spent.
            budget = MAX_CHAINS + 1 - len(per_class_availability)
            if budget > 0:
                for chain in _chains_for_class(cls, rel, budget):
                    per_class_availability.append((chain, rel))

    for chain, rel in per_class_availability:
        chain["availability"] = _availability_basis(
            rel, site_files, autoload_registered, include_graph)
        chains.append(chain)

    # Parent resolution is TREE-wide over casefolded FQNs: every
    # target (already resolved under its file's namespace/import
    # context) matches against every class declared in the tree;
    # ONLY a global-context reference may then fall back to the
    # internal-base allowlist — a bare name inside a namespace means
    # <namespace>\<name> (PHP classes have no global fallback) and an
    # import alias redirects the name, so neither is ever the
    # internal base it happens to spell. Whatever is left is an
    # out-of-tree parent whose inherited trigger surface the census
    # cannot see.
    unresolved_parents: list[str] = []
    for kind, tgt in extends_targets:
        if tgt in declared_class_names:
            continue
        if kind == _REF_GLOBAL and tgt in _INTERNAL_BASE_CLASSES:
            continue
        unresolved_parents.append(tgt)
    unresolved_parent_count = len(unresolved_parents)

    incomplete: list[str] = []
    if not report["capability"]["tree_sitter_php"]:
        incomplete.append(REASON_GRAMMAR_UNAVAILABLE)
    if parse_error_count:
        incomplete.append("parse-errors")
    if read_error_count:
        incomplete.append("read-errors")
    if oversized_count:
        incomplete.append("oversized-files")
    if php_like_unscanned_count:
        incomplete.append("php-like-unscanned")
    if walk_stats["symlink_skipped"]:
        # A symlink can point at a gadget class the walk never read —
        # completeness-breaking, never a silent skip.
        incomplete.append("symlinks-skipped")
    if unresolved_trait_count:
        # A trait defined elsewhere can carry the magic method AND
        # the sink — using it unresolved breaks the absence claim.
        incomplete.append("unresolved-traits")
    if unresolved_parent_count:
        # An out-of-tree parent class hands its child every inherited
        # magic method — a trigger the census never parsed.
        incomplete.append("unresolved-parents")
    if walk_stats["skipped_dirs_with_php"]:
        # A never-walked dir (node_modules/, .git/, ...) that holds
        # PHP-like content can hide a gadget class from the census.
        incomplete.append("walk-skipped-dirs")
    if walk_stats["truncated"]:
        incomplete.append("file-cap-truncated")
    # Special files (FIFO/socket/device) are COUNTED but not
    # completeness-breaking: they have no at-rest content a parse
    # could have seen, so no gadget class can hide in one. Breaking
    # on them would mark any tree with a stray socket Incomplete for
    # content that cannot exist; not counting them would hide that
    # the walk met (and refused to open) non-regular files.

    report["census"] = {
        "php_files": php_files,
        "parsed_clean": parsed_clean,
        "parse_error_count": parse_error_count,
        "read_error_count": read_error_count,
        "oversized_count": oversized_count,
        "php_like_unscanned_count": php_like_unscanned_count,
        "symlink_skipped_count": walk_stats["symlink_skipped"],
        "special_file_count": walk_stats["special_skipped"],
        "unresolved_trait_count": unresolved_trait_count,
        "unresolved_parent_count": unresolved_parent_count,
        "walk_skipped_dirs_with_php_count":
            walk_stats["skipped_dirs_with_php"],
        "php_probe_bytes": _PHP_PROBE_BYTES,
        "files_truncated": walk_stats["truncated"],
        "complete": not incomplete,
        "incomplete_reasons": incomplete,
    }
    report["census_detail"] = {
        "parse_error_files": parse_error_files,
        "read_error_files": read_error_files,
        "oversized_files": oversized_files,
        "php_like_unscanned_files": php_like_listed,
        "unresolved_parents": sorted(
            set(unresolved_parents))[:MAX_CENSUS_PATHS_LISTED],
        "walk_skipped_dirs_with_php":
            walk_stats["skipped_dirs_with_php_listed"],
    }
    report["magic_method_census"] = {
        "classes": class_count,
        "by_method": dict(sorted(magic_counts.items())),
    }
    report["autoload"] = {
        "registered": autoload_registered,
        "sites": autoload_sites,
    }
    report["unserialize_sites"] = sites
    report["unserialize_sites_total"] = sites_total
    if sites_total > MAX_SITES_LISTED:
        report["unserialize_sites_truncated"] = True
    report["chains"] = chains[:MAX_CHAINS]
    if len(chains) > MAX_CHAINS:
        report["chains_truncated"] = True
    report["pop_surface"] = {
        "by_method": dict(sorted(surface_counts.items())),
        "total_methods": sum(surface_counts.values()),
        "serializable_impls": serializable_impls,
        "dynamic_definition_sites": dynamic_definition_sites,
        "anonymous_class_methods": anonymous_class_methods,
    }
    report["absence_tier"] = absence_tier(report)
    return report


def _census_count_ok(value: Any) -> bool:
    """A well-formed census counter: a non-negative real int."""
    return (isinstance(value, int) and not isinstance(value, bool)
            and value >= 0)


def absence_tier(report: dict[str, Any]) -> str:
    """The absence tier a report supports — pure and FAIL-CLOSED.

    * :data:`TIER_NO_GADGET_SURFACE` — complete census of at least
      one PHP file, zero chains, zero POP trigger surface (no
      surface magic method anywhere, no declared
      ``serialize``/``unserialize`` pair, no ``Serializable``
      implementation, no dynamic-definition site), AND no
      autoload-family registration anywhere in the tree — the
      fail-closed dynamic-callee, dynamic-ini-key, and
      family-literal-mention facts included.
      Depth-independent structural claim; the only tier a corpus can
      ever promote to suppression authority.
    * :data:`TIER_NO_CHAINS_FOUND` — complete census, zero chains,
      but surface EXISTS or an autoload mechanism is registered.
      Depth-limited / registration-blocked; never promotable.
    * :data:`TIER_NONE` — chains present, degraded census, a
      vacuously empty scan (zero PHP files — "no gadget surface"
      would be true of any mis-pointed path, so it is no claim at
      all), or ANY missing/malformed/inconsistent census field — the
      ``autoload`` record included (fail-closed: a tier must never
      be minted from a report that cannot prove it; a report
      predating the autoload record cannot prove the registration
      side of the claim, and a record whose ``registered`` boolean
      contradicts its own ``sites`` list proves nothing either).

    Why registration blocks: ``unserialize('O:7:"payload":0:{}')``
    hands the attacker-chosen class-name string to the autoload
    chain (SPL registrations, legacy ``__autoload``, the ini
    ``unserialize_callback_func`` callback) BEFORE any object method
    is consulted. An in-tree loader that maps names to
    ``include``/``require`` paths executes in-tree top-level code —
    trigger surface no method census counts. Proving a registered
    loader side-effect-free (every mapping resolves only to
    class-definition files with no side-effectful top-level code) is
    new analysis, not a predicate tweak — until then registration
    demotes, fail-closed.
    """
    if not isinstance(report, dict):
        return TIER_NONE
    census = report.get("census")
    if not isinstance(census, dict) or census.get("complete") is not True:
        return TIER_NONE
    php_files = census.get("php_files")
    if not _census_count_ok(php_files) or php_files == 0:
        # Zero PHP files is a VACUOUS absence: every counter is zero
        # because nothing was looked at, not because a census cleared
        # anything. A mis-pointed target path must never mint a
        # suppression-grade claim about findings filed elsewhere.
        return TIER_NONE
    chains = report.get("chains")
    if not isinstance(chains, list) or chains:
        return TIER_NONE
    if report.get("chains_truncated"):
        return TIER_NONE
    autoload = report.get("autoload")
    if not isinstance(autoload, dict):
        return TIER_NONE
    autoload_registered = autoload.get("registered")
    if not isinstance(autoload_registered, bool):
        return TIER_NONE
    if autoload_registered is False and autoload.get("sites"):
        # "Not registered" alongside a non-empty sites list is an
        # internally inconsistent record — an artifact edit, never a
        # live scan (which derives the boolean FROM the sites).
        # Fail closed rather than trust either half.
        return TIER_NONE
    surface = report.get("pop_surface")
    if not isinstance(surface, dict):
        return TIER_NONE
    by_method = surface.get("by_method")
    if not isinstance(by_method, dict):
        return TIER_NONE
    total = 0
    for count in by_method.values():
        if not _census_count_ok(count):
            return TIER_NONE
        total += count
    blockers = [
        surface.get("serializable_impls"),
        surface.get("dynamic_definition_sites"),
        surface.get("anonymous_class_methods"),
    ]
    if not all(_census_count_ok(b) for b in blockers):
        return TIER_NONE
    if total == 0 and not any(blockers) and not autoload_registered:
        return TIER_NO_GADGET_SURFACE
    return TIER_NO_CHAINS_FOUND


# ── artifact I/O ─────────────────────────────────────────────────────


def save_gadget_report(output_dir: str | Path,
                       report: dict[str, Any]) -> None:
    """Write ``gadget-chains.json`` into the run directory (atomic)."""
    from core.json import save_json
    save_json(Path(output_dir) / ARTIFACT_NAME, report)


def resolve_artifact_path(output_dir: str | Path) -> Path | None:
    """The existing artifact for a run dir, or None. Follows the
    project-mode ``checklist.json`` symlink the way the include-graph
    loader does (sibling artifacts live beside the resolved
    checklist)."""
    base = Path(output_dir)
    cand = base / ARTIFACT_NAME
    if not cand.exists():
        cl = base / "checklist.json"
        if cl.is_symlink():
            try:
                cand = cl.resolve().parent / ARTIFACT_NAME
            except OSError:
                return None
    return cand if cand.is_file() else None


def load_gadget_report(output_dir: str | Path) -> dict[str, Any] | None:
    """Read the artifact from a run dir; None when missing/malformed
    (consumers degrade to pre-oracle behaviour)."""
    from core.json import load_json
    cand = resolve_artifact_path(output_dir)
    if cand is None:
        return None
    try:
        data = load_json(cand, max_bytes=MAX_REPORT_BYTES)
    except Exception:  # noqa: BLE001 — a bad artifact never blocks a consumer
        logger.debug("gadget_oracle: unreadable artifact at %s", cand,
                     exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def report_matches_target(report: dict[str, Any],
                          target_root: str | Path | None) -> bool:
    """One-target rule, fail-closed: the artifact's facts apply only
    to the tree they were derived from. Unknown/unresolvable roots on
    EITHER side refuse (False), never guess."""
    recorded = report.get("target_path")
    if not isinstance(recorded, str) or not recorded or target_root is None:
        return False
    try:
        return Path(recorded).resolve() == Path(target_root).resolve()
    except OSError:
        return False


# ── consumer query (the ONE re-validating read path) ─────────────────


#: Qualifier rendered when the census cannot be validated.
CENSUS_UNKNOWN_QUALIFIER = (
    "Gadget-oracle census is missing or invalid — enumeration "
    "completeness is unknown. Treat both directions as hints and "
    "verify against source; never treat these facts as a verdict "
    "input."
)


def census_qualifier(report: dict[str, Any]) -> str:
    """Mandatory completeness qualifier every consumer must render
    beside the facts — quoting absence without it is exactly the
    dishonest shape this tool exists to replace."""
    census = report.get("census")
    if not isinstance(census, dict) or not isinstance(
            census.get("complete"), bool):
        return CENSUS_UNKNOWN_QUALIFIER
    depth = "intra-method + one same-class call hop"
    probe = census.get("php_probe_bytes")
    probe_note = (
        f"; non-PHP extensions probed only the first "
        f"{probe // 1024} KiB for open tags"
        if isinstance(probe, int) and not isinstance(probe, bool)
        and probe > 0 else ""
    )
    if census["complete"]:
        tier = absence_tier(report)
        if tier == TIER_NO_GADGET_SURFACE:
            tier_note = (
                " Zero POP trigger surface censused (absence tier: "
                "no_gadget_surface — no in-tree magic-method trigger "
                "at ANY depth, no declared serialize/unserialize "
                "pair, no Serializable implementation, no "
                "dynamic-definition site, no autoload-family "
                "registration)."
            )
        elif tier == TIER_NO_CHAINS_FOUND:
            tier_note = (
                " POP trigger surface EXISTS (or an autoload "
                "mechanism is registered — unserialize() runs the "
                "loader on the attacker-chosen class name before "
                "any object method) but the depth-limited search "
                "found no chains (absence tier: no_chains_found — "
                "never suppression-grade)."
            )
        else:
            tier_note = ""
        return (
            f"Hint-tier gadget facts from a COMPLETE parse census "
            f"({census.get('parsed_clean', '?')} PHP file(s), all "
            f"parsed clean; flow depth: {depth}{probe_note}). A "
            f"deeper or cross-class chain would not be found."
            f"{tier_note} "
            f"Steering context — verify against source; never treat "
            f"as a verdict input."
        )
    reasons = ", ".join(
        str(r) for r in (census.get("incomplete_reasons") or [])[:6]
    ) or "unknown"
    return (
        f"Hint-tier gadget facts from an INCOMPLETE census "
        f"({census.get('parsed_clean', '?')}/"
        f"{census.get('php_files', '?')} PHP file(s) parsed clean; "
        f"gaps: {reasons}; flow depth: {depth}{probe_note}). Absence "
        f"of chains here is weak evidence. Steering context — verify "
        f"against source; never treat as a verdict input."
    )


def _coerce_chain(raw: Any) -> dict[str, Any] | None:
    """Bound and type-coerce one chain row from run-dir (untrusted)
    JSON — tampered strings must never ride unbounded into prompts."""
    if not isinstance(raw, dict):
        return None
    sink = raw.get("sink") if isinstance(raw.get("sink"), dict) else {}
    line = raw.get("line")
    sink_line = sink.get("line")
    steps = []
    for s in (raw.get("steps") or [])[:4]:
        if isinstance(s, dict):
            steps.append(str(s.get("method") or "")[:128])
    return {
        "class": str(raw.get("class") or "")[:256],
        "file": str(raw.get("file") or "")[:512],
        "magic_method": str(raw.get("magic_method") or "")[:64],
        "line": line if isinstance(line, int)
        and not isinstance(line, bool) and line >= 0 else 0,
        "trigger": ("unserialize"
                    if raw.get("trigger") == "unserialize"
                    else "conditional"),
        "trigger_requires": str(raw.get("trigger_requires") or "")[:200],
        "steps": steps,
        "property_path": str(
            raw.get("property_path") or "")[:MAX_PROPERTY_PATH_CHARS],
        "sink_category": str(sink.get("category") or "")[:32],
        "sink_callee": str(sink.get("callee") or "")[:128],
        "sink_line": sink_line if isinstance(sink_line, int)
        and not isinstance(sink_line, bool) and sink_line >= 0 else 0,
        "sink_excerpt": str(sink.get("excerpt") or "")[:MAX_EXCERPT_CHARS],
        "availability": str(raw.get("availability") or "")[:64],
    }


def gadget_facts_for_file(
    report: dict[str, Any],
    file_path: str,
    *,
    max_chains: int = 8,
    max_sites: int = 5,
) -> dict[str, Any] | None:
    """Consumer-facing gadget facts for one file plus the tree-level
    summary. The census + qualifier are ALWAYS part of the result.
    Returns None when the report carries no usable census (an
    unqualified fact must never exist). The artifact lives in a run
    directory (attacker-adjacent shapes), so every field is coerced
    and bounded here — the one query every consumer goes through.
    """
    if not isinstance(report, dict):
        return None
    census = report.get("census")
    if not isinstance(census, dict):
        return None
    p = (file_path.replace("\\", "/").removeprefix("./")
         if file_path else "")
    all_chains = [c for c in (report.get("chains") or [])
                  if isinstance(c, dict)]
    file_chains = []
    for raw in all_chains:
        coerced = _coerce_chain(raw)
        if coerced and coerced["file"] == p:
            file_chains.append(coerced)
        if len(file_chains) >= max_chains:
            break
    tree_chains: list[dict[str, Any]] = []
    if not file_chains:
        for raw in all_chains[:max_chains]:
            coerced = _coerce_chain(raw)
            if coerced:
                tree_chains.append(coerced)
    file_sites = []
    for s in (report.get("unserialize_sites") or []):
        if not isinstance(s, dict) or s.get("file") != p:
            continue
        line = s.get("line")
        file_sites.append({
            "line": line if isinstance(line, int)
            and not isinstance(line, bool) and line >= 0 else 0,
            "request_derived": bool(s.get("request_derived")),
            "excerpt": str(s.get("excerpt") or "")[:MAX_EXCERPT_CHARS],
        })
        if len(file_sites) >= max_sites:
            break
    return {
        "tier": "hint",
        "chains_total": len(all_chains),
        "chains_in_file": file_chains,
        "chains_elsewhere": tree_chains,
        "unserialize_sites_in_file": file_sites,
        "census_complete": bool(census.get("complete"))
        if isinstance(census.get("complete"), bool) else False,
        "qualifier": census_qualifier(report),
    }


# ── audit-channel surface ────────────────────────────────────────────


def is_gadget_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts a deserialization-gadget shape
    (either direction: a chain exists, or 'no gadgets in tree')."""
    return bool(text) and bool(_GADGET_HYPOTHESIS_RE.search(text))


def gadget_oracle_applicable(cwe: str) -> bool:
    """CWE fallback-chain gate: the deserialization family."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in GADGET_ORACLE_CWES


def gadget_language_permitted(
    file_path: str, language: str | None = None,
) -> bool:
    """Chain-BUILD language gate (both orchestrator hooks call it).

    PHP is the only modeled substrate. Mirrors the sanwit gate: mapped
    ``.php`` extensions pass; unmapped extensions pass on a php
    content-probe hint; no file context fails CLOSED (the joern_langs
    precedent) — the leg's existence feeds the empty-dispatch
    synthesis routing, which must stay unchanged off-PHP.
    """
    from core.audit.hypothesis_mapping import (
        semgrep_language_for,
        semgrep_probed_language,
    )
    if semgrep_language_for(file_path or "") == "php":
        return True
    return semgrep_probed_language(file_path or "", language) == "php"


def is_detection_rule_id(rule_id: str) -> bool:
    """The WHOLE namespace is detection-grade (sanwit precedent): a
    found chain adjudicates gadget existence, not the request-to-
    unserialize taint path, so it may corroborate and exhibit but
    never promote a finding alone."""
    return rule_id.startswith("gadget_oracle:")


@dataclass
class GadgetOracleEvidence:
    """Channel verdict for one CWE-502 hypothesis."""

    outcome: str                 # confirmed | inconclusive | skipped | error
    reason: str
    rule_id: str = RULE_CHAIN
    tool: str = "gadget_oracle"
    file_path: str = ""
    function_name: str = ""
    chains: list[dict[str, Any]] = field(default_factory=list)
    census: dict[str, Any] = field(default_factory=dict)
    qualifier: str = ""
    #: Absence tier the scan report supports (``no_gadget_surface`` /
    #: ``no_chains_found`` / ``none``) — surfaced honestly on every
    #: verdict so consumers see WHICH absence claim rode along. Stays
    #: informational while :data:`ABSENCE_EARNS_SUPPRESSION` is False.
    absence_tier: str = TIER_NONE
    # Plain tool stamps and structured receipts both slot in (the
    # fail_open corroboration convention).
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool,
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "census": self.census,
            "qualifier": self.qualifier,
            "absence_tier": self.absence_tier,
        }
        if self.chains:
            d["chains"] = self.chains
        if self.corroboration:
            d["corroboration"] = list(self.corroboration)
        return d


_SCAN_MEMO_LOCK = threading.Lock()
_SCAN_MEMO: dict[str, dict[str, Any]] = {}


def reset_scan_memo() -> None:
    """Test seam: forget per-target scan results."""
    with _SCAN_MEMO_LOCK:
        _SCAN_MEMO.clear()


def _memoized_scan(target_root: Path,
                   include_graph: dict[str, Any] | None) -> dict[str, Any]:
    """One tree scan per resolved target root per process — the audit
    dispatches this channel once per hypothesis, and the tree does
    not change mid-run."""
    try:
        key = str(target_root.resolve())
    except OSError:
        key = str(target_root)
    with _SCAN_MEMO_LOCK:
        hit = _SCAN_MEMO.get(key)
    if hit is not None:
        return hit
    report = scan_tree(target_root, include_graph=include_graph)
    with _SCAN_MEMO_LOCK:
        return _SCAN_MEMO.setdefault(key, report)


def _record_absence_row(
    output_dir: str | Path,
    file_path: str,
    function_name: str,
    report: dict[str, Any],
) -> None:
    """Record-only suppressions.jsonl row (``dropped: false``): the
    absence evidence was attached to a finding's adjudication. In this
    increment NOTHING is dropped on it — the row exists so operators
    can see exactly what the oracle saw, and so the corpus-earned
    promotion (named follow-up) has an audit trail to measure
    against."""
    try:
        from core.analysis.reach_chokepoint import record_suppression
        census = report.get("census") or {}
        record_suppression(
            Path(output_dir),
            finding={"file_path": file_path, "function": function_name},
            verdict=ABSENCE_RECORD_VERDICT,
            reason=census_qualifier(report),
            dropped=False,
            extra={
                "census": {
                    k: census.get(k)
                    for k in ("php_files", "parsed_clean", "complete",
                              "incomplete_reasons")
                },
                "absence_tier": absence_tier(report),
                "earns_suppression": ABSENCE_EARNS_SUPPRESSION,
            },
        )
    except Exception:  # noqa: BLE001 — best-effort audit trail
        logger.debug("gadget_oracle: absence record write failed",
                     exc_info=True)


def run_gadget_oracle_check(
    target_path: str | Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    language: str | None = None,
    include_graph: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
) -> GadgetOracleEvidence:
    """Channel entry point (the run_*_check convention).

    Outcome mapping — the authority adjudication, in code:

    * chains found → ``confirmed`` with a detection-grade stamp
      (witness exhibits ride on the receipt; the stamp never promotes
      alone).
    * no chains → ``inconclusive`` ALWAYS (never ``refuted``): with a
      complete census the reason is the strong-absence variant, with
      a degraded census the weak one. A ``dropped: false``
      suppressions row records what the oracle saw.
    * grammar absent / non-PHP file / unusable target → ``skipped``
      (capability-absent recorded, never a silent pass and never a
      clean resolution).
    """
    ev = GadgetOracleEvidence(
        outcome="skipped", reason="", file_path=file_path,
        function_name=function_name,
    )
    if not gadget_language_permitted(file_path, language):
        ev.reason = REASON_LANGUAGE_UNSUPPORTED
        return ev
    if not php_grammar_available():
        ev.reason = REASON_GRAMMAR_UNAVAILABLE
        return ev
    root = Path(target_path)
    if not root.is_dir():
        ev.reason = REASON_TARGET_UNUSABLE
        return ev
    report = _memoized_scan(root, include_graph)
    if output_dir is not None:
        try:
            existing = load_gadget_report(output_dir)
            if existing is None or not report_matches_target(
                    existing, root):
                save_gadget_report(output_dir, report)
        except Exception:  # noqa: BLE001 — artifact write is best-effort
            logger.debug("gadget_oracle: artifact write failed",
                         exc_info=True)
    census = report.get("census") or {}
    ev.census = {
        k: census.get(k)
        for k in ("php_files", "parsed_clean", "parse_error_count",
                  "php_like_unscanned_count", "complete",
                  "incomplete_reasons")
    }
    ev.qualifier = census_qualifier(report)
    chains = [c for c in (report.get("chains") or [])
              if isinstance(c, dict)]
    if chains:
        coerced = [c for c in (_coerce_chain(raw) for raw in chains[:8])
                   if c is not None]
        ev.chains = coerced
        unconditional = [c for c in coerced
                         if c["trigger"] == "unserialize"]
        ev.outcome = "confirmed"
        ev.rule_id = (RULE_CHAIN if unconditional
                      else RULE_CHAIN_CONDITIONAL)
        top = (unconditional or coerced)[0]
        ev.reason = (
            f"{len(chains)} gadget chain(s) in tree; e.g. "
            f"{top['class']}::{top['magic_method']} -> "
            f"{top['sink_category']}:{top['sink_callee']} via "
            f"$this->{top['property_path']} "
            f"({top['file']}:{top['sink_line']}, availability: "
            f"{top['availability']}). Witness exhibit — verify "
            f"against source; the request-to-unserialize taint path "
            f"is a separate claim."
        )
        return ev
    ev.outcome = "inconclusive"
    ev.rule_id = RULE_ABSENCE
    ev.absence_tier = absence_tier(report)
    complete = census.get("complete") is True
    ev.reason = (REASON_NO_GADGETS_COMPLETE if complete
                 else REASON_NO_GADGETS_DEGRADED)
    if output_dir is not None:
        _record_absence_row(output_dir, file_path, function_name, report)
    return ev
