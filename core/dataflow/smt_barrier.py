"""Tier 0 of the trust-witness sound tier: free SMT-backed barrier verdict.

Cost-asymmetric routing. The Tier 2 backend (LLM proposes a CodeQL barrier-
guard, CodeQL adjudicates) is correct but expensive — every attempt burns
LLM tokens and a CodeQL compile+run cycle. SMT over Z3's regex/string
theory is single-digit-ms of CPU and uses no LLM, so it's worth trying
FIRST on any case where the fix adds a charset/regex-shaped validator.
The whoogle archetype is::

    name = request.args.get('name')
    if not re.match(r'^[A-Za-z0-9_+-]+$', name):
        return error()
    open(os.path.join(CONFIG_PATH, name))            # CWE-22 sink

(The historical whoogle charset also admitted '.'; the pathtrav danger
model now includes '.' — '..' segments escape via multi-component
joins the charset model cannot see — so a dot-admitting charset is
DECLINED, not SOUND.)

The Tier 2 LLM keeps failing to express that as a CodeQL barrier-guard;
Z3 dispatches it directly by proving the validator's language and the
sink's danger language don't intersect.

Verdict structure (sound by construction):

    SOUND    -- validator's regex language INTERSECT danger language is
                empty (proven by Z3) AND validator dominates the sink
                (its location appears as a step in the SARIF codeFlow).
                Both checks are mechanical; no LLM involved.

    DECLINED -- intersection is non-empty (validator insufficient, with a
                concrete counterexample input); or validator location is
                not on the codeFlow (no dominance evidence we can prove
                from the SARIF alone). Tier 2 takes over with the full
                LLM+CodeQL machinery.

    NOT_APPLICABLE
             -- no validator-shape pattern recognised in the fix diff,
                or sink_class has no danger model. Tier 2 takes over.

    Z3_UNAVAILABLE
             -- substrate has no z3-solver installed. Tier 2 takes over.
                Substrate gate matches core.smt_solver's degradation
                pattern.

Soundness rests on two pillars: the regex-intersection proof (decidable
+ sound by Z3's automata procedure) and the dominance check (the
validator's source line is on the value's actual dataflow path, as
reported by CodeQL's own engine — we just trust CodeQL's path tracking).
The LLM never asserts safety: extraction is mechanical, adjudication
is mechanical.

The validator extractor is deliberately conservative (Python `re.match`
charset patterns only, for the first cut) — false NOT_APPLICABLE just
falls through to Tier 2, but a wrong extraction could synthesise an
unsound suppression. Widening the extractor is a follow-on once Tier 0
has been validated on the corpus.

Formulation note: `Contains(name, ...)` + `InRe(name, Plus(...))` hangs
the Z3 string solver. The working query is regex-intersection emptiness
(`InRe(name, Intersect(validator_re, danger_re))`), which stays inside
the automata decision procedure. Verified on z3 4.15.4.0 (the substrate
pin) and 4.16.0; all PoC cases finish in 7-9 ms.
"""

from __future__ import annotations

import ast
import builtins
import logging
import re as _re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from core.dataflow import sanitizer_cut_config as _sc_config
from core.paths import confine
from core.smt_solver import z3
from core.smt_solver import z3_available as _z3_available
from core.source import read_text_capped

# --------------------------------------------------------------------------
# Sink danger model.  Each sink_class maps to the set of characters whose
# presence in the value makes the sink exploitable.  Conservative by
# construction: the validator must exclude EVERY listed danger char for the
# verdict to come out SOUND.  Picking these is a soundness call — too narrow
# (missing danger chars) is unsound; too wide just defers more cases to
# Tier 2.
# --------------------------------------------------------------------------
# Per-class derivation rule: a danger set must name every character
# that is load-bearing in ANY interpolation context the sink class can
# put the value in — the charset model cannot see which context a
# given finding actually uses, so the union of the class's contexts is
# the sound set.  Each entry's comment enumerates the contexts it
# covers; a new attack context for a class means new chars here, never
# a caveat elsewhere.
_DANGER_CHARS = {
    # Contexts: POSIX path segments, downstream joins.
    # Path separators are the load-bearing chars for traversal, and '.'
    # builds '..' segments.  Whether a bare '..' (no separator) is
    # dangerous depends on how the value is joined downstream —
    # ``join(base, name, "x")`` escapes via name=".." — which the
    # charset model cannot see, so '.' must be excluded for the
    # verdict to be sound.  Residuals, named: (a) the
    # WINDOWS-only ':' contexts (drive-relative ``C:evil``, NTFS
    # alternate data streams); (b) the decode-after-validate channel
    # ('%': a sink that URL-decodes AFTER the check turns
    # ``%2e%2e%2f`` into ``../``). Both excluded because either char
    # would decline the canonical separator-stripping fix shape
    # (``re.sub(r'[/\\.]+'``) this tier exists to certify, and no
    # routing funnels Windows-path or decode-order findings into this
    # class the way CWE-88 funnelled argv findings into cmdi.
    # Revisit if such a corpus lands.
    "pathtrav": ["/", "\\", "."],
    # Contexts: POSIX shell strings, cmd.exe strings.
    # Shell metachars that introduce command separation, substitution,
    # backgrounding, or redirection.  Newlines included because they
    # terminate a command in most shell contexts; '<' / '>' because
    # redirects need no separator (``foo>x`` clobbers x); '%' and '!'
    # because cmd.exe expands ``%VAR%`` (and ``!VAR!`` under delayed
    # expansion) inside plain strings — the expansion splices variable
    # content, metachars included, with none of the POSIX chars
    # present in the value itself.  This class covers the
    # command-STRING contexts only; findings whose sink is an argv
    # element (CWE-88, the command-LINE-injection rule families) are
    # routed to ``cmdi_argv`` below — string metachars cover none of
    # that channel.
    "cmdi":     [";", "|", "&", "$", "`", "\n", "<", ">", "%", "!"],
    # Contexts: argv elements (option parsing, tokenizer splits,
    # re-join quoting) UNION the command-string contexts.
    # Argument-position command sinks (Runtime.exec / ProcessBuilder /
    # execFile argv elements — CWE-88 and the ``*-command-line-
    # injection`` rule families).  Extends ``cmdi`` (composed below —
    # the superset invariant is structural, not a parallel list to
    # hand-sync):
    #   * '-' — option injection (``-rf``, ``--upload-file x``).  The
    #     charset model cannot see string position, so ANY dash must
    #     count, not just a leading one.
    #   * whitespace (space/tab/CR — LF rides in from cmdi) —
    #     tokenizing sinks split one value into several argv elements
    #     (``Runtime.exec(String)`` tokenizes on whitespace; wrapper
    #     relaunches re-split).
    #   * quote chars — platforms that re-JOIN argv into a command
    #     line and re-parse it (Windows CreateProcess) let a quote
    #     break out of the element.
    #   * the ``cmdi`` string set rides along because the model cannot
    #     see whether the argv element later reaches a shell
    #     (``ProcessBuilder("sh", "-c", x)``, cmd.exe wrappers) —
    #     excluding it only when provably shell-free would need
    #     command-target knowledge a charset has no access to.
    "cmdi_argv": [" ", "\t", "\r", "-", "'", '"'],
    # Contexts: quoted string literals, UNQUOTED (numeric) positions,
    # quoted identifiers, backslash-escaping dialects, comment
    # truncation.
    # SQL quote / comment / statement-terminator chars PLUS the chars
    # that suffice in an UNQUOTED (numeric) context, where no quote is
    # needed to change the query: whitespace and grouping/comparison
    # chars (``1 OR 1``, ``1)--``).  The charset model cannot see the
    # interpolation context, so every context must be covered for the
    # verdict to be sound.  Identifier-quote chars ('`' MySQL, '['/']'
    # T-SQL) cover the quoted-IDENTIFIER context: ``ORDER BY `pin```
    # is a no-quote-chars tautology injection when the value lands in
    # an identifier position.  '\\' covers backslash-escaping dialects
    # (MySQL et al.): a value ENDING in '\\' escapes the closing quote
    # and splices the next literal into the statement.  '#' is the
    # MySQL comment lead — ``1#`` truncates the statement tail from an
    # unquoted position with no other danger char.  Digits-only
    # charsets remain provably safe.
    "sqli":     ["'", '"', ";", "-", " ", "\t", "\n", "\r",
                 "=", "(", ")", "`", "[", "]", "\\", "#"],
    # Contexts: element text, quoted attributes, unquoted attributes,
    # URL-valued attributes (incl. the entity-decoding channel).
    # XSS tag- and attribute-breakers PLUS unquoted-attribute-context
    # injectors: whitespace and '=' add new attributes without any of
    # <>"' (``x onmouseover=...``), '`' breaks IE-legacy attributes.
    # ':' / '(' / ')' cover the URL-valued attribute context (href,
    # src, formaction): ``javascript:alert(1)`` executes from a
    # QUOTED attribute using none of the tag/attribute breakers.
    # '&' covers the ENTITY-DECODING channel inside attribute values:
    # HTML decodes ``&#58;`` etc. before URL parsing, so
    # ``javascript&#58;alert&#40;1&#41;`` spells the same payload from
    # letters/digits plus '&', '#', ';' alone — and every entity needs
    # the '&' lead, so excluding '&' closes the whole channel without
    # also outlawing '#' and ';'.
    "xss":      ["<", ">", '"', "'", " ", "\t", "\n", "=", "`",
                 ":", "(", ")", "&"],
}
# Structural superset: the argv context can never rule out a
# downstream command-string join, so cmdi_argv = cmdi ∪ argv-specific.
_DANGER_CHARS["cmdi_argv"] = (
    _DANGER_CHARS["cmdi"]
    + [c for c in _DANGER_CHARS["cmdi_argv"]
       if c not in _DANGER_CHARS["cmdi"]]
)


def danger_chars_for(sink_class: str):
    """Public read of the per-class danger model (None for unknown
    classes). Finite-set consumers (the collection-membership guard)
    decide per element with the same chars the regex-intersection
    proof uses — the finite-language specialisation of one model."""
    return _DANGER_CHARS.get(sink_class)


# --------------------------------------------------------------------------
# ValidatorSpec: what we extract from the fix diff.
# --------------------------------------------------------------------------
@dataclass
class ValidatorSpec:
    """Mechanically-extracted description of a fix-added sanitizer.

    ``kind`` selects the soundness check in :func:`prove_neutralizes`:

      * ``"charset"`` — whole-string anchored allowlist (`re.match(r'^[...]+$', x)`,
        `re.fullmatch(...)`, language equivalents in JS/TS/Java/Ruby).
        ``charset`` field carries the allowed-char body of ``[...]``.
        Soundness via Z3 regex-intersection emptiness.
      * ``"charset_sub"`` — strip-by-substitution (`x = re.sub('[...]+', '', x)`).
        ``forbidden`` field carries the stripped-char body of ``[...]``.
        Soundness via finite-set inclusion: ``danger_chars ⊆ forbidden_chars``.
    """
    kind: str
    var_name: str                   # the variable the validator constrains
    charset: str = ""               # kind=="charset": whole-string allowed chars
    source_line: str = ""           # the literal diff `+` line for diagnostics
    forbidden: str = ""             # kind=="charset_sub": stripped-out chars


# --------------------------------------------------------------------------
# Tier0Result.
# --------------------------------------------------------------------------
class Tier0Status(str, Enum):
    SOUND = "sound"
    DECLINED = "declined"
    NOT_APPLICABLE = "not_applicable"
    Z3_UNAVAILABLE = "z3_unavailable"


@dataclass
class Tier0Result:
    status: Tier0Status
    reasoning: str
    spec: ValidatorSpec | None = None
    counterexample: str | None = None
    # Pre-formatted spec string suitable to persist in the synth_results
    # ``barrier_query`` column.  Populated only on SOUND; lets the bridge
    # store a self-describing artifact (`smt:charset:[A-Za-z0-9_.+-]@app.py:429`)
    # without callers re-formatting.
    artifact: str | None = None
    extras: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Mechanical validator extractor.
#
# First cut targets the whoogle archetype: a Python `re.match` /
# `re.fullmatch` over a `^[CHARS]+$`-style anchored charset, added in the
# fix.  Anchored on BOTH ends (or `re.fullmatch` regardless of anchors) so
# the whole-string constraint is unambiguous — partial matches don't
# constrain the unmatched suffix and would be unsound to treat as a
# whole-string charset.
#
# Conservatism: only `+` (one-or-more) and `*` quantifiers — `?` (zero-or-
# one) gives a one-char language which doesn't generalise to the
# tainted-value usage we see, and complex patterns (alternation, groups)
# need a richer extractor than this first cut.
# --------------------------------------------------------------------------

# Reusable string-literal capture that allows backslash-escaped chars
# (including escaped quotes) inside the literal body.  Pre-fix the
# bare-class ``[^"']+`` stopped at the first ``\"`` or ``\'`` and
# silently truncated the captured pattern — see Gerapy CVE-2020-7698
# fix whose pattern contains ``\"`` and ``\'`` inside a single-quoted
# Python string.
# The literal body is BOUNDED: with an unbounded body, a hostile line
# that plants the call head inside an unterminated quote makes every
# head occurrence re-scan the rest of the line — quadratic in line
# length. Real validator pattern literals are tens of chars; 1000 is
# generous (a longer literal stops matching and the spec-lift is
# declined, versus an unbounded scan on hostile text).
_STR_LITERAL = (
    r"r?(?:"
    r"'(?:[^'\\]|\\.){1,1000}'"     # 'body' with escaped chars allowed
    r"|"
    r"\"(?:[^\"\\]|\\.){1,1000}\""  # "body" with escaped chars allowed
    r")"
)

# `re.match(pattern, var)` or `re.fullmatch(pattern, var)`.  Captures the
# string literal verbatim (with its quotes/prefix) so the anchor analysis
# can be exact.
#
# The call must CLOSE right after the var (`\s*\)`).  Pre-fix the match
# was an open prefix, so a third ``flags`` argument was silently
# accepted: with ``re.MULTILINE``, ``$`` in ``^[chars]+$`` becomes a
# LINE anchor and the real validator passes any string whose FIRST line
# conforms while smuggling arbitrary danger content after a newline
# (``'abc\n; rm -rf /'``) — yet the Z3 model still treated the pattern
# as a whole-string charset and proved SOUND.  Other flags mis-model
# too (``re.IGNORECASE`` widens the accepted set, ``re.VERBOSE``
# changes the parse), and a method-call suffix (``var.strip()``)
# validates a DIFFERENT value than the one the chain check tracks to
# the sink.  No supported flag is modeled, so any suffix refuses the
# spec-lift (Tier 2 takes the case).  The Ruby extractor refuses
# line-anchored guards for exactly this hazard.
_RE_MATCH_CALL = _re.compile(
    # The called function is captured as a group: classification must
    # read the CALL, never a substring of the whole matched span — the
    # span includes the variable name, and a variable named
    # ``*fullmatch*`` would otherwise lift an unanchored ``re.match``
    # prefix guard to whole-string fullmatch semantics.
    r"re\.(?P<kind>fullmatch|match)\s*\(\s*"
    rf"(?P<pat>{_STR_LITERAL})"
    r"\s*,\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\)"
)

# `^[chars]+$` / `^[chars]*$` inside a captured string literal.  The body
# pattern `(?:[^\]\\]|\\.)+` allows escaped close-brackets (``\]``) and
# other backslash-escaped chars inside the class — without this, real
# fix-author conventions like ``[\!\@\#\$\;\]\[…]+`` would have my
# regex stop at the first ``\]`` and silently truncate the captured
# body, dropping chars from the forbidden set.
_ANCHORED_CHARSET = _re.compile(r"^\^\[((?:[^\]\\]|\\.)+)\][+*]\$$")

# `re.fullmatch` uses fullmatch semantics so anchors are implicit.  Allow
# unanchored `[chars]+` / `[chars]*` only when the call is fullmatch.
_FULLMATCH_CHARSET = _re.compile(r"^\[((?:[^\]\\]|\\.)+)\][+*]$")


# Substitution rebind: ``x = re.sub('[forbidden]+', '', x)``.
# Constraints for soundness:
#   1. LHS and the third argument (the input) are the SAME identifier — so
#      the sanitized value replaces the original (`safe = re.sub(..., '', x)`
#      would leave the unsanitized `x` reachable; we'd need dataflow to
#      know whether `safe` actually reaches the sink, which we don't have).
#   2. Replacement is the EMPTY string — anything else could introduce a
#      different danger char.
#   3. Pattern body is a single `[...]+` or `[...]*` character class
#      (same shape as the allowlist case, just used inversely).
#   4. The call CLOSES right after the input argument.  ``re.sub``
#      takes optional ``count`` and ``flags`` — a trailing
#      ``count=1`` strips only the FIRST occurrence (the "every
#      forbidden char removed" claim breaks), and flags change the
#      pattern semantics.  Same suffix-blindness hazard as
#      _RE_MATCH_CALL above.
# The \b pins the variable to a word start: unanchored, every
# position inside a long identifier-shaped run starts a fresh scan of
# the rest of the line — quadratic on hostile text. A mid-word start
# is never a real assignment target.
_RE_SUB_REBIND = _re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"re\.sub\s*\(\s*"
    rf"(?P<pat>{_STR_LITERAL})"
    r"\s*,\s*"
    r"(?:''|\"\")"                    # empty replacement, strictly
    r"\s*,\s*"
    r"(?P=var)"                       # same identifier on the RHS
    r"\s*\)"
)

# Body of the `[...]` charset inside a re.sub pattern.  Quantifier optional
# — `re.sub` strips even single occurrences, so `[chars]` and `[chars]+`
# are equally sound for our purposes (every match is replaced).
# Body shape `(?:[^\]\\]|\\.)+` supports backslash-escaped chars inside
# the class (e.g. ``\]``, ``\\``) — Gerapy's fix uses
# ``'[\!\@\#\$\;\&\*\~\"\'\{\}\]\[\-\+\%\^]+'`` which contains ``\]``
# and would otherwise truncate at the escaped close-bracket.
_SUB_CHARSET = _re.compile(r"^\[((?:[^\]\\]|\\.)+)\][+*]?$")


# --------------------------------------------------------------------------
# Multi-language guard-and-exit patterns.
#
# Each regex matches the validator call AND its exit-on-fail in ONE diff
# line — so when the extractor fires, we already have the dominance
# evidence baked in (the fix author wrote both on the same line).  No
# language-specific AST parsing required.  This trades some recall
# (multi-line guard-and-exit shapes are missed) for full soundness
# without tree-sitter / external parsers.
#
# For all forms: the captured `chars` group is the body of the `[...]`
# class and is fed into the existing Python charset proof
# (:func:`_prove_charset`); the regex semantics for `[chars]+` are the
# same across all these languages for the literal characters and ranges
# our extractor accepts.
# --------------------------------------------------------------------------

# JS/TS — `if (!/^[chars]+$/.test(<var>)) return|throw …`
# The optional brace gates its own trailing whitespace in all five
# guard shapes ((?:\{\s*)?): the naive ``\{?\s*`` pair put two
# whitespace spans around it — quadratic on a guard-opening line
# ending in a whitespace run.
# The chars-class body is BOUNDED in all five guard shapes: with an
# unbounded ``[^\]]+``, a hostile line that plants the guard head
# inside an unterminated class makes every head occurrence re-scan
# the rest of the line — quadratic. Real allowlist classes are tens
# of chars; 1000 is generous (a longer class declines the spec-lift).
_JS_GUARD_TEST = _re.compile(
    r"if\s*\(\s*!\s*/\^\[(?P<chars>[^\]]{1,1000})\][+*]\$/\s*\.test\s*\(\s*"
    r"(?P<var>[A-Za-z_$][A-Za-z_$0-9]*)\s*\)\s*\)\s*"
    r"(?:\{\s*)?(?:return|throw)\b"
)
# JS/TS — `if (!<var>.match(/^[chars]+$/)) return|throw …`
_JS_GUARD_MATCH = _re.compile(
    r"if\s*\(\s*!\s*(?P<var>[A-Za-z_$][A-Za-z_$0-9]*)\s*\.match\s*\(\s*"
    r"/\^\[(?P<chars>[^\]]{1,1000})\][+*]\$/\s*\)\s*\)\s*"
    r"(?:\{\s*)?(?:return|throw)\b"
)

# Java — `if (!<var>.matches("[chars]+")) return|throw …`
# Java's ``String.matches`` is FULLMATCH by default: the regex is anchored
# even without explicit ``^...$``.  Anchor characters in the source are
# permitted (no-op) but not required.
_JAVA_GUARD = _re.compile(
    r'if\s*\(\s*!\s*(?P<var>[A-Za-z_$][A-Za-z_$0-9]*)\s*\.matches\s*\(\s*'
    r'"\^?\[(?P<chars>[^\]]{1,1000})\][+*]\$?"\s*\)\s*\)\s*'
    r'(?:\{\s*)?(?:return|throw)\b'
)

# Ruby — `return|raise … unless <var> =~ /^[chars]+$/`
# Ruby anchors: ^ and $ are ALWAYS line anchors (Onigmo has no flag
# that changes this; /m only alters `.`), so /^[chars]+$/ passes any
# string containing ONE conforming line — "safe\n../../etc/passwd"
# satisfies the guard while smuggling the danger characters on another
# line. Only \A...\z proves whole-string membership (\Z would readmit
# the trailing-newline hazard). Line-anchored Ruby guards therefore
# never lift; the fix author must use \A\z for the proof to hold.
# The trailing ``(?![a-zA-Z])`` refuses regex-literal FLAGS after the
# closing ``/`` — ``/\A[a-z]+\z/i`` (IGNORECASE) accepts characters
# outside the modeled set; none of Onigmo's flags are modeled, so any
# flagged literal declines the spec-lift (same suffix-blindness
# doctrine as _RE_MATCH_CALL).
# The guard is matched in TWO steps — statement head, then the
# ``unless``/``if`` tail searched from the head's end — instead of a
# single regex with an unbounded statement filler between them: the
# filler made every planted head re-scan the line tail (quadratic,
# cubic through the chars class). Two anchored searches are linear
# and accept the same lines: head anywhere before a whitespace-
# preceded tail is exactly the old ``head (filler?) \s+ tail``.
_RUBY_STMT_HEAD_RE = _re.compile(r"\b(?:return|raise)\b")
_RUBY_GUARD_UNLESS_TAIL = _re.compile(
    r"(?<=\s)unless\s+(?P<var>[a-z_][a-z_0-9]*)\s*=~\s*"
    r"/\\A\[(?P<chars>[^\]]{1,200})\][+*]\\z/(?![a-zA-Z])"
)
# Ruby — `return|raise … if <var> !~ /\A[chars]+\z/`
_RUBY_GUARD_IF_NOT_TAIL = _re.compile(
    r"(?<=\s)if\s+(?P<var>[a-z_][a-z_0-9]*)\s*!~\s*"
    r"/\\A\[(?P<chars>[^\]]{1,200})\][+*]\\z/(?![a-zA-Z])"
)


def _ruby_guard_search(line: str):
    """(tail match, head start) for the Ruby guard shapes, or None."""
    head = _RUBY_STMT_HEAD_RE.search(line)
    if head is None:
        return None
    m = (_RUBY_GUARD_UNLESS_TAIL.search(line, head.end())
         or _RUBY_GUARD_IF_NOT_TAIL.search(line, head.end()))
    if m is None:
        return None
    return m, head.start()


def _string_escape_decode(body: str) -> str:
    r"""Decode the string-LITERAL escape layer of a regex written inside
    a non-raw Python (or Java) string.

    The regex engine never sees the source spelling — ``"\\-"`` in
    source reaches it as ``\-`` (one backslash).  Tokenizing the SOURCE
    spelling misreads the doubled backslash as an escaped-backslash
    atom, so ``[A-Za-z0-9\\-_]`` modeled a ``\``..``_`` RANGE instead
    of a literal ``-`` — the charset model omitted a character the real
    validator accepts, a false SOUND.  Only the quoting-relevant
    escapes are collapsed (``\\``, ``\'``, ``\"``); every other escape
    is left intact so the regex-layer safety gate still sees — and
    rejects — shorthand classes like ``\d`` (and Python itself leaves
    unknown string escapes intact, so this matches its semantics).
    """
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        if body[i] == "\\" and i + 1 < n and body[i + 1] in ("\\", "'", '"'):
            out.append(body[i + 1])
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def _strip_string_literal(raw: str) -> str:
    """Strip Python string-literal quoting from a token captured by
    ``_RE_MATCH_CALL`` and, for non-raw literals, decode the string
    escape layer — the regex body is returned as the regex ENGINE
    receives it, not as it is spelled in source."""
    is_raw = raw.startswith("r")
    raw = raw.removeprefix("r")
    if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
        body = raw[1:-1]
        return body if is_raw else _string_escape_decode(body)
    return raw


# Any `\X` where X is alphabetic — covers regex shorthand classes
# (``\d \w \s \D \W \S``), word boundary (``\b``), and control-char
# escapes (``\n \t ...``).  Conservative blanket reject because:
#
#   * ``\D``, ``\W``, ``\S`` are the NEGATIVE shorthand classes; they
#     INCLUDE typical danger chars (``/``, ``\\``, shell metachars).
#     If our literal-char extractor silently reads ``\W`` as chars
#     ``{\\, W}``, the soundness check returns SOUND for a validator
#     that actually accepts the danger char — a false positive
#     suppression.  This is unsound.
#   * ``\d`` / ``\w`` / ``\s`` are the POSITIVE counterparts; under
#     the same literal-misreading they happen to be conservative
#     (under-approximate the language, so the verdict goes to
#     DECLINED) but the misreading itself is wrong and would compound
#     with other patterns.
#
# Rejecting any alphabetic backslash escape sidesteps the whole class
# of bugs.  Callers that want to model ``[\\d]`` properly will need a
# richer extractor — Tier 2 takes those cases for now.
#
# Digits are rejected for the same reason: inside a char class Python
# reads ``\\1`` as an OCTAL escape (chr(1)), which our literal-char
# extractor would misread as the character ``'1'`` — a modeled
# language disjoint from the real one.
_ALPHA_BACKSLASH_ESCAPE = _re.compile(r"\\[A-Za-z0-9]")


def _charset_body_is_safe(body: str) -> bool:
    r"""Reject character-class bodies our literal-char extractor would
    misread:

      * **Negation** (``[^chars]``) — inverts the language and would
        need entirely different proof semantics.  Currently silently
        misread as a literal ``^`` plus the chars.
      * **Regex shorthand classes** (``\d``, ``\W``, ...) — see
        ``_ALPHA_BACKSLASH_ESCAPE`` above.
    """
    if not body or body.startswith("^"):
        return False
    return _ALPHA_BACKSLASH_ESCAPE.search(body) is None


def _code_view_line(line: str, language: str) -> str:
    """Comment/string-blanked view of ONE line (no file context).

    Uses the shared core.audit.source_view scanner (lazy leaf import —
    source_view depends only on ``re``, so the downward-only import
    doctrine is not violated at module import time). Single-line
    scanning cannot see enclosing multi-line constructs; callers that
    hold the whole file pass a full-file view line instead.
    """
    from core.audit.source_view import sanitized_view

    return sanitized_view(line, language=language)


def code_view_lines(source_text: str, language: str) -> list[str]:
    """Comment/string-blanked view of a whole file, split into lines
    (newlines are preserved by the scanner, so indices map 1:1)."""
    from core.audit.source_view import sanitized_view

    return split_source_lines(
        sanitized_view(source_text, language=language),
    )



def split_source_lines(text: str) -> list[str]:
    r"""Split target-controlled text into lines by ``\n`` ONLY.

    Every producer whose line numbers this stack consumes (CodeQL
    SARIF locations, git diffs, SARIF snippets) counts lines by
    ``\n``; ``str.splitlines()`` additionally breaks on U+2028/U+2029,
    U+000B, U+000C, U+0085 — one exotic terminator planted early in a
    target file shifts every line-keyed judgment after it (observed
    direction: refusal — a real guard becomes unfindable; the
    suppression direction is blocked by the var-reach and dominance
    gates, which shift consistently with the sink text).  One shared
    helper so producer and consumer line arithmetic cannot diverge
    again; ``\r`` tails from CRLF files survive on the line and are
    tolerated by the strip()/regex matching at every consumer.

    A trailing newline yields one final empty element ("phantom
    line"); consumers bounds-check indices and skip blank lines, so
    it is inert.
    """
    return text.split("\n")


def _span_is_code(view: str | None, start: int) -> bool:
    """True when a regex match starting at ``start`` is anchored in
    executable code: the view (comments and string interiors blanked
    to spaces) still carries a non-space character there.  Every
    extractor regex starts its match on a non-space char, so a space
    in the view means the span is prose — a comment or string decoy
    must never mint a validator.
    """
    if view is None:
        return True
    return start < len(view) and view[start] != " "


def _try_charset_validator(
    line: str, view: str | None = None,
) -> ValidatorSpec | None:
    """Match the whole-string `re.match`/`re.fullmatch` over `^[chars]+$`
    pattern.  Returns ``None`` on no match so the caller can try other
    extractors."""
    m = _RE_MATCH_CALL.search(line)
    if not m or not _span_is_code(view, m.start()):
        return None
    call_kind = m.group("kind")
    pattern = _strip_string_literal(m.group("pat"))
    var_name = m.group("var")
    cs = _ANCHORED_CHARSET.match(pattern)
    if cs is None and call_kind == "fullmatch":
        cs = _FULLMATCH_CHARSET.match(pattern)
    if cs is None or not _charset_body_is_safe(cs.group(1)):
        return None
    return ValidatorSpec(
        kind="charset", var_name=var_name, charset=cs.group(1),
        source_line=line.strip(),
    )


def _try_charset_sub_validator(
    line: str, view: str | None = None,
) -> ValidatorSpec | None:
    """Match the ``x = re.sub('[forbidden]+', '', x)`` rebind pattern.
    Returns ``None`` on no match."""
    m = _RE_SUB_REBIND.search(line)
    if not m or not _span_is_code(view, m.start()):
        return None
    pattern = _strip_string_literal(m.group("pat"))
    cs = _SUB_CHARSET.match(pattern)
    if not cs or not _charset_body_is_safe(cs.group(1)):
        return None
    # Store the class body with REGEX escapes intact (the string-literal
    # layer was already decoded by _strip_string_literal for non-raw
    # literals): _expand_charset_body is the single REGEX-escape
    # interpreter.  Unescaping the regex layer here and expanding later
    # double-processes the body — a stored ``\\`` swallows the following
    # char (``[/\\.]`` lost the backslash from the forbidden set).
    return ValidatorSpec(
        kind="charset_sub", var_name=m.group("var"),
        forbidden=cs.group(1), source_line=line.strip(),
    )


def _try_jsts_validator(
    line: str, view: str | None = None,
) -> ValidatorSpec | None:
    """JS / TS guard-and-exit shapes.  Single regex match implies both
    the validator and its exit-on-fail are on the line — dominance is
    established by the diff itself."""
    m = _JS_GUARD_TEST.search(line) or _JS_GUARD_MATCH.search(line)
    if m is None or not _span_is_code(view, m.start()):
        return None
    if not _charset_body_is_safe(m.group("chars")):
        return None
    return ValidatorSpec(
        kind="charset", var_name=m.group("var"), charset=m.group("chars"),
        source_line=line.strip(),
    )


def _try_java_validator(
    line: str, view: str | None = None,
) -> ValidatorSpec | None:
    """Java ``String.matches`` guard-and-exit shape.

    The captured class body is the SOURCE spelling of a Java string
    literal (Java has no raw strings), so the string-escape layer is
    decoded before the safety gate and the charset tokenizer — every
    escaped-hyphen Java charset (``"[A-Za-z0-9\\\\-_]+"``) otherwise
    tokenizes as escaped-backslash + range and drops the literal ``-``
    from the model.
    """
    m = _JAVA_GUARD.search(line)
    if m is None or not _span_is_code(view, m.start()):
        return None
    chars = _string_escape_decode(m.group("chars"))
    if not _charset_body_is_safe(chars):
        return None
    return ValidatorSpec(
        kind="charset", var_name=m.group("var"), charset=chars,
        source_line=line.strip(),
    )


def _try_ruby_validator(
    line: str, view: str | None = None,
) -> ValidatorSpec | None:
    r"""Ruby ``unless x =~ /…/`` and ``if x !~ /…/`` guard shapes.

    Only ``\A[chars]+\z``-anchored patterns lift — Ruby ``^``/``$``
    are line anchors, so a line-anchored guard does not bound the whole
    string (see the anchor note on the guard regexes above).
    """
    found = _ruby_guard_search(line)
    if found is None:
        return None
    m, head_start = found
    if not _span_is_code(view, head_start):
        return None
    if not _charset_body_is_safe(m.group("chars")):
        return None
    return ValidatorSpec(
        kind="charset", var_name=m.group("var"), charset=m.group("chars"),
        source_line=line.strip(),
    )


# Per-language extractor table.  Each entry is a list of single-line
# pattern-tryers, evaluated in order; the first match wins.  Python is
# special-cased: its extractors don't include the exit-on-fail
# pattern (the validator and its `if`-body are typically on separate
# lines), so Python uses the AST-based dominance check downstream.
_LANG_EXTRACTORS = {
    "python":     [_try_charset_validator, _try_charset_sub_validator],
    "javascript": [_try_jsts_validator],
    "typescript": [_try_jsts_validator],
    "java":       [_try_java_validator],
    "ruby":       [_try_ruby_validator],
}


def extractor_languages() -> frozenset:
    """Languages the mechanical validator extractor supports."""
    return frozenset(_LANG_EXTRACTORS)


def extract_validator_from_line(
    line: str, language: str = "python", *, code_view: str | None = None,
) -> ValidatorSpec | None:
    """Run the per-``language`` extractor table on ONE source line.

    Shared by the fix-diff scanner below and the live-finding
    injection prescreen (core.dataflow.injection_prescreen), which
    lifts validators from dataflow-path step lines instead of diff
    ``+`` lines. First matching extractor wins; None when the line
    carries no recognised validator shape.

    Every match is anchored against a comment/string-blanked view of
    the line: a validator that exists only inside a comment or string
    literal is prose, and lifting it would let the scanned repo
    neutralise its own live flows (mint refutations) with a planted
    decoy.  ``code_view`` is the view line when the caller holds the
    whole file (needed to see enclosing multi-line comments/strings);
    by default the line itself is scanned in isolation.
    """
    extractors = _LANG_EXTRACTORS.get(language)
    if not extractors:
        return None
    if code_view is None:
        code_view = _code_view_line(line, language)
    for try_fn in extractors:
        spec = try_fn(line, code_view)
        if spec is not None:
            return spec
    return None


def extract_validator(fix_diff: str, language: str = "python") -> ValidatorSpec | None:
    """Scan the fix diff for a recognised mechanical validator pattern.

    Iterates every line starting with ``+`` (excluding the ``+++`` file
    header).  Dispatches to the per-``language`` extractor table; first
    match wins.  None when no recognised pattern is present — Tier 0
    then falls through to Tier 2.

    Non-Python languages: each extractor matches the full
    ``if (!validator) exit`` shape on ONE line, so dominance is
    established by the diff itself (the fix author bound the guard and
    the exit-on-fail together).  Multi-line variants are deliberately
    missed for soundness — partial matches could falsely claim
    dominance where the exit isn't actually reached.
    """
    if not fix_diff:
        return None
    if language not in _LANG_EXTRACTORS:
        return None
    for raw in split_source_lines(fix_diff):
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        spec = extract_validator_from_line(raw[1:], language)
        if spec is not None:
            return spec
    return None


# --------------------------------------------------------------------------
# Dominance check.
#
# The validator must dominate the sink — every flow that reaches the sink
# must have passed through the validator.  Otherwise neutralising the
# validator's language doesn't suppress the real flow.
#
# Pre-fix design tried the SARIF codeFlow ("if the validator's line is a
# step on the value's tainted path, dominance is established").  That
# turned out to be too strict: CodeQL's codeFlow tracks
# value-transformation nodes (where the tainted value moves), not
# control-flow guards (where the value is examined).  A ``re.match``
# ``if``-check inspects the value without transforming it, so the
# validator line ISN'T on the codeFlow even when it provably gates the
# sink.  Net effect: zero Tier 0 hits across the 87-FP-candidate corpus,
# even on cases (e.g. CVE-2024-22204 whoogle) whose validator was the
# exact shape Tier 0 was built for.
#
# Replacement: source-order + same-function + exit-on-fail AST check.
# Sound for the dominant fix-added-charset-validator pattern:
#
#   if not <validator_call>:
#       return <error>
#   # ... value continues to the sink
#
# AND the symmetric:
#
#   if <validator_call>:
#       # continue
#   else:
#       return <error>
#
# Anything more exotic falls through to Tier 2; soundness is preserved
# because Tier 0 declines, it doesn't fabricate a suppression.
# --------------------------------------------------------------------------

def _is_sys_exit_call(call: ast.Call) -> bool:
    """``sys.exit(...)`` / ``exit(...)`` / ``quit(...)`` — bare or via
    ``sys.``.  Treated as a function-exiting control transfer for the
    dominance check (matches how operators emit hard-stop guards)."""
    f = call.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        return f.value.id == "sys" and f.attr == "exit"
    if isinstance(f, ast.Name):
        return f.id in {"exit", "quit"}
    return False


def _block_always_exits(body: list) -> bool:
    """A block always exits if it contains a top-level ``Return`` /
    ``Raise`` / ``sys.exit(...)``.

    Conservative — does NOT reason about nested control flow (if every
    branch of a nested ``if`` returns, the block exits too, but we don't
    detect that).  False negatives just mean Tier 0 declines on
    unusual-but-sound guards; soundness is preserved.

    Empty / missing body -> False (no statements at all means no exit,
    e.g. ``if X: pass`` doesn't gate anything).
    """
    if not body:
        return False
    for stmt in body:
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return True
        if (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
                and _is_sys_exit_call(stmt.value)):
            return True
    return False


def _function_containing(tree: ast.AST, line: int) -> ast.AST | None:
    """Smallest-range FunctionDef / AsyncFunctionDef containing ``line``,
    or None.  "Smallest range" so nested functions resolve to the inner
    one, matching the semantics of "same function" we want for dominance."""
    best: ast.AST | None = None
    best_size: int | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            if start <= line <= end:
                size = end - start
                if best_size is None or size < best_size:
                    best = node
                    best_size = size
    return best


def _walk_same_scope(root: ast.AST):
    """Yield ``root``'s descendants without descending into nested
    function / lambda / class scopes.  The nested-scope NODE itself is
    yielded (its ``def`` line is a binding in the enclosing scope) but
    its body is not — names assigned there belong to the nested scope.
    """
    stack = list(ast.iter_child_nodes(root))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _block_uses_raise(body: list) -> bool:
    """True iff the block exits via ``raise`` specifically (not Return /
    sys.exit).  Used to detect Bug 19: a ``raise`` exit inside a
    ``try/except`` can be CAUGHT and let the unvalidated value reach
    the sink — soundness requires checking the surrounding context."""
    if not body:
        return False
    return any(isinstance(stmt, ast.Raise) for stmt in body)


# Plain and exception-group try statements — ``except*`` handlers
# swallow (and run conditionally) exactly like plain ``except`` for
# dominance purposes. ``ast.TryStar`` is 3.11+; on older runtimes
# ``except*`` source is a SyntaxError and the parse-failure path
# already declines.
_TRY_NODES: tuple[type, ...] = (
    (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)
)

# ``type X = ...`` alias statements are 3.12+; the construct is a
# SyntaxError on older runtimes, so ``None`` there is exhaustive
# (same guard shape as ``_TRY_NODES``).
_TYPE_ALIAS_NODE: type | None = getattr(ast, "TypeAlias", None)


def _raised_exception_names(body: list) -> list[str | None]:
    """Names of the exception classes the block's top-level ``raise``
    statements throw. ``None`` entries mark statically-unresolvable
    raises (dotted classes, re-raises, computed expressions) — the
    caller must treat those as catchable-by-anything."""
    names: list[str | None] = []
    for stmt in body:
        if not isinstance(stmt, ast.Raise):
            continue
        exc = stmt.exc
        if isinstance(exc, ast.Call):
            exc = exc.func
        names.append(exc.id if isinstance(exc, ast.Name) else None)
    return names


def _handler_type_names(t: ast.AST | None) -> list[str | None]:
    """Exception-class names an ``except`` clause declares. ``None``
    entries mark unresolvable elements (dotted / computed)."""
    elts = t.elts if isinstance(t, ast.Tuple) else [t]
    return [e.id if isinstance(e, ast.Name) else None for e in elts]


def _handler_name_may_catch(handler: str | None, raised: str | None) -> bool:
    """Whether an ``except <handler>:`` clause may catch a ``raise
    <raised>`` — resolvable statically only when BOTH names are real
    builtin exception classes (then Python's own hierarchy answers);
    every unresolvable pairing errs toward "may catch" (refusing a
    dominance claim costs yield, never soundness). Builtin-name
    shadowing by the scanned repo can only ADD catches this misses in
    the certify direction for provably-disjoint builtin pairs — the
    same static-name assumption the pre-existing disjoint-class
    behavior already encodes."""
    if handler is None or raised is None:
        return True
    if handler in {"Exception", "BaseException"}:
        return True
    handler_cls = getattr(builtins, handler, None)
    raised_cls = getattr(builtins, raised, None)
    if (isinstance(handler_cls, type)
            and issubclass(handler_cls, BaseException)
            and isinstance(raised_cls, type)
            and issubclass(raised_cls, BaseException)):
        return issubclass(raised_cls, handler_cls)
    return True


def _line_in_try_body_with_catching_handler(
    tree: ast.AST, validator_line: int,
    raised_names: list[str | None],
) -> bool:
    """True iff ``validator_line`` falls inside the ``try.body`` of a
    ``Try`` with a handler that may SWALLOW the failure branch's raise
    — the exception is caught and control falls through to the code
    after the ``try``, so the unvalidated value reaches the sink.

    Triggers:

    * ``except:`` (bare), ``except Exception:``, ``except
      BaseException:`` — catch everything, always trigger (even an
      exiting body stays conservative here, the pre-existing rule).
    * A TYPED handler that may catch one of ``raised_names`` (builtin
      hierarchy when both names resolve to real builtin exception
      classes; assumed catching otherwise) AND whose body falls
      through (does not provably exit) — ``except ValueError: pass``
      around a ``raise ValueError`` guard swallows exactly like a bare
      except. A catching handler that re-raises / returns keeps the
      failure path exiting and does NOT trigger.

    False positives here only cost yield — they don't compromise
    soundness.
    """
    for node in ast.walk(tree):
        if not isinstance(node, _TRY_NODES):
            continue
        # validator_line must be inside try.body specifically (NOT inside
        # an except handler or finally — those are different control paths)
        in_try_body = False
        for stmt in node.body:
            stmt_end = getattr(stmt, "end_lineno", None) or stmt.lineno
            if stmt.lineno <= validator_line <= stmt_end:
                in_try_body = True
                break
        if not in_try_body:
            continue
        for h in node.handlers:
            names = _handler_type_names(h.type) if h.type is not None else []
            # bare except: -> catches everything (UNSOUND if validator raises)
            if h.type is None:
                return True
            # except Exception: / except BaseException: (incl. in tuples)
            if any(n in {"Exception", "BaseException"} for n in names):
                return True
            # Typed handler: a swallow needs BOTH a catch and a
            # fall-through — a re-raising / returning handler keeps
            # the failure path exiting.
            if _block_always_exits(h.body):
                continue
            if any(
                _handler_name_may_catch(hn, rn)
                for hn in names
                for rn in (raised_names or [None])
            ):
                return True
    return False


def _validator_block_exits_on_failure(
    tree: ast.AST, validator_line: int,
) -> bool:
    """Find the :class:`ast.If` whose ``lineno`` equals ``validator_line``
    and confirm the FAILURE branch exits.

      * ``if not <call>: BODY`` (UnaryOp/Not) — BODY is the failure branch.
      * ``if <call>: ... else: ELSE`` — ELSE is the failure branch.

    Additional soundness check (Bug 19): if the failure branch exits via
    ``raise`` and the validator's ``If`` is inside a ``try.body`` whose
    handler might catch the exception, dominance does NOT hold (the
    raise is caught and the unvalidated value reaches the sink).
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and node.lineno == validator_line:
            test = node.test
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                failure_body = node.body
            else:
                failure_body = node.orelse
            if not _block_always_exits(failure_body):
                return False
            # If the exit is `raise` and we're inside a try with a
            # handler that may swallow it, the raise gets caught —
            # decline.
            return not (
                _block_uses_raise(failure_body)
                and _line_in_try_body_with_catching_handler(
                    tree, validator_line,
                    _raised_exception_names(failure_body))
            )
    return False


def _binds_conditional_value(tree: ast.AST, line: int) -> bool:
    """True when an assignment on ``line`` binds a CONDITIONAL value —
    ``x = clean(x) if cond else x`` (IfExp) or ``x = cond and clean(x)
    or x`` (short-circuit BoolOp). The statement itself executes
    unconditionally, so the statement-level branch walk cannot see it,
    but the SANITIZED value is bound only on some paths — the
    fall-through arm sends the raw value into the sink. Conservative:
    any IfExp / BoolOp anywhere in the assigned value refuses (an
    exotic-but-sound conditional value costs yield, never soundness).
    Walrus bindings (``log(safe := clean(x) if cond else x)``) are the
    same shape spelled as an expression — the transform gate accepts
    NamedExpr as a binding form, so this walk must see it too or the
    conditional value slips through inside a call argument."""
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr),
        ):
            continue
        if node.lineno != line or node.value is None:
            continue
        if any(isinstance(sub, (ast.IfExp, ast.BoolOp))
               for sub in ast.walk(node.value)):
            return True
    return False


def _validator_in_branch(
    tree: ast.AST, validator_line: int, sink_line: int,
    *, exclude_guard_at: int | None = None,
) -> bool:
    """Return True if ``validator_line`` is inside a conditional branch
    of the function containing the sink — meaning the validator does NOT
    dominate the sink unconditionally.  An assignment whose VALUE is
    conditional (ternary / short-circuit — see
    :func:`_binds_conditional_value`) counts as branch-wrapped too: the
    sanitized binding happens only on some paths even though the
    statement itself is unconditional.

    ``exclude_guard_at`` names the line of the validator's OWN ``if``
    statement for guard-shaped validators (``kind="charset"``): a
    single-line guard (``if not re.match(...): return``) has its body
    on the guard's own line, and without the exclusion the guard would
    read as wrapped by itself. Substitution / safe-call validators are
    plain statements — callers leave the exclusion unset.
    """
    fn = _function_containing(tree, sink_line)
    body = fn.body if fn else tree.body

    def _in_branch(stmts, target) -> bool:
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                if stmt.lineno == exclude_guard_at:
                    continue
                if _spans(stmt.body, target) or _spans(stmt.orelse, target):
                    return True
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                # A loop body may run ZERO times, and the ``else:``
                # clause is skipped whenever the loop ``break``s —
                # both are conditional placements for a validator
                # (async-for included: aiohttp-style retry wrappers
                # are exactly the loop-wrapped-sanitizer shape).
                # Conservative refuse — the sound tier's bar is zero
                # false suppression.
                if _spans(stmt.body, target) or _spans(stmt.orelse, target):
                    return True
            elif isinstance(stmt, _TRY_NODES):
                for handler in stmt.handlers:
                    if _spans(handler.body, target):
                        return True
                # A conditional nested inside the try body / else /
                # finally still wraps the validator — descend.
                if (_in_branch(stmt.body, target)
                        or _in_branch(stmt.orelse, target)
                        or _in_branch(stmt.finalbody, target)):
                    return True
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                # ``with`` executes unconditionally, but its body can
                # contain conditionals — descend rather than skip.
                if _in_branch(stmt.body, target):
                    return True
            elif isinstance(stmt, ast.Match):
                # Every case arm is conditional.
                if any(_spans(case.body, target) for case in stmt.cases):
                    return True
        return False

    def _spans(stmts, target) -> bool:
        for stmt in stmts:
            if hasattr(stmt, "lineno") and hasattr(stmt, "end_lineno"):
                if stmt.lineno <= target <= (stmt.end_lineno or stmt.lineno):
                    return True
            elif hasattr(stmt, "lineno") and stmt.lineno == target:
                return True
        return False

    if _binds_conditional_value(tree, validator_line):
        return True
    return _in_branch(body, validator_line)


# Block-opening keywords that make a brace block CONDITIONAL (or
# repeated) — a safe-call inside one does not dominate a sink outside
# it.  ``else``/``catch``/``case``/``default`` are conditional arms;
# loops are included because a loop body may execute zero times.
_COND_BLOCK_KEYWORD = _re.compile(
    r"\b(?:if|else|for|while|switch|case|default|catch|do)\b"
)


def _tracker_brace_view(line: str) -> str:
    """Second-stage blanking for the BRACE COUNTING only.

    Applied on top of the whole-file sanitized view, and consumed
    exclusively by the brace-stack scan — every KEYWORD read (the
    validator-line arms, the preceding-line dangling scan, and the
    ``prev_tail`` conditional classifier inside the loop) stays on
    the softer sanitized view, where a phantom keyword inside a
    visible regex can only mark a real block conditional (a refusal),
    never un-mark one.

    * ``/…/`` spans blank GREEDILY, ignoring the sanitizer's
      regex-vs-division position heuristic.  That heuristic errs
      toward leaving code visible (right for its original absence/
      presence consumers), which is ANTI-conservative here: a
      statement-position regex literal (``if (a) /{/.test(x)``, or
      after ``return`` / ``]``) stays visible and feeds its interior
      braces to the tracker as phantoms — and a balanced phantom PAIR
      (``/{/`` inside the wrap, ``/}/`` after it) defeats the
      EOF-unbalance refusal.  Over-blanking is brace-conservative in
      both directions: an UNBALANCED swallow of a real brace leaves
      the file unbalanced (underflow or EOF-leftover → True), and a
      BALANCED swallow needs the block's open and close inside one
      same-line span, where the validator-line keyword arms already
      refuse.  Keyword classification is untouched by construction —
      it never reads this view (a greedy span between two genuine
      divisions can swallow an ``if``, which is exactly why the
      classifier must not look here).  Character classes (``[/{]``)
      and escapes do not close a span; an unclosed ``/`` blanks
      nothing (division tails carry no braces the source didn't).
    * Annex-B HTML comment channels — ``<!--`` to end of line, and a
      line whose code starts with ``-->`` — blank the same way: dead
      to execution, visible to the tracker, and pairable into the
      same balanced-phantom shape.

    Length-preserving (blanked spans become spaces), so the tracker
    view stays per-character aligned with the sanitized view it was
    derived from.
    """
    stripped = line.lstrip()
    if stripped.startswith("-->"):
        return " " * len(line)
    cut = line.find("<!--")
    if cut != -1:
        line = line[:cut] + " " * (len(line) - cut)
    if "/" not in line:
        return line
    out = list(line)
    n = len(line)
    i = 0
    while i < n:
        if line[i] != "/":
            i += 1
            continue
        j = i + 1
        in_class = False
        closed = False
        while j < n:
            ch = line[j]
            if ch == "\\":
                j += 2
                continue
            if in_class:
                if ch == "]":
                    in_class = False
            elif ch == "[":
                in_class = True
            elif ch == "/":
                closed = True
                break
            j += 1
        if not closed:
            break
        for k in range(i, j + 1):
            out[k] = " "
        i = j + 1
    return "".join(out)
def _lexical_validator_in_branch(
    source_text: str, validator_line: int, sink_line: int,
    *, guard_shaped: bool = False, language: str = "javascript",
) -> bool:
    """Brace-language (JS/TS/Java/C/C++) analogue of
    :func:`_validator_in_branch`: True when the validator line is
    conditionally executed relative to the sink.

    Tracks a stack of ``{`` blocks tagged conditional by the keyword
    preceding the brace.  The validator is branch-wrapped when a
    conditional block open at the validator line has closed again
    before the sink line (``if (opts.clean) { x = escape(x); }
    send(x)``) — sharing the block is fine (whenever the sink runs the
    validator ran).  A conditional keyword on the validator line
    itself (braceless ``if (c) x = escape(x);``) also flags, as does a
    DANGLING guard — ``if (c)`` alone on the nearest preceding
    non-blank line with no ``{``, whose guarded statement is the
    validator line (legal Java/JS braceless form the brace tracker
    never sees).  Residual, not modeled: ternaries, and dangling
    guards whose condition spans multiple lines (the keyword is then
    not on the nearest preceding line).  CONSERVATIVE on tracker
    confusion (unbalanced braces after scrubbing) in BOTH directions:
    a ``}`` with no open block (underflow) returns True immediately,
    and a block still open when the file ends (excess ``{``) returns
    True as well — "not proven unconditional" must never read as
    dominance.  The excess direction matters: a phantom ``{`` the
    scrubber failed to blank pushes an extra block, the real ``}``
    closing the enclosing conditional pops the phantom instead, and
    the conditional reads "still open at the sink" — certifying
    dominance for a branch-wrapped validator.

    Scrubbing uses the whole-file comment/string-blanked view
    (:func:`code_view_lines`, ``language``-aware) — the same
    chokepoint the validator-line anchors use.  A per-line scrubber
    cannot see enclosing multi-line constructs, so one ``{`` planted
    inside a multi-line block comment or template literal leaked into
    the stack (the phantom above).

    ``guard_shaped=True`` is for ``kind="charset"`` guard validators
    whose exit-on-fail lives ON the matched line (``if
    (!x.matches("[a-z]+")) return;``): the guard line legitimately
    carries ONE conditional keyword and legitimately opens its own
    conditional block, so the single-keyword-on-line check is skipped
    and blocks OPENED on the validator line itself are exempt from
    the closed-before-sink test.  The preceding-line dangling scan
    still applies — the guard's own ``if`` is on its line, so a
    conditional keyword on the nearest preceding non-blank line is
    always enclosing.  A SECOND conditional
    keyword on the guard line is an enclosing conditional collapsed
    onto it (``if (strict) { if (!ok) { return; } }``) and refuses —
    a block that both opens and closes on the guard line is invisible
    to the brace snapshots below.  Enclosing conditional blocks
    (opened on earlier lines) still flag, including ones whose ``}``
    lands on the guard line: the branch-wrap snapshot is taken at the
    START of the validator line so a same-line close cannot hide them.
    """
    lines = split_source_lines(source_text)
    if not (0 < validator_line <= len(lines) and 0 < sink_line <= len(lines)):
        return True
    view = code_view_lines(source_text, language)
    if len(view) < len(lines):
        # Defensive: the scanner preserves newlines, so the views map
        # 1:1; pad rather than index past the end if that ever drifts.
        view = view + [""] * (len(lines) - len(view))
    scrubbed_validator = view[validator_line - 1]
    if not guard_shaped:
        if _COND_BLOCK_KEYWORD.search(scrubbed_validator):
            return True
    elif len(_COND_BLOCK_KEYWORD.findall(scrubbed_validator)) >= 2:
        # The guard accounts for exactly one conditional keyword on
        # its own line; any further one wraps the guard conditionally.
        return True
    # Dangling braceless conditional on the nearest preceding
    # non-blank scrubbed line (a conditional keyword opening no block
    # there): for a plain validator, the validator line IS its
    # guarded statement; for guard_shaped, the guard's own ``if``
    # lives on the validator line, so a preceding-line keyword is
    # always an ENCLOSING conditional — braceless (`if (strict)` then
    # the guard line), or with its `{` landing on the guard line,
    # where the open-line exemption below would otherwise wave it
    # through.
    for prev_idx in range(validator_line - 2, -1, -1):
        prev = view[prev_idx]
        if not prev.strip():
            continue
        if _COND_BLOCK_KEYWORD.search(prev) and "{" not in prev:
            return True
        break
    # Each block gets a unique id so "still open at the sink" means the
    # SAME block, not merely the same nesting depth.  The scan runs to
    # the END of the file (not just the sink line): leftover open
    # blocks at EOF mean the tracker mis-lexed something — every
    # judgment it made is then suspect, including the sink snapshot.
    stack: list[tuple[int, bool, int]] = []  # (block id, conditional?, open line)
    at_validator: list[tuple[int, bool, int]] | None = None
    opened_on_validator: list[tuple[int, bool, int]] = []
    open_at_sink: set[int] | None = None
    next_id = 0
    prev_tail = ""                       # SOFT-view text since the last brace
    # Braces come from the hard-blanked tracker view; prev_tail (the
    # conditional classifier) accumulates the per-char-aligned SOFT
    # view — a greedy division span must never swallow a real keyword
    # (that would classify a real wrap non-conditional), and a phantom
    # keyword from the soft view can only add a refusal.
    for idx, (soft, text) in enumerate(
            zip(view, map(_tracker_brace_view, view)), start=1):
        if idx == validator_line:
            # Snapshot at line START: a block whose `}` lands on the
            # validator line itself must still count as wrapping it.
            at_validator = list(stack)
        if "{" not in text and "}" not in text:
            prev_tail += soft
        else:
            for pos, ch in enumerate(text):
                if ch == "{":
                    conditional = bool(_COND_BLOCK_KEYWORD.search(prev_tail))
                    entry = (next_id, conditional, idx)
                    stack.append(entry)
                    if idx == validator_line:
                        opened_on_validator.append(entry)
                    next_id += 1
                    prev_tail = ""
                elif ch == "}":
                    if not stack:
                        return True      # tracker confused — conservative
                    stack.pop()
                    prev_tail = ""
                else:
                    prev_tail += soft[pos]
        if idx == sink_line:
            # Snapshot at line END (matches the historical semantics of
            # stopping the scan after the sink line).
            open_at_sink = {block_id for block_id, _, _ in stack}
    if stack:
        # Excess-'{' direction: a block never closed by EOF.  The
        # phantom-brace shape (a '{' the scrubber failed to blank)
        # lands here when its stray open survives to EOF; a stray open
        # CONSUMED by a later real '}' shifts every close after it, so
        # the file still ends unbalanced unless the source itself also
        # carries a matching stray '}' — at which point the underflow
        # arm above fires first on that close.
        return True
    if at_validator is None or open_at_sink is None:
        return True
    # Every conditional block wrapping the validator — open at its
    # line start, or opened on the line itself — must STILL be open
    # at the sink; one that closed in between means the sink runs on
    # paths that skipped the validator.
    return any(
        conditional and block_id not in open_at_sink
        for block_id, conditional, open_line in at_validator + opened_on_validator
        if not (guard_shaped and open_line == validator_line)
    )


def find_validator_line(
    source_text: str, spec: ValidatorSpec, *, language: str = "python",
    sink_line: int | None = None,
) -> int | None:
    """Locate the validator's 1-based line number in the post-fix source
    text.  Matches by the stripped line-text the extractor saved on the
    spec.

    Occurrence selection mirrors Tier 1B's
    ``_find_best_validator_line``: with ``sink_line`` given, prefer
    CODE occurrences strictly before the sink — for Python, among
    those in the SAME function as the sink — picking the closest
    (largest line < sink_line).  First-match-wins (the historical
    rule, kept for callers without a sink) could bind an occurrence
    in an unrelated function and fail the dominance check even when a
    later occurrence is the actual sanitizer — a pure yield loss, the
    verdict then lands NOT_APPLICABLE rather than SOUND.  When no
    occurrence precedes the sink, the first occurrence is returned
    and the dominance check downstream refuses it.

    Anchored against the comment/string-blanked view of the file: a
    line whose validator text lives inside a comment or a multi-line
    string is prose — matching it would bind the dominance check to a
    decoy location (a planted earlier copy inside a docstring would
    otherwise shadow the real validator).

    Pre-fix this read the file from disk; the refactor pulls the I/O out
    to :func:`try_tier0` so the source text can be reused by the
    dominance check without a second read.
    """
    needle = spec.source_line
    lines = split_source_lines(source_text)
    view = code_view_lines(source_text, language)
    candidates: list[int] = []
    for idx, ln in enumerate(lines):
        if ln.strip() != needle:
            continue
        view_ln = view[idx] if idx < len(view) else None
        if extract_validator_from_line(
            ln, language, code_view=view_ln,
        ) is None:
            continue
        candidates.append(idx + 1)
    if not candidates:
        return None
    if sink_line is None:
        return candidates[0]
    before = [ln for ln in candidates if ln < sink_line]
    if not before:
        return candidates[0]
    if language == "python":
        try:
            tree = ast.parse(source_text)
        except SyntaxError:
            return max(before)
        sink_fn = _function_containing(tree, sink_line)
        if sink_fn is not None:
            same_fn = [ln for ln in before
                       if _function_containing(tree, ln) is sink_fn]
            if same_fn:
                return max(same_fn)
        return max(before)
    return max(before)


def _target_rebinds(target: ast.AST, var_name: str) -> bool:
    """Recursively check if an assignment-target AST node rebinds
    ``var_name``.  Handles bare ``Name``, ``Tuple``/``List`` unpacking,
    and ``Starred`` star-unpacking.  ``Subscript`` and ``Attribute``
    targets are mutations of contents, not rebindings, and return
    False."""
    if isinstance(target, ast.Name):
        return target.id == var_name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_rebinds(t, var_name) for t in target.elts)
    if isinstance(target, ast.Starred):
        return _target_rebinds(target.value, var_name)
    return False


def _variable_reassigned_between(
    tree: ast.AST, var_name: str, after_line: int, before_line: int,
) -> bool:
    """True iff ``var_name`` is rebound at a line strictly between
    ``after_line`` and ``before_line``.

    Sound conservatism for ``charset_sub``: ``x = re.sub('[F]+', '', x)``
    rebinds ``x`` to the sanitized value, but a later rebind would undo
    that sanitization.  Detect every common rebinding form so the
    dominance check doesn't false-positive:

      * ``x = …`` / ``x += …`` / ``x: T = …`` (Assign / AugAssign / AnnAssign)
      * ``x, y = pair`` and ``*x, = …`` (tuple / star-unpack targets)
      * ``for x in …:`` (For / AsyncFor)
      * ``with … as x:`` (With / AsyncWith optional_vars)
      * ``(x := …)`` (NamedExpr walrus)
      * ``except … as x:`` (ExceptHandler, plain and ``except*``)
      * ``case x:`` / ``case … as x`` / ``case [*x]`` / ``case {**x}``
        (match-case capture / as / star / mapping-rest patterns — all
        bind in the ENCLOSING scope, 3.10+)
      * ``def x(…)`` / ``class x`` / ``type x = …`` (definition
        statements shadow the name with a new object)
      * ``import m as x`` / ``from m import y as x`` (and
        ``from m import *``, which can rebind ANY name — flagged for
        every variable, the conservative direction)

    Pure-mutation forms (``x[0] = …``, ``x.attr = …``) don't rebind
    ``x`` itself and are NOT flagged.  Also NOT flagged, each sound by
    scope/runtime semantics rather than by rarity: ``del x`` (unbinds —
    a later use of the name raises ``NameError``, so no value flows),
    comprehension targets and ``lambda``/``def`` parameters (they bind
    their own scope, never the enclosing one), and ``global`` /
    ``nonlocal`` statements (declarations — the actual binding is an
    Assign-family node this walk already flags).  The
    constructs-vs-detector closure test pins this enumeration against
    CPython's own ``symtable`` so a new binding construct cannot be
    missed silently.
    """
    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)
        if line is None or not (after_line < line < before_line):
            continue
        if _node_rebinds_var(node, var_name):
            return True
    return False


def _node_rebinds_var(node: ast.AST, var_name: str) -> bool:
    """True iff a single AST node rebinds ``var_name`` (all the forms
    documented on :func:`_variable_reassigned_between`)."""
    # Forms whose target is an AST node (Name / Tuple / Starred).
    targets: list = []
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(
        node,
        (ast.AugAssign, ast.AnnAssign, ast.NamedExpr, ast.For, ast.AsyncFor),
    ):
        targets = [node.target]
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                targets.append(item.optional_vars)
    for t in targets:
        if _target_rebinds(t, var_name):
            return True
    # Forms whose binding name is a plain string attribute.
    # ``except SomeError as x`` binds x in the surrounding scope
    # (unbound at end of handler in Py3, but during the handler
    # body x IS the exception, not the sanitized value).
    if isinstance(node, ast.ExceptHandler) and node.name == var_name:
        return True
    # match-case patterns bind names in the ENCLOSING scope (3.10+):
    # ``case x:`` and ``case [...] as x`` (MatchAs), ``case [1, *x]``
    # (MatchStar), ``case {..., **x}`` (MatchMapping rest).  Nested
    # patterns (inside MatchClass / MatchSequence / MatchOr) are
    # reached because every caller drives ``ast.walk``.  A sink
    # consuming the case-bound value is exactly the rebind this
    # helper exists to catch.
    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == var_name:
        return True
    if isinstance(node, ast.MatchMapping) and node.rest == var_name:
        return True
    # ``import m as x`` / ``from m import y as x`` rebind x to a
    # module/attribute object; a bare ``import a.b`` binds the top
    # package name ``a``.  ``from m import *`` (module scope only)
    # can rebind ANY name — flagged for every variable, the
    # conservative (kill) direction.
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        for alias in node.names:
            if alias.name == "*":
                return True
            if (alias.asname or alias.name.split(".")[0]) == var_name:
                return True
    # ``type x = ...`` (3.12+) binds x like a class definition.
    if _TYPE_ALIAS_NODE is not None and isinstance(node, _TYPE_ALIAS_NODE):
        alias_name = node.name
        if isinstance(alias_name, ast.Name) and alias_name.id == var_name:
            return True
    # Nested function / class definitions inside the body shadow
    # the outer name with a function/class object — rare but
    # possible in fix code.
    return bool(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)) and node.name == var_name)


def _rebound_in_loop_containing_sink(
    tree: ast.AST, var_name: str, validator_line: int, sink_line: int,
    *, sanitizer_call_tails: frozenset | None = None,
) -> bool:
    """True iff ``var_name`` is rebound anywhere inside a loop whose
    span contains the sink line (the validator's own sanitizing
    binding NODE is exempt — for ``charset_sub`` that rebind IS the
    sanitization; other bindings sharing the validator's line, e.g. a
    trailing ``; x = raw``, count like any other rebind).

    Loop back-edge soundness: the flat ``(validator, sink)`` interval
    treats the function as straight-line code, but when the sink sits
    inside a loop, a rebind textually AFTER the sink (or before the
    validator) reaches the sink on the NEXT iteration —
    ``x = re.sub(...)`` before the loop, then
    ``for item in items: open(x); x = item.raw_name`` sends the raw
    value into the sink from iteration 2 on.  Any same-name rebind
    sharing a loop with the sink therefore invalidates dominance.
    Conservative: per-iteration re-validation patterns are declined
    too — the sound direction; Tier 2 takes those cases.
    """
    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.AsyncFor, ast.While)):
            continue
        end = getattr(loop, "end_lineno", None)
        if end is None or not (loop.lineno <= sink_line <= end):
            continue
        for node in ast.walk(loop):
            line = getattr(node, "lineno", None)
            if line is None:
                continue
            if line == validator_line and _is_sanitizing_binding_node(
                    node, sanitizer_call_tails):
                continue
            if _node_rebinds_var(node, var_name):
                return True
    return False


def _same_function_in_order(
    tree: ast.AST, validator_line: int, sink_line: int,
) -> bool:
    """Shared first half of every kind's dominance check: validator
    appears BEFORE the sink in source order, AND both lines are inside
    the same enclosing function."""
    if validator_line >= sink_line:
        return False
    v_fn = _function_containing(tree, validator_line)
    s_fn = _function_containing(tree, sink_line)
    return v_fn is not None and v_fn is s_fn


# ``sink_class`` (xss / sqli / cmdi / pathtrav) is the per-sink-family
# tag the SMT-barrier proof flow uses; the value-bound finding
# resolver wants a CWE id. Pick the canonical CWE in each family —
# any CWE in the family round-trips through
# :func:`core.dataflow.sanitizer_catalog.sink_classes_for_cwe` back
# to the same sink_class set, so the choice doesn't affect catalog
# lookup. Used only by the Phase 7 wire-up below.
_SINK_CLASS_TO_CWE = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "cmdi": "CWE-78",
    "cmdi_argv": "CWE-88",
    "pathtrav": "CWE-22",
}


# The gate's behaviour (value-bound on/off, lexical fallback on/off,
# parity-log path) is resolved centrally in
# :mod:`core.dataflow.sanitizer_cut_config` (imported at the top of
# this module as ``_sc_config``) from the consuming command's
# ``--sanitizer-cut`` flag, falling back to the legacy env vars. The
# "no lexical fallback" end-state corresponds to the ``strict`` mode
# there; parity telemetry to ``shadow`` mode (or an explicit
# ``--sanitizer-cut-parity-log``). See review #4 on PR #794.
def _no_lexical_fallback() -> bool:
    """True when the lexical fallback is disabled (the ``strict``
    end-state). Footgun-guarded: the config layer never returns a state
    with both the value-bound gate and the lexical fallback off."""
    return not _sc_config.lexical_fallback_enabled()


def lexical_fallback_status() -> dict:
    """Introspection surface for the arc's closure state. Returns a
    dict describing whether the lexical fallback is currently active
    and why it is retained. Consumed by the closure test and useful
    for operators auditing a run's suppression behaviour."""
    return {
        "lexical_fallback_disabled": _no_lexical_fallback(),
        "retained": not _no_lexical_fallback(),
        "retention_reason": (
            "Phase 15 parity gate not cleared — the value-bound gate "
            "does not cover validator-guard / substitution shapes the "
            "lexical check handles. Use --sanitizer-cut=strict to "
            "disable the fallback (value-bound only); delete the "
            "lexical bodies once the parity gate clears twice on real "
            "data."
        ),
        "mode": _sc_config.current().mode,
    }


def _maybe_record_parity(
    *,
    kind: str,
    file_path: str | None,
    validator_line: int,
    sink_line: int,
    cwe: str | None,
    language: str | None,
    lexical_suppressed: bool,
) -> None:
    """Phase 15 shadow telemetry. When a parity-log path is configured
    (``shadow`` mode or an explicit ``--sanitizer-cut-parity-log``),
    compute the value-bound verdict alongside the lexical decision and
    append a :class:`ParityRecord` to the log. No-op and near-zero cost
    when no path is configured. Never raises — telemetry must not break
    a real run."""
    log_path = _sc_config.parity_log_path()
    if not log_path:
        return
    if not (file_path and cwe and language):
        return
    try:
        from core.dataflow.sanitizer_cut_parity import (
            append_parity_record,
            build_parity_record,
            value_bound_verdict_for,
        )
        finding = {
            "cwe": cwe,
            "file_path": file_path,
            "source_line": validator_line,
            "sink_line": sink_line,
            "language": language,
        }
        verdict = value_bound_verdict_for(finding)
        record = build_parity_record(
            # ``kind`` joins the id: a charset and a charset_sub
            # observation at the same coordinates are two different
            # lexical decisions, and the report's last-record-wins
            # dedupe would otherwise collapse them (under-counting one
            # shape in the window that gates lexical removal).
            finding_id=(
                f"{file_path}:{validator_line}:{sink_line}:{cwe}:{kind}"
            ),
            file=file_path,
            cwe=cwe,
            language=language,
            source_line=validator_line,
            sink_line=sink_line,
            kind=kind,
            lexical_suppressed=lexical_suppressed,
            value_bound_verdict=verdict,
        )
        append_parity_record(log_path, record)
    except Exception:
        # Blanket by design (matches _value_bound_dominates): the
        # resolver/evaluator stack behind value_bound_verdict_for
        # raises on realistic inputs — RecursionError from ast.parse
        # on deeply nested code, KeyError from malformed inventory —
        # and shadow-mode telemetry observing a run must never break
        # it.  A narrower OSError-only catch let those escape into the
        # consumer's blanket handler, discarding the whole Tier 0/1B
        # verdict for the finding being observed.
        logging.getLogger(__name__).debug(
            "parity telemetry failed", exc_info=True,
        )


def _record_value_bound_audit(finding, result) -> None:
    """Record-only audit bridge: write the value-bound gate's verdict
    to ``suppressions.jsonl`` under the configured audit dir
    (``sanitizer_cut_config.audit_dir`` — set by the consuming
    command's ``--sanitizer-cut on|strict`` + run dir).

    Always ``enforce=False``: the sanitizer-cut witness has not earned
    hard-suppression on the zero-false-suppress corpus
    (``core/analysis/scripts/sanitizer-cut-precision``), so every record
    carries ``dropped: false`` — evidence for the operator, never a
    drop. Best-effort: telemetry must not break a run.
    """
    try:
        audit = _sc_config.audit_dir()
        if not audit:
            return
        from pathlib import Path as _Path

        from core.analysis.sanitizer_cut import (
            record_sanitizer_cut_suppression,
        )
        record = dict(finding)
        record.setdefault("line", finding.get("sink_line"))
        record_sanitizer_cut_suppression(
            _Path(audit), record, result, enforce=False,
        )
    except Exception:                                       # noqa: BLE001
        return


def _value_bound_dominates(
    *,
    file_path: str | None,
    validator_line: int,
    sink_line: int,
    cwe: str | None,
    language: str | None,
) -> bool | None:
    """Phase 7 of the value-binding arc — wire ``validator_dominates_sink``
    and ``substitution_dominates_sink`` through the value-bound gate.

    Returns:

    * ``True``  → value-bound vertex-cut suppresses; the caller treats
      this as dominance proved by value flow (stronger than the
      lexical check could prove).
    * ``False`` → ``VERDICT_NO_SUPPRESS``; the gate found a path
      bypassing every catalog sanitizer. The caller treats this as
      "value-bound disagrees — no dominance" even if the lexical
      heuristic would have said yes.
    * ``None``  → "consult lexical fallback." Returned when the
      value-bound gate is disabled (``off`` / ``shadow`` mode), the
      resolver can't normalise the finding (missing kwargs, file
      unreadable, function not found, or a language without a
      resolver leg — python, c/c++, and java are wired), or the
      gate's verdict was ``candidate_only`` (control-flow holds but
      value binding unproven).

    Lazy import of the inventory + dataflow packages so this module
    stays cheap to import; the heavier dependencies are paid only
    when the gate is enabled on a real run.
    """
    if not _sc_config.value_bound_enabled():
        return None
    if not (file_path and cwe and language):
        return None

    from core.analysis.finding_resolver import (
        ResolvedFinding,
        resolve_finding,
    )
    from core.analysis.sanitizer_cut import (
        VERDICT_NO_SUPPRESS,
        VERDICT_SUPPRESS,
        evaluate_finding,
    )

    finding = {
        "cwe": cwe,
        "file_path": file_path,
        "source_line": validator_line,
        "sink_line": sink_line,
        "language": language,
    }
    # Review #2: the value-bound resolver/evaluator pulls in optional
    # dependencies (tree-sitter wheels) and parses arbitrary scanned
    # source, so any of ImportError / KeyError / SyntaxError / a
    # malformed inventory could raise. The design contract is
    # "resolver failure → lexical fallback", so every failure mode must
    # fall through to ``None`` rather than escaping and crashing the
    # /agentic run mid-flight.
    try:
        resolved = resolve_finding(finding)
        if not isinstance(resolved, ResolvedFinding):
            return None
        java_text = None
        if resolved.language == "java" and file_path:
            # The constant-definers pre-check folds over the file's
            # AST; an unreadable file skips that check, never the
            # gate. Capped read: the path names scanned-repo source,
            # and a truncated read only weakens the pre-check.
            got = read_text_capped(file_path)
            java_text = got[0] if got is not None else None
        result = evaluate_finding(
            resolved.cfg,
            [resolved.source_node],
            resolved.sink_node,
            cwe=resolved.cwe,
            language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg,
            # Phase 14 resolver contract: inter-procedural synthetic
            # sanitizer bindings must reach the gate, and the parity
            # shadow path already passes them — omitting them here made
            # the production gate evaluate DIFFERENT bindings than the
            # telemetry used for the strict-promotion decision.
            extra_bindings=resolved.inter_proc_bindings,
            java_source_text=java_text,
            # Keep the kwarg set in lockstep with the Phase-15 parity
            # shadow (sanitizer_cut_parity.value_bound_verdict_for):
            # java_file_path activates the bounded cross-file constant
            # resolver, so omitting it here while the shadow passes it
            # makes the telemetry that gates Phase-16 lexical removal
            # measure a DIFFERENT gate than production runs.
            java_file_path=file_path,
        )
    except Exception:                                       # noqa: BLE001
        return None
    _record_value_bound_audit(finding, result)
    if result.verdict == VERDICT_SUPPRESS:
        return True
    if result.verdict == VERDICT_NO_SUPPRESS:
        return False
    # VERDICT_CANDIDATE_ONLY (or any verdict this gate doesn't act on)
    # — control-flow may hold but value-binding is unproven; defer to
    # the lexical heuristic. A defensive fallthrough rather than an
    # ``assert`` so a future verdict value can't turn into a crash.
    return None


def validator_dominates_sink(
    source_text: str,
    validator_line: int,
    sink_line: int,
    *,
    file_path: str | None = None,
    cwe: str | None = None,
    language: str | None = None,
) -> bool:
    """Sound dominance for the ``kind="charset"`` form — whole-string
    allowlist guarded by an ``if``-statement.

    Two checks ride on the post-fix source AST:

      1. ``validator_line < sink_line`` AND both lines inside the same
         enclosing function.
      2. The validator's ``if not X:`` block (or the ``else:`` branch
         of an ``if X: ... else:`` form) provably exits via return /
         raise / ``sys.exit`` — so a value that fails validation
         cannot reach the sink.

    Substitution-form (``kind="charset_sub"``) uses a different check
    (no ``if`` block, instead a no-reassignment guard) — see
    :func:`substitution_dominates_sink`.

    Phase 7 of the value-binding arc adds the optional ``file_path``
    / ``cwe`` / ``language`` kwargs. When the value-bound gate is
    enabled (``--sanitizer-cut=on``/``strict``) AND all three are
    supplied, the function first consults
    :func:`_value_bound_dominates`. The lexical AST check below is the
    fallback for ``candidate_only`` results, resolver failures, missing
    kwargs, and the gate-off path.
    """
    vb = _value_bound_dominates(
        file_path=file_path,
        validator_line=validator_line,
        sink_line=sink_line,
        cwe=cwe,
        language=language,
    )
    lexical = _lexical_validator_dominates(
        source_text, validator_line, sink_line,
    )
    # Phase 15 — shadow telemetry. Records BOTH decisions for every
    # finding when a parity-log path is configured (shadow mode or an
    # explicit --sanitizer-cut-parity-log), regardless of the
    # suppression mode. Zero overhead when no path is configured (the
    # check returns immediately).
    _maybe_record_parity(
        kind="charset",
        file_path=file_path, validator_line=validator_line,
        sink_line=sink_line, cwe=cwe, language=language,
        lexical_suppressed=lexical,
    )
    if vb is not None:
        return vb
    # Phase 16 — with the lexical fallback disabled, a verdict the
    # value-bound gate can't make becomes "we don't know → don't
    # suppress" rather than deferring to the lexical heuristic.
    if _no_lexical_fallback():
        return False
    return lexical


def _if_test_contains_call(tree: ast.AST, line: int) -> bool:
    """True when the :class:`ast.If` at ``line`` tests a CALL result.

    Node-anchor for the guard kind: the certified charset always comes
    from a validation call (``re.match``/``fullmatch``/method guard),
    so the ``if`` at the validator line must actually test one.  A
    decoy sharing a line with an unrelated exiting guard (``if not
    flag: raise  # if not re.match(...): raise``) has a call-free
    test — prose next to code must not certify.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and node.lineno == line:
            return any(
                isinstance(sub, ast.Call) for sub in ast.walk(node.test)
            )
    return False


def _sub_call_bound_at_line(
    tree: ast.AST, line: int, var_name: str,
) -> bool:
    """True when ``line`` really binds ``var_name`` from a ``.sub``
    call — the AST node-anchor for ``kind="charset_sub"``.  A
    substitution that exists only inside a comment or string literal
    is invisible to the AST, so requiring the real binding kills
    comment/string decoys for every lift lane (mechanical and
    LLM-pointed alike)."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        if node.lineno != line or node.value is None:
            continue
        targets = (
            node.targets if isinstance(node, ast.Assign) else [node.target]
        )
        if not any(
            isinstance(t, ast.Name) and t.id == var_name for t in targets
        ):
            continue
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Call):
                func = sub.func
                if (isinstance(func, ast.Attribute) and func.attr == "sub") \
                        or (isinstance(func, ast.Name) and func.id == "sub"):
                    return True
    return False


def _lexical_validator_dominates(
    source_text: str, validator_line: int, sink_line: int,
) -> bool:
    """Pure lexical (charset-validator) dominance check — the body
    that Phase 16 will remove. Extracted so the Phase 15 parity hook
    can record what the lexical heuristic *would* have decided
    without re-entering :func:`validator_dominates_sink` (which now
    also consults the value-bound gate)."""
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return False
    if not _same_function_in_order(tree, validator_line, sink_line):
        return False
    if not _validator_block_exits_on_failure(tree, validator_line):
        return False
    if not _if_test_contains_call(tree, validator_line):
        return False
    # Enclosing-conditional gate: an exit-on-fail guard nested inside
    # another conditional (``if cond: if not re.match(...): raise``)
    # executes only on some paths — the sink still runs on paths that
    # skipped the guard, so certifying dominance would suppress a live
    # flow. The guard's OWN ``if`` is excluded (a single-line guard
    # spans its own body). Same gate the known_safe_call kind already
    # carries in tier1_llm.
    return not _validator_in_branch(
        tree, validator_line, sink_line, exclude_guard_at=validator_line,
    )


# Function-definition markers per non-Python language.  Used by the
# non-Python dominance heuristic: any line strictly between validator and
# sink that matches one of these implies a function boundary, which
# means the validator's exit-on-fail (the diff's guard-and-exit shape)
# returns from a DIFFERENT function than the one the sink lives in.
# Conservative: any match -> decline Tier 0.  False negatives (some
# non-function lines coincidentally matching) cost us a sound case;
# false positives (function boundary missed) would be UNSOUND.
# Control-flow keywords that must NOT be confused with a function /
# method name in the line-start pattern.  ``if (x) {`` would otherwise
# match a bare-identifier-then-args-then-brace shape and look like a
# method header.
_JS_NOT_FUNC = r"(?:if|for|while|switch|catch|else|do|try|with|return|throw|var|let|const)"
_JAVA_NOT_FUNC = r"(?:if|for|while|switch|catch|else|do|try|return|throw|new|synchronized)"

# JS / TS modifier list — includes TS-only modifiers (public/private/
# protected/readonly) on the JS key too, because ``cvefix_walk._codeql_lang``
# maps both ``JavaScript`` and ``TypeScript`` repos to ``"javascript"``, so
# TS class methods would otherwise skip past the JS boundary regex
# (cross-method dominance hole — UNSOUND).
_JSTS_METHOD_MODIFIERS = (
    r"(?:async\s+|static\s+|get\s+|set\s+"
    r"|public\s+|private\s+|protected\s+|readonly\s+)*"
)
# Optional generator marker — ``function* name()`` / ``*method()``.
# The whitespace is gated on the literal ``*`` ((?:\*\s*)?): the
# naive ``\*?\s*`` put a second unbounded whitespace span adjacent
# to the surrounding ones — quadratic on an indentation-run line.
_JSTS_GENERATOR = r"(?:\*\s*)?"

_FUNCTION_BOUNDARY_PATTERNS = {
    # JS / TS:
    #   `function [*] name(` / `function(` (named, anonymous, generator)
    #   `=> {` arrow function declaration at end of line
    #   `<modifier*> [*] name(args) {` ES6 method or TS class method —
    #     with a negative lookahead so `if (x) {` etc. don't match
    # ``function`` head: the generator star and the name each own
    # their trailing whitespace ((?:\*\s*)? / (?:\w+\s*)?) — the
    # naive ``\s*\*?\s*\w*\s*\(`` chained unbounded whitespace
    # spans through optional atoms, quadratic on a whitespace run
    # after the keyword. Same language: the merged runs land in the
    # first span.
    "javascript": _re.compile(
        rf"\bfunction\s*(?:\*\s*)?(?:\w+\s*)?\("
        r"|=>\s*(?:\{\s*)?$"
        rf"|^\s*{_JSTS_METHOD_MODIFIERS}{_JSTS_GENERATOR}"
        rf"(?!{_JS_NOT_FUNC}\b)"
        r"[A-Za-z_$][\w$]*\s*\([^)]{0,4096}\)\s*\{",
    ),
    "typescript": _re.compile(
        rf"\bfunction\s*(?:\*\s*)?(?:\w+\s*)?\("
        r"|=>\s*(?:\{\s*)?$"
        rf"|^\s*{_JSTS_METHOD_MODIFIERS}{_JSTS_GENERATOR}"
        rf"(?!{_JS_NOT_FUNC}\b)"
        r"[A-Za-z_$][\w$]*\s*\([^)]{0,4096}\)\s*\{",
    ),
    # Java:
    #   `<modifier+> <return-type?> name(args) [throws ...] {?` — the
    #     explicit-modifier form covers public / private / protected /
    #     static / final / abstract / synchronized methods.
    #   `<type> name(args) [throws ...] {?` at line start — covers
    #     package-private methods (no modifier).  ``type`` is either a
    #     primitive or a TitleCase identifier (Java naming convention);
    #     negative lookahead excludes control-flow keywords so
    #     `if (x) {` doesn't false-positive match.
    "java": _re.compile(
        # gated optional brace tails ((?:\{\s*)?$) — the
        # ``\{?\s*$`` pairs were quadratic on signature lines
        # ending in whitespace runs
        # signature spans BOUNDED and paren-deterministic: the
        # pre-parameter run stops at '(' (with a bounded allowance
        # for up to two parenthesized annotation groups), parameter/
        # throws/generic spans carry generous bounds. Unbounded (or
        # '('-crossing) spans let a hostile line planting the
        # modifier keyword re-scan the line tail per occurrence —
        # quadratic, and worse through the nested parameter span.
        # Real one-line signatures sit far inside these bounds; a
        # longer line stops matching (the boundary check misses it)
        # instead of scanning without bound.
        r"\b(?:public|private|protected|static|final|abstract|synchronized)\b"
        r"(?:[^{};(]{0,400}\([^){};]{0,200}\)){0,2}[^{};(]{0,400}"
        r"\([^)]{0,2000}\)\s*(?:throws[^{]{0,2000})?(?:\{\s*)?$"
        rf"|^\s*(?!{_JAVA_NOT_FUNC}\b)"
        r"(?:(?:void|boolean|byte|char|short|int|long|float|double)"
        r"|[A-Z]\w*(?:<[^>]{0,1000}>)?(?:\[\])?)\s+"
        r"\w+\s*\([^)]{0,2000}\)\s*(?:throws[^{]{0,2000})?(?:\{\s*)?$",
    ),
    # Ruby: ``def name`` (instance) or ``def self.name`` (class method)
    # at line start (any indentation level for nested methods / class
    # methods).
    "ruby": _re.compile(r"^\s*def\s+(?:self\.)?\w"),
}


def _crosses_function_boundary(
    source_text: str, validator_line: int, sink_line: int, language: str,
) -> bool:
    """True iff any line strictly between ``validator_line`` and
    ``sink_line`` matches a function-definition pattern for ``language``.

    Plugs the cross-function dominance hole for non-Python: without a
    real AST, the source-order check alone would say a validator in
    helper A dominates a sink in helper B when both live in the same
    file and A's line < B's line.  The validator's ``if (!X) return``
    returns from A, not B, so the sink in B is not gated.  Reject
    Tier 0 when we see a function boundary.
    """
    pat = _FUNCTION_BOUNDARY_PATTERNS.get(language)
    if pat is None:
        return False
    lines = split_source_lines(source_text)
    # lines is 0-indexed; validator/sink are 1-indexed lines.
    return any(pat.search(ln) for ln in lines[validator_line:sink_line - 1])


def _collect_target_names(target: ast.AST, names: set) -> None:
    """Walk an assignment target and add every bound ``Name`` id to
    ``names``.  Subscript / Attribute targets mutate contents instead of
    rebinding and are correctly ignored."""
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _collect_target_names(elt, names)
    elif isinstance(target, ast.Starred):
        _collect_target_names(target.value, names)


def _operator_mixes_taint(value: ast.AST, chain: set) -> bool:
    """True when a string-building operator expression OR a container
    literal inside ``value`` combines a chain member with a non-chain
    :class:`ast.Name`.

    Covers ``BinOp`` (``+`` concatenation and ``%`` formatting),
    f-strings (``JoinedStr``), and container literals (``Tuple`` /
    ``List`` / ``Set`` / ``Dict``): ``p = [safe, raw]`` carries the
    raw element verbatim to whatever consumes ``p`` (``''.join(p)``),
    and a select over a mixed container (``{...: safe, ...: raw}[k]``)
    may BE the raw member — so a target bound to a mixed container
    must never join the chain as fully validated.  Call-ARGUMENT
    mixing (``os.path.join(BASE, name)``) is deliberately NOT flagged:
    the chain's documented contract accepts derivations through calls
    (the whoogle archetype), and distinguishing a module constant
    from a tainted local inside an argument list needs real taint
    tracking — Tier 2's job.  Operator mixing is the shape the
    charset proof actually breaks on: the mixed-in non-chain
    operand's characters reach the sink unvalidated.
    """
    for sub in ast.walk(value):
        if isinstance(sub, (ast.BinOp, ast.JoinedStr,
                            ast.Tuple, ast.List, ast.Set, ast.Dict)):
            if isinstance(sub, ast.Tuple) and isinstance(sub.ctx, ast.Store):
                continue  # target-side tuple, not a value expression
            names = {
                n.id for n in ast.walk(sub) if isinstance(n, ast.Name)
            }
            if (names & chain) and (names - chain):
                return True
    return False


def _is_sanitizer_call_value(
    value: ast.AST | None, tails: frozenset | None,
) -> bool:
    """True iff ``value`` IS the sanitizer call's result expression —
    an :class:`ast.Call` whose callee tail is one of ``tails`` (any
    call when the lane cannot name it).  Deliberately NOT a subtree
    search: a value that merely CONTAINS the call
    (``[escape(x), x]``, ``{...}[flag]``, ``escape(x) + raw``) mixes
    raw input around the sanitized result, so it must never earn the
    validator-binding exemption."""
    if not isinstance(value, ast.Call):
        return False
    if tails is None:
        return True
    func = value.func
    if isinstance(func, ast.Name):
        return func.id in tails
    if isinstance(func, ast.Attribute):
        return func.attr in tails
    return False


def _is_sanitizing_binding_node(
    node: ast.AST, tails: frozenset | None,
) -> bool:
    """True iff ``node`` is a binding statement whose bound value IS
    the sanitizer call (Assign / AnnAssign / walrus).  Used to scope
    the validator-line exemption to the sanitizing binding NODE — the
    whole-LINE exemption certified any trailing same-line rebind
    (``p = safe_join(base, fn); p = fn``) as still validated."""
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        return _is_sanitizer_call_value(getattr(node, "value", None), tails)
    return False


def _class_body_escaping_bindings(
    scope_root: ast.AST,
) -> list[tuple[ast.AST, frozenset]]:
    """``(node, declared_names)`` pairs for bindings inside class
    bodies that can rebind an ENCLOSING-scope name.

    Class bodies execute inline at definition time (unlike function
    bodies), and a ``global`` / ``nonlocal`` declaration inside the
    body redirects that name's bindings to the enclosing/module scope
    — ``class C: global x; x = raw`` between validator and sink
    rebinds the validated ``x`` exactly like a top-level assignment,
    while :func:`_walk_same_scope` correctly keeps ordinary
    class-namespace bindings out of the chain walk.  Kill-direction
    only: a class-body binding never GROWS the chain (an undeclared
    target is a class attribute, and modelling even the declared case
    as growth buys nothing the kill doesn't).

    Nested classes are collected by the outer scan; function bodies
    inside class bodies stay excluded (they do not execute inline).
    """
    classes: list[ast.ClassDef] = []
    stack = list(ast.iter_child_nodes(scope_root))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.Lambda)):
            continue
        if isinstance(node, ast.ClassDef):
            classes.append(node)
        stack.extend(ast.iter_child_nodes(node))
    out: list[tuple[ast.AST, frozenset]] = []
    for cls in classes:
        declared: set = set()
        body_nodes: list[ast.AST] = []
        inner = list(ast.iter_child_nodes(cls))
        while inner:
            n = inner.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.Lambda, ast.ClassDef)):
                continue  # nested classes handled by the outer scan
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                declared.update(n.names)
            body_nodes.append(n)
            inner.extend(ast.iter_child_nodes(n))
        if declared:
            frozen = frozenset(declared)
            out.extend((n, frozen) for n in body_nodes)
    return out


def _nested_scope_escaping_rebinds(scope_root: ast.AST) -> frozenset:
    """Enclosing-scope names a NESTED function can rebind — the
    ``nonlocal``/``global``-declared names that some nested
    function/method body assigns.

    Function bodies do not execute inline, but any call between
    validator and sink (direct, indirect, or through a callback) may
    run them — and call positions are not tracked here, so the only
    sound treatment is kill-direction membership for the whole
    window: a chain member a nested scope can rebind is never
    provably still the validated value at the sink.  Shrink-only
    (mirrors the class-body arm): these names never GROW the chain.

    Over-approximates on purpose: declarations and assignments are
    paired per nested function without modelling which enclosing
    scope each ``nonlocal`` resolves to — the cost is a declined
    suppression, never a false one.
    """
    out: set = set()
    for node in ast.walk(scope_root):
        if node is scope_root or not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            continue
        declared: set = set()
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Global, ast.Nonlocal)):
                declared.update(sub.names)
        if not declared:
            continue
        for sub in ast.walk(node):
            for name in declared - out:
                if _node_rebinds_var(sub, name):
                    out.add(name)
    return frozenset(out)


def _sanitizer_tails_for_spec_kind(kind: str) -> frozenset | None:
    """Callee-name tails identifying the sanitizing binding on the
    validator line for a mechanical :class:`ValidatorSpec` kind.
    ``charset_sub``'s binding is always an ``re.sub`` rebind;
    guard-shaped kinds bind nothing themselves, so any call-valued
    binding on the guard line (e.g. a walrus normalising the guarded
    value, which the guard then constrains) keeps the exemption
    (``None`` = any call)."""
    return frozenset({"sub"}) if kind == "charset_sub" else None


def _bind_chain_target(
    target: ast.AST, value: ast.AST, chain: set,
    grows: set, kills: set, *, at_validator: bool,
    tails: frozenset | None,
) -> None:
    """Chain grow/kill decision for ONE assignment target bound to
    ``value``, element-wise through tuple/list structure (mirroring
    runtime unpacking).

    Statement-level "any RHS name is a member → every target joins"
    certified the co-assigned raw value in ``a, b = safe, x`` (``b``
    IS raw ``x``) and kept ``safe`` a member through the swap idiom
    ``safe, x = x, safe`` while rebinding it to raw ``x``.  Pairing
    evaluates each element against the PRE-statement chain
    (simultaneous-assignment semantics) and the caller applies
    ``(chain | grows) - kills`` — kill wins on a name that appears in
    both, the conservative direction.  Unpairable shapes (starred
    target, length mismatch, non-literal RHS for a destructuring
    target) contribute no members and kill member targets — the
    unpacked provenance is unknown; refusing costs yield, never
    soundness.

    The validator line's own sanitizing binding — the target(s) whose
    paired value IS the sanitizer call (:func:`_is_sanitizer_call_value`)
    — is exempt: it binds the validated value.  Every OTHER binding on
    the validator line carries a pre-sanitizer value forward and is
    processed like any other line's.
    """
    if isinstance(target, (ast.Tuple, ast.List)):
        if (
            isinstance(value, (ast.Tuple, ast.List))
            and len(value.elts) == len(target.elts)
            and not any(isinstance(t, ast.Starred) for t in target.elts)
        ):
            for t_elt, v_elt in zip(target.elts, value.elts):
                _bind_chain_target(
                    t_elt, v_elt, chain, grows, kills,
                    at_validator=at_validator, tails=tails,
                )
            return
        names: set = set()
        _collect_target_names(target, names)
        kills |= names
        return
    names = set()
    _collect_target_names(target, names)
    if not names:
        return  # Attribute / Subscript target: mutation, not a rebind
    if at_validator and _is_sanitizer_call_value(value, tails):
        return  # the sanitizing binding itself — the chain's seed
    # Load-context names only: a walrus TARGET inside the RHS
    # (``y = (x := raw)``) is a simultaneous rebind, not a read of
    # the (possibly validated) old value — counting it as a read
    # certified ``y`` from stale ``x`` while ``x`` was being
    # rebound to raw data in the same statement.
    rhs_names = {
        n.id for n in ast.walk(value)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }
    if chain & rhs_names:
        if _operator_mixes_taint(value, chain):
            # Taint mixing on a plain Assign: a string-building
            # operator expression (``cmd = name + raw``, an f-string
            # interpolating both) or a mixed container literal
            # combines a chain member with a non-chain name.  The
            # target carries PARTIALLY-unvalidated data, so it must
            # never join the chain — and if it was a member, it stops
            # being one.
            kills |= names
            return
        grows |= names
        return
    # Rebind from non-chain RHS: the target no longer carries the
    # validated value.
    kills |= names


def _python_chain_reaches_sink(
    tree: ast.AST, start_var: str, validator_line: int,
    sink_line: int, sink_line_text: str,
    *, sanitizer_call_tails: frozenset | None = None,
) -> bool:
    """Intra-procedural data-dependency chain: ``True`` iff some variable
    reachable from ``start_var`` (via assignments between validator and
    sink) appears at ``sink_line_text``.

    Why this exists: the previous "validator's var must literally appear
    at the sink line" check rejected the standard pattern where the
    validated value threads through a derived expression
    (``cfg = os.path.join(BASE, name); open(cfg)``) — the sink line
    references ``cfg``, not ``name``, but ``cfg`` carries ``name``'s
    constraint.  Chain tracking accepts that case while still rejecting
    the original Bug 15 scenario (validator for ``x``, sink for
    unrelated ``y`` in the same function) — ``y`` never appears as a
    chain member.

    Chain growth: any Assign/AnnAssign/AugAssign between validator and
    sink whose RHS references a chain variable adds its target name(s)
    to the chain — element-wise through tuple/list destructuring
    (:func:`_bind_chain_target`: ``a, b = safe, x`` grows only ``a``;
    unpairable shapes never join and kill member targets) and UNLESS
    the paired RHS operator-mixes taint
    (:func:`_operator_mixes_taint`): ``cmd = name + raw`` combines the
    validated ``name`` with the unvalidated ``raw``, so ``cmd`` never
    joins the chain (and a chain-member target is killed); container
    literals mixing chain and non-chain names count as mixing too.
    Mixing through call ARGUMENTS is not modeled (see the helper's
    docstring).

    Validator-line exemption is per-NODE, never per-line: only the
    binding whose value IS the sanitizer call
    (``sanitizer_call_tails``; any call when the lane cannot name it)
    binds the validated value.  Any OTHER binding sharing the
    validator's line carries a pre-sanitizer value forward and kills
    like any other line's — the whole-line exemption certified
    ``p = safe_join(base, fn); p = fn`` (and the ``p += fn`` /
    trailing ``x = raw`` spellings) as still validated.

    Chain KILL: an assignment whose target is a chain member and whose
    RHS references NO chain member REBINDS that variable to a fresh
    value — the validator's constraint no longer applies to it.
    Without the kill, ``y = name; y = request.args.get('raw')`` left
    ``y`` "validated" at the sink and the Tier 0 verdict suppressed a
    live flow.  ALL binding forms — Assign-family and the non-Assign
    rebinds :func:`_node_rebinds_var` enumerates (loop targets, walrus,
    ``with``/``except … as``, match captures, imports, def/class) —
    are processed in ONE pass ordered by source position, so a later
    rebind wins over an earlier derivation AND a derivation from an
    already-rebound variable never joins (a kill that ran after chain
    growth let ``for name in …: … ; y = name`` certify ``y`` from the
    raw loop value).
    Loop-carried back-edges ARE modeled in the kill direction: a
    rebind sharing a loop with the sink removes the member (see
    :func:`_rebound_in_loop_containing_sink` — a rebind after the sink
    reaches it on the next iteration, so ignoring back-edges here was
    NOT conservative).  Back-edges never GROW the chain.

    Conservative w.r.t. control flow (every assignment is treated as
    reachable) — soundness for the Tier 0 verdict still rests on the
    SMT proof + the dominance check; this is the soundness layer that
    the validator's constraint applies to what reaches the sink.
    """
    chain: set = {start_var}
    # Scope filter: an assignment inside a NESTED function defined
    # between validator and sink binds the nested scope's name, not the
    # enclosing one — a bare line-window ast.walk treated it as
    # straight-line same-scope code and extended the validated chain
    # across scopes (false SOUND).  Walk only the sink's own scope.
    scope_root = _function_containing(tree, sink_line) or tree
    # ONE ordered pass over the whole window — Assign-family chain
    # grow/kill AND the non-Assign rebind-KILL interleaved by source
    # position.  A separate position-insensitive kill pass ran AFTER
    # chain growth and only removed the rebound name itself, so
    # ``for name in request.args.getlist('e'):`` followed by
    # ``y = name`` certified ``y`` from the ALREADY-REBOUND raw value
    # (false SOUND).  Killing at the rebind's own position means every
    # later derivation sees the member already gone.
    window: list = [
        (node, None) for node in _walk_same_scope(scope_root)
        if validator_line <= (getattr(node, "lineno", None) or -1) <= sink_line
    ]
    # Class bodies execute inline: their ``global``/``nonlocal``-
    # declared bindings rebind THIS scope's names, so they join the
    # ordered window as kill-only events (see
    # :func:`_class_body_escaping_bindings`).
    window += [
        (node, decls)
        for node, decls in _class_body_escaping_bindings(scope_root)
        if validator_line <= (getattr(node, "lineno", None) or -1) <= sink_line
    ]
    window.sort(
        key=lambda pair: (pair[0].lineno,
                          getattr(pair[0], "col_offset", 0)),
    )
    for node, class_decls in window:
        if class_decls is not None:
            # Kill-only: a class-body binding of a declared name
            # escapes to this scope; everything else in the body is
            # class-namespace and never touches the chain.
            for var in list(chain):
                if var in class_decls and _node_rebinds_var(node, var):
                    chain.discard(var)
            continue
        if not isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            # Non-Assign binding forms: walrus / loop targets,
            # ``with|except ... as``, match-case captures, import
            # aliases, nested def/class shadowing.  Shrink-only —
            # back-edges never GROW the chain.  Only the node that IS
            # the sanitization keeps its binding (a walrus wrapping
            # the sanitizer call); every OTHER binding sharing the
            # validator's line carries a pre-sanitizer value forward
            # and kills like any other line's.
            if (
                node.lineno == validator_line
                and isinstance(node, ast.NamedExpr)
                and _is_sanitizer_call_value(node.value,
                                             sanitizer_call_tails)
            ):
                continue
            for var in list(chain):
                if _node_rebinds_var(node, var):
                    chain.discard(var)
            continue
        if node.value is None:
            continue  # bare annotation (``x: int``) binds nothing
        at_validator = node.lineno == validator_line
        if isinstance(node, ast.AugAssign):
            # ``x += rhs`` mixes the old value with the RHS.  It never
            # ADDS to the chain (the old target value may be
            # unvalidated), and it kills a chain member when the RHS
            # references any non-chain name (the mixed-in data is not
            # covered by the validator's constraint).  An AugAssign is
            # never the sanitizing binding itself (every curated /
            # mechanical sanitizer binds via plain assignment), so the
            # validator line grants NO exemption here —
            # ``p = safe_join(base, fn); p += fn`` re-taints ``p``.
            rhs_names = {
                n.id for n in ast.walk(node.value)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
            }
            target_names: set = set()
            _collect_target_names(node.target, target_names)
            if rhs_names - chain:
                chain -= target_names
            continue
        targets = (list(node.targets) if isinstance(node, ast.Assign)
                   else [node.target])
        grows: set = set()
        kills: set = set()
        for t in targets:
            _bind_chain_target(
                t, node.value, chain, grows, kills,
                at_validator=at_validator, tails=sanitizer_call_tails,
            )
        # Simultaneous-assignment semantics: every element pair was
        # evaluated against the PRE-statement chain; kill wins when a
        # name lands in both sets (conservative).
        chain = (chain | grows) - kills
    # Loop back-edge kill: a rebind textually AFTER the sink (or before
    # the validator) still reaches the sink on the next iteration when
    # it shares a loop with the sink — the flat forward pass cannot see
    # it, so such members leave the chain (shrink-only: conservative).
    chain = {
        var for var in chain
        if not _rebound_in_loop_containing_sink(
            tree, var, validator_line, sink_line,
            sanitizer_call_tails=sanitizer_call_tails,
        )
    }
    # Nested-scope escape kill: a nested function rebinding a chain
    # member through ``nonlocal``/``global`` executes on ANY call in
    # the window (``def taint(): nonlocal y; y = raw`` + ``taint()``),
    # and call positions are untracked — such members leave the chain
    # (shrink-only: conservative; see
    # :func:`_nested_scope_escaping_rebinds`).
    chain -= _nested_scope_escaping_rebinds(scope_root)
    if not chain:
        return False
    return any(_re.search(rf"\b{_re.escape(var)}\b", sink_line_text) for var in chain)


def _lexical_var_reaches_sink(
    var: str, source_text: str, validator_line: int,
    sink_line: int, sink_line_text: str,
) -> bool:
    r"""AST-free analogue of ``_python_chain_reaches_sink``'s rebind-KILL,
    for languages without a parsed tree (JS/TS/Java).

    Returns ``True`` iff ``var`` appears at the sink line AND is not
    rebound between the validator and the sink. Previously the non-Python
    path was a bare ``\bvar\b`` match at the sink with NO rebind-KILL
    (a204f309): ``x = validate(raw); x = req.query.evil; sink(x)`` left
    ``x`` "validated" at the sink and the charset prescreen suppressed a
    live flow. A reassignment ``var = <expr not referencing var>`` between
    validator and sink rebinds it to a value the validator never
    constrained, so it must KILL the reach.

    Compound assignments (``var += rhs`` and the other ``op=`` forms,
    including JS logical assignment ``||= &&= ??=``) MIX new data into
    the validated value; they KILL the reach whenever the RHS
    references any identifier other than ``var`` itself — the mixed-in
    operand's characters were never covered by the validator's charset
    proof.  Pre-fix ``\bvar\b\s*=(?!=)`` matched only the plain
    ``=`` spelling, so ``x += req.query.evil`` slid past the
    rebind-KILL entirely (the lexical analogue of the AugAssign mixing
    kill the AST path already had).  Identifier detection does not
    strip string literals, so ``x += ".cfg"`` also kills — extra
    conservatism in the sound direction.

    Conservative by design: it detects reassignments lexically and errs
    toward KILL (declining the suppression → the finding falls through to
    LLM validation), which is the sound direction for a false-negative
    fix. Member/index writes (``var.f = …``, ``var[i] = …``) and
    comparisons (``==``/``!=``/``<=``/``>=``) do not count as rebinds.
    Residual (documented): the self-referencing plain-assign mix
    ``x = x + evil`` still passes — the AST path covers it for Python;
    modelling it lexically without breaking ``x = validate(x)`` needs
    a parser.
    """
    if not _re.search(rf"\b{_re.escape(var)}\b", sink_line_text):
        return False
    lines = split_source_lines(source_text)
    assign_re = _re.compile(rf"\b{_re.escape(var)}\b\s*=(?!=)")
    compound_re = _re.compile(
        rf"\b{_re.escape(var)}\b\s*"
        r"(?:[-+*/%&|^]|<<|>>|\*\*|\|\||&&|\?\?)=(?!=)"
    )
    self_re = _re.compile(rf"\b{_re.escape(var)}\b")
    ident_re = _re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
    for lineno in range(validator_line + 1, sink_line):
        if 1 <= lineno <= len(lines):
            text = lines[lineno - 1]
            m = compound_re.search(text)
            if m:
                rhs_idents = set(ident_re.findall(text[m.end():]))
                if rhs_idents - {var}:
                    return False  # compound assign mixes taint -> KILL
                continue
            m = assign_re.search(text)
            if m and not self_re.search(text[m.end():]):
                return False  # rebind from a non-self RHS -> KILL
    return True


def substitution_dominates_sink(
    source_text: str,
    validator_line: int,
    sink_line: int,
    var_name: str,
    *,
    file_path: str | None = None,
    cwe: str | None = None,
    language: str | None = None,
) -> bool:
    """Sound dominance for ``kind="charset_sub"`` — assignment-form
    sanitizer (``x = re.sub('[forbidden]+', '', x)``).

    Conditions:

      1. Same source-order + same-function check.
      2. ``var_name`` is NOT rebound between the substitution line and
         the sink line.  A later ``x = req.GET('x')`` would undo the
         sanitization and invalidate the post-sub language claim.
         Mutating-subscript assignments (``x[0] = ...``) don't rebind
         ``x`` itself and aren't flagged.

    Phase 7 of the value-binding arc adds the optional ``file_path``
    / ``cwe`` / ``language`` kwargs (same shape as
    :func:`validator_dominates_sink`). When the value-bound gate is
    enabled (``--sanitizer-cut=on``/``strict``) AND all three are
    supplied, the value-bound gate is consulted first; the lexical
    no-reassignment check is the fallback.
    """
    vb = _value_bound_dominates(
        file_path=file_path,
        validator_line=validator_line,
        sink_line=sink_line,
        cwe=cwe,
        language=language,
    )
    lexical = _lexical_substitution_dominates(
        source_text, validator_line, sink_line, var_name,
    )
    _maybe_record_parity(
        kind="charset_sub",
        file_path=file_path, validator_line=validator_line,
        sink_line=sink_line, cwe=cwe, language=language,
        lexical_suppressed=lexical,
    )
    if vb is not None:
        return vb
    if _no_lexical_fallback():
        return False
    return lexical


def _lexical_substitution_dominates(
    source_text: str, validator_line: int, sink_line: int, var_name: str,
) -> bool:
    """Pure lexical (substitution-form) dominance check — the body
    Phase 16 will remove. Extracted for the Phase 15 parity hook."""
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return False
    if not _sub_call_bound_at_line(tree, validator_line, var_name):
        return False
    if not _same_function_in_order(tree, validator_line, sink_line):
        return False
    if _variable_reassigned_between(tree, var_name, validator_line, sink_line):
        return False
    # Enclosing-conditional gate: ``if cond: x = re.sub('[/.]', '', x)``
    # sanitizes only on some paths — a branch-skipping path reaches the
    # sink with the raw value, so certifying dominance would suppress a
    # live flow. Same gate the known_safe_call kind already carries in
    # tier1_llm.
    if _validator_in_branch(tree, validator_line, sink_line):
        return False
    # Loop back-edge: a rebind outside the flat interval still reaches
    # the sink on the next iteration when both share a loop.  This
    # helper is substitution-form only, so the sanitizing binding on
    # the validator line is exactly the ``re.sub`` rebind.
    return not _rebound_in_loop_containing_sink(
        tree, var_name, validator_line, sink_line,
        sanitizer_call_tails=frozenset({"sub"}),
    )


# --------------------------------------------------------------------------
# SMT: regex-intersection emptiness.
# --------------------------------------------------------------------------

def _iter_charclass_atoms(body: str):
    r"""Tokenize a Python `[...]` char-class body into literal chars and
    ascending ``(lo, hi)`` ranges, interpreting a backslash escape on
    EITHER range endpoint.

    Yields ``("lit", ch)`` and ``("range", lo, hi)`` tuples.  This is
    the single range/escape interpreter shared by :func:`_charclass_to_re`
    (allowlist Z3 model) and :func:`_expand_charset_body` (forbidden-set
    expansion) — pre-fix each had its own parse and BOTH misread an
    escaped range endpoint as literals: for body ``\--z`` the escape
    branch consumed ``\-`` and the remaining ``-z`` read as two
    literals, so the modeled language was ``{'-','z'}`` while Python's
    real semantics for ``[\--z]`` are the RANGE 0x2D..0x7A (which
    includes ``/ . ; < > =`` — every pathtrav/cmdi/xss danger char).
    Z3 then proved the under-approximated language disjoint from the
    danger set and returned SOUND for a validator that in reality
    accepts the danger chars — attacker-controlled self-suppression
    of live findings via an innocuous-looking guard.

    A DESCENDING range (``z-a``) is a compile-time ``re.error`` in
    Python — the guard would never run; treat it as three literals
    (same doctrine both consumers already used).

    Alphabetic/digit escapes (``\d``, ``\2``…) never reach this
    tokenizer: :func:`_charset_body_is_safe` rejects those bodies.
    """
    i, n = 0, len(body)

    def _atom(j: int) -> tuple[str, int]:
        if body[j] == "\\" and j + 1 < n:
            return body[j + 1], j + 2
        return body[j], j + 1

    while i < n:
        first, after = _atom(i)
        if after < n and body[after] == "-" and after + 1 < n:
            second, after2 = _atom(after + 1)
            if ord(first) <= ord(second):
                yield ("range", first, second)
            else:
                yield ("lit", first)
                yield ("lit", "-")
                yield ("lit", second)
            i = after2
            continue
        yield ("lit", first)
        i = after


def _charclass_to_re(chars: str):
    """Build a Z3 regex matching ONE char from a Python `[...]` body
    (literal chars and `a-z` ranges, escapes allowed on either range
    endpoint via the shared tokenizer).  ``\\d``-style metachars are
    out of scope — the body-safety gate rejects them upstream."""
    alts = []
    for tok in _iter_charclass_atoms(chars):
        if tok[0] == "range":
            alts.append(z3.Range(tok[1], tok[2]))
        else:
            alts.append(z3.Re(z3.StringVal(tok[1])))
    if not alts:
        return None
    return z3.Union(*alts) if len(alts) > 1 else alts[0]


def _danger_re(danger: list[str]):
    """Regex for strings containing any danger char: ``.*[danger].*``."""
    rs = z3.ReSort(z3.StringSort())
    anystr = z3.Star(z3.AllChar(rs))
    if len(danger) > 1:
        chars = z3.Union(*[z3.Re(z3.StringVal(c)) for c in danger])
    else:
        chars = z3.Re(z3.StringVal(danger[0]))
    return z3.Concat(anystr, chars, anystr)


@dataclass
class _ProofVerdict:
    sound: bool
    counterexample: str | None
    reasoning: str


# Widest code-point span a single ``X-Y`` range may expand to.  Real
# sanitizer charsets are ASCII-sized; without a cap, one attacker-shaped
# range in a fix diff (space to U+10FFFF) materializes a ~1.1M-element
# set.  Over-cap ranges are treated as three literals — that UNDER-
# approximates the forbidden set, which can only push the charset_sub
# verdict toward DECLINED (sound direction; Tier 2 takes the case).
_RANGE_EXPANSION_CAP = 1024


def _expand_charset_body(body: str) -> set:
    """Expand a regex char-class body like ``A-Za-z0-9_.+-`` into the
    finite set of characters it matches.

    Handles ``X-Y`` ranges with ``ord(X) <= ord(Y)`` (spanning at most
    :data:`_RANGE_EXPANSION_CAP` code points, escapes allowed on either
    endpoint via the shared tokenizer) and literal chars; everything
    else (descending ranges — a compile-time ``re.error`` in Python —
    and over-cap ranges) is treated as three separate literals.
    """
    out: set = set()
    for tok in _iter_charclass_atoms(body):
        if tok[0] == "range":
            lo, hi = tok[1], tok[2]
            if ord(hi) - ord(lo) <= _RANGE_EXPANSION_CAP:
                for cp in range(ord(lo), ord(hi) + 1):
                    out.add(chr(cp))
            else:
                out.update((lo, "-", hi))
        else:
            out.add(tok[1])
    return out


def _prove_charset(
    spec: ValidatorSpec, sink_class: str, danger: list[str],
    timeout_ms: int | None = None,
) -> _ProofVerdict:
    """Z3 regex-intersection emptiness for whole-string anchored allowlists."""
    name = z3.String("name")
    char_re = _charclass_to_re(spec.charset)
    if char_re is None:
        return _ProofVerdict(
            True, None,
            "empty charset — validator rejects all input",
        )
    validator_re = z3.Plus(char_re)
    s = z3.Solver()
    if timeout_ms:
        # Hard per-query bound for callers on a latency budget (the
        # live-finding prescreen). Timeout surfaces as z3 `unknown`,
        # which the caller below already treats as "declining" — a
        # timed-out proof can never read as SOUND.
        s.set("timeout", timeout_ms)
    s.add(z3.InRe(name, z3.Intersect(validator_re, _danger_re(danger))))
    r = s.check()
    if r == z3.unsat:
        return _ProofVerdict(
            True, None,
            f"UNSAT: no string in [{spec.charset}]+ can contain any of "
            f"{danger!r} -> validator provably neutralises {sink_class}",
        )
    if r == z3.sat:
        try:
            ce = s.model()[name].as_string()
        except (AttributeError, z3.Z3Exception):
            # Unconstrained var: model()[name] is None (no .as_string),
            # or Z3 refuses the conversion — verdict stands without a
            # printable counterexample.
            ce = None
        return _ProofVerdict(
            False, ce,
            f"SAT: validator [{spec.charset}]+ permits an input that still "
            f"carries a {sink_class} danger char (counterexample: {ce!r})",
        )
    return _ProofVerdict(False, None,
                         f"z3 returned {r}; declining at Tier 0")


def _prove_charset_sub(
    spec: ValidatorSpec, sink_class: str, danger: list[str],
) -> _ProofVerdict:
    """Finite-set inclusion for ``x = re.sub('[forbidden]+', '', x)``.

    Post-sub ``x`` cannot contain any char in ``forbidden`` (every
    occurrence has been replaced with the empty string).  Therefore:

      * If ``danger_chars ⊆ forbidden_chars`` — every dangerous char was
        also stripped, so post-sub ``x`` cannot carry any danger.  SOUND.
      * Otherwise — at least one danger char survives the substitution.
        That char is the counterexample: any input containing it passes
        through ``re.sub`` unchanged (and the post-fix CodeQL run still
        flags this exact flow), so suppression would be unsound.

    Z3 is unnecessary for this proof: the question reduces to finite-set
    inclusion, decidable in constant time.  Soundness is the same form
    as the Z3 charset path — a real mathematical proof of language
    neutralisation — just on a domain small enough to evaluate directly.
    """
    forbidden_set = _expand_charset_body(spec.forbidden)
    danger_set = set(danger)
    missing = danger_set - forbidden_set
    if not missing:
        return _ProofVerdict(
            True, None,
            f"set inclusion: re.sub('[{spec.forbidden}]+', '', x) strips every "
            f"{sink_class} danger char {danger!r} -> validator provably "
            f"neutralises {sink_class}",
        )
    # Stable counterexample pick — deterministic across runs (sets
    # have no order).
    ce = min(missing)
    return _ProofVerdict(
        False, ce,
        f"set inclusion fails: re.sub strips [{spec.forbidden}]+ but "
        f"{sink_class} danger char {ce!r} survives -> validator insufficient",
    )


def prove_neutralizes(
    spec: ValidatorSpec, sink_class: str,
    timeout_ms: int | None = None,
) -> _ProofVerdict:
    """Dispatch on ``spec.kind`` to the appropriate sound proof:

      * ``charset``     -> Z3 regex-intersection emptiness
      * ``charset_sub`` -> finite-set inclusion (danger ⊆ forbidden)

    Either way, SOUND verdicts are real mathematical proofs of
    language neutralisation; SAT/missing-element verdicts carry a
    concrete counterexample input.

    ``timeout_ms`` bounds the Z3 query (charset kind only —
    finite-set inclusion is constant-time); ``None`` keeps the
    unbounded patch-verification behaviour.
    """
    danger = _DANGER_CHARS.get(sink_class)
    if danger is None:
        return _ProofVerdict(
            False, None,
            f"no danger model for sink_class={sink_class!r}",
        )
    if spec.kind == "charset":
        return _prove_charset(spec, sink_class, danger, timeout_ms=timeout_ms)
    if spec.kind == "charset_sub":
        return _prove_charset_sub(spec, sink_class, danger)
    return _ProofVerdict(
        False, None,
        f"prove_neutralizes does not handle kind={spec.kind!r}",
    )


# --------------------------------------------------------------------------
# Orchestrator.
# --------------------------------------------------------------------------

def try_tier0(
    *, fix_diff: str, repo_root: Path, sink_uri: str, sink_line: int,
    sink_class: str, language: str = "python",
) -> Tier0Result:
    """Run the full Tier 0 pipeline on one finding.

    Order matters: cheapest checks first.  z3 availability gate first,
    then mechanical extraction (no z3 yet), then dominance (no z3,
    single source-file read), then the SMT proof.  Each negative
    outcome short-circuits with a self-explanatory reasoning string
    so the bridge's ``detail`` column tells us WHY Tier 0 declined.

    ``language`` selects the per-language extractor and dominance
    semantics:

      * ``python``: AST-based dominance (source-order + same-function
        + exit-on-fail).  Supports ``charset`` and ``charset_sub``.
      * ``javascript`` / ``typescript`` / ``java`` / ``ruby``:
        guard-and-exit on one diff line implies dominance; the source
        order check is the only additional verification.
    """
    if not _z3_available():
        return Tier0Result(
            Tier0Status.Z3_UNAVAILABLE,
            "z3 not installed; Tier 0 unavailable, falling through to Tier 2",
        )
    spec = extract_validator(fix_diff, language=language)
    if spec is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            "no recognised charset/regex validator added in fix diff",
        )
    # Containment-checked read: ``sink_uri`` derives from SARIF /
    # finding records produced over an untrusted repo, so a
    # traversal-shaped URI (or an in-repo symlink) would walk the read
    # outside ``repo_root`` and adjudicate a barrier against an
    # arbitrary host file. Same defence as the module's siblings
    # (tier1_llm.try_tier1b, injection_prescreen._read_source,
    # cvefix_bridge._resolve_in_repo).
    src_path = confine(repo_root, sink_uri)
    if src_path is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"sink path {sink_uri!r} resolves outside the repo root — "
            f"refusing to read it",
            spec=spec,
        )
    if not src_path.is_file():
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"post-fix source not readable at {sink_uri!r}",
            spec=spec,
        )
    # Capped read (shared default): a truncated read can only make
    # the validator line unfindable below — NOT_APPLICABLE, falling
    # through to Tier 2 — never prove a barrier from missing text.
    got = read_text_capped(src_path)
    if got is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"could not read source {sink_uri!r}",
            spec=spec,
        )
    source_text = got[0]
    line = find_validator_line(
        source_text, spec, language=language, sink_line=sink_line,
    )
    if line is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"validator located in diff but not findable in {sink_uri!r}",
            spec=spec,
        )
    if language != "python":
        # Non-Python extractors require guard-and-exit on one diff line —
        # dominance is partly established by the diff itself.  Three
        # additional checks:
        #   1. source order in the post-fix file (cheap textual);
        #   2. no function boundary between validator and sink — without
        #      an AST per language, a regex-based function-definition
        #      heuristic plugs the cross-function-dominance hole that
        #      source-order alone would create;
        #   3. the guard is not wrapped in an ENCLOSING conditional that
        #      closes before the sink (``if (opts.strict) { if (!ok)
        #      return; } use(x)``) — the sink then runs on paths that
        #      skipped the guard.  guard_shaped exempts the guard's own
        #      exit-on-fail block.
        dominates = (
            line < sink_line
            and not _crosses_function_boundary(
                source_text, line, sink_line, language,
            )
            and not _lexical_validator_in_branch(
                source_text, line, sink_line,
                guard_shaped=(spec.kind == "charset"),
                language=language,
            )
        )
        why = (f"either out of source order, a function boundary "
               f"appears between the validator at line {line} and the "
               f"sink at line {sink_line} (the validator's exit-on-fail "
               f"would then return from a different function than the "
               f"sink's), or the validator is wrapped in an enclosing "
               f"conditional the sink does not share")
    elif spec.kind == "charset_sub":
        # Phase 7 plumbing: pass the resolved absolute path + CWE +
        # language through so the dominance function can consult the
        # value-bound gate when it is enabled. Defaults (None) keep the
        # lexical-only behaviour for the gate-off path and for callers
        # from outside this module who don't
        # yet populate these kwargs.
        dominates = substitution_dominates_sink(
            source_text, line, sink_line, spec.var_name,
            file_path=str(src_path),
            cwe=_SINK_CLASS_TO_CWE.get(sink_class),
            language=language,
        )
        why = (f"either out of source order, in a different function, "
               f"or {spec.var_name} was reassigned between the "
               f"substitution and the sink (undoing sanitization)")
    else:
        dominates = validator_dominates_sink(
            source_text, line, sink_line,
            file_path=str(src_path),
            cwe=_SINK_CLASS_TO_CWE.get(sink_class),
            language=language,
        )
        why = ("either out of source order, in a different function, "
               "or the `if not X:` block doesn't exit on failure")
    if not dominates:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"validator at {sink_uri}:{line} does not dominate sink at "
            f"{sink_uri}:{sink_line} — {why}",
            spec=spec,
        )
    # Variable-match check: the validator constrains ``spec.var_name``,
    # so the value at the sink must be in the data-dependency chain
    # starting from that variable.  For Python we track this via
    # intra-procedural AST chain growth — handles the common
    # pass-through pattern ``cfg = os.path.join(BASE, name); open(cfg)``
    # where the validated ``name`` reaches the sink through ``cfg``.
    # For non-Python (no per-language AST) we fall back to the literal
    # "var must appear at sink line" check — conservative direction
    # but loses pass-through cases.  Both still catch the original
    # Bug 15 scenario (validator for x, unrelated sink for y).
    source_lines = split_source_lines(source_text)
    if sink_line - 1 < len(source_lines):
        sink_line_text = source_lines[sink_line - 1]
    else:
        sink_line_text = ""
    if language == "python":
        try:
            chain_tree = ast.parse(source_text)
        except SyntaxError:
            var_reaches = False
        else:
            var_reaches = _python_chain_reaches_sink(
                chain_tree, spec.var_name, line, sink_line, sink_line_text,
                sanitizer_call_tails=_sanitizer_tails_for_spec_kind(
                    spec.kind),
            )
    else:
        var_reaches = _lexical_var_reaches_sink(
            spec.var_name, source_text, line, sink_line, sink_line_text,
        )
    if not var_reaches:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"validator constrains {spec.var_name!r} but no chain member "
            f"reaches the sink line at {sink_uri}:{sink_line} — the "
            f"validated value may not be what reaches the sink",
            spec=spec,
        )
    verdict = prove_neutralizes(spec, sink_class)
    if verdict.sound:
        if spec.kind == "charset_sub":
            artifact = (
                f"smt:charset_sub:[{spec.forbidden}]@{sink_uri}:{line}"
            )
        else:
            artifact = f"smt:charset:[{spec.charset}]+@{sink_uri}:{line}"
        return Tier0Result(
            Tier0Status.SOUND, verdict.reasoning, spec=spec,
            artifact=artifact,
            extras={"validator_line": line, "var_name": spec.var_name},
        )
    return Tier0Result(
        Tier0Status.DECLINED, verdict.reasoning, spec=spec,
        counterexample=verdict.counterexample,
        extras={"validator_line": line},
    )
