"""Tier 0 of the trust-witness sound tier: free SMT-backed barrier verdict.

Cost-asymmetric routing. The Tier 2 backend (LLM proposes a CodeQL barrier-
guard, CodeQL adjudicates) is correct but expensive — every attempt burns
LLM tokens and a CodeQL compile+run cycle. SMT over Z3's regex/string
theory is single-digit-ms of CPU and uses no LLM, so it's worth trying
FIRST on any case where the fix adds a charset/regex-shaped validator.
The whoogle archetype is::

    name = request.args.get('name')
    if not re.match(r'^[A-Za-z0-9_.+-]+$', name):
        return error()
    open(os.path.join(CONFIG_PATH, name))            # CWE-22 sink

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
import re as _re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional

from core.dataflow import sanitizer_cut_config as _sc_config
from core.smt_solver import z3, z3_available as _z3_available


# --------------------------------------------------------------------------
# Sink danger model.  Each sink_class maps to the set of characters whose
# presence in the value makes the sink exploitable.  Conservative by
# construction: the validator must exclude EVERY listed danger char for the
# verdict to come out SOUND.  Picking these is a soundness call — too narrow
# (missing danger chars) is unsound; too wide just defers more cases to
# Tier 2.
# --------------------------------------------------------------------------
_DANGER_CHARS = {
    # Path separators are the load-bearing chars for traversal.  Without '/'
    # (or '\') the value can't escape os.path.join's base directory or name
    # an absolute path.  Conservative — a lone '..' without separators
    # resolves to a directory, not an arbitrary file.
    "pathtrav": ["/", "\\"],
    # Shell metachars that introduce command separation, substitution, or
    # backgrounding.  Newlines included because they terminate a command in
    # most shell contexts.
    "cmdi":     [";", "|", "&", "$", "`", "\n"],
    # SQL quote / comment / statement-terminator chars.  Wider than strict
    # SQLi exploits need (a lone '-' isn't an exploit), so the verdict here
    # will more often be DECLINED than for pathtrav/cmdi.  Honest scope.
    "sqli":     ["'", '"', ";", "-"],
    # XSS tag- and attribute-breakers.  Same fuzziness caveat as SQLi.
    "xss":      ["<", ">", '"', "'"],
}


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
    diff_line_offset: int = 0       # position within the diff hunk (for tests)
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
    spec: Optional[ValidatorSpec] = None
    counterexample: Optional[str] = None
    # Pre-formatted spec string suitable to persist in the synth_results
    # ``barrier_query`` column.  Populated only on SOUND; lets the bridge
    # store a self-describing artifact (`smt:charset:[A-Za-z0-9_.+-]@app.py:429`)
    # without callers re-formatting.
    artifact: Optional[str] = None
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
_STR_LITERAL = (
    r"r?(?:"
    r"'(?:[^'\\]|\\.)+'"     # 'body' with escaped chars allowed
    r"|"
    r"\"(?:[^\"\\]|\\.)+\""  # "body" with escaped chars allowed
    r")"
)

# `re.match(pattern, var)` or `re.fullmatch(pattern, var)`.  Captures the
# string literal verbatim (with its quotes/prefix) so the anchor analysis
# can be exact.
_RE_MATCH_CALL = _re.compile(
    r"re\.(?:match|fullmatch)\s*\(\s*"
    rf"(?P<pat>{_STR_LITERAL})"
    r"\s*,\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
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
_RE_SUB_REBIND = _re.compile(
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"re\.sub\s*\(\s*"
    rf"(?P<pat>{_STR_LITERAL})"
    r"\s*,\s*"
    r"(?:''|\"\")"                    # empty replacement, strictly
    r"\s*,\s*"
    r"(?P=var)"                       # same identifier on the RHS
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
_JS_GUARD_TEST = _re.compile(
    r"if\s*\(\s*!\s*/\^\[(?P<chars>[^\]]+)\][+*]\$/\s*\.test\s*\(\s*"
    r"(?P<var>[A-Za-z_$][A-Za-z_$0-9]*)\s*\)\s*\)\s*"
    r"\{?\s*(?:return|throw)\b"
)
# JS/TS — `if (!<var>.match(/^[chars]+$/)) return|throw …`
_JS_GUARD_MATCH = _re.compile(
    r"if\s*\(\s*!\s*(?P<var>[A-Za-z_$][A-Za-z_$0-9]*)\s*\.match\s*\(\s*"
    r"/\^\[(?P<chars>[^\]]+)\][+*]\$/\s*\)\s*\)\s*"
    r"\{?\s*(?:return|throw)\b"
)

# Java — `if (!<var>.matches("[chars]+")) return|throw …`
# Java's ``String.matches`` is FULLMATCH by default: the regex is anchored
# even without explicit ``^...$``.  Anchor characters in the source are
# permitted (no-op) but not required.
_JAVA_GUARD = _re.compile(
    r'if\s*\(\s*!\s*(?P<var>[A-Za-z_$][A-Za-z_$0-9]*)\s*\.matches\s*\(\s*'
    r'"\^?\[(?P<chars>[^\]]+)\][+*]\$?"\s*\)\s*\)\s*'
    r'\{?\s*(?:return|throw)\b'
)

# Ruby — `return|raise … unless <var> =~ /^[chars]+$/`
_RUBY_GUARD_UNLESS = _re.compile(
    r"(?:return|raise)\b[^\n]*?\s+unless\s+(?P<var>[a-z_][a-z_0-9]*)\s*=~\s*"
    r"/\^\[(?P<chars>[^\]]+)\][+*]\$/"
)
# Ruby — `return|raise … if <var> !~ /^[chars]+$/`
_RUBY_GUARD_IF_NOT_MATCH = _re.compile(
    r"(?:return|raise)\b[^\n]*?\s+if\s+(?P<var>[a-z_][a-z_0-9]*)\s*!~\s*"
    r"/\^\[(?P<chars>[^\]]+)\][+*]\$/"
)


def _strip_string_literal(raw: str) -> str:
    """Strip Python string-literal quoting (and the `r` prefix) from a
    token captured by ``_RE_MATCH_CALL``.  Returns the inner regex body."""
    if raw.startswith("r"):
        raw = raw[1:]
    if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
        return raw[1:-1]
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
_ALPHA_BACKSLASH_ESCAPE = _re.compile(r"\\[A-Za-z]")


def _charset_body_is_safe(body: str) -> bool:
    """Reject character-class bodies our literal-char extractor would
    misread:

      * **Negation** (``[^chars]``) — inverts the language and would
        need entirely different proof semantics.  Currently silently
        misread as a literal ``^`` plus the chars.
      * **Regex shorthand classes** (``\\d``, ``\\W``, ...) — see
        ``_ALPHA_BACKSLASH_ESCAPE`` above.
    """
    if not body or body.startswith("^"):
        return False
    return _ALPHA_BACKSLASH_ESCAPE.search(body) is None


def _unescape_charclass(chars: str) -> str:
    """Strip backslash escapes from a regex character-class body.

    Inside ``[...]`` only ``]``, ``\\``, and a leading ``^`` need real
    escaping; other escape sequences (``\\!``, ``\\@``, ...) are
    unnecessary but legal, and the unescaped character is what the
    pattern actually matches.  Stripping them gives us the true
    member-set of the class.

    Used by the ``re.sub`` extractor where authors often over-escape
    (e.g. Gerapy's
    ``'[\\!\\@\\#\\$\\;\\&\\*\\~\\"\\'\\{\\}\\]\\[\\-\\+\\%\\^]+'``).
    """
    return _re.sub(r"\\(.)", r"\1", chars)


def _try_charset_validator(line: str, offset: int) -> Optional[ValidatorSpec]:
    """Match the whole-string `re.match`/`re.fullmatch` over `^[chars]+$`
    pattern.  Returns ``None`` on no match so the caller can try other
    extractors."""
    m = _RE_MATCH_CALL.search(line)
    if not m:
        return None
    call_kind = "fullmatch" if "fullmatch" in line[m.start():m.end()] else "match"
    pattern = _strip_string_literal(m.group("pat"))
    var_name = m.group("var")
    cs = _ANCHORED_CHARSET.match(pattern)
    if cs is None and call_kind == "fullmatch":
        cs = _FULLMATCH_CHARSET.match(pattern)
    if cs is None or not _charset_body_is_safe(cs.group(1)):
        return None
    return ValidatorSpec(
        kind="charset", var_name=var_name, charset=cs.group(1),
        source_line=line.strip(), diff_line_offset=offset,
    )


def _try_charset_sub_validator(line: str, offset: int) -> Optional[ValidatorSpec]:
    """Match the ``x = re.sub('[forbidden]+', '', x)`` rebind pattern.
    Returns ``None`` on no match."""
    m = _RE_SUB_REBIND.search(line)
    if not m:
        return None
    pattern = _strip_string_literal(m.group("pat"))
    cs = _SUB_CHARSET.match(pattern)
    if not cs or not _charset_body_is_safe(cs.group(1)):
        return None
    forbidden = _unescape_charclass(cs.group(1))
    return ValidatorSpec(
        kind="charset_sub", var_name=m.group("var"),
        forbidden=forbidden, source_line=line.strip(),
        diff_line_offset=offset,
    )


def _try_jsts_validator(line: str, offset: int) -> Optional[ValidatorSpec]:
    """JS / TS guard-and-exit shapes.  Single regex match implies both
    the validator and its exit-on-fail are on the line — dominance is
    established by the diff itself."""
    m = _JS_GUARD_TEST.search(line) or _JS_GUARD_MATCH.search(line)
    if m is None or not _charset_body_is_safe(m.group("chars")):
        return None
    return ValidatorSpec(
        kind="charset", var_name=m.group("var"), charset=m.group("chars"),
        source_line=line.strip(), diff_line_offset=offset,
    )


def _try_java_validator(line: str, offset: int) -> Optional[ValidatorSpec]:
    """Java ``String.matches`` guard-and-exit shape."""
    m = _JAVA_GUARD.search(line)
    if m is None or not _charset_body_is_safe(m.group("chars")):
        return None
    return ValidatorSpec(
        kind="charset", var_name=m.group("var"), charset=m.group("chars"),
        source_line=line.strip(), diff_line_offset=offset,
    )


def _try_ruby_validator(line: str, offset: int) -> Optional[ValidatorSpec]:
    """Ruby ``unless x =~ /…/`` and ``if x !~ /…/`` guard shapes."""
    m = _RUBY_GUARD_UNLESS.search(line) or _RUBY_GUARD_IF_NOT_MATCH.search(line)
    if m is None or not _charset_body_is_safe(m.group("chars")):
        return None
    return ValidatorSpec(
        kind="charset", var_name=m.group("var"), charset=m.group("chars"),
        source_line=line.strip(), diff_line_offset=offset,
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


def extract_validator(fix_diff: str, language: str = "python") -> Optional[ValidatorSpec]:
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
    extractors = _LANG_EXTRACTORS.get(language)
    if not extractors:
        return None
    for offset, raw in enumerate(fix_diff.splitlines()):
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        line = raw[1:]
        for try_fn in extractors:
            spec = try_fn(line, offset)
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


def _function_containing(tree: ast.AST, line: int) -> Optional[ast.AST]:
    """Smallest-range FunctionDef / AsyncFunctionDef containing ``line``,
    or None.  "Smallest range" so nested functions resolve to the inner
    one, matching the semantics of "same function" we want for dominance."""
    best: Optional[ast.AST] = None
    best_size: Optional[int] = None
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


def _block_uses_raise(body: list) -> bool:
    """True iff the block exits via ``raise`` specifically (not Return /
    sys.exit).  Used to detect Bug 19: a ``raise`` exit inside a
    ``try/except`` can be CAUGHT and let the unvalidated value reach
    the sink — soundness requires checking the surrounding context."""
    if not body:
        return False
    for stmt in body:
        if isinstance(stmt, ast.Raise):
            return True
    return False


def _line_in_try_body_with_catching_handler(
    tree: ast.AST, validator_line: int,
) -> bool:
    """True iff ``validator_line`` falls inside the ``try.body`` of a
    ``Try`` whose handlers might catch a generic / unspecified
    exception.

    Conservative: any ``except:`` (bare), ``except Exception:``,
    ``except BaseException:`` triggers; specific exception classes
    don't (since the validator's ``raise`` typically raises
    ``ValueError``/``BadRequest`` and a generic ``except OSError:``
    won't catch those).  False positives here only cost yield —
    they don't compromise soundness.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
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
            t = h.type
            # bare except: -> catches everything (UNSOUND if validator raises)
            if t is None:
                return True
            # except Exception: / except BaseException:
            if isinstance(t, ast.Name) and t.id in {"Exception", "BaseException"}:
                return True
            # except (Exception, OSError): tuple of types
            if isinstance(t, ast.Tuple):
                for elt in t.elts:
                    if isinstance(elt, ast.Name) and elt.id in {"Exception", "BaseException"}:
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
            # If the exit is `raise` and we're inside a catching try,
            # the raise gets caught — decline.
            if (_block_uses_raise(failure_body)
                    and _line_in_try_body_with_catching_handler(
                        tree, validator_line)):
                return False
            return True
    return False


def find_validator_line(source_text: str, spec: ValidatorSpec) -> Optional[int]:
    """Locate the validator's 1-based line number in the post-fix source
    text.  Matches by the stripped line-text the extractor saved on the
    spec; first occurrence wins (multiple matches are unusual and any of
    them would gate the sink the same way).

    Pre-fix this read the file from disk; the refactor pulls the I/O out
    to :func:`try_tier0` so the source text can be reused by the
    dominance check without a second read.
    """
    needle = spec.source_line
    for idx, ln in enumerate(source_text.splitlines()):
        if ln.strip() == needle:
            return idx + 1
    return None


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

    Pure-mutation forms (``x[0] = …``, ``x.attr = …``) don't rebind
    ``x`` itself and are NOT flagged.  Function/class definitions and
    imports that happen to bind ``x`` are not flagged either — they
    create their own scopes and very rarely appear between a fix-added
    substitution and its sink.
    """
    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)
        if line is None or not (after_line < line < before_line):
            continue
        # Forms whose target is an AST node (Name / Tuple / Starred).
        targets: list = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
            targets = [node.target]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
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
        # Nested function / class definitions inside the body shadow
        # the outer name with a function/class object — rare but
        # possible in fix code.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef)) and node.name == var_name:
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
        "horizon_doc": "docs/sanitizer-cut-parity/HORIZON.md",
    }


def _maybe_record_parity(
    *,
    kind: str,
    file_path: Optional[str],
    validator_line: int,
    sink_line: int,
    cwe: Optional[str],
    language: Optional[str],
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
            finding_id=f"{file_path}:{validator_line}:{sink_line}:{cwe}",
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
    except Exception:                                       # noqa: BLE001
        # Telemetry is best-effort; swallow everything.
        pass


def _value_bound_dominates(
    *,
    file_path: Optional[str],
    validator_line: int,
    sink_line: int,
    cwe: Optional[str],
    language: Optional[str],
):
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
      unreadable, function not found, non-python language, …), or the
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

    from core.inventory.finding_resolver import (
        ResolvedFinding,
        resolve_finding,
    )
    from core.inventory.sanitizer_cut import (
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
        result = evaluate_finding(
            resolved.cfg,
            [resolved.source_node],
            resolved.sink_node,
            cwe=resolved.cwe,
            language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg,
        )
    except Exception:                                       # noqa: BLE001
        return None
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
    file_path: Optional[str] = None,
    cwe: Optional[str] = None,
    language: Optional[str] = None,
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
    return _validator_block_exits_on_failure(tree, validator_line)


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
_JSTS_GENERATOR = r"\*?\s*"

_FUNCTION_BOUNDARY_PATTERNS = {
    # JS / TS:
    #   `function [*] name(` / `function(` (named, anonymous, generator)
    #   `=> {` arrow function declaration at end of line
    #   `<modifier*> [*] name(args) {` ES6 method or TS class method —
    #     with a negative lookahead so `if (x) {` etc. don't match
    "javascript": _re.compile(
        rf"\bfunction\s*{_JSTS_GENERATOR}\w*\s*\("
        r"|=>\s*\{?\s*$"
        rf"|^\s*{_JSTS_METHOD_MODIFIERS}{_JSTS_GENERATOR}"
        rf"(?!{_JS_NOT_FUNC}\b)"
        r"[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{",
    ),
    "typescript": _re.compile(
        rf"\bfunction\s*{_JSTS_GENERATOR}\w*\s*\("
        r"|=>\s*\{?\s*$"
        rf"|^\s*{_JSTS_METHOD_MODIFIERS}{_JSTS_GENERATOR}"
        rf"(?!{_JS_NOT_FUNC}\b)"
        r"[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{",
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
        r"\b(?:public|private|protected|static|final|abstract|synchronized)\b"
        r"[^{};]*\([^)]*\)\s*(?:throws[^{]*)?\{?\s*$"
        rf"|^\s*(?!{_JAVA_NOT_FUNC}\b)"
        r"(?:(?:void|boolean|byte|char|short|int|long|float|double)"
        r"|[A-Z]\w*(?:<[^>]*>)?(?:\[\])?)\s+"
        r"\w+\s*\([^)]*\)\s*(?:throws[^{]*)?\{?\s*$",
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
    lines = source_text.splitlines()
    # lines is 0-indexed; validator/sink are 1-indexed lines.
    for ln in lines[validator_line:sink_line - 1]:
        if pat.search(ln):
            return True
    return False


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


def _python_chain_reaches_sink(
    tree: ast.AST, start_var: str, validator_line: int,
    sink_line: int, sink_line_text: str,
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
    to the chain.  Conservative w.r.t. control flow (every assignment
    is treated as reachable) — soundness for the Tier 0 verdict still
    rests on the SMT proof + the dominance check; this is just the
    soundness layer that the validator's constraint applies to what
    reaches the sink.
    """
    chain: set = {start_var}
    # Iterate multiple passes — a derived variable assigned later might
    # itself feed a still-later assignment.  Fixed point on a small
    # chain is cheap (at most ~function-line-count iterations).
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                continue
            node_line = getattr(node, "lineno", None) or 0
            if not (validator_line <= node_line <= sink_line):
                continue
            value = node.value
            if value is None:
                continue
            rhs_names = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
            if not (chain & rhs_names):
                continue
            targets = (list(node.targets) if isinstance(node, ast.Assign)
                       else [node.target])
            before = len(chain)
            for t in targets:
                _collect_target_names(t, chain)
            if len(chain) > before:
                changed = True
    for var in chain:
        if _re.search(rf"\b{_re.escape(var)}\b", sink_line_text):
            return True
    return False


def substitution_dominates_sink(
    source_text: str,
    validator_line: int,
    sink_line: int,
    var_name: str,
    *,
    file_path: Optional[str] = None,
    cwe: Optional[str] = None,
    language: Optional[str] = None,
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
    if not _same_function_in_order(tree, validator_line, sink_line):
        return False
    return not _variable_reassigned_between(
        tree, var_name, validator_line, sink_line,
    )


# --------------------------------------------------------------------------
# SMT: regex-intersection emptiness.
# --------------------------------------------------------------------------

def _charclass_to_re(chars: str):
    """Build a Z3 regex matching ONE char from a Python `[...]` body
    (literal chars and `a-z` ranges).  Limited to the syntax our extractor
    captures — escapes and `\\d`-style metachars are out of scope for the
    first cut."""
    alts = []
    i, n = 0, len(chars)
    while i < n:
        if i + 2 < n and chars[i + 1] == "-":
            alts.append(z3.Range(chars[i], chars[i + 2]))
            i += 3
        else:
            alts.append(z3.Re(z3.StringVal(chars[i])))
            i += 1
    return z3.Union(*alts) if len(alts) > 1 else alts[0]


def _danger_re(danger: List[str]):
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
    counterexample: Optional[str]
    reasoning: str


def _expand_charset_body(body: str) -> set:
    """Expand a regex char-class body like ``A-Za-z0-9_.+-`` into the
    finite set of characters it matches.

    Handles ``X-Y`` ranges with ``ord(X) <= ord(Y)`` and literal chars;
    everything else (including ``X-Y`` where ``X`` and ``Y`` aren't in
    range-ascending order — would silently drop chars under a naive
    ``range(ord(X), ord(Y)+1)``) is treated as three separate literals.
    """
    out: set = set()
    i, n = 0, len(body)
    while i < n:
        if (i + 2 < n and body[i + 1] == "-"
                and ord(body[i]) <= ord(body[i + 2])):
            for cp in range(ord(body[i]), ord(body[i + 2]) + 1):
                out.add(chr(cp))
            i += 3
        else:
            out.add(body[i])
            i += 1
    return out


def _prove_charset(spec: ValidatorSpec, sink_class: str, danger: List[str]) -> _ProofVerdict:
    """Z3 regex-intersection emptiness for whole-string anchored allowlists."""
    name = z3.String("name")
    char_re = _charclass_to_re(spec.charset)
    validator_re = z3.Plus(char_re)
    s = z3.Solver()
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
        except Exception:
            ce = None
        return _ProofVerdict(
            False, ce,
            f"SAT: validator [{spec.charset}]+ permits an input that still "
            f"carries a {sink_class} danger char (counterexample: {ce!r})",
        )
    return _ProofVerdict(False, None,
                         f"z3 returned {r}; declining at Tier 0")


def _prove_charset_sub(
    spec: ValidatorSpec, sink_class: str, danger: List[str],
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
    # Stable counterexample pick — sort so the message is deterministic
    # across runs (sets have no order).
    ce = sorted(missing)[0]
    return _ProofVerdict(
        False, ce,
        f"set inclusion fails: re.sub strips [{spec.forbidden}]+ but "
        f"{sink_class} danger char {ce!r} survives -> validator insufficient",
    )


def prove_neutralizes(spec: ValidatorSpec, sink_class: str) -> _ProofVerdict:
    """Dispatch on ``spec.kind`` to the appropriate sound proof:

      * ``charset``     -> Z3 regex-intersection emptiness
      * ``charset_sub`` -> finite-set inclusion (danger ⊆ forbidden)

    Either way, SOUND verdicts are real mathematical proofs of
    language neutralisation; SAT/missing-element verdicts carry a
    concrete counterexample input.
    """
    danger = _DANGER_CHARS.get(sink_class)
    if danger is None:
        return _ProofVerdict(
            False, None,
            f"no danger model for sink_class={sink_class!r}",
        )
    if spec.kind == "charset":
        return _prove_charset(spec, sink_class, danger)
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
    src_path = repo_root / sink_uri.lstrip("/")
    if not src_path.is_file():
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"post-fix source not readable at {sink_uri!r}",
            spec=spec,
        )
    try:
        source_text = src_path.read_text(errors="replace")
    except OSError as exc:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"could not read source {sink_uri!r}: {exc}",
            spec=spec,
        )
    line = find_validator_line(source_text, spec)
    if line is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"validator located in diff but not findable in {sink_uri!r}",
            spec=spec,
        )
    if language != "python":
        # Non-Python extractors require guard-and-exit on one diff line —
        # dominance is partly established by the diff itself.  Two
        # additional checks:
        #   1. source order in the post-fix file (cheap textual);
        #   2. no function boundary between validator and sink — without
        #      an AST per language, a regex-based function-definition
        #      heuristic plugs the cross-function-dominance hole that
        #      source-order alone would create.
        dominates = (line < sink_line and not _crosses_function_boundary(
            source_text, line, sink_line, language,
        ))
        why = (f"either out of source order, or a function boundary "
               f"appears between the validator at line {line} and the "
               f"sink at line {sink_line} (the validator's exit-on-fail "
               f"would then return from a different function than the "
               f"sink's)")
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
    source_lines = source_text.splitlines()
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
            )
    else:
        var_reaches = bool(_re.search(
            rf"\b{_re.escape(spec.var_name)}\b", sink_line_text,
        ))
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
