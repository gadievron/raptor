"""Lifetime witness family for the anti-self-refutation gate (C).

Corroborates a reviewer's SELF-REFUTATION of a lifetime claim
(double-free / use-after-free, CWE-415/416) on a C function by proving
a mechanical control-flow fact over a goto/label-resolved
intra-function CFG.  When a witness holds, the dismissed claim's
mechanism is impossible as stated, so re-flagging it via the
receipt-free CWE-allowlist floor would manufacture a false positive.

Four arms over one shared substrate:

W-FREEPATH (double-free)
    Every pair of visible release sites of the claimed pointer is
    path-exclusive: no execution reaches two of them, and no loop
    encloses one.  Discharges pure double-free claims about this
    function's own free sites (the two-site typestate-echo shape) —
    CWE-415 only.  Mixed UAF/double-free phrasings are out of family.

W-NOUSE (use-after-release)
    No use of the claimed pointer — or of anything that could still
    reach it — on any path after the releasing call.  Tracking is
    deliberately over-approximate: bare-copy aliases propagate fully;
    values derived through calls/expressions and the possibly-retaining
    co-arguments of any call that received the pointer refuse the proof
    when they are dereferenced, indexed, or passed onward after the
    release.  A store of the pointer into memory, or its address being
    taken, refuses outright.  Discharges CWE-416.

W-BRACKET (acquire-release pairing)
    The claimed "free" is a put/unpin-family call paired with a
    get/pin-family acquisition that is the pointer's single definition
    and dominates every release.  No two releases through the same
    callee can both execute, no release sits in a loop, and after the
    final release nothing uses the pointer.  Stores of the pointer into
    longer-lived objects are permitted — a refcount drop paired with an
    acquisition is not a deallocation, and the claim being discharged
    is the in-function freed-then-used echo.  Discharges CWE-415/416.

W-DELEG (delegation-only)
    The function body is a single forwarding call of the function's own
    parameter to a free-family callee — it adds no lifetime behaviour
    of its own, so a "the framework/caller invokes this twice" double-
    free claim has no in-function mechanism and belongs to the caller's
    verdict lane.  Discharges CWE-415 for exactly that claim shape.

Async-handoff sub-arm (W-NOUSE variant)
    For claims about an asynchronous-completion path selected by a
    handoff sentinel (``-EINPROGRESS``): every path from the sentinel
    test to function exit contains zero release-family calls and never
    touches the claimed objects.  Discharges CWE-415/416 for the
    sentinel-path claim shape.

Applicability fences (claim phrasing) decide only which dismissals an
arm may EXAMINE — the proof is always the mechanical CFG analysis.
Claims attributing the free or the use to a concurrent actor are out
of family for the synchronous arms: a path proof says nothing about
another thread.

Macro certification
-------------------

The CFG is built from the RAW function source (tree-sitter C), so
every macro invocation must first be certified against the target
tree's own macro table (:mod:`core.audit.defassign` include-closure
machinery).  A macro whose definition cannot be proven inert for this
analysis refuses the whole claim: conflicting/poisoned definitions,
control-transfer tokens or labels in the (transitively resolved) body,
token pasting, a body that names one of the reviewed function's own
locals, a hidden release-family call, or an assignment/address-of
through a macro parameter whose argument is a tracked name.  Kernel
iteration macros (``IDENT(args) { ... }`` at statement position) are
certified the same way and then modelled as a conservative ``while``
loop — a superset of any iteration count the real expansion produces,
sound for the universally-quantified negatives proven here provided
the certified header transfers control only into its own loop.

Soundness bounds (documented, deliberate)
-----------------------------------------

- The macro table is textual (same residual class as the
  definite-assignment prover): headers the closure scan cannot read
  can hide a macro this module then treats as a plain call or
  identifier.  Consumers therefore gate the witness on the operator's
  repo-trust assertion.
- A release performed by a NAMED CALLEE the vocabulary does not cover
  is invisible: W-FREEPATH's obligation is the claimed in-function
  site pair (the fence restricts it to that claim shape), and
  W-NOUSE's obligation is what happens AFTER the visible releasing
  call — neither claims whole-program lifetime correctness.
- A macro body may assign a value derived from its arguments to a
  file-scope object; the after-release occurrence scan does not see
  such a stash.  Same trust-gate class as the textual-table residual.

Failure direction is uniformly conservative: every unresolvable
construct refuses ("no witness") — the floor stands.  Vocabulary is
seed-small (the shared free-verb seeds plus ``deactivate_locked_super``
for releases; ``get``/``pin`` vs ``put``/``unpin`` word stems for the
bracket arm) and grows only through the study-learned
DomainVocabulary, never from claim text.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence, TypeVar

from .callback_lifetime import _SEED_FREE_NAMES
from .defassign import (
    MacroDef,
    MacroTable,
    ProofRefusal,
    Token,
    _macro_table_for,
    _node_text,
    _parse_function,
    _substitute,
    _walk_nodes,
    function_local_names,
    function_parameter_names,
)
from .defassign import (
    _TOKEN_RE as _DEFASSIGN_TOKEN_RE,
)
from .defassign import (
    _tokenize as _defassign_tokenize,
)

logger = logging.getLogger(__name__)

# Token tuple shapes: plain (kind, spelling) and offset-carrying
# (kind, spelling, start, end).
_Tok = TypeVar("_Tok", tuple[str, str], tuple[str, str, int, int])

# ---------------------------------------------------------------------------
# Caps.  Exceeding any of them refuses.
# ---------------------------------------------------------------------------

_MAX_SOURCE_BYTES = 256 * 1024
_MAX_CFG_NODES = 4000
_MAX_MACRO_VET_DEPTH = 48
_MAX_TRACK_ROUNDS = 32
_MAX_CANDIDATES = 4

# ---------------------------------------------------------------------------
# Vocabulary.  Seeds are deliberately small; growth rides the
# study-learned DomainVocabulary (``deallocators`` / ``refcount_gets``
# / ``refcount_puts``), never claim text.
# ---------------------------------------------------------------------------

# Releasing verbs for W-FREEPATH / W-NOUSE: the shared free-verb seed
# set plus deactivate_locked_super (drops the superblock's last active
# reference and unlocks — the releasing call of the thaw idiom).
_SEED_RELEASE_NAMES: frozenset[str] = frozenset(_SEED_FREE_NAMES) | {
    "deactivate_locked_super",
}

# Word-stem seeds for W-BRACKET (matched against ``_``-separated name
# components, never substrings — "output"/"input" do not match).
_ACQUIRE_STEMS: frozenset[str] = frozenset({"get", "pin"})
_RELEASE_STEMS: frozenset[str] = frozenset({"put", "unpin"})

# Async-handoff sentinels the async arm recognises (spelled with a
# unary minus at the test site, kernel convention).
_ASYNC_SENTINELS: frozenset[str] = frozenset({"EINPROGRESS"})

_SETJMP_FAMILY = frozenset({
    "setjmp", "_setjmp", "sigsetjmp", "longjmp", "siglongjmp",
})

# Tokens that transfer control in a way a certified-inert macro body
# must not contain (a label is checked separately by shape).  Plain
# ``asm`` is deliberately absent: an asm statement cannot free memory
# or rebind a local, and ``asm goto`` — the one control-transferring
# form — carries a ``goto`` token this set already refuses.
_MACRO_CTRL_TOKENS = frozenset({
    "goto", "return", "break", "continue", "switch", "case", "default",
    "__label__",
}) | _SETJMP_FAMILY

_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default",
    "do", "double", "else", "enum", "extern", "float", "for", "goto",
    "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch",
    "typedef", "union", "unsigned", "void", "volatile", "while",
})


def _name_components(name: str) -> frozenset[str]:
    """``_``-separated components of a C identifier, lowercased."""
    return frozenset(p for p in name.lower().split("_") if p)


def _release_names(vocab: Any = None) -> frozenset[str]:
    """Exact releasing-verb names: seeds plus study-learned."""
    extra = getattr(vocab, "deallocators", None) or frozenset()
    return _SEED_RELEASE_NAMES | frozenset(extra)


def _put_names(vocab: Any = None) -> frozenset[str]:
    extra = getattr(vocab, "refcount_puts", None) or frozenset()
    return frozenset(extra)


def _get_names(vocab: Any = None) -> frozenset[str]:
    extra = getattr(vocab, "refcount_gets", None) or frozenset()
    return frozenset(extra)


def _is_release_callee(name: str, vocab: Any = None) -> bool:
    """Free-family callee (exact vocabulary name)."""
    return name in _release_names(vocab)


def _is_put_callee(name: str, vocab: Any = None) -> bool:
    """Put/unpin-family callee (word stem or learned exact name)."""
    if name in _put_names(vocab):
        return True
    return bool(_name_components(name) & _RELEASE_STEMS)


def _is_get_callee(name: str, vocab: Any = None) -> bool:
    if name in _get_names(vocab):
        return True
    return bool(_name_components(name) & _ACQUIRE_STEMS)


def _is_release_family_component(name: str, vocab: Any = None) -> bool:
    """Does *name* hide release behaviour a macro body must not carry?

    Free-vocabulary names as components (``__kfree_x``) and put/unpin
    stems refuse; acquire stems are harmless (an uncounted GET cannot
    weaken any obligation proven here).
    """
    comps = _name_components(name)
    if comps & _RELEASE_STEMS:
        return True
    for rel in _release_names(vocab):
        if rel in comps or name == rel:
            return True
    return False


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class LifetimeProof:
    """One arm's discharged proof."""

    arm: str
    pointer: str
    reason: str
    cwes: frozenset[str]


@dataclass
class LifetimeClaimResult:
    """Outcome of :func:`check_lifetime_claim`.

    ``discharged`` is True ONLY when at least one arm proved; the CWE
    families the proofs cover are the union in ``covered_cwes`` —
    consumers must check the claim's own CWE set against it.  Every
    refusal is ``discharged=False`` with the refusing construct named.
    """

    discharged: bool
    covered_cwes: frozenset[str]
    proofs: tuple[LifetimeProof, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "discharged": self.discharged,
            "covered_cwes": sorted(self.covered_cwes),
            "proofs": [
                {
                    "arm": p.arm,
                    "pointer": p.pointer,
                    "reason": p.reason,
                    "cwes": sorted(p.cwes),
                }
                for p in self.proofs
            ],
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Claim-phrasing applicability fences.  These decide which dismissals
# an arm may EXAMINE — never the verdict.
# ---------------------------------------------------------------------------

_LT_DF_RE = re.compile(
    r"double[\s-]?free|freed?\s+twice|"
    r"free[ds]?\b[^.;]{0,120}?\b(?:again|twice|second\s+time)|"
    r"(?:then|and)\s+(?:freed|again\s+freed)|"
    r"two\s+(?:k?v?free|frees)",
    re.IGNORECASE,
)

# In-function two-site indicator for W-FREEPATH: the claim must talk
# about this function's own free sites (typestate-echo shape), not a
# callee- or caller-induced second free.
_LT_TWO_SITE_RE = re.compile(
    r"(?:at\s+)?l(?:ine\s+)?~?\d+[^.;]{0,120}?"
    r"(?:again|then|second|twice|l(?:ine\s+)?~?\d+)|"
    r"freed?\s+twice|"
    r"(?:then|and)\s+again",
    re.IGNORECASE,
)

_LT_UAF_RE = re.compile(
    r"use[\s-]?after[\s-]?free|\buaf\b|dangling|"
    r"use\s+of\s+freed|"
    r"(?:used?|dereferenc\w+|read|accessed)\s[^.;]{0,120}?"
    r"\bafter\b[^.;]{0,120}?(?:free|releas|drop|put|deactivat)|"
    r"(?:free[ds]?|freed|releas\w+|drop\w+)\b[^.;]{0,120}?"
    r"(?:then|and|later)\s+(?:used?|dereferenc\w+|accessed|read)|"
    r"freed?\s+at\s[^.;]{0,80}?used?\s+at",
    re.IGNORECASE,
)

# Hard out-of-family for the synchronous arms: the claim attributes
# the free or the use to a concurrent actor — a path proof over this
# function says nothing about another thread.
_LT_CONCURRENT_ACTOR_RE = re.compile(
    r"concurren|race\b|racing|another\s+(?:thread|cpu|core|context)|"
    r"other\s+(?:thread|cpu|core)s?|simultaneous|in\s+parallel|"
    r"interrupt\s+(?:handler|context)|"
    r"\bthreads?\s+[a-z0-9]\b|two\s+threads|"
    r"second\s+(?:thread|cpu|core|invocation)|"
    r"softirq|hardirq|\birq\b|timer\s+(?:handler|callback)|"
    r"re-?ent(?:er|ers|ered|rant|ry)|"
    r"nested\s+(?:call|invocation)|"
    r"(?:another|other)\s+(?:invocation|caller)|"
    r"while\s+(?:this|the)\s+\w+\s+(?:runs|is\s+running|executes)",
    re.IGNORECASE,
)

# W-DELEG: the double invocation is attributed to the caller /
# framework — the exactly-once discipline of whoever calls us.
_LT_CALLER_TWICE_RE = re.compile(
    r"(?:call(?:ed|s)?|invok\w+|releas\w+|dispatch\w+|run[s]?)"
    r"[^.;]{0,80}?\btwice\b|"
    r"\btwice\b[^.;]{0,80}?(?:same|by\s+the|framework|caller|core)|"
    r"(?:framework|caller|upper\s+layer|core)[^.;]{0,80}?"
    r"(?:twice|double)",
    re.IGNORECASE,
)

# Async-handoff claim shape: names the handoff sentinel or the
# asynchronous completion explicitly.
_LT_ASYNC_RE = re.compile(
    r"EINPROGRESS|async|asynchronous|in[\s-]progress|"
    r"completion\s+(?:handler|callback|path)|handed?\s*[- ]?off",
    re.IGNORECASE,
)

_C_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_CWE_415 = frozenset({"CWE-415"})
_CWE_416 = frozenset({"CWE-416"})
_CWE_415_416 = frozenset({"CWE-415", "CWE-416"})


# ---------------------------------------------------------------------------
# Offset-aware tokenization (defassign's grammar, positions kept)
# ---------------------------------------------------------------------------


def _trim_to_function(text: str) -> str:
    """Cut *text* at the close of the first top-level brace pair.

    Function spans sometimes carry trailing material after the
    definition; only ``EXPORT_SYMBOL(...)``-shaped call trailers and
    stray semicolons are tolerated there — anything brace-carrying or
    otherwise substantial refuses, so a second function definition in
    the span can never silently displace the analysed one.
    """
    toks = _tokenize_with_offsets(text)
    depth = 0
    opened = False
    cut = None
    cut_idx = 0
    for i, (_kind, s, _start, end) in enumerate(toks):
        if s == "{":
            depth += 1
            opened = True
        elif s == "}":
            depth -= 1
            if opened and depth == 0:
                cut = end
                cut_idx = i + 1
                break
    if cut is None:
        raise ProofRefusal("no balanced function body found")
    rest = toks[cut_idx:]
    j = 0
    n = len(rest)
    while j < n:
        kind, s = rest[j][0], rest[j][1]
        if s == ";":
            j += 1
            continue
        if kind == "ident" and j + 1 < n and rest[j + 1][1] == "(":
            _args, after = _split_top_level_args(rest, j + 1)
            if after < n and rest[after][1] == ";":
                j = after + 1
                continue
        raise ProofRefusal(
            "source carries additional definitions after the "
            "function body"
        )
    return text[:cut]


def _tokenize_with_offsets(text: str) -> list[tuple[str, str, int, int]]:
    """(kind, spelling, start, end) tokens; refuses on unknown bytes."""
    out: list[tuple[str, str, int, int]] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _DEFASSIGN_TOKEN_RE.match(text, pos)
        if m is None:
            raise ProofRefusal(
                f"untokenizable character {text[pos]!r} at offset {pos}"
            )
        pos = m.end()
        kind = str(m.lastgroup)
        if kind in ("ws", "comment"):
            continue
        out.append((kind, m.group(), m.start(), m.end()))
    return out


# ---------------------------------------------------------------------------
# Token-level tracked superset (macro-certification input)
# ---------------------------------------------------------------------------


def _token_tracked_superset(
    tokens: list[Token], seeds: frozenset[str],
) -> frozenset[str]:
    """Over-approximate closure of names that may carry a seed value.

    Fixpoint over ``ident = <rhs...>;`` shapes in the raw token
    stream: any RHS mentioning a member adds the LHS.  Used only to
    decide which macro invocations must refuse — over-approximation
    can only over-refuse, never over-prove.

    Declarator shapes (``struct s *q = p;``) are invisible at token
    level: the ``*`` before the name reads as an operator here.
    :class:`_Analysis` closes that gap with a second certification
    pass against the tree-sitter alias/derived closure once the
    token-certified parse can be trusted.
    """
    tracked = set(seeds)
    spellings = [s for _k, s in tokens]
    for _round in range(_MAX_TRACK_ROUNDS):
        grew = False
        i = 0
        n = len(tokens)
        while i < n:
            kind, s = tokens[i]
            if (
                kind == "ident"
                and i + 1 < n
                and tokens[i + 1][1] == "="
                and (i + 2 >= n or tokens[i + 2][1] != "=")
                and (i == 0 or spellings[i - 1] not in ("=", "!", "<",
                                                        ">", "+", "-",
                                                        "*", "/", "%",
                                                        "&", "|", "^"))
            ):
                j = i + 2
                rhs_hit = False
                while j < n and tokens[j][1] != ";":
                    if tokens[j][0] == "ident" and tokens[j][1] in tracked:
                        rhs_hit = True
                    j += 1
                if rhs_hit and s not in tracked:
                    tracked.add(s)
                    grew = True
                i = j
                continue
            i += 1
        if not grew:
            return frozenset(tracked)
    raise ProofRefusal("tracked-superset fixpoint did not converge")


# ---------------------------------------------------------------------------
# Macro certification
# ---------------------------------------------------------------------------


_MARKER_RE = re.compile(r"__ltwp(?:\d+|va)__")


def _marker(i: int | str) -> str:
    return f"__ltwp{i}__"


class _VetBudget:
    """Global bound on macro-vetting work per analysis.

    Charged both per expansion AND per token PRODUCED: a single
    substitution's output is |parameter occurrences| x |argument
    tokens|, so an expansion count alone admits a multiplicative
    token bomb from two closure ``#define`` lines.
    """

    def __init__(
        self,
        max_expansions: int = 5000,
        max_tokens: int = 2_000_000,
    ) -> None:
        self.remaining = max_expansions
        self.token_remaining = max_tokens

    def spend(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise ProofRefusal("macro vetting budget exceeded")

    def spend_tokens(self, produced: int) -> None:
        self.token_remaining -= produced
        if self.token_remaining < 0:
            raise ProofRefusal(
                "macro vetting token budget exceeded"
            )


def _charge_substitution(
    d: MacroDef, args: list[list[Token]], budget: _VetBudget,
) -> None:
    """Charge a substitution's worst-case output size BEFORE
    materializing it: |body| + Σ per-parameter occurrences × argument
    length.  A multiplicative pair of ``#define`` lines otherwise
    builds its entire token product in memory before any budget check
    can see it.
    """
    try:
        body = _defassign_tokenize(d.body)
    except ProofRefusal:
        raise ProofRefusal(
            f"macro {d.name} has an untokenizable definition body"
        )
    params = list(d.params or ())
    counts = {p: 0 for p in params}
    counts["__VA_ARGS__"] = 0
    for _k, s in body:
        if s in counts:
            counts[s] += 1
    cost = len(body)
    arg_lens = [len(a) for a in args]
    for i, p in enumerate(params):
        if i < len(arg_lens):
            cost += counts[p] * arg_lens[i]
    if d.variadic and len(arg_lens) > len(params):
        va_len = sum(arg_lens[len(params):]) + max(
            0, len(arg_lens) - len(params) - 1,
        )
        cost += counts["__VA_ARGS__"] * va_len
    budget.spend_tokens(cost)


def _macro_defs(table: MacroTable, name: str) -> list[MacroDef]:
    """Every candidate definition of *name* (config-conditional
    definitions included).  Unlike the definite-assignment prover this
    module never needs the exact expansion the build used — only that
    EVERY candidate is inert — so conflicting definitions do not
    refuse by themselves and a same-named function fallback is
    harmless (a by-value call is a plain call to the CFG).  Keywords
    are never treated as macros (an active keyword rewrite that hides
    control flow is part of the documented trust-gated residual);
    unparseable definitions poison the name.
    """
    if name in _C_KEYWORDS:
        return []
    if name in table.poisoned:
        raise ProofRefusal(
            f"macro {name} has an unparseable definition in the closure"
        )
    return table.defs.get(name, [])


# GNU named-variadic parameter lists (``#define f(args...)``) are
# unparseable to the definite-assignment prover, which poisons the
# name.  This module only needs inertness, so it re-parses such
# definitions itself: the named tail becomes ``__VA_ARGS__`` in the
# body and the definition joins the candidate set.
_NAMED_VA_PARAMS_RE = re.compile(
    r"\s*\(\s*((?:[A-Za-z_][A-Za-z0-9_]*\s*,\s*)*)"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\.\.\s*\)"
)

_LT_TABLE_CACHE: dict[tuple[str, str], MacroTable] = {}
_LT_TABLE_CACHE_MAX = 8


def _reparse_named_variadic(rest: str, path: str) -> MacroDef | None:
    """Parse ``NAME(a, b, tail...)<body>`` after ``#define``."""
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", rest)
    if m is None:
        return None
    name = m.group(1)
    after = rest[m.end():]
    pm = _NAMED_VA_PARAMS_RE.match(after)
    if pm is None:
        return None
    fixed = tuple(
        p.strip() for p in pm.group(1).split(",") if p.strip()
    )
    va_name = pm.group(2)
    body = after[pm.end():].strip()
    try:
        toks = _defassign_tokenize(body)
    except ProofRefusal:
        return None
    rebuilt = " ".join(
        "__VA_ARGS__" if (k == "ident" and s == va_name) else s
        for k, s in toks
    )
    return MacroDef(
        name=name, params=fixed, variadic=True, body=rebuilt, path=path,
    )


def _lifetime_macro_table(
    target_path: str | Path, rel_file: str,
) -> MacroTable:
    """A full-fidelity macro table for this module.

    Rebuilt from the include closure with comments stripped BEFORE
    line joining: a multi-line comment inside a ``#define`` is valid C
    (newlines inside comments do not end the directive) but a
    line-based join truncates such definitions into unbalanced
    garbage the balance check would then refuse.  GNU named-variadic
    definitions are re-parsed instead of poisoned; anything neither
    grammar accepts poisons the name (refuse-on-use).  The base
    table's closure-visible function-name set is reused.
    """
    key = (str(target_path), rel_file)
    cached = _LT_TABLE_CACHE.get(key)
    if cached is not None:
        return cached
    base = _macro_table_for(target_path, rel_file)
    from .defassign import (
        _DIRECTIVE_RE,
        _join_continuations,
        _parse_define,
        _strip_comments,
        resolve_include_closure,
    )

    files, unresolved = resolve_include_closure(target_path, rel_file)
    defs: dict[str, list[MacroDef]] = {}
    poisoned: set[str] = set()
    scanned = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        for line in _join_continuations(_strip_comments(text)):
            dm = _DIRECTIVE_RE.match(line)
            if dm is None or dm.group(1) != "define":
                continue
            rest = dm.group(2)
            parsed = _parse_define(rest, str(path))
            if parsed is None:
                parsed = _reparse_named_variadic(rest, str(path))
            if parsed is None:
                nm = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", rest)
                if nm is not None:
                    poisoned.add(nm.group(1))
                continue
            defs.setdefault(parsed.name, []).append(parsed)
    table = MacroTable(
        defs=defs,
        poisoned=poisoned,
        function_names=base.function_names,
        unresolved_includes=tuple(unresolved),
        files_scanned=scanned,
    )
    if len(_LT_TABLE_CACHE) >= _LT_TABLE_CACHE_MAX:
        _LT_TABLE_CACHE.pop(next(iter(_LT_TABLE_CACHE)))
    _LT_TABLE_CACHE[key] = table
    return table


def _arity_ok(d: MacroDef, args: Sequence[Sequence[object]]) -> bool:
    """Can *d* be the definition a compiling build used for an
    invocation with *args*?  (Mirrors ``_substitute``'s acceptance.)"""
    if d.params is None:
        return True
    p = len(d.params)
    if len(args) < p and not (len(args) == 0 and p == 1):
        return False
    if not d.variadic and len(args) > p:
        return False
    return True


def _check_body_balance(name: str, d: MacroDef) -> None:
    """A certified definition body must be bracket-balanced.

    An unbalanced body (``do {`` / ``} while (...)`` pairs) splices
    control structure into the surrounding raw source that the CFG
    cannot see; a BALANCED body with internal loops/branches is a
    self-contained unit the atomic-invocation model covers.
    """
    try:
        body = _defassign_tokenize(d.body)
    except ProofRefusal:
        raise ProofRefusal(
            f"macro {name} has an untokenizable definition body"
        )
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for _k, s in body:
        if s in "([{":
            stack.append(s)
        elif s in ")]}":
            if not stack or stack.pop() != pairs[s]:
                raise ProofRefusal(
                    f"macro {name} has an unbalanced definition body"
                )
    if stack:
        raise ProofRefusal(
            f"macro {name} has an unbalanced definition body"
        )


def _marker_args(d: MacroDef) -> list[list[Token]]:
    """Placeholder arguments for an abstract (top-level) vet: one
    unique marker identifier per parameter, plus one for the variadic
    tail, so argument provenance survives substitution."""
    args: list[list[Token]] = [
        [("ident", _marker(i))] for i in range(len(d.params or ()))
    ]
    if d.variadic:
        args.append([("ident", _marker("va"))])
    return args


def _pre_expand(
    tokens: list[Token],
    table: MacroTable,
    budget: _VetBudget,
    active: frozenset[str],
    depth: int = 0,
) -> list[Token]:
    """Expand SINGLE-definition macros inside argument tokens.

    The standard expands macro arguments before substitution at
    ordinary parameter positions — the ``__PASTE(a, b)`` indirection
    idiom depends on it.  Names with multiple candidate definitions
    are left unexpanded (the scan's per-definition recursion covers
    them); self-referential names stay painted.
    """
    if depth > _MAX_MACRO_VET_DEPTH:
        raise ProofRefusal("macro pre-expansion depth exceeded")
    out: list[Token] = []
    i = 0
    n = len(tokens)
    while i < n:
        kind, s = tokens[i]
        if kind == "ident" and s not in active:
            defs = _macro_defs(table, s)
            if len(defs) == 1:
                d = defs[0]
                budget.spend()
                if d.params is None:
                    sub = _defassign_tokenize(d.body)
                    budget.spend_tokens(len(sub))
                    out.extend(_pre_expand(
                        sub, table, budget, active | {s}, depth + 1,
                    ))
                    i += 1
                    continue
                if i + 1 < n and tokens[i + 1][1] == "(":
                    args, after = _split_top_level_args(tokens, i + 1)
                    if _arity_ok(d, args):
                        # Arguments are not part of this macro's own
                        # replacement — they expand unpainted; only
                        # the rescan of the substituted result paints
                        # the name (C11 6.10.3.4).
                        _charge_substitution(d, args, budget)
                        sub = _substitute(
                            d, args,
                            expand_arg=lambda a: _pre_expand(
                                a, table, budget, active, depth + 1,
                            ),
                        )
                        budget.spend_tokens(len(sub))
                        out.extend(_pre_expand(
                            sub, table, budget, active | {s},
                            depth + 1,
                        ))
                        i = after
                        continue
        out.append(tokens[i])
        i += 1
    return out


def _expand_and_vet(
    name: str,
    actual_args: list[list[Token]] | None,
    table: MacroTable,
    local_names: frozenset[str],
    vocab: Any,
    budget: _VetBudget,
    memo: dict[Any, frozenset[str]],
    active: frozenset[str] = frozenset(),
    depth: int = 0,
) -> frozenset[str]:
    """Certify every candidate definition of *name* as inert for the
    CFG analysis, with *actual_args* substituted (or per-parameter
    markers when None — the abstract top-level form).

    Nested macro invocations are expanded with their REAL argument
    tokens, so fixed-token pastes (``_AC(1, UL)``) compute while a
    paste involving a top-level parameter marker still refuses.
    Returns the set of marker spellings the expansion assigns,
    updates, takes the address of, or invokes — the caller maps them
    back to source argument positions.  Raises :class:`ProofRefusal`
    on anything the analysis cannot model in ANY candidate
    definition.
    """
    if depth > _MAX_MACRO_VET_DEPTH:
        raise ProofRefusal(f"macro vetting depth exceeded at {name}")
    if name in active:
        raise ProofRefusal(f"recursive macro {name}")
    key: Any = (
        (name, None) if actual_args is None
        else (name, tuple(tuple(t[1] for t in a) for a in actual_args))
    )
    cached = memo.get(key)
    if cached is not None:
        return cached
    defs = _macro_defs(table, name)
    if not defs:
        raise ProofRefusal(f"{name} is not a macro")
    if actual_args is not None:
        # A definition whose arity cannot match this invocation
        # cannot be the one a compiling build used.
        defs = [d for d in defs if _arity_ok(d, actual_args)]
        if not defs:
            raise ProofRefusal(
                f"no candidate definition of {name} matches the "
                f"invocation arity"
            )
    budget.spend()
    flagged: set[str] = set()
    for d in defs:
        _check_body_balance(name, d)
        if d.params is None:
            sub = _defassign_tokenize(d.body)
        else:
            args = actual_args if actual_args is not None \
                else _marker_args(d)
            # Argument tokens are not part of this macro's own
            # replacement — they pre-expand unpainted.
            _charge_substitution(d, args, budget)
            sub = _substitute(
                d, args,
                expand_arg=lambda a: _pre_expand(
                    a, table, budget, active, depth + 1,
                ),
            )
        budget.spend_tokens(len(sub))
        flagged |= _scan_expansion(
            name, sub, table, local_names, vocab, budget, memo,
            active | {name}, depth,
        )
    result = frozenset(flagged)
    memo[key] = result
    return result


def _scan_expansion(
    name: str,
    sub: list[Token],
    table: MacroTable,
    local_names: frozenset[str],
    vocab: Any,
    budget: _VetBudget,
    memo: dict[Any, frozenset[str]],
    active: frozenset[str],
    depth: int,
) -> set[str]:
    """Hazard scan over one substituted candidate expansion."""
    flagged: set[str] = set()
    n = len(sub)
    i = 0
    while i < n:
        kind, s = sub[i]
        nxt = sub[i + 1][1] if i + 1 < n else ""
        prv = sub[i - 1][1] if i > 0 else ""
        if s in ("#", "##"):
            raise ProofRefusal(
                f"macro {name} carries an unresolved {s} operator"
            )
        if kind != "ident":
            i += 1
            continue
        if s in _MACRO_CTRL_TOKENS:
            raise ProofRefusal(
                f"macro {name} contains control token {s!r}"
            )
        if nxt == ":" and prv in ("", ";", "{", "}"):
            raise ProofRefusal(f"macro {name} contains a label")
        m = _MARKER_RE.search(s)
        if m is not None:
            if m.group(0) != s:
                raise ProofRefusal(
                    f"macro {name} pastes a parameter (## can "
                    f"synthesize names from arguments)"
                )
            # Exact marker: adjacency hazards flag the parameter.
            # Adjacency is computed THROUGH balanced parenthesis
            # wraps — ``&(x)`` and ``(x) = y`` carry the same hazards
            # as ``&x`` and ``x = y`` (ordinary kernel macro idiom).
            lwrap = 0
            while i - 1 - lwrap >= 0 and sub[i - 1 - lwrap][1] == "(":
                lwrap += 1
            rwrap = 0
            while i + 1 + rwrap < n and sub[i + 1 + rwrap][1] == ")":
                rwrap += 1
            wrap = min(lwrap, rwrap)
            eprv = sub[i - 1 - wrap][1] if i - 1 - wrap >= 0 else ""
            eprv2 = sub[i - 2 - wrap][1] if i - 2 - wrap >= 1 else ""
            envt = sub[i + 1 + wrap][1] if i + 1 + wrap < n else ""
            if envt in ("=", "+=", "-=", "*=", "/=", "%=", "&=", "^=",
                        "|=", "<<=", ">>=", "++", "--", "(") or \
                    eprv in ("++", "--"):
                # No comparison exemption: the tokenizer is
                # maximal-munch (`==`/`!=`/`<=`/`>=` are single
                # tokens), so a bare `=` on BOTH sides of the marker
                # can only be chained assignment (`a = MARKER = b`) —
                # which rebinds the parameter and must flag.
                flagged.add(s)
            if eprv == "&" and envt not in ("->", ".", "["):
                unary = eprv2 in (
                    "", "(", "[", ",", ";", "{", "}", "=", "return",
                ) or eprv2 in ("&&", "||", "?", ":")
                if unary:
                    flagged.add(s)
            i += 1
            continue
        if s in local_names:
            raise ProofRefusal(
                f"macro {name} names function local {s!r}"
            )
        # ANY position, not just call shape: a parenthesized or
        # comma-laundered callee (``(kfree)(x)``) and a release verb
        # taken as a value are equally invisible to the raw CFG.
        # The match is TEXTUAL and therefore macro-spoofable in the
        # harmless direction only: a closure that redefines a free
        # verb to something inert makes this rule over-refuse, never
        # over-prove (an actual release behind an innocent name is
        # caught by this same scan on the defining body when invoked,
        # and stays a trust-gated residual when the definition is
        # unreadable).
        if _is_release_family_component(s, vocab):
            raise ProofRefusal(
                f"macro {name} carries release-family name {s!r}"
            )
        nested_defs = _macro_defs(table, s) if s not in active else []
        if nested_defs:
            has_fn = any(nd.params is not None for nd in nested_defs)
            has_obj = any(nd.params is None for nd in nested_defs)
            if has_fn and nxt == "(":
                args, after = _split_top_level_args(sub, i + 1)
                flagged |= _expand_and_vet(
                    s, args, table, local_names, vocab, budget,
                    memo, active, depth + 1,
                )
                if not has_obj:
                    # The whole invocation is covered by the
                    # recursion; an object-like candidate leaves its
                    # argument list in place, so keep scanning it.
                    i = after
                    continue
                i += 1
                continue
            if has_obj:
                flagged |= _expand_and_vet(
                    s, None, table, local_names, vocab, budget,
                    memo, active, depth + 1,
                )
        i += 1
    return flagged



def _split_top_level_args(
    tokens: list[_Tok], open_idx: int,
) -> tuple[list[list[_Tok]], int]:
    """Balanced argument split starting at ``tokens[open_idx] == '('``.

    Works over plain and offset-carrying token tuples.  Returns
    (args, index_after_close)."""
    args: list[list[_Tok]] = []
    cur: list[_Tok] = []
    depth = 0
    i = open_idx
    n = len(tokens)
    while i < n:
        s = tokens[i][1]
        if s in "([{":
            depth += 1
            if depth > 1:
                cur.append(tokens[i])
        elif s in ")]}":
            depth -= 1
            if depth == 0:
                if s != ")":
                    raise ProofRefusal("mismatched bracket in argument list")
                if cur or args:
                    args.append(cur)
                return args, i + 1
            cur.append(tokens[i])
        elif s == "," and depth == 1:
            args.append(cur)
            cur = []
        elif depth >= 1:
            cur.append(tokens[i])
        i += 1
    raise ProofRefusal("unbalanced argument list")


def _bare_arg_ident(arg: Sequence[Sequence[Any]]) -> str | None:
    """The identifier when *arg* is a bare (possibly parenthesized)
    identifier, else None."""
    toks = list(arg)
    while len(toks) >= 2 and toks[0][1] == "(" and toks[-1][1] == ")":
        toks = toks[1:-1]
    if len(toks) == 1 and toks[0][0] == "ident":
        return toks[0][1]
    return None


def _certify_macros(
    src_tokens: list[tuple[str, str, int, int]],
    table: MacroTable,
    local_names: frozenset[str],
    tracked_superset: frozenset[str],
    vocab: Any,
) -> None:
    """Certify every macro invocation in the function source.

    Each source-level invocation is vetted abstractly (parameter
    markers), so the flagged markers map back to source argument
    positions: an argument holding a tracked name at a position the
    expansion assigns, addresses or invokes refuses, as does an
    invoked argument spelling a release-family name.  Raises
    :class:`ProofRefusal` on anything that cannot be certified.
    """
    memo: dict[Any, frozenset[str]] = {}
    budget = _VetBudget()
    n = len(src_tokens)
    for i, (kind, s, _a, _b) in enumerate(src_tokens):
        if kind != "ident" or s in _C_KEYWORDS:
            continue
        defs = _macro_defs(table, s)  # raises on poisoned names
        if not defs:
            continue
        invoked = i + 1 < n and src_tokens[i + 1][1] == "("
        if all(d.params is not None for d in defs) and not invoked:
            continue  # function-like name without arguments: plain ident
        flagged = _expand_and_vet(
            s, None, table, local_names, vocab, budget, memo,
        )
        if not flagged or not invoked:
            continue
        args, _after = _split_top_level_args(src_tokens, i + 1)
        for marker in flagged:
            mm = re.fullmatch(r"__ltwp(\d+)__", marker)
            if mm is None:
                continue  # variadic marker: no single position
            pi = int(mm.group(1))
            if pi >= len(args):
                continue
            arg_idents = {t[1] for t in args[pi] if t[0] == "ident"}
            if arg_idents & tracked_superset:
                raise ProofRefusal(
                    f"macro {s} rebinds, addresses or invokes tracked "
                    f"name(s) {sorted(arg_idents & tracked_superset)}"
                )
            bare = _bare_arg_ident(args[pi])
            if bare is not None and _is_release_family_component(
                bare, vocab,
            ):
                raise ProofRefusal(
                    f"macro {s} may invoke release-family {bare!r}"
                )


# ---------------------------------------------------------------------------
# Loop-macro transform:  IDENT(args) { ... }  →  while (IDENT(args)) { ... }
# ---------------------------------------------------------------------------


def _transform_loop_macros(
    text: str, table: MacroTable,
) -> str:
    """Rewrite statement-position ``IDENT(args) {`` blocks into
    ``while (IDENT(args)) {`` so kernel iteration macros join the CFG
    as conservative loops.

    Only certified shapes are rewritten: the identifier must resolve to
    a function-like macro in the table (its body is separately
    certified by :func:`_certify_macros`), and the invocation must sit
    at a statement boundary.  Any other bare-block call shape refuses
    downstream at parse time (missing ``;``).
    """
    toks = _tokenize_with_offsets(text)
    n = len(toks)
    edits: list[tuple[int, int, str]] = []  # (start, end, replacement)
    for i, (kind, s, start, _end) in enumerate(toks):
        if kind != "ident" or s in _C_KEYWORDS:
            continue
        if i + 1 >= n or toks[i + 1][1] != "(":
            continue
        prev = toks[i - 1][1] if i > 0 else ""
        if prev not in ("", ";", "{", "}", ":"):
            continue
        try:
            _args, after = _split_top_level_args(toks, i + 1)
        except ProofRefusal:
            continue
        if after >= n or toks[after][1] != "{":
            continue
        defs = _macro_defs(table, s)  # raises on poisoned names
        if not defs or any(d.params is None for d in defs):
            raise ProofRefusal(
                f"statement-shaped block call {s} does not resolve to "
                f"a function-like macro"
            )
        close_end = toks[after - 1][3]
        edits.append((start, close_end, None))  # type: ignore[arg-type]
    if not edits:
        return text
    out: list[str] = []
    pos = 0
    for start, close_end, _ in edits:
        out.append(text[pos:start])
        out.append("while (")
        out.append(text[start:close_end])
        out.append(")")
        pos = close_end
    out.append(text[pos:])
    return "".join(out)


# ---------------------------------------------------------------------------
# CFG over tree-sitter statements (goto/label resolved)
# ---------------------------------------------------------------------------

_EXIT = -1

_ALLOWED_STMTS = frozenset({
    "compound_statement", "expression_statement", "declaration",
    "if_statement", "else_clause", "while_statement", "do_statement",
    "for_statement", "return_statement", "break_statement",
    "continue_statement", "goto_statement", "labeled_statement",
    "switch_statement", "case_statement", "comment",
})


class _CFG:
    """Statement-level CFG with resolved gotos, labels and switches."""

    def __init__(self) -> None:
        self.exprs: dict[int, list[Any]] = {}
        self.succ: dict[int, set[int]] = {}
        self.labels: dict[str, int] = {}
        self.pending_gotos: list[tuple[int, str]] = []
        # Condition node → entry node of each branch (if statements).
        self.if_then: dict[int, int] = {}
        self.if_else: dict[int, int] = {}
        self._next = 0

    def new_node(self) -> int:
        nid = self._next
        self._next += 1
        if self._next > _MAX_CFG_NODES:
            raise ProofRefusal("CFG node cap exceeded")
        self.exprs[nid] = []
        self.succ[nid] = set()
        return nid

    def edge(self, a: int, b: int) -> None:
        if a != _EXIT:
            self.succ[a].add(b)

    def reachable_from(self, starts: set[int]) -> set[int]:
        seen: set[int] = set()
        queue = [s for s in starts if s != _EXIT]
        while queue:
            nid = queue.pop()
            if nid in seen:
                continue
            seen.add(nid)
            queue.extend(
                t for t in self.succ.get(nid, ()) if t not in seen
            )
        return seen


_MAX_STMT_DEPTH = 400


class _CFGBuilder:
    def __init__(self) -> None:
        self.cfg = _CFG()
        self.loop_stack: list[tuple[int, int]] = []  # (continue, break)
        self.break_stack: list[int] = []  # innermost break target
        self.depth = 0

    # Every builder method returns the set of "open ends" — node ids
    # whose successor is the NEXT statement in sequence.

    def build(self, body: Any) -> _CFG:
        entry = self.cfg.new_node()  # synthetic entry
        ends = self._seq(body.named_children, {entry})
        for e in ends:
            self.cfg.edge(e, _EXIT)
        for src, label in self.cfg.pending_gotos:
            target = self.cfg.labels.get(label)
            if target is None:
                raise ProofRefusal(f"goto to unknown label {label!r}")
            self.cfg.edge(src, target)
        return self.cfg

    def _seq(self, stmts: list[Any], incoming: set[int]) -> set[int]:
        open_ends = set(incoming)
        for st in stmts:
            open_ends = self._stmt(st, open_ends)
        return open_ends

    def _join(self, open_ends: set[int]) -> int:
        """Materialize a node all *open_ends* flow into."""
        nid = self.cfg.new_node()
        for e in open_ends:
            self.cfg.edge(e, nid)
        return nid

    def _stmt(self, node: Any, incoming: set[int]) -> set[int]:
        self.depth += 1
        try:
            return self._stmt_inner(node, incoming)
        finally:
            self.depth -= 1

    def _stmt_inner(self, node: Any, incoming: set[int]) -> set[int]:
        if self.depth > _MAX_STMT_DEPTH:
            raise ProofRefusal("statement nesting depth cap exceeded")
        t = node.type
        if t not in _ALLOWED_STMTS:
            raise ProofRefusal(f"unsupported statement form: {t}")
        if t == "comment":
            return incoming
        if t == "compound_statement":
            return self._seq(node.named_children, incoming)
        if t == "labeled_statement":
            label = node.child_by_field_name("label")
            if label is None or label.type != "statement_identifier":
                raise ProofRefusal("unsupported label shape")
            name = _node_text(label)
            if name in self.cfg.labels:
                raise ProofRefusal(f"duplicate label {name!r}")
            nid = self._join(incoming)
            self.cfg.labels[name] = nid
            inner = [
                c for c in node.named_children
                if c != label and c.type != "comment"
            ]
            return self._seq(inner, {nid})
        if t == "goto_statement":
            label = node.child_by_field_name("label")
            if label is None or label.type != "statement_identifier":
                raise ProofRefusal("computed or malformed goto")
            nid = self._join(incoming)
            self.cfg.pending_gotos.append((nid, _node_text(label)))
            return set()
        if t in ("expression_statement", "declaration"):
            nid = self._join(incoming)
            self.cfg.exprs[nid] = [node]
            return {nid}
        if t == "return_statement":
            nid = self._join(incoming)
            self.cfg.exprs[nid] = [node]
            self.cfg.edge(nid, _EXIT)
            return set()
        if t == "break_statement":
            nid = self._join(incoming)
            if not self.break_stack:
                raise ProofRefusal("break outside loop/switch")
            self.cfg.edge(nid, self.break_stack[-1])
            return set()
        if t == "continue_statement":
            nid = self._join(incoming)
            if not self.loop_stack:
                raise ProofRefusal("continue outside a loop")
            self.cfg.edge(nid, self.loop_stack[-1][0])
            return set()
        if t == "if_statement":
            cond = node.child_by_field_name("condition")
            cnode = self._join(incoming)
            self.cfg.exprs[cnode] = [cond] if cond is not None else []
            tentry = self.cfg.new_node()
            self.cfg.edge(cnode, tentry)
            self.cfg.if_then[cnode] = tentry
            cons = node.child_by_field_name("consequence")
            then_ends = (
                self._stmt(cons, {tentry}) if cons is not None
                else {tentry}
            )
            eentry = self.cfg.new_node()
            self.cfg.edge(cnode, eentry)
            self.cfg.if_else[cnode] = eentry
            alt = node.child_by_field_name("alternative")
            if alt is not None:
                else_ends = self._stmt(alt, {eentry})
            else:
                else_ends = {eentry}
            return then_ends | else_ends
        if t == "else_clause":
            inner = [
                c for c in node.named_children if c.type != "comment"
            ]
            return self._seq(inner, incoming)
        if t == "while_statement":
            cond = node.child_by_field_name("condition")
            body = node.child_by_field_name("body")
            if body is None:
                raise ProofRefusal("while without a body")
            cnode = self._join(incoming)
            self.cfg.exprs[cnode] = [cond] if cond is not None else []
            after = self.cfg.new_node()
            self.loop_stack.append((cnode, after))
            self.break_stack.append(after)
            try:
                body_ends = self._stmt(body, {cnode})
            finally:
                self.loop_stack.pop()
                self.break_stack.pop()
            for e in body_ends:
                self.cfg.edge(e, cnode)
            self.cfg.edge(cnode, after)
            return {after}
        if t == "do_statement":
            cond = node.child_by_field_name("condition")
            body = node.child_by_field_name("body")
            if body is None:
                raise ProofRefusal("do without a body")
            head = self._join(incoming)
            cnode = self.cfg.new_node()
            self.cfg.exprs[cnode] = [cond] if cond is not None else []
            after = self.cfg.new_node()
            self.loop_stack.append((cnode, after))
            self.break_stack.append(after)
            try:
                body_ends = self._stmt(body, {head})
            finally:
                self.loop_stack.pop()
                self.break_stack.pop()
            for e in body_ends:
                self.cfg.edge(e, cnode)
            self.cfg.edge(cnode, head)
            self.cfg.edge(cnode, after)
            return {after}
        if t == "for_statement":
            init = node.child_by_field_name("initializer")
            cond = node.child_by_field_name("condition")
            update = node.child_by_field_name("update")
            body = node.child_by_field_name("body")
            if body is None:
                raise ProofRefusal("for without a body")
            inode = self._join(incoming)
            self.cfg.exprs[inode] = [init] if init is not None else []
            cnode = self.cfg.new_node()
            self.cfg.exprs[cnode] = [cond] if cond is not None else []
            self.cfg.edge(inode, cnode)
            unode = self.cfg.new_node()
            self.cfg.exprs[unode] = [update] if update is not None else []
            after = self.cfg.new_node()
            self.loop_stack.append((unode, after))
            self.break_stack.append(after)
            try:
                body_ends = self._stmt(body, {cnode})
            finally:
                self.loop_stack.pop()
                self.break_stack.pop()
            for e in body_ends:
                self.cfg.edge(e, unode)
            self.cfg.edge(unode, cnode)
            self.cfg.edge(cnode, after)
            return {after}
        if t == "switch_statement":
            return self._switch(node, incoming)
        raise ProofRefusal(f"unsupported statement form: {t}")

    def _switch(self, node: Any, incoming: set[int]) -> set[int]:
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if body is None or body.type != "compound_statement":
            raise ProofRefusal("unsupported switch shape")
        cnode = self._join(incoming)
        self.cfg.exprs[cnode] = [cond] if cond is not None else []
        after = self.cfg.new_node()
        self.break_stack.append(after)
        has_default = False
        prev_ends: set[int] = set()
        try:
            for child in body.named_children:
                if child.type == "comment":
                    continue
                if child.type != "case_statement":
                    raise ProofRefusal(
                        "statement outside case labels in switch"
                    )
                entry = self.cfg.new_node()
                value = child.child_by_field_name("value")
                if value is None:
                    has_default = True
                else:
                    self.cfg.exprs[entry] = [value]
                self.cfg.edge(cnode, entry)
                for e in prev_ends:  # fallthrough
                    self.cfg.edge(e, entry)
                stmts = [
                    c for c in child.named_children
                    if c != value and c.type != "comment"
                ]
                prev_ends = self._seq(stmts, {entry})
        finally:
            self.break_stack.pop()
        ends = set(prev_ends)
        ends.add(after)
        if not has_default:
            self.cfg.edge(cnode, after)
        return ends


# ---------------------------------------------------------------------------
# Expression facts
# ---------------------------------------------------------------------------


def _refuse_expr_constructs(node: Any) -> None:
    for n in _walk_nodes(node):
        if n.type == "compound_statement":
            raise ProofRefusal("statement expression in expression position")
        if n.type == "function_definition":
            raise ProofRefusal("nested function definition")
        if n.type == "identifier" and _node_text(n) in _SETJMP_FAMILY:
            raise ProofRefusal(f"{_node_text(n)} reachable in the function")
        if "asm" in n.type:
            raise ProofRefusal("asm construct")


def _idents(node: Any) -> Iterator[Any]:
    for n in _walk_nodes(node):
        if n.type == "identifier":
            yield n


def _strip_parens_casts(node: Any) -> Any:
    n = node
    while n is not None:
        if n.type == "parenthesized_expression":
            inner = [c for c in n.named_children if c.type != "comment"]
            if len(inner) == 1:
                n = inner[0]
                continue
            return n
        if n.type == "cast_expression":
            v = n.child_by_field_name("value")
            if v is not None:
                n = v
                continue
            return n
        return n
    return n


def _call_callee_name(call: Any) -> str | None:
    fn = call.child_by_field_name("function")
    if fn is None:
        return None
    fn = _strip_parens_casts(fn)
    if fn.type == "identifier":
        return _node_text(fn)
    return None


def _call_args(call: Any) -> list[Any]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.named_children if c.type != "comment"]


@dataclass
class _Occurrence:
    node: Any
    name: str
    context: str  # "def" | "addr" | "deref" | "callarg" | "read" | "store"
    call: Any = None


def _classify_occurrence(occ: Any) -> _Occurrence:
    """Context of one identifier occurrence within its statement.

    Classification ascends the FULL ancestry through value-preserving
    wrappers (parentheses, casts, conditional/comma/arithmetic
    expressions), so a laundered dereference like
    ``((struct t *)q)->f`` or ``*(q + 0)`` still classifies as
    ``deref`` — the immediate-parent shape alone is spoofable.
    """
    name = _node_text(occ)
    parent = occ.parent
    # Whole-variable definition:  occ = ...  (direct only)
    if (
        parent is not None
        and parent.type == "assignment_expression"
        and parent.child_by_field_name("left") == occ
    ):
        return _Occurrence(occ, name, "def")
    if (
        parent is not None
        and parent.type == "init_declarator"
        and parent.child_by_field_name("declarator") == occ
    ):
        return _Occurrence(occ, name, "def")
    n = occ
    while n is not None and n.parent is not None:
        p = n.parent
        t = p.type
        if t == "pointer_expression":
            op = p.child_by_field_name("operator")
            arg = p.child_by_field_name("argument")
            if arg is not None and arg == n and op is not None:
                if _node_text(op) == "&":
                    if n == occ:
                        return _Occurrence(occ, name, "addr")
                    # Address of a derefed lvalue built over the
                    # value: still reaches through the pointer.
                    return _Occurrence(occ, name, "deref")
                return _Occurrence(occ, name, "deref")
        if t == "field_expression" and \
                p.child_by_field_name("argument") == n:
            return _Occurrence(occ, name, "deref")
        if t == "subscript_expression" and \
                p.child_by_field_name("argument") == n:
            return _Occurrence(occ, name, "deref")
        if t == "update_expression":
            return _Occurrence(occ, name, "deref")
        if t == "argument_list" and p.parent is not None \
                and p.parent.type == "call_expression":
            return _Occurrence(occ, name, "callarg", call=p.parent)
        if t in (
            "parenthesized_expression", "cast_expression",
            "conditional_expression", "comma_expression",
            "binary_expression", "unary_expression",
        ):
            n = p
            continue
        if t in ("expression_statement", "declaration",
                 "return_statement", "if_statement",
                 "while_statement", "do_statement", "for_statement",
                 "switch_statement", "case_statement",
                 "assignment_expression", "init_declarator"):
            break
        n = p
    return _Occurrence(occ, name, "read")


def _stmt_occurrences(node: Any, names: frozenset[str]) -> list[_Occurrence]:
    out: list[_Occurrence] = []
    for occ in _idents(node):
        if _node_text(occ) in names:
            out.append(_classify_occurrence(occ))
    return out


# ---------------------------------------------------------------------------
# Function analysis (shared substrate)
# ---------------------------------------------------------------------------


class _Analysis:
    """Parsed function + CFG + tracked sets for one claimed pointer."""

    def __init__(
        self,
        func_source: str,
        pointer_set: frozenset[str],
        *,
        target_path: str | Path,
        rel_file: str,
        vocab: Any = None,
    ) -> None:
        self.vocab = vocab
        if not func_source or len(func_source) > _MAX_SOURCE_BYTES:
            raise ProofRefusal("function source empty or too large")
        func_source = _trim_to_function(func_source)
        if re.search(r"^\s*#", func_source, re.MULTILINE):
            raise ProofRefusal(
                "preprocessor directive inside the function source"
            )
        table = _lifetime_macro_table(target_path, rel_file)
        if not table.files_scanned:
            raise ProofRefusal(
                "macro table unavailable (anchor file not readable "
                "under the target tree)"
            )
        for p in pointer_set:
            if p in table.defs or p in table.poisoned:
                raise ProofRefusal(
                    f"claimed name {p} is itself a macro in the closure"
                )
        self.locals = function_local_names(func_source)
        self.params = function_parameter_names(func_source)
        plain_tokens = _defassign_tokenize(func_source)
        self.tracked_superset = _token_tracked_superset(
            plain_tokens, pointer_set,
        )
        src_tokens = _tokenize_with_offsets(func_source)
        _certify_macros(
            src_tokens, table, self.locals, self.tracked_superset, vocab,
        )
        transformed = _transform_loop_macros(func_source, table)
        self.fn_node = _parse_function(transformed)
        body = self.fn_node.child_by_field_name("body")
        if body is None:
            raise ProofRefusal("function has no body")
        # Self-recursion invalidates every path argument made here:
        # one invocation can execute "path-exclusive" sites at two
        # recursion depths and an after-region use before the caller's
        # release.  (MUTUAL recursion through another function is part
        # of the unknown-callee residual — a callee may re-enter.)
        decl = self.fn_node.child_by_field_name("declarator")
        fn_name = None
        if decl is not None:
            d = decl
            while d is not None and d.type != "identifier":
                d = d.child_by_field_name("declarator") or (
                    d.named_children[0] if d.named_children else None
                )
            if d is not None:
                fn_name = _node_text(d)
        if fn_name:
            for occ in _idents(body):
                if _node_text(occ) == fn_name:
                    raise ProofRefusal(
                        f"function {fn_name} refers to itself — "
                        f"recursive execution defeats path reasoning"
                    )
        for stmt_node in _walk_nodes(body):
            if stmt_node.type in ("expression_statement", "declaration",
                                  "return_statement"):
                _refuse_expr_constructs(stmt_node)
        self.cfg = _CFGBuilder().build(body)
        self.pointer_set = pointer_set
        self._compute_sets()
        # Second certification pass with the parse-precise closure:
        # the token-level superset cannot see declarator shapes
        # (``struct s *q = p;``), so an alias born in a declaration
        # initializer could reach a macro that rebinds or addresses
        # it without refusing.  The first (token-level) pass made the
        # parse trustworthy; this pass re-certifies against the
        # tree-sitter alias/derived closure so both trackings agree.
        precise = self.tracked_superset | self.aliases | self.derived
        if precise - self.tracked_superset:
            _certify_macros(
                src_tokens, table, self.locals, precise, vocab,
            )

    # -- tracked sets ------------------------------------------------------

    def _compute_sets(self) -> None:
        """Path-insensitive alias / derived / retainer closures."""
        body = self.fn_node.child_by_field_name("body")
        aliases: set[str] = set(self.pointer_set)
        derived: set[str] = set()
        for _round in range(_MAX_TRACK_ROUNDS):
            grew = False
            for n in _walk_nodes(body):
                lhs_name: str | None = None
                rhs: Any = None
                if n.type == "assignment_expression":
                    left = n.child_by_field_name("left")
                    op = n.child_by_field_name("operator")
                    if (
                        left is not None and left.type == "identifier"
                        and op is not None and _node_text(op) == "="
                    ):
                        lhs_name = _node_text(left)
                        rhs = n.child_by_field_name("right")
                elif n.type == "init_declarator":
                    decl = n.child_by_field_name("declarator")
                    d = decl
                    while d is not None and d.type in (
                        "pointer_declarator", "attributed_declarator",
                        "parenthesized_declarator",
                    ):
                        d = d.child_by_field_name("declarator") or (
                            d.named_children[0] if d.named_children
                            else None
                        )
                    if d is not None and d.type == "identifier":
                        lhs_name = _node_text(d)
                        rhs = n.child_by_field_name("value")
                    else:
                        # Array (or other unresolved) declarators can
                        # stash a tracked pointer through their
                        # initializer without any assignment
                        # expression the closure would see.
                        value = n.child_by_field_name("value")
                        if value is not None and {
                            _node_text(x) for x in _idents(value)
                        } & (aliases | derived):
                            raise ProofRefusal(
                                "tracked pointer stored through a "
                                "non-identifier declarator's "
                                "initializer"
                            )
                if lhs_name is None or rhs is None:
                    continue
                stripped = _strip_parens_casts(rhs)
                rhs_idents = {
                    _node_text(x) for x in _idents(rhs)
                }
                if stripped is not None and stripped.type == "identifier" \
                        and _node_text(stripped) in aliases:
                    if lhs_name not in aliases:
                        aliases.add(lhs_name)
                        grew = True
                elif rhs_idents & (aliases | derived):
                    if lhs_name not in derived and lhs_name not in aliases:
                        derived.add(lhs_name)
                        grew = True
            if not grew:
                break
        else:
            raise ProofRefusal("alias fixpoint did not converge")
        retainers: set[str] = set()
        for n in _walk_nodes(body):
            if n.type != "call_expression":
                continue
            argnames: list[set[str]] = []
            hit = False
            for a in _call_args(n):
                names = {_node_text(x) for x in _idents(a)}
                argnames.append(names)
                if names & aliases:
                    hit = True
            if hit:
                for names in argnames:
                    retainers |= names - aliases
        self.aliases = frozenset(aliases)
        self.derived = frozenset(derived)
        self.retainers = frozenset(retainers)

    # -- site discovery ----------------------------------------------------

    def _pure_call_node(self, nid: int) -> Any | None:
        """The sole call expression when node *nid* is a pure
        ``callee(args);`` statement, else None."""
        exprs = self.cfg.exprs.get(nid, [])
        if len(exprs) != 1:
            return None
        st = exprs[0]
        if st.type != "expression_statement":
            return None
        inner = [c for c in st.named_children if c.type != "comment"]
        if len(inner) != 1 or inner[0].type != "call_expression":
            return None
        return inner[0]

    def release_sites(self, kind: str) -> list[int]:
        """CFG nodes that are pure release-call statements on a
        tracked bare-identifier argument.

        *kind*: ``"free"`` (exact release vocabulary) or ``"put"``
        (put/unpin stems + learned refcount_puts).  Strictness rules
        (each refuses rather than skipping — a silently uncounted
        release is how a real free hides from the proofs):

        - a release call on a tracked pointer that is NOT
          statement-pure refuses (the surrounding expression could
          reorder against the release);
        - a release call whose argument expression MENTIONS any
          tracked / derived / possibly-retaining name without being a
          bare tracked identifier refuses (ternary/comma/cast/deref
          laundering of the freed pointer);
        - a release-vocabulary identifier in any position other than
          the direct callee of a counted call refuses (parenthesized
          or comma-laundered callees, release verbs taken as values).
        """
        pred = (
            _is_release_callee if kind == "free" else _is_put_callee
        )
        maybe_tracked = self.aliases | self.derived | self.retainers
        sites: list[int] = []
        site_callee_ids: set[int] = set()
        for nid in list(self.cfg.exprs):
            for st in self.cfg.exprs[nid]:
                for n in _walk_nodes(st):
                    if n.type != "call_expression":
                        continue
                    callee = _call_callee_name(n)
                    if callee is None or not pred(callee, self.vocab):
                        continue
                    hit = False
                    laundered = False
                    for a in _call_args(n):
                        stripped = _strip_parens_casts(a)
                        if (
                            stripped is not None
                            and stripped.type == "identifier"
                            and _node_text(stripped) in self.aliases
                        ):
                            hit = True
                            continue
                        if {
                            _node_text(x) for x in _idents(a)
                        } & maybe_tracked:
                            laundered = True
                    if laundered:
                        raise ProofRefusal(
                            f"release call {callee} takes a "
                            f"possibly-aliasing expression of the "
                            f"claimed pointer"
                        )
                    if not hit:
                        continue
                    pure = self._pure_call_node(nid)
                    if pure is None or pure.id != n.id:
                        raise ProofRefusal(
                            f"release call {callee} is not a "
                            f"standalone statement"
                        )
                    fn_node = n.child_by_field_name("function")
                    if fn_node is not None:
                        site_callee_ids.add(fn_node.id)
                    sites.append(nid)
        # Release verbs appearing anywhere else refuse: the raw CFG
        # cannot see what a laundered callee or a stored function
        # value releases.  field_identifier occurrences are scanned
        # too: a member-callee release (``r->ops->free(p)``) never
        # surfaces through _call_callee_name OR _idents, so it was
        # invisible to both passes — the nouse/async arms then proved
        # "no release before X" over a function whose real free
        # happened through the ops table.
        body = self.fn_node.child_by_field_name("body")
        for occ in _walk_nodes(body):
            if occ.type not in ("identifier", "field_identifier"):
                continue
            if not pred(_node_text(occ), self.vocab):
                continue
            if occ.id in site_callee_ids:
                continue
            parent = occ.parent
            if (
                parent is not None
                and parent.type == "call_expression"
                and parent.child_by_field_name("function") == occ
            ):
                # A direct call that was not counted: either its
                # argument never mentions a tracked name (an
                # unrelated release — harmless to these proofs) or
                # the laundering rule above already refused.
                continue
            raise ProofRefusal(
                f"release verb {_node_text(occ)} used outside a "
                f"direct call"
            )
        return sites

    # -- queries -----------------------------------------------------------

    def after(self, nid: int) -> set[int]:
        return self.cfg.reachable_from(set(self.cfg.succ.get(nid, ())))

    def occurrences(self, nid: int, names: frozenset[str]) -> list[_Occurrence]:
        out: list[_Occurrence] = []
        for st in self.cfg.exprs.get(nid, []):
            out.extend(_stmt_occurrences(st, names))
        return out

    def refuse_global_escapes(self, *, allow_stores: bool = False) -> None:
        """Store of a tracked pointer into memory, or its address
        taken, refuses.

        The address rule always applies (a callee reached through
        ``&p`` can free or rewrite the pointer invisibly).  Stores
        are refused by default; the bracket arm passes
        ``allow_stores=True`` — its discharged claim is the
        in-function freed-then-used echo and the paired-store idiom
        takes its own reference.
        """
        body = self.fn_node.child_by_field_name("body")
        if not allow_stores:
            for n in _walk_nodes(body):
                if n.type == "assignment_expression":
                    left = n.child_by_field_name("left")
                    rhs = n.child_by_field_name("right")
                    if left is None or rhs is None:
                        continue
                    if left.type == "identifier" and (
                        _node_text(left) in self.locals
                    ):
                        # Local alias propagation — _compute_sets
                        # tracks it.  A file-scope global is an
                        # identifier too (``g_saved = p;`` is a store
                        # into memory a callee or the caller reads
                        # after the free), so only names this function
                        # declares are exempt.
                        continue
                    # Derived names (pointer arithmetic results —
                    # still inside the freed allocation) escape
                    # through memory exactly like bare aliases.
                    rhs_idents = {_node_text(x) for x in _idents(rhs)}
                    if rhs_idents & (self.aliases | self.derived):
                        raise ProofRefusal(
                            "tracked pointer stored into memory "
                            f"({_node_text(n)[:60]!r})"
                        )
        for occ in _idents(body):
            if _node_text(occ) not in self.aliases:
                continue
            if _classify_occurrence(occ).context == "addr":
                raise ProofRefusal(
                    f"address of tracked pointer "
                    f"{_node_text(occ)} is taken"
                )

    def check_nothing_after(
        self, site: int, *, allow_sites: set[int] | None = None,
        strict_names: frozenset[str] | None = None,
        weak_names: frozenset[str] | None = None,
    ) -> None:
        """No use after *site*: strict names refuse on ANY occurrence,
        weak names refuse on deref / index / call-argument use."""
        strict = (
            strict_names if strict_names is not None else self.aliases
        )
        weak = (
            weak_names if weak_names is not None
            else (self.derived | self.retainers) - strict
        )
        region = self.after(site)
        if site in region:
            raise ProofRefusal("release site is inside a loop")
        for nid in region:
            if allow_sites and nid in allow_sites:
                continue
            for occ in self.occurrences(nid, strict):
                raise ProofRefusal(
                    f"{occ.name} occurs after the release "
                    f"({occ.context})"
                )
            for occ in self.occurrences(nid, weak):
                if occ.context in ("deref", "callarg", "addr"):
                    raise ProofRefusal(
                        f"possibly-retaining {occ.name} used after "
                        f"the release ({occ.context})"
                    )


# ---------------------------------------------------------------------------
# Arms
# ---------------------------------------------------------------------------


def _arm_freepath(an: _Analysis, pointer: str) -> LifetimeProof:
    sites = an.release_sites("free")
    # Address-of and memory stores of the pointer refuse here too: a
    # free reached through a stored or addressed alias is not a
    # visible site, so path exclusivity over the visible ones would
    # prove nothing.
    an.refuse_global_escapes()
    if len(sites) < 2:
        raise ProofRefusal(
            f"fewer than two visible release sites of {pointer}"
        )
    for s in sites:
        if s in an.after(s):
            raise ProofRefusal("a release site is inside a loop")
    for i, s1 in enumerate(sites):
        for s2 in sites[i + 1:]:
            if s2 in an.after(s1) or s1 in an.after(s2):
                raise ProofRefusal(
                    "two release sites lie on one path"
                )
    return LifetimeProof(
        arm="freepath",
        pointer=pointer,
        reason=(
            f"the {len(sites)} release sites of {pointer} are pairwise "
            f"path-exclusive on the goto-resolved CFG and none is "
            f"loop-enclosed — no execution frees it twice at the "
            f"claimed sites"
        ),
        cwes=_CWE_415,
    )


def _arm_nouse(an: _Analysis, pointer: str) -> LifetimeProof:
    sites = an.release_sites("free")
    if not sites:
        raise ProofRefusal(
            f"no visible release site of {pointer}"
        )
    an.refuse_global_escapes()
    for s in sites:
        an.check_nothing_after(s)
    return LifetimeProof(
        arm="nouse",
        pointer=pointer,
        reason=(
            f"no path uses {pointer} (or any alias / possibly-"
            f"retaining object) after its releasing call — the "
            f"claimed use-after-release path does not exist"
        ),
        cwes=_CWE_416,
    )


def _arm_bracket(an: _Analysis, pointer: str) -> LifetimeProof:
    if pointer in an.params:
        raise ProofRefusal(
            f"{pointer} is a parameter — no in-function acquisition "
            f"can bracket it"
        )
    body = an.fn_node.child_by_field_name("body")
    defs: list[Any] = []
    for n in _walk_nodes(body):
        if n.type == "update_expression":
            # ``p++`` / ``--p`` rebinds the pointer between acquire
            # and release: neither an assignment_expression nor an
            # init_declarator, so the def-collector never saw it and
            # certified "single acquire definition" over a mutated
            # pointer (the release then drops p+1, not the acquired
            # object).
            if pointer in {_node_text(x) for x in _idents(n)}:
                raise ProofRefusal(
                    f"{pointer} is mutated by ++/-- between acquire "
                    f"and release"
                )
        elif n.type == "assignment_expression":
            left = _strip_parens_casts(n.child_by_field_name("left"))
            op = n.child_by_field_name("operator")
            if (
                left is not None and left.type == "identifier"
                and _node_text(left) == pointer
            ):
                # left is paren-stripped: ``(p) = x`` is the same
                # definition as ``p = x`` and must count toward the
                # single-definition premise.
                if op is None or _node_text(op) != "=":
                    raise ProofRefusal(
                        f"compound assignment to {pointer}"
                    )
                defs.append(n.child_by_field_name("right"))
        elif n.type == "init_declarator":
            decl = n.child_by_field_name("declarator")
            d = decl
            while d is not None and d.type in (
                "pointer_declarator", "attributed_declarator",
                "parenthesized_declarator",
            ):
                d = d.child_by_field_name("declarator") or (
                    d.named_children[0] if d.named_children else None
                )
            if d is not None and d.type == "identifier" \
                    and _node_text(d) == pointer:
                v = n.child_by_field_name("value")
                if v is not None:
                    defs.append(v)
    if len(defs) != 1:
        raise ProofRefusal(
            f"{pointer} has {len(defs)} definitions — the acquire "
            f"bracket needs exactly one"
        )
    rhs = _strip_parens_casts(defs[0])
    if rhs is None or rhs.type != "call_expression":
        raise ProofRefusal(
            f"{pointer} is not defined by a call"
        )
    callee = _call_callee_name(rhs)
    if callee is None or not _is_get_callee(callee, an.vocab):
        raise ProofRefusal(
            f"{pointer}'s defining call {callee!r} is not an "
            f"acquire-family (get/pin) callee"
        )
    sites = an.release_sites("put")
    if not sites:
        raise ProofRefusal(
            f"no put/unpin-family release site of {pointer}"
        )
    # The acquire must dominate every release: with the defining node
    # removed, no release may be reachable from the entry.
    def_nodes = {
        nid for nid in an.cfg.exprs
        for st in an.cfg.exprs[nid]
        for n in _walk_nodes(st)
        if n.id == defs[0].id
    }
    if not def_nodes:
        raise ProofRefusal("defining statement not found in the CFG")
    seen: set[int] = set()
    queue = [0]
    while queue:
        nid = queue.pop()
        if nid in seen or nid in def_nodes:
            continue
        seen.add(nid)
        queue.extend(
            t for t in an.cfg.succ.get(nid, ()) if t != _EXIT
        )
    if any(s in seen for s in sites):
        raise ProofRefusal(
            "a release site is reachable without passing the acquire"
        )
    # Per-callee double execution + nothing after the bracket.
    an.refuse_global_escapes(allow_stores=True)
    # Double-execution rule over the WHOLE site set: two releases on
    # one path are a double drop against the single acquisition.  The
    # one seeded exception is the pin idiom: a pin-stem acquisition
    # grants BOTH a pin and a reference by kernel convention, so
    # exactly one unpin-stem site followed by one put-stem site (or
    # vice versa) may share a path.  Same-name pairs never may.
    def _site_name(s: int) -> str:
        call = an._pure_call_node(s)
        name = _call_callee_name(call) if call is not None else None
        return name or "?"

    acquire_is_pin = "pin" in _name_components(callee)

    def _pair_allowed(s1: int, s2: int) -> bool:
        n1, n2 = _site_name(s1), _site_name(s2)
        if n1 == n2 or not acquire_is_pin:
            return False
        c1, c2 = _name_components(n1), _name_components(n2)
        return ("unpin" in c1 and "put" in c2) or (
            "unpin" in c2 and "put" in c1
        )

    # A callee carrying BOTH release stems (an unpin_put-class
    # combined drop) denotes the whole bracket close by itself; a
    # further put after it is a real over-drop the pin-idiom pair
    # exception must never launder.
    for s in sites:
        comps = _name_components(_site_name(s))
        if "unpin" in comps and "put" in comps:
            raise ProofRefusal(
                f"release site {_site_name(s)} combines unpin and "
                f"put stems — the pair rule cannot type it"
            )

    for i, s1 in enumerate(sites):
        if s1 in an.after(s1):
            raise ProofRefusal(
                f"release site {_site_name(s1)} is inside a loop"
            )
        for s2 in sites[i + 1:]:
            if s2 in an.after(s1) or s1 in an.after(s2):
                if not _pair_allowed(s1, s2):
                    raise ProofRefusal(
                        f"release sites {_site_name(s1)} and "
                        f"{_site_name(s2)} lie on one path"
                    )
    site_set = set(sites)
    for s in sites:
        an.check_nothing_after(
            s, allow_sites=site_set,
            strict_names=an.aliases,
        )
    return LifetimeProof(
        arm="bracket",
        pointer=pointer,
        reason=(
            f"{pointer} is defined only by the acquire-family call "
            f"{callee}(), which dominates every put/unpin release; "
            f"no two reference "
            f"drops share a path (the seeded pin idiom's unpin+put "
            f"pair excepted), none is loop-enclosed, and nothing "
            f"uses {pointer} after the bracket closes — the claimed "
            f"free is a paired reference drop"
        ),
        cwes=_CWE_415_416,
    )


def _arm_async(
    an: _Analysis, claimed: frozenset[str],
) -> LifetimeProof:
    # Invoked for its strictness side effects (laundered release
    # arguments and release verbs outside direct calls refuse — a
    # hidden free on the sentinel path must not escape the region
    # scan below just because its callee is not a bare name) AND for
    # the release-before-sentinel check further down.
    sites = an.release_sites("free")
    body = an.fn_node.child_by_field_name("body")
    # Locals assigned from a call (handoff results).
    call_assigned: set[str] = set()
    for n in _walk_nodes(body):
        if n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            rhs = n.child_by_field_name("right")
            if left is not None and left.type == "identifier" \
                    and rhs is not None:
                if _strip_parens_casts(rhs) is not None and \
                        _strip_parens_casts(rhs).type == "call_expression":
                    call_assigned.add(_node_text(left))

    def _is_sentinel(node: Any) -> bool:
        n = _strip_parens_casts(node)
        if n is None or n.type != "unary_expression":
            return False
        op = n.child_by_field_name("operator")
        arg = n.child_by_field_name("argument")
        return (
            op is not None and _node_text(op) == "-"
            and arg is not None and arg.type == "identifier"
            and _node_text(arg) in _ASYNC_SENTINELS
        )

    def _refined_start(nid: int) -> int:
        """Branch-precise start for an if-condition whose WHOLE test
        is ``x == -SENTINEL`` / ``x != -SENTINEL``; anything else
        starts at the node itself (conservative: both branches)."""
        if nid not in an.cfg.if_then:
            return nid
        exprs = an.cfg.exprs.get(nid, [])
        if len(exprs) != 1:
            return nid
        cond = _strip_parens_casts(exprs[0])
        if cond is None or cond.type != "binary_expression":
            return nid
        op = cond.child_by_field_name("operator")
        left = cond.child_by_field_name("left")
        right = cond.child_by_field_name("right")
        if op is None or left is None or right is None:
            return nid
        op_text = _node_text(op)
        if op_text not in ("==", "!="):
            return nid
        if not (_is_sentinel(left) or _is_sentinel(right)):
            return nid
        if op_text == "==":
            return an.cfg.if_then[nid]
        return an.cfg.if_else[nid]

    starts: list[int] = []
    for nid in list(an.cfg.exprs):
        for st in an.cfg.exprs[nid]:
            for n in _walk_nodes(st):
                if _is_sentinel(n):
                    starts.append(_refined_start(nid))
                    break
    starts = sorted(set(starts))
    if not starts:
        raise ProofRefusal(
            "no handoff-sentinel test found in the function"
        )
    # A release of a tracked object on the path INTO the sentinel test
    # is the textbook in-flight free: the handoff has already happened
    # when the sentinel is inspected, so a free that can REACH the
    # test frees memory the asynchronous completion still owns.  The
    # forward region below cannot see it — check reachability from
    # every release site to every start.
    for site in sites:
        reach = an.after(site)
        if any(st in reach or st == site for st in starts):
            raise ProofRefusal(
                "a release of the claimed object can reach the "
                "handoff-sentinel test"
            )
    # The tested/selected value must be a call result somewhere.
    if not call_assigned:
        raise ProofRefusal(
            "no local is assigned from a call — the sentinel cannot "
            "be a handoff result"
        )
    release_vocab_check = lambda name: _is_release_callee(name, an.vocab)  # noqa: E731
    strict = an.aliases  # claimed ∪ bare-copy aliases
    weak = (an.derived | an.retainers) - strict
    for start in starts:
        region = an.cfg.reachable_from({start})
        for nid in region:
            for st in an.cfg.exprs.get(nid, []):
                for n in _walk_nodes(st):
                    if n.type == "call_expression":
                        callee = _call_callee_name(n)
                        if callee is not None and \
                                release_vocab_check(callee):
                            raise ProofRefusal(
                                f"release call {callee} is reachable "
                                f"on the sentinel path"
                            )
            for occ in an.occurrences(nid, strict):
                raise ProofRefusal(
                    f"{occ.name} occurs on the sentinel path "
                    f"({occ.context})"
                )
            for occ in an.occurrences(nid, weak):
                if occ.context in ("deref", "callarg", "addr"):
                    raise ProofRefusal(
                        f"possibly-retaining {occ.name} used on the "
                        f"sentinel path ({occ.context})"
                    )
    names = ", ".join(sorted(claimed))
    return LifetimeProof(
        arm="async_handoff",
        pointer=names,
        reason=(
            f"every path from the handoff-sentinel test to exit "
            f"contains zero release-family calls and never touches "
            f"{names} — the claimed async-path free/use does not "
            f"exist"
        ),
        cwes=_CWE_415_416,
    )


def _arm_deleg(
    func_source: str,
    *,
    target_path: str | Path,
    rel_file: str,
    vocab: Any = None,
) -> LifetimeProof:
    an = _Analysis(
        func_source, frozenset(),
        target_path=target_path, rel_file=rel_file, vocab=vocab,
    )
    body = an.fn_node.child_by_field_name("body")
    stmts = [c for c in body.named_children if c.type != "comment"]
    if len(stmts) != 1 or stmts[0].type != "expression_statement":
        raise ProofRefusal(
            "body is not a single forwarding statement"
        )
    inner = [
        c for c in stmts[0].named_children if c.type != "comment"
    ]
    if len(inner) != 1 or inner[0].type != "call_expression":
        raise ProofRefusal("body statement is not a single call")
    call = inner[0]
    callee = _call_callee_name(call)
    if callee is None:
        raise ProofRefusal("forwarding callee is not a plain name")
    if not (
        _is_release_callee(callee, vocab)
        or "free" in _name_components(callee)
    ):
        raise ProofRefusal(
            f"forwarding callee {callee} is not free-family"
        )
    args = _call_args(call)
    if len(args) != 1:
        raise ProofRefusal("forwarding call takes more than one argument")
    arg = _strip_parens_casts(args[0])
    if arg is None or arg.type != "identifier" \
            or _node_text(arg) not in an.params:
        raise ProofRefusal(
            "forwarded value is not the function's own parameter"
        )
    return LifetimeProof(
        arm="deleg",
        pointer=_node_text(arg),
        reason=(
            f"the body is a single forwarding call "
            f"{callee}({_node_text(arg)}) of the function's own "
            f"parameter — a double-invocation defect lives in the "
            f"caller's exactly-once contract, not in this function"
        ),
        cwes=_CWE_415,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _claim_candidates(
    mechanism: str, func_source: str,
) -> frozenset[str]:
    """Function locals/parameters the claim's prose names."""
    names = function_local_names(func_source)
    if not names:
        return frozenset()
    return frozenset(
        w for w in _C_IDENT_RE.findall(mechanism or "") if w in names
    )


def check_lifetime_claim(
    func_source: str,
    mechanism: str,
    claim_cwes: frozenset[str],
    *,
    target_path: str | Path | None = None,
    rel_file: str | None = None,
    vocab: Any = None,
) -> LifetimeClaimResult:
    """Probe the lifetime witness arms against one dismissed claim.

    *mechanism* is the dismissed hypothesis text (applicability fences
    only — the proof is the CFG analysis over *func_source*).
    *claim_cwes* is the claim's extracted CWE set; arms whose coverage
    cannot contribute to it are skipped.  *target_path*/*rel_file*
    locate the function's file inside the analysed tree for macro
    certification (REQUIRED — without the tree's own macro table the
    CFG cannot be certified).

    Returns a :class:`LifetimeClaimResult`; every refusal is
    ``discharged=False`` with the refusing construct named.  Consumers
    must verify the claim's lifetime CWEs are a subset of
    ``covered_cwes`` and are expected to gate on the operator's
    repo-trust assertion (see module docstring).
    """

    def refusal(reason: str) -> LifetimeClaimResult:
        logger.debug("lifetime witness refusal: %s", reason)
        return LifetimeClaimResult(
            discharged=False, covered_cwes=frozenset(),
            proofs=(), reason=reason,
        )

    if not mechanism:
        return refusal("empty claim mechanism")
    if not func_source:
        return refusal("empty function source")
    if not target_path or not rel_file:
        return refusal(
            "no target tree — macro certification impossible"
        )
    lifetime_cwes = claim_cwes & _CWE_415_416
    if not lifetime_cwes:
        return refusal("claim carries no lifetime CWE")

    is_async = bool(_LT_ASYNC_RE.search(mechanism))
    concurrent = bool(_LT_CONCURRENT_ACTOR_RE.search(mechanism))
    is_df = bool(_LT_DF_RE.search(mechanism))
    is_uaf = bool(_LT_UAF_RE.search(mechanism))

    proofs: list[LifetimeProof] = []
    reasons: list[str] = []

    # W-DELEG needs no candidate pointer.
    if (
        is_df
        and lifetime_cwes == _CWE_415
        and _LT_CALLER_TWICE_RE.search(mechanism)
    ):
        try:
            proofs.append(_arm_deleg(
                func_source, target_path=target_path,
                rel_file=rel_file, vocab=vocab,
            ))
        except ProofRefusal as exc:
            reasons.append(f"deleg: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            logger.debug("deleg arm error", exc_info=True)
            reasons.append(f"deleg: internal error {type(exc).__name__}")

    candidates = _claim_candidates(mechanism, func_source)
    if not candidates and not proofs:
        return LifetimeClaimResult(
            discharged=False, covered_cwes=frozenset(), proofs=(),
            reason=(
                "claim names no local/parameter of the function; "
                + "; ".join(reasons[:3])
            ),
        )
    if len(candidates) > _MAX_CANDIDATES:
        return refusal("claim names too many candidate pointers")

    def _analysis(seed: frozenset[str]) -> _Analysis:
        return _Analysis(
            func_source, seed,
            target_path=target_path, rel_file=rel_file, vocab=vocab,
        )

    # Async-handoff arm: the claim is about the sentinel path; ALL
    # claimed objects must be untouched on it.
    if is_async and candidates:
        try:
            an = _analysis(candidates)
            proofs.append(_arm_async(an, candidates))
        except ProofRefusal as exc:
            reasons.append(f"async_handoff: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            logger.debug("async arm error", exc_info=True)
            reasons.append(
                f"async_handoff: internal error {type(exc).__name__}"
            )

    # Synchronous arms: out of family for concurrent-actor claims.
    if candidates and not concurrent and not is_async:
        # W-FREEPATH: pure double-free claims only, two-site shape,
        # exactly one claimed pointer.
        if (
            is_df and not is_uaf
            and lifetime_cwes == _CWE_415
            and _LT_TWO_SITE_RE.search(mechanism)
        ):
            if len(candidates) == 1:
                try:
                    an = _analysis(candidates)
                    proofs.append(
                        _arm_freepath(an, next(iter(candidates)))
                    )
                except ProofRefusal as exc:
                    reasons.append(f"freepath: {exc.reason}")
                except Exception as exc:  # noqa: BLE001
                    logger.debug("freepath arm error", exc_info=True)
                    reasons.append(
                        f"freepath: internal error {type(exc).__name__}"
                    )
            else:
                reasons.append(
                    "freepath: claim names more than one candidate"
                )
        # W-NOUSE / W-BRACKET: use-after-release claims.  Every
        # candidate must prove through some arm — a claim naming two
        # pointers is not discharged by proving one.
        if is_uaf:
            per_candidate: list[LifetimeProof] = []
            all_proved = True
            for cand in sorted(candidates):
                cand_seed = frozenset({cand})
                proof: LifetimeProof | None = None
                for label, fn in (
                    ("nouse", _arm_nouse), ("bracket", _arm_bracket),
                ):
                    try:
                        an = _analysis(cand_seed)
                        proof = fn(an, cand)
                        break
                    except ProofRefusal as exc:
                        reasons.append(f"{label}({cand}): {exc.reason}")
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(
                            "%s arm error", label, exc_info=True,
                        )
                        reasons.append(
                            f"{label}({cand}): internal error "
                            f"{type(exc).__name__}"
                        )
                if proof is None:
                    all_proved = False
                    break
                per_candidate.append(proof)
            if all_proved and per_candidate:
                proofs.extend(per_candidate)

    if not proofs:
        return LifetimeClaimResult(
            discharged=False, covered_cwes=frozenset(), proofs=(),
            reason="; ".join(reasons[:4]) or "no applicable arm",
        )
    covered: frozenset[str] = frozenset()
    for p in proofs:
        covered |= p.cwes
    if not lifetime_cwes <= covered:
        return LifetimeClaimResult(
            discharged=False, covered_cwes=covered,
            proofs=tuple(proofs),
            reason=(
                f"proofs cover {sorted(covered)} but the claim "
                f"carries {sorted(lifetime_cwes)}; "
                + "; ".join(reasons[:3])
            ),
        )
    return LifetimeClaimResult(
        discharged=True,
        covered_cwes=covered,
        proofs=tuple(proofs),
        reason="; ".join(f"{p.arm}: {p.reason}" for p in proofs),
    )


__all__ = [
    "LifetimeClaimResult",
    "LifetimeProof",
    "check_lifetime_claim",
]
