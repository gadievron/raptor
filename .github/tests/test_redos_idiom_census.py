"""Repo-wide census of the blank-run-quadratic regex idiom.

The idiom: a pattern compiled with ``re.MULTILINE`` whose ``^`` anchor
is immediately followed by an UNBOUNDED quantifier over an atom that
can match a newline (``^\\s*``, ``^\\s+``, ``^[\\s#]*`` ...).  Applied
to whole file content (``finditer``/``findall``/``search``), the ``^``
matches at every line start inside a run of blank lines and the
quantifier re-scans the remainder of the run from each of them —
O(n^2) on n blank lines.  Scanned-repo files are attacker-supplied, so
a planted megabyte of whitespace turns a scan pass into tens of
minutes per pattern, with no timeout on these paths.

The fix discipline is horizontal-only whitespace at the anchor
(``[^\\S\\n]``): line-leading indent never spans lines, the match set
on real inputs is unchanged, and the scan is linear.

This census exists because the idiom kept being fixed one FILE FAMILY
at a time while identical siblings shipped elsewhere.  It derives the
member set mechanically — every regex in runtime source, parsed
structurally — and asserts the set is exactly the allowlist below, so
the next member fails CI instead of waiting for the next audit.

Scope: runtime source — the shared ``runtime_file_universe()``
derivation (runtime roots incl. plugins/ hooks and the repo-root
entry modules) — plus the pattern DATA files the runtime loads and
compiles with MULTILINE-class flags (derived from the loader, not a
hardcoded file list).  Tests and dev scripts are out of scope — they
never receive attacker-controlled file content.

Detection is structural, not textual: patterns are resolved from the
AST (constants, module-level constant names, f-string/concat parts)
and parsed with ``re``'s own parser, so spellings like ``^[\\s#]*``,
``(?m)`` inline flags, and branch-embedded anchors like
``(?:^|;)\\s*`` are members too, and per-line ``^\\s*`` WITHOUT
``re.MULTILINE`` (bounded by one line) is not.

Allowlisting a member requires a justification string; the only
acceptable justifications are structural (the pattern is applied
per-line via ``.match(line)``, or the input is length-bounded by
construction).  Prefer fixing the anchor over allowlisting.

TWO-STAGE ARMS (trailing-span and anchor-restart)
-------------------------------------------------

Two further superlinear mechanisms are censused with a two-stage
design — a static rule PROPOSES members, an empirical pump oracle
DISPOSES them:

* **Trailing-span pairs** (Rule C): two adjacent unbounded quantified
  subpatterns whose consumable character sets intersect, reachable
  through optional/zero-width atoms, with a FAILABLE continuation
  after the pair (a required consuming atom OR a failable zero-width
  ``$`` / backslash-Z / backslash-b / lookaround).  A run of characters from the
  intersection can be split between the two repeats in O(n) ways and
  the failing continuation makes the engine try them all — O(n^2)
  (three overlapping spans: O(n^3)).  Recall against the empirical
  oracle is 1.00 on the corpus that derived the rule; precision is
  ~0.56, which is why the oracle stage exists.
* **Anchor-restart** (Rule R): under ``re.MULTILINE``, a ``^`` anchor
  followed (not necessarily adjacently) by an unbounded repeat that
  can cross newlines, with a failable continuation.  Every line start
  anchors a match attempt whose repeat re-scans the remaining text —
  O(lines x tail) on planted prefix-shaped lines.  This is the
  mechanism that survived the anchor-adjacent census above with the
  newline-crossing repeat one token past the anchor.

The pump oracle synthesizes an attack from the parse tree (prefix
min-model + pump run + poison for pairs; repeated prefix-shaped lines
for restarts), times the pattern's OWN call mode (anchored
``match``/``fullmatch`` call sites are measured anchored) at doubling
sizes in a hard-killed subprocess, and classifies superlinear at
growth exponent >= 1.6 with an absolute-time floor that defeats
timer noise.  The oracle is deterministic and mechanical — no LLM.

The default CI tier never runs the oracle: accepted members (static
proposals the oracle measured linear) are PINNED in
``data/redos_trailing_span_expected.json`` with a hash of their
pattern text, and the default-tier test asserts the live member set
equals the pinned set.  A new member, a drifted pattern, or a stale
pin fails CI with regeneration instructions; the regeneration tool
re-runs the oracle and REFUSES to pin a superlinear member — the fix
is the only way through.  The nightly tier re-runs the full oracle
against every pinned verdict.  Members whose attack the synthesizer
cannot build land in the NOATTACK manual-review lane: a documented
list this file pins exactly, so the lane cannot grow silently.

PATTERN TABLES: the two-stage arms' universe also covers patterns
stored in literal TABLES (list/tuple/set/dict constants, including
constructor-call entries like registry rows) and compiled through a
loop variable — ``for p in PATTERNS: re.search(p, line)`` never shows
the resolver a constant operand at the call site, and a table-shaped
member once shipped a wall-kill pattern that every call-site-only
sweep missed.  The same family's class-constant spelling
(``re.match(self.ANSI_PATTERN, line)``) resolves through a per-class
attribute map, at the call's real flags and mode.  Table entries
cannot carry call-site flags or an anchored call mode statically, so
they are judged at WORST CASE (inline flags only, unanchored
``search``).  A table member that is
superlinear at worst case but bounded or mode-corrected at every real
call site lives in the ADJUDICATED lane: pinned by identity in
``_TABLE_ADJUDICATED`` with its written-down disposition, so the lane
cannot grow silently and a NEW superlinear table entry still refuses
to pin.

SCAN-RESTART ARM (Rule S): the unanchored scan-restart family — the
follow-up arm the boundary below called for.  At a SCANNING call
site (search/finditer/findall/sub/split), ``re``'s position loop
attempts a match at every input position; when an unbounded repeat R
re-scans the remaining hostile run per attempt, cost is O(n^2)+
WITHOUT nested quantifiers and WITHOUT an adjacent overlapping pair.
Rule S proposes an unbounded repeat on the concatenation spine with
a REQUIRED consuming failable continuation whose required prefix
min-model (the "entry") is drawn from charset(R): entry == "" is the
leading-density shape (``backslash-s*X``, ``[^.]*X``), entry != "" the
planted-entry shape (multi-term ``A.*B.*C`` chains, their lazy/DOTALL
two-term degenerate case ``A.*?B``, head-dense ``,[^;]*x``).  The
position-density pump — (entry + fill)^k + poison — disposes; pins
live in ``data/redos_scan_restart_expected.json`` under the same
propose/refuse/nightly regime as the trailing-span arm, over the
same universe (call sites and pattern-table entries both).

HONEST BOUNDARY — mechanisms NO arm covers with a dedicated rule:
(1) nested-quantifier ambiguity (the classic ``(?:a+)+``
exponential) — no ADJACENT pair exists (Rule C blind) and the
ambiguity lives inside one repeat rather than in the position loop
(Rule S's pump happens to fire on some such shapes when the inner
repeat sits on the spine, but coverage is NOT claimed).  The
boundary self-check pins the exemplar shape as a non-member of Rule
C/R so nobody assumes coverage; an adversarial sweep at introduction
time measured every nested-unbounded site in the tree and found no
live member of the dangerous subclass.  That family still needs its
own membership rule and attack synthesis — a follow-up arm, not a
silent extension of these.  Also outside the static universe, by
construction: (2)
patterns assembled or learned at RUNTIME (e.g. discovered-convention
registries) — no static census can see them; their consumers own
input bounds; and (3) a pattern table in a module that never binds
``re`` itself and is compiled by ANOTHER module — cross-module
constant resolution stays out of the resolver by design, so such a
table sits with the chained-constant boundary.
"""

from __future__ import annotations

import ast
import re
import sys
import unicodedata
import unittest
from pathlib import Path

import pytest

try:  # Python 3.11+
    from re import _parser as sre_parse  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - older interpreters
    import sre_parse  # type: ignore[no-redef]

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_REPO = repo_root()

# (posix-relative path, pattern variable/first-40-chars key) -> justification.
# Empty on purpose: every historic member was fixed, not allowlisted.
_ALLOWLIST: dict[tuple[str, str], str] = {}

_RE_FUNCS = {
    "compile", "search", "match", "fullmatch", "findall",
    "finditer", "split", "sub", "subn",
}

# Raw-text gate applied before the AST pass: EVERY census arm needs a
# ``re`` binding in the file, which the parser can only produce from
# ``import re [as name]`` or ``from re import ...`` — a file whose
# NFKC-normalized text spells neither cannot produce a member, so the
# census skips its parse+walk.  (NFKC because Python normalizes
# identifiers at parse time, so a fullwidth spelling is the same
# binding to the AST and must be to the gate.)  This gate replaced
# the earlier MULTILINE-token gate when the trailing-span arms joined
# the census: those arms census EVERY pattern, not only MULTILINE
# ones, so the necessary condition is the import itself — and the
# broader gate also closes the two resolver blind spots the previous
# gate design carried (a ``from re import compile, MULTILINE`` file
# spells no ``re.``-attribute token; a numeric-literal flags operand
# — ``re.compile(p, 8)`` — spells no flag token at all).  Declared
# blind spot, same doctrine as ``_const_str_parts``'s
# spell-anchors-literally rule: an ``importlib``/``getattr``-smuggled
# ``re`` binding is invisible — bind ``re`` with a plain import.
# ``test_scan_catches_every_multiline_spelling`` plants every
# supported spelling through ``_scan_file`` so a gate regression
# fails the census's own tests, not the closure.
_RE_BINDING_GATE = re.compile(
    r"\bimport\s+re\b"        # import re [as name]
    r"|\bfrom\s+re\s+import\b",  # from re import compile, M, ...
)

# Flag names a ``from re import ...`` statement can bind bare, and
# the bit each contributes when it appears in a flags operand.
_FLAG_NAME_BITS: dict[str, int] = {
    "MULTILINE": re.MULTILINE, "M": re.MULTILINE,
    "DOTALL": re.DOTALL, "S": re.DOTALL,
    "IGNORECASE": re.IGNORECASE, "I": re.IGNORECASE,
    "VERBOSE": re.VERBOSE, "X": re.VERBOSE,
    "ASCII": re.ASCII, "A": re.ASCII,
}


def _iter_python_files() -> list[Path]:
    # The shared runtime-source derivation (runtime_universe module
    # docstring documents roots and exclusions). Versus this census's
    # previous private walk it adds plugins/ hook scripts and the
    # repo-root entry modules — both receive scanned-repo content and
    # belong to the invariant — and drops the bash launchers the old
    # candidate list carried only for the AST parse to reject.
    return runtime_file_universe(_REPO)


def _const_str_parts(node: ast.AST, consts: dict[str, str]) -> str | None:
    """Best-effort resolution of a pattern expression to a string.

    f-string interpolations and unresolvable concat operands (calls
    like ``re.escape(x)``, unknown names) become a harmless
    placeholder atom ``X`` — the anchor+quantifier prefix under test
    is always spelled literally, and dropping the whole pattern for
    one dynamic operand hid real members. A dynamic operand that
    EXPANDS to the idiom stays invisible — spell anchors literally.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        # Bytes patterns decode latin-1 (lossless byte-to-codepoint
        # map): a bytes pattern compiled with MULTILINE re-scans a
        # blank run exactly like its str twin, and the structural
        # prefix under test is ASCII either way.
        return node.value.decode("latin-1")
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif (isinstance(value, ast.FormattedValue)
                    and isinstance(value.value, ast.Name)
                    and value.format_spec is None
                    and value.conversion == -1
                    and value.value.id in consts):
                # A plain module-constant interpolation resolves like
                # the BinOp-concat spelling below — an rf-string built
                # from pattern-fragment constants is the same pattern
                # to the runtime, and the placeholder used to hide the
                # fragment's repeats from every arm.
                parts.append(consts[value.value.id])
            else:
                parts.append("X")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _const_str_parts(node.left, consts)
        right = _const_str_parts(node.right, consts)
        return (left if left is not None else "X") \
            + (right if right is not None else "X")
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, (ast.Call, ast.Attribute)):
        return "X"
    return None


def _expr_flag_bits(node: ast.AST, flag_bits: dict[str, int]) -> int:
    """Flag bits an assignment VALUE carries (attributes and known
    flag names) — the module-flag-constant closure's judge."""
    value = 0
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            value |= _FLAG_NAME_BITS.get(sub.attr, 0)
        elif isinstance(sub, ast.Name):
            value |= flag_bits.get(sub.id, 0)
    return value


# Positional index of the ``flags`` parameter per ``re`` function
# (an int literal is only a flags value at that exact position — the
# same walk that resolves flag names must not read ``re.sub``'s
# ``count`` or ``re.split``'s ``maxsplit`` as a bitmask).
_FLAGS_ARG_INDEX: dict[str, int] = {
    "compile": 1,
    "search": 2, "match": 2, "fullmatch": 2,
    "findall": 2, "finditer": 2,
    "split": 3,
    "sub": 4, "subn": 4,
}


def _flags_value(node: ast.Call, fn_name: str,
                 flag_bits: dict[str, int]) -> int:
    """Resolve a call's flags to a bitmask.

    Handles flag ATTRIBUTES under any receiver (``re.MULTILINE``,
    ``_rx.M``) anywhere in the argument list (legacy behaviour —
    attribute names are unambiguous), bare NAMES carrying flag bits
    (``from re import`` bindings and module flag constants like
    ``_FLAGS = re.MULTILINE``, both alias-aware via ``flag_bits``),
    and INT LITERALS at the function's flags position
    (``re.compile(p, 8)``) — the numeric, from-import and
    flag-constant spellings were all resolver blind spots that could
    hide a member."""
    value = 0
    named_nodes: list[ast.AST] = list(node.args[1:]) + [
        kw.value for kw in node.keywords if kw.arg == "flags"
    ]
    for operand in named_nodes:
        for sub in ast.walk(operand):
            if isinstance(sub, ast.Attribute):
                value |= _FLAG_NAME_BITS.get(sub.attr, 0)
            elif isinstance(sub, ast.Name):
                value |= flag_bits.get(sub.id, 0)
    int_nodes: list[ast.AST] = [
        kw.value for kw in node.keywords if kw.arg == "flags"
    ]
    flags_idx = _FLAGS_ARG_INDEX.get(fn_name)
    if flags_idx is not None and len(node.args) > flags_idx:
        int_nodes.append(node.args[flags_idx])
    for operand in int_nodes:
        for sub in ast.walk(operand):
            if isinstance(sub, ast.Constant) \
                    and isinstance(sub.value, int) \
                    and not isinstance(sub.value, bool):
                value |= sub.value
    return value


def _in_matches_newline(items: list) -> bool:
    """Does a character class (IN node body) match ``\\n``?"""
    negated = bool(items) and items[0][0] is sre_parse.NEGATE
    matched = False
    for op, arg in items:
        if op is sre_parse.NEGATE:
            continue
        if op is sre_parse.LITERAL and arg == 10:
            matched = True
        elif op is sre_parse.RANGE and arg[0] <= 10 <= arg[1]:
            matched = True
        elif op is sre_parse.CATEGORY:
            name = str(arg)
            if name.endswith("CATEGORY_SPACE"):
                matched = True
            elif name.endswith(("CATEGORY_NOT_WORD", "CATEGORY_NOT_DIGIT")):
                matched = True
    return not matched if negated else matched


def _node_matches_newline(node: tuple, flags: int) -> bool:
    op, arg = node
    if op is sre_parse.LITERAL:
        return arg == 10
    if op is sre_parse.IN:
        return _in_matches_newline(arg)
    if op is sre_parse.ANY:
        return bool(flags & re.DOTALL)
    if op is sre_parse.CATEGORY:  # pragma: no cover - wrapped in IN
        return str(arg).endswith("CATEGORY_SPACE")
    if op is sre_parse.SUBPATTERN:
        return any(_node_matches_newline(n, flags) for n in arg[3])
    if op is sre_parse.BRANCH:
        return any(
            _node_matches_newline(n, flags)
            for branch in arg[1] for n in branch
        )
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
        return any(_node_matches_newline(n, flags) for n in arg[2])
    return False


def _can_start_with_newline(seq, flags: int) -> bool:
    """Can ``seq`` begin matching by consuming a newline?  Walks
    through empty-matching (optional) prefixes."""
    for node in seq:
        op, arg = node
        if op is sre_parse.AT:
            continue  # zero-width
        if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
            lo, _hi, body = arg
            if _can_start_with_newline(body, flags):
                return True
            if lo == 0:
                continue  # optional — look past it
            return False
        if op is sre_parse.SUBPATTERN:
            return _can_start_with_newline(arg[3], flags)
        if op is sre_parse.BRANCH:
            return any(_can_start_with_newline(b, flags) for b in arg[1])
        return _node_matches_newline(node, flags)
    return False


def _leads_with_unbounded_newline_repeat(node: tuple, flags: int) -> bool:
    """Is ``node`` (the atom adjacent to a ``^`` anchor) an unbounded
    repeat that can start consuming at a newline — possibly wrapped in
    a group or an alternation branch (``^(?P<indent>\\s+)...``)?

    The first-set test keeps this honest: ``^(?:KEYWORD\\s*)*`` fails a
    blank-line attempt at its first literal in O(1) and is NOT a
    member, while ``^\\s*`` / ``^[\\s#]*`` re-scan the whole blank run
    from every line start inside it."""
    op, arg = node
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
        _lo, hi, body = arg
        return hi == sre_parse.MAXREPEAT and _can_start_with_newline(
            body, flags,
        )
    if op is sre_parse.SUBPATTERN:
        seq = list(arg[3])
        return bool(seq) and _leads_with_unbounded_newline_repeat(
            seq[0], flags,
        )
    if op is sre_parse.BRANCH:
        return any(
            branch and _leads_with_unbounded_newline_repeat(branch[0], flags)
            for branch in arg[1]
        )
    return False


def _ends_at_line_start(node: tuple) -> bool:
    """Does ``node`` finish having just asserted a line start?  True
    for a bare ``^`` (AT_BEGINNING) and for a group or alternation any
    of whose branches ends that way — ``(?:^|;)`` makes the FOLLOWING
    atom anchor-adjacent through its ``^`` branch, the exact idiom
    with the anchor one level down (``(?:^|;|\\})\\s*`` survived the
    top-level-only check while quadratic in production)."""
    op, arg = node
    if op is sre_parse.AT:
        return str(arg).endswith("AT_BEGINNING")
    if op is sre_parse.SUBPATTERN:
        seq = list(arg[3])
        return bool(seq) and _ends_at_line_start(seq[-1])
    if op is sre_parse.BRANCH:
        return any(
            branch and _ends_at_line_start(branch[-1])
            for branch in arg[1]
        )
    return False


def _seq_has_idiom(seq, flags: int) -> bool:
    """Anywhere in ``seq``: line-start ``^`` — bare or as a branch of
    the preceding group — immediately followed by an unbounded repeat
    whose atom can match a newline."""
    nodes = list(seq)
    for i, (op, arg) in enumerate(nodes):
        if (flags & re.MULTILINE) and _ends_at_line_start((op, arg)) \
                and i + 1 < len(nodes) \
                and _leads_with_unbounded_newline_repeat(nodes[i + 1], flags):
            return True
        # Recurse into structure.
        if op is sre_parse.SUBPATTERN:
            if _seq_has_idiom(arg[3], flags):
                return True
        elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
            if _seq_has_idiom(arg[2], flags):
                return True
        elif op is sre_parse.BRANCH:
            if any(_seq_has_idiom(b, flags) for b in arg[1]):
                return True
    return False


def _pattern_is_member(pattern: str,
                       call_flags: bool | int) -> bool:
    """``call_flags`` accepts the legacy bool (MULTILINE yes/no — the
    self-check pins use it) or the resolved flags bitmask."""
    if isinstance(call_flags, bool):
        call_flags = re.MULTILINE if call_flags else 0
    try:
        parsed = sre_parse.parse(pattern, call_flags)
    except re.error:
        return False
    flags = parsed.state.flags  # includes inline (?m) / (?s)
    if not flags & re.MULTILINE:
        return False
    return _seq_has_idiom(parsed, flags)


def _compiled_is_member(pattern: re.Pattern[str]) -> bool:
    """Membership for an already-compiled pattern (data-file corpora):
    same structural test, flags taken from the compile call."""
    if not pattern.flags & re.MULTILINE:
        return False
    try:
        parsed = sre_parse.parse(pattern.pattern, pattern.flags)
    except (re.error, ValueError):  # pragma: no cover - loader compiled it
        return False
    return _seq_has_idiom(parsed, parsed.state.flags)


def _data_file_members() -> list[tuple[str, str]]:
    """Census over pattern DATA FILES: every pattern the repo compiles
    from a data file with MULTILINE-class flags, taken from each loader
    itself, so a new corpus file, a new pattern line, or a flag change
    is picked up here automatically (never a hardcoded file list).
    AST resolution cannot see these patterns (each compile call's
    operand is a loop variable), which is exactly how a data-file
    member outlived the source census.

    Universe: every data-file regex loader in the runtime tree —

      * the preflight injection-pattern corpora (the loader globs its
        corpus directory and decides per-file which flags apply);
      * the SCA exfil-destination rules (operator-extensible JSON;
        entries compile flag-less at load, so only an inline ``(?m)``
        group makes one a member — which is precisely the spelling an
        operator extension would smuggle past the source census).
    """
    import sys

    sys.path.insert(0, str(_REPO))
    try:
        from core.security.prompt_input_preflight import _load_patterns
        from packages.sca.supply_chain import (
            exfil_destinations as _exfil,
        )
    finally:
        sys.path.remove(str(_REPO))
    members = [
        (stem, compiled.pattern)
        for stem, patterns in sorted(_load_patterns().items())
        for compiled in patterns
        if _compiled_is_member(compiled)
    ]
    members.extend(
        ("exfil_destinations", rule.pattern.pattern)
        for rule in _exfil._load_rules()
        if rule.pattern is not None and _compiled_is_member(rule.pattern)
    )
    return members


def _census_key(path: Path, pattern: str,
                assign_name: str | None) -> tuple[str, str]:
    # Keyed on (file, assigned name | pattern prefix) — line numbers
    # churn; names and patterns are stable. Out-of-repo paths (the
    # self-check's temp module) key on the bare name.
    try:
        rel = path.relative_to(_REPO).as_posix()
    except ValueError:
        rel = path.name
    return (rel, assign_name or pattern[:40])


class _Site:
    """One resolvable regex site (shared by every census arm).

    ``origin`` is ``"call"`` for a resolvable ``re.*`` call site and
    ``"table"`` for a literal-table entry judged at worst case (the
    MULTILINE arm consumes call sites only; the two-stage arms
    consume both)."""

    __slots__ = ("key", "lineno", "pattern", "flags", "mode", "name",
                 "origin")

    def __init__(self, key: tuple[str, str], lineno: int, pattern: str,
                 flags: int, mode: str, name: str | None,
                 origin: str = "call") -> None:
        self.key = key
        self.lineno = lineno
        self.pattern = pattern
        self.flags = flags
        self.mode = mode
        self.name = name
        self.origin = origin


def _table_pattern_entries(
    container: ast.expr, re_funcs: set[str],
) -> list[tuple[int, str]]:
    """String entries of one literal table (the pattern-table arm's
    per-assignment view): direct string/bytes elements, constructor-
    call arguments (registry rows like ``Hook("name", r"...")``),
    and ONE further nesting level of list/tuple/set/dict — enough for
    every table shape in the tree; deeper literals are exotic enough
    to earn resolver work when one appears.  ``re.*`` calls inside a
    table are excluded here: their constant operands are ordinary
    call sites the resolver already judges with real flags/mode."""
    def _strs(node: ast.AST, depth: int):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                yield (node.lineno, node.value)
            elif isinstance(node.value, bytes):
                yield (node.lineno, node.value.decode("latin-1"))
        elif isinstance(node, (ast.JoinedStr, ast.BinOp)):
            value = _const_str_parts(node, {})
            if value is not None:
                yield (node.lineno, value)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _RE_FUNCS:
                return
            if isinstance(func, ast.Name) and func.id in re_funcs:
                return
            for arg in list(node.args) + [k.value for k in node.keywords]:
                yield from _strs(arg, depth)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)) and depth:
            for elt in node.elts:
                yield from _strs(elt, depth - 1)
        elif isinstance(node, ast.Dict) and depth:
            for part in list(node.keys) + list(node.values):
                if part is not None:
                    yield from _strs(part, depth - 1)

    if isinstance(container, (ast.List, ast.Tuple, ast.Set)):
        parts = list(container.elts)
    else:
        parts = [part
                 for part in list(container.keys) + list(container.values)
                 if part is not None]
    entries: list[tuple[int, str]] = []
    for part in parts:
        entries.extend(_strs(part, 1))
    return entries


_METHOD_USE_RE = re.compile(
    r"\b(\w+)\s*\.\s*(match|fullmatch|search|findall|finditer"
    r"|split|sub|subn)\b"
)


def _method_uses(text: str) -> dict[str, set[str]]:
    """One pass per file: every ``NAME.<re-method>(``-shaped use,
    keyed by name — the per-site mode lookup below reads this map
    instead of re-scanning the file text per compiled pattern."""
    uses: dict[str, set[str]] = {}
    for name, method in _METHOD_USE_RE.findall(text):
        uses.setdefault(name, set()).add(method)
    return uses


def _compiled_mode(uses: dict[str, set[str]],
                   name: str | None) -> str:
    """Worst-of-uses call mode for a compiled pattern bound to
    ``name``: 'search' when any unanchored use is visible (or the
    binding is unnamed / unused / passed around), 'match' only when
    every visible use is ``match``/``fullmatch``.  The mode picks the
    engine entry point the oracle measures — an anchored call site
    has one start position, and measuring it unanchored would flag
    patterns that can never restart in production."""
    if not name or name not in uses:
        return "search"
    if uses[name] <= {"match", "fullmatch"}:
        return "match"
    return "search"


def _extract_sites(path: Path) -> list[_Site]:
    """Shared single-pass extraction feeding every census arm.

    ONE pass over the tree collects everything the membership tests
    need (the census's cost is walk-bound, and separate walks per
    collection quadrupled it):
     * re_names — names the ``re`` module is bound to in this file,
       module-level or function-local ``import re`` / ``import re
       as _re``;
     * from_funcs / from_flags — ``from re import compile as _c,
       MULTILINE`` bindings (bare-name call receivers and bare-name
       flag operands both hid members before the resolver knew the
       spelling);
     * consts — single-target constant-ish assignments, resolved
       with an empty namespace exactly as before (chained constant
       references stay unresolved by design);
     * assign_of — the name each call is assigned to (stable keys,
       and the compiled-pattern mode scan);
     * calls — candidate ``re``-function call sites, judged against
       the COMPLETE binding sets after the walk (an ``import re``
       later in walk order than a call site must still count).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError):
        return []  # binary libexec helper or undecodable
    if _RE_BINDING_GATE.search(
            unicodedata.normalize("NFKC", text)) is None:
        return []  # no ``re`` binding spelling — cannot be a member
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []  # non-Python libexec helper (shell) or unparseable

    re_names: set[str] = set()
    from_funcs: dict[str, str] = {}
    flag_bits: dict[str, int] = {}
    flag_assigns: list[tuple[list[str], ast.expr]] = []
    consts: dict[str, str] = {}
    assign_of: dict[ast.Call, str] = {}
    calls: list[tuple[ast.Call, str | None, str | None]] = []
    tables: list[tuple[str, ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "re":
                    re_names.add(alias.asname or "re")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "re" and not node.level:
                for alias in node.names:
                    bound = alias.asname or alias.name
                    if alias.name in _RE_FUNCS:
                        from_funcs[bound] = alias.name
                    if alias.name in _FLAG_NAME_BITS:
                        flag_bits[bound] = _FLAG_NAME_BITS[alias.name]
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            # Plain single- AND multi-target (``_A = _B = ...``) AND
            # annotated (``_P: str = ...``) assignments: each spelling
            # smuggled a planted member past the single-target-only
            # resolver.
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets
                           if isinstance(t, ast.Name)]
            else:
                targets = ([node.target.id]
                           if isinstance(node.target, ast.Name) else [])
            if not targets or node.value is None:
                continue
            if isinstance(node.value, ast.Call):
                assign_of[node.value] = targets[0]
                continue
            if isinstance(node.value,
                          (ast.Constant, ast.JoinedStr, ast.BinOp)):
                value = _const_str_parts(node.value, {})
                if value is not None:
                    for name in targets:
                        consts[name] = value
            elif isinstance(node.value,
                            (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                # Literal pattern-table candidate: judged after the
                # walk (the ``re``-function name set must be complete
                # so nested ``re.*`` calls can be excluded).
                tables.append((targets[0], node.value))
            # Every non-call assignment is a flag-constant candidate
            # (``_FLAGS = re.MULTILINE`` is an Attribute value,
            # ``re.M | re.S`` a BinOp) — judged after the walk.
            flag_assigns.append((targets, node.value))
        elif isinstance(node, ast.Call) and node.args:
            if isinstance(node.func, ast.Attribute) \
                    and node.func.attr in _RE_FUNCS \
                    and isinstance(node.func.value, ast.Name):
                calls.append((node, node.func.value.id, node.func.attr))
            elif isinstance(node.func, ast.Name):
                calls.append((node, None, node.func.id))

    # Class-attribute pattern constants: ``re.match(self.ANSI_PATTERN,
    # line)`` shows the resolver an Attribute operand a bare-name
    # constant map cannot see (the same in-class-body family as the
    # pattern tables above).  Resolved PER CLASS so two classes'
    # same-named constants never cross: each ClassDef's direct-body
    # string assignments feed only the calls inside that class (walk
    # order is outer-to-inner, so the innermost class wins for nested
    # classes).
    class_attr_consts: dict[ast.Call, dict[str, str]] = {}
    for cls_node in ast.walk(tree):
        if not isinstance(cls_node, ast.ClassDef):
            continue
        attrs: dict[str, str] = {}
        for stmt in cls_node.body:
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                continue
            if isinstance(stmt, ast.Assign):
                attr_names = [t.id for t in stmt.targets
                              if isinstance(t, ast.Name)]
            else:
                attr_names = ([stmt.target.id]
                              if isinstance(stmt.target, ast.Name) else [])
            if not attr_names or stmt.value is None:
                continue
            value = _const_str_parts(stmt.value, {})
            if value is not None:
                for attr_name in attr_names:
                    attrs[attr_name] = value
        if not attrs:
            continue
        for sub in ast.walk(cls_node):
            if isinstance(sub, ast.Call) and sub.args:
                class_attr_consts[sub] = attrs

    # Close flag_bits over module flag constants — iterated so a flag
    # constant bound to ANOTHER flag constant still resolves (each
    # pass adds bits to at least one name or stops, so it terminates).
    changed = True
    while changed:
        changed = False
        for targets, value in flag_assigns:
            bits = _expr_flag_bits(value, flag_bits)
            if not bits:
                continue
            for name in targets:
                if flag_bits.get(name, 0) | bits != flag_bits.get(name, 0):
                    flag_bits[name] = flag_bits.get(name, 0) | bits
                    changed = True

    sites: list[_Site] = []
    uses: dict[str, set[str]] | None = None
    for node, receiver, fn in calls:
        if receiver is not None:
            if receiver not in re_names:
                continue
            fn_name = fn
        else:
            fn_name = from_funcs.get(fn or "")
            if fn_name is None:
                continue
        arg = node.args[0]
        pattern = None
        if (isinstance(arg, ast.Attribute)
                and isinstance(arg.value, ast.Name)
                and arg.value.id in ("self", "cls")):
            # Resolve BEFORE the generic fallback: an unresolved
            # Attribute otherwise degrades to the placeholder atom
            # and the real pattern text is never judged.
            pattern = class_attr_consts.get(node, {}).get(arg.attr)
        if pattern is None:
            pattern = _const_str_parts(arg, consts)
        if pattern is None:
            continue
        flags = _flags_value(node, fn_name, flag_bits)
        name = assign_of.get(node)
        if fn_name == "compile":
            if uses is None:
                uses = _method_uses(text)
            mode = _compiled_mode(uses, name)
        elif fn_name in ("match", "fullmatch"):
            mode = "match"
        else:
            mode = "search"
        sites.append(_Site(_census_key(path, pattern, name),
                           node.lineno, pattern, flags, mode, name))
    # Literal pattern tables (compiled through a loop variable, so no
    # call site ever shows the resolver a constant operand).  Flags
    # and call mode are statically unknowable per entry — judged at
    # WORST CASE: inline flags only, unanchored search.  Members that
    # are superlinear at worst case but bounded/mode-corrected at
    # their real call sites live in the identity-pinned
    # ``_TABLE_ADJUDICATED`` lane.
    re_like = set(from_funcs)
    for table_name, container in tables:
        for index, (lineno, pattern) in enumerate(
                _table_pattern_entries(container, re_like)):
            entry_name = f"{table_name}[{index}]"
            sites.append(_Site(
                _census_key(path, pattern, entry_name),
                lineno, pattern, 0, "search", entry_name,
                origin="table",
            ))
    return sites


def _scan_file(path: Path) -> list[tuple[tuple[str, str], int]]:
    """MULTILINE-idiom arm view of the shared extraction (kept as the
    self-checks' planting surface).  Call-site origin only: a table
    entry carries no call-site flags, so the MULTILINE arm — whose
    membership is flag-driven — keeps its original universe; the
    two-stage arms consume both origins."""
    return [
        (site.key, site.lineno)
        for site in _extract_sites(path)
        if site.origin == "call"
        and _pattern_is_member(site.pattern, site.flags)
    ]


_ALL_SITES_CACHE: list[_Site] | None = None


def _all_runtime_sites() -> list[_Site]:
    """Whole-tree extraction, computed once per process — every arm's
    tests share it, so the parse cost is paid a single time."""
    global _ALL_SITES_CACHE
    if _ALL_SITES_CACHE is None:
        sites: list[_Site] = []
        for path in _iter_python_files():
            sites.extend(_extract_sites(path))
        _ALL_SITES_CACHE = sites
    return _ALL_SITES_CACHE



# ═════════════════════════════════════════════════════════════════════
# Trailing-span / anchor-restart arms (two-stage: static rule proposes,
# empirical pump oracle disposes — see the module docstring).
# ═════════════════════════════════════════════════════════════════════

_MAXREP = sre_parse.MAXREPEAT
# Probe alphabet for char-set reasoning: ASCII plus a NUL, NBSP and a
# line separator so negated classes keep non-trivial members.
_PROBE: list[int] = [*range(1, 128), 0, 160, 0x2028]

_EXPECTED_FILE = Path(__file__).resolve().parent / "data" / \
    "redos_trailing_span_expected.json"

# Growth exponent at or above which the oracle calls a member
# superlinear (quadratic measures ~2.0), and the absolute-time floor
# below which a top-probe measurement is linear-with-noise rather
# than evidence (a genuinely quadratic member clears 20ms by
# n=32000; log-ratios over sub-5ms probes flap with scheduler
# noise). The nightly re-check adds head-room on top (see
# test_nightly_oracle_agrees_with_pins) so a pinned-linear member
# only fails on a real regression, not on a loaded runner.
_SUPERLINEAR_EXP = 1.6
_TRUST_FLOOR_S = 5e-3

# ── Adjudicated table members ────────────────────────────────────────
# Table entries are judged at WORST CASE (inline flags, unanchored
# search) because their real flags/mode are statically unknowable.  A
# member that measures superlinear at worst case may still be sound in
# production when EVERY call site bounds the subject or anchors the
# call; such members are pinned HERE by pattern digest with their
# written-down disposition.  The bar for an entry: (1) every call site
# verified by hand, (2) the bound/mode stated, (3) the worst bounded
# cost measured and acceptable.  Regeneration turns these digests into
# ``adjudicated`` pins instead of refusing; anything not listed still
# refuses, so the lane cannot grow silently.  Currently EMPTY: every
# table member that measured superlinear at introduction was fixed
# outright (a 16 KB-capped quadratic still cost ~1.6 s per line —
# bounded was not acceptable).
_TABLE_ADJUDICATED: dict[str, str] = {}


def _cat_set(name: str) -> set[int]:
    name = str(name)
    if name.endswith("CATEGORY_SPACE"):
        return {c for c in _PROBE if chr(c).isspace()}
    if name.endswith("CATEGORY_NOT_SPACE"):
        return {c for c in _PROBE if not chr(c).isspace()}
    if name.endswith("CATEGORY_WORD"):
        return {c for c in _PROBE if chr(c).isalnum() or c == 95}
    if name.endswith("CATEGORY_NOT_WORD"):
        return {c for c in _PROBE if not (chr(c).isalnum() or c == 95)}
    if name.endswith("CATEGORY_DIGIT"):
        return {c for c in _PROBE if chr(c).isdigit()}
    if name.endswith("CATEGORY_NOT_DIGIT"):
        return {c for c in _PROBE if not chr(c).isdigit()}
    return set(_PROBE)  # unknown category: be permissive


def _in_set(items: list) -> set[int]:
    negated = bool(items) and items[0][0] is sre_parse.NEGATE
    got: set[int] = set()
    for op, arg in items:
        if op is sre_parse.NEGATE:
            continue
        if op is sre_parse.LITERAL:
            got.add(arg)
        elif op is sre_parse.RANGE:
            got |= {c for c in _PROBE if arg[0] <= c <= arg[1]}
        elif op is sre_parse.CATEGORY:
            got |= _cat_set(arg)
    return (set(_PROBE) - got) if negated else got


def _charset(node: tuple, flags: int) -> set[int]:
    """Every probe char the node can consume (union over structure)."""
    op, arg = node
    if op is sre_parse.LITERAL:
        return {arg}
    if op is sre_parse.NOT_LITERAL:
        return set(_PROBE) - {arg}
    if op is sre_parse.IN:
        return _in_set(arg)
    if op is sre_parse.ANY:
        return set(_PROBE) if flags & re.DOTALL else set(_PROBE) - {10}
    if op is sre_parse.SUBPATTERN:
        return _seq_charset(arg[3], flags)
    if op is sre_parse.BRANCH:
        out: set[int] = set()
        for branch in arg[1]:
            out |= _seq_charset(branch, flags)
        return out
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
        return _seq_charset(arg[2], flags)
    return set()  # AT / ASSERT / GROUPREF: zero-width or unknown


def _seq_charset(seq, flags: int) -> set[int]:
    out: set[int] = set()
    for node in seq:
        out |= _charset(node, flags)
    return out


def _is_unbounded_repeat(node: tuple) -> bool:
    op, arg = node
    return op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT) \
        and arg[1] == _MAXREP


def _is_zero_width(node: tuple) -> bool:
    return node[0] in (sre_parse.AT, sre_parse.ASSERT,
                       sre_parse.ASSERT_NOT)


def _is_transparent(node: tuple) -> bool:
    """Can the engine pass this node consuming nothing?"""
    op, arg = node
    if _is_zero_width(node):
        return True
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT) \
            and arg[0] == 0:
        return True
    if op is sre_parse.SUBPATTERN:
        return all(_is_transparent(n) for n in arg[3])
    if op is sre_parse.BRANCH:
        return any(all(_is_transparent(n) for n in b) for b in arg[1])
    return False


def _tail_verdict(tail_nodes: list, flags: int) -> dict:
    """Classify the continuation after a pair: does a required
    consuming atom or a failable zero-width assertion follow?  (Rule
    C's failable-continuation test — B's consuming-only variant was
    recall-blind on ``$``-terminated pairs.)"""
    consuming = False
    failable = False
    first_consumable: set[int] = set()
    for i, node in enumerate(tail_nodes):
        op, arg = node
        if _is_zero_width(node):
            failable = True  # $, \b, ^ mid-input, lookarounds
            continue
        if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
            if arg[0] > 0:
                consuming = True
                first_consumable |= _seq_charset(arg[2], flags)
                break
            continue  # optional: transparent, keep walking
        if op is sre_parse.SUBPATTERN:
            inner = _tail_verdict(list(arg[3]) + tail_nodes[i + 1:],
                                  flags)
            consuming = consuming or inner["consuming"]
            failable = failable or inner["failable_zw"]
            first_consumable |= set(inner["first_consumable"])
            break
        if op is sre_parse.BRANCH:
            for branch in arg[1]:
                inner = _tail_verdict(list(branch), flags)
                consuming = consuming or inner["consuming"]
                failable = failable or inner["failable_zw"]
                first_consumable |= set(inner["first_consumable"])
            break
        consuming = True  # plain consuming atom
        first_consumable |= _charset(node, flags)
        break
    return {"consuming": consuming, "failable_zw": failable,
            "first_consumable": sorted(first_consumable)}


def _find_pairs(seq, flags: int, tail_after=()) -> list[dict]:
    """Adjacent overlapping unbounded-repeat pairs (Rule A universe),
    each with its Rule C continuation verdict."""
    pairs: list[dict] = []
    nodes = list(seq)
    for i, node in enumerate(nodes):
        op, arg = node
        rest = nodes[i + 1:] + list(tail_after)
        if op is sre_parse.SUBPATTERN:
            pairs.extend(_find_pairs(arg[3], flags, rest))
        elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
            pairs.extend(_find_pairs(arg[2], flags, rest))
        elif op is sre_parse.BRANCH:
            for branch in arg[1]:
                pairs.extend(_find_pairs(branch, flags, rest))
        if not _is_unbounded_repeat(node):
            continue
        cs1 = _charset(node, flags)
        for k, nxt in enumerate(rest):
            repeat2 = None
            if _is_unbounded_repeat(nxt):
                repeat2 = nxt
            elif nxt[0] is sre_parse.SUBPATTERN:
                lead = next(
                    (n for n in nxt[1][3] if not _is_zero_width(n)),
                    None,
                )
                if lead is not None and _is_unbounded_repeat(lead):
                    repeat2 = lead
            if repeat2 is not None:
                overlap = cs1 & _charset(repeat2, flags)
                if overlap:
                    pairs.append({
                        "pump": sorted(overlap),
                        "tail": _tail_verdict(rest[k + 1:], flags),
                        "r1_node": node,
                    })
                if not _is_transparent(nxt):
                    break
                continue
            if _is_transparent(nxt):
                continue
            break
    return pairs


def _find_restart_entries(parsed, flags: int) -> list[tuple]:
    """Rule R proposer: under MULTILINE, a ``^`` anchor followed (not
    necessarily adjacently) by an unbounded repeat whose charset can
    include a newline, with a failable continuation.  Returns
    (prefix_nodes, repeat_node) entries for attack synthesis."""
    if not flags & re.MULTILINE:
        return []
    entries: list[tuple] = []

    def walk(seq, tail_after=()):
        nodes = list(seq)
        anchored_from = None
        for i, node in enumerate(nodes):
            op, arg = node
            if op is sre_parse.AT and str(arg).endswith("AT_BEGINNING"):
                anchored_from = i
                continue
            rest = nodes[i + 1:] + list(tail_after)
            if op is sre_parse.SUBPATTERN:
                walk(arg[3], rest)
            elif op is sre_parse.BRANCH:
                for branch in arg[1]:
                    walk(branch, rest)
            elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
                walk(arg[2], rest)
            if anchored_from is None:
                continue
            newline_capable = (
                (_is_unbounded_repeat(node)
                 and 10 in _charset(node, flags))
                or (op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT)
                    and arg[1] == _MAXREP
                    and 10 in _seq_charset(arg[2], flags))
            )
            if newline_capable:
                verdict = _tail_verdict(rest, flags)
                if verdict["consuming"] or verdict["failable_zw"]:
                    entries.append(
                        (nodes[anchored_from + 1:i], node),
                    )

    walk(parsed)
    return entries


class _Unsupported(Exception):
    """Attack synthesis cannot model this node (NOATTACK lane)."""


def _gen_min(node: tuple, flags: int) -> str:
    """Minimal model of a node — the synthesis prefix generator."""
    op, arg = node
    if op is sre_parse.LITERAL:
        return chr(arg)
    if op is sre_parse.NOT_LITERAL:
        return "a" if arg != 97 else "b"
    if op is sre_parse.IN:
        chars = _in_set(arg)
        if not chars:
            raise _Unsupported("empty class")
        for preferred in (97, 48, 32, 46):
            if preferred in chars:
                return chr(preferred)
        return chr(sorted(chars)[0])
    if op is sre_parse.ANY:
        return "a"
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
        low = arg[0]
        return "".join(
            _gen_min_seq(arg[2], flags) for _ in range(min(low, 5))
        )
    if op is sre_parse.SUBPATTERN:
        return _gen_min_seq(arg[3], flags)
    if op is sre_parse.BRANCH:
        for branch in arg[1]:
            try:
                return _gen_min_seq(branch, flags)
            except _Unsupported:
                continue
        raise _Unsupported("no generable branch")
    if op is sre_parse.AT:
        return ""
    if op in (sre_parse.ASSERT, sre_parse.ASSERT_NOT):
        return ""  # hope the assertion holds on the synthesized text
    if op is sre_parse.CATEGORY:  # pragma: no cover - wrapped in IN
        chars = _cat_set(arg)
        return chr(sorted(chars)[0]) if chars else ""
    raise _Unsupported(f"cannot generate {op}")


def _gen_min_seq(seq, flags: int) -> str:
    return "".join(_gen_min(node, flags) for node in seq)


def _pump_units(pair: dict, flags: int) -> list[str]:
    """Pump units for a pair: the single overlap char, plus the
    min-model STRING of the first repeat's body — word-granularity
    loops (whole-keyword repeats) only expose their split ambiguity to
    whole-word pumps, a synthesis blind spot the review campaign
    demonstrated on the C-declaration matchers."""
    units = [chr(32 if 32 in pair["pump"] else pair["pump"][0])]
    op, arg = pair["r1_node"]
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
        try:
            body = _gen_min_seq(arg[2], flags)
        except _Unsupported:
            body = ""
        if len(body) > 1:
            units.append(body)
    return units


def _build_pair_attack(parsed, flags: int, pair: dict, n: int,
                       unit: str) -> str | None:
    """prefix (min-model of everything before the pair) + pump run +
    poison (outside the pump set and the continuation's first set)."""
    pump_char = chr(32 if 32 in pair["pump"] else pair["pump"][0])
    bad = set(pair["pump"]) | set(pair["tail"]["first_consumable"])
    poison = next(
        (chr(c) for c in (1, 46, 59, 88, 10, 33) if c not in bad),
        "\x01",
    )

    def walk(seq, acc: list[str]):
        for node in seq:
            op, arg = node
            if node is pair["r1_node"]:
                return "".join(acc)
            if op is sre_parse.SUBPATTERN:
                found = walk(arg[3], acc[:])
                if found is not None:
                    return found
            elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
                found = walk(arg[2], acc[:])
                if found is not None:
                    return found
            elif op is sre_parse.BRANCH:
                for branch in arg[1]:
                    found = walk(branch, acc[:])
                    if found is not None:
                        return found
            try:
                acc.append(_gen_min(node, flags))
            except _Unsupported:
                acc.append("")
        return None

    prefix = walk(parsed, []) or ""
    if len(unit) == 1:
        return prefix + pump_char * n + poison
    repeats = max(2, n // max(1, len(unit)))
    return prefix + unit * repeats + poison


def _build_restart_attack(parsed, flags: int, entry: tuple,
                          k: int) -> str | None:
    """k lines each matching the pattern's anchored prefix followed
    by a partial repeat fill: every line start anchors an attempt
    whose newline-crossing repeat re-scans the tail."""
    prefix_nodes, repeat = entry
    try:
        prefix = "".join(_gen_min(n, flags) for n in prefix_nodes)
    except _Unsupported:
        return None
    op, arg = repeat
    try:
        body = _gen_min_seq(arg[2], flags) if op in (
            sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT) else ""
    except _Unsupported:
        body = ""
    if body.strip() == "" or "\n" in body:
        wordish = [c for c in sorted(_charset(repeat, flags))
                   if chr(c).isalnum()]
        filler = (chr(wordish[0]) * 2 + " ") * 4 if wordish else "  "
    else:
        filler = (body + " ") * 4
    line = (prefix + filler).rstrip("\n")
    if not line.strip():
        line = prefix + "x"
    return (line + "\n") * k



def _site_rules(site: _Site) -> tuple[bool, bool, list, list]:
    """(rule_c, rule_r, pairs, restart_entries) for one site."""
    try:
        parsed = sre_parse.parse(site.pattern, site.flags)
    except (re.error, ValueError, OverflowError):
        return (False, False, [], [])
    flags = parsed.state.flags  # includes inline (?m)/(?s)
    pairs = _find_pairs(parsed, flags)
    rule_c = any(
        pair["tail"]["consuming"] or pair["tail"]["failable_zw"]
        for pair in pairs
    )
    entries = _find_restart_entries(parsed, flags)
    return (rule_c, bool(entries), pairs, entries)


def _trailing_span_members() -> dict[tuple[str, str], dict]:
    """The two-stage arms' PROPOSED member set over runtime source:
    every site Rule C or Rule R flags, keyed like the MULTILINE arm,
    with the pattern digest the pin file validates against."""
    import hashlib

    members: dict[tuple[str, str], dict] = {}
    for site in _all_runtime_sites():
        rule_c, rule_r, _pairs, _entries = _site_rules(site)
        if not (rule_c or rule_r):
            continue
        digest = hashlib.sha256(
            f"{site.flags}:{site.mode}:{site.pattern}".encode(),
        ).hexdigest()[:12]
        record = members.setdefault(site.key, {
            "digests": set(), "rules": set(), "sites": [],
        })
        record["digests"].add(digest)
        record["rules"].add("C" if rule_c else "R")
        if rule_r:
            record["rules"].add("R")
        record["sites"].append(
            (site.lineno, site.pattern, site.flags, site.mode),
        )
    return members


def _load_expected() -> dict:
    import json

    with _EXPECTED_FILE.open(encoding="utf-8") as fh:
        return json.load(fh)


def _oracle_probe_lines(pattern: str, flags: int, mode: str,
                        kind: str, index: int, unit: str) -> None:
    """Worker body (runs in a hard-killed subprocess): print
    ``n dt`` probe lines for one attack lane at doubling sizes."""
    import time

    if kind == "scan":
        _scan_oracle_probe_lines(pattern, flags, index)
        return
    try:
        parsed = sre_parse.parse(pattern, flags)
    except (re.error, ValueError):
        print("NOPARSE")
        return
    eff_flags = parsed.state.flags
    if kind == "pair":
        pairs = _find_pairs(parsed, eff_flags)
        if index >= len(pairs):
            print("NOLANE")
            return
        pair = pairs[index]

        def attack(n: int) -> str | None:
            return _build_pair_attack(parsed, eff_flags, pair, n, unit)
    else:
        entries = _find_restart_entries(parsed, eff_flags)
        if index >= len(entries):
            print("NOLANE")
            return
        entry = entries[index]

        def attack(n: int) -> str | None:
            return _build_restart_attack(parsed, eff_flags, entry, n)

    rx = re.compile(pattern, flags)
    if kind == "restart":
        def run(text: str) -> None:
            for _ in rx.finditer(text):
                pass
    elif mode == "match":
        def run(text: str) -> None:
            rx.match(text)
    else:
        def run(text: str) -> None:
            rx.search(text)
    n = 500
    while n <= 32000:
        try:
            text = attack(n)
        except _Unsupported:
            text = None
        if text is None:
            print("NOATTACK")
            return
        start = time.perf_counter()
        run(text)
        elapsed = time.perf_counter() - start
        print(n, f"{elapsed:.6f}", flush=True)
        if elapsed > 1.0:
            break
        n *= 2


def _oracle_lane(pattern: str, flags: int, mode: str, kind: str,
                 index: int, unit: str,
                 timeout_s: float = 14.0) -> tuple[float | None, str]:
    """One hard-killed oracle lane: (exponent | None, status)."""
    import json
    import math
    import subprocess
    import sys

    request = json.dumps({
        "pattern": pattern, "flags": flags, "mode": mode,
        "kind": kind, "index": index, "unit": unit,
    })
    try:
        proc = subprocess.run(
            [sys.executable, __file__, "--oracle-worker"],
            input=request, capture_output=True, text=True,
            timeout=timeout_s,
        )
        lines = proc.stdout.strip().splitlines()
        killed = False
    except subprocess.TimeoutExpired as exc:
        lines = (exc.stdout or "").strip().splitlines()
        killed = True
    probes: list[tuple[int, float]] = []
    status = "ok"
    for line in lines:
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            probes.append((int(parts[0]), float(parts[1])))
        elif parts:
            status = parts[0]
    if killed:
        return (99.0, "wall")
    if status in ("NOATTACK", "NOPARSE", "NOLANE"):
        return (None, status)
    if len(probes) == 1 and probes[0][1] > 1.0:
        return (99.0, "wall")  # first probe already over the wall
    if len(probes) < 2:
        return (None, "short")
    (n1, t1), (n2, t2) = probes[-2], probes[-1]
    if t2 < _TRUST_FLOOR_S:
        # Too fast to trust a log-ratio exponent: a genuinely
        # quadratic member clears 20ms by n=32000.
        return (1.0, "fast")
    return (math.log(t2 / max(t1, 1e-7)) / math.log(n2 / n1), "ok")


def _oracle_classify(pattern: str, flags: int,
                     mode: str) -> tuple[float | None, bool]:
    """(worst exponent | None, any-lane-synthesized) across pair
    lanes (both pump units) and restart lanes."""
    try:
        parsed = sre_parse.parse(pattern, flags)
    except (re.error, ValueError):
        return (None, False)
    eff_flags = parsed.state.flags
    worst: float | None = None
    synthesized = False
    pairs = _find_pairs(parsed, eff_flags)
    for index, pair in enumerate(pairs[:3]):
        for unit in _pump_units(pair, eff_flags)[:2]:
            exponent, status = _oracle_lane(
                pattern, flags, mode, "pair", index, unit,
            )
            if status not in ("NOATTACK", "NOPARSE", "NOLANE"):
                synthesized = True
            if exponent is not None and (worst is None
                                         or exponent > worst):
                worst = exponent
    entries = _find_restart_entries(parsed, eff_flags)
    for index in range(min(len(entries), 3)):
        exponent, status = _oracle_lane(
            pattern, flags, mode, "restart", index, "",
        )
        if status not in ("NOATTACK", "NOPARSE", "NOLANE"):
            synthesized = True
        if exponent is not None and (worst is None or exponent > worst):
            worst = exponent
    return (worst, synthesized)


def _regen_expected(workers: int = 8) -> int:
    """Re-run the pump oracle over every proposed member and rewrite
    the pin file.  REFUSES to pin a superlinear member — fixing the
    pattern is the only way through; refusal is the design."""
    import json
    from concurrent.futures import ThreadPoolExecutor

    members = _trailing_span_members()
    rows: dict[str, dict] = {}
    failures: list[str] = []

    def classify(item):
        key, record = item
        lineno, pattern, flags, mode = record["sites"][0]
        exponent, synthesized = _oracle_classify(pattern, flags, mode)
        return key, record, exponent, synthesized

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for key, record, exponent, synthesized in pool.map(
                classify, sorted(members.items())):
            if not synthesized:
                verdict = "noattack"
            elif exponent is not None and exponent >= 1.5:
                if record["digests"] <= set(_TABLE_ADJUDICATED):
                    # Worst-case-superlinear table member with a
                    # written-down call-site disposition (see
                    # _TABLE_ADJUDICATED) — pinned, not refused.
                    verdict = "adjudicated"
                else:
                    # Regeneration margin sits BELOW the census
                    # threshold: a member measuring in the 1.5-1.6
                    # noise band must be fixed, not pinned at the
                    # edge of flapping.
                    failures.append(
                        f"{key[0]} :: {key[1]} measures superlinear "
                        f"(exp={exponent:.2f}) — fix the pattern; the "
                        f"pin file only accepts oracle-linear members "
                        f"(or an adjudicated table entry, see "
                        f"_TABLE_ADJUDICATED)",
                    )
                    continue
            else:
                verdict = "linear"
            rows["\x1f".join(key)] = {
                "digests": sorted(record["digests"]),
                "rules": sorted(record["rules"]),
                "verdict": verdict,
                "exp": None if exponent is None else round(exponent, 2),
            }
    if failures:
        print("REFUSED to regenerate:")
        for failure in failures:
            print(" ", failure)
        return 1
    _EXPECTED_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_comment": (
            "Pinned trailing-span/anchor-restart census members: "
            "static proposals (Rule C / Rule R) the pump oracle "
            "measured linear, keyed file\x1fname with pattern "
            "digests. Regenerate with: python3 "
            ".github/tests/test_redos_idiom_census.py "
            "--regen-trailing-span  (the tool refuses superlinear "
            "members; hand-editing a verdict is caught by the "
            "nightly oracle re-check)."
        ),
        "members": dict(sorted(rows.items())),
    }
    with _EXPECTED_FILE.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
        fh.write("\n")
    noatt = [k for k, v in rows.items() if v["verdict"] == "noattack"]
    print(f"pinned {len(rows)} members "
          f"({len(noatt)} noattack) -> {_EXPECTED_FILE}")
    return 0


# ═════════════════════════════════════════════════════════════════════
# Scan-restart arm (Rule S): unanchored position-loop superlinearity.
# Static rule proposes, position-density pump oracle disposes.
# ═════════════════════════════════════════════════════════════════════

_SCAN_EXPECTED_FILE = Path(__file__).resolve().parent / "data" / \
    "redos_scan_restart_expected.json"

# Rule S's identity-pinned manual-review lane, digest-keyed like
# ``_TABLE_ADJUDICATED``: string-table entries the worst-case table
# extraction admits but that are NEVER COMPILED as regexes — output
# text a module emits verbatim (a generated C comment line, a QL
# header line) or markers consumed by substring containment.  Read
# as regexes they carry a quantified ``/`` and measure superlinear,
# but rewriting the strings would corrupt real output.  Growth
# requires editing this documented dict (the regeneration tool pins
# these with the ``adjudicated`` verdict and refuses any other
# superlinear member), so the lane cannot grow silently.
_SCAN_ADJUDICATED: dict[str, str] = {
    "0f64f014c82d": (
        "core/audit/compile_probe.py lines[0]: the generated probe "
        "TU's own header comment — emitted as C source text, never "
        "compiled as a pattern"
    ),
    "8eba6201f599": (
        "core/iris/specs.py lines[7]: the QL query header's "
        "comment-closer line — emitted as query text, never "
        "compiled as a pattern"
    ),
    "37de29a408f1": (
        "core/inventory/exclusions.py GENERATED_MARKERS[10]: a "
        "generated-file marker consumed via substring containment "
        "(`marker in lowered`), never compiled as a pattern"
    ),
}


def _seq_leading_anchor(seq) -> bool:
    """True when the pattern is start-anchored (``\\A`` or ``^``):
    the search loop cannot restart densely without MULTILINE, and
    with MULTILINE the anchor-restart arm (Rule R) owns the
    mechanism."""
    for node in seq:
        op, arg = node
        if op is sre_parse.AT:
            if str(arg).endswith(("AT_BEGINNING", "AT_BEGINNING_STRING")):
                return True
            continue
        if op is sre_parse.SUBPATTERN:
            return _seq_leading_anchor(arg[3])
        return False
    return False


def _find_scan_restart_lanes(parsed, flags: int) -> list[dict]:
    """Rule S lanes: for an unbounded repeat R on the concatenation
    spine with a REQUIRED consuming continuation after it, the site
    is start-dense when the min-model of everything required before
    R (the "entry", possibly empty) is drawn from charset(R):

    * entry == "": leading ``\\s*`` / ``.*`` / ``[^X]*`` — every
      position of a hostile fill run is a match attempt and each
      attempt re-scans the rest of the run;
    * entry != "" and chars(entry) <= charset(R): the attacker
      plants entry occurrences INSIDE R's own span (multi-term
      ``A.*B.*C`` chains, head-dense ``,[^;]*x`` shapes) — attempts
      multiply with density and each backtrack re-scans the tail.

    Walks into subpatterns, branches, and repeat BODIES (an unbounded
    repeat nested inside an optional group scan-restarts all the
    same), with the enclosing tail visible, accumulating the
    min-model entry string."""
    lanes: list[dict] = []
    seen: set[int] = set()

    def walk(seq, entry: str, tail_after: tuple) -> None:
        for i, node in enumerate(list(seq)):
            op, arg = node
            rest = tuple(list(seq)[i + 1:]) + tail_after
            if op is sre_parse.SUBPATTERN:
                walk(arg[3], entry, rest)
            elif op is sre_parse.BRANCH:
                for branch in arg[1]:
                    walk(branch, entry, rest)
            elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT) \
                    and not _is_unbounded_repeat(node):
                walk(arg[2], entry, rest)
            elif _is_unbounded_repeat(node) and id(node) not in seen:
                seen.add(id(node))
                charset = _charset(node, flags)
                if charset:
                    tail = _tail_verdict(list(rest), flags)
                    first = set(tail["first_consumable"])
                    fills = [c for c in sorted(charset - first)
                             if c not in (10, 13)]
                    if tail["consuming"] and fills \
                            and all(ord(ch) in charset for ch in entry):
                        fill = chr(32 if 32 in fills else next(
                            (c for c in fills if chr(c).isalnum()),
                            fills[0]))
                        poison = next(
                            (chr(c) for c in (1, 46, 59, 88, 10, 33, 2)
                             if c not in charset and c not in first),
                            None,
                        )
                        lanes.append({
                            "entry": entry, "fill": fill,
                            "poison": poison or "",
                        })
                walk(arg[2], entry, rest)
            try:
                entry += _gen_min(node, flags)
            except _Unsupported:
                pass

    if not _seq_leading_anchor(parsed):
        walk(parsed, "", ())
    return lanes


def _build_scan_restart_attack(lane: dict, n: int) -> str | None:
    """Position-density pump: (entry + fill)^k + poison.  Every entry
    occurrence is a live attempt position inside the fill run; the
    poison keeps the continuation failing so each attempt pays its
    full re-scan.  The trailing-span pair pump does NOT fire on
    these shapes (no adjacent overlapping pair) — this family needs
    its own synthesis."""
    unit = lane["entry"] + lane["fill"]
    if not unit:
        return None
    return unit * max(2, n // len(unit)) + lane["poison"]


def _site_scan_lanes(site: _Site) -> list[dict]:
    """Rule S applies to scanning call modes only: an anchored
    match/fullmatch site has a single start position, so the
    position loop never restarts."""
    if site.mode != "search":
        return []
    try:
        parsed = sre_parse.parse(site.pattern, site.flags)
    except (re.error, ValueError, OverflowError):
        return []
    return _find_scan_restart_lanes(parsed, parsed.state.flags)


def _scan_restart_members() -> dict[tuple[str, str], dict]:
    """Rule S's PROPOSED member set over runtime source, keyed and
    digest-stamped like the trailing-span arm."""
    import hashlib

    members: dict[tuple[str, str], dict] = {}
    for site in _all_runtime_sites():
        lanes = _site_scan_lanes(site)
        if not lanes:
            continue
        digest = hashlib.sha256(
            f"{site.flags}:{site.mode}:{site.pattern}".encode(),
        ).hexdigest()[:12]
        record = members.setdefault(site.key, {
            "digests": set(), "sites": [],
        })
        record["digests"].add(digest)
        record["sites"].append(
            (site.lineno, site.pattern, site.flags, site.mode),
        )
    return members


def _load_scan_expected() -> dict:
    import json

    with _SCAN_EXPECTED_FILE.open(encoding="utf-8") as fh:
        return json.load(fh)


def _scan_oracle_probe_lines(pattern: str, flags: int,
                             index: int) -> None:
    """Worker body (hard-killed subprocess): ``n dt`` probe lines
    for one scan-restart lane at doubling sizes."""
    import time

    try:
        parsed = sre_parse.parse(pattern, flags)
    except (re.error, ValueError):
        print("NOPARSE")
        return
    lanes = _find_scan_restart_lanes(parsed, parsed.state.flags)
    if index >= len(lanes):
        print("NOLANE")
        return
    lane = lanes[index]
    rx = re.compile(pattern, flags)
    n = 500
    while n <= 32000:
        text = _build_scan_restart_attack(lane, n)
        if text is None:
            print("NOATTACK")
            return
        start = time.perf_counter()
        rx.search(text)
        elapsed = time.perf_counter() - start
        print(n, f"{elapsed:.6f}", flush=True)
        if elapsed > 1.0:
            break
        n *= 2


def _scan_oracle_classify(pattern: str,
                          flags: int) -> tuple[float | None, bool]:
    """(worst exponent | None, any-lane-synthesized) across the
    site's scan-restart lanes (subprocess-hard-killed, same probe
    protocol and trust floor as the pair/restart oracle)."""
    try:
        parsed = sre_parse.parse(pattern, flags)
    except (re.error, ValueError):
        return (None, False)
    lanes = _find_scan_restart_lanes(parsed, parsed.state.flags)
    worst: float | None = None
    synthesized = False
    for index in range(min(len(lanes), 4)):
        exponent, status = _oracle_lane(
            pattern, flags, "search", "scan", index, "",
        )
        if status not in ("NOATTACK", "NOPARSE", "NOLANE"):
            synthesized = True
        if exponent is not None and (worst is None or exponent > worst):
            worst = exponent
    return (worst, synthesized)


def _regen_scan_expected(workers: int = 8) -> int:
    """Re-run the position-density oracle over every Rule S proposal
    and rewrite the pin file.  REFUSES to pin a superlinear member —
    fixing the pattern is the only way through."""
    import json
    from concurrent.futures import ThreadPoolExecutor

    members = _scan_restart_members()
    rows: dict[str, dict] = {}
    failures: list[str] = []

    def classify(item):
        key, record = item
        _lineno, pattern, flags, _mode = record["sites"][0]
        exponent, synthesized = _scan_oracle_classify(pattern, flags)
        return key, record, exponent, synthesized

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for key, record, exponent, synthesized in pool.map(
                classify, sorted(members.items())):
            if record["digests"] <= set(_SCAN_ADJUDICATED):
                # Never-compiled table string with a documented
                # disposition (see _SCAN_ADJUDICATED) — pinned, not
                # refused.
                verdict = "adjudicated"
            elif not synthesized:
                verdict = "noattack"
            elif exponent is not None and exponent >= 1.5:
                failures.append(
                    f"{key[0]} :: {key[1]} measures superlinear "
                    f"(exp={exponent:.2f}) — fix the pattern (pin the "
                    f"run start, bound the window, break the chain); "
                    f"the pin file only accepts oracle-linear members",
                )
                continue
            else:
                verdict = "linear"
            rows["\x1f".join(key)] = {
                "digests": sorted(record["digests"]),
                "verdict": verdict,
                "exp": None if exponent is None else round(exponent, 2),
            }
    if failures:
        print("REFUSED to regenerate:")
        for failure in failures:
            print(" ", failure)
        return 1
    _SCAN_EXPECTED_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_comment": (
            "Pinned scan-restart census members: Rule S proposals "
            "the position-density pump oracle measured linear, keyed "
            "file\x1fname with pattern digests. Regenerate with: "
            "python3 .github/tests/test_redos_idiom_census.py "
            "--regen-scan-restart  (the tool refuses superlinear "
            "members; hand-editing a verdict is caught by the "
            "nightly oracle re-check)."
        ),
        "members": dict(sorted(rows.items())),
    }
    with _SCAN_EXPECTED_FILE.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
        fh.write("\n")
    noattack = [k for k, v in rows.items() if v["verdict"] == "noattack"]
    print(f"pinned {len(rows)} members "
          f"({len(noattack)} noattack) -> {_SCAN_EXPECTED_FILE}")
    return 0


class RedosIdiomCensus(unittest.TestCase):

    def test_detector_catches_the_idiom(self) -> None:
        """Self-check: the detector recognises the known spellings
        (guards against the census silently going vacuous)."""
        self.assertTrue(_pattern_is_member(r"^\s*FROM\s+(\S+)", True))
        self.assertTrue(_pattern_is_member(r"^\s+import", True))
        self.assertTrue(_pattern_is_member(r"(?m)^\s*x", False))
        self.assertTrue(_pattern_is_member(r"^[\s#]*x", True))
        self.assertTrue(_pattern_is_member(r"^(?P<indent>\s+)- name:", True))
        # Branch-embedded anchor: a MULTILINE ``^`` as one alternative
        # of a statement-boundary group is the same idiom — every
        # blank line satisfies the ``^`` branch.
        self.assertTrue(_pattern_is_member(r"(?:^|;|\})\s*static\b", True))
        self.assertFalse(
            _pattern_is_member(r"(?:^|;|\})[^\S\n]*static\b", True),
        )
        self.assertFalse(_pattern_is_member(r"(?:;|\})\s*static\b", True))
        # Non-members: no MULTILINE, horizontal-only, bounded repeat.
        self.assertFalse(_pattern_is_member(r"^\s*import", False))
        self.assertFalse(_pattern_is_member(r"^[^\S\n]*import", True))
        self.assertFalse(_pattern_is_member(r"^\s{0,8}import", True))
        self.assertFalse(_pattern_is_member(r"^import\s+x", True))
        # Repeats that cannot BEGIN at a newline fail a blank-line
        # attempt in O(1): not members.
        self.assertFalse(_pattern_is_member(
            r"^(?:__attribute__\s*\(\([^()]*\)\)\s*)*(\w+)\s*\(", True,
        ))
        self.assertFalse(_pattern_is_member(r"^([0-9a-f]+)\s+\w+", True))

    def test_scan_sees_aliased_and_composed_patterns(self) -> None:
        """Scan-level self-check: an aliased ``import re as _rx``
        receiver and a concat pattern with a dynamic operand
        (``"^\\s*" + re.escape(x)``) are still members — both
        spellings hid real members before the resolver handled
        them."""
        import tempfile

        source = (
            "import re as _rx\n"
            "def probe(name, text):\n"
            "    pat = _rx.compile(\n"
            "        r'^\\s*static\\s+' + _rx.escape(name) + r'\\s*\\(',\n"
            "        _rx.MULTILINE,\n"
            "    )\n"
            "    return pat.search(text)\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False,
        ) as fh:
            fh.write(source)
            probe = Path(fh.name)
        try:
            members = _scan_file(probe)
        finally:
            probe.unlink()
        self.assertEqual([key for key, _ in members],
                         [(probe.name, "pat")])

    def test_scan_catches_every_multiline_spelling(self) -> None:
        """Scan-level self-check for the raw-text gate: a planted
        member must be caught through ``_scan_file`` under EVERY
        supported MULTILINE spelling — the flag attribute, its ``M``
        alias (on an aliased import), inline flag groups (bare and
        combined), and the NFKC fullwidth ``Ｍ`` — plus the
        branch-embedded anchor, so a gate regression fails here
        instead of silently shrinking the census."""
        import tempfile

        plants: list[tuple[str, str]] = [
            ("import re\n"
             "p = re.compile(r'^\\s*planted', re.MULTILINE)\n", "p"),
            ("import re as _rx\n"
             "p = _rx.compile(r'^\\s*planted', _rx.M)\n", "p"),
            ("import re\n"
             "p = re.compile(r'(?m)^\\s*planted')\n", "p"),
            ("import re\n"
             "p = re.compile(r'(?im)^[\\s#]*planted')\n", "p"),
            # Branch-embedded anchor member through the scan layer.
            ("import re\n"
             "p = re.compile(r'(?:^|;)\\s*planted', re.M)\n", "p"),
            # Fullwidth Ｍ: Python NFKC-normalizes identifiers at
            # parse time, so this IS the ``M`` attribute to the AST
            # detector — the gate normalizes before matching so it
            # agrees.
            ("import re\n"
             "p = re.compile(r'^\\s*planted', re.Ｍ)\n", "p"),
            # Numeric flag literals: positional, |-combined value,
            # and keyword — no MULTILINE/M/(?m token anywhere, so
            # both the gate and the AST flag check must handle the
            # decimal spelling.
            ("import re\n"
             "p = re.compile(r'^\\s*planted', 8)\n", "p"),
            ("import re\n"
             "p = re.compile(r'^\\s*planted', 10)\n", "p"),
            ("import re\n"
             "p = re.compile(r'^\\s*planted', flags=8)\n", "p"),
            # Annotated constant: the repo's type-annotation practice
            # steers new pattern constants into exactly this spelling.
            ("import re\n"
             "_P: str = r'^\\s*planted'\n"
             "p = re.compile(_P, re.MULTILINE)\n", "p"),
            # Multi-target constant assignment.
            ("import re\n"
             "_A = _B = r'^\\s*planted'\n"
             "p = re.compile(_B, re.MULTILINE)\n", "p"),
            # Name-bound flag constant ("extract shared flags" is a
            # natural refactor; the raw-text gate passes on the
            # MULTILINE token, so this miss was silent).
            ("import re\n"
             "_FLAGS = re.MULTILINE\n"
             "p = re.compile(r'^\\s*planted', _FLAGS)\n", "p"),
            # Bytes pattern (decoded latin-1 for the structural test).
            ("import re\n"
             "p = re.compile(rb'^\\s*planted', re.MULTILINE)\n", "p"),
            # from-import bindings: Name-shaped call site AND a bare
            # flag name — neither Attribute-shaped spelling appears.
            ("from re import compile as _rc, MULTILINE as _ML\n"
             "p = _rc(r'^\\s*planted', _ML)\n", "p"),
        ]
        for source, name in plants:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".py", delete=False,
            ) as fh:
                fh.write(source)
                probe = Path(fh.name)
            try:
                members = _scan_file(probe)
            finally:
                probe.unlink()
            self.assertEqual([key for key, _ in members],
                             [(probe.name, name)], source)

    def test_runtime_source_has_no_members(self) -> None:
        files = _iter_python_files()
        self.assertGreater(len(files), 100, "scan roots missing?")
        # Sites and keys are reported DISTINCTLY: several call sites
        # can share one key (same file + same assigned name or
        # 40-char pattern prefix — e.g. one module-level pattern
        # searched from two call sites, or two same-named builder
        # locals), so the site count and the key count differ and
        # both must be visible for the numbers to reconcile.
        offenders: dict[tuple[str, str], list[str]] = {}
        n_sites = 0
        # Consumes the shared whole-tree extraction (cached once per
        # process) — the trailing-span arm pays for the parse, this
        # arm reuses it.
        for site in _all_runtime_sites():
            if not _pattern_is_member(site.pattern, site.flags):
                continue
            n_sites += 1
            offenders.setdefault(site.key, []).append(
                f"{site.key[0]}:{site.lineno}: {site.key[1]}",
            )
        unexpected = sorted(set(offenders) - set(_ALLOWLIST))
        stale = sorted(set(_ALLOWLIST) - set(offenders))
        sites = [s for k in unexpected for s in offenders[k]]
        self.assertFalse(unexpected, (
            f"blank-run-quadratic regex idiom (MULTILINE ^ + unbounded "
            f"newline-capable quantifier) in runtime source — "
            f"{n_sites} member call site(s) across {len(unexpected)} "
            f"key(s). Spell the anchor whitespace horizontally "
            f"([^\\S\\n]) or, if the pattern is provably applied "
            f"per-line, allowlist it WITH justification:\n  "
            + "\n  ".join(sites)
        ))
        self.assertFalse(stale, f"stale allowlist entries: {stale}")

    def test_pattern_data_files_have_no_members(self) -> None:
        """The same class closure for patterns that live in DATA
        files: the preflight corpus loader compiles ``_multiline``
        corpora with re.MULTILINE | re.DOTALL and searches them over
        explicitly untrusted content.  Membership runs over the
        patterns the loader actually loads, with the flags it
        actually compiles."""
        members = _data_file_members()
        self.assertFalse(members, (
            "blank-run-quadratic regex idiom in a pattern data file — "
            "spell the anchor whitespace horizontally ([^\\S\\n]):\n  "
            + "\n  ".join(f"{stem}: {pat}" for stem, pat in members)
        ))

    def test_data_file_arm_detects_a_planted_member(self) -> None:
        """Self-check for the data-file arm: plant a member in a
        scratch copy of the corpus directory and point the loader at
        it — the arm must flag the plant (and ONLY the plant, on the
        fixed corpus)."""
        import shutil
        import sys
        import tempfile

        sys.path.insert(0, str(_REPO))
        try:
            from core.security import prompt_input_preflight as pf
        finally:
            sys.path.remove(str(_REPO))

        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "injection_patterns"
            shutil.copytree(pf._PATTERNS_DIR, scratch)
            with (scratch / "english_multiline.txt").open(
                "a", encoding="utf-8",
            ) as fh:
                fh.write("\n^\\s*planted_member\\b\n")
            original = pf._PATTERNS_DIR
            pf._PATTERNS_DIR = scratch
            try:
                members = _data_file_members()
            finally:
                pf._PATTERNS_DIR = original
        self.assertEqual(
            members,
            [("english_multiline", "^\\s*planted_member\\b")],
        )

    def test_data_file_arm_detects_a_planted_exfil_member(self) -> None:
        """Self-check for the exfil-rules arm: plant an inline-(?m)
        member in a scratch copy of the JSON and point the loader at
        it — the arm must flag the plant. Today's shipped entries
        compile flag-less (not census-class), so an operator-extended
        entry with an inline ``(?m)`` was invisible to BOTH census
        arms before this arm existed."""
        import json as _json
        import sys
        import tempfile

        sys.path.insert(0, str(_REPO))
        try:
            from packages.sca.supply_chain import (
                exfil_destinations as _exfil,
            )
        finally:
            sys.path.remove(str(_REPO))

        planted = r"(?m)^\s*evil\.example\b"
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "exfil_destinations.json"
            data = _json.loads(
                _exfil._DATA_FILE.read_text(encoding="utf-8"))
            data["entries"].append({
                "category": "test", "severity": "high",
                "reason": "planted census member", "pattern": planted,
            })
            scratch.write_text(_json.dumps(data), encoding="utf-8")
            original_file = _exfil._DATA_FILE
            original_cache = _exfil._RULES_CACHE
            _exfil._DATA_FILE = scratch
            _exfil._RULES_CACHE = None
            try:
                members = _data_file_members()
            finally:
                _exfil._DATA_FILE = original_file
                _exfil._RULES_CACHE = original_cache
        # The plant — and ONLY the plant — on the shipped rule set.
        self.assertEqual(
            [m for m in members if m[0] == "exfil_destinations"],
            [("exfil_destinations", planted)],
        )


class TrailingSpanCensus(unittest.TestCase):
    """Two-stage arms: Rule C / Rule R propose, the pinned oracle
    verdicts dispose.  The default tier never runs the oracle."""

    def test_rule_c_catches_known_spellings(self) -> None:
        """Detector self-check on the arm's founding members and
        non-members (guards against the proposer going vacuous)."""

        def rule_c(pattern: str, flags: int = 0) -> bool:
            parsed = sre_parse.parse(pattern, flags)
            return any(
                pair["tail"]["consuming"] or pair["tail"]["failable_zw"]
                for pair in _find_pairs(parsed, parsed.state.flags)
            )

        # The two founding members: consuming and ZERO-WIDTH failable
        # continuations (the consuming-only variant of this rule was
        # recall-blind on the second).
        self.assertTrue(rule_c(
            r"^[^\S\n]*import\s+(?:static\s+)?"
            r"([A-Za-z_][A-Za-z0-9_.]*)\s*(?:\.\*)?\s*;",
            re.MULTILINE,
        ))
        self.assertTrue(rule_c(
            r"^[^\S\n]*return\s+(0|nil|None|True|true|EXIT_SUCCESS)"
            r"\s*;?\s*$",
            re.MULTILINE,
        ))
        # Fixed spellings: folding the tail into the gated group
        # removes the adjacent pair entirely.
        self.assertFalse(rule_c(
            r"^[^\S\n]*import\s+(?:static\s+)?"
            r"([A-Za-z_][A-Za-z0-9_.]*)\s*(?:\.\*\s*)?;",
            re.MULTILINE,
        ))
        self.assertFalse(rule_c(
            r"^[^\S\n]*return\s+(0|nil|None|True|true|EXIT_SUCCESS)"
            r"\s*(?:;\s*)?$",
            re.MULTILINE,
        ))
        # Linear lookalike that must NOT flood the arm: adjacent
        # overlapping spans with NO failable continuation (the
        # pattern can end the match inside the run).
        self.assertFalse(rule_c(r"=\s*(.+)"))

    def test_rule_r_catches_the_restart_shape(self) -> None:
        """The anchor-restart proposer sees the newline-crossing
        repeat one token PAST the anchor (the spelling that survived
        the anchor-adjacent arm above), and lets bounded spellings
        through."""

        def rule_r(pattern: str, flags: int = 0) -> bool:
            parsed = sre_parse.parse(pattern, flags)
            return bool(
                _find_restart_entries(parsed, parsed.state.flags),
            )

        self.assertTrue(rule_r(
            r"^(?P<head>[A-Za-z_][\w\s\*]*?)\b(?P<name>[A-Za-z_]\w*)"
            r"\s*\((?P<params>[^;{)]*)\)\s*\{",
            re.MULTILINE,
        ))
        self.assertTrue(rule_r(
            r"^[ \t]*(?:\w+\s+)*(\w+)\s*\(", re.MULTILINE,
        ))
        # No MULTILINE -> a single anchor, no restart.
        self.assertFalse(rule_r(r"^(?:\w+\s+)*(\w+)\s*\("))

    def test_oracle_synthesizes_both_attack_families(self) -> None:
        """Synthesis self-check (in-process, no timing): the pair
        attack carries prefix + pump + poison, the word-unit pump
        repeats whole loop bodies, and the restart attack repeats
        prefix-shaped lines."""
        pattern = (r"^[^\S\n]*import\s+(?:static\s+)?"
                   r"([A-Za-z_][A-Za-z0-9_.]*)\s*(?:\.\*)?\s*;")
        parsed = sre_parse.parse(pattern, re.MULTILINE)
        flags = parsed.state.flags
        pairs = _find_pairs(parsed, flags)
        self.assertTrue(pairs)
        attack = _build_pair_attack(parsed, flags, pairs[0], 64, " ")
        self.assertIsNotNone(attack)
        self.assertIn("import", attack)
        loop_pattern = r"(?:(?:static|inline)\s+)+(\w+)\s*\("
        loop_parsed = sre_parse.parse(loop_pattern, 0)
        loop_pairs = _find_pairs(loop_parsed, 0)
        units = _pump_units(loop_pairs[0], 0)
        self.assertTrue(any(len(unit) > 1 for unit in units))
        restart_pattern = r"^(?:\w+\s+)*(\w+)\s*\("
        restart_parsed = sre_parse.parse(restart_pattern, re.MULTILINE)
        entries = _find_restart_entries(restart_parsed, re.MULTILINE)
        self.assertTrue(entries)
        text = _build_restart_attack(restart_parsed, re.MULTILINE,
                                     entries[0], 8)
        self.assertIsNotNone(text)
        self.assertEqual(text.count("\n"), 8)

    def test_members_match_the_pinned_verdicts(self) -> None:
        """Default-tier closure: the live proposed-member set equals
        the pinned set, every pinned digest still matches its live
        pattern, and every pin is ``linear`` or ``noattack`` — a new
        member, a drifted pattern, or a stale pin fails here with
        regeneration instructions (and regeneration refuses
        superlinear members, so the fix is the only way through)."""
        live = _trailing_span_members()
        pinned = _load_expected()["members"]
        live_keys = {"\x1f".join(key) for key in live}
        pinned_keys = set(pinned)
        regen = ("python3 .github/tests/test_redos_idiom_census.py "
                 "--regen-trailing-span")
        new_members = sorted(live_keys - pinned_keys)
        self.assertFalse(new_members, (
            f"unpinned trailing-span/anchor-restart census member(s) "
            f"— an adjacent overlapping repeat pair with a failable "
            f"continuation, or a MULTILINE anchor-restart shape. Fix "
            f"the pattern (fold the optional atom's whitespace into "
            f"its gated group / \\S-delimit trims / bound windows) "
            f"or, if the pump oracle measures it linear, pin it with "
            f"`{regen}`:\n  " + "\n  ".join(
                member.replace("\x1f", " :: ")
                for member in new_members)
        ))
        stale = sorted(pinned_keys - live_keys)
        self.assertFalse(stale, (
            f"stale trailing-span pins (member no longer proposed) — "
            f"re-run `{regen}`:\n  " + "\n  ".join(
                member.replace("\x1f", " :: ") for member in stale)
        ))
        drifted = []
        bad_verdicts = []
        for key, record in live.items():
            row = pinned["\x1f".join(key)]
            if set(row["digests"]) != record["digests"]:
                drifted.append(" :: ".join(key))
            if row["verdict"] == "adjudicated":
                # Only digests carried by the documented lane may
                # hold this verdict (see _TABLE_ADJUDICATED).
                if not set(row["digests"]) <= set(_TABLE_ADJUDICATED):
                    bad_verdicts.append(" :: ".join(key))
            elif row["verdict"] not in ("linear", "noattack"):
                bad_verdicts.append(" :: ".join(key))
        self.assertFalse(sorted(drifted), (
            f"pattern text drifted under existing pins — the pinned "
            f"verdict no longer describes the live pattern; re-run "
            f"`{regen}`:\n  " + "\n  ".join(sorted(drifted))
        ))
        self.assertFalse(bad_verdicts, (
            "pin file carries a verdict outside linear/noattack (or "
            "an 'adjudicated' pin whose digest the documented "
            "_TABLE_ADJUDICATED lane does not carry) — hand-edited? "
            "The nightly oracle re-check owns verdict truth; "
            "regenerate instead."
        ))

    def test_noattack_lane_is_exactly_the_documented_list(self) -> None:
        """The manual-review lane (members whose attack the
        synthesizer cannot build) is pinned by IDENTITY, so it cannot
        grow silently: a new unsynthesizable member fails here and
        must be manually adjudicated (analysed and documented below)
        before it can be pinned.

        Current lane, one member, manually adjudicated LINEAR:
        packages/sca/update.py ``poetry_re`` — its backreference
        defeats the generator, and by inspection its adjacent
        unbounded repeats have pairwise-disjoint character sets
        (horizontal-only ``[ \t]*`` against a quote/word class), so
        no run can be split between them."""
        pinned = _load_expected()["members"]
        noattack = sorted(
            key.replace("\x1f", " :: ")
            for key, row in pinned.items()
            if row["verdict"] == "noattack"
        )
        self.assertEqual(noattack, [
            "packages/sca/update.py :: poetry_re",
        ])

    def test_adjudicated_lane_is_exactly_the_documented_dict(self) -> None:
        """The adjudicated-table lane (worst-case-superlinear table
        members with hand-verified call-site bounds) is pinned by
        IDENTITY: every ``adjudicated`` pin's digests must be carried
        by ``_TABLE_ADJUDICATED``, and every documented digest must
        back a live pin — a stale entry would silently pre-authorise
        a future superlinear member."""
        pinned = _load_expected()["members"]
        pinned_digests: set[str] = set()
        for row in pinned.values():
            if row["verdict"] == "adjudicated":
                pinned_digests.update(row["digests"])
        self.assertEqual(pinned_digests, set(_TABLE_ADJUDICATED), (
            "adjudicated pins and _TABLE_ADJUDICATED disagree — "
            "adjudications live in the documented dict, nowhere else"
        ))

    def test_planted_table_member_is_caught(self) -> None:
        """Self-check for the pattern-table arm: a KNOWN-superlinear
        spelling planted in a literal table (and one behind a
        ``self.`` class constant) is proposed by Rule C even though
        no call site carries a constant operand; the fixed table
        spelling is not (no flood)."""
        import tempfile

        source = (
            "import re\n"
            "PATTERNS = [\n"
            "    r'(?:public|private|protected)?\\s*(?:static)?"
            "\\s*\\w+\\s+(\\w+)\\s*\\(',\n"
            "    r'(?:(?:public|private|protected)\\s+)?"
            "(?:static\\s+)?\\w+\\s+(\\w+)\\s*\\(',\n"
            "]\n"
            "class Probe:\n"
            "    BAD_ATTR = r'func\\s*\\w*\\s*\\(\\s*x\\s*\\)\\s*y'\n"
            "    def scan(self, line: str):\n"
            "        for pattern in PATTERNS:\n"
            "            if re.search(pattern, line):\n"
            "                return True\n"
            "        return re.search(self.BAD_ATTR, line)\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False,
        ) as fh:
            fh.write(source)
            probe = Path(fh.name)
        try:
            sites = _extract_sites(probe)
            rule_c_names = {
                site.name for site in sites if _site_rules(site)[0]
            }
            rule_c_patterns = {
                site.pattern for site in sites if _site_rules(site)[0]
            }
        finally:
            probe.unlink()
        self.assertIn("PATTERNS[0]", rule_c_names)
        self.assertNotIn("PATTERNS[1]", rule_c_names)
        # The class-constant spelling resolves through the per-class
        # attribute map (the call site's operand is ``self.BAD_ATTR``).
        self.assertIn(r"func\s*\w*\s*\(\s*x\s*\)\s*y", rule_c_patterns)

    def test_planted_superlinear_member_is_caught(self) -> None:
        """Self-check: a module planted with a KNOWN-superlinear
        trailing-span spelling (a founding member's pre-fix pattern)
        is proposed by the arm and — being unpinned — would fail the
        closure. A linear lookalike in the same module must NOT be
        proposed (no flood)."""
        import tempfile

        source = (
            "import re\n"
            "BAD = re.compile(\n"
            "    r'^[^\\S\\n]*return\\s+(0|nil|None)\\s*;?\\s*$',\n"
            "    re.MULTILINE,\n"
            ")\n"
            "OK = re.compile(\n"
            "    r'^[^\\S\\n]*return\\s+(0|nil|None)\\s*(?:;\\s*)?$',\n"
            "    re.MULTILINE,\n"
            ")\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False,
        ) as fh:
            fh.write(source)
            probe = Path(fh.name)
        try:
            rule_c_proposed = {
                site.name
                for site in _extract_sites(probe)
                if _site_rules(site)[0]
            }
            all_proposed = {
                site.name
                for site in _extract_sites(probe)
                if any(_site_rules(site)[:2])
            }
        finally:
            probe.unlink()
        self.assertIn("BAD", rule_c_proposed)
        # The fixed spelling has no adjacent pair (Rule C clean); its
        # MULTILINE whitespace spans still propose it under Rule R,
        # where the oracle-pinned linear verdict accepts it — being
        # PROPOSED is not flooding, being unpinnable is.
        self.assertNotIn("OK", rule_c_proposed)
        self.assertIn("OK", all_proposed)

    def test_dispatch_triggers_cover_the_universe(self) -> None:
        """The census can only stop the NEXT member if a change in its
        universe DISPATCHES it — assert the ``redos_census`` dispatch
        tier's trigger set covers every file the universe walk yields
        (derived from the walk itself, so widening the universe fails
        here until the trigger set follows), names exactly this test
        file, and carries no dead trigger claiming nothing (a stale
        trigger row would dispatch the census for trees that no
        longer exist while reading as coverage)."""
        import sys

        scripts_dir = _REPO / ".github" / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            from test_scope import TIERS
        finally:
            sys.path.remove(str(scripts_dir))
        tier = TIERS["redos_census"]
        rel_self = Path(__file__).resolve().relative_to(_REPO).as_posix()
        self.assertEqual(tier["test_files"], [rel_self])
        triggers = tier["extra_triggers"]
        universe = [
            p.relative_to(_REPO).as_posix() for p in _iter_python_files()
        ]
        self.assertTrue(universe, "universe walk went vacuous")
        uncovered = sorted(
            rel for rel in universe
            if not any(rel == t or rel.startswith(t + "/")
                       for t in triggers)
        )
        self.assertFalse(uncovered, (
            f"census universe file(s) outside the dispatch triggers "
            f"(first: {uncovered[:5]}) — a member added there merges "
            "green; extend TIERS['redos_census']['extra_triggers'] in "
            ".github/scripts/test_scope.py"
        ))
        dead = sorted(
            t for t in triggers
            if not any(rel == t or rel.startswith(t + "/")
                       for rel in universe)
        )
        self.assertFalse(dead, (
            f"dispatch trigger(s) {dead} claim no census universe "
            "file — drop the stale row(s) from "
            "TIERS['redos_census']['extra_triggers']"
        ))

    def test_from_import_and_numeric_flag_members_are_seen(self) -> None:
        """U-resolver self-check: the ``from re import`` spelling
        (bare callable, bare flag name) and the numeric-literal flags
        operand are members of the MULTILINE arm — both hid members
        from the previous resolver — and the raw-text gate admits
        both files."""
        import tempfile

        for source, description in (
            (
                "from re import compile as _c, MULTILINE\n"
                "PAT = _c(r'^\\s*needle', MULTILINE)\n",
                "from-import spelling",
            ),
            (
                "import re\n"
                "PAT = re.compile(r'^\\s*needle', 8)\n",
                "numeric flags literal",
            ),
        ):
            self.assertIsNotNone(
                _RE_BINDING_GATE.search(
                    unicodedata.normalize("NFKC", source)),
                f"gate must admit the {description}",
            )
            with tempfile.NamedTemporaryFile(
                "w", suffix=".py", delete=False,
            ) as fh:
                fh.write(source)
                probe = Path(fh.name)
            try:
                members = _scan_file(probe)
            finally:
                probe.unlink()
            self.assertEqual(
                [key for key, _ in members], [(probe.name, "PAT")],
                f"{description} must be a member",
            )
        # Position-awareness: an int literal in a NON-flags position
        # (re.sub's count) must not read as a flags bitmask.
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False,
        ) as fh:
            fh.write("import re\n"
                     "def clean(t):\n"
                     "    return re.sub(r'^\\s*needle', '', t, 8)\n")
            probe = Path(fh.name)
        try:
            members = _scan_file(probe)
        finally:
            probe.unlink()
        self.assertEqual(members, [])

    def test_boundary_shapes_are_not_members_of_these_arms(self) -> None:
        """HONEST BOUNDARY pins (see the module docstring): the
        unanchored scan-restart family is NOT covered by Rule C or
        Rule R — the exemplar shapes (a multi-term dot-star chain,
        its lazy/DOTALL two-term case, a sentence-body family
        pattern, and a whitespace-prefixed search) are pinned as
        non-members of THESE arms.  Rule S now owns that family: the
        same shapes must be PROPOSED by it (the coverage handshake
        below), so the boundary is a routing statement, not a gap."""
        for pattern, flags in (
            # nested-quantifier ambiguity: the classic exponential
            # ((?:a+)+ tail) has NO adjacent pair — Rule C is blind
            # to it by construction. The adversarial sweep that
            # pinned this boundary measured every nested-unbounded
            # site in the tree with inner-run attacks and found no
            # live member of the dangerous (ambiguous-outer-width)
            # subclass; the shape stays named here so a future
            # member is a known gap, not a surprise.
            (r"(?:\w+)+\)", 0),
            # multi-term chain (prompt_defence's pre-fix class)
            (r"ignore\b.*\ball\b.*\binstructions", re.IGNORECASE),
            # lazy/DOTALL two-term degenerate case of the same
            # scan-restart family (an unclosed-opener storm makes the
            # position loop re-scan to end-of-text per opener) — the
            # follow-up arm's membership rule must cover it.
            (r"/\*.*?\*/", re.DOTALL),
            # sentence-body family (exploit-text sanitizer class)
            (r"\bthe\s+attacks?\s+(may|can)\s+be\s+launched"
             r"[^.!?\n]*[.!?\n]", re.IGNORECASE),
            # whitespace-prefixed unanchored search
            (r",?\s*leading to (?:a |an )?compromise", 0),
        ):
            site = _Site(
                ("<boundary>", pattern[:40]), 0, pattern, flags,
                "search", None,
            )
            rule_c, rule_r, _pairs, _entries = _site_rules(site)
            self.assertFalse(rule_c or rule_r, pattern)
            # Coverage handshake: every boundary shape except the
            # nested-quantifier exemplar is Rule S's to own.
            if pattern != r"(?:\w+)+\)":
                self.assertTrue(_site_scan_lanes(site), pattern)


class TrailingSpanNightly(unittest.TestCase):
    """Nightly re-verification: the pump oracle re-measures every
    pinned member, so a hand-edited verdict or an environment-
    dependent regression cannot hide behind the default tier's
    static-only check."""

    @pytest.mark.slow
    def test_nightly_oracle_agrees_with_pins(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        live = _trailing_span_members()
        pinned = _load_expected()["members"]
        violations: list[str] = []

        def measure(item):
            key, record = item
            lineno, pattern, flags, mode = record["sites"][0]
            return key, _oracle_classify(pattern, flags, mode)

        items = [
            (key, record) for key, record in sorted(live.items())
            if pinned.get("\x1f".join(key)) is not None
        ]
        # The lanes are hard-killed subprocesses; eight in flight
        # keeps the nightly run in minutes without starving the
        # runner (each worker is one child at a time).
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(measure, items))
        for key, (exponent, synthesized) in results:
            row = pinned["\x1f".join(key)]
            if row["verdict"] == "adjudicated":
                # Deliberately pinned worst-case-superlinear (bounded
                # at every call site — see _TABLE_ADJUDICATED); the
                # default tier already enforces lane identity.
                continue
            if row["verdict"] == "noattack":
                if synthesized:
                    violations.append(
                        f"{key}: pinned noattack but the synthesizer "
                        f"now builds an attack — re-adjudicate "
                        f"(exp={exponent})",
                    )
                continue
            # Pinned linear: re-measure with head-room above the
            # census threshold so a loaded runner cannot flap a
            # borderline member (regeneration refuses >= 1.5, the
            # census threshold is 1.6, the nightly alarm is 1.9).
            if exponent is not None and exponent >= 1.9:
                violations.append(
                    f"{key}: pinned linear but measures "
                    f"exp={exponent:.2f}",
                )
        self.assertFalse(violations,
                         "nightly oracle disagrees with pins:\n  "
                         + "\n  ".join(violations))

    @pytest.mark.slow
    def test_nightly_oracle_detects_a_known_superlinear(self) -> None:
        """Oracle self-check: the founding member's pre-fix spelling
        measures superlinear and its fixed spelling measures linear —
        so a broken oracle cannot silently bless the tree."""
        bad = (r"^[^\S\n]*return\s+(0|nil|None|True|true|EXIT_SUCCESS)"
               r"\s*;?\s*$")
        good = (r"^[^\S\n]*return\s+"
                r"(0|nil|None|True|true|EXIT_SUCCESS)\s*(?:;\s*)?$")
        exponent, synthesized = _oracle_classify(
            bad, re.MULTILINE, "search",
        )
        self.assertTrue(synthesized)
        self.assertIsNotNone(exponent)
        self.assertGreaterEqual(exponent, _SUPERLINEAR_EXP)
        exponent, _ = _oracle_classify(good, re.MULTILINE, "search")
        self.assertLess(exponent if exponent is not None else 1.0,
                        _SUPERLINEAR_EXP)


class ScanRestartCensus(unittest.TestCase):
    """Rule S arm: static scan-restart rule proposes, the pinned
    position-density oracle verdicts dispose.  The default tier never
    runs the oracle."""

    def test_rule_s_catches_known_spellings(self) -> None:
        """Detector self-check on the arm's founding shapes and
        non-members (guards against the proposer going vacuous or
        flooding)."""

        def rule_s(pattern: str, flags: int = 0,
                   mode: str = "search") -> bool:
            return bool(_site_scan_lanes(_Site(
                ("<probe>", pattern[:40]), 0, pattern, flags, mode,
                None,
            )))

        # Founding shapes: the three exemplars the trailing-span arms
        # pinned as out-of-coverage, plus the head-dense variant.
        self.assertTrue(rule_s(
            r",?\s*leading to (?:a |an )?compromise", re.IGNORECASE,
        ))
        self.assertTrue(rule_s(
            r"ignore\b.*\ball\b.*\binstructions", re.IGNORECASE,
        ))
        self.assertTrue(rule_s(
            r"\bthe\s+attacks?\s+(may|can)\s+be\s+launched"
            r"[^.!?\n]*[.!?\n]", re.IGNORECASE,
        ))
        self.assertTrue(rule_s(r",[^;]*x"))
        # Lazy-quantifier + DOTALL delimited-span shapes are
        # first-class members: the lazy repeat expands from every
        # planted opener and re-scans to the missing closer — the
        # 2-term case of the planted-entry mechanism. (These shapes
        # are INVISIBLE to Rule C — no adjacent pair — and to Rule R
        # — no MULTILINE anchor; this arm owns them.)
        self.assertTrue(rule_s(r"/\*.*?\*/", re.DOTALL))
        self.assertTrue(rule_s(r"<!--.*?-->", re.DOTALL))
        self.assertTrue(rule_s(r"/\*.*?\*/"))
        # An unbounded repeat hidden inside an OPTIONAL group is
        # still a scan-restart member (the walker descends into
        # repeat bodies); the entry ("a ") is drawn from the inner
        # repeat's own class, so occurrences can be planted in its
        # span.
        self.assertTrue(rule_s(r"a\s+(?:[\w\-][\w\- ]*?)?flag\b"))
        # ... but when the entry carries a char OUTSIDE the repeat's
        # class ('='), planted entries break the span and the
        # position skip prunes attempts — correctly not a member.
        self.assertFalse(rule_s(r"=\s+(?:[\w\-][\w\- ]*?)?flag\b"))
        # Non-members: a literal head whose chars fall outside the
        # repeat's set (position skip prunes attempts), a bounded
        # window, an anchored pattern, an anchored CALL MODE, and a
        # tail that cannot fail.
        self.assertFalse(rule_s(r"leading to [a-z]+", re.IGNORECASE))
        self.assertFalse(rule_s(r",?\s{0,16}leading to"))
        self.assertFalse(rule_s(r"^\s*foo"))
        self.assertFalse(rule_s(r"\s*==\s*0\b", 0, "match"))
        self.assertFalse(rule_s(r"\s*(.*)"))

    def test_oracle_flags_superlinear_and_passes_fixed(self) -> None:
        """Oracle self-check with real timing: a known scan-restart
        member measures superlinear and its run-start-pinned fix
        measures linear — so a broken oracle cannot silently bless
        the tree."""
        bad = r"\s*==\s*0\b"
        exponent, synthesized = _scan_oracle_classify(bad, 0)
        self.assertTrue(synthesized)
        assert exponent is not None
        self.assertGreaterEqual(exponent, _SUPERLINEAR_EXP)
        good = r"(?<!\s)\s*==\s*0\b"
        exponent, _ = _scan_oracle_classify(good, 0)
        self.assertLess(exponent if exponent is not None else 1.0,
                        _SUPERLINEAR_EXP)
        # The lazy-DOTALL delimited-span exemplar: planted openers
        # with the closer withheld make every opener re-scan to the
        # end — the position-density pump must expose it.
        exponent, synthesized = _scan_oracle_classify(
            r"/\*.*?\*/", re.DOTALL,
        )
        self.assertTrue(synthesized)
        assert exponent is not None
        self.assertGreaterEqual(exponent, _SUPERLINEAR_EXP)

    def test_members_match_the_pinned_verdicts(self) -> None:
        """Default-tier closure: the live Rule S proposal set equals
        the pinned set, digests match, and every pin is linear or
        noattack — a new member, a drifted pattern, or a stale pin
        fails here (and regeneration refuses superlinear members, so
        the fix is the only way through)."""
        live = _scan_restart_members()
        pinned = _load_scan_expected()["members"]
        live_keys = {"\x1f".join(key) for key in live}
        pinned_keys = set(pinned)
        regen = ("python3 .github/tests/test_redos_idiom_census.py "
                 "--regen-scan-restart")
        new_members = sorted(live_keys - pinned_keys)
        self.assertFalse(new_members, (
            f"unpinned scan-restart census member(s) — an unanchored "
            f"scanning call site whose unbounded repeat re-scans a "
            f"hostile run from every attempt position. Fix the "
            f"pattern (pin the run start with \\b/(?<!...), bound "
            f"the window, break the ``A.*B.*C`` chain) or, if the "
            f"position-density oracle measures it linear, pin it "
            f"with `{regen}`:\n  " + "\n  ".join(
                member.replace("\x1f", " :: ")
                for member in new_members)
        ))
        stale = sorted(pinned_keys - live_keys)
        self.assertFalse(stale, (
            f"stale scan-restart pins (member no longer proposed) — "
            f"re-run `{regen}`:\n  " + "\n  ".join(
                member.replace("\x1f", " :: ") for member in stale)
        ))
        drifted = []
        bad_verdicts = []
        for key, record in live.items():
            row = pinned["\x1f".join(key)]
            if set(row["digests"]) != record["digests"]:
                drifted.append(" :: ".join(key))
            if row["verdict"] == "adjudicated":
                if not set(row["digests"]) <= set(_SCAN_ADJUDICATED):
                    bad_verdicts.append(" :: ".join(key))
            elif row["verdict"] not in ("linear", "noattack"):
                bad_verdicts.append(" :: ".join(key))
        self.assertFalse(sorted(drifted), (
            f"pattern text drifted under existing scan-restart pins "
            f"— re-run `{regen}`:\n  " + "\n  ".join(sorted(drifted))
        ))
        self.assertFalse(bad_verdicts, (
            "scan-restart pin carries a verdict outside "
            "linear/noattack (or an adjudicated pin whose digest the "
            "_SCAN_ADJUDICATED lane does not carry) — hand-edited? "
            "The nightly oracle re-check owns verdict truth; "
            "regenerate instead."
        ))

    def test_planted_superlinear_member_is_caught(self) -> None:
        """Self-check: a module planted with a KNOWN-superlinear
        scan-restart spelling is proposed by Rule S — being unpinned
        it would fail the closure — and the fixed spelling in the
        same module is NOT proposed (bounded glue has no unbounded
        repeat left)."""
        import tempfile

        source = (
            "import re\n"
            "BAD = re.compile(r',?\\s*leading to compromise')\n"
            "OK = re.compile(r',?\\s{0,16}leading to compromise')\n"
            "def strip(t):\n"
            "    return BAD.sub('', OK.sub('', t))\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False,
        ) as fh:
            fh.write(source)
            probe = Path(fh.name)
        try:
            proposed = {
                site.name
                for site in _extract_sites(probe)
                if _site_scan_lanes(site)
            }
        finally:
            probe.unlink()
        self.assertIn("BAD", proposed)
        self.assertNotIn("OK", proposed)

    def test_fstring_constant_members_are_seen(self) -> None:
        """Resolver self-check: a pattern assembled from module
        pattern-fragment constants through an rf-string resolves to
        its real spelling — the placeholder used to hide the
        fragment's unbounded repeats from every arm."""
        import tempfile

        source = (
            "import re\n"
            "_BODY = r'[^.\\n]*'\n"
            "PAT = re.compile(rf'{_BODY}leads to{_BODY}\\.')\n"
            "def strip(t):\n"
            "    return PAT.sub('', t)\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False,
        ) as fh:
            fh.write(source)
            probe = Path(fh.name)
        try:
            sites = {s.name: s.pattern for s in _extract_sites(probe)}
        finally:
            probe.unlink()
        self.assertEqual(sites.get("PAT"),
                         r"[^.\n]*leads to[^.\n]*\.")

    def test_noattack_lane_is_exactly_the_documented_list(self) -> None:
        """The scan-restart manual-review lanes are pinned by
        IDENTITY so they cannot grow silently.  The noattack lane is
        empty (the synthesizer built an attack for every proposed
        member); the adjudicated lane is exactly the documented
        never-compiled table strings, and every documented digest
        must still be pinned (a stale disposition is drift too)."""
        pinned = _load_scan_expected()["members"]
        noattack = sorted(
            key.replace("\x1f", " :: ")
            for key, row in pinned.items()
            if row["verdict"] == "noattack"
        )
        self.assertEqual(noattack, [])
        adjudicated_digests: set[str] = set()
        for row in pinned.values():
            if row["verdict"] == "adjudicated":
                adjudicated_digests |= set(row["digests"])
        self.assertEqual(adjudicated_digests, set(_SCAN_ADJUDICATED))


class ScanRestartNightly(unittest.TestCase):
    """Nightly re-verification: the position-density oracle
    re-measures every scan-restart pin, so a hand-edited verdict or
    an environment-dependent regression cannot hide behind the
    default tier's static-only check."""

    @pytest.mark.slow
    def test_nightly_oracle_agrees_with_pins(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        live = _scan_restart_members()
        pinned = _load_scan_expected()["members"]
        violations: list[str] = []

        def measure(item):
            key, record = item
            _lineno, pattern, flags, _mode = record["sites"][0]
            return key, _scan_oracle_classify(pattern, flags)

        items = [
            (key, record) for key, record in sorted(live.items())
            if pinned.get("\x1f".join(key)) is not None
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            for key, (exponent, synthesized) in pool.map(
                    measure, items):
                row = pinned["\x1f".join(key)]
                if row["verdict"] == "adjudicated":
                    # Never-compiled table strings (documented in
                    # _SCAN_ADJUDICATED) hold their verdict by
                    # identity, not by measurement.
                    continue
                if row["verdict"] == "noattack":
                    if synthesized:
                        violations.append(
                            f"{key[0]} :: {key[1]}: noattack pin but "
                            f"the synthesizer now builds an attack — "
                            f"regenerate")
                    continue
                # Alarm threshold sits ABOVE the census threshold
                # (1.6) so a pinned-linear member only fails on a
                # real regression, not on a loaded runner.
                if exponent is not None and exponent >= 1.9:
                    violations.append(
                        f"{key[0]} :: {key[1]}: pinned linear but "
                        f"measures exp={exponent:.2f}")
        self.assertFalse(violations,
                         "scan-restart nightly oracle disagrees with "
                         "pins:\n  " + "\n  ".join(violations))


if __name__ == "__main__":
    import sys

    if "--oracle-worker" in sys.argv:
        import json

        request = json.load(sys.stdin)
        _oracle_probe_lines(
            request["pattern"], request["flags"], request["mode"],
            request["kind"], request["index"], request["unit"],
        )
        sys.exit(0)
    if "--regen-trailing-span" in sys.argv:
        sys.exit(_regen_expected())
    if "--regen-scan-restart" in sys.argv:
        sys.exit(_regen_scan_expected())
    unittest.main()
