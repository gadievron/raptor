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
``re.MULTILINE`` (bounded by one line) is not.  Constant resolution
covers plain, annotated (``_P: str = ...``), and multi-target
(``_A = _B = ...``) assignments plus bytes patterns (decoded
latin-1); flag resolution covers the ``re.MULTILINE``/``re.M``
attributes, module-level flag constants bound to them
(``_FLAGS = re.MULTILINE``), and bare names bound by ``from re
import`` — every one of these spellings smuggled a planted member
past the census before it was resolved.

Allowlisting a member requires a justification string; the only
acceptable justifications are structural (the pattern is applied
per-line via ``.match(line)``, or the input is length-bounded by
construction).  Prefer fixing the anchor over allowlisting.
"""

from __future__ import annotations

import ast
import re
import sys
import unicodedata
import unittest
from pathlib import Path

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

# Raw-text gate applied before the AST pass: a member REQUIRES
# re.MULTILINE in effect, and every arrival route spells a gate
# token — a flag ATTRIBUTE named ``MULTILINE`` or ``M`` at the call
# site or bound to a module flag constant (both spell ``MULTILINE``
# or the ``.M`` token), an inline ``(?m…)`` flag group inside the
# pattern string, a bare NAME bound by ``from re import`` (which
# spells the import statement), or a decimal integer flag literal
# (the numeric arms below).  A file whose
# raw text contains none of these spellings cannot produce a member,
# so the census skips its parse+walk — the whole-tree cost was
# dominated by files that never set MULTILINE at all (a bare ``\bM\b``
# token gate was tried first and over-admitted half the runtime tree's
# bytes on prose "M"s in comments).  ``\.\s*M\b`` is the textual shape
# of the ``M`` attribute access: dot, then the identifier, with any
# whitespace/newline layout between (false positives just pay the old
# full-scan price).  The gate is applied to NFKC-NORMALIZED text:
# Python normalizes identifiers with NFKC at parse time, so a
# fullwidth ``re.Ｍ`` is the ``M`` attribute to the AST detector and
# must be the ``M`` attribute to the gate too.  Known blind spots,
# documented like the resolver's own spell-anchors-literally
# discipline in ``_const_str_parts``: a comment or
# backslash-continuation between the dot and the ``M``, an inline
# flag group no single string literal spells (escape-encoded
# ``"(?\x6d)"`` or a concat split like ``"(?" + "m)"``), and a
# MULTILINE-bit integer flag spelled non-decimally or computed
# (``0x8``, ``8 + 0``, an int through a variable) — spell flags
# plainly and adjacently.  ``test_scan_catches_every_multiline_spelling``
# plants every supported spelling through ``_scan_file`` so a gate
# regression fails the census's own tests, not the closure.
_MULTILINE_SOURCE_GATE = re.compile(
    r"MULTILINE"          # re.MULTILINE / _rx.MULTILINE
    r"|\.\s*M\b"          # re.M / _rx.M (attribute-shaped token)
    r"|\(\?[a-zA-Z-]*m"   # inline flags: (?m) (?im) (?m:...) ...
    r"|\bfrom\s+re\s+import\b"  # from re import compile, M, ...
    # Numeric flag literals: ``re.compile(p, 8)`` / ``flags=8`` set
    # MULTILINE with no MULTILINE/M/(?m spelling anywhere in the file,
    # so the gate must admit the decimal-literal shapes (a positional
    # int argument, possibly ``|``-combined, or an int keyword value).
    # The AST arm then checks the actual bit. Over-admission (any
    # call with a trailing small-int arg) just pays the parse+walk
    # price, per this gate's contract. Non-decimal or computed
    # spellings (``0x8``, ``8+0``, an int through a variable) stay
    # gate-blind — documented with the other spell-flags-plainly
    # blind spots below.
    r"|,\s*\d+\s*[|)]"
    r"|flags\s*=\s*\d",
)


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

    Bytes patterns are decoded latin-1 (lossless byte→codepoint map):
    ``rb'^\\s*...'`` compiled with MULTILINE re-scans a blank run
    exactly like its str twin, and the anchor/quantifier prefix under
    test is ASCII either way.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value.decode("latin-1")
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
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


def _flags_has_multiline(
    node: ast.AST, flag_names: frozenset[str] | set[str] = frozenset(),
) -> bool:
    """Does a flags-position expression set MULTILINE? Three
    spellings: the attribute (``re.MULTILINE`` / ``re.M``, wherever
    it sits in a ``|`` expression); a plain integer literal with the
    MULTILINE bit set (``re.compile(p, 8)`` — the flag values are
    stable API; the numeric arm checks the BIT, not equality, so
    combined numeric flags (``10`` = I|M) count too, and bool is
    excluded so ``True`` cannot smuggle bit checks); and bare NAMES
    known to carry it — module flag constants
    (``_FLAGS = re.MULTILINE``) and ``from re import`` bindings —
    which the attribute-only walk silently missed."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in ("MULTILINE", "M"):
            return True
        if (isinstance(sub, ast.Constant)
                and isinstance(sub.value, int)
                and not isinstance(sub.value, bool)
                and sub.value & re.MULTILINE):
            return True
        if isinstance(sub, ast.Name) and sub.id in flag_names:
            return True
    return False


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


def _pattern_is_member(pattern: str, call_flags_multiline: bool) -> bool:
    try:
        parsed = sre_parse.parse(
            pattern, re.MULTILINE if call_flags_multiline else 0,
        )
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


def _scan_file(path: Path) -> list[tuple[tuple[str, str], int]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError):
        return []  # binary libexec helper or undecodable
    if _MULTILINE_SOURCE_GATE.search(
            unicodedata.normalize("NFKC", text)) is None:
        return []  # no MULTILINE spelling anywhere — cannot be a member
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []  # non-Python libexec helper (shell) or unparseable

    # ONE pass over the tree collects everything the membership test
    # needs (the census's cost is walk-bound, and separate walks per
    # collection quadrupled it):
    #  * re_names — names the ``re`` module is bound to in this file,
    #    module-level or function-local ``import re`` / ``import re
    #    as _re``;
    #  * from_funcs — bare names bound to ``re`` functions by ``from
    #    re import compile as _rc``: their call sites are Name-shaped,
    #    not Attribute-shaped, so the receiver check cannot see them;
    #  * flag_names — bare names carrying re.MULTILINE: ``from re
    #    import MULTILINE as _ML`` bindings, closed after the walk
    #    over module flag constants (``_FLAGS = re.MULTILINE``);
    #  * consts — constant-ish assignments (plain single- and
    #    multi-target, and annotated), resolved with an empty
    #    namespace exactly as before (chained constant references
    #    stay unresolved by design);
    #  * assign_of — the name each call is assigned to (stable keys);
    #  * calls — candidate ``re``-function call sites, judged against
    #    the COMPLETE binding sets after the walk (an ``import re``
    #    later in walk order than a call site must still count).
    re_names: set[str] = set()
    from_funcs: set[str] = set()
    flag_names: set[str] = set()
    flag_assigns: list[tuple[list[str], ast.expr]] = []
    consts: dict[str, str] = {}
    assign_of: dict[ast.Call, str] = {}
    attr_calls: list[tuple[ast.Call, str]] = []
    name_calls: list[tuple[ast.Call, str]] = []
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
                        from_funcs.add(bound)
                    elif alias.name in ("MULTILINE", "M"):
                        flag_names.add(bound)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
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
            # Every non-call assignment is a flag-constant candidate
            # (``_FLAGS = re.MULTILINE`` is an Attribute value;
            # ``re.M | re.S`` a BinOp) — judged after the walk.
            flag_assigns.append((targets, node.value))
        elif isinstance(node, ast.Call) and node.args:
            if (isinstance(node.func, ast.Attribute)
                    and node.func.attr in _RE_FUNCS
                    and isinstance(node.func.value, ast.Name)):
                attr_calls.append((node, node.func.value.id))
            elif isinstance(node.func, ast.Name):
                name_calls.append((node, node.func.id))

    # Close flag_names over module flag constants — iterated so a
    # flag constant bound to ANOTHER flag constant still resolves
    # (each pass adds at least one name or stops, so this terminates).
    changed = True
    while changed:
        changed = False
        for bound_names, flag_expr in flag_assigns:
            if _flags_has_multiline(flag_expr, flag_names):
                for name in bound_names:
                    if name not in flag_names:
                        flag_names.add(name)
                        changed = True

    members: list[tuple[tuple[str, str], int]] = []

    def _judge(node: ast.Call) -> None:
        pattern = _const_str_parts(node.args[0], consts)
        if pattern is None:
            return
        flag_nodes = list(node.args[1:]) + [
            kw.value for kw in node.keywords if kw.arg == "flags"
        ]
        multiline = any(
            _flags_has_multiline(f, flag_names) for f in flag_nodes
        )
        if _pattern_is_member(pattern, multiline):
            members.append(
                (_census_key(path, pattern, assign_of.get(node)),
                 node.lineno),
            )

    for node, receiver in attr_calls:
        if receiver in re_names:
            _judge(node)
    for node, func_name in name_calls:
        if func_name in from_funcs:
            _judge(node)
    return members


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
        for path in files:
            for key, lineno in _scan_file(path):
                n_sites += 1
                offenders.setdefault(key, []).append(
                    f"{key[0]}:{lineno}: {key[1]}",
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


if __name__ == "__main__":
    unittest.main()
