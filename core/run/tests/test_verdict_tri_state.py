"""Tri-state verdict accessor semantics + runtime idiom closure.

``read_verdict`` is the one shared read for the ``VERDICT_KEYS``
boolean fields (``is_true_positive`` / ``is_exploitable``). Those
fields are tri-state: True / False / abstained (missing, schema-nulled
None, or malformed shape). Reading an abstention as a verdict — via a
verdict-fabricating ``.get`` default, ``not``, an ``==``/``!=``
compare against a bool or ``None`` constant, direct truthiness
(including the positive ternary, ``bool()``, and walrus-wrapped
reads), a membership test, a direct ``is None`` identity check, or an
attribute read off a splat-constructed object — has repeatedly demoted
findings
whose analysis response was merely malformed. The closure test scans
every runtime module (including the repo-root ``raptor*.py`` entry
modules) for those idiom families so a new member of the class cannot
be written without either routing through the accessor or consciously
editing this test.

The scan also covers the GRADED string tri-state field
(``exploitability``: high/medium/low with ``"unknown"`` as the
producer's abstention value): truthiness, membership splits, and
non-abstention defaults on a raw read of it collapse "unknown" into
whichever side of the split it happens to fall on. The blessed
spelling binds the read to a name first and maps each level
explicitly, with the unknown/absent arm preserved.

Scope boundary (deliberate, keep this docstring honest): the scan
flags the enumerated idiom families applied DIRECTLY to a raw read —
including through a walrus wrapper (``if (v := r.get(k)):``), which
is still a direct read — AND, for the bool keys, applied to a
NAME-BOUND read: a name assigned exactly once in its scope, by a
plain single-target assignment whose value is a raw read of a bool
verdict key (``v = r.get(k)`` … ``if v:`` — the separate-statement
escape idiom CrossFamilyCheckTask's junk==junk agreement mint hid
in). Name tracking is per-scope (module / function, nested scopes
excluded), refuses any name with a second binding of any kind
(parameter, loop target, import, del, global/nonlocal, match
capture — reassignment may launder the value), and treats an
``isinstance(name, …)`` call anywhere in the scope as laundering
(shape-checked ladders are semantically equal to ``read_verdict``;
the scan cannot judge branch placement, so the audited class stays
legal). Two tracked names compared with ``==``/``!=`` are also
flagged: junk == junk is how agreement gets minted from two
non-verdicts. Still outside the vocabulary: walrus/AugAssign
bindings and attribute/subscript homes for the tracked value; raw
values forwarded into ``tally_verdict_votes`` (which applies its own
documented counting contract); ``any()`` / ``all()`` /
``filter(None, …)`` consuming reads yielded from comprehensions;
graded keys under a name binding (that IS the blessed spelling); and
positive graded equality with a fabricating ``else`` arm
(``== 'high' … else <verdict>`` — an AST lint cannot see the else's
semantics; only the negative-equality split is mechanically a
misread).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from core.run.finding_status import VERDICT_KEYS, read_verdict  # noqa: E402


class TestReadVerdict:

    def test_explicit_bools_pass_through(self):
        assert read_verdict({"is_exploitable": True}, "is_exploitable") is True
        assert read_verdict({"is_exploitable": False}, "is_exploitable") is False

    def test_missing_key_is_abstention(self):
        assert read_verdict({}, "is_true_positive") is None

    def test_schema_nulled_none_is_abstention(self):
        assert read_verdict({"is_true_positive": None}, "is_true_positive") is None

    def test_non_bool_shapes_are_abstention(self):
        # Response validation nulls malformed verdicts, but a record
        # that bypassed it ("true", 1, [], {}) must not be coerced
        # into a verdict either way.
        for junk in ("true", "false", 1, 0, [], {}, 0.9):
            assert read_verdict({"is_exploitable": junk}, "is_exploitable") is None

    def test_non_dict_record_is_abstention(self):
        for rec in (None, [], "x", 42):
            assert read_verdict(rec, "is_exploitable") is None  # type: ignore[arg-type]

    def test_verdict_keys_enumerates_both_fields(self):
        assert set(VERDICT_KEYS) == {"is_true_positive", "is_exploitable"}


# ---------------------------------------------------------------------------
# Idiom closure scan
# ---------------------------------------------------------------------------

#: Runtime trees the verdict-record dicts flow through (producers and
#: consumers of analysis/finding records). Test dirs, scripts/ dev
#: harnesses, and conftest files are excluded below — fixtures may
#: legitimately build records with literal defaults. The repo-root
#: ``raptor*.py`` entry modules join via _runtime_py_files: the
#: fuzzing entry point consumed a graded verdict outside every
#: earlier sweep precisely because the roots stopped at the package
#: trees.
_SCAN_ROOTS = ("core", "packages", "plugins")

#: Graded string tri-state verdict fields and their abstention
#: spellings: a raw read yields None when absent and the producers
#: (packages/autonomous/dialogue.py, crash-context consumers) keep
#: "unknown" as the explicit non-verdict. Any other constant default,
#: a truthiness read, or a membership split of a raw read collapses
#: the abstention. There is deliberately no shared accessor for these
#: (the levels are surface-specific); the blessed spelling binds the
#: read to a name and maps each level explicitly.
_GRADED_VERDICT_KEYS: frozenset[str] = frozenset({"exploitability"})
_GRADED_ABSTENTION_DEFAULTS = (None, "unknown")

#: Legacy bool ALIAS keys (sequential-mode records carry
#: ``exploitable`` where orchestrated records carry
#: ``is_exploitable``). Same tri-state discipline, but the blessed
#: spelling is the genuine-bool read (``.get("exploitable") is
#: True`` / an isinstance-gated ladder — the agentic_passes
#: precedent) since the alias sits outside ``read_verdict``'s
#: VERDICT_KEYS. The same spelling also names STATS COUNTERS
#: (``counts["exploitable"] += 1``, ``stats.get("exploitable", 0)``)
#: — int buckets keyed by a status value, not verdict record reads —
#: so the alias scan is scoped to the verdict-shaped forms only:
#: ``.get`` calls (record readers use ``.get``; the subscript
#: spelling is the tally idiom) whose default, if any, is None or a
#: bool constant (an int/str/expr default marks the counter idiom or
#: an ambiguous read and stays out of scope — the conservative
#: direction for a dual-use key). NOTE the subscript scope-out is a
#: spelling boundary, not a semantic guarantee: the orchestrator's
#: ``r["exploitable"]`` truthiness reads are safe because the SAME
#: function writes the parsed bool a few lines up (read-own-write),
#: not because they are counters — a new subscript reader of a
#: record it did not just write gets no protection from this scan.
_BOOL_ALIAS_GET_KEYS: frozenset[str] = frozenset({"exploitable"})

#: (repo-relative path, lineno) pairs reviewed and deliberately
#: exempted, each with its rationale. Keep entries rare — an entry
#: must explain why the flagged idiom does NOT consume the verdict.
#: Known key weakness: the lineno key means an edit above the entry
#: surfaces it loudly for re-adjudication (fail-closed), but a NEW
#: misread landing exactly on the exempted line would inherit the
#: exemption while the displaced original resurfaces — the scan
#: still fails overall, so silent re-arm needs a careless
#: re-adjudication on top; re-verify the rationale whenever an
#: entry's file moves.
_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({
    # Display-only interpolation: the graded level is embedded in a
    # human-readable seed-reasoning string next to sibling fields
    # that share the module's "?" placeholder convention; no verdict
    # semantics are consumed and "?" reads as absent, not as a level.
    ("core/audit/synthesis_seeds.py", 257),
    # Presence check, not verdict consumption: the verdict was
    # already taken from read_verdict two lines up (abstained arm);
    # the raw read only distinguishes present-but-junk (normalised to
    # an explicit None) from absent/already-None (left untouched).
    ("core/witness/provenance.py", 743),
})


def _read_key(node: ast.AST, keys) -> str | None:
    """The verdict key when ``node`` is ``X.get("<key>"[, d])`` or a
    Load-context ``X["<key>"]``; None otherwise. A walrus wrapper is
    unwrapped first: ``(v := r.get(k))`` in a flagged position is
    still a direct read of the raw value (the binding does not
    launder it), unlike a separate-statement binding."""
    while isinstance(node, ast.NamedExpr):
        node = node.value
    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in keys):
        return node.args[0].value
    if (isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in keys):
        return node.slice.value
    return None


def _alias_get_key(node: ast.AST) -> str | None:
    """The alias key when ``node`` is a VERDICT-SHAPED alias read:
    ``X.get("<alias>")`` with no default, or a None / bool-constant
    default (see ``_BOOL_ALIAS_GET_KEYS`` for the counter-idiom
    scope-out); a walrus wrapper is unwrapped like ``_read_key``."""
    while isinstance(node, ast.NamedExpr):
        node = node.value
    if not (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in _BOOL_ALIAS_GET_KEYS):
        return None
    if len(node.args) >= 2:
        default = node.args[1]
        if not (isinstance(default, ast.Constant)
                and (default.value is None
                     or isinstance(default.value, bool))):
            return None
    return node.args[0].value


def _is_verdict_read(node: ast.AST) -> bool:
    """True for a raw read of a bool verdict key — ``.get``/subscript
    for the VERDICT_KEYS members, ``.get`` only for the legacy alias
    keys."""
    return (_read_key(node, VERDICT_KEYS) is not None
            or _alias_get_key(node) is not None)


def _is_graded_read(node: ast.AST) -> bool:
    """True for a raw read of a graded (string) verdict key."""
    return _read_key(node, _GRADED_VERDICT_KEYS) is not None


def _is_any_verdict_read(node: ast.AST) -> bool:
    return _is_verdict_read(node) or _is_graded_read(node)


#: Scope-opening nodes for the name-bound tracking pass. Class bodies
#: are their own namespace and lambdas cannot contain statements —
#: none of them inherit the enclosing scope's single-binding
#: determination, so the walk never descends into them.
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                ast.ClassDef)


def _scope_own_nodes(scope: ast.AST) -> list[ast.AST]:
    """Nodes belonging to *scope*: descendants reached without
    crossing a nested scope boundary. The nested def/class node
    itself IS yielded (its name binds in this scope); its body is
    not."""
    out: list[ast.AST] = []

    def rec(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            out.append(child)
            if not isinstance(child, _SCOPE_NODES):
                rec(child)

    rec(scope)
    return out


def _scope_binding_counts(scope: ast.AST, own: list[ast.AST]):
    """How many times each name is (re)bound in *scope* — every
    binding construct disqualifies single-assignment tracking, the
    conservative direction (an unmodelled rebind could launder a
    tracked value, so anything that binds counts)."""
    from collections import Counter
    counts: Counter[str] = Counter()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef,
                          ast.Lambda)):
        a = scope.args
        for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs,
                    *([a.vararg] if a.vararg else []),
                    *([a.kwarg] if a.kwarg else [])):
            counts[arg.arg] += 1
    for n in own:
        if isinstance(n, ast.Name) and isinstance(n.ctx,
                                                  (ast.Store, ast.Del)):
            counts[n.id] += 1
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for alias in n.names:
                counts[(alias.asname or alias.name).split(".")[0]] += 1
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            for name in n.names:
                counts[name] += 2  # externally bound — never track
        elif isinstance(n, ast.ExceptHandler) and n.name:
            counts[n.name] += 1
        elif isinstance(n, _SCOPE_NODES) and hasattr(n, "name"):
            counts[n.name] += 1
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            counts[n.name] += 1
        elif isinstance(n, ast.MatchMapping) and n.rest:
            counts[n.rest] += 1
    return counts


def _tracked_verdict_names(scope: ast.AST,
                           own: list[ast.AST]) -> dict[str, str]:
    """Names bound EXACTLY ONCE in *scope*, by a plain single-target
    assignment whose value is a raw read of a bool verdict key —
    the separate-statement spelling of a direct raw read. A name
    that ever feeds ``isinstance(name, …)`` in the scope is dropped:
    shape-checked ladders are the audited legal alternative to
    ``read_verdict`` and the scan cannot adjudicate branch
    placement."""
    counts = _scope_binding_counts(scope, own)
    tracked: dict[str, str] = {}
    for n in own:
        target = None
        value = None
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)):
            target, value = n.targets[0], n.value
        elif (isinstance(n, ast.AnnAssign) and n.value is not None
                and isinstance(n.target, ast.Name)):
            target, value = n.target, n.value
        if target is None or counts[target.id] != 1:
            continue
        key = _read_key(value, VERDICT_KEYS) or _alias_get_key(value)
        if key is not None:
            tracked[target.id] = key
    if tracked:
        for n in own:
            if (isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name)
                    and n.func.id == "isinstance"
                    and n.args
                    and isinstance(n.args[0], ast.Name)):
                tracked.pop(n.args[0].id, None)
    return tracked


def _mentions_verdict_key(source: str) -> bool:
    """Smoke-subset selector: does the raw text mention a verdict key?

    Used ONLY to pick the default-tier smoke's file subset — it is NOT
    a sound skip filter for the closure scan. The parser folds
    adjacent string literals and escape sequences into plain
    ``ast.Constant`` values (``r.get("is_" "exploitable")``,
    ``"is_exploitabl\\x65"``), so a file can carry a scannable verdict
    read whose source text never contains the key; only the full parse
    in the nightly-tier scan catches those. Built on the scanned key
    sets (bool + graded + alias) so a new verdict field widens the
    smoke subset automatically.
    """
    return any(key in source
               for key in (*VERDICT_KEYS, *_GRADED_VERDICT_KEYS,
                           *_BOOL_ALIAS_GET_KEYS))


def _violations_in(path: Path) -> list[str]:
    # Deliberately no text prescreen before the parse: see
    # _mentions_verdict_key — a "file never mentions a key" skip
    # misses parser-folded key literals the AST scan does catch.
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return []
    out = []

    def bad(node: ast.AST, why: str) -> None:
        # Tolerate paths outside REPO_ROOT: the scanner-behaviour
        # tests below feed it files under pytest's tmp_path.
        try:
            rel = path.relative_to(REPO_ROOT)
        except ValueError:
            rel = path
        if (str(rel), node.lineno) in _ALLOWLIST:
            return
        out.append(f"{rel}:{node.lineno}: {why}")

    def truth_tested(node: ast.AST) -> list[ast.AST]:
        """Sub-expressions this node reads for their truth value."""
        tests: list[ast.AST] = []
        if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            tests.append(node.test)
        if isinstance(node, ast.BoolOp):
            # and/or truth-test every operand — this is also the
            # or-literal fabrication (`r.get(k) or False`).
            tests.extend(node.values)
        if isinstance(node, ast.comprehension):
            tests.extend(node.ifs)
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "bool"
                and len(node.args) == 1
                and not node.keywords):
            tests.append(node.args[0])
        return tests

    for node in ast.walk(tree):
        # Verdict-fabricating .get defaults. Bool keys: only an
        # explicit None default preserves the abstention (and equals
        # the no-default read). Graded keys: only None/"unknown" do.
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and len(node.args) >= 2):
            key = node.args[0].value
            default = node.args[1]
            if key in VERDICT_KEYS and not (
                    isinstance(default, ast.Constant)
                    and default.value is None):
                bad(node, f"verdict-fabricating default on "
                          f".get({key!r}, ...)")
            elif (key in _BOOL_ALIAS_GET_KEYS
                    and isinstance(default, ast.Constant)
                    and isinstance(default.value, bool)):
                # Alias keys: only a bool-constant default is
                # mechanically a fabricated verdict — int/str/expr
                # defaults mark the stats-counter idiom (see
                # _BOOL_ALIAS_GET_KEYS) and stay out of scope.
                bad(node, f"verdict-fabricating default on "
                          f".get({key!r}, ...)")
            elif key in _GRADED_VERDICT_KEYS and not (
                    isinstance(default, ast.Constant)
                    and default.value in _GRADED_ABSTENTION_DEFAULTS):
                bad(node, f"non-abstention default on .get({key!r}, "
                          f"...) — use None or \"unknown\"")
        # `not <raw read>` reads an abstention as an explicit negative.
        if (isinstance(node, ast.UnaryOp)
                and isinstance(node.op, ast.Not)
                and _is_any_verdict_read(node.operand)):
            bad(node, "`not` on a raw verdict read")
        # ==/!= against a bool constant silently mishandles None
        # (and non-bool junk), and `== None` / `!= None` is the
        # Eq-spelling of the is-None misread (no E711 lint backstop
        # in this repo's ruff selection); identity checks on
        # read_verdict()'s result are the explicit form.
        if isinstance(node, ast.Compare) and all(
                isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            sides = [node.left, *node.comparators]
            if (any(_is_verdict_read(s) for s in sides)
                    and any(isinstance(s, ast.Constant)
                            and (isinstance(s.value, bool)
                                 or s.value is None)
                            for s in sides)):
                bad(node, "==/!= bool/None compare on a raw verdict "
                          "read")
            # Two raw reads compared with each other (directly or
            # walrus-wrapped): junk == junk mints agreement — the
            # direct-read spelling of the name-bound pair rule below.
            if sum(1 for s in sides if _is_verdict_read(s)) >= 2:
                bad(node, "==/!= between two raw verdict reads "
                          "(junk == junk mints agreement)")
        # Graded-key negative-equality split: `.get('exploitability')
        # != 'low'` sends "unknown"/absent down the truthy side — the
        # membership misread in negative spelling. Positive
        # single-level equality (`== 'high'`) does NOT split the
        # domain (an abstention falls through safely) and stays
        # legal, as does `!= 'unknown'` (an abstention-presence
        # check, not a level split).
        if isinstance(node, ast.Compare) and all(
                isinstance(op, ast.NotEq) for op in node.ops):
            sides = [node.left, *node.comparators]
            if (any(_is_graded_read(s) for s in sides)
                    and any(isinstance(s, ast.Constant)
                            and isinstance(s.value, str)
                            and s.value != "unknown" for s in sides)):
                bad(node, "!= level compare on a raw graded-verdict "
                          "read")
        # `is None` / `is not None` directly on a raw read: correct
        # for missing/null but reads a junk shape as a voted verdict
        # — read_verdict(...) is None is the junk-safe spelling.
        if isinstance(node, ast.Compare) and all(
                isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            sides = [node.left, *node.comparators]
            if (any(_is_verdict_read(s) for s in sides)
                    and any(isinstance(s, ast.Constant)
                            and s.value is None for s in sides)):
                bad(node, "is/is-not None identity check on a raw "
                          "verdict read")
        # Truthiness (if/while/assert/comprehension-if tests, the
        # positive ternary, and/or operands, bool()): an abstention
        # and an explicit False are indistinguishable, and for the
        # graded keys "unknown" is truthy.
        for t in truth_tested(node):
            if _is_verdict_read(t):
                bad(t, "truthiness on a raw verdict read")
            elif _is_graded_read(t):
                bad(t, "truthiness on a raw graded-verdict read")
        # Membership split of a tri-state domain: `.get(k) in [...]`
        # sends the abstention down whichever branch the container
        # doesn't name. Bind to a name and map each level explicitly.
        if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            if _is_any_verdict_read(node.left):
                bad(node, "membership test on a raw verdict read")
        # Splat-latent: an attribute named like a verdict key on an
        # object constructed from a splatted mapping
        # (SimpleNamespace(**record).is_exploitable) carries the raw
        # value where the dict-read arms above can no longer see it.
        if (isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and node.attr in VERDICT_KEYS
                and isinstance(node.value, ast.Call)
                and any(kw.arg is None for kw in node.value.keywords)):
            bad(node, "verdict attribute read on a splat-constructed "
                      "object")

    # Name-bound pass (bool keys only): the separate-statement
    # spelling of the idiom families above — ``v = r.get(k)`` then
    # ``if v:`` / ``v is None`` / ``v == True`` / ``v in […]`` /
    # ``not v``, and ``v == w`` between two tracked raw reads (the
    # junk==junk agreement mint). See the module docstring for the
    # tracking and laundering rules.
    scopes: list[ast.AST] = [tree]
    scopes += [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        own = _scope_own_nodes(scope)
        tracked = _tracked_verdict_names(scope, own)
        if not tracked:
            continue

        def is_tracked(x: ast.AST) -> bool:
            return (isinstance(x, ast.Name)
                    and isinstance(x.ctx, ast.Load)
                    and x.id in tracked)

        for node in own:
            for t in truth_tested(node):
                if is_tracked(t):
                    bad(t, f"truthiness on a name-bound raw verdict "
                           f"read ({tracked[t.id]!r})")
            if (isinstance(node, ast.UnaryOp)
                    and isinstance(node.op, ast.Not)
                    and is_tracked(node.operand)):
                bad(node, "`not` on a name-bound raw verdict read")
            if not isinstance(node, ast.Compare):
                continue
            sides = [node.left, *node.comparators]
            if all(isinstance(op, (ast.Eq, ast.NotEq))
                   for op in node.ops):
                if (any(is_tracked(s) for s in sides)
                        and any(isinstance(s, ast.Constant)
                                and (isinstance(s.value, bool)
                                     or s.value is None)
                                for s in sides)):
                    bad(node, "==/!= bool/None compare on a "
                              "name-bound raw verdict read")
                if sum(1 for s in sides if is_tracked(s)) >= 2:
                    bad(node, "==/!= between two name-bound raw "
                              "verdict reads (junk == junk mints "
                              "agreement)")
            if all(isinstance(op, (ast.Is, ast.IsNot))
                   for op in node.ops):
                if (any(is_tracked(s) for s in sides)
                        and any(isinstance(s, ast.Constant)
                                and s.value is None for s in sides)):
                    bad(node, "is/is-not None identity check on a "
                              "name-bound raw verdict read")
            if any(isinstance(op, (ast.In, ast.NotIn))
                   for op in node.ops):
                if is_tracked(node.left):
                    bad(node, "membership test on a name-bound raw "
                              "verdict read")
    return out


def _runtime_py_files() -> list[Path]:
    files = []
    for root in _SCAN_ROOTS:
        for p in (REPO_ROOT / root).rglob("*.py"):
            parts = set(p.parts)
            if "tests" in parts or "scripts" in parts:
                continue
            if p.name.startswith("test_") or p.name == "conftest.py":
                continue
            files.append(p)
    # Repo-root entry modules (raptor.py, raptor_fuzzing.py, …):
    # they consume verdict records directly and sat outside every
    # package-rooted sweep.
    files.extend(sorted(REPO_ROOT.glob("raptor*.py")))
    return files


class TestVerdictIdiomClosure:

    def test_scan_sees_the_runtime_tree(self):
        # Guard against the scan going vacuous (e.g. roots renamed).
        files = _runtime_py_files()
        assert len(files) > 100
        assert any("llm_analysis" in str(f) for f in files)
        # Entry modules are in scope — the fuzzing entry point held a
        # misread no package-rooted sweep could see.
        assert any(f.name == "raptor_fuzzing.py" for f in files)

    def test_scanner_catches_each_hostile_idiom(self, tmp_path: Path):
        # The scanner itself is behaviour under test: feed it one
        # planted mutation per idiom family and a set of clean
        # shapes. Written under tmp_path, never the live repo tree —
        # a hostile temp file inside REPO_ROOT would race the closure
        # scan in a parallel worker and, if orphaned by a crash,
        # permanently fail it.
        family_shapes = [
            # (planted shape, expected violation-count)
            ("x = r.get('is_exploitable', False)\n", 1),      # bool default
            ("x = r.get('is_true_positive', 'unknown')\n", 1),  # non-None default
            ("x = r.get('is_exploitable', fallback)\n", 1),   # expr default
            ("y = not r.get('is_true_positive')\n", 1),       # negation
            ("z = r['is_exploitable'] == True\n", 1),         # bool compare
            ("a = r.get('is_exploitable') is None\n", 1),     # is-None ident
            ("if r.get('is_exploitable'):\n    pass\n", 1),   # truthiness
            ("b = 'x' if r.get('is_exploitable') else 'y'\n", 1),  # ternary
            ("c = r.get('is_exploitable') or False\n", 1),    # or-literal
            ("d = bool(r.get('is_true_positive'))\n", 1),     # bool()
            ("e = [f for f in fs if f.get('is_exploitable')]\n", 1),
            ("g = r.get('is_exploitable') in [True, None]\n", 1),  # membership
            ("h = SimpleNamespace(**r).is_exploitable\n", 1),  # splat latent
            # Walrus is a DIRECT read, not variable mediation.
            ("if (v := r.get('is_exploitable')):\n    pass\n", 1),
            ("while (v := r.get('is_true_positive')):\n    pass\n", 1),
            # Eq-spelling of the is-None misread (no E711 backstop).
            ("j = r.get('is_exploitable') == None\n", 1),
            ("j2 = r.get('is_true_positive') != None\n", 1),
        ]
        for i, (shape, expected) in enumerate(family_shapes):
            tmp = tmp_path / f"hostile_{i}.py"
            tmp.write_text(shape, encoding="utf-8")
            found = _violations_in(tmp)
            assert len(found) == expected, (shape, found)
        clean = (
            "v = read_verdict(r, 'is_exploitable')\n"
            "ok = v is False\n"
            "maybe = v is None\n"
            # Value pass-through preserves the tri-state — legal.
            "rec = {'is_exploitable': r.get('is_exploitable')}\n"
            # Bare read bound to a name: outside the scan's
            # vocabulary by design (see module docstring).
            "raw = r.get('is_true_positive')\n"
            # Writes are not reads.
            "r['is_exploitable'] = True\n"
        )
        tmp = tmp_path / "clean_shape.py"
        tmp.write_text(clean, encoding="utf-8")
        assert _violations_in(tmp) == []

    def test_scanner_catches_name_bound_idioms(self, tmp_path: Path):
        # The separate-statement spelling of each flagged family:
        # a single-assignment name bound to a raw verdict read is the
        # raw read, one statement later (CrossFamilyCheckTask minted
        # cross_family_agreed from junk == junk through exactly this
        # shape).
        family_shapes = [
            ("v = r.get('is_exploitable')\nif v:\n    pass\n", 1),
            ("v = r.get('is_exploitable')\nx = not v\n", 1),
            ("v = r['is_true_positive']\nok = v == True\n", 1),  # noqa: E712
            ("v = r.get('is_exploitable')\nif v is None:\n    pass\n", 1),
            ("v = r.get('is_exploitable')\ny = v in (True, None)\n", 1),
            ("v = r.get('is_exploitable')\nz = 'x' if v else 'y'\n", 1),
            ("v = r.get('is_exploitable')\nb = bool(v)\n", 1),
            # Two tracked names compared: junk == junk mints
            # agreement (the CrossFamilyCheckTask shape).
            ("a = p.get('is_exploitable')\n"
             "b = c.get('is_exploitable')\n"
             "if a != b:\n    pass\n", 1),
            # Direct spelling of the pair rule, incl. walrus-wrapped.
            ("ok = p.get('is_exploitable') == r.get('is_exploitable')\n",
             1),
            ("if (a := p.get('is_exploitable')) == "
             "(b := r.get('is_exploitable')):\n    pass\n", 1),
            # Function-scope tracking.
            ("def f(r):\n"
             "    v = r.get('is_exploitable')\n"
             "    return bool(v)\n", 1),
        ]
        for i, (shape, expected) in enumerate(family_shapes):
            tmp = tmp_path / f"namebound_{i}.py"
            tmp.write_text(shape, encoding="utf-8")
            found = _violations_in(tmp)
            assert len(found) == expected, (shape, found)

    def test_name_bound_tracking_launder_rules(self, tmp_path: Path):
        clean = (
            # read_verdict binding: is-None / truthiness on it are the
            # blessed spellings.
            "v = read_verdict(r, 'is_exploitable')\n"
            "if v is None:\n    pass\n"
            "if v:\n    pass\n"
            # isinstance-guarded ladder: semantically equal to
            # read_verdict; the scan cannot judge branch placement,
            # so the shape-check launders the name.
            "w = r.get('is_exploitable')\n"
            "if isinstance(w, bool) and w:\n    pass\n"
            # Reassigned name: a second binding may launder the value
            # — never tracked.
            "def f(r):\n"
            "    x = r.get('is_exploitable')\n"
            "    x = coerce(x)\n"
            "    return bool(x)\n"
            # Parameter shadow in a NESTED scope does not inherit the
            # outer tracking.
            "def g(r):\n"
            "    y = r.get('is_exploitable')\n"
            "    def h(y):\n"
            "        return bool(y)\n"
            "    return {'is_exploitable': y}\n"
            # Pass-through forwarding stays legal.
            "raw = r.get('is_true_positive')\n"
            "rec = {'is_true_positive': raw}\n"
        )
        tmp = tmp_path / "namebound_clean.py"
        tmp.write_text(clean, encoding="utf-8")
        assert _violations_in(tmp) == []

    def test_scanner_catches_graded_key_idioms(self, tmp_path: Path):
        # The graded string tri-state ("unknown" = abstention): one
        # planted mutation per flagged family, plus the blessed
        # spellings staying clean.
        hostile = (
            "a = d.get('exploitability') in ['high', 'medium']\n"
            "b = d.get('exploitability', 'none')\n"
            "c = d.get('exploitability', level_default)\n"
            "if d.get('exploitability'):\n    pass\n"
            "e = not d.get('exploitability')\n"
            "f = bool(d['exploitability'])\n"
            # Negative-equality level split — the membership misread
            # in `!=` spelling.
            "k = d.get('exploitability') != 'low'\n"
            # Walrus-wrapped graded truthiness is a direct read.
            "if (lvl := d.get('exploitability')):\n    pass\n"
        )
        tmp = tmp_path / "graded_hostile.py"
        tmp.write_text(hostile, encoding="utf-8")
        assert len(_violations_in(tmp)) == 8
        clean = (
            "level = d.get('exploitability')\n"
            "level2 = d.get('exploitability', 'unknown')\n"
            "level3 = d.get('exploitability', None)\n"
            "hit = level == 'high'\n"
            "miss = level != 'low'\n"
            # Positive single-level equality on a direct read does
            # not split the tri-state domain.
            "pos = d.get('exploitability') == 'high'\n"
            # Abstention-presence check, not a level split.
            "present = d.get('exploitability') != 'unknown'\n"
            "d['exploitability'] = 'low'\n"
        )
        tmp = tmp_path / "graded_clean.py"
        tmp.write_text(clean, encoding="utf-8")
        assert _violations_in(tmp) == []

    def test_scanner_catches_alias_key_idioms(self, tmp_path: Path):
        # The legacy `exploitable` alias in its verdict-shaped .get
        # forms: same idiom families as the VERDICT_KEYS members.
        hostile_shapes = [
            ("if r.get('exploitable'):\n    pass\n", 1),      # truthiness
            ("x = a or r.get('exploitable')\n", 1),           # or-operand
            ("y = not r.get('exploitable')\n", 1),            # negation
            ("z = r.get('exploitable') == True\n", 1),        # noqa: E712
            ("d = r.get('exploitable', False)\n", 1),         # bool default
            ("n = r.get('exploitable') is None\n", 1),        # is-None
            ("v = r.get('exploitable')\nif v:\n    pass\n", 1),  # name-bound
        ]
        for i, (shape, expected) in enumerate(hostile_shapes):
            tmp = tmp_path / f"alias_hostile_{i}.py"
            tmp.write_text(shape, encoding="utf-8")
            found = _violations_in(tmp)
            assert len(found) == expected, (shape, found)
        clean = (
            # Blessed genuine-bool spellings (agentic_passes /
            # roundtrip precedent).
            "ok = r.get('exploitable') is True\n"
            "legacy = f.get('exploitable')\n"
            "if isinstance(legacy, bool):\n"
            "    f['is_exploitable'] = legacy\n"
            # Stats-counter idiom: int default and subscript tallies
            # are status-value buckets, not verdict record reads.
            "count = stats.get('exploitable', 0)\n"
            "if stats.get('exploitable', 0):\n    pass\n"
            "counts['exploitable'] += 1\n"
            "if counts['exploitable']:\n    pass\n"
            # Pass-through forwarding.
            "rec = {'exploitable': r.get('exploitable')}\n"
        )
        tmp = tmp_path / "alias_clean.py"
        tmp.write_text(clean, encoding="utf-8")
        assert _violations_in(tmp) == []

    def test_scanner_catches_parser_folded_keys(self, tmp_path: Path):
        # Contract against any future text prescreen: the parser folds
        # adjacent string literals and escape sequences into a plain
        # ast.Constant, so these misreads are scannable even though
        # the source text never contains a VERDICT_KEYS member. A
        # "skip files that don't mention a key" optimisation silently
        # dropped both; the scan must flag them.
        folded = (
            "a = r.get('is_' 'exploitable', False)\n"
            "b = r.get('is_exploitabl\\x65', False)\n"
        )
        tmp = tmp_path / "folded_shapes.py"
        tmp.write_text(folded, encoding="utf-8")
        assert len(_violations_in(tmp)) == 2

    def test_smoke_selector_contract(self):
        # The smoke selector must pick up every direct textual mention
        # of every VERDICT_KEYS member (so the default-tier smoke scans
        # all realistically-written verdict readers), and — pinned here
        # so the docstring stays true — it does NOT see parser-folded
        # key literals: those are exactly why the nightly full scan
        # exists and must never be re-labelled "covered" by the smoke.
        for key in (*VERDICT_KEYS, *_GRADED_VERDICT_KEYS,
                    *_BOOL_ALIAS_GET_KEYS):
            assert _mentions_verdict_key(f"v = r.get('{key}', False)\n")
        assert not _mentions_verdict_key("v = r.get('status', False)\n")
        # (The 'is_' 'exploitable' fold is no longer a valid example
        # here: the alias key 'exploitable' is a substring of its
        # second fragment, so the selector NOW sees that source. The
        # is_true_positive fold keeps the pinned blind spot honest.)
        assert not _mentions_verdict_key(
            "v = r.get('is_' 'true_positive', False)\n"
        )

    def test_smoke_no_misreads_in_key_mentioning_runtime_code(self):
        # Default-tier smoke: scan only the runtime files whose text
        # mentions a verdict key — the subset every realistically
        # written misread lives in (the flagged idioms read the key as
        # a string/attribute literal, which appears verbatim in source
        # unless deliberately split/escaped). Parser-folded literals
        # are invisible to the selector and are owned by the nightly
        # full scan below; the folded-shapes scanner test above keeps
        # the detection itself pinned daily.
        subset = []
        for f in _runtime_py_files():
            try:
                if _mentions_verdict_key(f.read_text(encoding="utf-8")):
                    subset.append(f)
            except (OSError, UnicodeDecodeError):
                continue
        # Vacuousness guard for the subset (mirrors
        # test_scan_sees_the_runtime_tree).
        assert len(subset) >= 5
        violations = []
        for f in subset:
            violations.extend(_violations_in(f))
        assert violations == [], (
            "raw tri-state verdict misread(s); route bool verdict "
            "keys through core.run.finding_status.read_verdict, and "
            "bind graded keys to a name with an explicit unknown "
            "arm:\n" + "\n".join(violations)
        )

    # Full-tree scan: genuinely heavy (a full AST parse + walk of every
    # runtime module; it breached the default tier's per-test budget on
    # CI), so it runs in the nightly tier. Trade-off, both directions:
    # unmarking it puts a multi-second, contention-sensitive test back
    # in every PR run; marking it WITHOUT the smoke above would leave a
    # new misread invisible until the next nightly. The smoke covers
    # every file that textually mentions a key on every PR; only
    # parser-folded key literals wait for nightly.
    @pytest.mark.slow
    def test_no_raw_tri_state_misreads_in_runtime_code(self):
        violations = []
        for f in _runtime_py_files():
            violations.extend(_violations_in(f))
        assert violations == [], (
            "raw tri-state verdict misread(s); route bool verdict "
            "keys through core.run.finding_status.read_verdict, and "
            "bind graded keys to a name with an explicit unknown "
            "arm:\n" + "\n".join(violations)
        )
