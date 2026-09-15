"""Tri-state verdict accessor semantics + runtime idiom closure.

``read_verdict`` is the one shared read for the ``VERDICT_KEYS``
boolean fields (``is_true_positive`` / ``is_exploitable``). Those
fields are tri-state: True / False / abstained (missing, schema-nulled
None, or malformed shape). Reading an abstention as a NEGATIVE verdict
— via a bool ``.get`` default, ``not``, or an ``==`` bool compare —
has repeatedly demoted findings whose analysis response was merely
malformed. The closure test scans every runtime module for those
idioms so a new member of the class cannot be written without either
routing through the accessor or consciously editing this test.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

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
#: legitimately build records with literal defaults.
_SCAN_ROOTS = ("core", "packages", "plugins")

#: (path-suffix, lineno) pairs reviewed and deliberately exempted.
#: Keep this empty unless a site has a documented reason the shared
#: accessor cannot express (none known today).
_ALLOWLIST: frozenset[tuple[str, int]] = frozenset()


def _is_verdict_read(node: ast.AST) -> bool:
    """True for ``X.get("<verdict key>"[, d])`` or ``X["<verdict key>"]``."""
    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in VERDICT_KEYS):
        return True
    if (isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in VERDICT_KEYS):
        return True
    return False


def _violations_in(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
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
        out.append(f"{rel}:{node.lineno}: {why} — use "
                   f"core.run.finding_status.read_verdict")

    for node in ast.walk(tree):
        # A bool default turns an abstention into a fabricated verdict.
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in VERDICT_KEYS
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, bool)):
            bad(node, f"bool default on .get({node.args[0].value!r}, ...)")
        # `not <raw read>` reads an abstention as an explicit negative.
        if (isinstance(node, ast.UnaryOp)
                and isinstance(node.op, ast.Not)
                and _is_verdict_read(node.operand)):
            bad(node, "`not` on a raw verdict read")
        # ==/!= against a bool constant silently mishandles None
        # (and non-bool junk); identity checks on read_verdict()'s
        # result are the explicit form.
        if isinstance(node, ast.Compare) and all(
                isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            sides = [node.left, *node.comparators]
            if (any(_is_verdict_read(s) for s in sides)
                    and any(isinstance(s, ast.Constant)
                            and isinstance(s.value, bool) for s in sides)):
                bad(node, "==/!= bool compare on a raw verdict read")
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
    return files


class TestVerdictIdiomClosure:

    def test_scan_sees_the_runtime_tree(self):
        # Guard against the scan going vacuous (e.g. roots renamed).
        files = _runtime_py_files()
        assert len(files) > 100
        assert any("llm_analysis" in str(f) for f in files)

    def test_scanner_catches_each_hostile_idiom(self, tmp_path: Path):
        # The scanner itself is behaviour under test: feed it the
        # three hostile shapes and one clean shape. Written under
        # tmp_path, never the live repo tree — a hostile temp file
        # inside REPO_ROOT would race the closure scan in a parallel
        # worker and, if orphaned by a crash, permanently fail it.
        hostile = (
            "x = r.get('is_exploitable', False)\n"
            "y = not r.get('is_true_positive')\n"
            "z = r['is_exploitable'] == True\n"
        )
        tmp = tmp_path / "hostile_shapes.py"
        tmp.write_text(hostile, encoding="utf-8")
        found = _violations_in(tmp)
        assert len(found) == 3
        clean = "v = read_verdict(r, 'is_exploitable')\nok = v is False\n"
        tmp = tmp_path / "clean_shape.py"
        tmp.write_text(clean, encoding="utf-8")
        assert _violations_in(tmp) == []

    def test_no_raw_tri_state_misreads_in_runtime_code(self):
        violations = []
        for f in _runtime_py_files():
            violations.extend(_violations_in(f))
        assert violations == [], (
            "raw tri-state verdict misread(s); route through "
            "core.run.finding_status.read_verdict:\n" + "\n".join(violations)
        )
