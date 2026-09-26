"""Cumulative retained-byte budget on :func:`load_call_graphs`.

``max_bytes`` gates INPUT per file only; without an output budget the
extraction loop retains unbounded OUTPUT — a call-dense file near the
input gate measures tens of MB retained on its own (a 1.48 MB
minimal-call fixture measured ~53 MiB deep). The budget bounds the
whole returned mapping (it is cached for the entire run), skip-and-
count on exceed, one loud warning naming the top offender. Two
directions pinned per the churn-prone-limits doctrine: normal trees
are unaffected; pathological density trips the budget.
"""
import logging
import sys

import pytest

import core.inventory.call_graph as cg


def _deep_size(obj, seen=None) -> int:
    """sys.getsizeof-deep with id-dedup (shared strings counted
    once). Test-local measurement oracle for the estimator pin."""
    if seen is None:
        seen = set()
    oid = id(obj)
    if oid in seen:
        return 0
    seen.add(oid)
    size = sys.getsizeof(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            size += _deep_size(k, seen) + _deep_size(v, seen)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for it in obj:
            size += _deep_size(it, seen)
    if hasattr(obj, "__dict__"):
        size += _deep_size(vars(obj), seen)
    if hasattr(type(obj), "__slots__"):
        for slot in type(obj).__slots__:
            if hasattr(obj, slot):
                size += _deep_size(getattr(obj, slot), seen)
    return size


def _dense_py(n_funcs: int) -> str:
    """Maximally call-dense python: semicolon-packed tiny calls with
    an identifier argument — the highest retained-bytes-per-input-
    byte shape measured (each call site retains a CallSite + chain +
    argument_identifiers)."""
    lines = []
    for i in range(n_funcs):
        lines.append(f"def f{i}(a):")
        for _ in range(4):
            lines.append("    " + "; ".join("g(a)" for _ in range(12)))
    return "\n".join(lines) + "\n"


_NORMAL_PY = (
    "import os\n\n"
    "def handler(request):\n"
    "    data = request.get_json()\n"
    "    result = service.process(data)\n"
    "    return jsonify(result)\n"
)


def _checklist(names):
    return {"files": [{"path": n} for n in names]}


class TestBudgetUnaffectedDirection:
    """Direction 1: ordinary trees never feel the budget."""

    def test_normal_tree_fully_retained_no_warning(self, tmp_path,
                                                   caplog):
        for i in range(5):
            (tmp_path / f"m{i}.py").write_text(_NORMAL_PY,
                                               encoding="utf-8")
        with caplog.at_level(logging.WARNING,
                             logger="core.inventory.call_graph"):
            graphs = cg.load_call_graphs(tmp_path)
        assert len(graphs) == 5
        assert "retained-byte budget" not in caplog.text

    def test_default_budget_fits_kernel_scale_checklist(self):
        # The budget meters ESTIMATED bytes, so both direction pins
        # are in estimated units. It must fit a checklist-ceiling run
        # at the measured kernel average (~15 KiB retained/file →
        # ~300 MiB at the 20k ceiling) with headroom, and a
        # python-heavy tree at this repo's own measured density
        # (~42 KiB/file as the estimator charges it — 41.5 KiB
        # measured over core/ with the arg-facts base at its
        # empty-object cost → ~820 MiB).
        # LOWERING below either point drops cross-function context on
        # honestly dense trees — change deliberately, re-measure.
        kernel_scale = cg._CHECKLIST_MAX_FILES * 15 * 1024
        dense_scale = cg._CHECKLIST_MAX_FILES * 42 * 1024
        assert cg.CALL_GRAPH_MAX_TOTAL_BYTES >= 2 * kernel_scale
        assert cg.CALL_GRAPH_MAX_TOTAL_BYTES >= dense_scale
        # ...and RAISING past 1 GiB only admits degenerate call
        # density (an input-cap call-dense file measures ~53 MiB
        # retained, ~57 MiB estimated — ~18 already fit) while the
        # mapping is cached for the whole run.
        assert cg.CALL_GRAPH_MAX_TOTAL_BYTES <= 1024 ** 3


class TestBudgetTripsDirection:
    """Direction 2: pathological density trips the budget —
    skip-and-count, pre-budget graphs kept, one loud warning naming
    the offender."""

    def _tree(self, tmp_path):
        # Checklist fixes extraction order: two small files fit, the
        # dense third exhausts the budget, the trailing small file
        # documents the sticky stop.
        (tmp_path / "small1.py").write_text(_NORMAL_PY,
                                            encoding="utf-8")
        (tmp_path / "small2.py").write_text(_NORMAL_PY,
                                            encoding="utf-8")
        (tmp_path / "dense.py").write_text(_dense_py(4),
                                           encoding="utf-8")
        (tmp_path / "small3.py").write_text(_NORMAL_PY,
                                            encoding="utf-8")
        return _checklist(
            ["small1.py", "small2.py", "dense.py", "small3.py"])

    def test_budget_exceeded_stops_retention(self, tmp_path, caplog):
        checklist = self._tree(tmp_path)
        small = cg.estimate_call_graph_bytes(
            cg.extract_call_graph_python(_NORMAL_PY))
        dense = cg.estimate_call_graph_bytes(
            cg.extract_call_graph_python(_dense_py(4)))
        # Two small graphs fit; the dense one is under the WHOLE
        # budget (not the monster case) but over the remaining slack
        # — the cumulative-exhaustion path.
        budget = small * 2 + dense - 1
        assert dense < budget
        with caplog.at_level(logging.WARNING,
                             logger="core.inventory.call_graph"):
            graphs = cg.load_call_graphs(tmp_path, checklist,
                                         max_total_bytes=budget)
        # Pre-budget graphs are never dropped.
        assert set(graphs) == {"small1.py", "small2.py"}
        # Sticky stop: small3 would fit the remaining slack but
        # extraction stopped at the budget hit.
        assert "small3.py" not in graphs
        warnings = [r for r in caplog.records
                    if "retained-byte budget" in r.getMessage()]
        assert len(warnings) == 1  # ONE loud warning
        msg = warnings[0].getMessage()
        assert str(budget) in msg           # names the budget
        assert "2 candidate" in msg         # skip count
        assert "dense.py" in msg            # top offender named
        assert "partial call-graph context" in msg

    def test_monster_single_graph_refused_small_files_survive(
            self, tmp_path, caplog):
        # A single graph larger than the WHOLE budget can never fit:
        # it is refused (not retained-then-stop) so the small files
        # behind it keep their cross-function context.
        (tmp_path / "monster.py").write_text(_dense_py(60),
                                             encoding="utf-8")
        (tmp_path / "small1.py").write_text(_NORMAL_PY,
                                            encoding="utf-8")
        (tmp_path / "small2.py").write_text(_NORMAL_PY,
                                            encoding="utf-8")
        checklist = _checklist(["monster.py", "small1.py",
                                "small2.py"])
        small = cg.estimate_call_graph_bytes(
            cg.extract_call_graph_python(_NORMAL_PY))
        budget = small * 3
        assert cg.estimate_call_graph_bytes(
            cg.extract_call_graph_python(_dense_py(60))) > budget
        with caplog.at_level(logging.WARNING,
                             logger="core.inventory.call_graph"):
            graphs = cg.load_call_graphs(tmp_path, checklist,
                                         max_total_bytes=budget)
        assert set(graphs) == {"small1.py", "small2.py"}
        warnings = [r for r in caplog.records
                    if "retained-byte budget" in r.getMessage()]
        assert len(warnings) == 1
        assert "monster.py" in warnings[0].getMessage()

    def test_explicit_budget_honoured_verbatim(self, tmp_path):
        (tmp_path / "a.py").write_text(_NORMAL_PY, encoding="utf-8")
        graphs = cg.load_call_graphs(tmp_path, max_total_bytes=1)
        assert graphs == {}

    def test_file_cap_warning_shape_untouched(self, tmp_path, caplog):
        # The budget warning is additive — the existing file-cap
        # warning keeps its own trigger and wording.
        for i in range(3):
            (tmp_path / f"m{i}.py").write_text(_NORMAL_PY,
                                               encoding="utf-8")
        with caplog.at_level(logging.WARNING,
                             logger="core.inventory.call_graph"):
            graphs = cg.load_call_graphs(tmp_path, max_files=1)
        assert len(graphs) == 1
        assert "file cap (1) reached" in caplog.text
        assert "retained-byte budget" not in caplog.text


class TestEstimator:
    """estimate_call_graph_bytes pinned against a real deep-size
    measurement — loose 2.5x band both ways so constant drift in
    CPython object sizes doesn't flake the suite."""

    def test_estimator_tracks_pathological_deep_size(self):
        g = cg.extract_call_graph_python(_dense_py(400))
        deep = _deep_size(g)
        est = cg.estimate_call_graph_bytes(g)
        assert deep > 500_000  # the pathological shape is real
        assert deep / 2.5 <= est <= deep * 2.5

    def test_estimator_tracks_normal_deep_size(self):
        g = cg.extract_call_graph_python(_NORMAL_PY * 40)
        deep = _deep_size(g)
        est = cg.estimate_call_graph_bytes(g)
        assert deep / 2.5 <= est <= deep * 2.5

    def test_estimator_counts_php_include_edges(self):
        # The include-edge / define layer (PHP walker) must be
        # charged too — a PHP-heavy tree budgets like any other.
        # extract_call_graph_php returns an EMPTY graph without the
        # grammar wheel (documented degradation), so the charging pin
        # needs tree-sitter-php present — the same guard the
        # include-edge suite carries. Every other test in this file
        # runs the stdlib-ast Python extractor and stays unguarded.
        pytest.importorskip("tree_sitter_php")
        php = "<?php\n" + "\n".join(
            f"include('inc/mod{k}.php'); define('C{k}', 'v{k}');"
            for k in range(200))
        g = cg.extract_call_graph_php(php)
        assert g.includes and g.defines
        deep = _deep_size(g)
        est = cg.estimate_call_graph_bytes(g)
        assert deep / 2.5 <= est <= deep * 2.5

    def test_estimator_charges_long_caller_names(self):
        # Adversarial shape: many functions with LONG names, one tiny
        # call each. `caller` is the enclosing function name —
        # attacker-shaped and distinct per function — so an estimator
        # that skips it lets this shape defeat the budget (true size
        # many times the charged size). Byte-aware charging keeps it
        # in band.
        src = "\n".join(
            f"def f{i}_{'x' * 2000}(a):\n    g(a)" for i in range(200))
        g = cg.extract_call_graph_python(src)
        deep = _deep_size(g)
        est = cg.estimate_call_graph_bytes(g)
        assert deep > 400_000  # the long names really are retained
        assert deep / 2.5 <= est <= deep * 2.5

    def test_estimator_charges_astral_identifiers(self):
        # Wide (UCS-4) identifiers occupy 4 bytes per char in memory;
        # a char-length charge undercounts them 4x. Charging through
        # sys.getsizeof keeps astral-name shapes in band.
        wide = "\U00010400" * 150  # Deseret letters, identifier-valid
        src = "\n".join(
            f"def f{i}_{wide}(a):\n    g(a)" for i in range(200))
        g = cg.extract_call_graph_python(src)
        deep = _deep_size(g)
        est = cg.estimate_call_graph_bytes(g)
        assert deep / 2.5 <= est <= deep * 2.5

    def test_estimator_monotone_in_density(self):
        small = cg.extract_call_graph_python(_dense_py(5))
        big = cg.extract_call_graph_python(_dense_py(50))
        assert (cg.estimate_call_graph_bytes(big)
                > cg.estimate_call_graph_bytes(small))

    def test_exported(self):
        assert "estimate_call_graph_bytes" in cg.__all__
        assert "CALL_GRAPH_MAX_TOTAL_BYTES" in cg.__all__

    def test_estimator_charges_decorator_floods(self):
        # Adversarial shape: `@d()` repeated — every CALL decorator
        # allocates one (empty) CallArgumentFacts, the only UNCAPPED
        # facts carrier (constructed_objects and string_ref_calls
        # are capped). An arg-facts base charge below the measured
        # empty-object cost lets this shape under-charge (a 200 B
        # base measured est/deep 0.63 at 160x input amplification,
        # ~1.6x budget overshoot), so this fixture pins a tighter
        # floor than the drift band: the estimator must never
        # under-charge the flood by more than 1.5x. The upper bound
        # stays at the suite's loose 2.5x drift band.
        src = "\n".join(
            "@d()\n" * 50 + f"def f{i}(a): pass" for i in range(200))
        g = cg.extract_call_graph_python(src)
        assert len(g.decorated_functions) == 200
        assert all(a is not None for d in g.decorated_functions
                   for a in d.decorator_args)
        deep = _deep_size(g)
        est = cg.estimate_call_graph_bytes(g)
        assert deep > 5_000_000  # the flood really amplifies
        assert deep / 1.5 <= est <= deep * 2.5

    def test_arg_facts_base_covers_empty_object_cost(self):
        # The base charge tracks the true deep size of an EMPTY
        # CallArgumentFacts (slots instance + 4 empty dicts + 3
        # empty lists — 548 B on 64-bit CPython 3.14). Tight band on
        # purpose: the flood fixture above only amplifies this
        # per-object gap, so catch drift at the object level first.
        deep = _deep_size(cg.CallArgumentFacts())
        est = cg._est_arg_facts(cg.CallArgumentFacts())
        assert deep / 1.5 <= est <= deep * 1.5
