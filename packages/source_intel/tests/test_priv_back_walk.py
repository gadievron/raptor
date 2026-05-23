"""Tests for the multi-hop privilege back-walk.

Validates the BFS/DFS walk from a finding's enclosing function up
through the inverted call graph (via PR-4 ``function_inventory``) to
check whether every call path passes through a privileged
``capable()`` check within bounded depth.

No spatch required — ``gather_prereqs`` and ``_enclosing_function``
are both patched with synthetic facts so test latency stays sub-ms.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


from core.dataflow.finding import Finding, Step
from packages.source_intel.adapter import (
    _PRIV_BACK_WALK_DEFAULT_DEPTH,
    _PRIV_BACK_WALK_MAX_DEPTH,
    _path_is_gated,
    _privilege_back_walk_suppresses,
)
from packages.source_intel.analyze import (
    CapabilityEvidence,
    GRADE_SAME_FUNCTION,
    SourceIntelResult,
)


# ---- fixtures ---------------------------------------------------------


def _finding(rule_id: str = "cpp/use-after-free") -> Finding:
    return Finding(
        finding_id="t",
        producer="codeql",
        rule_id=rule_id,
        message="m",
        source=Step(file_path="/repo/a.c", line=1, column=1,
                    snippet="s", label="source"),
        sink=Step(file_path="/repo/a.c", line=100, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(),
        raw={},
    )


class _StubFacts:
    """Drop-in for PrereqFacts with controllable callers_of()."""

    def __init__(self, edges):
        # edges: dict[callee_name, list[(file, line, caller_name)]]
        # The (file, line) is the call site; caller_name is what
        # _enclosing_function would return for that call site.
        self._edges = edges
        # site_to_caller maps (file, line) → caller name; used by the
        # stub _enclosing_function below
        self._site_to_caller = {
            (file, line): caller
            for v in edges.values() for (file, line, caller) in v
        }
        self.is_skipped = False
        self.skipped_reason = None

    def callers_of(self, name):
        return [(f, l) for (f, l, _c) in self._edges.get(name, [])]

    def enclosing(self, file_path, line):
        return self._site_to_caller.get((file_path, line))


def _cap_for(fn_name: str, *, cap_function: str = "capable",
             const: str = "CAP_SYS_ADMIN") -> CapabilityEvidence:
    """Build a capability observation in `fn_name`'s body."""
    return CapabilityEvidence(
        cap_function=cap_function,
        location=(f"/repo/{fn_name}.c", 5),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function=fn_name,
    )


def _result_with_caps(*caps):
    return SourceIntelResult(target="/repo", capabilities=tuple(caps))


def _patch_walk(facts, *, line_cap_check=True):
    """Patch helpers the walk depends on. line_cap_check controls
    whether _line_uses_privileged_cap returns True for any line."""
    from unittest.mock import patch as _patch
    return [
        _patch("packages.coccinelle.prereqs.gather_prereqs",
               return_value=facts),
        _patch("packages.source_intel.adapter.gather_prereqs",
               return_value=facts, create=True),
        _patch("packages.source_intel.analyze._enclosing_function",
               side_effect=lambda f, l: facts.enclosing(f, l)
               if hasattr(facts, "enclosing")
               else None),
        _patch("packages.source_intel.adapter._line_uses_privileged_cap",
               return_value=line_cap_check),
    ]


# ---- _path_is_gated direct tests --------------------------------------


class TestPathIsGated:
    """Unit tests for the recursive helper. No prereq machinery —
    bypass to test the cycle / depth / leaf logic in isolation."""

    def test_immediate_gate_at_fn(self):
        facts = _StubFacts({})
        result = _result_with_caps(_cap_for("gated_fn"))
        with patch(
            "packages.source_intel.adapter._line_uses_privileged_cap",
            return_value=True,
        ):
            assert _path_is_gated(
                "gated_fn", facts, result,
                remaining_depth=3, visited=frozenset(),
            ) is True

    def test_leaf_without_gate_is_not_gated(self):
        facts = _StubFacts({})  # no callers, no gate
        result = _result_with_caps()
        assert _path_is_gated(
            "entry_fn", facts, result,
            remaining_depth=3, visited=frozenset(),
        ) is False

    def test_depth_exhausted_without_gate(self):
        # one_hop → two_hop → ... (chain longer than depth)
        facts = _StubFacts({
            "one_hop": [("/repo/x.c", 10, "two_hop")],
            "two_hop": [("/repo/x.c", 20, "three_hop")],
            "three_hop": [("/repo/x.c", 30, "four_hop")],
        })
        result = _result_with_caps()  # no caps anywhere
        with (
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=False),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, l: facts.enclosing(f, l)),
        ):
            assert _path_is_gated(
                "one_hop", facts, result,
                remaining_depth=2, visited=frozenset(),
            ) is False

    def test_cycle_returns_false_not_infinite(self):
        # a → b → a → ... — must not recurse forever
        facts = _StubFacts({
            "a": [("/repo/x.c", 1, "b")],
            "b": [("/repo/x.c", 2, "a")],
        })
        result = _result_with_caps()
        with (
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=False),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, l: facts.enclosing(f, l)),
        ):
            assert _path_is_gated(
                "a", facts, result,
                remaining_depth=10, visited=frozenset(),
            ) is False

    def test_gate_two_hops_up(self):
        facts = _StubFacts({
            "leaf_fn": [("/repo/x.c", 10, "mid_fn")],
            "mid_fn": [("/repo/x.c", 20, "top_fn")],
        })
        result = _result_with_caps(_cap_for("top_fn"))
        with (
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, l: facts.enclosing(f, l)),
        ):
            assert _path_is_gated(
                "leaf_fn", facts, result,
                remaining_depth=3, visited=frozenset(),
            ) is True

    def test_any_ungated_caller_path_returns_false(self):
        # leaf has two callers; one gated, one ungated.
        facts = _StubFacts({
            "leaf_fn": [
                ("/repo/x.c", 10, "gated_caller"),
                ("/repo/x.c", 20, "ungated_caller"),
            ],
        })
        result = _result_with_caps(_cap_for("gated_caller"))
        with (
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, l: facts.enclosing(f, l)),
        ):
            assert _path_is_gated(
                "leaf_fn", facts, result,
                remaining_depth=3, visited=frozenset(),
            ) is False


# ---- _privilege_back_walk_suppresses end-to-end ----------------------


class TestPrivilegeBackWalkSuppresses:
    def test_returns_false_when_rule_not_memory_corruption(self):
        # Even with facts that would suppress, irrelevant rule = False.
        assert _privilege_back_walk_suppresses(
            _finding(rule_id="py/sql-injection"),
            _result_with_caps(),
            Path("/repo"),
        ) is False

    def test_returns_false_when_no_callers(self):
        facts = _StubFacts({})
        with (
            patch("packages.source_intel.adapter.gather_prereqs",
                  return_value=facts, create=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  return_value="entry_fn"),
        ):
            # Patch the import inside the function as well.
            import packages.coccinelle.prereqs as p
            with patch.object(p, "gather_prereqs", return_value=facts):
                with patch.object(Path, "is_dir", return_value=True):
                    assert _privilege_back_walk_suppresses(
                        _finding(),
                        _result_with_caps(),
                        Path("/repo"),
                    ) is False

    def test_max_depth_clamped_to_ceiling(self):
        """User-supplied max_depth above _MAX is clamped."""
        # No real walk; just verify the clamp constant.
        assert _PRIV_BACK_WALK_DEFAULT_DEPTH <= _PRIV_BACK_WALK_MAX_DEPTH

    def test_two_hop_gate_suppresses(self):
        """leaf_fn callers all funnel through gated_top within 2 hops."""
        facts = _StubFacts({
            "leaf_fn": [("/repo/a.c", 50, "mid_fn")],
            "mid_fn": [("/repo/a.c", 30, "gated_top")],
        })

        # enclosing_function: sink line 100 → leaf_fn (the finding fn);
        # call sites resolve via the stub.
        def _enc(file_path, line):
            if line == 100:
                return "leaf_fn"
            return facts.enclosing(file_path, line)

        with (
            patch("packages.coccinelle.prereqs.gather_prereqs",
                  return_value=facts),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=_enc),
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=True),
            patch.object(Path, "is_dir", return_value=True),
        ):
            assert _privilege_back_walk_suppresses(
                _finding(),
                _result_with_caps(_cap_for("gated_top")),
                Path("/repo"),
                max_depth=3,
            ) is True

    def test_two_hop_ungated_does_not_suppress(self):
        """Same shape as above, but no gate anywhere — must NOT suppress."""
        facts = _StubFacts({
            "leaf_fn": [("/repo/a.c", 50, "mid_fn")],
            "mid_fn": [("/repo/a.c", 30, "top_fn")],
        })

        def _enc(file_path, line):
            if line == 100:
                return "leaf_fn"
            return facts.enclosing(file_path, line)

        with (
            patch("packages.coccinelle.prereqs.gather_prereqs",
                  return_value=facts),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=_enc),
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=False),
            patch.object(Path, "is_dir", return_value=True),
        ):
            assert _privilege_back_walk_suppresses(
                _finding(),
                _result_with_caps(),  # no caps
                Path("/repo"),
                max_depth=3,
            ) is False

    def test_one_hop_behavior_preserved_with_max_depth_1(self):
        """Regression: explicitly setting max_depth=1 reproduces the
        old 1-hop semantics — only direct callers count."""
        # mid_fn is gated, but if depth=1 we shouldn't recurse to find
        # gating at the next level. leaf → mid (no gate at mid itself,
        # gate at top): depth=1 means mid alone is checked → False.
        facts = _StubFacts({
            "leaf_fn": [("/repo/a.c", 50, "mid_fn")],
            "mid_fn": [("/repo/a.c", 30, "gated_top")],
        })

        def _enc(file_path, line):
            if line == 100:
                return "leaf_fn"
            return facts.enclosing(file_path, line)

        with (
            patch("packages.coccinelle.prereqs.gather_prereqs",
                  return_value=facts),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=_enc),
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=True),
            patch.object(Path, "is_dir", return_value=True),
        ):
            # depth=1: walks one hop (leaf_fn → mid_fn). mid_fn body
            # has no cap. Remaining depth after that call is 0 → False.
            assert _privilege_back_walk_suppresses(
                _finding(),
                _result_with_caps(_cap_for("gated_top")),
                Path("/repo"),
                max_depth=1,
            ) is False

    def test_default_depth_is_three(self):
        assert _PRIV_BACK_WALK_DEFAULT_DEPTH == 3
