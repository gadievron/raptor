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
    GRADE_SAME_FUNCTION,
    CapabilityEvidence,
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
        return [(f, line) for (f, line, _c) in self._edges.get(name, [])]

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
        with patch(
            "packages.source_intel.adapter._function_is_static",
            return_value=True,
        ):
            assert _path_is_gated(
                "entry_fn", facts, result,
                remaining_depth=3, visited=frozenset(),
                fn_file="/repo/x.c",
            ) is False

    def test_non_static_fn_cannot_prove_gating(self):
        """The prereq scan is directory-scoped: a non-static function
        may have unseen callers in other translation units, so its
        in-scope caller set can't prove every path is gated — even
        when every SEEN caller is."""
        facts = _StubFacts({
            "leaf_fn": [("/repo/x.c", 10, "gated_caller")],
        })
        result = _result_with_caps(_cap_for("gated_caller"))
        with (
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=True),
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=False),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, line: facts.enclosing(f, line)),
        ):
            assert _path_is_gated(
                "leaf_fn", facts, result,
                remaining_depth=3, visited=frozenset(),
                fn_file="/repo/x.c",
            ) is False

    def test_unknown_defining_file_cannot_prove_gating(self):
        """Without knowing where the function lives, its linkage —
        and therefore caller-set completeness — can't be verified."""
        facts = _StubFacts({
            "leaf_fn": [("/repo/x.c", 10, "gated_caller")],
        })
        result = _result_with_caps(_cap_for("gated_caller"))
        with (
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=True),
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, line: facts.enclosing(f, line)),
        ):
            assert _path_is_gated(
                "leaf_fn", facts, result,
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
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, line: facts.enclosing(f, line)),
        ):
            assert _path_is_gated(
                "one_hop", facts, result,
                remaining_depth=2, visited=frozenset(),
                fn_file="/repo/x.c",
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
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, line: facts.enclosing(f, line)),
        ):
            assert _path_is_gated(
                "a", facts, result,
                remaining_depth=10, visited=frozenset(),
                fn_file="/repo/x.c",
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
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, line: facts.enclosing(f, line)),
        ):
            assert _path_is_gated(
                "leaf_fn", facts, result,
                remaining_depth=3, visited=frozenset(),
                fn_file="/repo/x.c",
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
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=True),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=lambda f, line: facts.enclosing(f, line)),
        ):
            assert _path_is_gated(
                "leaf_fn", facts, result,
                remaining_depth=3, visited=frozenset(),
                fn_file="/repo/x.c",
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
            patch("packages.source_intel.analyze._enclosing_function",
                  return_value="entry_fn"),
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=True),
        ):
            # Patch the import inside the gather helper as well.
            import packages.coccinelle.prereqs as p
            with patch.object(p, "gather_prereqs", return_value=facts), \
                    patch.object(Path, "is_dir", return_value=True):
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
            patch("packages.source_intel.adapter._function_is_static",
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
            patch("packages.source_intel.adapter._function_is_static",
                  return_value=True),
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
            patch("packages.source_intel.adapter._function_is_static",
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

    def test_non_static_finding_fn_never_suppressed(self, tmp_path):
        """Two-direction linkage gate on real files: the prereq scan
        only sees the sink file's parent directory, so a NON-static
        finding function may have ungated callers in other
        translation units the walk can't see — even a fully-gated
        in-scope caller set must not suppress. The identical shape
        with `static` linkage (all callers provably in-file) still
        suppresses."""
        gated_line = 5
        non_static = tmp_path / "a.c"
        non_static.write_text(
            "int leaf_fn(int a)\n"
            "{\n"
            "    return a * 2;\n"
            "}\n"
            "static int caller(int a)\n"
            "{\n"
            "    if (!capable(CAP_SYS_ADMIN)) return -1;\n"
            "    return leaf_fn(a);\n"
            "}\n"
        )

        facts = _StubFacts({
            "leaf_fn": [(str(non_static), 8, "caller")],
        })
        finding = Finding(
            finding_id="t", producer="codeql",
            rule_id="cpp/use-after-free", message="m",
            source=Step(file_path=str(non_static), line=3, column=1,
                        snippet="s", label="source"),
            sink=Step(file_path=str(non_static), line=3, column=1,
                      snippet="x", label="sink"),
            intermediate_steps=(), raw={},
        )
        caps = _result_with_caps(CapabilityEvidence(
            cap_function="capable",
            location=(str(non_static), gated_line + 2),
            grade=GRADE_SAME_FUNCTION,
            enclosing_function="caller",
        ))

        def _enc(file_path, line):
            if line == 3:
                return "leaf_fn"
            return facts.enclosing(file_path, line)

        with (
            patch("packages.coccinelle.prereqs.gather_prereqs",
                  return_value=facts),
            patch("packages.source_intel.analyze._enclosing_function",
                  side_effect=_enc),
            patch("packages.source_intel.adapter._line_uses_privileged_cap",
                  return_value=True),
        ):
            # Direction 1: non-static finding fn — must NOT suppress.
            assert _privilege_back_walk_suppresses(
                finding, caps, tmp_path,
            ) is False

            # Direction 2: identical shape, static linkage — still
            # suppresses (the legitimately-gated case keeps working).
            non_static.write_text(
                "static int leaf_fn(int a)\n"
                "{\n"
                "    return a * 2;\n"
                "}\n"
                "static int caller(int a)\n"
                "{\n"
                "    if (!capable(CAP_SYS_ADMIN)) return -1;\n"
                "    return leaf_fn(a);\n"
                "}\n"
            )
            assert _privilege_back_walk_suppresses(
                finding, caps, tmp_path,
            ) is True
