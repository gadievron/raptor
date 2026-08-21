"""If/else dead-branch pruning in the Java CFG builder (b40).

Pins run in BOTH directions: the payoff (a proof-dead branch's
definitions must NOT reach) and recall safety (the live branch's
definitions MUST reach; anything short of a full boolean proof —
unfoldable, TAINT_FREE-valued, non-boolean — keeps every edge).
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import build_java_intraproc_cfg  # noqa: E402
from core.analysis.dataflow import reaching_defs  # noqa: E402


def _cfg(body: str, *,
         imports: str = "import org.owasp.encoder.Encode;\n",
         params: str = "String x, java.io.PrintWriter out",
         name: str = "handle"):
    src = (f"{imports}public class T {{\n"
           f"    public void {name}({params}) {{\n"
           f"{body}    }}\n}}\n")
    return build_java_intraproc_cfg(src, name), src


def _node(cfg, prefix: str):
    hits = [n for n in cfg.nodes() if n.label.startswith(prefix)]
    assert hits, f"no node labelled {prefix!r}"
    return hits[0]


def _definer_labels(cfg, sink_prefix: str, symbol: str):
    rd = reaching_defs(cfg)
    sink = _node(cfg, sink_prefix)
    return {d.label for d in rd.at(sink, symbol)}


class TestDeadBranchPruning:
    def test_false_condition_dead_then_def_does_not_reach(self):
        # (7*42) - num > 200 with num=106 → 188 > 200 → False: the
        # tainted then-branch is proof-dead; only the constant reaches.
        cfg, _ = _cfg(
            "        int num = 106;\n"
            "        String y = \"c0\";\n"
            "        if ((7 * 42) - num > 200) { y = x; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        assert "if:constant-resolved" in cfg.build_notes
        labels = _definer_labels(cfg, "out.println", "y")
        assert any("c0" in lb for lb in labels)
        assert not any("y = x" in lb for lb in labels)

    def test_true_condition_live_then_def_must_reach(self):
        # Same arithmetic, inverted comparison → True: the tainted
        # branch is LIVE — over-pruning here is the damage direction.
        cfg, _ = _cfg(
            "        int num = 106;\n"
            "        String y = \"c0\";\n"
            "        if ((7 * 42) - num < 200) { y = x; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        labels = _definer_labels(cfg, "out.println", "y")
        assert any("y = x" in lb for lb in labels)
        # The pre-init is killed on the taken path but survives the
        # (pruned-or-kept) skip edge only if pruning fired; either
        # way the live def is present — that is the pin.

    def test_true_condition_no_else_fallthrough_pruned(self):
        # Condition provably True and the then-branch rejoins: the
        # cond→join skip edge is dead, so the pre-init must be killed.
        cfg, _ = _cfg(
            "        String y = x;\n"
            "        if (1 + 1 == 2) { y = \"c1\"; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        assert "if:constant-resolved" in cfg.build_notes
        labels = _definer_labels(cfg, "out.println", "y")
        assert any("c1" in lb for lb in labels)
        assert not any("y = x" in lb for lb in labels)

    def test_true_condition_then_returns_join_guard_keeps_edge(self):
        # then ends in return → the following statement has no other
        # predecessor; the join-reachability guard must refuse the
        # fall-through prune (conservative over-approximation).
        cfg, _ = _cfg(
            "        String y = x;\n"
            "        if (1 + 1 == 2) { out.println(\"a\"); return; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        labels = _definer_labels(cfg, "out.println(y)", "y")
        assert any("y = x" in lb for lb in labels)

    def test_unfoldable_condition_keeps_both(self):
        cfg, _ = _cfg(
            "        String y = \"c0\";\n"
            "        if (x.length() > 3) { y = x; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        assert "if:all-branches" in cfg.build_notes
        labels = _definer_labels(cfg, "out.println", "y")
        assert any("y = x" in lb for lb in labels)
        assert any("c0" in lb for lb in labels)

    def test_taint_free_condition_must_not_prune(self):
        # System.getProperty folds only in the TAINT_FREE tier — it
        # has no VALUE, so a condition built on it must keep every
        # edge (the value-only contract of branch pruning).
        cfg, _ = _cfg(
            "        String p = System.getProperty(\"mode\");\n"
            "        String y = \"c0\";\n"
            "        if (p == null) { y = x; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        assert "if:constant-resolved" not in cfg.build_notes
        labels = _definer_labels(cfg, "out.println", "y")
        assert any("y = x" in lb for lb in labels)

    def test_nested_if_only_outer_foldable(self):
        cfg, _ = _cfg(
            "        String y = \"c0\";\n"
            "        if (2 > 1) {\n"
            "            if (x.length() > 3) { y = x; } else { y = \"c1\"; }\n"
            "        } else { y = \"dead\"; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        assert "if:constant-resolved" in cfg.build_notes
        labels = _definer_labels(cfg, "out.println", "y")
        assert any("y = x" in lb for lb in labels)       # inner unpruned
        assert any("c1" in lb for lb in labels)
        assert not any("dead" in lb for lb in labels)    # outer else dead

    def test_else_if_chain_prunes_per_condition(self):
        cfg, _ = _cfg(
            "        String y;\n"
            "        if (1 == 2) { y = x; }\n"
            "        else if (2 == 2) { y = \"c1\"; }\n"
            "        else { y = \"c2\"; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        labels = _definer_labels(cfg, "out.println", "y")
        assert not any("y = x" in lb for lb in labels)
        assert any("c1" in lb for lb in labels)
        assert not any("c2" in lb for lb in labels)

    def test_boolean_only_nonbool_fold_refuses(self):
        # An int-valued condition expression is a compile error in
        # real Java, but the builder must not trust the folder's int
        # into a prune — strict bool or nothing.
        cfg, _ = _cfg(
            "        String y = \"c0\";\n"
            "        boolean b = x != null;\n"
            "        if (b) { y = x; }\n"
            "        out.println(y);\n")
        assert cfg is not None
        assert "if:constant-resolved" not in cfg.build_notes
        labels = _definer_labels(cfg, "out.println", "y")
        assert any("y = x" in lb for lb in labels)
