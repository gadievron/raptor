"""Finite constant value-set recognizer (b40) — the if-equals-chain
shape at the reaching-definitions level, and its gate consumption
with the per-element danger check."""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import build_java_intraproc_cfg  # noqa: E402
from core.analysis.const_fold_java import JavaConstIndex  # noqa: E402
from core.analysis.dataflow import reaching_defs  # noqa: E402
from core.analysis.value_set_java import finite_constant_value_set  # noqa: E402


def _setup(body: str, params: str = "String x, java.io.PrintWriter out"):
    src = ("public class T {\n"
           f"    public void handle({params}) {{\n"
           f"{body}    }}\n}}\n")
    cfg = build_java_intraproc_cfg(src, "handle")
    assert cfg is not None
    rd = reaching_defs(cfg)
    index = JavaConstIndex(src, (1, src.count("\n") + 1))
    sink = next(n for n in cfg.nodes() if n.label.startswith("out.println"))
    return rd, sink, index


_CHAIN = (
    "        String y;\n"
    "        if (x.equals(\"a\")) { y = \"v1\"; }\n"
    "        else if (x.equals(\"b\")) { y = \"v2\"; }\n"
    "        else { y = \"d\"; }\n"
    "        out.println(y);\n"
)


class TestFiniteConstantValueSet:
    def test_chain_yields_constant_set(self):
        rd, sink, index = _setup(_CHAIN)
        vals = finite_constant_value_set(rd, sink, "y", index)
        assert vals == frozenset({"v1", "v2", "d"})

    def test_nonconstant_branch_refuses(self):
        rd, sink, index = _setup(
            "        String y;\n"
            "        if (x.equals(\"a\")) { y = \"v1\"; }\n"
            "        else { y = x; }\n"
            "        out.println(y);\n")
        assert finite_constant_value_set(rd, sink, "y", index) is None

    def test_missing_else_with_tainted_preinit_refuses(self):
        # The fall-through definition (y = x) reaches the sink — the
        # RD anchor surfaces it and the whole set refuses.
        rd, sink, index = _setup(
            "        String y = x;\n"
            "        if (x.equals(\"a\")) { y = \"v1\"; }\n"
            "        out.println(y);\n")
        assert finite_constant_value_set(rd, sink, "y", index) is None

    def test_chain_over_cap_refuses(self):
        arms = "".join(
            f"        else if (x.equals(\"k{i}\")) {{ y = \"v{i}\"; }}\n"
            for i in range(1, 9))
        body = ("        String y;\n"
                "        if (x.equals(\"k0\")) { y = \"v0\"; }\n"
                + arms +
                "        else { y = \"d\"; }\n"
                "        out.println(y);\n")
        rd, sink, index = _setup(body)
        assert finite_constant_value_set(rd, sink, "y", index) is None

    def test_taint_free_definer_refuses(self):
        # System.getProperty is TAINT_FREE-tier only: no VALUE means
        # no danger-model member — the set must refuse.
        rd, sink, index = _setup(
            "        String y;\n"
            "        if (x.equals(\"a\")) { y = \"v1\"; }\n"
            "        else { y = System.getProperty(\"mode\"); }\n"
            "        out.println(y);\n")
        assert finite_constant_value_set(rd, sink, "y", index) is None


class TestGateConsumption:
    def _reason(self, body, cwe="CWE-79"):
        from core.analysis.sanitizer_cut import _sink_arg_constant_reason
        src = ("public class T {\n"
               "    public void handle(String x, java.io.PrintWriter out) {\n"
               f"{body}    }}\n}}\n")
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        sink = next(n for n in cfg.nodes()
                    if n.label.startswith("out.println"))
        return _sink_arg_constant_reason(
            cfg, frozenset(), sink, "y", ("x",), src, cwe=cwe)

    def test_chain_clears_danger_suppresses(self):
        # b42 composition: the danger-checked taint-free union claims
        # this set first (same per-member discipline, same verdict);
        # the finite-set reason remains the fallback attribution.
        reason = self._reason(_CHAIN)
        assert reason is not None and (
            "finite set" in reason
            or "taint-free union" in reason
        )

    def test_dangerous_member_must_not_suppress(self):
        body = (
            "        String y;\n"
            "        if (x.equals(\"a\")) { y = \"v1\"; }\n"
            "        else { y = \"<b>bold</b>\"; }\n"
            "        out.println(y);\n")
        assert self._reason(body) is None

    def test_no_cwe_no_finite_path(self):
        from core.analysis.sanitizer_cut import _sink_arg_constant_reason
        src = ("public class T {\n"
               "    public void handle(String x, java.io.PrintWriter out) {\n"
               f"{_CHAIN}    }}\n}}\n")
        cfg = build_java_intraproc_cfg(src, "handle")
        sink = next(n for n in cfg.nodes()
                    if n.label.startswith("out.println"))
        assert _sink_arg_constant_reason(
            cfg, frozenset(), sink, "y", ("x",), src) is None
