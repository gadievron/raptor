"""Unit battery for the local-collection index (b28).

Adversarial shapes first: every refusal below is a way the mechanism
could false-suppress if it were sloppy, so each is pinned before the
happy paths.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.java_collection_index import (  # noqa: E402
    ALL_ELEMENTS,
    CollectionFoldResolver,
    build_local_collection_index,
    compose_invocation_hooks,
)

_IMPORTS = (
    "import java.util.HashMap;\n"
    "import java.util.ArrayList;\n"
    "import org.owasp.encoder.Encode;\n"
)


def _index(body: str):
    src = (
        _IMPORTS
        + "public class T {\n"
        + "    public void handle(String x, java.io.PrintWriter out) {\n"
        + body
        + "    }\n}\n"
    )
    n_lines = src.count("\n") + 1
    idx = build_local_collection_index(src, (1, n_lines))
    assert idx is not None
    return idx, src


# ---------------------------------------------------------------------------
# Adversarial: tracking refusals
# ---------------------------------------------------------------------------


class TestTrackingRefusals:
    def test_aliased_map_untracks(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", "v");\n'
            "        HashMap<String, String> m2 = m;\n"
            '        out.println(m.get("k"));\n'
        )
        assert not idx.tracked("m")

    def test_passed_to_call_untracks(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", "v");\n'
            "        helper(m);\n"
        )
        assert not idx.tracked("m")

    def test_returned_untracks(self):
        # return inside the walked span (helper body appended raw)
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            "        if (x != null) { store = m; }\n"
        )
        assert not idx.tracked("m")

    def test_non_allowlisted_method_untracks(self):
        for call in ('m.remove("k")', "m.clear()", "m.putAll(other)",
                     'm.containsKey("k")', "m.values()"):
            idx, _ = _index(
                "        HashMap<String, String> m = new HashMap<>();\n"
                f"        {call};\n"
                '        out.println(m.get("k"));\n'
            )
            assert not idx.tracked("m"), call

    def test_iteration_escape_untracks(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", "v");\n'
            "        for (String v : m.keySet()) { out.println(v); }\n"
        )
        assert not idx.tracked("m")

    def test_non_constant_key_poisons(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", "v");\n'
            "        m.put(x, \"other\");\n"
            '        out.println(m.get("k"));\n'
        )
        assert not idx.tracked("m")

    def test_non_constant_get_key_poisons(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", "v");\n'
            "        out.println(m.get(x));\n"
        )
        assert not idx.tracked("m")

    def test_escaped_string_key_refuses(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k\\n", "v");\n'
        )
        assert not idx.tracked("m")

    def test_copy_construction_refuses(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>(other);\n"
            '        m.put("k", "v");\n'
        )
        assert not idx.tracked("m")

    def test_second_declaration_untracks(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            "        if (x != null) { HashMap<String, String> m = "
            "new HashMap<>(); }\n"
        )
        assert not idx.tracked("m")

    def test_reassignment_untracks(self):
        idx, _ = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            "        m = other;\n"
        )
        assert not idx.tracked("m")

    def test_unlisted_collection_type_not_tracked(self):
        idx, _ = _index(
            "        java.util.concurrent.ConcurrentHashMap<String, String> "
            "m = new java.util.concurrent.ConcurrentHashMap<>();\n"
            '        m.put("k", "v");\n'
        )
        # ConcurrentHashMap is not in the allowlist — never tracked.
        assert not idx.tracked("m")


# ---------------------------------------------------------------------------
# Adversarial: fold refusals
# ---------------------------------------------------------------------------


def _refold_literals(node, _depth):
    from core.analysis.const_fold_java import REFUSE, fold_expr
    return fold_expr(node, lambda _n, _d: REFUSE)


class TestFoldRefusals:
    def _resolve_get(self, idx, src, key_marker: str):
        """Run the fold hook on the get invocation whose source line
        contains ``key_marker``."""
        target_line = next(
            i + 1 for i, ln in enumerate(src.split("\n"))
            if key_marker in ln
        )
        sites = [
            (ln, col) for (ln, col) in idx._get_sites
            if ln == target_line
        ]
        assert sites, f"no get site on marker line {target_line}"
        resolver = CollectionFoldResolver(idx)

        class _FakeNode:
            start_point = (sites[0][0] - 1, sites[0][1])

        return resolver(
            _FakeNode(),
            lambda n, d: _refold_literals(n, d),
            0,
        ), resolver

    def test_mixed_constants_refuse(self):
        idx, src = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", "a");\n'
            '        if (x != null) { m.put("k", "b"); }\n'
            '        String bar = m.get("k"); // READ\n'
        )
        from core.analysis.const_fold_java import REFUSE
        assert idx.tracked("m")
        val, _ = self._resolve_get(idx, src, "// READ")
        assert val is REFUSE

    def test_tainted_write_refuses_fold(self):
        idx, src = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", x);\n'
            '        String bar = m.get("k"); // READ\n'
        )
        from core.analysis.const_fold_java import REFUSE
        val, _ = self._resolve_get(idx, src, "// READ")
        assert val is REFUSE

    def test_never_put_key_refuses(self):
        idx, src = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("other", "v");\n'
            '        String bar = m.get("k"); // READ\n'
        )
        from core.analysis.const_fold_java import REFUSE
        val, _ = self._resolve_get(idx, src, "// READ")
        assert val is REFUSE

    def test_untracked_returns_none_not_refuse(self):
        idx, src = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            "        helper(m);\n"
            '        String bar = m.get("k"); // READ\n'
        )
        target_line = next(
            i + 1 for i, ln in enumerate(src.split("\n")) if "// READ" in ln
        )
        resolver = CollectionFoldResolver(idx)

        class _FakeNode:
            start_point = (target_line - 1, 0)

        # untracked → not ours → None (fall through), never a value
        assert resolver(_FakeNode(), _refold_literals, 0) is None

    def test_list_mixed_adds_positional(self):
        # Graduated by b34's positional simulation: get(0) provably
        # reads the constant slot in straight-line code. The tainted
        # slot (get(1)) is the standing refusal twin below.
        idx, src = _index(
            "        ArrayList<String> l = new ArrayList<>();\n"
            '        l.add("a");\n'
            "        l.add(x);\n"
            "        String bar = l.get(0); // READ\n"
        )
        assert idx.tracked("l")
        val, _ = self._resolve_get(idx, src, "// READ")
        assert val == "a"

    def test_list_mixed_adds_tainted_slot_refuses(self):
        idx, src = _index(
            "        ArrayList<String> l = new ArrayList<>();\n"
            '        l.add("a");\n'
            "        l.add(x);\n"
            "        String bar = l.get(1); // READ\n"
        )
        from core.analysis.const_fold_java import REFUSE
        assert idx.tracked("l")
        val, _ = self._resolve_get(idx, src, "// READ")
        assert val is REFUSE


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestHappyPaths:
    def test_map_constant_key_folds(self):
        idx, src = _index(
            "        HashMap<String, Object> m = new HashMap<>();\n"
            '        m.put("keyA", "a-Value");\n'
            '        m.put("keyB", "safe");\n'
            '        m.put("keyC", "another");\n'
            '        String bar = (String) m.get("keyB"); // READ\n'
        )
        assert idx.tracked("m")
        f = TestFoldRefusals()
        val, resolver = f._resolve_get(idx, src, "// READ")
        assert val == "safe"
        assert resolver.hits == 1

    def test_scalar_copy_through_cast(self):
        idx, src = _index(
            "        HashMap<String, Object> m = new HashMap<>();\n"
            '        m.put("k", "v");\n'
            '        String bar = (String) m.get("k"); // COPY\n'
        )
        ln = next(i + 1 for i, s in enumerate(src.split("\n"))
                  if "// COPY" in s)
        assert idx.scalar_copy(ln, "bar") == ("m", "k")

    def test_list_all_writes_governed(self):
        idx, _ = _index(
            "        ArrayList<String> l = new ArrayList<>();\n"
            '        l.add("a");\n'
            '        l.add(0, "b");\n'
            '        l.set(1, "c");\n'
            "        String bar = l.get(3);\n"
        )
        assert idx.tracked("l")
        assert len(idx.element_writes("l", ALL_ELEMENTS)) == 3

    def test_sanitizer_write_recognised(self):
        idx, src = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", Encode.forHtml(x));\n'
            '        String bar = (String) m.get("k");\n'
        )
        assert idx.tracked("m")
        writes = idx.element_writes("m", "k")
        assert len(writes) == 1
        assert idx.write_is_catalog_call(
            writes[0], {"org.owasp.encoder.Encode.forHtml"})

    def test_direct_read_at_sink_line(self):
        idx, src = _index(
            "        HashMap<String, String> m = new HashMap<>();\n"
            '        m.put("k", "v");\n'
            '        out.println(m.get("k")); // SINK\n'
        )
        ln = next(i + 1 for i, s in enumerate(src.split("\n"))
                  if "// SINK" in s)
        assert idx.element_reads_at(ln, "m") == {"k"}


class TestHookComposition:
    def test_first_claim_wins_and_none_falls_through(self):
        calls = []

        def h1(node, refold, depth):
            calls.append("h1")
            return None

        def h2(node, refold, depth):
            calls.append("h2")
            return "claimed"

        combined = compose_invocation_hooks(h1, None, h2)
        assert combined("n", None, 0) == "claimed"
        assert calls == ["h1", "h2"]

    def test_all_none_returns_none(self):
        assert compose_invocation_hooks(None, None) is None
        combined = compose_invocation_hooks(lambda *a: None)
        assert combined("n", None, 0) is None


class TestCastFoldRule:
    """The cast_expression fold rule added for collection round-trips
    is soundness-critical shared surface — pin both directions."""

    def _fold(self, expr: str):
        from core.analysis.cfg_builder_java import _get_parser
        from core.analysis.const_fold_java import REFUSE, fold_expr
        src = ("public class T { void m() { Object v = "
               + expr + "; } }").encode()
        tree = _get_parser().parse(src)
        stack = [tree.root_node]
        node = None
        while stack:
            cur = stack.pop()
            if cur.type == "cast_expression":
                node = cur
                break
            stack.extend(c for c in cur.children if c.is_named)
        assert node is not None, expr
        return fold_expr(node, lambda _n, _d: REFUSE)

    def test_string_cast_of_string_folds(self):
        assert self._fold('(String) "abc"') == "abc"

    def test_qualified_string_cast_folds(self):
        assert self._fold('(java.lang.String) "abc"') == "abc"

    def test_int_cast_refuses(self):
        from core.analysis.const_fold_java import REFUSE
        assert self._fold("(int) 3") is REFUSE

    def test_string_cast_of_int_refuses(self):
        from core.analysis.const_fold_java import REFUSE
        assert self._fold("(String) 3") is REFUSE

    def test_object_cast_refuses(self):
        from core.analysis.const_fold_java import REFUSE
        assert self._fold('(Object) "abc"') is REFUSE
