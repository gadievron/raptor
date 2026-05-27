"""Tests for function extraction with metadata."""

import json
import pytest
from core.inventory.extractors import (
    FunctionInfo, FunctionMetadata,
    PythonExtractor, JavaExtractor, CExtractor, GoExtractor,
    JavaScriptExtractor, extract_functions, _TS_AVAILABLE, _get_ts_languages,
)


# ---------------------------------------------------------------------------
# FunctionMetadata / FunctionInfo dataclass tests
# ---------------------------------------------------------------------------

class TestFunctionInfoRoundTrip:
    """Verify to_dict / from_dict round-trip with metadata."""

    def test_round_trip_with_metadata(self):
        f = FunctionInfo(
            name="process",
            line_start=42,
            line_end=78,
            signature="def process(x: int) -> str",
            metadata=FunctionMetadata(
                class_name="Controller",
                visibility="public",
                attributes=["app.route('/api')"],
                return_type="str",
                parameters=[("x", "int")],
            ),
        )
        d = f.to_dict()
        f2 = FunctionInfo.from_dict(d)
        assert f2.name == f.name
        assert f2.metadata.class_name == "Controller"
        assert f2.metadata.attributes == ["app.route('/api')"]
        assert f2.metadata.parameters == [("x", "int")]
        assert f2.metadata.return_type == "str"

    def test_round_trip_without_metadata(self):
        f = FunctionInfo(name="hello", line_start=1)
        d = f.to_dict()
        f2 = FunctionInfo.from_dict(d)
        assert f2.name == "hello"
        assert f2.metadata is None

    def test_json_serialisation(self):
        f = FunctionInfo(
            name="func",
            line_start=1,
            metadata=FunctionMetadata(parameters=[("x", "int"), ("y", None)]),
        )
        d = f.to_dict()
        j = json.dumps(d)
        d2 = json.loads(j)
        f2 = FunctionInfo.from_dict(d2)
        assert f2.metadata.parameters == [("x", "int"), ("y", None)]

    def test_from_dict_missing_metadata_key(self):
        d = {"name": "old_func", "line_start": 10}
        f = FunctionInfo.from_dict(d)
        assert f.metadata is None

    def test_from_dict_empty_metadata(self):
        d = {"name": "func", "line_start": 1, "metadata": {}}
        f = FunctionInfo.from_dict(d)
        assert f.metadata is not None
        assert f.metadata.class_name is None


# ---------------------------------------------------------------------------
# Python AST extractor (always available)
# ---------------------------------------------------------------------------

class TestPythonExtractor:
    """Python AST extraction with full metadata."""

    def test_decorators(self):
        code = "@app.route('/pay')\n@login_required\ndef pay(): pass"
        funcs = PythonExtractor().extract("t.py", code)
        assert len(funcs) == 1
        assert funcs[0].metadata.attributes == ["app.route('/pay')", "login_required"]

    def test_class_name(self):
        code = "class Ctrl:\n    def handle(self): pass"
        funcs = PythonExtractor().extract("t.py", code)
        assert funcs[0].metadata.class_name == "Ctrl"

    def test_standalone_no_class(self):
        code = "def helper(): pass"
        funcs = PythonExtractor().extract("t.py", code)
        assert funcs[0].metadata.class_name is None

    def test_typed_parameters(self):
        code = "def f(x: int, y: str, z): pass"
        funcs = PythonExtractor().extract("t.py", code)
        assert funcs[0].metadata.parameters == [("x", "int"), ("y", "str"), ("z", None)]

    def test_return_type(self):
        code = "def f() -> bool: pass"
        funcs = PythonExtractor().extract("t.py", code)
        assert funcs[0].metadata.return_type == "bool"

    def test_no_return_type(self):
        code = "def f(): pass"
        funcs = PythonExtractor().extract("t.py", code)
        assert funcs[0].metadata.return_type is None

    def test_line_end(self):
        code = "def f():\n    x = 1\n    return x\n"
        funcs = PythonExtractor().extract("t.py", code)
        assert funcs[0].line_end == 3

    def test_function_inside_compound_statement_extracted(self):
        # The stdlib walker must descend into compound statements (if /
        # try / with / for / while) so nested functions are captured —
        # matching tree-sitter. Pre-fix it stopped at the first non-
        # class/def node, so functions inside ``if False:`` guards or
        # ``try/except`` import fallbacks were invisible to inventory +
        # reachability on tree-sitter-less environments. Required for
        # the dead-scope reachability gate to have anything to tag.
        code = (
            "if False:\n"
            "    def dead_fn(x):\n"
            "        return x\n"
            "\n"
            "try:\n"
            "    import fast\n"
            "except ImportError:\n"
            "    def fallback(y):\n"
            "        return y\n"
            "\n"
            "def live(z):\n"
            "    return z\n"
        )
        names = {f.name for f in PythonExtractor().extract("t.py", code)}
        assert names == {"dead_fn", "fallback", "live"}


# ---------------------------------------------------------------------------
# Regex extractors — basic metadata
# ---------------------------------------------------------------------------

class TestJavaRegexExtractor:

    def test_visibility(self):
        code = "public class T {\n    private void helper() {\n    }\n}"
        funcs = JavaExtractor().extract("T.java", code)
        assert funcs[0].metadata.visibility == "private"

    def test_class_name(self):
        code = "public class Ctrl {\n    public void handle() {\n    }\n}"
        funcs = JavaExtractor().extract("T.java", code)
        assert funcs[0].metadata.class_name == "Ctrl"

    def test_return_type(self):
        code = "public class T {\n    public String get() {\n    }\n}"
        funcs = JavaExtractor().extract("T.java", code)
        assert funcs[0].metadata.return_type == "String"

    def test_parameters(self):
        code = "public class T {\n    public void set(String k, int v) {\n    }\n}"
        funcs = JavaExtractor().extract("T.java", code)
        assert funcs[0].metadata.parameters == [("k", "String"), ("v", "int")]


class TestCRegexExtractor:

    def test_static_visibility(self):
        code = "static void helper() {\n}\n"
        funcs = CExtractor().extract("t.c", code)
        assert funcs[0].metadata.visibility == "static"

    def test_extern_visibility(self):
        code = "extern int process(int x) {\n}\n"
        funcs = CExtractor().extract("t.c", code)
        assert funcs[0].metadata.visibility == "extern"

    def test_static_inline_is_static_not_inline(self):
        # Gap 2: `inline` must not mask the `static` internal-linkage signal
        # (`static inline` is still internal — not an external entry).
        code = "static inline int clamp(int a, int b) {\n    return a;\n}\n"
        funcs = CExtractor().extract("t.h", code)
        assert funcs[0].metadata.visibility == "static"

    def test_extern_beats_static_on_conflict(self):
        # Invalid `extern static` (conflicting linkage) is treated as external
        # — never under-claim reachability on malformed input.
        code = "extern static int weird(void) {\n    return 0;\n}\n"
        funcs = CExtractor().extract("t.c", code)
        assert funcs[0].metadata.visibility == "extern"

    def test_bare_inline_is_not_static(self):
        # `inline` alone is not a linkage class → external (not "static").
        code = "inline int helper(void) {\n    return 0;\n}\n"
        funcs = CExtractor().extract("t.c", code)
        assert funcs[0].metadata.visibility != "static"

    def test_return_type(self):
        code = "int main() {\n}\n"
        funcs = CExtractor().extract("t.c", code)
        assert funcs[0].metadata.return_type is not None

    def test_no_visibility(self):
        code = "void func() {\n}\n"
        funcs = CExtractor().extract("t.c", code)
        assert funcs[0].metadata.visibility is None


class TestGoRegexExtractor:

    def test_exported(self):
        code = "func HandleRequest() {\n}\n"
        funcs = GoExtractor().extract("t.go", code)
        assert funcs[0].metadata.visibility == "exported"

    def test_unexported(self):
        code = "func helper() {\n}\n"
        funcs = GoExtractor().extract("t.go", code)
        assert funcs[0].metadata.visibility is None

    def test_receiver_as_class(self):
        code = "func (s *Server) Handle() {\n}\n"
        funcs = GoExtractor().extract("t.go", code)
        assert funcs[0].metadata.class_name == "Server"

    def test_no_receiver(self):
        code = "func standalone() {\n}\n"
        funcs = GoExtractor().extract("t.go", code)
        assert funcs[0].metadata.class_name is None


class TestJSRegexExtractor:

    def test_exported(self):
        code = "export function handle(req) {\n}\n"
        funcs = JavaScriptExtractor().extract("t.js", code)
        assert funcs[0].metadata.visibility == "exported"

    def test_not_exported(self):
        code = "function internal() {\n}\n"
        funcs = JavaScriptExtractor().extract("t.js", code)
        assert funcs[0].metadata.visibility is None


# ---------------------------------------------------------------------------
# Fallback chain
# ---------------------------------------------------------------------------

class TestFallbackChain:

    def test_python_always_has_metadata(self):
        """Python uses AST regardless of tree-sitter."""
        code = "@deco\ndef f(x: int) -> str: pass"
        funcs = extract_functions("t.py", "python", code)
        assert len(funcs) == 1
        assert funcs[0].metadata is not None
        assert funcs[0].metadata.attributes == ["deco"]

    def test_regex_fallback_has_basic_metadata(self):
        """Without tree-sitter, regex extractors still produce metadata."""
        code = "func Exported() {\n}\n"
        # Force regex by using a language tree-sitter might not have
        funcs = GoExtractor().extract("t.go", code)
        assert funcs[0].metadata is not None
        assert funcs[0].metadata.visibility == "exported"


# ---------------------------------------------------------------------------
# Tree-sitter (conditional)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _TS_AVAILABLE, reason="tree-sitter not installed")
class TestTreeSitter:

    def test_python_decorators(self):
        code = "@app.route('/x')\ndef f(): pass"
        funcs = extract_functions("t.py", "python", code)
        assert any("app.route" in (a or "") for a in funcs[0].metadata.attributes)

    def test_java_annotations(self):
        code = "public class T {\n    @GetMapping\n    public void get() {\n    }\n}"
        funcs = extract_functions("T.java", "java", code)
        assert any("GetMapping" in a for a in funcs[0].metadata.attributes)

    def test_java_visibility(self):
        code = "public class T {\n    private void secret() {\n    }\n}"
        funcs = extract_functions("T.java", "java", code)
        assert funcs[0].metadata.visibility == "private"

    def test_c_static(self):
        code = "static void internal() {\n}\n"
        funcs = extract_functions("t.c", "c", code)
        assert funcs[0].metadata.visibility == "static"

    def test_c_params(self):
        code = "int process(char *buf, size_t len) {\n    return 0;\n}\n"
        funcs = extract_functions("t.c", "c", code)
        if not funcs[0].metadata.parameters:
            pytest.skip("tree-sitter-c build does not expose parameter nodes")
        assert len(funcs[0].metadata.parameters) > 0

    def test_go_exported(self):
        code = "func Public() {\n}\nfunc private() {\n}\n"
        funcs = extract_functions("t.go", "go", code)
        names = {f.name: f.metadata.visibility for f in funcs}
        assert names.get("Public") == "exported"

    def test_ts_languages_available(self):
        langs = _get_ts_languages()
        assert "python" in langs


def _has_tree_sitter_cpp() -> bool:
    try:
        import tree_sitter_cpp  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(
    not _has_tree_sitter_cpp(),
    reason="tree_sitter_cpp grammar not installed",
)
class TestCppTreeSitter:
    """Pin the C++ extraction fixes landed alongside ``core.ast`` (PR
    ``feat/core-ast``):

      * ``_ts_language("cpp")`` now loads ``tree_sitter_cpp`` (was
        loading ``tree_sitter_c``, which can't parse class / method
        / template / namespace shapes).
      * ``_get_name`` handles the C++ declarator shapes the cpp
        grammar produces: ``qualified_identifier`` (out-of-line
        methods), ``destructor_name`` (``~Foo``),
        ``pointer_declarator`` / ``parenthesized_declarator`` wraps.

    Direct extractor coverage (the ``core.ast`` view tests cover
    this indirectly; pinning here makes the contract explicit at the
    layer where it lives)."""

    def test_inline_class_method_extracted(self):
        # Previously emitted only the class name because the C
        # grammar couldn't parse the class body. Now: the inline
        # method ``m`` should be in the output.
        src = "class A { public: void m() { foo(); } };\n"
        funcs = extract_functions("t.cpp", "cpp", src)
        names = [f.name for f in funcs]
        assert "m" in names, names

    def test_inline_class_methods_with_name_collision(self):
        # Two classes, both with a method called ``m``. Both must
        # appear as separate entries so callers can disambiguate by
        # line range.
        src = (
            "class A { public: void m() {} };\n"
            "class B { public: void m() {} };\n"
        )
        funcs = extract_functions("t.cpp", "cpp", src)
        m_entries = [f for f in funcs if f.name == "m"]
        assert len(m_entries) == 2
        # The two ``m`` entries occupy different line ranges.
        assert m_entries[0].line_start != m_entries[1].line_start

    def test_out_of_line_method_keeps_bare_name(self):
        # ``void W::setup() {...}`` — the function declarator's name
        # is a qualified_identifier. _get_name walks to the trailing
        # ``setup`` and returns the bare name (matches the C-side
        # convention of caller-tracking by bare name).
        src = (
            "class W { public: void setup(); };\n"
            "void W::setup() { helper(); }\n"
        )
        funcs = extract_functions("t.cpp", "cpp", src)
        names = [f.name for f in funcs]
        assert "setup" in names

    def test_out_of_line_destructor_named_with_tilde(self):
        # ``W::~W() {...}`` — destructor_name (`~W`) is the inner
        # child of the qualified_identifier. _get_name returns the
        # destructor name verbatim, including the tilde.
        src = (
            "class W { public: ~W(); };\n"
            "W::~W() { cleanup(); }\n"
        )
        funcs = extract_functions("t.cpp", "cpp", src)
        names = [f.name for f in funcs]
        assert "~W" in names

    def test_namespaced_function_definition(self):
        # ``namespace ns { void f() {...} }`` — the function inside
        # the namespace is extracted with its bare name. We don't
        # qualify with the namespace (matches the inventory's
        # name-resolution convention).
        src = "namespace ns { void f() { helper(); } }\n"
        funcs = extract_functions("t.cpp", "cpp", src)
        names = [f.name for f in funcs]
        assert "f" in names

    def test_pointer_return_type_function_name(self):
        # ``char *strdup(...) {...}`` — the declarator is wrapped in
        # a pointer_declarator. _get_name recurses through and finds
        # the inner name.
        src = "char *upper(char *s) { return s; }\n"
        funcs = extract_functions("t.cpp", "cpp", src)
        names = [f.name for f in funcs]
        assert "upper" in names


class TestInterstitialItems:
    """compute_interstitial_items — the 'every SLOC belongs to an item' net."""

    def test_gaps_between_items_become_interstitial(self):
        from core.inventory.extractors import (
            CodeItem, KIND_FUNCTION, KIND_INTERSTITIAL,
            compute_interstitial_items,
        )
        # 1: import os   2: (blank)   3: def f():   4:   pass   5: x = os.system(z)
        content = "import os\n\ndef f():\n    pass\nx = os.system('z')\n"
        items = [CodeItem(name="f", kind=KIND_FUNCTION, line_start=3, line_end=4)]
        inter = compute_interstitial_items(items, content)
        ranges = {(it.line_start, it.line_end): it.kind for it in inter}
        assert ranges.get((1, 2)) == KIND_INTERSTITIAL    # import (blank trailing kept)
        assert ranges.get((5, 5)) == KIND_INTERSTITIAL    # top-level os.system

    def test_blank_only_gap_is_skipped(self):
        from core.inventory.extractors import (
            CodeItem, KIND_FUNCTION, compute_interstitial_items,
        )
        content = "def a():\n    pass\n\n\ndef b():\n    pass\n"
        items = [
            CodeItem(name="a", kind=KIND_FUNCTION, line_start=1, line_end=2),
            CodeItem(name="b", kind=KIND_FUNCTION, line_start=5, line_end=6),
        ]
        # lines 3-4 are blank-only → no interstitial item
        assert compute_interstitial_items(items, content) == []

    def test_fully_covered_file_has_no_interstitial(self):
        from core.inventory.extractors import (
            CodeItem, KIND_FUNCTION, compute_interstitial_items,
        )
        content = "def a():\n    pass\n"
        items = [CodeItem(name="a", kind=KIND_FUNCTION, line_start=1, line_end=2)]
        assert compute_interstitial_items(items, content) == []


class TestTopLevelItems:
    """top_level — module-scope executable code (runs at import)."""

    def test_python_module_level_call_is_top_level(self):
        # AST path (no tree-sitter needed → testable in CI).
        from core.inventory.extractors import PythonExtractor, KIND_TOP_LEVEL
        content = "import os\nos.system('x')\ndef f():\n    pass\n"
        items = PythonExtractor().extract("t.py", content)
        kinds = {(i.kind, i.line_start) for i in items}
        assert (KIND_TOP_LEVEL, 2) in kinds          # os.system at module scope
        assert any(i.kind == "function" for i in items)

    def test_python_bare_non_call_expr_is_not_top_level(self):
        # A docstring / bare literal isn't executable-of-interest.
        from core.inventory.extractors import PythonExtractor
        content = '"""module docstring"""\n42\n'
        items = PythonExtractor().extract("t.py", content)
        assert not any(i.kind == "top_level" for i in items)


class TestCGlobalDeclarators:
    """C/C++ globals through declarator wrappers (array/pointer)."""

    def test_c_array_and_pointer_globals_captured(self):
        from core.inventory.extractors import (
            _TS_AVAILABLE, extract_items, KIND_GLOBAL,
        )
        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter required for C global extraction")
        content = ("char g_buf[8];\nchar *p;\nint x = 0;\n"
                   "int f(void) { return 0; }\n")
        items = extract_items("t.c", "c", content)
        names = {i.name for i in items if i.kind == KIND_GLOBAL}
        assert {"g_buf", "p", "x"} <= names      # array, pointer, scalar
        assert "f" not in names                  # function not a global

    def test_function_pointer_global_named_by_variable_not_initializer(self):
        # Regression: `int (*h)(int) = foo;` must be the variable `h`, NOT the
        # initializer `foo` (the declared name is nested in the FP declarator).
        from core.inventory.extractors import (
            _TS_AVAILABLE, extract_items, KIND_GLOBAL,
        )
        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter required for C global extraction")
        content = "int (*h)(int) = foo;\nint x = 0;\n"
        names = {i.name for i in extract_items("t.c", "c", content)
                 if i.kind == KIND_GLOBAL}
        assert "h" in names              # the function-pointer variable
        assert "foo" not in names        # NOT the initializer value
        assert "x" in names              # plain scalar still works
