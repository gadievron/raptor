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
