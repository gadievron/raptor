"""Tests for function extraction with metadata."""

import json
from pathlib import Path

import pytest
from core.inventory.extractors import (
    FunctionInfo, FunctionMetadata,
    PythonExtractor, JavaExtractor, CExtractor, GoExtractor,
    GenericExtractor, JavaScriptExtractor, LuaExtractor, TreeSitterExtractor,
    extract_functions, extract_items, _TS_AVAILABLE, _get_ts_languages,
)
from core.testing.treesitter import requires_ts


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

    def test_braces_inside_string_literal_ignored(self):
        code = (
            "public class T {\n"
            '    public void log() {\n'
            '        System.out.println("value={" + x + "}");\n'
            '    }\n'
            '    public void other() {\n'
            '    }\n'
            '}\n'
        )
        funcs = JavaExtractor().extract("T.java", code)
        names = [f.name for f in funcs]
        assert "log" in names
        assert "other" in names
        assert funcs[1].metadata.class_name == "T"


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

    def test_knr_with_macro(self):
        code = (
            "int ZEXPORT inflate(strm, flush)\n"
            "z_streamp strm;\n"
            "int flush;\n"
            "{\n"
            "    int x = 0;\n"
            "    return x;\n"
            "}\n"
        )
        funcs = CExtractor().extract("inflate.c", code)
        names = [f.name for f in funcs]
        assert "inflate" in names
        fn = next(f for f in funcs if f.name == "inflate")
        assert fn.line_end is not None
        assert fn.line_end > fn.line_start


class TestCReservedWordIdentities:
    """The regex lane's name capture is "last word before `(`" — on
    declarator shapes where that paren is not the parameter list, the
    captured word is a TYPE and real-world corpora minted inventory
    identities named `int` / `void` with multi-KB brace-filled spans.
    A recognised function name must never be a C/C++ reserved word."""

    def test_funcptr_param_continuation_does_not_mint_type_name(self):
        # A function-pointer PARAMETER on a signature continuation
        # line (ubiquitous in event-driven C) matches
        # ANSI_SPLIT_PATTERN with `int` in the name group, and the `{`
        # on the next line confirmed the phantom.
        code = (
            "static void drain_timeout_queue(struct timeout_queue *q,\n"
            "                                int (*func)(struct conn_state *))\n"
            "{\n"
            "    unsigned total = 0;\n"
            "}\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", code)]
        assert "int" not in names
        assert "drain_timeout_queue" in names

    def test_funcptr_return_defn_does_not_mint_type_name(self):
        # Function-pointer RETURN type: the word before the declarator
        # paren is the type. The regex lane cannot recover the real
        # name (`lookup_handler`) from this shape — tree-sitter does —
        # but it must not mint `int` in its place.
        code = (
            "static int (*lookup_handler(const char *name))(int)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", code)]
        assert "int" not in names

    def test_keyword_block_still_refused(self):
        # Statement keywords stay refused (pre-existing behavior).
        code = (
            "void f(void)\n"
            "{\n"
            "    if (cond) {\n"
            "        work();\n"
            "    }\n"
            "    while (more()) {\n"
            "        step();\n"
            "    }\n"
            "}\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", code)]
        assert "if" not in names
        assert "while" not in names

    def test_keyword_prefix_names_still_extract(self):
        # Two-direction guard on the churn-prone list: identifiers
        # that merely PREFIX a reserved word are ordinary names and
        # must keep extracting.
        code = (
            "static int iffy(void) {\n"
            "    return 0;\n"
            "}\n"
            "int interior(int x) {\n"
            "    return x;\n"
            "}\n"
            "unsigned intp(void) {\n"
            "    return 1;\n"
            "}\n"
        )
        names = {f.name for f in CExtractor().extract("t.c", code)}
        assert {"iffy", "interior", "intp"} <= names

    def test_ansi_one_line_funcptr_return_does_not_mint(self):
        # Seam pin: the one-line ANSI arm. A funcptr-return definition
        # whose whole signature fits one line puts `int` in the ANSI
        # pattern's name group; reverting this seam's RESERVED_WORDS
        # check back to KEYWORDS re-mints it.
        code = (
            "static int (*get_handler(const char *name))(int) {\n"
            "    return 0;\n"
            "}\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", code)]
        assert not set(names) & CExtractor.RESERVED_WORDS

    def test_split_funcptr_return_does_not_mint(self):
        # Seam pin: the FUNCNAME_OPEN_PAREN arm (storage class alone
        # on line 1, `int (*get_hook(...,` opening line 2).
        code = (
            "static\n"
            "int (*get_hook(const char *name,\n"
            "               int flags))(int)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", code)]
        assert not set(names) & CExtractor.RESERVED_WORDS

    def test_multiline_opener_funcptr_return_does_not_mint(self):
        # Seam pin: the multi-line opener arm (signature spans two
        # lines, brace on its own line).
        code = (
            "static int (*get_filter(const char *name,\n"
            "                        int flags))(void)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
        names = [f.name for f in CExtractor().extract("t.c", code)]
        assert not set(names) & CExtractor.RESERVED_WORDS

    def test_reserved_words_contains_no_ordinary_identifiers(self):
        # The list's membership criterion, executable: ISO C / C++
        # reserved words only — never typedef/library names, never
        # keyword-prefix identifiers.
        reserved = CExtractor.RESERVED_WORDS
        assert CExtractor.KEYWORDS <= reserved
        assert CExtractor.C_TYPE_HINTS <= reserved
        for legit in ("iffy", "interior", "intp", "main",
                      "size_t", "uint32_t", "apr_status_t"):
            assert legit not in reserved

    def test_reserved_words_is_exactly_iso_c_union_iso_cpp(self):
        # Exact-set pin (both directions): the effective vocabulary is
        # precisely ISO C23 ∪ ISO C++23 — a shrink (dropping e.g.
        # `restrict` or `co_await`) fails here just as loudly as an
        # ordinary-identifier addition. Closed language enumeration,
        # so pinning the exact set is safe: it changes only when a new
        # ISO revision reserves new words.
        c23 = frozenset("""alignas alignof auto bool break case char const
            constexpr continue default do double else enum extern false float
            for goto if inline int long nullptr register restrict return short
            signed sizeof static static_assert struct switch thread_local true
            typedef typeof typeof_unqual union unsigned void volatile while
            _Alignas _Alignof _Atomic _BitInt _Bool _Complex _Decimal128
            _Decimal32 _Decimal64 _Generic _Imaginary _Noreturn _Static_assert
            _Thread_local""".split())
        cxx23 = frozenset("""alignas alignof and and_eq asm auto bitand bitor
            bool break case catch char char8_t char16_t char32_t class compl
            concept const consteval constexpr constinit const_cast continue
            co_await co_return co_yield decltype default delete do double
            dynamic_cast else enum explicit export extern false float for
            friend goto if inline int long mutable namespace new noexcept not
            not_eq nullptr operator or or_eq private protected public register
            reinterpret_cast requires return short signed sizeof static
            static_assert static_cast struct switch template this thread_local
            throw true try typedef typeid typename union unsigned using
            virtual void volatile wchar_t while xor xor_eq""".split())
        assert CExtractor.RESERVED_WORDS == c23 | cxx23

    @requires_ts("c")
    def test_repair_pass_gate_refuses_reserved_names(self, monkeypatch):
        # Independent defense-in-depth check of the merge seam in
        # extract_items: even if the regex lane regresses and mints a
        # reserved-word identity again, the repair pass must not
        # append it beside the correctly-named tree-sitter item.
        from core.inventory import extractors as ex

        class _MintingStub:
            def extract(self, _filepath, _content):
                return [
                    FunctionInfo(name="int", line_start=1, line_end=3),
                    FunctionInfo(name="rescued_fn", line_start=1, line_end=3),
                ]

        monkeypatch.setitem(ex._REGEX_EXTRACTORS, "c", _MintingStub())
        src = (
            "static int real_fn(int x)\n"
            "{\n"
            "    return x;\n"
            "}\n"
        )
        items = extract_items("t.c", "c", src)
        names = {i.name for i in items if i.kind == "function"}
        assert "real_fn" in names
        assert "rescued_fn" in names   # legitimate gap-fill still lands
        assert "int" not in names      # reserved identity gated out


class TestTsMainLaneReservedGate:
    """The tree-sitter MAIN lane (_extract_function) must refuse
    reserved-word names on c/cpp: preprocessor-fragmented parses can
    leave a statement keyword as the declarator identifier of a CLEAN
    function_definition node, minting `if` identities with multi-KB
    spans from real corpora."""

    @requires_ts("c")
    def test_ifdef_wrapped_else_if_does_not_mint(self):
        # An `#ifdef`-wrapped `else if` arm fragments the parse:
        # tree-sitter accepts `if` as a declarator identifier inside a
        # clean function_definition — bypassing the regex-lane seams,
        # both recovery arms, and the merge gate. This exact shape
        # minted per-arm `if` identities from a real-world C corpus.
        code = (
            "static void seed_pool(int n)\n"
            "{\n"
            "    int i;\n"
            "    for (i = 0; i < n; i++) {\n"
            "        if (src == FROM_FILE) {\n"
            "            feed_file();\n"
            "        }\n"
            "#ifdef HAVE_EXTERNAL_DAEMON\n"
            "        else if (src == FROM_DAEMON) {\n"
            "            feed_daemon();\n"
            "        }\n"
            "#endif\n"
            "        else if (src == FROM_BUILTIN) {\n"
            "            feed_builtin();\n"
            "        }\n"
            "    }\n"
            "}\n"
            "static int next_chunk(int lo, int hi)\n"
            "{\n"
            "    return lo + hi;\n"
            "}\n"
        )
        items = extract_items("t.c", "c", code)
        names = [i.name for i in items if i.kind == "function"]
        assert not set(names) & CExtractor.RESERVED_WORDS
        assert "seed_pool" in names
        assert "next_chunk" in names

    @requires_ts("c")
    @requires_ts("cpp")
    @pytest.mark.parametrize("lang", ["c", "cpp"])
    def test_dangling_type_line_if_header_does_not_mint(self, lang):
        # A dangling type line above an `if` header parses as a
        # function_definition whose declarator identifier is `if`.
        code = (
            "unsigned long\n"
            "if (cond)\n"
            "{\n"
            "    body();\n"
            "}\n"
        )
        items = extract_items(f"t.{'c' if lang == 'c' else 'cpp'}", lang, code)
        names = [i.name for i in items if i.kind == "function"]
        assert not set(names) & CExtractor.RESERVED_WORDS

    @requires_ts("c")
    def test_macro_wrapped_keyword_declarator_does_not_mint(self):
        # `WRAP(if)(void) { }` puts `if` in a parenthesized_declarator
        # identifier slot.
        code = (
            "WRAP(if)(void)\n"
            "{\n"
            "}\n"
            "int real_one(void)\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
        items = extract_items("t.c", "c", code)
        names = [i.name for i in items if i.kind == "function"]
        assert not set(names) & CExtractor.RESERVED_WORDS
        assert "real_one" in names

    @requires_ts("c")
    def test_conversion_operator_routed_to_c_does_not_mint(self):
        # C++ `operator int()` in a header routed to the c lane parses
        # with `int` in the name slot.
        code = "operator int() { }\n"
        items = extract_items("t.h", "c", code)
        names = [i.name for i in items if i.kind == "function"]
        assert "int" not in names

    @requires_ts("cpp")
    def test_cpp_special_functions_survive_gate(self):
        # Accept direction: legitimate C++ special functions carry
        # multi-token / punctuated names — never a bare reserved word —
        # and must keep extracting on the cpp lane.
        code = (
            "struct V {\n"
            "    int x;\n"
            "    V() : x(0) {}\n"
            "    ~V() {}\n"
            "    operator int() const { return x; }\n"
            "    int operator()(int y) { return y; }\n"
            "    V& operator+=(const V& o) { return *this; }\n"
            "};\n"
        )
        names = {f.name for f in TreeSitterExtractor("cpp").extract("v.cpp", code)}
        assert {"V", "~V", "operator int", "operator()", "operator+="} <= names


class TestGenericExtractorControlFlowGate:
    """The generic fallback's brace-and-paren pattern captures the word
    before `(` — statement headers like `} else if (x) {` put a
    control-flow keyword there. Language-agnostic lane, so the gate is
    the small control-flow subset, NOT the C/C++ reserved vocabulary."""

    def test_else_if_header_does_not_mint(self):
        code = (
            "foo bar (baz) {\n"
            "} else if (x) {\n"
            "}\n"
        )
        names = [f.name for f in GenericExtractor().extract("t.inc", code)]
        assert "if" not in names
        assert "bar" in names

    def test_kotlin_when_header_does_not_mint(self):
        code = (
            "fun pick(x: Int): Int {\n"
            "    return when (x) {\n"
            "        else -> 0\n"
            "    }\n"
            "}\n"
        )
        names = [f.name for f in GenericExtractor().extract("k.kt", code)]
        assert "when" not in names
        assert "pick" in names

    def test_inc_lane_end_to_end_does_not_mint(self):
        # The `.inc` residual lane routes to the generic fallback via
        # extract_items — the end-to-end path that minted `if`.
        code = (
            "handler:\n"
            "    mov r0, r1\n"
            "foo bar (baz) {\n"
            "} else if (x) {\n"
            "}\n"
        )
        items = extract_items("tables.inc", "inc", code)
        names = [i.name for i in items if i.kind == "function"]
        assert "if" not in names

    def test_c_only_reserved_words_still_extract(self):
        # Accept direction (membership criterion, executable): words
        # reserved only in C/C++ are ordinary method names in the
        # generic lane's languages and must keep extracting.
        code = (
            "public int template(int x) { return x; }\n"
            "static long restrict(long v) { return v; }\n"
            "private bool typename(int k) { return k > 0; }\n"
        )
        names = {f.name for f in GenericExtractor().extract("r.cs", code)}
        assert {"template", "restrict", "typename"} <= names
        for word in ("template", "restrict", "typename"):
            assert word not in GenericExtractor._CONTROL_FLOW_NAMES
        assert "if" in GenericExtractor._CONTROL_FLOW_NAMES


class TestNoReservedIdentitiesInTreeCorpus:

    def test_absolute_zero_reserved_names_over_repo_c_corpus(self):
        # ABSOLUTE assertion, not a BASE-relative diff (a diff is blind
        # to phantoms present on both sides): the full extract_items
        # path over every C/C++ file in this repository emits zero
        # reserved-word function identities.
        repo = Path(__file__).resolve().parents[3]
        files = sorted(
            p for ext in ("*.c", "*.h", "*.cc", "*.cpp")
            for p in repo.rglob(ext)
            if ".git" not in p.parts
        )
        assert len(files) > 50  # the corpus actually loaded
        offenders = []
        for p in files:
            content = p.read_text(errors="replace")
            lang = "cpp" if p.suffix in (".cpp", ".cc") else "c"
            for i in extract_items(str(p), lang, content):
                if i.kind == "function" and i.name in CExtractor.RESERVED_WORDS:
                    offenders.append((str(p.relative_to(repo)), i.name))
        assert offenders == []


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

    def test_block_comment_with_braces(self):
        code = "function f() {\n  /* { } */\n  return 1;\n}\n"
        funcs = JavaScriptExtractor().extract("t.js", code)
        assert funcs[0].line_end == 4

    def test_multiline_block_comment_with_braces(self):
        code = "function f() {\n  /*\n  {\n  */\n  return 1;\n}\n"
        funcs = JavaScriptExtractor().extract("t.js", code)
        assert funcs[0].line_end == 6

    def test_regex_literal_with_braces(self):
        code = "function f() {\n  var r = /{[^}]+}/g;\n  return 1;\n}\n"
        funcs = JavaScriptExtractor().extract("t.js", code)
        assert funcs[0].line_end == 4

    def test_commented_out_function_skipped(self):
        code = "// function fake(ev) {\nfunction real() {\n  return 1;\n}\n"
        funcs = JavaScriptExtractor().extract("t.js", code)
        assert len(funcs) == 1
        assert funcs[0].name == "real"

    def test_block_comment_opener_skipped(self):
        code = "/* function fake() { */\nfunction real() {\n  return 1;\n}\n"
        funcs = JavaScriptExtractor().extract("t.js", code)
        names = [f.name for f in funcs]
        assert "fake" not in names
        assert "real" in names


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

    @requires_ts("java")
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

    def test_c_knr_macro_repair(self):
        code = (
            "int ZEXPORT inflate(strm, flush)\n"
            "z_streamp strm;\n"
            "int flush;\n"
            "{\n"
            "    int x = 0;\n"
            "    return x;\n"
            "}\n"
            "\n"
            "int ZEXPORT inflateEnd(strm)\n"
            "z_streamp strm;\n"
            "{\n"
            "    return 0;\n"
            "}\n"
        )
        items = extract_items("inflate.c", "c", code)
        funcs = [i for i in items if i.kind == "function"]
        names = {f.name: f for f in funcs}
        assert "inflate" in names, f"inflate not found; got {[f.name for f in funcs]}"
        assert names["inflate"].line_end > names["inflate"].line_start
        assert "inflateEnd" in names, f"inflateEnd not found; got {[f.name for f in funcs]}"
        assert names["inflateEnd"].line_end > names["inflateEnd"].line_start

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


@requires_ts("c")
class TestCGlobalDeclarators:
    """C/C++ globals through declarator wrappers (array/pointer)."""

    def test_c_array_and_pointer_globals_captured(self):
        # Name capture through declarator wrappers; these inert shapes
        # now classify as ``declaration`` (still in the checklist).
        from core.inventory.extractors import (
            _TS_AVAILABLE, extract_items, KIND_DECLARATION, KIND_GLOBAL,
        )
        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter required for C global extraction")
        content = ("char g_buf[8];\nchar *p;\nint x = 0;\n"
                   "int f(void) { return 0; }\n")
        items = extract_items("t.c", "c", content)
        names = {i.name for i in items
                 if i.kind in (KIND_GLOBAL, KIND_DECLARATION)}
        assert {"g_buf", "p", "x"} <= names      # array, pointer, scalar
        assert "f" not in names                  # function not a global

    def test_function_pointer_global_named_by_variable_not_initializer(self):
        # Regression: `int (*h)(int) = foo;` must be the variable `h`, NOT the
        # initializer `foo` (the declared name is nested in the FP declarator).
        from core.inventory.extractors import (
            _TS_AVAILABLE, extract_items, KIND_DECLARATION, KIND_GLOBAL,
        )
        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter required for C global extraction")
        content = "int (*h)(int) = foo;\nint x = 0;\n"
        names = {i.name for i in extract_items("t.c", "c", content)
                 if i.kind in (KIND_GLOBAL, KIND_DECLARATION)}
        assert "h" in names              # the function-pointer variable
        assert "foo" not in names        # NOT the initializer value
        assert "x" in names              # plain scalar still works


# ---------------------------------------------------------------------------
# Extraction-artifact kinds: declaration / constant_macro / hoisted locals
# ---------------------------------------------------------------------------

@requires_ts("c")
class TestCDeclarationKind:
    """File-scope pure/extern/inert-initializer C declarations classify
    as ``declaration`` — kept in the checklist for coverage bookkeeping,
    excluded from review by default. Anything whose initializer may run
    code stays a reviewable ``global``."""

    @staticmethod
    def _kinds(content, language="c"):
        from core.inventory.extractors import extract_items
        return {i.name: i.kind
                for i in extract_items("t." + ("c" if language == "c" else "cc"),
                                       language, content)}

    def test_pure_declaration_without_initializer(self):
        kinds = self._kinds("int tty_flag;\nOptions options;\n")
        assert kinds.get("tty_flag") == "declaration"
        assert kinds.get("options") == "declaration"

    def test_extern_declaration(self):
        kinds = self._kinds("extern char *progname_var;\n")
        assert kinds.get("progname_var") == "declaration"

    def test_inert_constant_initializer(self):
        kinds = self._kinds('int tty_flag = 0;\nchar *config = NULL;\n')
        assert kinds.get("tty_flag") == "declaration"
        assert kinds.get("config") == "declaration"

    def test_const_function_pointer_table(self):
        content = (
            "const struct key_impl_funcs key_funcs = {\n"
            "\t/* .size = */ NULL,\n"
            "\t/* .alloc = */ key_alloc,\n"
            "\t/* .cleanup = */ key_cleanup,\n"
            "};\n"
        )
        kinds = self._kinds(content)
        assert kinds.get("key_funcs") == "declaration"

    def test_initializer_with_call_stays_global(self):
        kinds = self._kinds("int counter = init_counter();\n")
        assert kinds.get("counter") == "global"

    def test_initializer_with_expression_stays_global(self):
        # Unknown/expression shapes stay reviewable (conservative).
        kinds = self._kinds("int limit = 60 * 60;\n")
        assert kinds.get("limit") == "global"

    def test_cpp_no_initializer_stays_global(self):
        # C++: `Foo bar;` can run a constructor at start-up — only
        # extern-without-initializer is reclassified there.
        from core.testing.treesitter import ts_parser_available
        if not ts_parser_available("cpp"):
            pytest.skip("tree-sitter cpp grammar required")
        kinds = self._kinds("Options options;\nextern Options other;\n",
                            language="cpp")
        assert kinds.get("options") == "global"
        assert kinds.get("other") == "declaration"


@requires_ts("c")
class TestFragmentedParseLocals:
    """Error recovery on an unparseable C file can hoist FUNCTION-BODY
    locals to root scope. Those must never become checklist items —
    each local of an affected function used to surface as a separate
    'global' consuming full review effort."""

    def test_hoisted_locals_are_not_items(self):
        from core.inventory.extractors import extract_items
        content = (
            "int file_scope = 0;\n"
            "}\n"                             # stray closer: fragmented parse
            "\tstatic int hoisted_local;\n"   # body-indented, hoisted to root
            "\tchar *another_local;\n"
            "int file_scope_after;\n"
        )
        items = extract_items("t.c", "c", content)
        names = {i.name for i in items}
        assert "hoisted_local" not in names
        assert "another_local" not in names
        # Column-0 file-scope declarations survive the guard.
        assert "file_scope" in names
        assert "file_scope_after" in names

    def test_pristine_parse_keeps_indented_declarations(self):
        # The guard only fires on fragmented parses; an error-free file
        # keeps whatever the grammar put at root, indented or not.
        from core.inventory.extractors import extract_items
        content = "  int indented_but_valid = 0;\n"
        names = {i.name for i in extract_items("t.c", "c", content)}
        assert "indented_but_valid" in names


class TestConstantMacroKind:
    """Object-like macros with a single literal/identifier body classify
    as ``constant_macro``; function-like macros and anything with logic
    stay reviewable ``macro``. Regex path — no tree-sitter needed."""

    @staticmethod
    def _kinds(content):
        from core.inventory.extractors import _extract_macros_regex
        return {m.name: m.kind for m in _extract_macros_regex(content)}

    def test_number_body(self):
        kinds = self._kinds("#define MKTEMP_NAME\t0\n#define MAX_SZ 0x1000\n")
        assert kinds["MKTEMP_NAME"] == "constant_macro"
        assert kinds["MAX_SZ"] == "constant_macro"

    def test_string_body(self):
        kinds = self._kinds('#define _PATH_PIDDIR\t\t"/var/run"\n')
        assert kinds["_PATH_PIDDIR"] == "constant_macro"

    def test_identifier_and_subscript_body(self):
        kinds = self._kinds("#define\tatime\ttv[0]\n#define ALIAS other_name\n")
        assert kinds["atime"] == "constant_macro"
        assert kinds["ALIAS"] == "constant_macro"

    def test_string_paste_body(self):
        kinds = self._kinds('#define _PATH_HOSTFILE\tSSHDIR "/ssh_known_hosts"\n')
        assert kinds["_PATH_HOSTFILE"] == "constant_macro"

    def test_parenthesised_literal_body(self):
        kinds = self._kinds("#define BUFSZ (2048)\n")
        assert kinds["BUFSZ"] == "constant_macro"

    def test_function_like_macro_stays_macro(self):
        # An unsafe function-like macro is a real bug multiplier.
        kinds = self._kinds(
            "#define\tSCREWUP(str)\t{ why = str; goto screwup; }\n")
        assert kinds["SCREWUP"] == "macro"

    def test_include_guard_stays_macro(self):
        kinds = self._kinds("#define CONFIG_H\n")
        assert kinds["CONFIG_H"] == "macro"

    def test_expression_body_stays_macro(self):
        kinds = self._kinds("#define LIMIT (8 * 1024)\n#define NEG (u_int)-1\n")
        assert kinds["LIMIT"] == "macro"
        assert kinds["NEG"] == "macro"

    def test_multiline_body_stays_macro(self):
        kinds = self._kinds("#define BIG \\\n\t42\n")
        assert kinds["BIG"] == "macro"

    def test_body_comment_is_ignored(self):
        kinds = self._kinds("#define TIMEOUT 30 /* seconds */\n")
        assert kinds["TIMEOUT"] == "constant_macro"


# ---------------------------------------------------------------------------
# LuaExtractor tests
# ---------------------------------------------------------------------------

class TestLuaExtractor:
    ext = LuaExtractor()

    def test_global_function(self):
        code = "function greet(name)\n  print(name)\nend\n"
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "greet"
        assert funcs[0].line_start == 1
        assert funcs[0].line_end == 3
        assert funcs[0].metadata.visibility == "public"

    def test_local_function(self):
        code = "local function helper(x)\n  return x + 1\nend\n"
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "helper"
        assert funcs[0].metadata.visibility == "private"

    def test_module_dot_syntax(self):
        code = "function M.init(cfg)\n  M.cfg = cfg\nend\n"
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "M.init"

    def test_method_colon_syntax(self):
        code = "function Widget:render()\n  return self.html\nend\n"
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "Widget.render"

    def test_assigned_anonymous(self):
        code = "M.handler = function(req)\n  return 200\nend\n"
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "M.handler"

    def test_local_assigned_anonymous(self):
        code = "local parse = function(s)\n  return tonumber(s)\nend\n"
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "parse"
        assert funcs[0].metadata.visibility == "private"

    def test_line_end_nested_blocks(self):
        code = (
            "function outer()\n"
            "  if true then\n"
            "    for i=1,10 do\n"
            "      print(i)\n"
            "    end\n"
            "  end\n"
            "end\n"
        )
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].line_end == 7

    def test_multiple_functions(self):
        code = (
            "function a()\n  return 1\nend\n\n"
            "function b()\n  return 2\nend\n"
        )
        funcs = self.ext.extract("test.lua", code)
        names = [f.name for f in funcs]
        assert names == ["a", "b"]
        assert funcs[0].line_end == 3
        assert funcs[1].line_end == 7

    def test_comment_not_counted(self):
        code = (
            "function f()\n"
            "  -- if this were parsed it would add depth\n"
            "  return 1\n"
            "end\n"
        )
        funcs = self.ext.extract("test.lua", code)
        assert funcs[0].line_end == 4

    def test_repeat_until_not_confused(self):
        code = (
            "function poll()\n"
            "  repeat\n"
            "    x = read()\n"
            "  until x ~= nil\n"
            "  return x\n"
            "end\n"
        )
        funcs = self.ext.extract("test.lua", code)
        assert funcs[0].line_end == 6

    def test_commented_out_function_skipped(self):
        code = "-- function fake()\nfunction real()\n  return 1\nend\n"
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "real"

    def test_keyword_in_string_not_counted(self):
        code = (
            'function call(name)\n'
            '  return {\n'
            '    ["function"] = name,\n'
            '    ["type"] = "call"\n'
            '  }\n'
            'end\n'
        )
        funcs = self.ext.extract("test.lua", code)
        assert len(funcs) == 1
        assert funcs[0].line_end == 6

    def test_extract_functions_lua(self):
        code = "function dispatch(req)\n  route(req)\nend\n"
        funcs = extract_functions("controller.lua", "lua", code)
        assert len(funcs) == 1
        assert funcs[0].name == "dispatch"


# ---------------------------------------------------------------------------
# Scala (tree-sitter). Regression guard for the regex-fallback gap: .scala had
# no loader branch, so it silently degraded to regex — fewer functions and no
# line_end, which disables every span-based consumer.
# ---------------------------------------------------------------------------

_SCALA_SRC = '''package kafka.server

import scala.collection.Map

object ConfigHelper {
  def normalize(name: String): String = {
    name.trim.toLowerCase
  }
}

class ConfigAdminManager(nodeId: Int) {

  def preprocess(request: AlterConfigsRequest): Map[String, String] = {
    val out = Map.empty[String, String]
    out
  }

  private def validateBrokerConfigChange(props: Properties): Unit = {
    if (props.isEmpty) {
      throw new InvalidRequestException("empty")
    }
  }
}

trait Reconfigurable {
  def reconfigure(configs: Map[String, _]): Unit
}
'''


def _has_tree_sitter_scala() -> bool:
    try:
        import tree_sitter_scala  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(
    not _has_tree_sitter_scala(),
    reason="tree_sitter_scala grammar not installed",
)
class TestScalaExtraction:
    def _extract(self):
        return extract_functions("ConfigAdminManager.scala", "scala", _SCALA_SRC)

    def test_finds_defs_in_class_object_and_trait(self):
        names = {f.name for f in self._extract()}
        assert {"normalize", "preprocess", "validateBrokerConfigChange"} <= names

    def test_every_function_has_a_line_span(self):
        """The whole point: the regex fallback returned line_end=None, which
        silently disables source-slicing consumers."""
        fns = self._extract()
        assert fns
        for f in fns:
            assert f.line_start, f.name
            assert f.line_end, f.name
            assert f.line_end >= f.line_start, f.name

    def test_span_covers_the_body(self):
        fn = next(f for f in self._extract() if f.name == "validateBrokerConfigChange")
        body = "\n".join(_SCALA_SRC.splitlines()[fn.line_start - 1:fn.line_end])
        assert "InvalidRequestException" in body

    def test_scala_uses_function_definition_not_java_node_names(self):
        """Scala `def` is function_definition; reusing Java's
        method_declaration extracts zero from a cleanly-parsed file."""
        assert TreeSitterExtractor._FUNC_TYPES["scala"] == ("function_definition",)
        assert "method_declaration" not in TreeSitterExtractor._FUNC_TYPES["scala"]

    def test_abstract_trait_def_is_excluded(self):
        """An abstract `def` with no body is `function_declaration`, not
        `function_definition` — no code to review. Same rule as Rust's
        `function_signature_item`. The regex fallback wrongly includes it."""
        assert "reconfigure" not in {f.name for f in self._extract()}

    def test_regex_fallback_has_no_line_end(self):
        """Pins the defect this branch fixes. Deliberately does NOT compare
        counts: on a tiny fixture the regex can over-match (it picks up the
        abstract def), while on real files tree-sitter finds substantially
        more. The invariant that always holds, and the one span-based
        consumers depend on, is that the fallback yields no line_end."""
        import core.inventory.extractors as _E
        saved = _E._TS_AVAILABLE
        _E._TS_AVAILABLE = False
        try:
            rx = extract_functions("ConfigAdminManager.scala", "scala", _SCALA_SRC)
        finally:
            _E._TS_AVAILABLE = saved
        assert rx, "fallback should still find something"
        assert not any(f.line_end for f in rx)
        assert all(f.line_end for f in self._extract())


class TestTsProbeMatchesLoader:
    def test_probe_list_covers_every_loader_branch(self):
        """The banner list drifted behind the loader — cpp/typescript/rust/
        csharp/ruby/php had working branches but were never probed, so the
        doctor under-reported what the inventory could parse."""
        from core.inventory.extractors import _TS_PROBE_LANGUAGES
        for lang in TreeSitterExtractor._FUNC_TYPES:
            assert lang in _TS_PROBE_LANGUAGES, (
                f"{lang} has node types but is not probed for the banner"
            )


# ---------------------------------------------------------------------------
# CExtractor._fill_line_ends — linear post-pass (U09-F1)
# ---------------------------------------------------------------------------


class TestCFillLineEndsLinear:
    def test_matches_per_function_reference_scanner(self):
        from core.inventory.extractors import CExtractor, FunctionInfo
        src = (
            "int f(void)\n"
            "{\n"
            "  if (x) { /* } */ y(\"}\"); }\n"
            "}\n"
            "static int g(int a) {\n"
            "  return a; // }\n"
            "}\n"
            "int h(void)\n"
            "{\n"
            "  char c = '}';\n"
            "}\n"
        )
        lines = src.split("\n")
        starts = [1, 5, 8]
        ref = {
            s: CExtractor._find_end_brace(lines, s - 1) for s in starts
        }
        funcs = [FunctionInfo(name=f"fn{s}", line_start=s) for s in starts]
        CExtractor._fill_line_ends(lines, funcs)
        assert {f.line_start: f.line_end for f in funcs} == ref
        assert ref == {1: 4, 5: 7, 8: 11}

    def test_never_closing_openers_fill_is_linear(self):
        # A file of N one-line functions each opening a brace that
        # never closes made every function re-scan to EOF: O(N²) — an
        # effective hang at the 8 MiB per-file cap. The linear fill
        # must finish the whole batch in well under a second.
        import time
        from core.inventory.extractors import CExtractor, FunctionInfo
        n = 50_000
        lines = [f"int f{k}()" + "{" for k in range(n)]
        funcs = [
            FunctionInfo(name=f"f{k}", line_start=k + 1) for k in range(n)
        ]
        start = time.perf_counter()
        CExtractor._fill_line_ends(lines, funcs)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"fill took {elapsed:.1f}s on {n} lines"
        assert all(f.line_end is None for f in funcs)

    def test_unbalanced_head_still_resolves_later_functions(self):
        from core.inventory.extractors import CExtractor, FunctionInfo
        lines = [
            "int broken()",   # 1 — never opens
            "int ok(void)",   # 2
            "{",              # 3
            "  return 1;",    # 4
            "}",              # 5
        ]
        funcs = [
            FunctionInfo(name="broken", line_start=1),
            FunctionInfo(name="ok", line_start=2),
        ]
        CExtractor._fill_line_ends(lines, funcs)
        by_name = {f.name: f.line_end for f in funcs}
        assert by_name == {"broken": 5, "ok": 5}


@requires_ts("c")
def test_c_repair_pass_ignores_commented_out_functions():
    # tree-sitter correctly sees only a comment; the gap-filling regex
    # ran over raw text and minted a phantom function item (a
    # reviewable checklist unit over dead text whose span overlapped
    # the real function below the comment).
    src = (
        "int keep_top(void) { return 1; }\n"
        "/*\n"
        "int old_impl(int x) {\n"
        "    return x + 1;\n"
        "}\n"
        "*/\n"
        "int real_fn(int y) { return y; }\n"
    )
    items = extract_items("t.c", "c", src)
    names = {i.name for i in items if i.kind == "function"}
    assert "old_impl" not in names
    assert {"keep_top", "real_fn"} <= names


def test_c_repair_pass_still_rescues_macro_fragmented_functions():
    # The pass exists to fill tree-sitter gaps from unknown macros —
    # the comment-blanked view must not lose that rescue.
    src = (
        "int ZEXPORT frag_fn(z_streamp strm)\n"
        "{\n"
        "    return 0;\n"
        "}\n"
    )
    items = extract_items("t.c", "c", src)
    names = {i.name for i in items if i.kind == "function"}
    assert "frag_fn" in names


# ---------------------------------------------------------------------------
# JavaScriptExtractor._fill_line_ends — linear post-pass (the
# CExtractor idiom ported to the JS fallback)
# ---------------------------------------------------------------------------


class TestJsFillLineEndsLinear:
    def test_matches_per_function_reference_scanner(self):
        src = (
            "function outer(a) {\n"
            "  const s = \"} not a close\";\n"
            "  const t = `}` /* } */;\n"
            "  const re = /}/; // }\n"
            "  if (a) { return 1; }\n"
            "}\n"
            "const add = (a, b) => a + b;\n"
            "const wrap = function() {\n"
            "  return () => { f(); };\n"
            "}\n"
        )
        lines = src.split("\n")
        starts = [1, 7, 8]
        ref = {
            s: JavaScriptExtractor._find_end(lines, s - 1) for s in starts
        }
        funcs = [FunctionInfo(name=f"fn{s}", line_start=s) for s in starts]
        JavaScriptExtractor._fill_line_ends(lines, funcs)
        assert {f.line_start: f.line_end for f in funcs} == ref
        assert ref == {1: 6, 7: 7, 8: 10}

    def test_braceless_arrow_semicolon_rule_survives(self):
        # `;` before any `{`: the span must end at the statement, not
        # adopt the NEXT function's braces.
        src = (
            "const add = (a, b) =>\n"
            "  a + b;\n"
            "function next() {\n"
            "  return 2;\n"
            "}\n"
        )
        lines = src.split("\n")
        funcs = [FunctionInfo(name="add", line_start=1)]
        JavaScriptExtractor._fill_line_ends(lines, funcs)
        assert funcs[0].line_end == 2
        assert JavaScriptExtractor._find_end(lines, 0) == 2

    def test_random_differential_against_reference(self):
        # Property test: on files built from single-line constructs
        # (every line starts outside strings/comments/regex — the
        # documented equivalence domain), the event-stream fill must
        # agree with the per-function reference scanner at EVERY line.
        import random
        rng = random.Random(20260923)
        pool = [
            "function f() {",
            "}",
            "const a = (x) => x + 1;",
            "let b = { k: 1 };",
            "// } stray comment close",
            "/* { */ call(); /* } */",
            "const s = \"{ } ; //\";",
            "const t = '} {';",
            "const u = `{ ; }`;",
            "if (x) { y(); }",
            # `x = /…/`: the `=` prefix makes the regex-literal read
            # line-local in BOTH lexers (a `return /…/` spelling can
            # mislex as division from a carried prev-char and leak
            # regex state across lines — outside the documented
            # equivalence domain, like a start line inside a comment).
            "x = /}{/.test(s);",
            "g(function inner() {",
            "});",
            "",
            "; ;",
        ]
        for _ in range(150):
            lines = [rng.choice(pool) for _ in range(rng.randint(5, 40))]
            for start in range(1, len(lines) + 1):
                ref = JavaScriptExtractor._find_end(lines, start - 1)
                funcs = [FunctionInfo(name="p", line_start=start)]
                JavaScriptExtractor._fill_line_ends(lines, funcs)
                assert funcs[0].line_end == ref, (
                    f"divergence at start={start} for {lines!r}"
                )

    def test_never_closing_openers_extract_is_linear(self):
        # A file of N one-line headers each opening a brace that never
        # closes made every header re-scan to EOF: O(N²) — ~5 s at
        # n=2000 pre-fix, an effective hang at real bundle sizes.
        import time
        n = 20_000
        src = "\n".join(f"function f{k}() {{ // open" for k in range(n))
        start = time.perf_counter()
        funcs = JavaScriptExtractor().extract("f.js", src)
        elapsed = time.perf_counter() - start
        assert elapsed < 10.0, f"extract took {elapsed:.1f}s on {n} headers"
        assert len(funcs) == n
        assert all(f.line_end is None for f in funcs)


# ---------------------------------------------------------------------------
# LuaExtractor._fill_line_ends — linear post-pass
# ---------------------------------------------------------------------------


class TestLuaFillLineEndsLinear:
    def test_matches_per_function_reference_scanner(self):
        src = (
            "function outer(a)\n"
            "  local s = \"end function\"\n"
            "  -- end end end\n"
            "  if a then\n"
            "    return 1\n"
            "  end\n"
            "end\n"
            "--[[ function ghost()\n"
            "end ]]\n"
            "local f = function(x)\n"
            "  while x do x = g(x) end\n"
            "end\n"
        )
        ex = LuaExtractor()
        lines = ex._mask_long_comments(src.split("\n"))
        starts = [1, 10]
        ref = {s: ex._find_end(lines, s - 1) for s in starts}
        funcs = [FunctionInfo(name=f"fn{s}", line_start=s) for s in starts]
        ex._fill_line_ends(src.split("\n"), funcs)
        assert {f.line_start: f.line_end for f in funcs} == ref
        assert ref == {1: 7, 10: 12}

    def test_random_differential_against_reference(self):
        import random
        rng = random.Random(20260923)
        pool = [
            "function f(a)",
            "end",
            "if x then",
            "for i = 1, 10 do",
            "while x do",
            "end end",
            "local s = \"function end\"",
            "-- function end",
            "local t = 'end'",
            "x = y + 1",
            "return f(x)",
            "",
            "repeat",
            "until x",
        ]
        ex = LuaExtractor()
        for _ in range(150):
            raw = [rng.choice(pool) for _ in range(rng.randint(5, 40))]
            masked = ex._mask_long_comments(raw)
            for start in range(1, len(raw) + 1):
                ref = ex._find_end(masked, start - 1)
                funcs = [FunctionInfo(name="p", line_start=start)]
                ex._fill_line_ends(raw, funcs)
                assert funcs[0].line_end == ref, (
                    f"divergence at start={start} for {raw!r}"
                )

    def test_never_closing_headers_extract_is_linear(self):
        import time
        n = 20_000
        src = "\n".join(
            f"function f{k}() -- never closes" for k in range(n)
        )
        start = time.perf_counter()
        funcs = LuaExtractor().extract("f.lua", src)
        elapsed = time.perf_counter() - start
        assert elapsed < 10.0, f"extract took {elapsed:.1f}s on {n} headers"
        assert len(funcs) == n
        assert all(f.line_end is None for f in funcs)


# ---------------------------------------------------------------------------
# ObjCExtractor — shared brace-event fill, declaration skip first
# ---------------------------------------------------------------------------


class TestObjCExtractorLinear:
    def test_methods_and_declarations(self):
        from core.inventory.extractors import ObjCExtractor
        src = (
            "@interface Foo\n"
            "- (void)declaredOnly:(int)x;\n"
            "@end\n"
            "@implementation Foo\n"
            "- (void)realMethod:(int)x {\n"
            "  if (x) { bar(); }\n"
            "}\n"
            "+ (int)classMethod {\n"
            "  return 1;\n"
            "}\n"
            "@end\n"
            "static int plain_c(void) {\n"
            "  return 2;\n"
            "}\n"
        )
        funcs = ObjCExtractor().extract("f.m", src)
        by_name = {f.name: (f.line_start, f.line_end) for f in funcs}
        assert "declaredOnly" not in by_name
        assert by_name["realMethod"] == (5, 7)
        assert by_name["classMethod"] == (8, 10)
        assert by_name["plain_c"] == (12, 14)

    def test_never_closing_methods_extract_is_linear(self):
        import time
        from core.inventory.extractors import ObjCExtractor
        n = 20_000
        src = "\n".join(f"- (void)m{k} {{ // open" for k in range(n))
        start = time.perf_counter()
        funcs = ObjCExtractor().extract("f.m", src)
        elapsed = time.perf_counter() - start
        assert elapsed < 10.0, f"extract took {elapsed:.1f}s on {n} headers"
        assert len(funcs) == n


# ---------------------------------------------------------------------------
# TreeSitterExtractor C orphan-declarator recovery — deferred span
# fill + sibling context (fragmented-parse flood)
# ---------------------------------------------------------------------------


@requires_ts("c")
def test_c_orphan_recovery_span_covers_the_knr_body():
    # zlib's K&R + macro shape: tree-sitter fragments the parse (the
    # declarator becomes a sibling of bare `{`); the recovered span
    # must still cover the whole body, answered from the shared
    # brace-event fill (the walk-rooted cursor of an intermediate
    # rewrite could not reach siblings and silently left the span at
    # the declaration line).
    src = (
        "int ZEXPORT inflate(strm, flush)\n"
        "z_streamp strm;\n"
        "int flush;\n"
        "{\n"
        "    if (strm) { work(); }\n"
        "    return 0;\n"
        "}\n"
        "int tail_fn(void) { return 0; }\n"
    )
    funcs = TreeSitterExtractor("c").extract("f.c", src)
    by_name = {f.name: (f.line_start, f.line_end) for f in funcs}
    assert by_name["inflate"] == (1, 7)


@requires_ts("c")
def test_c_fragmented_parse_flood_is_linear():
    # N fragmented K&R headers whose bodies never close: the per-
    # orphan _find_end_brace walk (plus per-orphan seen-name set
    # rebuilds and per-orphan Node.parent/next_sibling relocations)
    # made this O(N²) on the PRIMARY tree-sitter path.
    import time
    n = 4000
    src = "".join(
        f"int ZEXPORT f{i}(a, b)\nint a; int b;\n{{ x = y[0]\n"
        for i in range(n)
    )
    start = time.perf_counter()
    funcs = TreeSitterExtractor("c").extract("f.c", src)
    elapsed = time.perf_counter() - start
    assert elapsed < 15.0, f"extract took {elapsed:.1f}s on {n} headers"
    assert len(funcs) == n
