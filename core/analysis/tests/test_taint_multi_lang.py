"""Tests for core.analysis.taint_multi_lang — multi-language taint extraction."""

import time

from core.analysis.taint_multi_lang import (
    extract_java_summaries,
    extract_js_summaries,
    extract_go_summaries,
    extract_rust_summaries,
    extract_summaries_for_file,
    _extract_callees_java,
    _find_brace_end,
    _JAVA_FUNC,
    _MAX_CALLEES,
    _parse_java_params,
    _parse_go_params,
    _parse_rust_params,
)


class TestJavaExtraction:
    def test_basic_function(self):
        src = """\
public class Foo {
    public void execute(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}"""
        results = extract_java_summaries(src, "Foo.java")
        assert "execute" in results
        s = results["execute"]
        assert len(s.taint_rules) > 0
        assert any(r.sink_call for r in s.taint_rules if "exec" in r.sink_call)

    def test_null_check_precondition(self):
        src = """\
public class Foo {
    public void process(String input) {
        if (input == null) return;
        System.out.println(input);
    }
}"""
        results = extract_java_summaries(src, "Foo.java")
        assert "process" in results
        s = results["process"]
        assert any(p.param == "input" for p in s.preconditions)

    def test_multiple_params(self):
        src = """\
public class Foo {
    public void query(String sql, int limit) {
        Statement.executeQuery(sql);
    }
}"""
        results = extract_java_summaries(src, "Foo.java")
        assert "query" in results
        s = results["query"]
        assert any(r.source_param == "sql" for r in s.taint_rules)

    def test_parse_java_params(self):
        assert _parse_java_params("String name, int age") == ["name", "age"]
        assert _parse_java_params("final List<String> items") == ["items"]
        assert _parse_java_params("") == []


class TestJavaFuncRegex:
    def test_matches_modifier_functions(self):
        m = _JAVA_FUNC.search("public static void main(String[] args) {")
        assert m and m.group(1) == "main"
        m = _JAVA_FUNC.search("  private int foo(int a) throws IOException {")
        assert m and m.group(1) == "foo"

    def test_matches_bare_and_generic_return(self):
        m = _JAVA_FUNC.search("int bare(int x) {")
        assert m and m.group(1) == "bare"
        m = _JAVA_FUNC.search("public List<String> get(String k) {")
        assert m and m.group(1) == "get"

    def test_no_midword_match(self):
        assert _JAVA_FUNC.search("myint foo(") is None

    def test_whitespace_heavy_file_completes_quickly(self):
        # ~500KB of whitespace must not stall through quadratic
        # backtracking. Generous budget keeps the assertion hermetic
        # on slow machines.
        content = (" " * 200 + "\n") * 2500
        start = time.monotonic()
        assert list(_JAVA_FUNC.finditer(content)) == []
        assert time.monotonic() - start < 5.0


class TestCalleeCap:
    """Extractors and their consumer share one callee cap."""

    def _body_with_calls(self, n: int) -> str:
        return "\n".join(f"call_{i}(x);" for i in range(n))

    def test_extractor_caps_at_max_callees(self):
        callees = _extract_callees_java(self._body_with_calls(40))
        assert len(callees) == _MAX_CALLEES

    def test_summary_callees_match_extractor_cap(self):
        body = self._body_with_calls(40)
        content = f"public void worker(String input) {{\n{body}\n}}\n"
        summaries = extract_java_summaries(content, "Worker.java")
        assert "worker" in summaries
        assert len(summaries["worker"].callees) == _MAX_CALLEES


class TestJavaScriptExtraction:
    def test_named_function(self):
        src = """\
function handleRequest(userInput, res) {
    eval(userInput);
    res.send("done");
}"""
        results = extract_js_summaries(src, "app.js")
        assert "handleRequest" in results
        s = results["handleRequest"]
        assert any("eval" in r.sink_call for r in s.taint_rules)

    def test_null_check(self):
        src = """\
function validate(data) {
    if (data === null) throw new Error("null");
    return data.length;
}"""
        results = extract_js_summaries(src, "util.js")
        assert "validate" in results
        s = results["validate"]
        assert any(p.param == "data" for p in s.preconditions)

    def test_typescript_file(self):
        src = """\
function query(input: string): void {
    db.query(input);
}"""
        results = extract_summaries_for_file(src, "db.ts")
        assert "query" in results


class TestGoExtraction:
    def test_basic_function(self):
        src = """\
func RunCommand(cmd string, args []string) error {
    return exec.Command(cmd, args...).Run()
}"""
        results = extract_go_summaries(src, "cmd.go")
        assert "RunCommand" in results
        s = results["RunCommand"]
        assert any("exec.Command" in r.sink_call or "Command" in r.sink_call
                   for r in s.taint_rules)

    def test_nil_check(self):
        src = """\
func Process(conn *net.Conn) {
    if conn == nil {
        return
    }
    conn.Write([]byte("hello"))
}"""
        results = extract_go_summaries(src, "net.go")
        assert "Process" in results
        s = results["Process"]
        assert any(p.param == "conn" for p in s.preconditions)

    def test_method_receiver(self):
        src = """\
func (s *Server) Handle(input string) {
    db.Query(input)
}"""
        results = extract_go_summaries(src, "server.go")
        assert "Handle" in results
        s = results["Handle"]
        assert any("Query" in r.sink_call for r in s.taint_rules)

    def test_parse_go_params(self):
        assert _parse_go_params("name string, age int") == ["name", "age"]
        assert _parse_go_params("*conn net.Conn") == ["conn"]
        assert _parse_go_params("...args string") == ["args"]


class TestRustExtraction:
    def test_basic_function(self):
        src = """\
pub fn execute(cmd: &str) -> Result<(), Error> {
    Command::new(cmd).spawn()?;
    Ok(())
}"""
        results = extract_rust_summaries(src, "exec.rs")
        assert "execute" in results
        s = results["execute"]
        assert any("Command" in r.sink_call for r in s.taint_rules)

    def test_assert_precondition(self):
        src = """\
fn process(buf: &[u8], len: usize) {
    assert!(len <= buf.len());
    unsafe {
        ptr::copy(buf.as_ptr(), dst, len);
    }
}"""
        results = extract_rust_summaries(src, "mem.rs")
        assert "process" in results
        s = results["process"]
        assert any(p.param == "len" for p in s.preconditions)

    def test_unsafe_sink(self):
        src = """\
pub fn convert(data: *const u8, size: usize) -> Vec<u8> {
    unsafe {
        slice::from_raw_parts(data, size).to_vec()
    }
}"""
        results = extract_rust_summaries(src, "conv.rs")
        assert "convert" in results
        s = results["convert"]
        assert any("from_raw_parts" in r.sink_call for r in s.taint_rules)

    def test_parse_rust_params(self):
        assert _parse_rust_params("buf: &[u8], len: usize") == ["buf", "len"]
        assert _parse_rust_params("&self, name: String") == ["name"]
        assert _parse_rust_params("mut data: Vec<u8>") == ["data"]


class TestDispatch:
    def test_java_dispatch(self):
        src = "public class X { public void f(String s) { exec(s); } }"
        results = extract_summaries_for_file(src, "X.java")
        assert "f" in results

    def test_js_dispatch(self):
        src = "function f(x) { eval(x); }"
        results = extract_summaries_for_file(src, "app.js")
        assert "f" in results

    def test_ts_dispatch(self):
        src = "function f(x: string) { eval(x); }"
        results = extract_summaries_for_file(src, "app.ts")
        assert "f" in results

    def test_go_dispatch(self):
        src = 'func f(cmd string) { exec.Command(cmd) }'
        results = extract_summaries_for_file(src, "main.go")
        assert "f" in results

    def test_rust_dispatch(self):
        src = 'fn f(cmd: &str) { Command::new(cmd); }'
        results = extract_summaries_for_file(src, "main.rs")
        assert "f" in results

    def test_unknown_extension(self):
        results = extract_summaries_for_file("code", "file.rb")
        assert results == {}


class TestBraceMatching:
    def test_simple(self):
        assert _find_brace_end("{ foo }", 0) == 7

    def test_nested(self):
        assert _find_brace_end("{ { } }", 0) == 7

    def test_string_braces_ignored(self):
        s = '{ x = "}" }'
        assert _find_brace_end(s, 0) == len(s)

    def test_unterminated_line_comment_scans_to_eof(self):
        content = "{ x(); // no trailing newline"
        # The str.find -1 sentinel must not leak out; like the
        # unterminated-block-comment branch, this returns len(content).
        assert _find_brace_end(content, 0) == len(content)

    def test_matched_braces_unchanged(self):
        content = "{ if (a) { b(); } }"
        assert _find_brace_end(content, 0) == len(content)

    def test_line_comment_with_newline_unchanged(self):
        content = "{ x(); // brace in comment }\n}"
        assert _find_brace_end(content, 0) == len(content)
