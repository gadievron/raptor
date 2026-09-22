"""Tests for core.analysis.taint_multi_lang — multi-language taint extraction."""

import time

from core.analysis.taint_multi_lang import (
    extract_java_summaries,
    extract_js_summaries,
    extract_go_summaries,
    extract_php_summaries,
    extract_rust_summaries,
    extract_summaries_for_file,
    _extract_callees_java,
    _extract_php_extra_flows,
    _find_brace_end,
    _JAVA_FUNC,
    _PHP_FUNC,
    _MAX_CALLEES,
    _parse_java_params,
    _parse_go_params,
    _parse_php_params,
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


class TestPhpExtraction:
    def test_basic_function(self):
        src = """\
<?php
function run_command($cmd) {
    system($cmd);
}"""
        results = extract_php_summaries(src, "run.php")
        assert "run_command" in results
        s = results["run_command"]
        assert any(
            r.source_param == "cmd" and r.sink_call == "system"
            for r in s.taint_rules
        )

    def test_method_with_modifiers(self):
        src = """\
<?php
class Loader {
    public static function loadPage(string $page): void {
        require_once($page);
    }
}"""
        results = extract_php_summaries(src, "Loader.php")
        assert "loadPage" in results
        assert any(
            r.source_param == "page" and "require" in r.sink_call
            for r in results["loadPage"].taint_rules
        )

    def test_superglobal_source_has_no_param_index(self):
        # Superglobals are not positional parameters: index -1, the
        # convention upward propagation already skips.
        src = """\
<?php
function handle() {
    eval($_GET['code']);
    header("Location: " . $_POST['next']);
}"""
        results = extract_php_summaries(src, "handle.php")
        rules = results["handle"].taint_rules
        get_rule = next(r for r in rules if r.source_param == "$_GET")
        assert get_rule.sink_call == "eval"
        assert get_rule.source_index == -1
        assert any(
            r.source_param == "$_POST" and r.sink_call == "header"
            for r in rules
        )

    def test_keyword_sinks_without_parentheses(self):
        src = """\
<?php
function render($name) {
    echo "Hello " . $name;
    include $_REQUEST['page'];
}"""
        results = extract_php_summaries(src, "render.php")
        rules = results["render"].taint_rules
        assert any(
            r.source_param == "name" and r.sink_call == "echo"
            for r in rules
        )
        assert any(
            r.source_param == "$_REQUEST" and r.sink_call == "include"
            for r in rules
        )

    def test_backtick_operator_is_shell_exec(self):
        src = """\
<?php
function list_dir($dir) {
    return `ls $dir`;
}"""
        results = extract_php_summaries(src, "sh.php")
        assert any(
            r.source_param == "dir" and r.sink_call == "shell_exec"
            for r in results["list_dir"].taint_rules
        )

    def test_stream_and_env_sources(self):
        src = """\
<?php
function ingest() {
    $raw = unserialize(file_get_contents('php://input'));
    system(getenv('CMD_OVERRIDE'));
}"""
        results = extract_php_summaries(src, "ingest.php")
        rules = results["ingest"].taint_rules
        assert any(r.source_param == "php://input" for r in rules)
        assert any(
            r.source_param == "getenv" and r.sink_call == "system"
            for r in rules
        )

    def test_sanitizer_and_cast_preconditions(self):
        # Sanitizer application rides the precondition channel, never
        # flow suppression: the echo flow is still recorded.
        src = """\
<?php
function show($name, $id) {
    echo htmlspecialchars($name);
    $n = (int) $id;
    $safe = escapeshellarg($name);
}"""
        results = extract_php_summaries(src, "show.php")
        s = results["show"]
        pre = {(p.param, p.conditions[0]) for p in s.preconditions}
        assert ("name", "sanitized: htmlspecialchars") in pre
        assert ("name", "sanitized: escapeshellarg") in pre
        assert ("id", "cast to int") in pre
        assert any(
            r.source_param == "name" and r.sink_call == "echo"
            for r in s.taint_rules
        )

    def test_isset_and_null_preconditions(self):
        src = """\
<?php
function guard($a, $b) {
    if (!isset($a)) { return; }
    if ($b === null) { return; }
    echo $a . $b;
}"""
        results = extract_php_summaries(src, "guard.php")
        pre = {(p.param, p.conditions[0])
               for p in results["guard"].preconditions}
        assert ("a", "isset/empty checked") in pre
        assert ("b", "null check") in pre

    def test_bodyless_declaration_not_claimed(self):
        # An interface method ends in ';' — the next definition's
        # brace must not be swallowed as its body.
        src = """\
<?php
interface Store {
    public function find(int $id): array;
}
function lookup($key) {
    system($key);
}"""
        results = extract_php_summaries(src, "store.php")
        assert "find" not in results
        assert any(
            r.sink_call == "system"
            for r in results["lookup"].taint_rules
        )

    def test_language_constructs_not_callees(self):
        src = """\
<?php
function walk($items) {
    foreach ($items as $i) {
        if (isset($i)) {
            process($i);
        }
    }
}"""
        results = extract_php_summaries(src, "walk.php")
        callees = results["walk"].callees
        assert "process" in callees
        assert "foreach" not in callees
        assert "isset" not in callees

    def test_parse_php_params(self):
        assert _parse_php_params("string $s, ?int $id = 0") == ["s", "id"]
        assert _parse_php_params("&$ref, Type ...$rest") == ["ref", "rest"]
        assert _parse_php_params("") == []

    def test_no_functions_yields_empty(self):
        assert extract_php_summaries("<?php echo 'static';", "s.php") == {}


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

    def test_php_dispatch(self):
        src = '<?php function f($x) { system($x); }'
        results = extract_summaries_for_file(src, "index.php")
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


class TestRustLifetimes:
    def test_lifetime_does_not_open_a_string(self):
        # An apostrophe-as-string-opener made &'static swallow the
        # closing brace and corrupt the body extents.
        src = "{ let label: &'static str = \"tag\"; x() }"
        assert _find_brace_end(src, 0, rust_lifetimes=True) == len(src)

    def test_char_literal_with_brace_still_masked(self):
        # Direction check: a real char literal containing a brace
        # must still hide it from depth counting.
        src = "{ let c = '}'; x() }"
        assert _find_brace_end(src, 0, rust_lifetimes=True) == len(src)

    def test_escaped_char_literal_masked(self):
        src = "{ let c = '\\''; if a { b() } }"
        assert _find_brace_end(src, 0, rust_lifetimes=True) == len(src)

    def test_default_mode_keeps_apostrophe_strings(self):
        # Non-Rust callers (Java/JS/Go char and string syntax) keep
        # the original apostrophe handling.
        src = "{ x = '}' }"
        assert _find_brace_end(src, 0) == len(src)

    def test_function_after_lifetime_heavy_body_still_extracted(self):
        src = """\
fn first(x: &str) -> &'static str {
    let label: &'static str = "tag";
    Command::new(x);
}

fn second(y: &str) {
    fs::write(y, "data");
}
"""
        results = extract_rust_summaries(src, "lt.rs")
        assert "first" in results
        assert "second" in results
        assert any(
            "fs::write" in r.sink_call
            for r in results["second"].taint_rules
        )


class TestRustMutPrefix:
    def test_mut_is_stripped_as_a_token(self):
        assert _parse_rust_params("mut data: Vec<u8>") == ["data"]

    def test_identifier_starting_with_mut_is_not_truncated(self):
        # removeprefix("mut") turned "mutation" into "ation".
        assert _parse_rust_params("mutation: u32") == ["mutation"]
        assert _parse_rust_params("mutex: &Mutex<()>") == ["mutex"]


class TestPhpKeywordFloodPerformance:
    """Keyword floods, not whitespace, are the quadratic fodder for
    the PHP shapes: a modifier-repetition prefix on _PHP_FUNC and an
    unbounded sink-argument class each took seconds at 64KB. The
    fixed patterns run in milliseconds; the budgets are generous for
    slow machines yet an order of magnitude below the quadratic
    variants at this input size."""

    def test_php_func_on_modifier_keyword_flood(self):
        flood = "public " * 18724  # ~128KB
        start = time.monotonic()
        assert _PHP_FUNC.findall(flood) == []
        assert time.monotonic() - start < 2.0

    def test_php_func_still_matches_modifier_signatures(self):
        # Direction check for the modifier-less pattern: captures are
        # anchored at the ``function`` keyword, so signatures with and
        # without modifiers yield identical tuples.
        sig = "  public static function &foo($a, &$b, ...$c) {}"
        assert _PHP_FUNC.findall(sig) == [("foo", "$a, &$b, ...$c")]
        assert _PHP_FUNC.findall("function foo($a) {}") == [("foo", "$a")]

    def test_extra_flows_on_unclosed_paren_flood(self):
        flood = "eval(" * 26000  # ~130KB, no closing paren
        start = time.monotonic()
        assert _extract_php_extra_flows(["p"], flood) == []
        assert time.monotonic() - start < 2.0

    def test_extra_flows_capped_arg_still_sees_sources(self):
        flows = _extract_php_extra_flows([], "eval($_GET['c']);")
        assert ("$_GET", -1, "eval", 0) in flows


class TestHashComments:
    def test_hash_comment_brace_masked(self):
        # A brace in a PHP '#' comment must not shift the extents.
        src = "{ x(); # closing } in a comment\n y(); }"
        assert _find_brace_end(src, 0, hash_comments=True) == len(src)

    def test_hash_comment_quote_masked(self):
        src = "{ x(); # don't\n y(); }"
        assert _find_brace_end(src, 0, hash_comments=True) == len(src)

    def test_default_mode_unchanged(self):
        # Direction check: without the flag '#' is ordinary content
        # and the commented brace still counts (Java/JS/Go/Rust
        # behaviour preserved).
        src = "{ x(); # }\n}"
        assert _find_brace_end(src, 0) == len("{ x(); # }")

    def test_body_with_hash_comment_still_extracted(self):
        src = """\
<?php
function first($a) {
    # legacy note with a stray }
    system($a);
}
function second($b) {
    passthru($b);
}"""
        results = extract_php_summaries(src, "h.php")
        assert "first" in results and "second" in results
        assert any(
            r.sink_call == "passthru"
            for r in results["second"].taint_rules
        )


class TestJsExtractorKeywordGuard:
    def test_switch_and_catch_are_not_functions(self):
        from core.analysis.taint_multi_lang import _extract_js_functions
        content = (
            "function real(a) { return a; }\n"
            "function other(x) {\n"
            "  switch (x) { default: break; }\n"
            "  try { x(); } catch (e) { log(e); }\n"
            "}\n"
        )
        names = {r[0] for r in _extract_js_functions(content)}
        assert "real" in names and "other" in names
        assert "switch" not in names
        assert "catch" not in names
