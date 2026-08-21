"""Tests for core.audit.ts_extract — tree-sitter extraction layer."""

from __future__ import annotations

import pytest
try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(not _HAS_TS, reason="tree-sitter not installed")

from core.audit.ts_extract import (  # noqa: E402
    CallChain,
    CallStep,
    DispatchTable,
    FunctionReturns,
    LoopCap,
    ReturnInfo,
    StringLiteralSite,
    extract_call_chains,
    extract_dispatch_tables,
    extract_function_body,
    extract_function_returns,
    extract_loop_caps,
    extract_string_literals,
)
from core.testing.treesitter import requires_ts  # noqa: E402


# ---------------------------------------------------------------
# 1. Return semantics
# ---------------------------------------------------------------


class TestExtractFunctionReturns:
    """extract_function_returns across languages."""

    @requires_ts("go")
    def test_go_nil_returns(self):
        src = """\
package main

func Lookup(key string) (*Item, error) {
    item, err := db.Get(key)
    if err != nil {
        return nil, err
    }
    if item == nil {
        return nil, nil
    }
    return item, nil
}
"""
        result = extract_function_returns("store.go", src)
        assert result is not None
        assert len(result) >= 1
        fr = result[0]
        assert fr.function == "Lookup"
        null_returns = [r for r in fr.returns if r.value_type == "null"]
        assert len(null_returns) >= 2

    @requires_ts("javascript")
    def test_js_null_and_undefined(self):
        src = """\
function fetchItem(id) {
    if (!id) {
        return null;
    }
    const item = cache.get(id);
    if (!item) {
        return undefined;
    }
    return item;
}
"""
        result = extract_function_returns("app.js", src)
        assert result is not None
        assert len(result) >= 1
        fr = result[0]
        null_returns = [r for r in fr.returns if r.value_type == "null"]
        assert len(null_returns) >= 1

    @requires_ts("java")
    def test_java_null_literal(self):
        src = """\
public class Store {
    public Item lookup(String key) {
        Item item = db.get(key);
        if (item == null) {
            return null;
        }
        return item;
    }
}
"""
        result = extract_function_returns("Store.java", src)
        assert result is not None
        assert len(result) >= 1
        null_returns = [r for r in result[0].returns if r.value_type == "null"]
        assert len(null_returns) >= 1

    @requires_ts("c")
    def test_c_returns_zero_and_null(self):
        src = """\
int process(const char *input) {
    if (input == NULL) {
        return 0;
    }
    return strlen(input);
}
"""
        result = extract_function_returns("proc.c", src)
        assert result is not None
        assert len(result) >= 1
        zero_returns = [r for r in result[0].returns if r.value_type == "zero"]
        assert len(zero_returns) >= 1

    def test_python_returns_none(self):
        # tree-sitter should work on python too
        result = extract_function_returns("app.py", "def f():\n    return None\n")
        # Python files use ast, so ts_extract returns None or parses with TS
        # Either way, no crash
        assert result is None or isinstance(result, list)

    def test_unsupported_extension(self):
        result = extract_function_returns("file.xyz", "some code")
        assert result is None


class TestFunctionReturnsSentinelAmbiguous:
    """Test the sentinel_ambiguous property."""

    def test_ambiguous_when_error_and_success_overlap(self):
        fr = FunctionReturns(function="f", file="x.go", returns=[
            ReturnInfo(value_type="null", is_error_path=True, line=5),
            ReturnInfo(value_type="null", is_error_path=False, line=10),
        ])
        assert fr.sentinel_ambiguous

    def test_not_ambiguous_when_distinct(self):
        fr = FunctionReturns(function="f", file="x.go", returns=[
            ReturnInfo(value_type="null", is_error_path=True, line=5),
            ReturnInfo(value_type="other", is_error_path=False, line=10),
        ])
        assert not fr.sentinel_ambiguous


# ---------------------------------------------------------------
# 2. Call chain extraction
# ---------------------------------------------------------------


class TestExtractCallChains:
    """extract_call_chains across languages."""

    @requires_ts("go")
    def test_go_reassignment_chain(self):
        src = """\
package main

func sanitize(input string) string {
    val := strings.TrimSpace(input)
    val = strings.ToLower(val)
    val = url.PathEscape(val)
    return val
}
"""
        result = extract_call_chains("clean.go", src)
        assert result is not None
        chains = [c for c in result if c.variable == "val"]
        assert len(chains) >= 1
        chain = chains[0]
        assert len(chain.steps) >= 2
        assert chain.function == "sanitize"

    @requires_ts("javascript")
    def test_js_method_chain(self):
        src = """\
function clean(input) {
    const result = input.trim().toLowerCase().replace(/[^a-z]/g, '');
    return result;
}
"""
        result = extract_call_chains("clean.js", src)
        assert result is not None
        # Should detect the method chain
        method_chains = [c for c in result if len(c.steps) >= 2]
        assert len(method_chains) >= 1

    def test_method_chain_emitted_once(self):
        """Only the maximal chain: every inner call node used to emit
        its own sub-chain (x.a().b() inside x.a().b().c())."""
        src = """\
function clean(input) {
    const result = input.trim().toLowerCase().replace(/[^a-z]/g, '');
    return result;
}
"""
        result = extract_call_chains("clean.js", src)
        assert result is not None
        method_chains = [
            c for c in result
            if c.steps and c.steps[0].call_name.startswith(".")
        ]
        assert len(method_chains) == 1
        assert [s.call_name for s in method_chains[0].steps] == [
            ".trim", ".toLowerCase", ".replace",
        ]
        assert method_chains[0].variable == "input"

    def test_c_field_expression_chain_emitted_once(self):
        # C field_expression chains go through the same maximal-chain
        # gate as the JS member_expression ones.
        src = """\
void process(ctx_t *c) {
    c->reader.open(c)->read(c)->close(c);
}
"""
        result = extract_call_chains("chain.c", src)
        assert result is not None
        method_chains = [
            ch for ch in result
            if ch.steps and ch.steps[0].call_name.startswith(".")
        ]
        assert len(method_chains) <= 1

    @requires_ts("c")
    def test_c_reassignment_chain(self):
        src = """\
char *process(const char *input) {
    char *val = strdup(input);
    val = strip_whitespace(val);
    val = normalize_path(val);
    return val;
}
"""
        result = extract_call_chains("path.c", src)
        assert result is not None
        chains = [c for c in result if c.variable == "val"]
        assert len(chains) >= 1
        assert len(chains[0].steps) >= 2

    @requires_ts("go")
    def test_empty_file(self):
        result = extract_call_chains("empty.go", "package main\n")
        assert result is not None
        assert len(result) == 0


# ---------------------------------------------------------------
# 3. String literal extraction
# ---------------------------------------------------------------


class TestExtractStringLiterals:
    """extract_string_literals across languages."""

    @requires_ts("go")
    def test_go_switch_case_strings(self):
        src = """\
package main

func dispatch(cmd string) {
    switch cmd {
    case "start":
        doStart()
    case "stop":
        doStop()
    case "restart":
        doRestart()
    }
}
"""
        result = extract_string_literals("cmd.go", src)
        assert result is not None
        values = {s.value for s in result}
        assert "start" in values
        assert "stop" in values
        assert "restart" in values
        # Check context for switch_case
        case_strings = [s for s in result if s.context == "switch_case"]
        assert len(case_strings) >= 2

    @requires_ts("javascript")
    def test_js_comparison_strings(self):
        src = """\
function check(status) {
    if (status === "active") {
        return true;
    }
    if (status === "inactive") {
        return false;
    }
}
"""
        result = extract_string_literals("check.js", src)
        assert result is not None
        values = {s.value for s in result}
        assert "active" in values
        assert "inactive" in values

    @requires_ts("java")
    def test_java_dict_key_strings(self):
        src = """\
public class Config {
    public void init() {
        Map<String, Object> map = new HashMap<>();
        map.put("host", "localhost");
        map.put("port", "8080");
    }
}
"""
        result = extract_string_literals("Config.java", src)
        assert result is not None
        values = {s.value for s in result}
        assert "host" in values
        assert "port" in values

    @requires_ts("c")
    def test_c_string_literals(self):
        src = """\
void log_level(const char *level) {
    if (strcmp(level, "error") == 0) {
        do_error();
    } else if (strcmp(level, "warn") == 0) {
        do_warn();
    }
}
"""
        result = extract_string_literals("log.c", src)
        assert result is not None
        values = {s.value for s in result}
        assert "error" in values
        assert "warn" in values

    @requires_ts("javascript")
    def test_template_string_detected(self):
        src = """\
function greet(name) {
    return `Hello, ${name}!`;
}
"""
        result = extract_string_literals("greet.js", src)
        assert result is not None
        templates = [s for s in result if s.is_template]
        assert len(templates) >= 1


# ---------------------------------------------------------------
# 4. Dispatch table extraction
# ---------------------------------------------------------------


class TestExtractDispatchTables:
    """extract_dispatch_tables across languages."""

    @requires_ts("go")
    def test_go_switch(self):
        src = """\
package main

func handle(action string) {
    switch action {
    case "create":
        doCreate()
    case "read":
        doRead()
    case "update":
        doUpdate()
    case "delete":
        doDelete()
    }
}
"""
        result = extract_dispatch_tables("handler.go", src)
        assert result is not None
        assert len(result) >= 1
        dt = result[0]
        assert dt.function == "handle"
        assert "create" in dt.keys
        assert "delete" in dt.keys
        assert len(dt.keys) == 4

    @requires_ts("javascript")
    def test_js_switch(self):
        src = """\
function route(method) {
    switch (method) {
    case "GET":
        handleGet();
        break;
    case "POST":
        handlePost();
        break;
    case "PUT":
        handlePut();
        break;
    }
}
"""
        result = extract_dispatch_tables("route.js", src)
        assert result is not None
        assert len(result) >= 1
        assert "GET" in result[0].keys
        assert "POST" in result[0].keys

    @requires_ts("go")
    def test_single_case_not_dispatch(self):
        src = """\
package main

func f(x string) {
    switch x {
    case "only":
        doOnly()
    }
}
"""
        result = extract_dispatch_tables("single.go", src)
        assert result is not None
        # Only 1 case key — not enough for a dispatch table
        assert len(result) == 0


# ---------------------------------------------------------------
# 5. Loop cap extraction
# ---------------------------------------------------------------


class TestExtractLoopCaps:
    """extract_loop_caps across languages."""

    @requires_ts("c")
    def test_c_loop_with_cap_break(self):
        src = """\
int collect(node_t *root, int max) {
    int count = 0;
    node_t *cur = root;
    while (cur != NULL) {
        if (count >= max)
            break;
        process(cur);
        cur = cur->next;
        count++;
    }
    return count;
}
"""
        result = extract_loop_caps("collect.c", src)
        assert result is not None
        assert len(result) >= 1
        assert result[0].function == "collect"

    @requires_ts("go")
    def test_go_loop_with_len_check(self):
        src = """\
package main

func gather(items []string, limit int) []string {
    var result []string
    for _, item := range items {
        if len(result) >= limit {
            break
        }
        result = append(result, item)
    }
    return result
}
"""
        result = extract_loop_caps("gather.go", src)
        assert result is not None
        assert len(result) >= 1

    @requires_ts("javascript")
    def test_js_loop_with_truncation_signal(self):
        src = """\
function scanPorts(host, max) {
    const results = [];
    for (let port = 1; port <= 65535; port++) {
        if (results.length >= max) {
            console.log("Results truncated");
            break;
        }
        if (isOpen(host, port)) {
            results.push(port);
        }
    }
    return results;
}
"""
        result = extract_loop_caps("scan.js", src)
        assert result is not None
        assert len(result) >= 1
        assert result[0].signals_truncation

    @requires_ts("go")
    def test_loop_without_cap_not_detected(self):
        src = """\
package main

func sum(items []int) int {
    total := 0
    for _, v := range items {
        total += v
    }
    return total
}
"""
        result = extract_loop_caps("sum.go", src)
        assert result is not None
        assert len(result) == 0


# ---------------------------------------------------------------
# 6. Function body extraction
# ---------------------------------------------------------------


class TestExtractFunctionBody:
    """extract_function_body across languages."""

    @requires_ts("go")
    def test_go_function_body(self):
        src = """\
package main

func Greet(name string) string {
    return "Hello, " + name
}

func Farewell(name string) string {
    return "Bye, " + name
}
"""
        body = extract_function_body("greet.go", src, "Greet")
        assert body is not None
        assert "Hello" in body
        assert "Bye" not in body

    @requires_ts("c")
    def test_c_function_body(self):
        src = """\
int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}
"""
        body = extract_function_body("math.c", src, "add")
        assert body is not None
        assert "a + b" in body

    @requires_ts("c")
    def test_missing_function(self):
        src = "int f(int x) { return x; }\n"
        body = extract_function_body("f.c", src, "nonexistent")
        assert body == ""

    def test_unsupported_file(self):
        body = extract_function_body("file.unknown", "code", "f")
        assert body is None


# ---------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------


class TestDataclasses:
    def test_call_step(self):
        cs = CallStep(call_name="strip", line=5, first_arg="x")
        assert cs.call_name == "strip"
        assert cs.first_arg == "x"

    def test_call_chain(self):
        cc = CallChain(
            file="a.go", function="clean", variable="val",
            steps=[
                CallStep(call_name="trim", line=3),
                CallStep(call_name="lower", line=4),
            ],
        )
        assert len(cc.steps) == 2
        assert cc.variable == "val"

    def test_string_literal_site(self):
        s = StringLiteralSite(
            value="hello", function="greet", file="a.js",
            line=5, context="return", is_template=False,
        )
        assert s.value == "hello"
        assert not s.is_template

    def test_dispatch_table(self):
        dt = DispatchTable(
            function="route", file="r.go", line=10,
            keys=["GET", "POST", "PUT"], table_type="switch",
        )
        assert len(dt.keys) == 3

    def test_loop_cap(self):
        lc = LoopCap(function="scan", file="s.c", line=15,
                     signals_truncation=True)
        assert lc.signals_truncation

    def test_return_info(self):
        ri = ReturnInfo(value_type="null", is_error_path=True, line=7)
        assert ri.is_error_path

    def test_function_returns_ambiguous_value(self):
        fr = FunctionReturns(function="f", file="x.go", returns=[
            ReturnInfo(value_type="null", is_error_path=True, line=5),
            ReturnInfo(value_type="null", is_error_path=False, line=10),
        ])
        assert "null" in fr.ambiguous_value


# ---------------------------------------------------------------
# Deep nesting (explicit-stack walker regression)
# ---------------------------------------------------------------


class TestDeepNesting:
    """CST depth tracks source nesting depth — the descendant walker
    must not recurse per level (regression: a 20k-deep parenthesised
    expression raised RecursionError)."""

    def test_string_literal_survives_deep_nesting(self):
        n = 20000
        src = (
            "int f(void) { const char *s = " + "(" * n + '"deep"'
            + ")" * n + "; return 0; }\n"
        )
        lits = extract_string_literals("deep.c", src)
        assert lits is not None
        assert any(lit.value == "deep" for lit in lits)
