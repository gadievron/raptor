"""Tests for condition_binding — guard–variable binding analysis."""


from core.audit.condition_binding import (
    check_all_bindings,
    check_guard_binding,
    extract_field_accesses,
    extract_identifiers,
    extract_sink_arg_identifiers,
)
from core.audit.condition_extraction import GuardCondition, SinkGuard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guard(text: str, category: str) -> GuardCondition:
    return GuardCondition(text=text, category=category, polarity="required", line=1)


def _sg(
    source_lines: list,
    sink_line: int,
    sink_api: str,
    guards: list,
    func: str = "process",
) -> tuple:
    source = "\n".join(source_lines)
    sg = SinkGuard(
        sink_file="test.c",
        sink_line=sink_line,
        sink_function=func,
        sink_api=sink_api,
        guards=guards,
        unconditional=(len(guards) == 0),
    )
    return source, sg


# ---------------------------------------------------------------------------
# Identifier extraction tests
# ---------------------------------------------------------------------------


class TestExtractIdentifiers:
    def test_simple_variable(self):
        ids = extract_identifiers("len < sizeof(buf)")
        assert "len" in ids
        assert "buf" in ids
        assert "sizeof" not in ids

    def test_excludes_keywords(self):
        ids = extract_identifiers("if (ptr != NULL)")
        assert "ptr" in ids
        assert "NULL" not in ids
        assert "if" not in ids

    def test_field_access(self):
        ids = extract_identifiers("ctx.user.is_admin")
        assert "ctx" in ids
        assert "user" in ids
        assert "is_admin" in ids

    def test_numeric_not_matched(self):
        ids = extract_identifiers("x > 1024")
        assert "x" in ids
        assert "1024" not in ids

    def test_empty_string(self):
        assert extract_identifiers("") == frozenset()


class TestExtractFieldAccesses:
    def test_dot_access(self):
        fields = extract_field_accesses("ctx.user")
        assert "ctx" in fields
        assert "ctx.user" in fields

    def test_arrow_access(self):
        fields = extract_field_accesses("ptr->len")
        assert "ptr" in fields
        assert "ptr.len" in fields

    def test_no_field_access(self):
        fields = extract_field_accesses("x + y")
        assert fields == frozenset()


class TestExtractSinkArgIdentifiers:
    def test_simple_call(self):
        source = "void f() {\n    memcpy(dst, src, len);\n}"
        ids = extract_sink_arg_identifiers(source, 2, "memcpy")
        assert "dst" in ids
        assert "src" in ids
        assert "len" in ids

    def test_field_in_args(self):
        source = "void f() {\n    memcpy(buf->data, src, ctx->len);\n}"
        ids = extract_sink_arg_identifiers(source, 2, "memcpy")
        assert "buf" in ids
        assert "ctx" in ids
        assert "buf.data" in ids

    def test_dotted_api(self):
        source = "def f():\n    subprocess.call(cmd)\n"
        ids = extract_sink_arg_identifiers(source, 2, "subprocess.call")
        assert "cmd" in ids

    def test_invalid_line(self):
        source = "x = 1"
        ids = extract_sink_arg_identifiers(source, 99, "foo")
        assert ids == frozenset()

    def test_multiline_call(self):
        source = "void f() {\n    memcpy(\n        dst,\n        src,\n        len\n    );\n}"
        ids = extract_sink_arg_identifiers(source, 2, "memcpy")
        assert "dst" in ids
        assert "src" in ids
        assert "len" in ids


# ---------------------------------------------------------------------------
# Binding analysis tests
# ---------------------------------------------------------------------------


class TestCheckGuardBinding:
    def test_bound_guard(self):
        source = "void f() {\n    if (len < sizeof(buf))\n        memcpy(dst, src, len);\n}"
        sg = SinkGuard(
            sink_file="test.c", sink_line=3, sink_function="f",
            sink_api="memcpy",
            guards=[_guard("len < sizeof(buf)", "bounds")],
            unconditional=False,
        )
        result = check_guard_binding(source, sg)
        assert result.has_any_bound_guard
        assert not result.all_guards_decorative
        assert result.binding_results[0].is_bound
        assert "len" in result.binding_results[0].bound_identifiers

    def test_decorative_guard(self):
        source = "void f() {\n    if (debug_mode)\n        memcpy(dst, src, len);\n}"
        sg = SinkGuard(
            sink_file="test.c", sink_line=3, sink_function="f",
            sink_api="memcpy",
            guards=[_guard("debug_mode", "config")],
            unconditional=False,
        )
        result = check_guard_binding(source, sg)
        # config is "always relevant"
        assert result.has_any_bound_guard

    def test_truly_decorative_bounds(self):
        source = "void f() {\n    if (count > 0)\n        memcpy(dst, src, len);\n}"
        sg = SinkGuard(
            sink_file="test.c", sink_line=3, sink_function="f",
            sink_api="memcpy",
            guards=[_guard("count > 0", "bounds")],
            unconditional=False,
        )
        result = check_guard_binding(source, sg)
        # "count" is not in memcpy args (dst, src, len)
        assert not result.binding_results[0].is_bound
        assert result.all_guards_decorative

    def test_auth_always_relevant(self):
        source = "void f() {\n    if (is_admin)\n        system(cmd);\n}"
        sg = SinkGuard(
            sink_file="test.c", sink_line=3, sink_function="f",
            sink_api="system",
            guards=[_guard("is_admin", "auth")],
            unconditional=False,
        )
        result = check_guard_binding(source, sg)
        assert result.has_any_bound_guard
        assert result.binding_results[0].is_bound

    def test_multiple_guards_mixed(self):
        source = "void f() {\n    if (is_admin && len < MAX)\n        memcpy(dst, src, len);\n}"
        sg = SinkGuard(
            sink_file="test.c", sink_line=3, sink_function="f",
            sink_api="memcpy",
            guards=[
                _guard("is_admin", "auth"),
                _guard("len < MAX", "bounds"),
            ],
            unconditional=False,
        )
        result = check_guard_binding(source, sg)
        assert result.has_any_bound_guard
        # bounds guard references "len" which is in memcpy args
        bounds_result = result.binding_results[1]
        assert bounds_result.is_bound

    def test_to_dict(self):
        source = "void f() {\n    if (len < 100)\n        memcpy(dst, src, len);\n}"
        sg = SinkGuard(
            sink_file="test.c", sink_line=3, sink_function="f",
            sink_api="memcpy",
            guards=[_guard("len < 100", "bounds")],
            unconditional=False,
        )
        result = check_guard_binding(source, sg)
        d = result.to_dict()
        assert d["sink_api"] == "memcpy"
        assert d["has_any_bound_guard"] is True


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------


class TestCheckAllBindings:
    def test_batch(self):
        source = "void f() {\n    if (len < 100)\n        memcpy(dst, src, len);\n    strcpy(out, input);\n}"
        guards = [
            SinkGuard(
                sink_file="test.c", sink_line=3, sink_function="f",
                sink_api="memcpy",
                guards=[_guard("len < 100", "bounds")],
                unconditional=False,
            ),
            SinkGuard(
                sink_file="test.c", sink_line=4, sink_function="f",
                sink_api="strcpy",
                guards=[],
                unconditional=True,
            ),
        ]
        results = check_all_bindings(source, guards)
        assert len(results) == 2
        assert results[0].has_any_bound_guard
        assert not results[1].has_any_bound_guard
