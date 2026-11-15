"""Owned embedded reports retain full spans through parsing and deduplication."""
import ast
from contextlib import redirect_stdout
import io
from itertools import islice
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from packages.coccinelle.runner import _dedup_matches, _parse_results

_RULES = Path(__file__).resolve().parents[1] / "rules"
_SCRIPTS = [
    ("is_err_not_ptr_err", 0), ("is_err_not_ptr_err", 1),
    ("is_err_not_ptr_err", 2), ("double_byteswap", 0),
    ("sensitive_data_leak", 0),
    ("division_by_zero", 0), ("division_by_zero", 1),
    ("double_sizeof", 0), ("double_sizeof", 1), ("sizeof_container_of", 0),
    ("double_close", 0),
    ("double_close", 1),
    ("double_close", 2),
    ("double_close", 3),
    ("double_close", 4),
    ("double_close", 5),
    ("fdopendir_double_close", 0),
    ("fdopendir_double_close", 1),
    ("fdopendir_double_close", 2),
    ("fdopendir_double_close", 3),
    ("chroot_no_chdir", 0), ("dead_memset_free", 0),
    ("copy_user_size_mismatch", 0), ("copy_user_size_mismatch", 1),
    ("copy_user_size_mismatch", 2),
    ("fcntl_flag_domain", 0), ("free_stack_array", 0),
    ("sizeof_array_param", 0), ("sizeof_array_param", 1),
    ("malloc_strlen_strcpy", 0), ("malloc_strlen_strcpy", 1),
    ("free_nonbase_ptr", 0), ("free_nonbase_ptr", 1),
    ("use_after_close", 0),
    ("use_after_close", 1),
    ("use_after_close", 2),
    ("use_after_fclose", 0),
    ("use_after_fclose", 1),
    ("use_after_fclose", 2),
    ("snprintf_truncation_boundary", 0), ("snprintf_truncation_boundary", 1),
    ("snprintf_advance", 0), ("snprintf_advance", 1), ("snprintf_advance", 2),
    ("strncpy_no_nul", 0), ("strncpy_no_nul", 1),
    ("popen_fclose", 0),
    ("popen_fclose", 1),
    ("popen_fclose", 2),
    ("popen_fclose", 3),
    ("popen_fclose", 4),
    ("open_creat_no_mode", 0),
    ("gfp_kernel_under_spinlock", 0),
    ("sign_extension_widen", 0),
    ("sign_extension_widen", 1),
    ("sign_extension_widen", 2),
    ("sign_extension_widen", 3),
    ("signal_handler_unsafe", 0),
    ("signal_handler_unsafe", 1),
    ("signal_handler_unsafe", 2),
    ("signal_sigkill_sigstop", 0),
    ("signal_sigkill_sigstop", 1),
    ("signal_sigkill_sigstop", 2),
    ("signal_sigkill_sigstop", 3),
    ("sleep_under_spinlock", 0),
    ("stack_addr_escape", 0),
    ("stack_addr_escape", 1),
    ("unchecked_strtol", 0),
    ("unchecked_strtol", 1),
    ("va_arg_mismatch", 0),
    ("va_arg_mismatch", 1),
    ("va_arg_mismatch", 2),
    ("va_arg_mismatch", 3),
    ("inet_ntoa_double_call", 0), ("kfree_not_rcu", 0),
    ("toctou_stat_open", 0),
    ("socket_no_cloexec", 0), ("socket_no_cloexec", 1),
    ("rcu_no_lock", 0),
    ("rcu_dereference_outside_rcu", 0), ("rcu_dereference_outside_rcu", 1),
]


def _python_statements(script):
    lines = script.splitlines()
    # SmPL separator comments may follow a Python reporting block.
    while lines and (not lines[-1].strip() or lines[-1].lstrip().startswith("//")):
        lines.pop()
    return "\n".join(lines)


def _report(name, index, position, **bindings):
    rule = _RULES / f"{name}.cocci"
    scripts = re.findall(
        r"@script:python[^\n]*\n.*?\n@@\n(.*?)(?=\n@|\Z)", rule.read_text(), re.S,
    )
    tree = ast.parse(_python_statements(scripts[index]))
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    output = io.StringIO()
    namespace = {"json": json, "islice": islice, "p_use": [position], "p_copy": [SimpleNamespace(file="owned.c", line=1, column=1, line_end=1, column_end=8)], "fmt": '"%s"', "count": "8", "before": (), "after": (), "dst": "owned", "sys": SimpleNamespace(stderr=output, stdout=output), "buf": "owned", "n": "count", "ast": ast, "re": re, "ARR": "buffer", "offset": "1", "COMMAND": "F_SETFD", "FLAGS": "O_NONBLOCK", "p": [position], "p_call": [position], "unsafe_fn": "printf", "p1": [position], "p2": [position], "fn": "consume", "E": "owned_pointer", "PARAM": "count", "TD": "struct payload", "TL": "int", "T": "char", "LOCAL": "owned", "swap1": "htons", "swap2": "ntohs", "V": "secret"}
    namespace.update(bindings)
    with redirect_stdout(output):
        exec(compile(tree, str(rule), "exec"), namespace)
    return output.getvalue()


@pytest.mark.parametrize("name,index", _SCRIPTS, ids=[f"{name}-{index}" for name, index in _SCRIPTS])
def test_report_spans_survive_parser_and_deduplication(name, index):
    first = SimpleNamespace(file="owned.c", line="4", column="2", line_end="5", column_end="18")
    second = SimpleNamespace(file="owned.c", line="4", column="2", line_end="6", column_end="23")
    bindings = {"FLAGS": "O_CREAT"} if name == "open_creat_no_mode" else {}
    if name == "socket_no_cloexec":
        bindings["TYPE"] = "SOCK_STREAM"
    if name in {"kfree_not_rcu", "toctou_stat_open"}:
        bindings["p1"] = [SimpleNamespace(file="owned.c", line=1, column=7, line_end=1, column_end=15)]
    first_output = _report(name, index, first, **bindings)
    second_output = _report(name, index, second, **bindings)
    # Plain-prefix parsing is an owned transport control, not a nonce-authentication test.
    matches = _parse_results(first_output + second_output + first_output, name)
    assert len(matches) == 3
    rows = _dedup_matches(matches)
    assert len(rows) == 2
    assert [(row.file, row.line, row.column, row.line_end, row.column_end) for row in rows] == [
        ("owned.c", 4, 2, 5, 18), ("owned.c", 4, 2, 6, 23),
    ]
    expected_rule = {
        ("division_by_zero", 0): "division_by_zero_param",
        ("division_by_zero", 1): "modulo_by_zero_param",
        ("double_sizeof", 1): "pointer_scaling_double",
        ("double_close", 3): "double_fclose",
        ("double_close", 4): "double_fclose",
        ("double_close", 5): "double_fclose",
        ("copy_user_size_mismatch", 1): "copy_from_user_sizeof_ptr",
        ("copy_user_size_mismatch", 2): "copy_from_user_sizeof_ptr",
        ("sizeof_array_param", 1): "sizeof_array_param_unsized",
        ("free_nonbase_ptr", 1): "free_nonbase_ptr_inc",
        ("socket_no_cloexec", 1): "accept_no_cloexec",
        ("sign_extension_widen", 0): "sign_extension_char",
        ("sign_extension_widen", 1): "sign_extension_char",
        ("sign_extension_widen", 2): "sign_extension_short",
        ("sign_extension_widen", 3): "sign_extension_short",
        ("stack_addr_escape", 1): "stack_addr_escape_outparam",
        ("unchecked_strtol", 1): "strtol_null_endptr",
        ("va_arg_mismatch", 0): "va_arg_promoted_type",
        ("va_arg_mismatch", 1): "va_arg_promoted_type_short",
        ("va_arg_mismatch", 2): "va_arg_promoted_type_float",
        ("va_arg_mismatch", 3): "va_arg_promoted_type_bool",
    }.get((name, index), name)
    assert all(row.rule == expected_rule and row.message for row in rows)
    assert rows[0].message == rows[1].message


@pytest.mark.parametrize("bindings", [
    {"swap1": "htons", "swap2": "htole16"},
    {"swap1": "htons", "swap2": "htonl"},
], ids=["different-family", "different-width"])
def test_conversion_filter_stays_quiet(bindings):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("double_byteswap", 0, position, **bindings) == ""


def test_benign_sensitive_name_stays_quiet():
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("sensitive_data_leak", 0, position, V="usb_keyboard") == ""


def test_script_extraction_preserves_python_strings_and_floor_division():
    script = 'text = """first\n// inside Python string\nlast"""\nvalue = 7 // 2\n\n// SmPL separator\n'
    namespace = {}
    exec(compile(_python_statements(script), "owned-script", "exec"), namespace)
    assert namespace["text"] == "first\n// inside Python string\nlast"
    assert namespace["value"] == 3


@pytest.mark.parametrize("index,bindings", [
    (0, {"TD": "const unsigned int", "TL": "signed int"}),
    (2, {"T": "char", "TL": "char *"}),
], ids=["equivalent-scalar-width", "same-pointer-destination"])
def test_usercopy_type_filters_stay_quiet(index, bindings):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("copy_user_size_mismatch", index, position, **bindings) == ""


@pytest.mark.parametrize("command,flags", [
    ("F_SETFL", "O_NONBLOCK"), ("F_SETFD", "FD_CLOEXEC"),
], ids=["status-flags", "descriptor-flags"])
def test_correct_fcntl_domain_stays_quiet(command, flags):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("fcntl_flag_domain", 0, position, COMMAND=command, FLAGS=flags) == ""


@pytest.mark.parametrize("offset", ["(unsigned long)0UL", "(int)(-0)"],
                         ids=["cast-zero", "signed-zero"])
def test_zero_pointer_offset_stays_quiet(offset):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("free_nonbase_ptr", 0, position, offset=offset) == ""


@pytest.mark.parametrize("bindings", [
    {"fmt": '"%.4s"'}, {"fmt": '"%p"'},
    {"fmt": '"%.*s"', "before": ("4",)},
], ids=["bounded-string", "pointer-value", "bounded-star-string"])
def test_strncpy_format_filters_stay_quiet(bindings):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("strncpy_no_nul", 1, position, **bindings) == ""


def test_unknown_strncpy_format_remains_candidate():
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    rows = _parse_results(_report("strncpy_no_nul", 1, position, fmt="FMT"), "strncpy_no_nul")
    assert len(rows) == 1
    assert (rows[0].line_end, rows[0].column_end) == (5, 18)
    assert "unknown format" in rows[0].message


@pytest.mark.parametrize("flags", ["0x40", "O_CREAT & 0", "flags()"],
                         ids=["numeric-only", "masked-out", "unsupported-call"])
def test_open_mode_flag_filters_stay_quiet(flags):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("open_creat_no_mode", 0, position, FLAGS=flags) == ""


@pytest.mark.parametrize("flags", ["SOCK_CLOEXEC", "SOCK_STREAM | SOCK_CLOEXEC"],
                         ids=["exact-flag", "or-flag"])
def test_socket_cloexec_flags_stay_quiet(flags):
    position = SimpleNamespace(file="owned.c", line=4, column=2, line_end=5, column_end=18)
    assert _report("socket_no_cloexec", 0, position, TYPE=flags) == ""
