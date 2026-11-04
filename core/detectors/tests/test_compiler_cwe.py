"""Reporting classifications must not depend on family/taxonomy ordering."""
import json

import pytest

from core.detectors.compiler_families import compiler_reported_cwe, diagnostic_cwe, compiler_applicable


@pytest.mark.parametrize("message, expected", [
    ("Potential leak of memory pointed to by 'p'", "CWE-401"),
    ("Use of memory after it is freed", "CWE-416"),
    ("Attempt to free released memory", "CWE-415"),
    ("unknown allocation issue", None),
    ("use-after-free followed by a leak", None),
    ("", None),
])
def test_shared_clang_checker_needs_unambiguous_message(message, expected):
    assert diagnostic_cwe("unix.Malloc", message) == expected


def test_call_checker_is_not_always_null_dereference():
    assert diagnostic_cwe("core.CallAndMessage", "Called function pointer is null") == "CWE-476"
    assert diagnostic_cwe("core.CallAndMessage", "1st argument is an uninitialized value") is None


@pytest.mark.parametrize("rule, expected", [
    ("-Wanalyzer-infinite-loop", "CWE-835"),
    ("-Wloop-analysis", "CWE-834"),
    ("-Wanalyzer-out-of-bounds", "CWE-119"),
    ("-Wstringop-overread", "CWE-125"),
    ("-Wstringop-overflow=2", "CWE-120"),
])
def test_fallback_does_not_choose_first_family_alias(rule, expected):
    assert diagnostic_cwe(rule) == expected


@pytest.mark.parametrize("invalid", [True, False, 0, -1, 12.5, "not a CWE", "CWE-0", "CWE-１２５", [], {}, "1" * 100])
def test_bad_native_classification_cannot_override_known_family(invalid):
    assert diagnostic_cwe("-Wanalyzer-use-after-free", reported=invalid) == "CWE-416"


def test_native_classification_and_new_reported_families():
    assert diagnostic_cwe("-Wanalyzer-out-of-bounds", reported="CWE-00126") == "CWE-126"
    assert compiler_applicable("CWE-119") and compiler_applicable("CWE-126")


def test_both_gcc_metadata_formats_and_indexed_taxonomy():
    assert compiler_reported_cwe({"metadata": {"cwe": 126}}) == "CWE-126"
    assert compiler_reported_cwe({"taxa": [{"id": "126", "toolComponent": {"name": "cwe"}}]}) == "CWE-126"
    run = {"taxonomies": [{"name": "CWE", "taxa": [{"id": "126"}]}]}
    assert compiler_reported_cwe({"taxa": [{"index": 0, "toolComponent": {"index": 0}}]}, run) == "CWE-126"
    assert compiler_reported_cwe({"taxa": [{"id": "126", "toolComponent": {"name": "other"}}]}) is None


def test_multiple_cwes_are_not_decided_by_taxonomy_order():
    taxa = [{"id": value, "toolComponent": {"name": "cwe"}} for value in ("125", "787")]
    assert compiler_reported_cwe({"taxa": taxa}) is None
    assert compiler_reported_cwe({"taxa": list(reversed(taxa))}) is None


def test_native_classification_survives_both_compiler_parsers(tmp_path):
    from core.audit.compiler_sweep import _parse_gcc_json, _parse_gcc_sarif
    legacy = {"option": "-Wanalyzer-out-of-bounds", "kind": "warning", "message": "read",
              "locations": [{"caret": {"file": "a.c", "line": 1}}], "metadata": {"cwe": 126}}
    assert _parse_gcc_json(json.dumps([legacy]))[0]["cwe"] == "CWE-126"
    modern = {"ruleId": "-Wanalyzer-out-of-bounds", "message": {"text": "read"},
              "taxa": [{"id": "126", "toolComponent": {"name": "cwe"}}]}
    path = tmp_path / "gcc.sarif"
    path.write_text(json.dumps({"runs": [{"results": [modern]}]}))
    assert _parse_gcc_sarif(path)[0]["cwe"] == "CWE-126"


def test_conflicting_taxonomy_name_and_index_are_not_trusted():
    run = {"taxonomies": [{"name": "other", "taxa": [{"id": "126"}]}]}
    assert compiler_reported_cwe({"taxa": [{"id": "126", "toolComponent": {"name": "CWE", "index": 0}}]}, run) is None


def test_cpp_new_delete_leak_has_its_own_supported_checker():
    assert diagnostic_cwe("cplusplus.NewDeleteLeaks", "Potential leak of memory pointed to by 'p'") == "CWE-401"
