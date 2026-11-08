"""API scan preparation preserves physical LF coordinates and adapter order."""

import sys
import builtins
from types import SimpleNamespace
from contextlib import contextmanager

import pytest

from core.audit import api_boundary as api
from core.source.lines import split_lines
from core.testing.module_views import module_function_view


@contextmanager
def scan_splits():
    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    calls = []

    def observe(frame, event, arg):
        if (event == "call" and frame.f_code is split_lines.__code__
                and frame.f_back is not None
                and frame.f_back.f_code is api._scan_file_for_calls.__code__):
            calls.append(frame.f_locals["text"])

    try:
        sys.setprofile(observe)
        yield calls
    finally:
        sys.setprofile(None)


def write_source(tmp_path, source):
    path = tmp_path / "source.c"
    path.write_bytes(source.encode())
    return path


@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
@pytest.mark.parametrize("padding", [0, 2000])
def test_native_call_offsets_match_lf_reference(tmp_path, newline, padding):
    source = ("// padding\n" * padding + "void caller(void) {\n"
              "    before(); reviewed(\n        7, 8\n    ); after();\n}\n")
    path = write_source(tmp_path, source)
    expected = api._scan_file_for_calls(path, "source.c", "reviewed")
    path.write_bytes(source.replace("\n", newline).encode())
    actual = api._scan_file_for_calls(path, "source.c", "reviewed")
    assert actual == expected
    assert actual[0][0]["line"] == padding + 2
    assert actual[0][0]["args"] == ["7", "8"]
    assert "after()" in actual[0][0]["after_window"]
    assert "before()" in actual[0][0]["before_body"]
    assert "reviewed(" not in actual[0][0]["before_body"]


@pytest.mark.parametrize("skip", [False, True])
def test_bare_cr_comment_preserves_call_line_and_defining_span(tmp_path, skip):
    source = "/*" + "\r " * 30 + "*/\nvoid caller(void) {\n    reviewed(1);\n}\n"
    path = write_source(tmp_path, source)
    sites, report = api._scan_file_for_calls(path, "source.c", "reviewed", skip_span=(2, 4) if skip else None)
    assert [(site["line"], site["code"]) for site in sites] == ([] if skip else [(3, "reviewed(1);")])
    assert report["span_capped"] is False


@pytest.mark.parametrize("tail", [
    pytest.param("", id="empty"), pytest.param("\n", id="lf"), pytest.param("\r", id="cr"),
    pytest.param("\r\n", id="crlf"), pytest.param("\n\r", id="cr-tail"),
    pytest.param("\n\n", id="blank"), pytest.param("a\r\r\n", id="double-cr"),
])
@pytest.mark.parametrize("compact", [False, True], ids=["list", "compact"])
def test_offset_index_has_exactly_one_entry_per_canonical_row(tail, compact):
    source = "alpha\r\nbeta\v\u2028\r\n" + tail
    rows = split_lines(source)
    starts = api._source_line_starts(source, len(rows), compact=compact)
    assert len(starts) == len(rows)
    for line, start in enumerate(starts, 1):
        assert source.count("\n", 0, start) + 1 == line
        assert start == 0 or source[start - 1] == "\n"


@pytest.mark.parametrize("kind,expected_splits", [("comment", 0), ("definition", 1), ("call", 2), ("capped", 0)])
def test_large_native_sources_only_prepare_needed_line_lists(tmp_path, kind, expected_splits):
    source = "// padding\n" * 2000
    source += {"comment": "// reviewed(1)\n", "definition": "void reviewed(void) {}\n",
               "call": "void caller(void) { reviewed(1); }\n", "capped": "reviewed(1);\n"}[kind]
    path = write_source(tmp_path, source)
    with scan_splits() as calls:
        sites, report = api._scan_file_for_calls(path, "source.c", "reviewed", max_sites=0 if kind == "capped" else 10)
    assert len(calls) == expected_splits
    assert len(sites) == (1 if kind == "call" else 0)
    if kind == "definition":
        assert report["definitions"] == [2001]
    if kind == "capped":
        assert report["site_capped"] is True


def test_splitter_snapshot_survives_later_classifier_callback(tmp_path):
    source = "// padding\n" * 2000 + "void caller(void) { reviewed(1); }\n"
    path = write_source(tmp_path, source)
    unwanted = []

    def split(text):
        unwanted.append(text)
        return ["wrong"]

    def classify(*args):
        vars(view)["split_lines"] = split
        return False

    view = module_function_view(api, bindings={"_looks_like_decl_or_def": classify})
    sites, _ = view._scan_file_for_calls(path, "source.c", "reviewed")
    assert sites[0]["code"] == "void caller(void) { reviewed(1); }"
    assert unwanted == []


def test_adapter_split_callback_can_replace_the_next_splitter(tmp_path):
    path = write_source(tmp_path, "reviewed(1);\n")
    seen = []

    def second(text):
        seen.append("view")
        return ["reviewed(1);"]

    def first(text):
        seen.append("raw")
        vars(view)["split_lines"] = second
        return ["adapter code"]

    view = module_function_view(api, bindings={"split_lines": first})
    sites, _ = view._scan_file_for_calls(path, "source.c", "reviewed")
    assert seen == ["raw", "view"]
    assert sites[0]["code"] == "adapter code"


@pytest.mark.parametrize("excluded", [0, 2])
def test_address_scan_streams_only_through_receipt_cap(tmp_path, excluded):
    path = write_source(tmp_path, "void *p = reviewed;\n" * 1000)
    seen = []
    original = api.iter_source_lines

    def rows(text):
        for line in original(text):
            seen.append(line)
            yield line

    view = module_function_view(api, bindings={"iter_source_lines": rows})
    receipts, capped, size_skipped = view.address_taken_occurrences(
        tmp_path, "reviewed", def_file=path.name, def_span=(1, excluded) if excluded else None,
    )
    assert receipts == [f"source.c:{i}" for i in range(excluded + 1, excluded + 6)]
    assert len(seen) == excluded + 5
    assert capped is False and size_skipped == 0


def test_address_receipts_preserve_lf_coordinates_across_bare_cr(tmp_path):
    write_source(tmp_path, "/*" + "\r " * 30 + "*/\nvoid *p = reviewed;\n")
    receipts, capped, size_skipped = api.address_taken_occurrences(tmp_path, "reviewed")
    assert receipts == ["source.c:2"]
    assert capped is False and size_skipped == 0


def test_oversize_and_site_refusal_flags_are_preserved(tmp_path):
    path = write_source(tmp_path, "reviewed(1);\r\n" + "x" * 100)
    view = module_function_view(api, bindings={"_MAX_FILE_BYTES": 30})
    sites, report = view._scan_file_for_calls(path, "source.c", "reviewed")
    assert sites == [] and report["size_skipped"] is True
    receipts, capped, size_skipped = view.address_taken_occurrences(tmp_path, "reviewed")
    assert receipts == [] and capped is False and size_skipped == 1


def test_raw_crlf_characters_count_against_the_read_cap(tmp_path):
    # Keep the same numeric cap on the raw decoded source, before newline
    # translation: an over-cap file must remain an explicit refusal.
    path = write_source(tmp_path, "reviewed(1);\r\n" + "\r\n" * 10)
    assert len(path.read_bytes()) > 30
    view = module_function_view(api, bindings={"_MAX_FILE_BYTES": 30})
    sites, report = view._scan_file_for_calls(path, "source.c", "reviewed")
    assert sites == []
    assert report["size_skipped"] is True


def test_replaced_context_provider_keeps_original_call_signature(tmp_path):
    path = write_source(tmp_path, "void owner(void) { reviewed(1); }\n")
    seen = []

    def regions(*args):
        seen.append(len(args))
        return {"after_window": "adapter", "before_body": "custom"}

    view = module_function_view(api, bindings={"_site_regions": regions})
    sites, _ = view._scan_file_for_calls(path, "source.c", "reviewed")
    assert seen == [7]
    assert sites[0]["before_body"] == "custom"


@pytest.mark.parametrize("body", [
    pytest.param("reviewed(nested(\n  /* note */ 7,\n  8)); after();", id="nested"),
    pytest.param("reviewed(\n  /* note\n   continued */ 7\n); after();", id="block-comment"),
    pytest.param("// continued \\\n reviewed(99);\n reviewed(7); after();", id="line-splice"),
])
def test_crlf_context_and_arguments_match_lf_source(tmp_path, body):
    source = "// padding\n" * 2000 + "void owner(void) {\n" + body + "\n}\n"
    path = write_source(tmp_path, source)
    expected = api._scan_file_for_calls(path, "source.c", "reviewed")
    path.write_bytes(source.replace("\n", "\r\n").encode())
    assert api._scan_file_for_calls(path, "source.c", "reviewed") == expected


@pytest.mark.parametrize("source", ["", "alpha", "alpha\n", "alpha\n\n", "alpha\nbeta\n"],
                         ids=["empty", "single", "trailing-lf", "blank", "two-lines"])
@pytest.mark.parametrize("compact", [False, True], ids=["list", "compact"])
def test_prepared_lf_index_matches_raw_offset_index(source, compact):
    rows = split_lines(source)
    expected = api._source_line_starts(source, len(rows), compact=compact)
    actual = api._source_line_starts(source, len(rows), compact=compact, prepared_rows=rows)
    assert list(actual) == list(expected)


def test_custom_argument_provider_keeps_its_payload(tmp_path):
    path = write_source(tmp_path, "reviewed(\r\n1\r\n);\r\n")

    def balanced(text, opening):
        return "adapter\r\npayload", text.index(")", opening) + 1

    view = module_function_view(api, bindings={"_balanced_span": balanced})
    sites, _ = view._scan_file_for_calls(path, "source.c", "reviewed")
    assert sites[0]["args"] == ["adapter\r\npayload"]


def test_custom_sanitizer_keeps_its_own_line_view(tmp_path):
    source = "\r\nreviewed(1);\r\n"
    path = write_source(tmp_path, source)

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "source_view" and level == 1:
            return SimpleNamespace(sanitized_view=lambda *args: source.replace("\r", "\n"))
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(api, import_hook=import_local)
    sites, _ = view._scan_file_for_calls(path, "source.c", "reviewed")
    assert sites[0]["line"] == 3
