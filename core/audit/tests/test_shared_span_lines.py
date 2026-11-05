"""Consumers reuse canonical lines without changing span attribution."""
from pathlib import Path

import pytest

from core.audit import protocol_state, release_order, resource_bounds
from core.source import split_lines


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r\r\n"], ids=["lf", "crlf", "double-cr"])
def test_protocol_index_splits_native_source_once(monkeypatch, newline):
    source = newline.join(["void work(struct state *st)", "{",
                           "    st->field = 1;", "    use(st->field);", "}", ""])
    calls = []

    def counted(text):
        calls.append(text)
        return split_lines(text)

    monkeypatch.setattr(protocol_state, "split_lines", counted)
    monkeypatch.setattr(resource_bounds, "split_lines", counted)
    result = protocol_state.build_state_field_index({"a.c": source})
    assert len(calls) == 1
    field = result["fields"]["field"]
    assert [(r["line"], r["function"]) for r in field["writes"]] == [(3, "work")]
    assert [(r["line"], r["function"]) for r in field["reads"]] == [(4, "work")]


def test_release_candidate_scan_splits_source_once(monkeypatch, tmp_path: Path):
    # Calls outside a function exercise the admitted file without adjudication.
    source = "EVP_DecryptFinal_ex(ctx);\nwrite(fd, data, size);\n"
    calls = []

    def counted(text):
        calls.append(text)
        return split_lines(text)

    monkeypatch.setattr(release_order, "split_lines", counted)
    monkeypatch.setattr(resource_bounds, "split_lines", counted)
    result = release_order.run_release_order_prepass({"a.c": source}, target_path=tmp_path)
    assert len(calls) == 1
    assert result["telemetry"]["candidates"] == 0


def test_protocol_subclass_keeps_original_split_order(monkeypatch):
    class Source(str):
        pass

    source = Source("void work(void)\n{\n obj->field = 1;\n}\n")
    calls = []

    def protocol_split(text):
        calls.append("scan")
        return split_lines(text)

    def span_split(text):
        calls.append("spans")
        return split_lines(text)

    monkeypatch.setattr(protocol_state, "split_lines", protocol_split)
    monkeypatch.setattr(resource_bounds, "split_lines", span_split)
    index = protocol_state.build_state_field_index({"a.c": source})
    assert calls == ["spans", "scan"]
    assert index["fields"]["field"]["writes"][0]["function"] == "work"
