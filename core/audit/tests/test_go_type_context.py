"""Go context uses actual receiver declarations and field documentation."""

import pytest

from core.audit.callsite_consistency import parse_source_cached
from core.audit.context import _resolve_types, format_context_for_prompt
from core.audit import go_type_context as types


@pytest.fixture(autouse=True)
def grammar():
    if parse_source_cached("a.go", "package p\ntype Item struct{}\n")[0] is None:
        pytest.skip("requires tree-sitter Go")


def test_receiver_and_field_contract_are_included_in_review(tmp_path):
    source = (
        "package p\n"
        "// Record represents an optional value.\n"
        "type Record struct {\n"
        "    Seen bool // Seen means a nonempty input was supplied, irrespective of conversion success.\n"
        "}\n"
        "func (r *Record) Read(input any) error { r.Seen = true; return convert(input) }\n"
    )
    (tmp_path / "record.go").write_text(source)
    definitions = _resolve_types(tmp_path, "record.go", {"class_name": "Record"}, source.splitlines()[-1])
    assert [d["name"] for d in definitions] == ["Record"]
    assert "irrespective of conversion success" in definitions[0]["source"]
    prompt = format_context_for_prompt({
        "file": "record.go", "function": "Read", "line_start": 6,
        "source": source.splitlines()[-1], "metadata": {}, "callers": [], "callees": [],
        "type_definitions": definitions,
    })
    assert "Record represents an optional value" in prompt
    assert "irrespective of conversion success" in prompt


def test_same_package_sibling_definition_is_used_but_other_packages_are_not(tmp_path):
    (tmp_path / "reader.go").write_text("package p\nfunc (r *Record) Read() {}\n")
    (tmp_path / "a_wrong.go").write_text("package other\ntype Record struct { Wrong int }\n")
    (tmp_path / "b_test.go").write_text("package p\ntype Record struct { TestOnly int }\n")
    (tmp_path / "types.go").write_text("package p\ntype Record struct { Right int }\n")
    definitions = _resolve_types(tmp_path, "reader.go", {"class_name": "Record"}, "func (r *Record) Read() {}")
    assert len(definitions) == 1
    assert definitions[0]["file"] == "types.go"
    assert "Right" in definitions[0]["source"]


def test_imported_type_does_not_bind_to_same_named_local_type(tmp_path):
    (tmp_path / "reader.go").write_text("package p\ntype Record struct { Wrong int }\n")
    assert _resolve_types(tmp_path, "reader.go", {}, "func read(r external.Record) {}") == []


def test_named_alias_includes_its_underlying_declaration(tmp_path):
    (tmp_path / "reader.go").write_text(
        "package p\ntype Handle = Record\n// Record documents its fields.\n"
        "type Record struct { Ready bool // Ready is independent of decoding.\n}\n",
    )
    result = _resolve_types(tmp_path, "reader.go", {"class_name": "Handle"}, "func (h *Handle) Read() {}")
    assert [d["name"] for d in result] == ["Handle", "Record"]


def test_unexported_receiver_and_unicode_comments(tmp_path):
    (tmp_path / "reader.go").write_text("package p\n// Café metadata.\ntype record struct { n int }\n")
    result = _resolve_types(tmp_path, "reader.go", {"class_name": "record"}, "func (r *record) read() {}")
    assert result[0]["line"] == 2
    assert result[0]["name"] == "record"
    assert "Café" in result[0]["source"]


def test_external_symlink_is_not_read(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "reader.go").write_text("package p\nfunc (r *Record) Read() {}\n")
    external = tmp_path / "outside.go"
    external.write_text("package p\ntype Record struct { Outside int }\n")
    (target / "types.go").symlink_to(external)
    assert _resolve_types(target, "reader.go", {"class_name": "Record"}, "func (r *Record) Read() {}") == []


def test_unavailable_grammar_is_conservatively_omitted(tmp_path, monkeypatch):
    import core.audit.callsite_consistency as parser
    monkeypatch.setattr(parser, "parse_source_cached", lambda *args: (None, None))
    assert _resolve_types(tmp_path, "reader.go", {"class_name": "Record"}, "") == []


def test_type_and_source_byte_caps(tmp_path, monkeypatch):
    (tmp_path / "reader.go").write_text("package p\ntype Record struct { n int }\n")
    assert _resolve_types(tmp_path, "reader.go", {"class_name": "Record"}, "", max_types=0) == []
    monkeypatch.setattr(types, "_MAX_FILE_BYTES", 10)
    assert _resolve_types(tmp_path, "reader.go", {"class_name": "Record"}, "") == []


def test_sibling_file_budget_includes_the_anchor(tmp_path, monkeypatch):
    (tmp_path / "reader.go").write_text("package p\nfunc (r *Record) Read() {}\n")
    (tmp_path / "a.go").write_text("package p\ntype Record struct { n int }\n")
    monkeypatch.setattr(types, "_MAX_FILES", 1)
    assert _resolve_types(tmp_path, "reader.go", {"class_name": "Record"}, "") == []


def test_generic_receiver_parameters_are_not_mistaken_for_package_types(tmp_path):
    (tmp_path / "reader.go").write_text(
        "package p\ntype Element struct { Unrelated int }\n"
        "type Bucket[Element any] struct { Size int }\n",
    )
    result = _resolve_types(tmp_path, "reader.go", {"class_name": "Bucket[Element]"},
                            "func (b *Bucket[Element]) Put(v Element) {}")
    assert [d["name"] for d in result] == ["Bucket"]


def test_generic_function_parameter_is_not_a_package_type(tmp_path):
    (tmp_path / "reader.go").write_text("package p\ntype Element struct { Unrelated int }\n")
    assert _resolve_types(tmp_path, "reader.go", {}, "func use[Element any](v Element) {}") == []


def test_large_type_excerpt_is_bounded_and_marks_truncation(tmp_path, monkeypatch):
    (tmp_path / "reader.go").write_text("package p\ntype Record struct {\n" + "Field int\n" * 80 + "}\n")
    monkeypatch.setattr(types, "_MAX_TYPE_CHARS", 100)
    result = _resolve_types(tmp_path, "reader.go", {"class_name": "Record"}, "")
    assert len(result[0]["source"]) <= 100
    assert "truncated" in result[0]["source"]


def test_full_context_keeps_receiver_contract_and_strategy_item_together(tmp_path, monkeypatch):
    from core.audit.context import assemble_context
    import core.audit.strategy as strategy

    source = (
        "package p\n"
        "type InputRecord struct { Seen bool // Seen describes input presence.\n}\n"
        "type CheckedRecord struct { Seen bool // Seen describes processing success.\n}\n"
        "func (r *InputRecord) Decode(v any) error { return consume(v) }\n"
        "func (r *CheckedRecord) Decode(v any) error { return consume(v) }\n"
    )
    (tmp_path / "records.go").write_text(source)
    items = []
    for line, text in enumerate(source.splitlines(), 1):
        if not text.startswith("func"):
            continue
        owner = "InputRecord" if "*InputRecord" in text else "CheckedRecord"
        items.append({
            "name": "Decode", "kind": "function", "line_start": line, "line_end": line,
            "signature": text.split("{")[0],
            "metadata": {"class_name": owner, "parameters": [["r", "*" + owner], ["v", "any"]]},
        })
    inventory = {"files": [{"path": "records.go", "language": "go", "items": items}]}
    selected = []

    def capture(item, *args, **kwargs):
        selected.append(item["metadata"]["class_name"])
        return []

    monkeypatch.setattr(strategy, "strategies_from_item", capture)
    for item in reversed(items):
        owner = item["metadata"]["class_name"]
        context = assemble_context(
            target_path=tmp_path, file_path="records.go", function_name="Decode",
            line_start=item["line_start"], line_end=item["line_end"],
            checklist=inventory, inventory=inventory,
        )
        assert context["metadata"]["class_name"] == owner
        assert [d["name"] for d in context["type_definitions"]] == [owner]
        contract = context["type_definitions"][0]["source"]
        assert ("input presence" in contract) == (owner == "InputRecord")
        assert ("processing success" in contract) == (owner == "CheckedRecord")
        assert selected[-1] == owner
