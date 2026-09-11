"""Tests for packages.ghidra.diff — cross-version comparison."""

from __future__ import annotations

import json

from packages.ghidra.diff import diff_databases, FunctionChange
from packages.ghidra.model import (
    REComment,
    REDatabase,
    REFunction,
)


def _make_db(
    functions=None,
    comments=None,
    imports=None,
    program_name="test",
) -> REDatabase:
    return REDatabase(
        source_tool="ghidra",
        functions=functions or [],
        comments=comments or [],
        imports=imports or [],
        metadata={"program_name": program_name},
    )


def _make_func(name, address=0, size=100, signature=None, decompilation=None):
    return REFunction(
        name=name,
        address=address,
        size=size,
        signature=signature,
        decompilation=decompilation,
        source_tool="ghidra",
    )


class TestDiffDatabases:
    def test_identical_databases(self):
        funcs = [_make_func("main", 0x1000, 100)]
        diff = diff_databases(_make_db(funcs), _make_db(funcs))
        assert not diff.has_changes
        assert diff.added == []
        assert diff.removed == []
        assert diff.changed == []

    def test_added_function(self):
        old = _make_db([_make_func("main", 0x1000)])
        new = _make_db([
            _make_func("main", 0x1000),
            _make_func("new_func", 0x2000, 200),
        ])
        diff = diff_databases(old, new)
        assert len(diff.added) == 1
        assert diff.added[0].name == "new_func"
        assert diff.removed == []
        assert diff.changed == []

    def test_removed_function(self):
        old = _make_db([
            _make_func("main", 0x1000),
            _make_func("old_func", 0x2000),
        ])
        new = _make_db([_make_func("main", 0x1000)])
        diff = diff_databases(old, new)
        assert diff.added == []
        assert len(diff.removed) == 1
        assert diff.removed[0].name == "old_func"

    def test_size_change(self):
        old = _make_db([_make_func("process", 0x1000, 100)])
        new = _make_db([_make_func("process", 0x1000, 164)])
        diff = diff_databases(old, new)
        assert len(diff.changed) == 1
        c = diff.changed[0]
        assert c.name == "process"
        assert c.size_delta == 64
        assert c.size_old == 100
        assert c.size_new == 164

    def test_signature_change(self):
        old = _make_db([_make_func("parse", 0x1000, 100, signature="void parse(char*)")])
        new = _make_db([_make_func("parse", 0x1000, 100, signature="void parse(char*, int)")])
        diff = diff_databases(old, new)
        assert len(diff.changed) == 1
        assert diff.changed[0].signature_changed
        assert diff.changed[0].signature_old == "void parse(char*)"
        assert diff.changed[0].signature_new == "void parse(char*, int)"

    def test_address_shift(self):
        old = _make_db([_make_func("main", 0x1000, 100)])
        new = _make_db([_make_func("main", 0x2000, 100)])
        diff = diff_databases(old, new)
        assert len(diff.changed) == 1
        assert diff.changed[0].address_shifted
        assert diff.changed[0].address_old == 0x1000
        assert diff.changed[0].address_new == 0x2000

    def test_decompilation_change(self):
        old = _make_db([_make_func("f", 0x1000, 100, decompilation="int f() { return 0; }")])
        new = _make_db([_make_func("f", 0x1000, 100, decompilation="int f() { return 1; }")])
        diff = diff_databases(old, new)
        assert len(diff.changed) == 1
        assert diff.changed[0].decompilation_changed

    def test_decompilation_appearing_is_flagged(self):
        old = _make_db([_make_func("f", 0x1000, 100, decompilation=None)])
        new = _make_db([_make_func("f", 0x1000, 100, decompilation="int f() {}")])
        diff = diff_databases(old, new)
        assert len(diff.changed) == 1
        assert diff.changed[0].decompilation_changed

    def test_no_change_when_identical(self):
        f = _make_func("f", 0x1000, 100, signature="void f()")
        diff = diff_databases(_make_db([f]), _make_db([f]))
        assert diff.changed == []

    def test_labels_from_metadata(self):
        old = _make_db(program_name="v411")
        new = _make_db(program_name="v720")
        diff = diff_databases(old, new)
        assert diff.label_old == "v411"
        assert diff.label_new == "v720"

    def test_explicit_labels(self):
        diff = diff_databases(
            _make_db(), _make_db(),
            label_old="old-ver", label_new="new-ver",
        )
        assert diff.label_old == "old-ver"
        assert diff.label_new == "new-ver"

    def test_mixed_changes(self):
        old = _make_db([
            _make_func("kept", 0x1000, 100),
            _make_func("removed", 0x2000, 50),
            _make_func("changed", 0x3000, 200),
        ])
        new = _make_db([
            _make_func("kept", 0x1000, 100),
            _make_func("added", 0x4000, 75),
            _make_func("changed", 0x3000, 250),
        ])
        diff = diff_databases(old, new)
        assert len(diff.added) == 1
        assert len(diff.removed) == 1
        assert len(diff.changed) == 1
        assert diff.has_changes


class TestCommentDiff:
    def test_added_comment(self):
        old = _make_db(comments=[])
        new = _make_db(comments=[
            REComment(address=0x1000, function="f", kind="eol", text="new comment", source_tool="ghidra"),
        ])
        diff = diff_databases(old, new)
        assert len(diff.comment_deltas) == 1
        assert diff.comment_deltas[0].action == "added"
        assert diff.comment_deltas[0].text_new == "new comment"

    def test_removed_comment(self):
        old = _make_db(comments=[
            REComment(address=0x1000, function="f", kind="eol", text="old comment", source_tool="ghidra"),
        ])
        new = _make_db(comments=[])
        diff = diff_databases(old, new)
        assert len(diff.comment_deltas) == 1
        assert diff.comment_deltas[0].action == "removed"
        assert diff.comment_deltas[0].text_old == "old comment"

    def test_changed_comment(self):
        old = _make_db(comments=[
            REComment(address=0x1000, function="f", kind="eol", text="before", source_tool="ghidra"),
        ])
        new = _make_db(comments=[
            REComment(address=0x1000, function="f", kind="eol", text="after", source_tool="ghidra"),
        ])
        diff = diff_databases(old, new)
        assert len(diff.comment_deltas) == 1
        assert diff.comment_deltas[0].action == "changed"

    def test_identical_comments(self):
        c = REComment(address=0x1000, function="f", kind="eol", text="same", source_tool="ghidra")
        diff = diff_databases(_make_db(comments=[c]), _make_db(comments=[c]))
        assert diff.comment_deltas == []


class TestImportDiff:
    def test_added_import(self):
        old = _make_db(imports=[{"name": "printf", "address": 0}])
        new = _make_db(imports=[
            {"name": "printf", "address": 0},
            {"name": "malloc", "address": 0},
        ])
        diff = diff_databases(old, new)
        assert diff.import_deltas.get("added") == ["malloc"]

    def test_removed_import(self):
        old = _make_db(imports=[
            {"name": "printf", "address": 0},
            {"name": "gets", "address": 0},
        ])
        new = _make_db(imports=[{"name": "printf", "address": 0}])
        diff = diff_databases(old, new)
        assert diff.import_deltas.get("removed") == ["gets"]


class TestREDiffSerialization:
    def test_to_dict_roundtrip(self):
        old = _make_db([
            _make_func("kept", 0x1000, 100),
            _make_func("removed", 0x2000, 50),
        ])
        new = _make_db([
            _make_func("kept", 0x1000, 120),
            _make_func("added", 0x3000, 75),
        ])
        diff = diff_databases(old, new, label_old="v1", label_new="v2")
        d = diff.to_dict()

        assert d["label_old"] == "v1"
        assert d["label_new"] == "v2"
        assert len(d["added"]) == 1
        assert len(d["removed"]) == 1
        assert len(d["changed"]) == 1
        assert d["stats"]["added_count"] == 1

    def test_write_json(self, tmp_path):
        diff = diff_databases(
            _make_db([_make_func("f", 0x1000, 100)]),
            _make_db([_make_func("f", 0x1000, 200)]),
        )
        out = tmp_path / "diff.json"
        diff.write_json(out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data["changed"]) == 1

    def test_summary_text(self):
        old = _make_db([
            _make_func("kept", 0x1000, 100),
            _make_func("removed", 0x2000, 50),
        ])
        new = _make_db([
            _make_func("kept", 0x1000, 120),
            _make_func("added", 0x3000, 75),
        ])
        diff = diff_databases(old, new, label_old="v1", label_new="v2")
        summary = diff.summary()

        assert "v1 -> v2" in summary
        assert "Added (1 functions)" in summary
        assert "Removed (1 functions)" in summary
        assert "Changed (1 functions)" in summary

    def test_no_changes_summary(self):
        db = _make_db([_make_func("f", 0x1000, 100)])
        diff = diff_databases(db, db)
        assert "No differences found" in diff.summary()


class TestJsonEmissionScrub:
    """Comment texts, comment function names, and import names come
    from the analysed project; the JSON artifact is `jq`'d straight to
    operator terminals, so the emission layer must scrub controls/bidi
    and bound lengths — same chokepoint as function names."""

    HOSTILE = "\x1b[2K\x1b]0;PWNED\x07evil‮gnp.txt"

    def _diff_with_hostile_comment(self):
        old = _make_db(comments=[
            REComment(address=0x1000, function=self.HOSTILE, kind="plate",
                      text="benign old", source_tool="ghidra"),
        ])
        new = _make_db(
            comments=[
                REComment(address=0x1000, function=self.HOSTILE,
                          kind="plate", text=self.HOSTILE + "x" * 5000,
                          source_tool="ghidra"),
            ],
            imports=[{"name": "evil\x1b[2K" + "‮"}],
        )
        return diff_databases(old, new)

    def test_comment_deltas_scrubbed_and_bounded(self):
        d = self._diff_with_hostile_comment().to_dict()
        (delta,) = d["comment_deltas"]
        for value in (delta["function"], delta["text_old"],
                      delta["text_new"]):
            assert "\x1b" not in value
            assert "‮" not in value
        # texts bounded like signatures (512 + ellipsis)
        assert len(delta["text_new"]) <= 513
        # the whole serialised artifact carries no raw ESC
        assert "\\u001b" not in json.dumps(d)

    def test_import_deltas_scrubbed(self):
        d = self._diff_with_hostile_comment().to_dict()
        (name,) = d["import_deltas"]["added"]
        assert "\x1b" not in name
        assert "‮" not in name
        assert "evil" in name

    def test_benign_comment_text_passes_through(self):
        old = _make_db(comments=[])
        new = _make_db(comments=[
            REComment(address=0x2000, function="parse_hdr", kind="eol",
                      text="length check added", source_tool="ghidra"),
        ])
        d = diff_databases(old, new).to_dict()
        (delta,) = d["comment_deltas"]
        assert delta["function"] == "parse_hdr"
        assert delta["text_new"] == "length check added"


class TestFunctionChange:
    def test_size_delta(self):
        c = FunctionChange(
            name="f", address_old=0, address_new=0,
            size_old=100, size_new=150,
        )
        assert c.size_delta == 50

    def test_negative_delta(self):
        c = FunctionChange(
            name="f", address_old=0, address_new=0,
            size_old=200, size_new=100,
        )
        assert c.size_delta == -100

    def test_to_dict_minimal(self):
        c = FunctionChange(
            name="f", address_old=0x1000, address_new=0x1000,
            size_old=100, size_new=120,
        )
        d = c.to_dict()
        assert d["name"] == "f"
        assert d["size_delta"] == 20
        assert "signature_old" not in d
        assert "address_shifted" not in d

    def test_to_dict_with_changes(self):
        c = FunctionChange(
            name="f", address_old=0x1000, address_new=0x2000,
            size_old=100, size_new=100,
            signature_old="void f()", signature_new="int f(int)",
            decompilation_changed=True,
        )
        d = c.to_dict()
        assert d["address_shifted"] is True
        assert d["signature_old"] == "void f()"
        assert d["signature_new"] == "int f(int)"
        assert d["decompilation_changed"] is True
