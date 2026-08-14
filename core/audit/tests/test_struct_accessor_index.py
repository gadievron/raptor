"""Tests for core.audit.struct_accessor_index."""

from __future__ import annotations

from core.audit.struct_accessor_index import (
    AccessorRecord,
    CoAccessorGroup,
    build_index_from_source,
    format_co_accessor_context,
    get_co_accessors,
)


def _gap(name, file, source):
    return {"name": name, "file": file, "source": source}


class TestBuildIndexFromSource:

    def test_arrow_access(self):
        gaps = [
            _gap("ep_remove", "fs/eventpoll.c",
                 "void ep_remove(struct epitem *epi) {\n"
                 "    list_del(&epi->rdllink);\n"
                 "    epi->ffd.file = NULL;\n"
                 "}"),
        ]
        index = build_index_from_source(gaps)
        assert "rdllink" in index
        assert index["rdllink"][0].function == "ep_remove"
        assert index["rdllink"][0].file == "fs/eventpoll.c"

    def test_dot_access(self):
        gaps = [
            _gap("init", "kern.c",
                 "void init(struct config cfg) {\n"
                 "    cfg.timeout = 30;\n"
                 "}"),
        ]
        index = build_index_from_source(gaps)
        assert "timeout" in index

    def test_noise_fields_excluded(self):
        gaps = [
            _gap("f", "a.c",
                 "p->next = q;\n"
                 "p->prev = r;\n"
                 "p->data = buf;\n"
                 "p->flags = 0;\n"
                 "p->important_field = val;\n"),
        ]
        index = build_index_from_source(gaps)
        assert "next" not in index
        assert "prev" not in index
        assert "data" not in index
        assert "flags" not in index
        assert "important_field" in index

    def test_short_fields_excluded(self):
        gaps = [_gap("f", "a.c", "p->fd = 0;\np->cb = NULL;")]
        index = build_index_from_source(gaps)
        assert "fd" not in index
        assert "cb" not in index

    def test_lock_detection(self):
        gaps = [
            _gap("locked_fn", "kern.c",
                 "void locked_fn(struct ep *ep) {\n"
                 "    mutex_lock(&ep->mtx);\n"
                 "    ep->rdllink = NULL;\n"
                 "    mutex_unlock(&ep->mtx);\n"
                 "}"),
        ]
        index = build_index_from_source(gaps)
        assert "rdllink" in index
        assert index["rdllink"][0].lock_held != ""

    def test_no_lock(self):
        gaps = [
            _gap("unlocked", "a.c",
                 "void unlocked(struct s *s) {\n"
                 "    s->rdllink = NULL;\n"
                 "}"),
        ]
        index = build_index_from_source(gaps)
        assert index["rdllink"][0].lock_held == ""

    def test_multiple_functions_same_field(self):
        gaps = [
            _gap("fn_a", "ep.c",
                 "mutex_lock(&ep->mtx);\n"
                 "ep->rdllink = x;\n"
                 "mutex_unlock(&ep->mtx);"),
            _gap("fn_b", "ep.c",
                 "ep->rdllink = y;"),
        ]
        index = build_index_from_source(gaps)
        assert len(index["rdllink"]) == 2

    def test_empty_gaps(self):
        assert build_index_from_source([]) == {}

    def test_gap_without_source(self):
        gaps = [{"name": "f", "file": "a.c", "source": ""}]
        assert build_index_from_source(gaps) == {}


class TestGetCoAccessors:

    def _build_index(self):
        return {
            "rdllink": [
                AccessorRecord(
                    function="ep_remove", file="ep.c",
                    field="rdllink", lock_held="ep->mtx",
                ),
                AccessorRecord(
                    function="ep_poll_callback", file="ep.c",
                    field="rdllink", lock_held="",
                ),
                AccessorRecord(
                    function="ep_insert", file="ep.c",
                    field="rdllink", lock_held="ep->mtx",
                ),
            ],
            "timeout": [
                AccessorRecord(
                    function="ep_remove", file="ep.c",
                    field="timeout",
                ),
            ],
        }

    def test_finds_co_accessors(self):
        index = self._build_index()
        groups = get_co_accessors(index, "ep_remove", "ep.c")
        assert len(groups) >= 1
        fields = {g.field for g in groups}
        assert "rdllink" in fields

    def test_lock_conflict_detected(self):
        index = self._build_index()
        groups = get_co_accessors(index, "ep_remove", "ep.c")
        rdl_group = [g for g in groups if g.field == "rdllink"][0]
        assert rdl_group.lock_conflict is True

    def test_no_co_accessors_for_unique_field(self):
        index = {
            "unique_field": [
                AccessorRecord(
                    function="only_fn", file="a.c", field="unique_field",
                ),
            ],
        }
        groups = get_co_accessors(index, "only_fn", "a.c")
        assert groups == []

    def test_conflict_groups_sorted_first(self):
        index = {
            "field_a": [
                AccessorRecord(function="fn1", file="a.c", field="field_a", lock_held="mtx"),
                AccessorRecord(function="fn2", file="a.c", field="field_a", lock_held=""),
            ],
            "field_b": [
                AccessorRecord(function="fn1", file="a.c", field="field_b", lock_held="mtx"),
                AccessorRecord(function="fn3", file="a.c", field="field_b", lock_held="mtx"),
            ],
        }
        groups = get_co_accessors(index, "fn1", "a.c")
        assert len(groups) == 2
        assert groups[0].lock_conflict is True
        assert groups[1].lock_conflict is False

    def test_same_file_only_filter(self):
        index = {
            "shared_field": [
                AccessorRecord(function="fn1", file="a.c", field="shared_field"),
                AccessorRecord(function="fn2", file="b.c", field="shared_field"),
            ],
        }
        groups = get_co_accessors(
            index, "fn1", "a.c", same_file_only=True,
        )
        assert groups == []

    def test_function_not_in_index(self):
        index = {
            "field_x": [
                AccessorRecord(function="other", file="a.c", field="field_x"),
            ],
        }
        groups = get_co_accessors(index, "missing_fn", "a.c")
        assert groups == []


class TestFormatCoAccessorContext:

    def test_none_when_empty(self):
        assert format_co_accessor_context([]) is None

    def test_formats_lock_conflict(self):
        group = CoAccessorGroup(
            field="rdllink",
            accessors=[
                AccessorRecord(
                    function="ep_remove", file="ep.c",
                    field="rdllink", lock_held="ep->mtx",
                ),
                AccessorRecord(
                    function="ep_poll_callback", file="ep.c",
                    field="rdllink", lock_held="",
                ),
            ],
            lock_conflict=True,
        )
        result = format_co_accessor_context([group])
        assert result is not None
        assert "[LOCK CONFLICT]" in result
        assert "rdllink" in result

    def test_formats_no_conflict(self):
        group = CoAccessorGroup(
            field="timeout",
            accessors=[
                AccessorRecord(function="fn_a", file="a.c", field="timeout"),
                AccessorRecord(function="fn_b", file="a.c", field="timeout"),
            ],
            lock_conflict=False,
        )
        result = format_co_accessor_context([group])
        assert "[LOCK CONFLICT]" not in result
        assert "timeout" in result

    def test_max_groups_respected(self):
        groups = [
            CoAccessorGroup(
                field=f"field_{i}",
                accessors=[
                    AccessorRecord(function="fn", file="a.c", field=f"field_{i}"),
                    AccessorRecord(function="other", file="a.c", field=f"field_{i}"),
                ],
            )
            for i in range(10)
        ]
        result = format_co_accessor_context(groups, max_groups=3)
        assert "... and 7 more" in result

    def test_description_lock_vs_no_lock(self):
        group = CoAccessorGroup(
            field="buffer",
            accessors=[
                AccessorRecord(
                    function="writer", file="a.c",
                    field="buffer", lock_held="mtx",
                ),
                AccessorRecord(
                    function="reader", file="a.c",
                    field="buffer", lock_held="",
                ),
            ],
            lock_conflict=True,
        )
        desc = group.description
        assert "under lock" in desc
        assert "without lock" in desc
        assert "writer" in desc
        assert "reader" in desc
