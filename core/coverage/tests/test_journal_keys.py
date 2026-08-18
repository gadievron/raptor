"""Robustness tests for the injective ``file:function`` key encoding.

The raw ``f"{file}:{function}"`` join was only injective while path
extractors happened to trim colon-free trailing components. The
chokepoint helpers percent-encode ':' and '%' in the file component,
keeping every historical key (no ':'/'%' in the path) byte-identical.
"""

from __future__ import annotations

from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    encode_key_file,
    latest_entries,
    make_function_key,
    now_iso,
    reviewed_set,
    split_function_key,
)


class TestEncoding:
    def test_identity_for_plain_paths(self):
        """Paths without ':' or '%' keep their historical key exactly."""
        for path in ("src/a.c", "a b/c d.py", "üñí/çø∂é.rs", "x"):
            assert encode_key_file(path) == path
            assert make_function_key(path, "fn") == f"{path}:fn"

    def test_colon_bearing_file_no_collision(self):
        a = make_function_key("a.c:evil", "f")
        b = make_function_key("a.c", "evil:f")
        assert a != b

    def test_percent_bearing_file_no_collision(self):
        a = make_function_key("a%3Ab.c", "f")
        b = make_function_key("a:b.c", "f")
        assert a != b

    def test_round_trip(self):
        cases = [
            ("src/a.c", "foo"),
            ("a:b.c", "f"),
            ("a%b.c", "f"),
            ("a%3A.c", "f"),
            ("weird:%:path.c", "g"),
            ("", "f"),
        ]
        for file, function in cases:
            key = make_function_key(file, function)
            assert split_function_key(key) == (file, function)

    def test_old_format_keys_still_split(self):
        """Legacy keys (raw join) parse the same way as before —
        split on the LAST ':'."""
        assert split_function_key("src/a.c:foo") == ("src/a.c", "foo")
        assert split_function_key("foo") == ("", "foo")


class TestEntryKeys:
    def _entry(self, file: str, function: str) -> ReviewJournalEntry:
        return ReviewJournalEntry(
            ts=now_iso(),
            run_id="test",
            file=file,
            function=function,
            verdict="clean",
            source_hash="",
        )

    def test_entry_key_uses_encoding(self):
        e = self._entry("a:b.c", "f")
        assert e.key == make_function_key("a:b.c", "f")
        assert split_function_key(e.key) == ("a:b.c", "f")

    def test_entry_key_identity_for_plain_paths(self):
        e = self._entry("src/a.c", "f")
        assert e.key == "src/a.c:f"

    def test_index_key_file_component_encoded(self):
        e = self._entry("a:b.c", "f")
        assert e.index_key.startswith("a%3Ab.c:f:")

    def test_reviewed_set_and_latest_entries_align(self, tmp_path):
        """Journal round-trip: keys coming back from reviewed_set /
        latest_entries match make_function_key for the same fields —
        including a colon-bearing file."""
        e1 = self._entry("a.c:evil", "f")
        e2 = self._entry("a.c", "evil:f")
        append_entry(tmp_path, e1)
        append_entry(tmp_path, e2)

        keys = reviewed_set(tmp_path)
        assert make_function_key("a.c:evil", "f") in keys
        assert make_function_key("a.c", "evil:f") in keys
        assert len(keys) == 2  # no collision

        latest = latest_entries(tmp_path)
        assert latest[make_function_key("a.c:evil", "f")].function == "f"
        assert latest[make_function_key("a.c", "evil:f")].function == "evil:f"
