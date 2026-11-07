"""Fallback census keeps coordinates, classifications and adapter behavior."""

import pytest

from core.audit import callsite_consistency as cc


@pytest.mark.parametrize("suffix,assignment", [
    ("go", cc.USAGE_CAPTURED_UNUSED),
    ("py", cc.USAGE_ACKNOWLEDGED),
    ("swift", cc.USAGE_ACKNOWLEDGED),
    ("c", cc.USAGE_CAPTURED_USED),
])
@pytest.mark.parametrize("separator", ["\n", "\r\n"])
def test_streamed_coordinates_and_usage(suffix, assignment, separator):
    # Force multiple chunks, with exotic separators kept inside source rows.
    prefix = ["// untouched\v\f\x85\u2028\r text"] * 300
    rows = prefix + ["def handler", "_ = validate()", "if verify():", "return fetch()"]
    sites = cc._extract_callsites_regex("app." + suffix, separator.join(rows) + separator)
    assert [(s.callee, s.line, s.enclosing_function, s.usage, s.engine) for s in sites] == [
        ("validate", 302, "handler", assignment, "regex"),
        ("verify", 303, "handler", cc.USAGE_TESTED, "regex"),
        ("fetch", 304, "handler", cc.USAGE_PROPAGATED, "regex"),
    ]


def test_limiter_observes_non_call_rows_and_preserves_truncation(caplog):
    class Limiter(cc._CensusLimiter):
        def __init__(self):
            super().__init__(None, 10)
            self.counts = []

        def file_exhausted(self, count):
            self.counts.append(count)
            if len(self.counts) == 4:
                self.hit = "test row deadline"
                return True
            return False

    limiter = Limiter()
    source = "def owner\n// no call\nvalidate()\n// stop here\nverify()\n"
    sites = cc._extract_callsites_regex("app.py", source, limiter)
    assert [(s.callee, s.line, s.enclosing_function) for s in sites] == [("validate", 3, "owner")]
    assert limiter.counts == [0, 0, 0, 1]
    assert "census truncated in app.py (test row deadline)" in caplog.text


def test_site_cap_does_not_consume_remaining_stream(monkeypatch):
    consumed = []
    original = cc.iter_source_lines

    def tracked(source):
        for row in original(source):
            consumed.append(row)
            yield row

    monkeypatch.setattr(cc, "iter_source_lines", tracked)
    limiter = cc._CensusLimiter(None, 1)
    sites = cc._extract_callsites_regex("app.py", "validate()\n" + "unused\n" * 10000, limiter)
    assert [s.callee for s in sites] == ["validate"]
    assert consumed == ["validate()", "unused"]
    assert limiter.hit == "site cap (1/file) reached"


@pytest.mark.parametrize("name", [
    "_C_FUNC_HEADER_RE", "_GO_BLANK_ASSIGN_RE", "_C_VOID_CAST_RE",
    "_RUST_LET_UNDERSCORE_RE", "_PY_UNDERSCORE_ASSIGN_RE",
    "_SWIFT_UNDERSCORE_ASSIGN_RE", "_ASSIGN_LINE_RE", "_RETURN_LINE_RE",
    "_COND_LINE_RE", "_STMT_ONLY_LINE_RE", "_CALL_IN_LINE_RE",
])
def test_replaced_classifiers_still_observe_non_call_rows(monkeypatch, name):
    original = getattr(cc, name)
    seen = []

    class Classifier:
        def match(self, line):
            seen.append(line)
            return original.match(line)

        def finditer(self, line):
            seen.append(line)
            return original.finditer(line)

    suffix = {"_GO_BLANK_ASSIGN_RE": "go", "_SWIFT_UNDERSCORE_ASSIGN_RE": "swift"}.get(name, "py")
    monkeypatch.setattr(cc, name, Classifier())
    assert cc._extract_callsites_regex("app." + suffix, "no_call") == []
    assert seen == ["no_call"]


def test_limiter_can_replace_classifier_during_extraction(monkeypatch):
    class Calls:
        def finditer(self, line):
            return cc._NO_CALL_CLASSIFIERS[-1].finditer("injected()")

    class Limiter(cc._CensusLimiter):
        def file_exhausted(self, count):
            monkeypatch.setattr(cc, "_CALL_IN_LINE_RE", Calls())
            return False

    sites = cc._extract_callsites_regex("app.py", "no_call", Limiter(None, 10))
    assert [(s.callee, s.line) for s in sites] == [("injected", 1)]


def test_splitter_override_is_authoritative(monkeypatch):
    seen = []

    def split(source):
        seen.append(source)
        return ["def custom", "validate()"]

    monkeypatch.setattr(cc, "split_lines", split)
    sites = cc._extract_callsites_regex("app.py", "ignored")
    assert seen == ["ignored"]
    assert [(s.callee, s.line, s.enclosing_function) for s in sites] == [("validate", 2, "custom")]


def test_source_and_path_adapters_keep_original_operations():
    events = []

    class Source(str):
        def split(self, separator):
            events.append(("split", separator))
            return ["no_call", "validate()"]

    class File(str):
        def endswith(self, suffix):
            events.append(("suffix", suffix))
            return super().endswith(suffix)

    sites = cc._extract_callsites_regex(File("app.py"), Source("ignored"))
    assert [(s.callee, s.line) for s in sites] == [("validate", 2)]
    assert events == [("split", "\n")] + [("suffix", s) for s in (".go", ".py", ".swift")] * 2
