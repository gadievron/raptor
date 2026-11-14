"""Bounded SARIF reference observers and owned scalar suppression directives."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.sarif.parser import ResultRuleResolver
from packages.semgrep import nosemgrep


class ObservedRules(list):
    def __init__(self, values):
        super().__init__(values)
        self.iterations = self.visits = self.index_reads = 0

    def __iter__(self):
        self.iterations += 1
        for item in super().__iter__():
            self.visits += 1
            yield item

    def __getitem__(self, index):
        self.index_reads += 1
        return super().__getitem__(index)


class StringAdapter(str):
    __hash__ = None


class MappingAdapter(dict):
    pass


def row(reference=None, **fields):
    result = {"locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "owned.c"}, "region": {"startLine": 1}}}]}
    if reference is not None:
        result["rule"] = reference
    result.update(fields)
    return result


def run(rows, descriptors, *, name="owned-extension", driver=None):
    return {"tool": {"driver": {"name": "semgrep", "rules": driver or []},
                     "extensions": [{"name": name, "rules": descriptors}]},
            "results": rows}


def reference(**fields):
    return {"guid": "wanted", "toolComponent": {"name": "owned-extension"}, **fields}


@pytest.fixture
def lookup(tmp_path, monkeypatch):
    (tmp_path / "owned.c").write_text("// nosemgrep: selected\n")
    original = nosemgrep.get_result_rule
    calls = []

    def observe(owner, result):
        calls.append(result)
        return original(owner, result)

    class NoEagerIndex:
        _reference_key = staticmethod(ResultRuleResolver._reference_key)

        def __init__(self, *args):
            pytest.fail("annotation must not build a full descriptor index")

    monkeypatch.setattr(nosemgrep, "get_result_rule", observe)
    monkeypatch.setattr(nosemgrep, "ResultRuleResolver", NoEagerIndex, raising=False)
    return tmp_path, calls


def descriptors():
    return ObservedRules([{"id": f"other-{i}", "guid": f"other-guid-{i}"} for i in range(63)]
                         + [{"id": "selected", "guid": "wanted"}])


def test_repeated_guid_reference_validates_once_without_eager_index(lookup):
    root, calls = lookup
    rules = descriptors()
    doc = {"runs": [run([row(reference()) for _ in range(16)], rules)]}
    assert nosemgrep.annotate_sarif(doc, root) == 16
    assert len(calls) == 1
    assert (rules.iterations, rules.visits) == (1, 64)


def test_component_changes_do_not_share_readable_identity(lookup):
    root, calls = lookup
    first = reference()
    second = reference(toolComponent={"name": "other-extension"})
    owner = run([row(deepcopy(ref)) for ref in [first, first, second, second, first, first]],
                [{"id": "selected", "guid": "wanted"}])
    owner["tool"]["extensions"].append({"name": "other-extension", "rules": [
        {"id": "other", "guid": "wanted"}]})
    assert nosemgrep.annotate_sarif({"runs": [owner]}, root) == 4
    assert len(calls) == 3


def test_explicit_empty_component_is_not_legacy_extension_fallback(lookup):
    root, calls = lookup
    absent, empty = {"guid": "wanted"}, {"guid": "wanted", "toolComponent": {}}
    owner = run([row(deepcopy(ref)) for ref in [absent, absent, empty, empty, absent, absent]],
                [{"id": "selected", "guid": "wanted"}])
    assert nosemgrep.annotate_sarif({"runs": [owner]}, root) == 4
    assert len(calls) == 3


@pytest.mark.parametrize("kind", ["absent", "ambiguous"])
def test_unresolved_descriptor_is_cached_without_fabricating_id(lookup, kind):
    root, calls = lookup
    rules = [] if kind == "absent" else [
        {"id": "selected", "guid": "wanted"}, {"id": "other", "guid": "wanted"}]
    assert nosemgrep.annotate_sarif({"runs": [run([row(reference()) for _ in range(4)], rules)]}, root) == 0
    assert len(calls) == 1


@pytest.mark.parametrize("kind", ["driver", "nested-driver", "extension"])
def test_indexed_references_keep_constant_time_validation(lookup, monkeypatch, kind):
    root, calls = lookup
    rules = ObservedRules([{"id": "selected", "guid": "wanted"}])
    driver = ObservedRules([{"id": "selected", "guid": "wanted"}])
    refs = {"driver": row(ruleIndex=0), "nested-driver": row({"index": 0}),
            "extension": row({"index": 0, "toolComponent": {"index": 0}})}

    def forbidden(result):
        pytest.fail("indexed references must not construct memo keys")

    monkeypatch.setattr(nosemgrep, "ResultRuleResolver", SimpleNamespace(_reference_key=forbidden))
    owner = run([deepcopy(refs[kind]) for _ in range(4)], rules, driver=driver)
    assert nosemgrep.annotate_sarif({"runs": [owner]}, root) == 4
    assert len(calls) == 4
    assert rules.iterations == driver.iterations == 0
    assert rules.index_reads + driver.index_reads == 8


def test_explicit_ids_do_not_resolve_descriptors(lookup, monkeypatch):
    root, calls = lookup
    rules = descriptors()

    def forbidden(result):
        pytest.fail("explicit IDs must not construct memo keys")

    monkeypatch.setattr(nosemgrep, "ResultRuleResolver", SimpleNamespace(_reference_key=forbidden))
    assert nosemgrep.annotate_sarif({"runs": [run([row(ruleId="selected") for _ in range(4)], rules)]}, root) == 4
    assert calls == []
    assert rules.iterations == 0


def test_each_run_owns_its_memo(lookup):
    root, calls = lookup
    first = run([row(reference()) for _ in range(2)], [{"id": "selected", "guid": "wanted"}])
    second = run([row(reference()) for _ in range(2)], [{"id": "other", "guid": "wanted"}])
    assert nosemgrep.annotate_sarif({"runs": [first, second]}, root) == 2
    assert len(calls) == 2


@pytest.mark.parametrize("kind", ["reference-string", "resolved-string", "mapping", "oversized-key"])
def test_unsupported_adapters_and_keys_preserve_uncached_lookup(lookup, kind):
    root, calls = lookup
    ref = reference()
    descriptor = {"id": "selected", "guid": "wanted"}
    if kind == "reference-string":
        ref["guid"] = StringAdapter("wanted")
    elif kind == "resolved-string":
        descriptor["id"] = StringAdapter("selected")
    elif kind == "mapping":
        ref = MappingAdapter(ref)
    else:
        ref["guid"] = descriptor["guid"] = "x" * 2048
    rows = [row(deepcopy(ref)) for _ in range(4)]
    assert nosemgrep.annotate_sarif({"runs": [run(rows, [descriptor])]}, root) == 4
    assert len(calls) == 4


def test_single_lookup_does_not_build_or_scan_an_extra_index(lookup):
    root, calls = lookup
    rules = descriptors()
    assert nosemgrep.annotate_sarif({"runs": [run([row(reference())], rules)]}, root) == 1
    assert len(calls) == 1
    assert (rules.iterations, rules.visits) == (1, 64)


def test_alternating_references_do_not_grow_retained_entries(lookup):
    root, calls = lookup
    refs = [reference(), reference(guid="other-guid")]
    rules = [{"id": "selected", "guid": "wanted"}, {"id": "other", "guid": "other-guid"}]
    assert nosemgrep.annotate_sarif({"runs": [run([row(deepcopy(ref)) for ref in refs * 4], rules)]}, root) == 4
    assert len(calls) == 8


def test_unusable_locations_do_not_resolve_rules(lookup):
    root, calls = lookup
    rules = descriptors()
    assert nosemgrep.annotate_sarif({"runs": [run([{"rule": reference()}], rules)]}, root) == 0
    assert calls == []
    assert rules.iterations == 0


@pytest.mark.parametrize("kind", ["result-negative", "reference-negative", "component-index",
                                 "component-oversized", "component-negative", "guid-nonstring",
                                 "component-name-nonstring", "rule-id-nonstring"])
def test_indexed_or_malformed_selectors_do_not_construct_memo_keys(lookup, monkeypatch, kind):
    root, calls = lookup
    ref = reference()
    fields = {}
    expected = 0
    if kind == "result-negative":
        fields["ruleIndex"] = -(1 << 8192)
    elif kind == "reference-negative":
        ref["index"] = -(1 << 8192)
    elif kind == "component-index":
        ref["toolComponent"] = {"index": 0}
        expected = 4
    elif kind == "component-oversized":
        ref["toolComponent"] = {"index": 1 << 8192}
    elif kind == "component-negative":
        ref["toolComponent"] = {"index": -(1 << 8192)}
    elif kind == "guid-nonstring":
        ref["guid"] = 1 << 8192
    elif kind == "component-name-nonstring":
        ref["toolComponent"] = {"name": 1 << 8192}
    else:
        fields["ruleId"] = 1 << 8192
        expected = 4

    def forbidden(result):
        pytest.fail("indexed or malformed selectors must not construct memo keys")

    monkeypatch.setattr(nosemgrep, "ResultRuleResolver", SimpleNamespace(_reference_key=forbidden))
    owner = run([row(deepcopy(ref), **fields) for _ in range(4)], descriptors())
    assert nosemgrep.annotate_sarif({"runs": [owner]}, root) == expected
    assert len(calls) == 4


def test_negative_locations_do_not_authorise_source_or_rule_lookup(lookup, monkeypatch):
    root, calls = lookup
    (root / "negative.c").write_text("// nosemgrep: selected\n")
    bad = row(reference())
    bad["locations"][0]["physicalLocation"] = {
        "artifactLocation": {"uri": "negative.c"}, "region": {"startLine": -1}}
    good = row(reference())
    original = nosemgrep.confine
    confined = []

    def confine(owner, uri):
        assert uri != "negative.c", "negative positions must not authorise source lookup"
        confined.append(uri)
        return original(owner, uri)

    monkeypatch.setattr(nosemgrep, "confine", confine)
    owner = run([bad, good], descriptors())
    assert nosemgrep.annotate_sarif({"runs": [owner]}, root) == 1
    assert confined == ["owned.c"]
    assert len(calls) == 1 and calls[0] is good
    assert "nosemgrep" not in bad.get("properties", {})
    assert good["properties"]["nosemgrep"]["suppressed"] is True


def test_direct_nonpositive_integer_lines_do_not_read_source(lookup, monkeypatch):
    root, _ = lookup
    original = nosemgrep._read_source_lines
    reads = []

    def read(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(nosemgrep, "_read_source_lines", read)
    source = root / "owned.c"
    assert nosemgrep.extract_nosemgrep(source, -1, rule_id="selected") is None
    assert nosemgrep.extract_nosemgrep(source, 0, rule_id="selected") is None
    assert reads == []
    info = nosemgrep.extract_nosemgrep(source, 1, rule_id="selected")
    assert info["suppressed"] is True and info["comment_line"] == 1
    assert reads == [source]
