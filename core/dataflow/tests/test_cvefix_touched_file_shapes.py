"""Fix-file filters cannot silently become collections of characters."""

import pytest

from core.dataflow.cvefix_corpus_generator import generate_from_sarif


def _generate(files):
    locations = [{"location": {"physicalLocation": {
        "artifactLocation": {"uri": "owned.py"}, "region": {"startLine": line},
    }}} for line in (1, 2)]
    doc = {"runs": [{"results": [{
        "ruleId": "owned/inert", "message": {"text": "owned fixture"},
        "codeFlows": [{"threadFlows": [{"locations": locations}]}],
    }]}]}
    return generate_from_sarif(
        doc, doc, cve_id="CVE-OWN", cwe="CWE-89", labeled_at="2026-01-01",
        fix_touched_files=files,
    )


@pytest.mark.parametrize("files", ["owned.py", b"owned.py", {"owned.py": True}],
                         ids=["text", "bytes", "mapping"])
def test_ambiguous_filter_collection_is_refused(files):
    with pytest.raises(ValueError, match="fix_touched_files"):
        _generate(files)


@pytest.mark.parametrize("files", [[None], [1], [""], ["   "]])
def test_invalid_filter_entry_is_refused(files):
    with pytest.raises(ValueError, match="fix_touched_files"):
        _generate(files)


@pytest.mark.parametrize("factory", [list, tuple, set, iter])
def test_valid_filter_iterables_retain_both_observations(factory):
    pairs = _generate(factory(["owned.py"]))
    assert len(pairs) == 2
    assert {label.verdict for _, label in pairs} == {"true_positive", "false_positive"}
    assert all(finding.source.file_path == "owned.py" for finding, _ in pairs)


def test_explicit_empty_filter_still_selects_nothing():
    assert _generate([]) == []


def test_omitted_filter_retains_position_only_compatibility():
    assert len(_generate(None)) == 2
