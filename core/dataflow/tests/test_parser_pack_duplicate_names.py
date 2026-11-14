"""Existing pack ambiguity must not discard annotations during a merge."""

import copy

import pytest

from core.dataflow.parser_pack_harvest import merge_results


@pytest.mark.parametrize("second_library", ["owned", "other"], ids=["same-library", "different-library"])
def test_duplicate_existing_names_refused_without_mutation(second_library):
    pack = {"entries": [
        {"name": "owned_parse", "library": "owned", "provenance": ["legacy-catalog"], "cves": ["CVE-2099-1001"]},
        {"name": "owned_parse", "library": second_library, "provenance": ["cve-fix-diff"], "cves": ["CVE-2099-1002"]},
    ]}
    before = copy.deepcopy(pack)
    with pytest.raises(ValueError, match="duplicate.*owned_parse"):
        merge_results(pack, [])
    assert pack == before


def test_distinct_existing_names_keep_all_annotations():
    pack = {"entries": [
        {"name": "owned_parse", "library": "owned", "provenance": ["legacy-catalog"], "cves": ["CVE-2099-1001"]},
        {"name": "owned_decode", "library": "owned", "provenance": ["cve-fix-diff"], "cves": ["CVE-2099-1002"]},
    ]}
    merged = merge_results(pack, [])
    assert {entry["name"] for entry in merged["entries"]} == {"owned_parse", "owned_decode"}
    assert {cve for entry in merged["entries"] for cve in entry["cves"]} == {"CVE-2099-1001", "CVE-2099-1002"}
