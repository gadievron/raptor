"""CVE corroboration must retain the parser API's library identity."""

import copy

import pytest

from core.dataflow.parser_pack_harvest import HarvestResult, merge_results


def test_cross_library_corroboration_refused_without_mutating_pack():
    pack = {"entries": [{"name": "owned_parse", "library": "first", "provenance": ["legacy-catalog"], "cves": []}]}
    before = copy.deepcopy(pack)
    result = HarvestResult("second", names={"owned_parse": {"CVE-2099-1001"}})
    with pytest.raises(ValueError, match="library.*owned_parse"):
        merge_results(pack, [result])
    assert pack == before


@pytest.mark.parametrize("libraries", [("first", "second"), ("second", "first")], ids=["forward", "reverse"])
def test_cross_library_new_name_collision_refused(libraries):
    results = [HarvestResult(library, names={"owned_parse": {"CVE-2099-1001"}}) for library in libraries]
    with pytest.raises(ValueError, match="library.*owned_parse"):
        merge_results({"entries": []}, results)


def test_same_library_cve_corroboration_remains_additive():
    pack = {"entries": [{"name": "owned_parse", "library": "first", "provenance": ["legacy-catalog"], "cves": ["CVE-2099-1001"]}]}
    result = HarvestResult("first", names={"owned_parse": {"CVE-2099-1002"}})
    (entry,) = merge_results(pack, [result])["entries"]
    assert entry["library"] == "first"
    assert entry["cves"] == ["CVE-2099-1001", "CVE-2099-1002"]
    assert entry["provenance"] == ["cve-fix-diff", "legacy-catalog"]
