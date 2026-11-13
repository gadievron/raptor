"""Optional sidecar failures retain names, provenance and error accounting."""

import json

import pytest

from core.dataflow.parser_pack_harvest import HarvestSource, harvest_diff_dir


def _source(tmp_path, sidecar):
    stem = "CVE-2099-11111"
    (tmp_path / f"{stem}.diff").write_text(
        "diff --git a/inert.c b/inert.c\n"
        "--- a/inert.c\n+++ b/inert.c\n"
        "@@ -1 +1 @@ int OWN_parse(void)\n-old\n+new\n",
        encoding="utf-8",
    )
    (tmp_path / f"{stem}.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return HarvestSource(library="inert", api_patterns=("^OWN_",), diff_dir=str(tmp_path))


@pytest.mark.parametrize("sidecar", [[], ["CVE-2099-22222"], "CVE-2099-22222", 1, False])
def test_nonobject_sidecar_is_disclosed_without_losing_diff(tmp_path, sidecar):
    result = harvest_diff_dir(_source(tmp_path, sidecar))
    assert result.names == {"OWN_parse": {"CVE-2099-11111"}}
    assert result.commits_walked == 1
    assert len(result.errors) == 1
    assert "CVE-2099-11111.json" in result.errors[0]


def test_object_sidecar_retains_additional_provenance(tmp_path):
    result = harvest_diff_dir(_source(tmp_path, {"cve_id": "CVE-2099-22222"}))
    assert result.names == {"OWN_parse": {"CVE-2099-11111", "CVE-2099-22222"}}
    assert result.commits_walked == 1
    assert result.errors == []
