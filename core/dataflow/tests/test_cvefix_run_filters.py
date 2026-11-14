"""Run-directory filters require collections rather than substring matching."""

from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_loader as loader


@pytest.fixture
def inert_run(monkeypatch):
    reads = []
    record = SimpleNamespace(
        cve_id="CVE-OWNED", cwe="CWE-89", parent_commit="parent",
        repository_url="https://github.com/owned/inert", fix_commit="fix",
        files=[SimpleNamespace(path="Owned.java", is_test=False)],
    )

    def read(path):
        reads.append(path)
        return record

    monkeypatch.setattr("packages.checker_synthesis.cve_bridge.load_cve_run", read)
    return reads


@pytest.mark.parametrize("field,value", [
    ("cwes", "CWE-890"), ("languages", "JavaScript"),
    ("cwes", b"CWE-89"), ("languages", {"Java": True}),
    ("cwes", [""]), ("languages", [1]),
])
def test_invalid_run_filter_refuses_before_read(tmp_path, inert_run, field, value):
    with pytest.raises(ValueError, match=field):
        loader.load_pairs_from_cve_diff_runs([tmp_path / "unopened"], **{field: value})
    assert inert_run == []


@pytest.mark.parametrize("cwes,languages,expected", [
    (("CWE-89",), ("Java",), 1),
    (("CWE-890",), ("Java",), 0),
    (("CWE-89",), ("JavaScript",), 0),
    ([], ["Java"], 0),
    (["CWE-89"], [], 0),
])
def test_valid_run_filters_use_exact_membership(tmp_path, inert_run, cwes, languages, expected):
    pairs = loader.load_pairs_from_cve_diff_runs(
        [tmp_path / "unopened"], cwes=cwes, languages=languages,
    )
    assert len(pairs) == expected
    assert len(inert_run) == 1


def test_zero_limit_retains_no_read_shortcut(tmp_path, inert_run):
    assert loader.load_pairs_from_cve_diff_runs(
        [tmp_path / "unopened"], cwes="CWE-890", limit=0,
    ) == []
    assert inert_run == []
