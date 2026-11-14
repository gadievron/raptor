"""CLI sampling bounds are checked before advisory or resolution work."""

import pytest

from core.dataflow import ghsa_harvester as ghsa


def test_negative_sample_refused_before_advisory_scan(monkeypatch):
    calls = []
    def scan(*args):
        calls.append("scan")
        return []
    monkeypatch.setattr(ghsa, "_iter_advisories", scan)
    monkeypatch.setattr(ghsa, "_write_metadata_db", lambda *args: calls.append("write"))
    with pytest.raises(SystemExit) as exc:
        ghsa.main(["--ghsa-root", "owned-inert", "--out", "owned-inert.db", "--sample-size", "-1"])
    assert exc.value.code == 2
    assert calls == []


@pytest.mark.parametrize("size", [0, 2], ids=["zero", "positive"])
def test_valid_sample_size_preserves_resolution_count(monkeypatch, size):
    advisories = [{"aliases": [f"CVE-2099-{1000+i}"],
                   "database_specific": {"cwe_ids": ["CWE-22"]},
                   "affected": [{"package": {"ecosystem": "PyPI"}}],
                   "references": [{"url": f"https://github.com/owned/inert/commit/{i:040x}"}]}
                  for i in range(5)]
    monkeypatch.setattr(ghsa, "_iter_advisories", lambda *args: [(None, adv) for adv in advisories])
    resolved = []
    def resolve(repo, sha, **kwargs):
        resolved.append((repo, sha))
        return "f" * 40
    monkeypatch.setattr(ghsa, "_resolve_parent", resolve)
    written = []
    monkeypatch.setattr(ghsa, "_write_metadata_db", lambda path, rows: written.append(list(rows)))
    assert ghsa.main(["--ghsa-root", "owned-inert", "--out", "owned-inert.db", "--sample-size", str(size)]) == 0
    assert len(resolved) == size
    assert len(written) == 1
    assert len(written[0]) == size
