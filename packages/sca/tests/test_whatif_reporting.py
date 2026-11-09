"""Upgrade reports consume observations without repeating comparisons or IO."""

import pytest

from core.json import JsonCache
from core.reporting.writer import load_committed_report
from packages.sca import whatif
from packages.sca.whatif_reporting import UpgradeCapture


class OwnedAdvisories:
    def __init__(self, vulnerable=False):
        self.vulnerable = vulnerable
        self.requests = []

    def post_json(self, url, body, **kwargs):
        self.requests.append(url)
        return {"results": [{"vulns": [{"id": "TEST-1"}]} if self.vulnerable and query["version"] == "1.0.0" else {}
                            for query in body["queries"]]}

    def get_json(self, url, **kwargs):
        self.requests.append(url)
        assert url.endswith("TEST-1")
        return {"id": "TEST-1", "modified": "2024-01-01T00:00:00Z", "summary": "owned advisory",
                "aliases": ["CVE-2099-OWNED"], "affected": [{"package": {"ecosystem": "npm", "name": "owned"},
                                                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}


@pytest.mark.parametrize("arguments,mode", [
    (["npm", "owned", "1.0.0", "2.0.0"], "pairwise"),
    (["npm", "owned", "1.0.0", "--candidate", "2.0.0", "--candidate", "3.0.0"], "candidates"),
    (["--add", "npm:owned@1.0.0", "--remove", "npm:gone"], "add/remove change set"),
])
def test_each_upgrade_mode_captures_without_extra_queries(tmp_path, capsys, arguments, mode):
    output = tmp_path / "upgrade.json"
    http = OwnedAdvisories()
    assert whatif.main([*arguments, "--no-kev", "--no-epss", "--report-format", "json", "--report-output", str(output)],
                       http=http, cache=JsonCache(root=tmp_path / "cache")) == 0
    assert len(http.requests) == 1
    streams = capsys.readouterr()
    assert "raptor-sca upgrade" in streams.out and "Summary" in streams.err
    context, _, _ = load_committed_report(tmp_path / ".upgrade-report")
    assert context.extensions["raptor.result"]["mode"] == mode
    assert context.extensions["raptor.result"]["exit_code"] == 0
    assert context.state == "completed"


def test_pairwise_capture_retains_advisory_metadata_and_existing_resolution(tmp_path, capsys):
    output = tmp_path / "upgrade.json"
    http = OwnedAdvisories(vulnerable=True)
    assert whatif.main(["npm", "owned", "1.0.0", "2.0.0", "--no-kev", "--no-epss",
                        "--report-format", "json", "--report-output", str(output)],
                       http=http, cache=JsonCache(root=tmp_path / "cache")) == 0
    assert len(http.requests) == 2  # existing query + advisory detail; report adds none
    context, _, _ = load_committed_report(tmp_path / ".upgrade-report")
    payload = context.extensions["raptor.result"]
    assert payload["outcomes"][0]["result"]["resolved"] == 1
    advisory = payload["observations"][0]["result"]["advisories"][0]["sca"]["advisory"]
    assert advisory["id"] == "TEST-1" and "CVE-2099-OWNED" in advisory["aliases"]


def test_degraded_capture_keeps_unavailable_exit_and_no_network(tmp_path, capsys):
    http = OwnedAdvisories()
    output = tmp_path / "upgrade.xml"
    assert whatif.main(["npm", "owned", "1.0.0", "2.0.0", "--offline", "--no-kev", "--no-epss",
                        "--report-format", "xml", "--report-output", str(output)],
                       http=http, cache=JsonCache(root=tmp_path / "empty")) == 2
    assert http.requests == []
    assert "verdict unavailable" in capsys.readouterr().out
    context, _, _ = load_committed_report(tmp_path / ".upgrade-report")
    assert context.state == "partial"
    assert context.extensions["raptor.result"]["coverage"]["OSV degraded"]


def test_capture_cap_retains_late_domain_outcome(monkeypatch):
    from packages.sca import whatif_reporting
    monkeypatch.setattr(whatif_reporting, "DETAIL_LIMIT", 1)
    capture = UpgradeCapture()
    capture.record("from", {"version": "1"})
    capture.record("candidate", {"version": "2"})
    capture.record("candidate comparison", {"recommended candidate": "2"})
    assert capture.recorded == 2 and len(capture.observations) == 1
    assert capture.outcomes[0]["result"]["recommended candidate"] == "2"


def test_upgrade_preflight_does_not_query(tmp_path):
    http = OwnedAdvisories()
    with pytest.raises(SystemExit) as error:
        whatif.main(["npm", "owned", "1.0.0", "2.0.0", "--report-format", "json"],
                    http=http, cache=JsonCache(root=tmp_path))
    assert error.value.code == 2 and http.requests == []
