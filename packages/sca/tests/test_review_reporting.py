"""Pre-add report exports preserve verdict and availability contracts."""
import json

import pytest

from core.json import JsonCache
from packages.sca import review
from packages.sca.review_reporting import check_result


class OwnedRegistry:
    def __init__(self):
        self.requests = []

    def post_json(self, url, body, **kwargs):
        self.requests.append(url)
        return {"results": [{"vulns": []}]}

    def get_json(self, url, **kwargs):
        self.requests.append(url)
        assert url == "https://registry.npmjs.org/@types%2Fnode/20.10.5"
        return {"name": "@types/node"}


@pytest.mark.parametrize("format_name,extension", [("markdown", "md"), ("json", "json"), ("xml", "xml")])
def test_explicit_report_retains_clean_native_review(tmp_path, capsys, format_name, extension):
    http = OwnedRegistry()
    output = tmp_path / ("review." + extension)
    assert review.main(["npm", "@types/node", "20.10.5", "--no-transitive", "--no-kev", "--no-epss",
                        "--report-format", format_name, "--report-output", str(output)],
                       http=http, cache=JsonCache(root=tmp_path / "cache")) == 0
    streams = capsys.readouterr()
    assert "**Verdict:** Clean" in streams.out
    assert "No advisories found" in streams.out
    assert output.is_file() and "Summary" in streams.err
    assert len(http.requests) == 2  # one OSV query, one existence check; reporting adds none


def test_offline_unavailable_report_cannot_mint_clean_verdict(tmp_path, capsys):
    output = tmp_path / "unavailable.json"
    http = OwnedRegistry()
    assert review.main(["npm", "@types/node", "20.10.5", "--offline", "--no-kev", "--no-epss",
                        "--report-format", "json", "--report-output", str(output)],
                       http=http, cache=JsonCache(root=tmp_path / "empty-cache")) == 2
    assert http.requests == []
    assert "**Verdict:** Degraded" in capsys.readouterr().out
    report = json.loads(output.read_text())
    assert any("verdict unavailable" in note for note in report["diagnostics"])
    from core.reporting.writer import load_committed_report
    context, _, _ = load_committed_report(tmp_path / ".unavailable-report")
    assert context.extensions["raptor.result"]["verdict"] == "Degraded"


def test_check_report_preflight_does_not_query(tmp_path):
    http = OwnedRegistry()
    with pytest.raises(SystemExit) as error:
        review.main(["npm", "@types/node", "20.10.5", "--report-format", "json"],
                    http=http, cache=JsonCache(root=tmp_path))
    assert error.value.code == 2 and http.requests == []


def test_capture_retains_block_during_outage_and_discloses_transitive_bounds(monkeypatch):
    from packages.sca import review_reporting
    monkeypatch.setattr(review_reporting, "DETAIL_LIMIT", 1)
    dep = review._synthesise_dep("npm", "@types/node", "20.10.5")
    result = check_result(dep=dep, vuln_findings=[], typo_findings=[], slop_findings=[], verdict=review._VERDICT_BLOCK,
                          exit_code=2, transitive_deps=[dep, dep], transitive_findings=[],
                          transitive_walk_attempted=True, transitive_walk_supported=True,
                          seed_metadata_unverifiable=True, osv_degraded=True, failed_lookups=1,
                          failed_dep_keys=["</script>"], offline=True)
    context, document = result.build()
    payload = context.extensions["raptor.result"]
    assert payload["verdict"] == "Block" and payload["exit_code"] == 2
    assert payload["recommendation"].startswith("Do not install")
    assert context.state == "partial"
    assert len(payload["transitive dependencies"]) == 1
    assert context.extensions["raptor.metrics"]["transitive dependencies"] == 2
    assert any("captures 1 of 2" in note for note in context.diagnostics)
    assert payload["coverage"]["failed package sample"] == ["</script>"]
    assert document.snapshot_id == context.snapshot_id


def test_report_failure_preserves_review_exit_and_stdout(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("retained")
    assert review.main(["npm", "@types/node", "20.10.5", "--no-transitive", "--no-kev", "--no-epss",
                        "--report-output", str(blocker / "review.md")],
                       http=OwnedRegistry(), cache=JsonCache(root=tmp_path / "cache")) == 0
    streams = capsys.readouterr()
    assert "**Verdict:** Clean" in streams.out
    assert "persistence failed" in streams.err and blocker.read_text() == "retained"


def test_candidate_capture_retains_confidence_and_domain_recommendation():
    from packages.sca.models import Confidence
    from packages.sca.supply_chain.typosquat import TyposquatFinding
    from packages.sca.supply_chain.slopsquat import SlopsquatFinding
    dep = review._synthesise_dep("npm", "owned", "1")
    confidence = Confidence("medium", reason="heuristic only")
    typo = TyposquatFinding(dep, "popular", 2, "medium", confidence)
    slop = SlopsquatFinding(dep, 0.5, ("candidate",), "popular", "medium", confidence)
    result = check_result(dep=dep, vuln_findings=[], typo_findings=[typo], slop_findings=[slop],
                          verdict=review._VERDICT_REVIEW, exit_code=1, transitive_deps=[], transitive_findings=[],
                          transitive_walk_attempted=False, transitive_walk_supported=False,
                          seed_metadata_unverifiable=False, osv_degraded=False, failed_lookups=0)
    context, _ = result.build()
    payload = context.extensions["raptor.result"]
    assert payload["recommendation"] == review._recommendation(review._VERDICT_REVIEW, False)
    assert payload["typosquat candidates"][0]["confidence"]["reason"] == "heuristic only"
    assert payload["slopsquat candidates"][0]["confidence"]["numeric"] == 0.7
