from pathlib import Path
from types import SimpleNamespace

from packages.web.execution_policy import WebExecutionPolicy
from packages.web.external_validators import ExternalValidatorRunner
from packages.web.models import WebFinding


def _finding() -> WebFinding:
    return WebFinding(
        id="WEB-0001",
        title="SQL Injection",
        severity="high",
        confidence="medium",
        status="needs_review",
        url="https://example.test/search",
        evidence="confirmed",
        description="SQLi",
        recommendation="Use parameters",
        vuln_type="injection",
        asvs_category="V5",
        check_id="V5.2.1",
        confirmed=True,
        target_url="https://example.test/search",
    )


def test_nuclei_validator_parses_matches_without_refuting_no_match(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _binary: "/usr/bin/nuclei",
    )
    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"template-id":"test-id","info":{"name":"Test","severity":"high"},"matched-at":"https://example.test/search"}\n',
            stderr="",
        ),
    )
    runner = ExternalValidatorRunner(
        base_url="https://example.test",
        out_dir=tmp_path,
        policy=WebExecutionPolicy.for_target("https://example.test"),
    )

    results = runner.run([_finding()], ["nuclei"])

    assert results[0]["status"] == "matched"
    assert results[0]["matches"][0]["template_id"] == "test-id"
    assert "No-match is not a refutation" in results[0]["note"]


def test_validator_denial_is_reported_not_executed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _binary: "/usr/bin/nuclei",
    )
    called = []
    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted",
        lambda *args, **kwargs: called.append(True),
    )
    runner = ExternalValidatorRunner(
        base_url="https://example.test",
        out_dir=tmp_path,
        policy=WebExecutionPolicy.for_target("https://other.test"),
    )

    results = runner.run([_finding()], ["nuclei"])

    assert results[0]["status"] == "denied"
    assert called == []

