"""Hardened nuclei external-validator runner (no network, sandbox mocked)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.web.execution_policy import WebExecutionPolicy
from packages.web.external_validators import (
    ExternalValidatorRunner,
    NucleiConfig,
)
from packages.web.models import WebFinding


def _finding(url: str, vuln_type: str = "sqli", **overrides) -> WebFinding:
    kwargs = dict(
        id=f"WEB-{abs(hash(url)) % 10000:04d}",
        title="t",
        severity="high",
        confidence="medium",
        status="needs_review",
        url=url,
        evidence="e",
        description="d",
        recommendation="r",
        vuln_type=vuln_type,
        asvs_category="V5",
        check_id="V5.2.1",
        target_url=url,
    )
    kwargs.update(overrides)
    return WebFinding(**kwargs)


def _runner(tmp_path: Path, templates: Path | None, **config_kwargs):
    policy = WebExecutionPolicy.for_target("https://example.test")
    return ExternalValidatorRunner(
        base_url="https://example.test",
        out_dir=tmp_path,
        policy=policy,
        nuclei_config=NucleiConfig(templates_dir=templates, **config_kwargs),
    )


@pytest.fixture()
def templates_dir(tmp_path: Path) -> Path:
    d = tmp_path / "pinned-templates"
    d.mkdir()
    (d / "sqli.yaml").write_text("id: x\n", encoding="utf-8")
    return d


def test_missing_binary_reports_unavailable(tmp_path, templates_dir, monkeypatch):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which", lambda _b: None
    )
    results = _runner(tmp_path, templates_dir).run(
        [_finding("https://example.test/a")], ["nuclei"]
    )
    assert results == [
        {
            "tool": "nuclei",
            "status": "unavailable",
            "reason": "nuclei binary not found on PATH",
        }
    ]


def test_missing_pinned_templates_refuses_to_run(tmp_path, monkeypatch):
    """No pinned templates dir means no run — nuclei must never fall back
    to fetched or auto-updated templates."""
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _b: "/usr/bin/nuclei",
    )
    called = []
    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked",
        lambda *a, **k: called.append(1),
    )

    results = _runner(tmp_path, None).run(
        [_finding("https://example.test/a")], ["nuclei"]
    )

    assert results[0]["status"] == "unavailable"
    assert "pinned" in results[0]["reason"]
    assert not called


def test_batch_invocation_shape_and_scope(tmp_path, templates_dir, monkeypatch):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _b: "/usr/bin/nuclei",
    )
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        seen["kwargs"] = kwargs
        seen["targets"] = Path(cmd[cmd.index("-l") + 1]).read_text(encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked", fake_run
    )

    findings = [
        _finding("https://example.test/a", "sqli"),
        _finding("https://example.test/b", "xss"),
        _finding("https://example.test/a", "ssti"),  # same target, extra tag
    ]
    results = _runner(tmp_path, templates_dir).run(findings, ["nuclei"])

    cmd = seen["cmd"]
    # One batch over both unique targets.
    assert seen["targets"].splitlines() == [
        "https://example.test/a",
        "https://example.test/b",
    ]
    # Supply-chain / posture hard defaults.
    assert "-duc" in cmd
    assert "-ni" in cmd
    assert "-dut" not in cmd  # pinned dir is the provenance gate
    assert cmd[cmd.index("-t") + 1] == str(templates_dir.resolve())
    assert cmd[cmd.index("-rl") + 1] == "50"
    # Tags: union of the findings' classes, sorted.
    assert cmd[cmd.index("-tags") + 1] == "sqli,ssti,xss"
    # Public target: local-network pivots restricted.
    assert "-lna" in cmd
    # Sandbox scope: proxy pinned to the target host; templates readable.
    assert seen["kwargs"]["proxy_hosts"] == ["example.test"]
    assert str(templates_dir.resolve()) in seen["kwargs"]["readable_paths"]
    assert seen["kwargs"]["caller_label"] == "web-validator-nuclei"
    # Both targets get explicit no_match records — silence is not data.
    assert {r["status"] for r in results} == {"no_match"}
    assert all("not a refutation" in r["note"] for r in results)


def test_loopback_target_skips_lna(tmp_path, templates_dir, monkeypatch):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _b: "/usr/bin/nuclei",
    )
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked", fake_run
    )
    policy = WebExecutionPolicy.for_target("http://127.0.0.1:8080")
    runner = ExternalValidatorRunner(
        base_url="http://127.0.0.1:8080",
        out_dir=tmp_path,
        policy=policy,
        nuclei_config=NucleiConfig(templates_dir=templates_dir),
    )

    runner.run([_finding("http://127.0.0.1:8080/a")], ["nuclei"])

    assert "-lna" not in seen["cmd"]


def test_policy_denied_target_is_recorded_and_excluded(
    tmp_path, templates_dir, monkeypatch
):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _b: "/usr/bin/nuclei",
    )
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["targets"] = Path(cmd[cmd.index("-l") + 1]).read_text(encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked", fake_run
    )

    results = _runner(tmp_path, templates_dir).run(
        [
            _finding("https://example.test/ok"),
            _finding("https://evil.test/out-of-scope"),
        ],
        ["nuclei"],
    )

    denied = [r for r in results if r["status"] == "denied"]
    assert len(denied) == 1
    assert "outside scope receipt" in denied[0]["reason"]
    assert "evil.test" not in seen["targets"]


def test_credential_headers_ride_a_private_file_not_argv(
    tmp_path, templates_dir, monkeypatch
):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _b: "/usr/bin/nuclei",
    )
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        header_path = Path(cmd[cmd.index("-H") + 1])
        seen["mode"] = header_path.stat().st_mode & 0o777
        seen["content"] = header_path.read_text(encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked", fake_run
    )

    secret = "Authorization: Bearer nuclei-secret-42"
    _runner(tmp_path, templates_dir, headers=(secret,)).run(
        [_finding("https://example.test/a")], ["nuclei"]
    )

    assert secret not in " ".join(seen["cmd"])
    assert seen["mode"] == 0o600
    assert secret in seen["content"]
    # The header file must not outlive the run.
    assert not (tmp_path / "external-validators" / "nuclei-headers.txt").exists()


def test_jsonl_matches_attributed_per_target(tmp_path, templates_dir, monkeypatch):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _b: "/usr/bin/nuclei",
    )
    stdout = "\n".join(
        [
            json.dumps(
                {
                    "template-id": "sqli-error",
                    "info": {"name": "SQL error", "severity": "high"},
                    "matched-at": "https://example.test/a?q=1",
                    "extracted-results": ["boom"],
                    "curl-command": "curl https://example.test/a",
                }
            ),
            "not-json",
        ]
    )

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked", fake_run
    )

    results = _runner(tmp_path, templates_dir).run(
        [
            _finding("https://example.test/a"),
            _finding("https://example.test/b"),
        ],
        ["nuclei"],
    )

    by_url = {r["target_url"]: r for r in results}
    assert by_url["https://example.test/a"]["status"] == "matched"
    assert (
        by_url["https://example.test/a"]["matches"][0]["template_id"] == "sqli-error"
    )
    assert by_url["https://example.test/b"]["status"] == "no_match"
    # Raw JSONL is kept as an artifact.
    assert (tmp_path / "external-validators" / "nuclei-results.jsonl").exists()


def test_backstop_timeout_keeps_partial_output(tmp_path, templates_dir, monkeypatch):
    monkeypatch.setattr(
        "packages.web.external_validators.shutil.which",
        lambda _b: "/usr/bin/nuclei",
    )
    partial = json.dumps(
        {
            "template-id": "xss-probe",
            "info": {"name": "x", "severity": "medium"},
            "matched-at": "https://example.test/a",
        }
    )

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=cmd, timeout=kwargs["timeout"], output=partial, stderr=b"late"
        )

    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked", fake_run
    )

    results = _runner(tmp_path, templates_dir).run(
        [_finding("https://example.test/a")], ["nuclei"]
    )

    assert results[0]["status"] == "matched"
    assert results[0]["run"]["timed_out"] is True


def test_non_external_adapter_is_skipped(tmp_path, templates_dir):
    results = _runner(tmp_path, templates_dir).run(
        [_finding("https://example.test/a")], ["raptor-web-oracle"]
    )

    assert results[0]["status"] == "skipped"
