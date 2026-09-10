"""Fresh web-validation replay at the trusted scanner boundary."""

from __future__ import annotations

import http.server
import json
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import requests

from packages.web.models import WebFinding
from packages.web.scanner import (
    _VALIDATION_REPLAY_ARTIFACT,
    _VALIDATION_REPLAY_MAX_ARTIFACT_BYTES,
    WebScanner,
)


class _ReplayHandler(http.server.BaseHTTPRequestHandler):
    hits: list[dict] = []
    mode = "sqli"
    redirect_to: str | None = None

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        self._handle(
            method="GET",
            path=parsed.path,
            params={name: values[-1] for name, values in params.items()},
            body=b"",
        )

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        params = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        self._handle(
            method="POST",
            path=urlparse(self.path).path,
            params={name: values[-1] for name, values in params.items()},
            body=body,
        )

    def _handle(
        self,
        *,
        method: str,
        path: str,
        params: dict[str, str],
        body: bytes,
    ) -> None:
        type(self).hits.append({
            "method": method,
            "path": path,
            "params": params,
            "body": body,
            "headers": dict(self.headers),
        })
        if self.mode == "rate_limited":
            self._send(429, b"slow down")
            return
        if self.mode == "same_origin_redirect" and path == "/start":
            query = self.path.partition("?")[2]
            location = "/final" + (f"?{query}" if query else "")
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        if self.mode == "cross_origin_redirect":
            self.send_response(302)
            self.send_header("Location", str(self.redirect_to))
            self.end_headers()
            return

        value = params.get("q", "")
        if "' OR 1=1--" in value:
            body_out = b"SQL syntax error"
            if self.mode == "large_secret":
                body_out += (
                    b"\napi_key=secret-value-that-must-not-persist\n"
                    + b"A" * 5000
                )
            self._send(
                500,
                body_out,
                extra_headers={
                    "Set-Cookie":
                        "session=credential-that-must-not-persist",
                },
            )
            return
        self._send(200, b"clean control")

    def _send(
        self,
        status_code: int,
        body: bytes,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # pragma: no cover - keep tests quiet
        pass


@contextmanager
def _server(*, mode: str = "sqli", redirect_to: str | None = None):
    handler = type(
        "ValidationReplayHandler",
        (_ReplayHandler,),
        {
            "hits": [],
            "mode": mode,
            "redirect_to": redirect_to,
        },
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _base_url(server) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}"


def _finding(
    url: str,
    *,
    finding_id: str = "WEB-0001",
    method: str = "GET",
    attack_vector: str = "query_param",
    vuln_type: str = "sqli",
    payload: str | None = "' OR 1=1--",
) -> WebFinding:
    return WebFinding(
        id=finding_id,
        title="SQL Injection",
        severity="high",
        confidence="medium",
        status="needs_review",
        url=url,
        evidence="scanner oracle evidence",
        description="SQL injection candidate",
        recommendation="Use parameterized queries",
        vuln_type=vuln_type,
        asvs_category="V5",
        check_id="V5.2.1",
        confirmed=True,
        target_url=url,
        confirmation_payload=payload,
        response_evidence="SQL syntax error",
        baseline_evidence="HTTP 200 clean",
        attack_evidence="HTTP 500 SQL syntax error",
        diff_summary="baseline differs from attack",
        attack_vector=attack_vector,
        method=method,
        affected_parameters=["q"],
        oracle_signal="sqli_error:sql syntax",
    )


def _scanner(
    base_url: str,
    out_dir: Path,
    *,
    verify_findings: bool = True,
    max_verifications: int = 10,
) -> WebScanner:
    return WebScanner(
        base_url,
        out_dir=out_dir,
        block_private_ips=False,
        rate_limit=0,
        verify_findings=verify_findings,
        max_verifications=max_verifications,
    )


def _phase6v_hit(finding: WebFinding) -> dict:
    return {
        "endpoint": finding.url,
        "parameter": finding.affected_parameters[0],
        "payload": finding.confirmation_payload,
        "vulnerability_type": finding.vuln_type,
        "method": finding.method,
        "attack_vector": finding.attack_vector,
        "status_code": 500,
        "response_length": 16,
    }


def test_same_origin_get_replay_and_controls_are_fresh(tmp_path):
    with _server() as (server, handler):
        scanner = _scanner(_base_url(server), tmp_path)
        try:
            artifact = scanner._build_validation_replay_artifact([
                _finding(f"{_base_url(server)}/search"),
            ])
        finally:
            scanner.close()

    record = artifact["records"][0]
    assert record["evidence_status"] == "confirmed"
    assert record["freshness"] == "fresh"
    assert record["oracle"]["replay_signal_present"] is True
    assert record["oracle"]["control_signal_present"] == [False, False]
    assert artifact["summary"]["request_count"] == 3
    assert artifact["summary"]["reused_request_count"] == 0
    assert artifact["summary"]["verification_budget"] == {
        "limit": 10,
        "consumed": 1,
        "remaining": 9,
        "unit": "finding_verification",
        "control_requests_counted_separately": False,
        "consumed_by_phase": {
            "phase_6v": 0,
            "phase_7a": 1,
        },
        "consumed_before_phase": 0,
        "consumed_in_phase": 1,
    }
    assert [hit["method"] for hit in handler.hits] == ["GET", "GET", "GET"]
    assert all("q" in hit["params"] for hit in handler.hits)
    assert all(
        decision["target_origin"] == _base_url(server)
        for decision in record["policy"]["decisions"]
    )
    assert {
        decision["action"] for decision in record["policy"]["decisions"]
    } >= {
        "validation_control",
        "validation_replay",
        "validation_control_replay",
    }


def test_phase7a_reuses_fresh_compatible_phase6v_evidence(tmp_path):
    with _server() as (server, handler):
        scanner = _scanner(_base_url(server), tmp_path)
        finding = _finding(f"{_base_url(server)}/search")
        hit = _phase6v_hit(finding)
        try:
            verification = scanner._verify_findings([
                (hit, finding.url, "q", "GET"),
            ])
            assert len(handler.hits) == 3
            artifact = scanner._build_validation_replay_artifact([finding])
        finally:
            scanner.close()

    record = artifact["records"][0]
    assert len(handler.hits) == 3
    assert verification["verification_budget"]["consumed"] == 1
    assert record["evidence_status"] == "confirmed"
    assert record["freshness"] == "fresh"
    assert record["provenance"]["evidence_source"] == "phase_6v"
    assert record["provenance"]["reused_for_phase_7a"] is True
    assert artifact["summary"]["request_count"] == 0
    assert artifact["summary"]["reused_request_count"] == 3
    assert artifact["summary"]["reused_finding_count"] == 1
    assert artifact["summary"]["verification_budget"]["consumed"] == 1
    assert artifact["summary"]["verification_budget"]["remaining"] == 9
    assert artifact["summary"]["verification_budget"]["consumed_in_phase"] == 0


def test_phase6v_and_phase7a_share_one_verification_cap(tmp_path):
    with _server() as (server, handler):
        scanner = _scanner(
            _base_url(server),
            tmp_path,
            max_verifications=2,
        )
        phase6v = _finding(
            f"{_base_url(server)}/phase6v",
            finding_id="WEB-PHASE6V",
        )
        phase7a_first = _finding(
            f"{_base_url(server)}/phase7a-first",
            finding_id="WEB-PHASE7A-1",
        )
        phase7a_second = _finding(
            f"{_base_url(server)}/phase7a-second",
            finding_id="WEB-PHASE7A-2",
        )
        try:
            scanner._verify_findings([
                (_phase6v_hit(phase6v), phase6v.url, "q", "GET"),
            ])
            artifact = scanner._build_validation_replay_artifact([
                phase7a_first,
                phase7a_second,
            ])
        finally:
            scanner.close()

    assert len(handler.hits) == 6
    assert [
        record["evidence_status"] for record in artifact["records"]
    ] == ["confirmed", "skipped"]
    assert artifact["records"][1]["freshness"] == "not_obtained"
    assert artifact["summary"]["request_count"] == 3
    assert artifact["summary"]["verification_budget"]["consumed"] == 2
    assert artifact["summary"]["verification_budget"]["remaining"] == 0
    assert artifact["summary"]["verification_budget"]["consumed_by_phase"] == {
        "phase_6v": 1,
        "phase_7a": 1,
    }


def test_exhausted_shared_budget_skips_without_freshness_claim(tmp_path):
    with _server() as (server, handler):
        scanner = _scanner(
            _base_url(server),
            tmp_path,
            max_verifications=1,
        )
        phase6v = _finding(
            f"{_base_url(server)}/phase6v",
            finding_id="WEB-PHASE6V",
        )
        phase7a = _finding(
            f"{_base_url(server)}/phase7a",
            finding_id="WEB-PHASE7A",
        )
        try:
            scanner._verify_findings([
                (_phase6v_hit(phase6v), phase6v.url, "q", "GET"),
            ])
            artifact = scanner._build_validation_replay_artifact([phase7a])
        finally:
            scanner.close()

    record = artifact["records"][0]
    assert len(handler.hits) == 3
    assert record["evidence_status"] == "skipped"
    assert record["freshness"] == "not_obtained"
    assert record["reason"] == "shared per-run verification budget exhausted"
    assert record["replay"] is None
    assert record["controls"] == []
    assert (
        record["provenance"]["evidence_source"]
        == "skipped_budget_exhausted"
    )
    assert artifact["summary"]["request_count"] == 0
    assert artifact["summary"]["verification_budget"]["remaining"] == 0
    assert artifact["provenance"]["freshness_source"] == "not_obtained"


def test_post_replay_preserves_safe_body_and_excludes_unsafe_inputs(tmp_path):
    bearer = "Bearer credential-that-must-not-be-sent"
    with _server() as (server, handler):
        scanner = _scanner(_base_url(server), tmp_path)
        finding = _finding(
            f"{_base_url(server)}/submit",
            method="POST",
            attack_vector="request_body",
        )
        scanner._validation_request_evidence[finding.id] = {
            "method": "POST",
            "url": finding.url,
            "headers": {
                "Authorization": bearer,
                "Connection": "close",
                "Host": "evil.test",
                "X-Api-Key": "credential-that-must-not-be-sent",
                "X-Trace": "safe-trace",
            },
            "body_kind": "form",
            "body": {
                "q": "",
                "title": "hello",
                "csrf_token": "credential-that-must-not-be-sent",
                "password": "credential-that-must-not-be-sent",
            },
        }
        try:
            artifact = scanner._build_validation_replay_artifact([finding])
        finally:
            scanner.close()

    record = artifact["records"][0]
    assert record["evidence_status"] == "confirmed"
    assert [hit["method"] for hit in handler.hits] == ["POST", "POST", "POST"]
    for hit in handler.hits:
        assert hit["params"]["title"] == "hello"
        assert "q" in hit["params"]
        assert "csrf_token" not in hit["params"]
        assert "password" not in hit["params"]
        assert hit["headers"].get("Authorization") is None
        assert hit["headers"].get("Host") != "evil.test"
        assert hit["headers"].get("Connection") != "close"
        assert hit["headers"]["X-Trace"] == "safe-trace"

    replay_request = record["replay"]["request"]
    omitted_headers = {
        item["name"]: item["reason"]
        for item in replay_request["omitted_headers"]
    }
    assert omitted_headers == {
        "Authorization": "credential",
        "Connection": "hop_by_hop",
        "Host": "authority_or_method_override",
        "X-Api-Key": "credential",
    }
    assert replay_request["body_field_names"] == ["q", "title"]
    rendered = json.dumps(artifact, sort_keys=True)
    assert "credential-that-must-not-be-sent" not in rendered
    assert bearer not in rendered


def test_cross_origin_finding_is_refused_before_transport(tmp_path):
    with _server() as (target, target_handler), _server() as (
        off_scope,
        off_scope_handler,
    ):
        scanner = _scanner(_base_url(target), tmp_path)
        try:
            artifact = scanner._build_validation_replay_artifact([
                _finding(f"{_base_url(off_scope)}/search"),
            ])
        finally:
            scanner.close()

    record = artifact["records"][0]
    assert record["evidence_status"] == "blocked"
    assert record["policy"]["error"]["code"] == "policy_denied"
    assert any(
        decision["decision"] == "denied"
        for decision in record["policy"]["decisions"]
    )
    assert target_handler.hits == []
    assert off_scope_handler.hits == []


def test_same_origin_redirect_is_followed_and_recorded(tmp_path):
    with _server(mode="same_origin_redirect") as (server, handler):
        scanner = _scanner(_base_url(server), tmp_path)
        try:
            artifact = scanner._build_validation_replay_artifact([
                _finding(f"{_base_url(server)}/start"),
            ])
        finally:
            scanner.close()

    record = artifact["records"][0]
    assert record["evidence_status"] == "confirmed"
    assert record["replay"]["response"]["final_url"].startswith(
        f"{_base_url(server)}/final",
    )
    assert len(record["replay"]["response"]["redirect_chain"]) == 1
    assert {hit["path"] for hit in handler.hits} == {"/start", "/final"}


def test_cross_origin_redirect_is_refused_without_leaking_request(tmp_path):
    with _server() as (off_scope, off_scope_handler):
        redirect_to = f"{_base_url(off_scope)}/sink"
        with _server(
            mode="cross_origin_redirect",
            redirect_to=redirect_to,
        ) as (target, _target_handler):
            scanner = _scanner(_base_url(target), tmp_path)
            try:
                artifact = scanner._build_validation_replay_artifact([
                    _finding(f"{_base_url(target)}/start"),
                ])
            finally:
                scanner.close()

    record = artifact["records"][0]
    assert record["evidence_status"] == "blocked"
    assert record["policy"]["error"]["code"] == "cross_origin_redirect"
    assert any(
        decision["decision"] == "denied"
        and decision["action"] == "follow_redirect"
        for decision in record["policy"]["decisions"]
    )
    assert off_scope_handler.hits == []


def test_response_evidence_is_redacted_truncated_bounded_and_private(tmp_path):
    with _server(mode="large_secret") as (server, _handler):
        scanner = _scanner(_base_url(server), tmp_path)
        try:
            artifact = scanner._build_validation_replay_artifact([
                _finding(f"{_base_url(server)}/search"),
            ])
            path = tmp_path / _VALIDATION_REPLAY_ARTIFACT
            scanner._save_validation_replay_artifact(path, artifact)
        finally:
            scanner.close()

    persisted = json.loads(path.read_text(encoding="utf-8"))
    replay_response = persisted["records"][0]["replay"]["response"]
    assert replay_response["body_excerpt_truncated"] is True
    assert len(replay_response["body_excerpt"].encode("utf-8")) <= 1024
    assert "secret-value-that-must-not-persist" not in json.dumps(persisted)
    assert "credential-that-must-not-persist" not in json.dumps(persisted)
    assert "[REDACTED]" in replay_response["body_excerpt"]
    assert path.stat().st_size <= _VALIDATION_REPLAY_MAX_ARTIFACT_BYTES
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_rate_limit_and_timeout_are_explicit_inconclusive_evidence(
    tmp_path,
    monkeypatch,
):
    with _server(mode="rate_limited") as (server, _handler):
        scanner = _scanner(_base_url(server), tmp_path / "rate")
        try:
            rate_artifact = scanner._build_validation_replay_artifact([
                _finding(f"{_base_url(server)}/search"),
            ])
        finally:
            scanner.close()

    rate_record = rate_artifact["records"][0]
    assert rate_record["evidence_status"] == "inconclusive"
    assert rate_record["controls"][0]["error"]["code"] == "rate_limited"
    assert rate_artifact["summary"]["request_count"] == 1

    scanner = _scanner("https://example.test", tmp_path / "timeout")

    def timeout(*_args, **_kwargs):
        raise requests.Timeout("request timed out")

    monkeypatch.setattr(scanner.client, "get", timeout)
    try:
        timeout_artifact = scanner._build_validation_replay_artifact([
            _finding("https://example.test/search"),
        ])
    finally:
        scanner.close()

    timeout_record = timeout_artifact["records"][0]
    assert timeout_record["evidence_status"] == "inconclusive"
    assert timeout_record["policy"]["error"]["code"] == "timeout"
    assert timeout_record["freshness"] == "not_obtained"


def test_malformed_and_unsupported_evidence_have_deterministic_shape(tmp_path):
    scanner = _scanner("https://example.test", tmp_path)
    malformed_method = _finding(
        "https://example.test/search",
        finding_id="WEB-METHOD",
        method="TRACE",
    )
    missing_payload = _finding(
        "https://example.test/search",
        finding_id="WEB-PAYLOAD",
        payload=None,
    )
    unsupported_json = _finding(
        "https://example.test/api",
        finding_id="WEB-JSON",
        method="POST",
        attack_vector="json_body",
    )
    scanner._validation_request_evidence[unsupported_json.id] = {
        "method": "POST",
        "url": unsupported_json.url,
        "headers": {"Content-Type": "application/json"},
        "body_kind": "json",
        "body": {"q": unsupported_json.confirmation_payload},
    }
    try:
        artifact = scanner._build_validation_replay_artifact([
            malformed_method,
            missing_payload,
            unsupported_json,
        ])
    finally:
        scanner.close()

    assert [
        record["evidence_status"] for record in artifact["records"]
    ] == ["malformed", "malformed", "unsupported"]
    expected_keys = set(artifact["records"][0])
    assert all(set(record) == expected_keys for record in artifact["records"])
    assert artifact["schema"] == "raptor.web.validation-replay.v1"
    assert artifact["security_boundary"] == {
        "network_actor": "trusted_scanner_process",
        "http_client": "WebClient",
        "execution_policy": "WebExecutionPolicy",
        "model_generated_requests": False,
        "selected_agent_target_network_access": False,
        "cross_origin_redirects": "refused",
        "credential_inputs": "excluded",
    }


def test_phase_validate_replays_before_dispatch_and_mirrors_artifact(
    tmp_path,
    monkeypatch,
):
    with _server() as (server, handler):
        web_dir = tmp_path / "web"
        validate_dir = tmp_path / "validate"
        scanner = _scanner(_base_url(server), web_dir)
        finding = _finding(f"{_base_url(server)}/search")

        monkeypatch.setenv("RAPTOR_AGENT_CLI", "claude")
        monkeypatch.setattr(
            "core.security.rule_of_two.is_interactive",
            lambda: True,
        )
        monkeypatch.setattr(
            "shutil.which",
            lambda name: f"/fake/{name}",
        )

        def fake_validate(**kwargs):
            assert handler.hits, "scanner replay must finish before dispatch"
            parent_artifact = web_dir / _VALIDATION_REPLAY_ARTIFACT
            assert parent_artifact.is_file()
            handoff = json.loads(
                Path(kwargs["analysis_report"]).read_text(encoding="utf-8"),
            )
            assert handoff["web_validation_replay"] == {
                "artifact": str(parent_artifact),
                "schema": "raptor.web.validation-replay.v1",
                "network_actor": "trusted_scanner_process",
                "model_generated_requests": False,
            }
            validate_dir.mkdir()
            return SimpleNamespace(
                ran=True,
                validate_dir=validate_dir,
                report_path=None,
            )

        monkeypatch.setattr(
            "core.orchestration.agentic_passes.run_validate_postpass",
            fake_validate,
        )
        try:
            result = scanner._phase_validate([finding])
        finally:
            scanner.close()

    assert result == [finding]
    parent = json.loads(
        (web_dir / _VALIDATION_REPLAY_ARTIFACT).read_text(encoding="utf-8"),
    )
    mirrored = json.loads(
        (validate_dir / _VALIDATION_REPLAY_ARTIFACT).read_text(
            encoding="utf-8",
        ),
    )
    assert mirrored == parent
    assert parent["records"][0]["evidence_status"] == "confirmed"
    assert "validate" in scanner._phases_completed


def test_no_verify_validate_emits_skipped_evidence_without_network(
    tmp_path,
    monkeypatch,
):
    with _server() as (server, handler):
        web_dir = tmp_path / "web"
        scanner = _scanner(
            _base_url(server),
            web_dir,
            verify_findings=False,
        )
        finding = _finding(f"{_base_url(server)}/search")
        dispatched = []

        monkeypatch.setenv("RAPTOR_AGENT_CLI", "claude")
        monkeypatch.setattr(
            "core.security.rule_of_two.is_interactive",
            lambda: True,
        )
        monkeypatch.setattr(
            "shutil.which",
            lambda name: f"/fake/{name}",
        )

        def fake_validate(**kwargs):
            dispatched.append(kwargs)
            return SimpleNamespace(
                ran=True,
                validate_dir=None,
                report_path=None,
            )

        monkeypatch.setattr(
            "core.orchestration.agentic_passes.run_validate_postpass",
            fake_validate,
        )
        try:
            result = scanner._phase_validate([finding])
        finally:
            scanner.close()

    assert result == [finding]
    assert len(dispatched) == 1
    assert handler.hits == []
    artifact = json.loads(
        (web_dir / _VALIDATION_REPLAY_ARTIFACT).read_text(encoding="utf-8"),
    )
    record = artifact["records"][0]
    assert record["evidence_status"] == "skipped"
    assert record["freshness"] == "not_obtained"
    assert record["reason"] == "live replay disabled by --no-verify"
    assert record["provenance"]["evidence_source"] == "skipped_no_verify"
    assert artifact["summary"]["request_count"] == 0
    assert artifact["summary"]["reused_request_count"] == 0
    assert artifact["summary"]["live_replay_enabled"] is False
    assert artifact["summary"]["verification_budget"]["consumed"] == 0
    assert artifact["summary"]["verification_budget"]["remaining"] == 10
    assert artifact["provenance"]["freshness_source"] == "not_obtained"
