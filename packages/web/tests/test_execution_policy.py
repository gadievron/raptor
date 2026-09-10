import pytest

from core.security.redaction import redact_url_secrets_only
from packages.web.execution_policy import WebExecutionPolicy, WebPolicyError


def test_policy_writes_scope_receipt_and_allows_in_scope_active_actions():
    policy = WebExecutionPolicy.for_target("https://example.test/app")

    policy.authorize(
        tool_id="raptor-http",
        url="https://example.test/search?q=1",
        risk="active",
        action="http_request",
    )

    report = policy.report()
    assert report["scope_receipt"]["allowed_origins"] == ["https://example.test"]
    assert report["scope_receipt"]["approval_level"] == "active"
    assert report["summary"]["allowed_actions"] == 1


def test_policy_preserves_operator_target_identity_while_normalizing_origin():
    target = "HTTPS://Example.Test:443/app/"
    policy = WebExecutionPolicy.for_target(target)

    receipt = policy.report()["scope_receipt"]
    assert receipt["target"] == target
    assert receipt["allowed_origins"] == ["https://example.test"]


def test_policy_redacts_receipt_but_reuses_exact_target_credentials():
    password = "operator-password"
    token = "operator-access-token"
    target = (
        f"https://alice:{password}@example.test/search"
        f"?access_token={token}&mode=scan"
    )
    policy = WebExecutionPolicy.for_target(target)
    replay_url = f"{target}&q=probe"

    prepared = policy.prepare_replay_request(
        method="GET",
        url=replay_url,
        action="validation_replay",
    )

    receipt = policy.report()["scope_receipt"]
    assert receipt["target"] == redact_url_secrets_only(target)
    assert password not in receipt["target"]
    assert token not in receipt["target"]
    assert prepared.url == replay_url
    metadata_url = prepared.metadata()["url"]
    assert password not in metadata_url
    assert token not in metadata_url
    assert "[REDACTED]" in metadata_url


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.test/app",
        "file:///tmp/app",
        "/tmp/app",
        "./app",
        "example.test/app",
        "https:///app",
        "https://",
    ],
)
def test_policy_rejects_non_http_or_hostless_targets(target):
    with pytest.raises(WebPolicyError):
        WebExecutionPolicy.for_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "https://example.test:not-a-port/",
        "https://example.test:65536/",
        "https://example.test:/",
        "https://[::1/",
    ],
)
def test_policy_rejects_malformed_ports_and_authorities(target):
    with pytest.raises(WebPolicyError):
        WebExecutionPolicy.for_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "https://example.test/\nadmin",
        "https://example.test/\x00admin",
        "https://example.test/\x7fadmin",
        "https://example.test/\x85admin",
    ],
)
def test_policy_rejects_control_characters(target):
    with pytest.raises(WebPolicyError, match="control characters"):
        WebExecutionPolicy.for_target(target)


def test_policy_blocks_off_scope_origin_before_action_runs():
    policy = WebExecutionPolicy.for_target("https://example.test")

    try:
        policy.authorize(
            tool_id="raptor-http",
            url="https://evil.test/",
            risk="active",
            action="http_request",
        )
    except WebPolicyError as exc:
        assert "outside scope receipt" in str(exc)
    else:  # pragma: no cover - explicit failure reads better here
        raise AssertionError("off-scope action should have been denied")

    assert policy.report()["summary"]["denied_actions"] == 1


def test_policy_requires_explicit_approval_for_intrusive_tools():
    policy = WebExecutionPolicy.for_target("https://example.test", approval_level="active")

    try:
        policy.authorize(
            tool_id="sqlmap",
            url="https://example.test/item?id=1",
            risk="intrusive",
            action="external_validator",
        )
    except WebPolicyError as exc:
        assert "only approves active actions" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("intrusive tool should have been denied")

    approved = WebExecutionPolicy.for_target(
        "https://example.test",
        approval_level="active",
        approved_tools=["sqlmap"],
    )
    approved.authorize(
        tool_id="sqlmap",
        url="https://example.test/item?id=1",
        risk="intrusive",
        action="external_validator",
    )
    assert approved.report()["summary"]["allowed_actions"] == 1



def test_client_records_authorized_requests_in_policy_audit(tmp_path):
    from packages.web.client import WebClient
    from packages.web.execution_policy import WebExecutionPolicy

    policy = WebExecutionPolicy.for_target("https://example.test")
    client = WebClient("https://example.test", execution_policy=policy)
    try:
        url = client._build_url("login")
    finally:
        client.close()

    assert url == "https://example.test/login"
    report = policy.report()
    assert report["summary"]["allowed_actions"] == 1
    assert report["recent_decisions"][0]["action"] == "http_request"
    assert report["recent_decisions"][0]["tool_id"] == "raptor-http"


def test_replay_request_sanitizes_credentials_and_unsafe_headers():
    policy = WebExecutionPolicy.for_target("https://example.test")

    prepared = policy.prepare_replay_request(
        method="post",
        url="https://example.test/submit",
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer credential",
            "Connection": "close",
            "Host": "evil.test",
            "X-Api-Key": "credential",
        },
        form_data={
            "q": "' OR 1=1--",
            "title": "hello",
            "csrf_token": "credential",
        },
        required_body_field="q",
        action="validation_replay",
    )

    assert prepared.method == "POST"
    assert prepared.headers == {"Accept": "application/json"}
    assert prepared.form_data == {
        "q": "' OR 1=1--",
        "title": "hello",
    }
    assert prepared.metadata()["omitted_headers"] == [
        {"name": "Authorization", "reason": "credential"},
        {"name": "Connection", "reason": "hop_by_hop"},
        {"name": "Host", "reason": "authority_or_method_override"},
        {"name": "X-Api-Key", "reason": "credential"},
    ]
    assert prepared.metadata()["omitted_body_fields"] == [
        {"name": "csrf_token", "reason": "credential"},
    ]


@pytest.mark.parametrize(
    ("method", "url", "match"),
    [
        ("DELETE", "https://example.test/x", "only GET and POST"),
        ("GET", "https://evil.test/x", "outside scope receipt"),
        (
            "GET",
            "https://example.test/x?access_token=credential",
            "credential-bearing query",
        ),
    ],
)
def test_replay_request_refuses_malformed_or_unsafe_evidence(
    method,
    url,
    match,
):
    policy = WebExecutionPolicy.for_target("https://example.test")

    with pytest.raises(WebPolicyError, match=match):
        policy.prepare_replay_request(
            method=method,
            url=url,
            action="validation_replay",
        )

    decision = policy.decisions_since(0)[-1]
    assert decision["decision"] == "denied"
    assert decision["tool_id"] == "raptor-validation-replay"


def test_replay_request_requires_active_approval():
    policy = WebExecutionPolicy.for_target(
        "https://example.test",
        approval_level="passive",
    )

    with pytest.raises(WebPolicyError, match="only approves passive"):
        policy.prepare_replay_request(
            method="GET",
            url="https://example.test/search?q=test",
            action="validation_replay",
        )

    assert policy.report()["summary"]["denied_actions"] == 1
