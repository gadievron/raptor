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

