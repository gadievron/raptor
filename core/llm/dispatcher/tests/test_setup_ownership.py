"""An already-started upstream is reclaimed when later test setup fails."""

import importlib
import inspect
import threading

import pytest

from core.llm.dispatcher.auth import CredentialStore

_CALLERS = [
    (
        "test_body_limits",
        "TestBodyLimits",
        "_Upstream",
        ("test_provider_body_under_cap_accepted",),
    ),
    (
        "test_body_limits",
        "TestChildBudgetReservation",
        "_Upstream",
        ("test_reservation_released_after_forwarded_request",),
    ),
    (
        "test_child_ledger_vetoed_death",
        "TestChildLedgerOnVetoedDeath",
        "_AbortSSEUpstream",
        ("test_one_booking_and_reservation_released",),
    ),
    (
        "test_child_tokens",
        "TestMintAndDispatch",
        "_Upstream",
        (
            "test_child_token_round_trip_and_booking",
            "test_streamed_response_books_from_final_usage_frame",
            "test_streamed_abort_books_what_upstream_reported",
            "test_unpriced_model_books_zero_and_flags",
        ),
    ),
    (
        "test_child_tokens",
        "TestEnforcement",
        "_Upstream",
        (
            "test_model_not_in_allowlist_rejected",
            "test_allowlist_matches_across_id_spellings",
            "test_budget_exhaustion_refuses_before_forward",
            "test_provider_scope_and_shape",
        ),
    ),
    (
        "test_child_tokens",
        "TestReservationIsACap",
        "_Upstream",
        (
            "test_huge_declared_max_tokens_refused_at_admission",
            "test_booked_spend_at_budget_refuses_next_admission",
            "test_count_tokens_exempt_from_reservation_ceiling",
            "test_fragment_masquerade_cannot_claim_the_exemption",
            "test_count_tokens_still_enforces_scope_and_exhaustion",
        ),
    ),
    (
        "test_child_tokens",
        "TestReservationIsACap",
        "_GatedUpstream",
        ("test_release_returns_captured_amount_after_knob_lowered",),
    ),
    (
        "test_child_tokens",
        "TestLifecycle",
        "_Upstream",
        (
            "test_expiry_enforced_and_spend_survives",
            "test_revocation",
            "test_child_rows_use_public_token_id_not_secret_prefix",
            "test_audit_never_contains_token_value",
        ),
    ),
    (
        "test_child_tokens",
        "TestPlanes",
        "_Upstream",
        (
            "test_tcp_plane_serves_child_tokens",
            "test_tcp_plane_refuses_worker_tokens",
            "test_admin_unreachable_with_child_token",
            "test_admin_endpoints_with_worker_token_over_uds",
            "test_loopback_admin_op_returns_usable_shared_port",
            "test_loopback_admin_op_refused_for_child_tokens",
            "test_mint_request_budget_travels_and_enforces",
        ),
    ),
    (
        "test_child_tokens",
        "TestAnthropicSDKDialect",
        "_Upstream",
        (
            "test_x_api_key_dialect_books_once_and_releases_reservation",
            "test_x_api_key_dialect_scope_still_enforced",
            "test_x_api_key_dialect_budget_exhaustion_402",
        ),
    ),
    (
        "test_error_row_provenance",
        "TestErrorRowProvenance",
        "MockUpstream",
        (
            "test_pre_response_failure_marks_response_not_started",
            "test_mid_response_failure_marks_response_started",
            "test_retry_row_carries_the_same_provenance_fields",
        ),
    ),
    (
        "test_orphan_cancel",
        "TestOrphanCancel",
        "_CaptiveUpstream",
        (
            "_drive_disconnect_mid_stream",
            "test_healthy_slow_upstream_with_live_worker_is_untouched",
            "test_worker_close_after_full_response_is_normal_completion",
            "test_worker_close_during_post_body_dwell_is_normal_completion",
            "test_final_chunk_is_held_until_watcher_stop_returns",
            "test_worker_disconnect_during_head_dwell_aborts_at_head",
        ),
    ),
    (
        "test_orphan_cancel",
        "TestAcquireFailureRetiresWatcher",
        "_CaptiveUpstream",
        ("test_acquire_raise_stops_watcher_and_writes_no_orphan_row",),
    ),
    (
        "test_orphan_cancel",
        "TestWatcherAbortIsNotShardEvidence",
        "_CaptiveUpstream",
        ("test_watcher_cancel_does_not_drain_the_shard",),
    ),
    (
        "test_upstream_stale_retry",
        "TestUpstreamStaleRetry",
        "MockUpstream",
        (
            "test_half_open_reuse_recovers_transparently",
            "test_persistent_pre_response_failure_is_bounded",
            "test_slow_pre_response_death_past_ceiling_is_not_retried",
            "test_large_body_stale_reuse_recovers",
            "test_mid_response_failure_is_not_retried",
        ),
    ),
    (
        "test_upstream_stale_retry",
        "TestStaleRetryShardEvidence",
        "MockUpstream",
        (
            "test_recovered_stale_death_still_strikes",
            "test_consecutive_stale_deaths_drain_at_threshold",
            "test_clean_completion_still_resets_after_stale_strike",
        ),
    ),
    (
        "test_upstream_state_header",
        "TestUpstreamStateHeader",
        "MockUpstream",
        (
            "test_relayed_head_is_stamped_response_started",
            "test_pre_response_502_is_stamped_pre_response",
            "test_control_plane_responses_carry_no_stamp",
        ),
    ),
    (
        "test_upstream_state_header",
        "TestUpstreamStateHeader",
        "_CannedUpstream",
        (
            "test_upstream_copy_of_the_header_cannot_impersonate",
            "test_relayed_error_head_carries_no_stamp",
            "test_spoofed_stamp_on_error_head_is_stripped",
        ),
    ),
    (
        "test_usage_scan_seam",
        "TestAdmissionGate",
        "_EchoUpstream",
        (
            "test_scoped_token_refused_pre_upstream_when_jail_unavailable",
            "test_worker_token_relays_when_jail_unavailable",
        ),
    ),
]
_CASES = [
    (module, cls, method, factory)
    for module, cls, factory, methods in _CALLERS
    for method in methods
]


@pytest.mark.parametrize(
    "module_name,class_name,method_name,factory_name",
    _CASES,
    ids=[f"{m}.{c}.{f}" for m, c, f, _ in _CASES],
)
def test_dispatcher_failure_reclaims_started_upstream(
    module_name,
    class_name,
    method_name,
    factory_name,
    tmp_path,
    monkeypatch,
):
    module = importlib.import_module(f"core.llm.dispatcher.tests.{module_name}")
    upstreams = []
    threads = []
    real_factory = getattr(module, factory_name)
    real_thread = threading.Thread

    def thread(*args, **kwargs):
        instance = real_thread(*args, **kwargs)
        threads.append(instance)
        return instance

    def upstream(*args, **kwargs):
        instance = real_factory(*args, **kwargs)
        upstreams.append(instance)
        return instance

    def fail_dispatcher(*args, **kwargs):
        raise RuntimeError("injected dispatcher creation failure")

    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {"anthropic": "fixture-key", "openai": None, "gemini": None}
    method = getattr(getattr(module, class_name)(), method_name)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(threading, "Thread", thread)
            patcher.setattr(module, factory_name, upstream)
            patcher.setattr(module, "_make_dispatcher", fail_dispatcher)
            available = {
                "fake_creds": creds,
                "tmp_path": tmp_path,
                "monkeypatch": patcher,
            }
            kwargs = {
                name: available[name] for name in inspect.signature(method).parameters
            }
            with pytest.raises(
                RuntimeError, match="injected dispatcher creation failure"
            ):
                method(**kwargs)
        assert len(upstreams) == 1
        instance = upstreams[0]
        listener = getattr(instance, "_listener", None)
        if listener is None:
            listener = instance._server.socket
        assert listener.fileno() == -1, (
            "later setup failure left upstream listener open"
        )
        for t in threads:
            t.join(timeout=2)
        assert all(not t.is_alive() for t in threads), (
            "upstream thread survived cleanup"
        )
    finally:
        # Independent cleanup contains the failure-injection battery on the old code.
        for instance in upstreams:
            instance.shutdown()
        for t in threads:
            if t.ident is not None:
                t.join(timeout=3)
