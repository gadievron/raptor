"""The attempt fingerprint selects a closed accounting schema, not vocabulary."""

from core.llm.telemetry import TelemetrySink


def test_usage_fingerprint_has_only_financial_identity_and_usage_fields():
    keys = ("attempt_id", "call_id", "work_id", "call_class", "provider", "model",
            "event", "cost_usd", "tokens_in", "tokens_out", "cache_read_tokens",
            "cache_write_tokens", "billing_state", "reservation_usd", "usage_revision")
    row = {key: index for index, key in enumerate(keys)}
    row.update(ts="delivery-time", beneficiaries=["first"], unrelated="context")
    actual = TelemetrySink._usage_fingerprint(row)
    assert tuple(actual) == keys
    assert actual == {key: row[key] for key in keys}
    assert TelemetrySink._usage_fingerprint({**row, "ts": "later",
                                           "beneficiaries": ["second"]}) == actual


def test_usage_revision_and_billing_changes_are_not_hidden_by_delivery_identity():
    original = {"attempt_id": "attempt", "usage_revision": 1, "cost_usd": .25}
    before = TelemetrySink._usage_fingerprint(original)
    assert TelemetrySink._usage_fingerprint({**original, "usage_revision": 2}) != before
    assert TelemetrySink._usage_fingerprint({**original, "cost_usd": .5}) != before
