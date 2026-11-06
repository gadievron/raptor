"""Reason membership scales without changing ordered summary output."""
from core.sandbox import egress_summary as egress


def test_reasons_preserve_first_seen_order_per_endpoint(tmp_path, monkeypatch):
    events = [
        {'host': 'one.test', 'port': port, 'result': result}
        for port, result in [(443, 'denied_host'), (443, 'dns_failed'),
                             (443, 'denied_host'), (80, 'denied_host'),
                             (443, 'would_deny_policy'), (443, 'dns_failed'),
                             (443, 'allowed'), (443, 'unknown_result')]]
    monkeypatch.setattr(egress, '_read_proxy_events', lambda run, *, issues=None: events)
    summary = egress.summarise_egress(tmp_path)
    endpoints = {entry['port']: entry for entry in summary['hosts']}
    assert endpoints[443]['reasons'] == ['denied_host', 'dns_failed', 'would_deny_policy']
    assert endpoints[80]['reasons'] == ['denied_host']
    assert (summary['allowed'], summary['denied'], summary['failed']) == (1, 4, 3)


def test_distinct_reason_comparisons_are_linear(tmp_path, monkeypatch):
    class CountedReason(str):
        comparisons = 0
        __hash__ = str.__hash__

        def __eq__(self, other):
            type(self).comparisons += 1
            return str.__eq__(self, other)

    count = 2000
    reasons = [CountedReason(f'denied_reason_{i}') for i in range(count)]
    events = [{'host': 'one.test', 'port': 443, 'result': reason} for reason in reasons]
    monkeypatch.setattr(egress, '_read_proxy_events', lambda run, *, issues=None: events)
    summary = egress.summarise_egress(tmp_path)
    comparisons = CountedReason.comparisons
    assert summary['denied'] == count
    assert summary['hosts'][0]['reasons'] == reasons
    assert comparisons < count * 10


def test_equal_distinct_string_objects_are_deduplicated(tmp_path, monkeypatch):
    events = [{'host': 'one.test', 'port': 443,
               'result': ''.join(['denied_', 'host'])} for _ in range(100)]
    monkeypatch.setattr(egress, '_read_proxy_events', lambda run, *, issues=None: events)
    summary = egress.summarise_egress(tmp_path)
    assert summary['denied'] == 100
    assert summary['hosts'][0]['reasons'] == ['denied_host']
