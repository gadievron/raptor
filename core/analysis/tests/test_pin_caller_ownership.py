"""Retained text readers close after post-verification failures; no tools run."""
import pytest

from core.analysis import binary_oracle as consumer
from core.analysis.tests.test_pin_reader_ownership import pin_io as pin_io


@pytest.mark.parametrize("primary_type", [MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_failed_post_hash_closes_retained_reader(pin_io, monkeypatch, primary_type, close_type):
    primary = primary_type("after native post-verification hash")
    calls = []

    def classify(names, path):
        calls.append((names, path))
        pin_io["primary"] = primary
        pin_io["cleanup"] = close_type("after native close") if close_type else None
        return {}

    def no_tool(*_args, **_kwargs):
        pytest.fail("post-verification error reached tool metadata acquisition")

    monkeypatch.setattr(consumer, "classify_binary_evidence", classify)
    monkeypatch.setattr(consumer, "read_build_id", no_tool)
    inventory = {"files": [{"language": "c", "items": [{"name": "plain"}]}]}
    with pytest.raises(primary_type) as raised:
        consumer.enrich_inventory_with_binary_oracle(
            inventory, [pin_io["path"]],
            identity_pins={str(pin_io["path"]): pin_io["pin"]})
    assert raised.value is primary
    assert calls == [(["plain"], pin_io["path"])]
    assert pin_io["hashes"] == 2
    assert pin_io["closes"] == 1
    assert pin_io["streams"][0].closed


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_healthy_post_check_closes_retained_reader(pin_io, monkeypatch, close_type):
    calls = []
    monkeypatch.setattr(consumer, "classify_binary_evidence", lambda *_args: {})

    def build_id(path):
        calls.append(path)
        return ""

    monkeypatch.setattr(consumer, "read_build_id", build_id)
    inventory = {"files": [{"language": "c", "items": [{"name": "plain"}]}]}
    cleanup = close_type("after native close") if close_type else None
    pin_io["cleanup"] = cleanup

    def run():
        return consumer.enrich_inventory_with_binary_oracle(
            inventory, [pin_io["path"]],
            identity_pins={str(pin_io["path"]): pin_io["pin"]})

    if close_type in (KeyboardInterrupt, SystemExit):
        with pytest.raises(close_type) as raised:
            run()
        assert raised.value is cleanup
        assert calls == []
    else:
        result = run()
        assert result["classified"] == 0
        assert calls == [pin_io["path"]]
    assert pin_io["hashes"] == 2
    assert pin_io["closes"] == 1
    assert pin_io["streams"][0].closed
