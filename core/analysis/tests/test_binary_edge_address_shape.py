"""Boolean JSON fields are not binary function addresses."""

import pytest

from core.analysis import binary_oracle_edges as edges


@pytest.fixture(autouse=True)
def no_binary_work(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("direct address adapter entered binary processing")

    for name in ("_identity_cache_key", "_content_hash", "_try_graph_store",
                 "extract_direct_call_edges"):
        monkeypatch.setattr(edges, name, forbidden)


@pytest.mark.parametrize("record", [
    {"addr": True}, {"addr": False}, {"offset": True}, {"offset": False},
])
def test_boolean_address_is_unavailable(record):
    before = dict(record)
    assert edges._fn_addr(record) is None
    assert record == before


@pytest.mark.parametrize("record, expected", [
    ({"addr": True, "offset": 0}, 0),
    ({"addr": False, "offset": 4096}, 4096),
    ({"addr": 4096, "offset": True}, 4096),
    ({"addr": 0, "offset": 4096}, 0),
])
def test_integer_addresses_keep_precedence_and_zero(record, expected):
    before = dict(record)
    result = edges._fn_addr(record)
    assert type(result) is int
    assert result == expected
    assert record == before
