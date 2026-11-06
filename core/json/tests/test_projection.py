import hashlib
import io
import json

import pytest

from core.json.projection import project_object


class Chunks(io.BytesIO):
    def __init__(self, data, chunk):
        super().__init__(data)
        self.chunk = chunk
        self.requests = []
    def read(self, size=-1):
        assert size >= 0
        self.requests.append(size)
        return super().read(min(size, self.chunk))


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 65536])
def test_projection_keeps_original_hash_and_semantics_across_chunk_boundaries(chunk):
    value = {"header": {"unicode": "©\n\""}, "rows": [{"n": 1.23e10}, {"n": -12}, None], "trailer": True}
    raw = json.dumps(value, ensure_ascii=False).encode()
    stream = Chunks(raw, chunk)
    result, sha = project_object(stream, max_bytes=len(raw))
    assert result == value
    assert sha == hashlib.sha256(raw).hexdigest()
    assert stream.tell() == len(raw)


def test_rows_can_be_discarded_without_keeping_their_payload():
    raw = b'{"rows":[' + b','.join(b'{"payload":"' + b'x'*2000 + b'"}' for _ in range(100)) + b']}'
    observed = []
    result, sha = project_object(Chunks(raw, 97), max_bytes=len(raw), projectors={"rows": lambda row: None},
                                 observe=lambda key, row: observed.append(len(row["payload"])))
    assert result == {"rows": []}
    assert observed == [2000] * 100
    assert sha == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"rows":[{"a":1,"a":2}]}',
                                  b'{"rows":[NaN]}', b'{"rows":[1e999]}',
                                  b'{"x":"\\ud800"}', b'{"x":"\xff"}',
                                  b'{"x":[1,]}', b'{"x":1,}', b'{"x":1} trailing', b'{"x":1e}', b'[]'])
def test_invalid_values_are_refused_even_when_projected_away(raw):
    with pytest.raises((ValueError, UnicodeError)):
        project_object(Chunks(raw, 1), max_bytes=len(raw), projectors={"rows": lambda row: None})


def test_byte_budget_and_nesting_are_enforced():
    with pytest.raises(ValueError, match="budget"):
        project_object(io.BytesIO(b'{"x":1}'), max_bytes=4)
    raw = b'{"rows":[' + b'['*130 + b'0' + b']'*130 + b']}'
    with pytest.raises(ValueError, match="nesting"):
        project_object(io.BytesIO(raw), max_bytes=len(raw), projectors={"rows": lambda row: None})


@pytest.mark.parametrize("chunk", [1, 3, 65536])
def test_top_level_array_projection_keeps_hash_and_discards_descriptions(chunk):
    from core.json.projection import project_array
    value = [{"id": "one", "description": "x" * 300}, None, {"id": "two"}]
    raw = json.dumps(value).encode()
    result, sha = project_array(Chunks(raw, chunk), max_bytes=len(raw),
                                project=lambda row: {"id": row["id"]} if row else None)
    assert result == [{"id": "one"}, {"id": "two"}]
    assert sha == hashlib.sha256(raw).hexdigest()
    assert project_array(io.BytesIO(raw), max_bytes=len(raw))[0] == value


@pytest.mark.parametrize("raw", [b'{}', b'[1,]', b'[{"x":1,"x":2}]', b'[NaN]', b'[1e999]', b'[] garbage'])
def test_projected_array_invalid_values_fail_even_when_discarded(raw):
    from core.json.projection import project_array
    with pytest.raises(ValueError):
        project_array(io.BytesIO(raw), max_bytes=len(raw), project=lambda row: None)
