"""Malformed extractor envelopes cannot be cached as empty evidence."""

from core.dataflow.llm_extractor import extract_from_content


def test_missing_or_duplicate_validator_fields_are_diagnosed_not_cached():
    for malformed in ('{}', '{"error":"busy"}', '{"validators":[],"validators":[]}'):
        responses = iter((malformed, '{"validators":[]}'))
        calls = []
        cache = {}

        def extractor(bundle):
            calls.append(bundle)
            return next(responses)

        kwargs = dict(file_path="fixture.py", content="inert text\n", extractor=extractor, cache=cache)
        first, errors = extract_from_content(**kwargs)
        assert first == ()
        assert errors
        assert cache == {}
        second, errors = extract_from_content(**kwargs)
        assert second == ()
        assert errors == []
        assert cache
        assert len(calls) == 2
        assert extract_from_content(**kwargs) == ((), [])
        assert len(calls) == 2
