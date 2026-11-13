"""Legacy successful-empty cache entries cannot bypass stricter parsing."""

import hashlib

from core.dataflow.llm_extractor import build_cache_key, extract_from_content


def test_old_response_cache_is_not_reused_under_stricter_validation():
    content = "pass\n"
    key = build_cache_key(file_content_sha=hashlib.sha256(content.encode()).hexdigest(), language="python", model_family="default", file_path="fixture.py")
    legacy = ":".join("response_v1" if part.startswith("response_v") else part for part in key.split(":"))
    cache = {legacy: ()}
    responses = iter(('{}', '{"validators":[]}'))
    calls = []

    def extractor(bundle):
        calls.append(bundle)
        return next(responses)

    kwargs = dict(file_path="fixture.py", content=content, extractor=extractor, cache=cache)
    candidates, errors = extract_from_content(**kwargs)
    assert candidates == ()
    assert errors
    assert len(calls) == 1
    assert cache == {legacy: ()}
    assert extract_from_content(**kwargs) == ((), [])
    assert len(calls) == 2
    assert len(cache) == 2
    assert extract_from_content(**kwargs) == ((), [])
    assert len(calls) == 2
