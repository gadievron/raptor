"""Already-computed request identities do not change dispatch or retries."""
import json

import pytest

from core.llm import breaker, telemetry
from core.llm.client import _telemetry_cache_key
from core.llm.providers import LLMResponse
from core.testing import FakeStructuredProvider, install_provider, make_test_client
from core.testing.module_state import isolated_module_state


class Provider(FakeStructuredProvider):
    def __init__(self, failures=0):
        super().__init__({'status': 'ok'}, '{"status":"ok"}')
        self.failures = failures

    def _fail(self):
        if self.failures:
            self.failures -= 1
            self.calls += 1
            raise TimeoutError('owned read timeout')

    def generate(self, prompt, system_prompt=None, **kwargs):
        self._fail()
        self.calls += 1
        self.last_kwargs = dict(kwargs)
        self.total_cost += 0.001
        return LLMResponse('owned answer', 'test-primary', 'anthropic', 10, 0.001, 'stop')

    def generate_structured(self, prompt, schema, system_prompt=None, **kwargs):
        self._fail()
        return super().generate_structured(prompt, schema, system_prompt, **kwargs)


@pytest.fixture
def run(tmp_path):
    path = tmp_path / 'telemetry.jsonl'
    sink = telemetry.TelemetrySink(path)
    with isolated_module_state(telemetry, {'_sink': sink}, lock=telemetry._sink_lock), \
            isolated_module_state(breaker, {'_singleton': None}, lock=breaker._singleton_lock):
        yield tmp_path, path


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def call(client, structured, **kwargs):
    if structured:
        return client.generate_structured('owned prompt', kwargs.pop('schema', {'type': 'object'}),
                                          call_class='identity-probe', **kwargs)
    return client.generate('owned prompt', call_class='identity-probe', **kwargs)


@pytest.mark.parametrize('structured', [False, True])
def test_fresh_and_cache_hit_reuse_existing_key_once_per_call(run, monkeypatch, structured):
    tmp_path, path = run
    client = make_test_client(tmp_path)
    provider = Provider()
    install_provider(client, provider)
    name = '_get_structured_cache_key' if structured else '_get_cache_key'
    original = getattr(client, name)
    keys = []

    def key(*args, **kwargs):
        value = original(*args, **kwargs)
        keys.append(value)
        return value

    monkeypatch.setattr(client, name, key)
    first = call(client, structured, temperature=0.2)
    second = call(client, structured, temperature=0.2)
    records = rows(path)
    assert len(keys) == 2
    assert provider.calls == 1
    assert len(records) == 2
    assert [r['request_cache_key'] for r in records] == keys
    assert keys[0] == keys[1]
    assert [r['disposition'] for r in records] == ['ok', 'cache_hit']
    assert 'request_cache_key' not in provider.last_kwargs
    assert provider.last_kwargs['temperature'] == 0.2
    if structured:
        assert first.result == second.result == {'status': 'ok'}
    else:
        assert first.content == second.content == 'owned answer'


@pytest.mark.parametrize('structured', [False, True])
def test_failed_attempt_and_success_keep_key_and_original_retry_count(run, structured):
    tmp_path, path = run
    client = make_test_client(tmp_path, enable_caching=False, max_retries=2)
    provider = Provider(failures=1)
    install_provider(client, provider)
    call(client, structured)
    records = rows(path)
    assert provider.calls == 2
    assert len(records) == 2
    assert records[0]['request_cache_key'] == records[1]['request_cache_key']
    assert records[0]['event'] == 'attempt_failed'
    assert records[0]['disposition'] == 'timeout'
    assert records[1]['disposition'] == 'ok'
    assert [r['attempt'] for r in records] == [1, 2]


def test_schema_and_temperature_keep_distinct_existing_identities(run):
    tmp_path, path = run
    client = make_test_client(tmp_path)
    provider = Provider()
    install_provider(client, provider)
    call(client, True, temperature=0.1)
    call(client, True, temperature=0.2)
    call(client, True, temperature=0.1, schema={'type': 'object', 'description': 'owned variant'})
    assert provider.calls == 3
    records = rows(path)
    assert len({r['request_cache_key'] for r in records}) == 3
    assert all(r['structured'] and r['disposition'] == 'ok' for r in records)


@pytest.mark.parametrize('key', [None, 0, '', 'secret-not-a-digest', 'A' * 64, 'g' * 64, 'a' * 65])
def test_unknown_keys_do_not_become_prompt_or_adapter_data(key):
    assert _telemetry_cache_key(key) is None


def test_key_adapters_do_not_gain_callbacks():
    class Key(str):
        def __len__(self):
            pytest.fail('key adapter length was probed')

        def strip(self, *args):
            pytest.fail('key adapter contents were probed')

    assert _telemetry_cache_key(Key('a' * 64)) is None
    assert _telemetry_cache_key('a' * 64) == 'a' * 64
