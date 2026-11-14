"""Read-policy cache identity with owned inputs and existing MAC helpers."""

import json
from types import ModuleType

import pytest

from core.audit import codeql_backend as backend
from core.audit.prep_cache import content_fingerprint, load_prep_cache, prep_cache_path, write_prep_cache
from core.inventory.sink_discovery import SinkDiscoveryResult, UnreachableVerdict
from core.testing.module_views import scoped_function_imports


@pytest.fixture
def fingerprint(tmp_path):
    path = tmp_path / "owned.c"
    path.write_bytes(b"owned scalar")
    supplied = ModuleType("core.inventory.sink_discovery")
    supplied.iter_discovery_source_files = lambda root, **kwargs: iter([(path, path.name, "c")])
    supplied._PER_FILE_CAP = 16
    supplied._AGGREGATE_CAP = 32

    def compute(*, per_file=16, aggregate=32):
        supplied._PER_FILE_CAP = per_file
        supplied._AGGREGATE_CAP = aggregate
        with scoped_function_imports(backend, ("_sink_discovery_fingerprint",),
                                     {"core.inventory.sink_discovery": supplied}):
            return backend._sink_discovery_fingerprint(tmp_path, None)

    return path, compute


def test_policy_caps_separate_existing_source_fingerprint(fingerprint):
    path, compute = fingerprint
    old = content_fingerprint([(path.name, path.read_bytes())])
    current = compute()
    assert isinstance(current, str) and len(current) == 64
    assert current != old
    assert compute() == current
    assert compute(per_file=17) != current
    assert compute(aggregate=33) != current


def test_old_policy_misses_and_current_false_verdicts_keep_mac_validation(tmp_path, fingerprint):
    path, compute = fingerprint
    old = content_fingerprint([(path.name, path.read_bytes())])
    current = compute()
    run = tmp_path / "owned-run"
    run.mkdir()
    verdict = UnreachableVerdict("owned.c", "candidate", False, "discovery incomplete: source read refused")
    result = SinkDiscoveryResult([], [], [], {}, unreachable_eligible={("owned.c", "candidate"): verdict})
    payload = result.to_full_dict()
    write_prep_cache(run, "owned.json", old, payload, label="owned sink")
    assert load_prep_cache(run, "owned.json", old, label="owned sink") == payload
    assert load_prep_cache(run, "owned.json", current, label="owned sink") is None
    write_prep_cache(run, "owned.json", current, payload, label="owned sink")
    loaded = load_prep_cache(run, "owned.json", current, label="owned sink")
    assert SinkDiscoveryResult.from_full_dict(loaded).unreachable_eligible == result.unreachable_eligible
    cache_path = prep_cache_path(run, "owned.json")
    row = json.loads(cache_path.read_text())
    row["payload"]["unreachable_eligible"][0]["eligible"] = True
    cache_path.write_text(json.dumps(row))
    assert load_prep_cache(run, "owned.json", current, label="owned sink") is None
