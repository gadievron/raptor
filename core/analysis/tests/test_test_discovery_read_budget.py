"""Test discovery rechecks its existing byte limit on the opened file."""

from core.analysis import test_discovery as discovery
from core.audit.prep_cache import content_fingerprint


_ATTACK = b"def test_attack():\n    assert attack()\n"
_HEALTHY = b"def test_healthy():\n    assert healthy()\n"


def _source_bytes(size):
    padding = size - len(_ATTACK)
    return _ATTACK + (b"#\n" * ((padding + 1) // 2))[:padding]


def _grow_after_enumeration(monkeypatch, changed, size):
    original = discovery._find_test_files

    def enumerate_then_grow(target):
        files, skipped = original(target)
        assert changed in files
        changed.write_bytes(_source_bytes(size))
        return files, skipped

    monkeypatch.setattr(discovery, "_find_test_files", enumerate_then_grow)


def test_discovery_skips_source_that_grows_after_enumeration(tmp_path, monkeypatch):
    tests = tmp_path / "tests"
    tests.mkdir()
    changed = tests / "test_changed.py"
    changed.write_bytes(_ATTACK)
    (tests / "test_healthy.py").write_bytes(_HEALTHY)
    _grow_after_enumeration(monkeypatch, changed, 500_001)

    result = discovery.discover_tests(tmp_path)

    assert set(result) == {"healthy"}
    assert result["healthy"][0].in_test_tree is True


def test_fingerprint_refuses_growth_with_existing_read_error_marker(tmp_path, monkeypatch):
    tests = tmp_path / "tests"
    tests.mkdir()
    changed = tests / "test_changed.py"
    changed.write_bytes(_ATTACK)
    _grow_after_enumeration(monkeypatch, changed, 500_001)

    fingerprint = discovery._test_tree_fingerprint(tmp_path)

    assert fingerprint == content_fingerprint([(str(changed), b"")])


def test_source_just_below_existing_limit_remains_discoverable(tmp_path, monkeypatch):
    tests = tmp_path / "tests"
    tests.mkdir()
    changed = tests / "test_changed.py"
    changed.write_bytes(_ATTACK)
    _grow_after_enumeration(monkeypatch, changed, 499_999)

    assert set(discovery.discover_tests(tmp_path)) == {"attack"}


def test_exact_existing_limit_is_still_excluded_after_growth(tmp_path, monkeypatch):
    tests = tmp_path / "tests"
    tests.mkdir()
    changed = tests / "test_changed.py"
    changed.write_bytes(_ATTACK)
    _grow_after_enumeration(monkeypatch, changed, 500_000)

    assert discovery.discover_tests(tmp_path) == {}


def test_unchanged_fingerprint_keeps_original_raw_byte_framing(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    changed = tests / "test_changed.py"
    changed.write_bytes(_ATTACK)

    assert discovery._test_tree_fingerprint(tmp_path) == content_fingerprint([
        ("tests/test_changed.py", _ATTACK),
    ])
