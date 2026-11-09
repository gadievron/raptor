"""Bounded encoding retains journal canonical bytes and provider protocols."""
from __future__ import annotations

import builtins
import hashlib
import hmac
from pathlib import Path
from types import ModuleType

import pytest

from core.coverage import journal_mac as original
from core.hash import text as text_hash
from core.testing.module_views import module_function_view


@pytest.fixture
def view():
    private = module_function_view(original)
    private._hash = module_function_view(text_hash)
    private.try_sha256_ascii = private._hash.try_sha256_ascii
    return private


def reference(view, row):
    canonical = view.dumps_canonical({key: value for key, value in row.items()
                                      if key != view.TOKEN_KEY})
    return view.hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("extra", [
    {"unicode": "café🙂\ud800", "integer": 2**130},
    {"float": [float("nan"), float("inf"), -float("inf")]},
    {"path": Path("owned/file"), "nested": [{"b": 2, "a": 1}]},
])
def test_large_rows_keep_complete_canonical_digest_and_token_exclusion(view, extra):
    row = {"padding": "x" * view._hash._MIN_CHARS, **extra, view.TOKEN_KEY: "excluded"}
    assert view.row_sha256(row) == reference(view, row)
    assert view.row_sha256(row) == view.row_sha256({k: v for k, v in row.items()
                                                 if k != view.TOKEN_KEY})


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_threshold_and_chunk_boundaries_reach_native_path_when_available(view, delta):
    size = view._hash._MIN_CHARS + delta
    text = "a" * size
    calls = []

    def offsets(*args):
        calls.append(args)
        return range(*args)

    view.dumps_canonical = lambda row: text
    view._hash._RANGE_IMPL = offsets
    assert view.row_sha256({}) == hashlib.sha256(text.encode()).hexdigest()
    eligible = (view._hash._NATIVE_SHA256 is not None
                and view.hashlib.sha256 is view._hash._NATIVE_SHA256
                and delta >= 0)
    assert calls == ([(0, size, view._hash._CHUNK_CHARS)] if eligible else [])


def test_absent_native_backend_keeps_original_one_shot(view):
    view._hash._NATIVE_SHA256 = None
    view.dumps_canonical = lambda row: "x" * view._hash._MIN_CHARS
    view._hash._RANGE_IMPL = lambda *args: pytest.fail("unknown backend entered chunk path")
    assert view.row_sha256({}) == reference(view, {})


def test_default_conversion_occurs_once_and_keeps_row_snapshot(view):
    calls = []
    row = {"padding": "x" * view._hash._MIN_CHARS}

    class Value:
        def __str__(self):
            calls.append("str")
            row["later"] = "changed original only"
            return "owned value"

    row["value"] = Value()
    expected = hashlib.sha256(original.dumps_canonical(
        {"padding": row["padding"], "value": "owned value"}).encode()).hexdigest()
    assert view.row_sha256(row) == expected
    assert calls == ["str"]
    assert row["later"] == "changed original only"


def test_foreign_text_keeps_encode_only_protocol(view):
    calls = []

    class Text:
        def encode(self, encoding):
            calls.append(encoding)
            return b"adapter encoding"

    view.dumps_canonical = lambda row: Text()
    assert view.row_sha256({}) == hashlib.sha256(b"adapter encoding").hexdigest()
    assert calls == ["utf-8"]


def test_string_subclass_retains_encode_override(view):
    calls = []

    class Text(str):
        def encode(self, encoding):
            calls.append(encoding)
            return b"subclass encoding"

    view.dumps_canonical = lambda row: Text("x" * view._hash._MIN_CHARS)
    assert view.row_sha256({}) == hashlib.sha256(b"subclass encoding").hexdigest()
    assert calls == ["utf-8"]


@pytest.mark.parametrize("text", ["é" * 300_000, "x" * 300_000 + "\udcff"])
def test_non_ascii_and_encoding_failures_keep_whole_string_semantics(view, text):
    view.dumps_canonical = lambda row: text
    try:
        expected = reference(view, {})
    except UnicodeEncodeError as expected_error:
        with pytest.raises(UnicodeEncodeError) as caught:
            view.row_sha256({})
        assert caught.value.args == expected_error.args
        assert caught.value.object is text
    else:
        assert view.row_sha256({}) == expected


def test_foreign_constructor_keeps_one_full_argument(view):
    calls = []
    text = "x" * view._hash._MIN_CHARS

    def constructor(data):
        calls.append(data)
        return hashlib.sha256(data)

    assert view.row_sha256({"padding": text}) == reference(view, {"padding": text})
    view.hashlib = module_function_view(hashlib, bindings={"sha256": constructor})
    view.dumps_canonical = lambda row: text
    assert view.row_sha256({}) == hashlib.sha256(text.encode()).hexdigest()
    assert calls == [text.encode()]


def test_temporary_constructor_keeps_lookup_and_release_order(view):
    events = []

    class Digest:
        def hexdigest(self):
            events.append("digest")
            return "owned digest"

    class Constructor:
        def __call__(self, data):
            events.append(("construct", data[:3], len(data)))
            return Digest()

        def __del__(self):
            events.append("release constructor")

    class Provider(ModuleType):
        def __getattribute__(self, name):
            if name == "sha256":
                events.append("lookup")
                return Constructor()
            return super().__getattribute__(name)

    view.hashlib = Provider("owned_hashlib")
    view.dumps_canonical = lambda row: "x" * view._hash._MIN_CHARS
    assert reference(view, {}) == "owned digest"
    expected = list(events)
    events.clear()
    assert view.row_sha256({}) == "owned digest"
    assert events == expected


def test_constructor_patched_before_private_import_is_not_trusted():
    calls = []

    def constructor(data):
        calls.append(data)
        return hashlib.sha256(data)

    private_hashlib = module_function_view(hashlib, bindings={"sha256": constructor})
    inherited_import = builtins.__import__

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "hashlib":
            return private_hashlib
        return inherited_import(name, globals, locals, fromlist, level)

    # Execute definitions in an owned namespace, without sys.modules changes
    # or borrowed-module patches; reuse the already-owned logger name.
    namespace = {"__name__": original.__name__, "__package__": original.__package__,
                 "__file__": original.__file__,
                 "__builtins__": dict(vars(builtins), __import__=imports)}
    exec(compile(Path(original.__file__).read_text(), original.__file__, "exec"), namespace)
    text = "x" * text_hash._MIN_CHARS
    namespace["dumps_canonical"] = lambda row: text
    assert namespace["row_sha256"]({}) == hashlib.sha256(text.encode()).hexdigest()
    assert calls == [text.encode()]


def test_large_audit_token_keeps_domain_and_tamper_checks(view):
    key = b"owned fixed test key, 32 bytes..."[:32]
    view._load_or_create_key = lambda: key
    row = {"padding": "x" * view._hash._MIN_CHARS, "action": "record"}
    binding = "owned-run"
    expected = view._format_token(view.GENERATION_CURRENT, hmac.new(
        key, view._mac_message(reference(view, row), view._audit_domain(binding),
                               view.GENERATION_CURRENT), hashlib.sha256).hexdigest())
    token = view.mint_audit_log_row(row, binding)
    assert token == expected
    assert view.verify_audit_log_row(row, token, binding)
    assert not view.verify_audit_log_row({**row, "action": "changed"}, token, binding)
    assert not view.verify_audit_log_row(row, token, "another-run")


def test_encoding_callback_keeps_constructor_selected_before_encoding(view):
    calls = []

    def first(data):
        calls.append(("first", data))
        return hashlib.sha256(data)

    def later(data):
        pytest.fail("constructor was looked up after the encoding callback")

    class Text:
        def encode(self, encoding):
            view.hashlib = module_function_view(hashlib, bindings={"sha256": later})
            return b"owned text"

    view.hashlib = module_function_view(hashlib, bindings={"sha256": first})
    view.dumps_canonical = lambda row: Text()
    assert view.row_sha256({}) == hashlib.sha256(b"owned text").hexdigest()
    assert calls == [("first", b"owned text")]


def test_serialisation_failure_does_not_construct_a_hash(view):
    def unexpected(*args):
        pytest.fail("hash constructed before serialisation failed")

    view.hashlib = module_function_view(hashlib, bindings={"sha256": unexpected})
    row = {"padding": "x" * view._hash._MIN_CHARS, 1: "mixed key"}
    with pytest.raises(TypeError) as expected:
        reference(view, row)
    with pytest.raises(TypeError) as actual:
        view.row_sha256(row)
    assert actual.value.args == expected.value.args


def test_large_prep_cache_round_trip_and_tamper_refusal(view, tmp_path, monkeypatch):
    import json

    from core.audit import prep_cache
    from core.testing.module_views import scoped_function_imports

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    namespace = ModuleType("owned_coverage")
    namespace.journal_mac = view
    calls = []

    def offsets(*args):
        calls.append(args)
        return range(*args)

    view._hash._RANGE_IMPL = offsets
    payload = [{"line": i, "summary": "é" * 40, "ok": True} for i in range(5000)]
    out_dir = tmp_path / "run"
    with scoped_function_imports(prep_cache, ("write_prep_cache", "load_prep_cache"),
                                 {"core.coverage": namespace}):
        prep_cache.write_prep_cache(out_dir, "owned.json", "fp", payload, label="owned")
        assert prep_cache.load_prep_cache(out_dir, "owned.json", "fp", label="owned") == payload
        path = prep_cache.prep_cache_path(out_dir, "owned.json")
        row = json.loads(path.read_text())
        assert row[view.TOKEN_KEY]
        row["payload"][0]["summary"] = "tampered"
        path.write_text(json.dumps(row))
        assert prep_cache.load_prep_cache(out_dir, "owned.json", "fp", label="owned") is None
    eligible = view._hash._NATIVE_SHA256 is not None and view.hashlib.sha256 is view._hash._NATIVE_SHA256
    assert len(calls) == (3 if eligible else 0)
