"""Bounded frame encoding preserves canonical bytes and authentication."""
import builtins
import hashlib
from types import ModuleType

import pytest

from core.hash import text as text_hash
from core.inventory import checklist_frame_mac as original
from core.json import utils as json_utils
from core.testing.module_views import module_function_view


@pytest.fixture
def view():
    private_json = module_function_view(json_utils)

    def imports(name, *args, **kwargs):
        if name == 'core.json.utils':
            return private_json
        return builtins.__import__(name, *args, **kwargs)

    private = module_function_view(original, import_hook=imports)
    private._json = private_json
    private._hash = module_function_view(text_hash)
    private.try_sha256_ascii = private._hash.try_sha256_ascii
    return private


def reference(view, doc):
    text = view._json.dumps_canonical({k: v for k, v in doc.items() if k != view.FRAME_TOKEN_KEY})
    return view.hashlib.sha256(text.encode('utf-8')).hexdigest()


@pytest.mark.parametrize('size', [262143, 262144, 262145])
def test_threshold_routes_through_shared_native_encoder(view, size):
    text = 'a' * size
    calls = []
    view._json.dumps_canonical = lambda doc: text

    def offsets(*args):
        calls.append(args)
        return range(*args)

    view._hash._RANGE_IMPL = offsets
    assert view.frame_digest({}) == reference(view, {})
    eligible = (size >= view._hash._MIN_CHARS
                and view._hash._NATIVE_SHA256 is not None
                and view.hashlib.sha256 is view._hash._NATIVE_SHA256)
    assert bool(calls) is eligible


@pytest.mark.parametrize('text', ['é' * 300000, 'x' * 300000 + '\udcff'])
def test_whole_string_encoding_and_error_identity(view, text):
    view._json.dumps_canonical = lambda doc: text
    try:
        expected = reference(view, {})
    except UnicodeEncodeError as error:
        with pytest.raises(UnicodeEncodeError) as caught:
            view.frame_digest({})
        assert caught.value.args == error.args
        assert caught.value.object is text
    else:
        assert view.frame_digest({}) == expected


def test_foreign_text_keeps_constructor_lookup_before_encoding(view):
    events = []

    def first(data):
        events.append(('first', data))
        return hashlib.sha256(data)

    def later(data):
        pytest.fail('constructor selected after encoding callback')

    class Text:
        def encode(self, encoding):
            assert encoding == 'utf-8'
            view.hashlib = module_function_view(hashlib, bindings={'sha256': later})
            return b'owned adapter text'

    view._json.dumps_canonical = lambda doc: Text()
    view.hashlib = module_function_view(hashlib, bindings={'sha256': first})
    assert view.frame_digest({}) == hashlib.sha256(b'owned adapter text').hexdigest()
    assert events == [('first', b'owned adapter text')]


def test_temporary_constructor_lookup_and_release_order(view):
    events = []

    class Constructor:
        def __call__(self, data):
            events.append(('construct', len(data)))
            return hashlib.sha256(data)

        def __del__(self):
            events.append('release')

    class Provider(ModuleType):
        def __getattribute__(self, name):
            if name == 'sha256':
                events.append('lookup')
                return Constructor()
            return super().__getattribute__(name)

    view.hashlib = Provider('owned')
    view._json.dumps_canonical = lambda doc: 'a' * 300000
    expected = reference(view, {})
    baseline = list(events)
    events.clear()
    assert view.frame_digest({}) == expected
    assert events == baseline


def test_large_frame_token_domain_slot_and_tamper_refusals(view):
    key = b'owned frame digest test key......'[:32]
    view._load_or_create_key = lambda: key
    view._load_verify_key = lambda: key
    doc = {'files': [{'path': f'src/f{i}.c', 'items': [{'name': f'f{i}', 'line': 1}]}
                     for i in range(5000)]}
    assert view.frame_digest(doc) == reference(view, doc)
    token = view.mint_frame(doc, 'owned-slot', view.FORM_SINGLE)
    stamped = {**doc, view.FRAME_TOKEN_KEY: token}
    assert view.frame_digest(stamped) == view.frame_digest(doc)
    assert view.frame_provenance(stamped, 'owned-slot', view.FORM_SINGLE) == view.FRAME_VERIFIED
    assert view.frame_provenance(stamped, 'other-slot', view.FORM_SINGLE) == view.FRAME_RELOCATED
    assert view.frame_provenance(stamped, 'owned-slot', view.FORM_SHARDED) == view.FRAME_TAMPERED
    assert view.frame_provenance({**stamped, 'files': []}, 'owned-slot', view.FORM_SINGLE) == view.FRAME_TAMPERED
