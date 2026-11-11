"""Generated refinement rules retain the dispatch error during cleanup."""
import builtins
import os
from types import SimpleNamespace

import pytest

from core.audit import refinement
from core.testing.module_views import module_function_view


def _dispatch_with_owned_rule(tmp_path, primary, cleanup):
    path = tmp_path / 'owned-rule.yaml'
    original = b'rules: []\n'
    path.write_bytes(original)
    info = path.stat()
    calls = []

    def keyed(suggestion, file_path):
        assert suggestion == 'semgrep pattern check'
        assert file_path == 'owned.c'
        return str(path), 'owned-pattern'

    mapping = SimpleNamespace(
        hypothesis_to_smt_verb=lambda suggestion: None,
        hypothesis_to_cocci_check=lambda suggestion: None,
        hypothesis_to_semgrep_rule_keyed=keyed,
    )

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == 'hypothesis_mapping':
            return mapping
        return builtins.__import__(name, globals, locals, fromlist, level)

    result = {'tool': 'semgrep:owned-rule', 'result': 'inert adapter result'}

    def dispatch(rule_path, outcome, ctx, config, *, rule_keyword):
        assert rule_path == str(path)
        assert rule_keyword == 'owned-pattern'
        assert path.read_bytes() == original
        calls.append('dispatch')
        if primary is not None:
            raise primary
        return result

    def unlink(rule_path):
        assert rule_path == str(path)
        now = path.stat()
        assert (now.st_dev, now.st_ino) == (info.st_dev, info.st_ino)
        calls.append('unlink')
        os.unlink(path)
        if cleanup is not None:
            raise cleanup

    private = module_function_view(
        refinement,
        bindings={'_dispatch_semgrep': dispatch, 'os': SimpleNamespace(unlink=unlink)},
        import_hook=import_local,
    )
    caught = None
    value = None
    try:
        value = private.dispatch_suggestion(
            'semgrep pattern check', None, {'file': 'owned.c'}, None,
        )
    except BaseException as exc:
        caught = exc
    assert calls == ['dispatch', 'unlink']
    assert not path.exists()
    return caught, value, result


def test_dispatch_primary_survives_consuming_rule_cleanup(tmp_path):
    primary = KeyboardInterrupt('inert dispatch interruption')
    cleanup = SystemExit('after owned rule unlink')
    caught, value, _ = _dispatch_with_owned_rule(tmp_path, primary, cleanup)
    assert caught is primary, f'cleanup replaced primary: {caught!r}; result={value!r}'


@pytest.mark.parametrize('primary_kind', [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize('cleanup_kind', [OSError, KeyboardInterrupt])
def test_dispatch_interruption_identity(tmp_path, primary_kind, cleanup_kind):
    primary = primary_kind('inert dispatch interruption')
    caught, value, _ = _dispatch_with_owned_rule(
        tmp_path, primary, cleanup_kind('after owned unlink'),
    )
    assert caught is primary
    assert value is None


@pytest.mark.parametrize('cleanup_kind', [None, OSError, SystemExit])
def test_dispatch_success_cleanup_policy(tmp_path, cleanup_kind):
    cleanup = cleanup_kind('after owned unlink') if cleanup_kind else None
    caught, value, result = _dispatch_with_owned_rule(tmp_path, None, cleanup)
    if cleanup_kind is SystemExit:
        assert caught is cleanup
        assert value is None
    else:
        assert caught is None
        assert value == [result]


def test_caller_handled_error_does_not_hide_fresh_cleanup_error(tmp_path):
    cleanup = SystemExit('fresh cleanup interruption')
    try:
        raise KeyboardInterrupt('handled by caller')
    except KeyboardInterrupt:
        caught, value, _ = _dispatch_with_owned_rule(tmp_path, None, cleanup)
    assert caught is cleanup
    assert value is None
