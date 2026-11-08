"""Shared semantic prep owns launch state and its module signing domain."""

import json
import os
import sys

import pytest

from core.testing.standalone_cli import run_standalone_cli


@pytest.mark.parametrize('marker', [None, '', 'borrowed'], ids=['missing', 'empty', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_shared_prep_setup_restores_signing_environment(marker, outcome, tmp_path, monkeypatch, tmp_path_factory):
    from core.audit.tests import test_semantic_consistency_routing as native

    if marker is None:
        monkeypatch.delenv('XDG_DATA_HOME', raising=False)
    else:
        monkeypatch.setenv('XDG_DATA_HOME', marker)
    before = dict(os.environ)
    keys = tmp_path / 'keys'
    keys.mkdir()
    result = object()
    failure = RuntimeError('setup failed') if outcome == 'error' else KeyboardInterrupt('setup interrupted')

    def prepare(factory, signing_home):
        assert factory is tmp_path_factory
        assert signing_home is keys
        assert os.environ['XDG_DATA_HOME'] == str(keys)
        if outcome != 'normal':
            raise failure
        return result

    monkeypatch.setattr(native, '_prepare_semantic_result', prepare)
    if outcome == 'normal':
        assert native.prep_result.__wrapped__(tmp_path_factory, keys) is result
    else:
        with pytest.raises(type(failure)) as caught:
            native.prep_result.__wrapped__(tmp_path_factory, keys)
        assert caught.value is failure
    assert dict(os.environ) == before
    assert keys.is_dir()


@pytest.mark.parametrize('marker', [None, '', 'borrowed'], ids=['missing', 'empty', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_consumer_key_pin_restores_the_per_test_default(marker, outcome, tmp_path, monkeypatch):
    from core.audit.tests import test_semantic_consistency_routing as native

    if marker is None:
        monkeypatch.delenv('XDG_DATA_HOME', raising=False)
    else:
        monkeypatch.setenv('XDG_DATA_HOME', marker)
    before = dict(os.environ)
    keys = tmp_path / 'keys'
    keys.mkdir()
    failure = RuntimeError('consumer failed') if outcome == 'error' else KeyboardInterrupt('consumer interrupted')

    def consume():
        with pytest.MonkeyPatch.context() as owner:
            native._semantic_mac_keys.__wrapped__(None, keys, owner)
            assert os.environ['XDG_DATA_HOME'] == str(keys)
            if outcome != 'normal':
                raise failure

    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(failure)) as caught:
            consume()
        assert caught.value is failure
    assert dict(os.environ) == before
    assert keys.is_dir()


@pytest.mark.slow
@pytest.mark.parametrize('stale', [False, True], ids=['clean-launch', 'stale-launch'])
def test_real_shared_prep_authenticates_both_directions(stale, tmp_path, tmp_path_factory, monkeypatch):
    from core.audit import orchestrator as orch
    from core.audit.tests import test_semantic_consistency_routing as native
    from core.inventory import checklist_frame_mac as cm, read_checklist, save_checklist

    keys = native.semantic_signing_home.__wrapped__(tmp_path_factory)
    borrowed = tmp_path / 'borrowed-signing-home'
    borrowed.mkdir()
    monkeypatch.setenv('XDG_DATA_HOME', str(borrowed))
    if stale:
        monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', 'invalid-inherited-authorisation')
        monkeypatch.setenv('RAPTOR_SESSION_PID', '999999')
        monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'invalid-inherited-session')
    else:
        for name in ('_RAPTOR_SCRATCH_AUTH', 'RAPTOR_SESSION_PID', 'RAPTOR_SESSION_TOKEN'):
            monkeypatch.delenv(name, raising=False)
    before = dict(os.environ)
    compute = orch._compute_audit_prep
    observations = []

    def verified(out):
        doc = json.loads((out / 'checklist.json').read_text())
        assert cm.frame_provenance(doc, cm.frame_binding(out), cm.FORM_SINGLE) == cm.FRAME_VERIFIED
        return doc

    def observe(config):
        assert os.environ['XDG_DATA_HOME'] == str(keys)
        out = config.out_dir
        child_frame = verified(out)
        first = compute(config)
        assert any(row.get('function') == 'handle_delta' for row in first['semantic_findings'])
        parent_doc = read_checklist(out)
        parent_doc['_parent_signature_roundtrip'] = True
        save_checklist(out, parent_doc)
        verified(out)
        second = compute(config)
        assert any(row.get('function') == 'handle_delta' for row in second['semantic_findings'])

        # A fresh child also verifies the parent's stamp with the same owned
        # directory. Its temporary HOME and launch metadata remain independent.
        program = (
            'import json,sys; from pathlib import Path; '
            'from core.inventory import checklist_frame_mac as cm, read_checklist; '
            'out=Path(sys.argv[1]); doc=json.loads((out/"checklist.json").read_text()); '
            'assert cm.frame_provenance(doc,cm.frame_binding(out),cm.FORM_SINGLE)==cm.FRAME_VERIFIED; '
            'assert read_checklist(out)["_parent_signature_roundtrip"] is True; '
            'print("parent-frame-verified")'
        )
        env = dict(os.environ, _RAPTOR_TRUSTED='1', PYTHONPATH=str(native._RAPTOR_DIR))
        child = run_standalone_cli([sys.executable, '-c', program, str(out)],
                                   env=env, data_home=keys, capture_output=True, text=True)
        assert child.returncode == 0, child.stderr
        assert child.stdout.strip() == 'parent-frame-verified'
        with pytest.MonkeyPatch.context() as other:
            other.setenv('XDG_DATA_HOME', str(tmp_path / 'different-key'))
            assert cm.key_usable()
            assert cm.frame_provenance(child_frame, cm.frame_binding(out), cm.FORM_SINGLE) == cm.FRAME_TAMPERED
        observations.append(out)
        return first

    monkeypatch.setattr(orch, '_compute_audit_prep', observe)
    prep, out = native.prep_result.__wrapped__(tmp_path_factory, keys)
    assert observations == [out]
    assert prep is not None
    assert (keys / 'raptor/checklist-frame-mac.key').is_file()
    assert keys.is_dir()
    assert dict(os.environ) == before
