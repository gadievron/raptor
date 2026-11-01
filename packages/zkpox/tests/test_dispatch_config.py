"""SDK cache configuration survives the unified worker environment scrub."""
import pytest
import raptor

@pytest.mark.parametrize('explicit',[[],['--circuit-cache','/explicit/cache'],['--circuit-cache=/explicit/cache']])
def test_cache_forwarding_and_precedence(monkeypatch,explicit):
    monkeypatch.setenv('SP1_GROTH16_CIRCUIT_PATH','/configured/cache')
    calls=[]
    monkeypatch.setattr(raptor,'_run_with_lifecycle',lambda *args: calls.append(args) or 0)
    original=['prove','/private/bundle',*explicit]
    assert raptor.mode_zkpox(original)==0
    assert calls[0][2]==(original if explicit else original+['--circuit-cache','/configured/cache'])
    assert original==['prove','/private/bundle',*explicit]

def test_read_only_has_no_cache_argument(monkeypatch):
    monkeypatch.setenv('SP1_GROTH16_CIRCUIT_PATH','/configured/cache')
    calls=[]
    monkeypatch.setattr(raptor,'_run_script',lambda *args: calls.append(args) or 0)
    assert raptor.mode_zkpox(['verify','/public/bundle.cbor'])==0
    assert calls[0][1]==['verify','/public/bundle.cbor']

def test_default_cache_resolved_before_worker_scrub(monkeypatch,tmp_path):
    monkeypatch.delenv('SP1_GROTH16_CIRCUIT_PATH',raising=False)
    monkeypatch.setattr(raptor.Path,'home',staticmethod(lambda: tmp_path))
    calls=[]
    monkeypatch.setattr(raptor,'_run_with_lifecycle',lambda *args: calls.append(args) or 0)
    assert raptor.mode_zkpox(['prove','/private/bundle'])==0
    assert calls[0][2][-2:]==['--circuit-cache',str(tmp_path/'.sp1/circuits/groth16')]

@pytest.mark.parametrize('entry',[['raptor_zkpox.py'],['raptor.py','zkpox']])
def test_public_help_does_not_require_internal_dispatch_marker(entry):
    import os,subprocess,sys
    from pathlib import Path
    root=Path(__file__).resolve().parents[3]
    env=os.environ.copy()
    for key in ('_RAPTOR_TRUSTED','CLAUDECODE','RAPTOR_DIR'):
        env.pop(key,None)
    result=subprocess.run([sys.executable,str(root/entry[0]),*entry[1:],'prove','--help'],
        env=env,capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stdout+result.stderr
    assert '--circuit-cache' in result.stdout
