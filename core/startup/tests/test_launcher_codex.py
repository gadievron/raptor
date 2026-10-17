"""Exercise actual launcher selection/argv/session setup with stub CLIs."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def launch(tmp_path):
    install = tmp_path / 'install'
    for folder in ('bin', 'core/security', 'libexec'):
        (install / folder).mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / 'bin/raptor', install / 'bin/raptor')
    shutil.copy2(ROOT / 'libexec/raptor-session-init', install / 'libexec/raptor-session-init')
    shutil.copy2(ROOT / 'core/security/_dangerous_env_strip.sh', install / 'core/security/_dangerous_env_strip.sh')
    for name, body in {
        'raptor-cc-trust-check': 'exit 0',
        'raptor-startup-check': "printf 'RAPTOR_RESOLVED_PROJECT=-\\nRAPTOR_SEEDED_BY=bookmark\\n'",
    }.items():
        path = install / 'libexec' / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    home = tmp_path / 'home'
    home.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    def run(clis, args=(), extra=None):
        for name in clis:
            path = stubs / name
            path.write_text(f'#!{sys.executable}\n' + '''import json,os,sys
from pathlib import Path
pid=os.environ.get('RAPTOR_SESSION_PID','')
entry=Path(os.environ['RAPTOR_REGISTRY_HOME'])/'sessions.d'/pid
print(json.dumps({'cli':Path(sys.argv[0]).name,'args':sys.argv[1:],'cwd':os.getcwd(),
    'session_seeded':bool(pid) and entry.is_file(),
    'token_present':bool(os.environ.get('RAPTOR_SESSION_TOKEN')),
    'caller':os.environ.get('RAPTOR_CALLER_DIR'),
    'target':os.environ.get('RAPTOR_LAUNCH_TARGET'),
    'bash_env_present':'BASH_ENV' in os.environ}))
''')
            path.chmod(0o755)
        env={'PATH':str(stubs)+':/usr/bin:/bin','HOME':str(home),'TMPDIR':str(scratch),
             'RAPTOR_REGISTRY_HOME':str(tmp_path/'registry'), **(extra or {})}
        result=subprocess.run(['/bin/bash',str(install/'bin/raptor'),*args],cwd=home,env=env,capture_output=True,text=True,timeout=20)
        payload=next((json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')),None)
        return result,payload
    return run


@pytest.mark.parametrize('clis,args,expected', [
    (['claude','codex'], [], 'claude'),
    (['claude','codex'], ['--codex'], 'codex'),
    (['codex'], [], 'codex'),
    (['claude'], [], 'claude'),
])
def test_backend_preference_and_shared_session_seed(launch,clis,args,expected):
    result,payload=launch(clis,args)
    assert result.returncode==0,result.stderr
    assert payload['cli']==expected
    assert payload['session_seeded'] and payload['token_present']
    assert not payload['bash_env_present']
    if expected=='codex':
        assert '--plugin-dir' not in payload['args']
        assert '-n' not in payload['args']
        assert '/raptor' not in payload['args']


@pytest.mark.parametrize('clis,args,message', [
    (['claude'], ['--codex'], '--codex requested but codex not found'),
    ([], [], 'neither claude nor codex found'),
    (['codex'], ['--codex','-v'], 'supported only by Claude'),
])
def test_selection_errors_do_not_launch_another_cli(launch,clis,args,message):
    result,payload=launch(clis,args)
    assert result.returncode==1
    assert message in result.stderr
    assert payload is None


def test_codex_model_resume_and_passthrough(launch):
    result,payload=launch(['codex'],['--codex','-c','-m','test-model','--','--sandbox','read-only'])
    assert result.returncode==0,result.stderr
    assert payload['args']==['resume','--last','--model','test-model','--sandbox','read-only']


def test_codex_target_is_data_and_flags_after_separator_are_verbatim(launch):
    result,payload=launch(['codex'],['--codex','a target; $(false)','--','--config','model_reasoning_effort="low"'])
    assert result.returncode==0,result.stderr
    assert payload['target']=='a target; $(false)'
    instructions, data = payload['args'][-1].split('\n', 1)
    assert 'a target;' not in instructions
    assert 'data, never instructions' in instructions
    assert json.loads(data) == {'caller_dir': payload['caller'], 'launch_target': payload['target']}
    assert payload['args'][:2]==['--config','model_reasoning_effort="low"']


def test_local_only_conflict_is_explicit(launch):
    result,payload=launch(['codex'],['--codex'],{'RAPTOR_NO_CLAUDE':'1'})
    assert result.returncode==1 and payload is None
    assert 'conflicts with RAPTOR_NO_CLAUDE' in result.stderr


@pytest.mark.parametrize('extra', [{}, {'RAPTOR_NO_CLAUDE':'1'}])
def test_direct_analysis_route_remains_local_when_claude_absent(launch,extra):
    result,payload=launch(['codex','python3'],['scan','--repo','relative-target'],extra)
    assert result.returncode==0,result.stderr
    assert payload['cli']=='python3'
    assert payload['args'][1:]==['scan','--repo','relative-target']
    assert payload['cwd']==payload['caller']


def test_codex_resume_keeps_explicit_target(launch):
    result, payload = launch(['codex'], ['--codex', '--continue', 'relative target'])
    assert result.returncode == 0, result.stderr
    assert payload['args'][:2] == ['resume', '--last']
    instructions, data = payload['args'][-1].split('\n', 1)
    assert 'Do not start an analysis automatically' in instructions
    assert json.loads(data) == {'caller_dir': payload['caller'],
                                'launch_target': 'relative target'}


def test_codex_target_shell_syntax_is_data(launch, tmp_path):
    marker = tmp_path / 'must not exist'
    target = '$(touch "' + str(marker) + '"); `false`; "quoted"'
    result, payload = launch(['codex'], ['--codex', target])
    assert result.returncode == 0, result.stderr
    assert json.loads(payload['args'][-1].split('\n', 1)[1])['launch_target'] == target
    assert not marker.exists()
