"""Go shell taint must follow command text through variadic argument tails."""
import hashlib
import json
import shutil
import pytest
from pathlib import Path

from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_go_shell_command_text_with_extra_arguments(tmp_path):
    report = tmp_path
    root = tmp_path / 'inputs'
    root.mkdir()
    cases = []
    for api in ['Command', 'CommandContext']:
        for shell in ['sh', 'bash', '/bin/sh', '/bin/bash']:
            for tail in [0, 1, 2]:
                cases.append({'api':api,'shell':shell,'kind':'command-text','tail':tail})
            cases.append({'api':api,'shell':shell,'kind':'later-argument','tail':1})
        cases += [{'api':api,'shell':None,'kind':'program-name','tail':0},
                  {'api':api,'shell':None,'kind':'fixed-program-argument','tail':0}]
    for index, case in enumerate(cases):
        imports = ['"net/http"','"os/exec"']
        args = []
        if case['api'] == 'CommandContext':
            imports.append('"context"')
            args.append('context.Background()')
        if case['kind'] == 'program-name':
            args += ['user']
        elif case['kind'] == 'fixed-program-argument':
            args += ['"owned-fixed-program"','user']
        else:
            args += [json.dumps(case['shell']), '"-c"',
                     'user' if case['kind'] == 'command-text' else '"owned-fixed-command"']
            args += ['user'] if case['kind'] == 'later-argument' else ['"owned-arg"'] * case['tail']
        source = ('package fixture\nimport (' + '; '.join(imports) + ')\n'
            'func subject(req *http.Request) {\n user := req.FormValue("value")\n'
            ' _ = exec.' + case['api'] + '(' + ', '.join(args) + ')\n}\n')
        name = f'case_{index:02}.go'
        (root / name).write_text(source)
        case['file'] = name
        case['source_sha256'] = hashlib.sha256(source.encode()).hexdigest()
    rule = Path(__file__).resolve().parents[1] / 'rules/injection/command-taint-multi.yaml'
    env = RaptorConfig.get_safe_env()
    env['SEMGREP_SEND_METRICS'] = 'off'
    env['SEMGREP_SETTINGS_FILE'] = str(tmp_path / 'semgrep-settings.yml')
    env['SEMGREP_LOG_FILE'] = str(tmp_path / 'semgrep.log')
    proc = run_pinned_subprocess(['semgrep','scan','--config',str(rule),'--json',
        '--metrics=off','--disable-version-check','--jobs','1','--no-git-ignore',str(root)],
        timeout=60, context='Owned Go shell argument-position syntax',env=env,skip_signals=(9,))
    (report / 'stdout.json').write_text(proc.stdout)
    (report / 'stderr.log').write_text(proc.stderr)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get('errors'), data.get('errors')
    assert {Path(p).name for p in data['paths']['scanned']} == {c['file'] for c in cases}
    rows = data['results']
    assert all(row['check_id'].endswith('raptor.injection.command.taint.go') for row in rows)
    by_file = {case['file']:[] for case in cases}
    for row in rows:
        by_file[Path(row['path']).name].append(row)
    for case in cases:
        case['reported'] = bool(by_file[case['file']])
    (report / 'summary.json').write_text(json.dumps({'cases':cases,
        'rule_sha256':hashlib.sha256(rule.read_bytes()).hexdigest(),
        'qualification':'Owned Go source parsed only; no process creation or target program execution. Command-text positives and later-argument negatives are checked independently. Later arguments to a constant shell command and fixed program are distinct from tainted command text/program names. Only one Go rule and bounded arities, not all APIs/platforms or default-CWE admission.'},indent=2))
    assert all(case['reported'] for case in cases if case['kind'] == 'program-name'
        or case['kind'] == 'command-text')
    assert not any(case['reported'] for case in cases if case['kind'] in
                   ('later-argument','fixed-program-argument'))
