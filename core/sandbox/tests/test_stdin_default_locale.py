"""Native text input uses the owning Python process's default codec."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


pytestmark = [
    pytest.mark.slow, pytest.mark.linux_native,
    pytest.mark.skipif(sys.platform != 'linux', reason='Linux native stdin spool'),
    requires_landlock, requires_mount, requires_userns,
]


def test_default_text_input_refuses_unencodable_parent_locale(tmp_path):
    code = r'''
import locale, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from core.sandbox import sandbox
assert not sys.flags.utf8_mode
assert locale.getencoding().lower() in ('ascii', 'ansi_x3.4-1968')
target, output = Path(sys.argv[2]), Path(sys.argv[3])
target.mkdir(); output.mkdir()
with sandbox(profile='strict', target=str(target), output=str(output)) as run:
    positive = run(['/bin/cat'], input='owned ascii', text=True,
                   capture_output=True, check=True, timeout=15)
    assert positive.stdout == 'owned ascii'
    assert positive.sandbox_info['mount_ns_active'] is True
    try:
        run(['/bin/cat'], input='owned \u03bb', text=True,
            capture_output=True, check=True, timeout=15)
    except UnicodeEncodeError:
        pass
    else:
        raise AssertionError('native stdin silently accepted text outside the parent codec')
'''
    root = Path(__file__).resolve().parents[3]
    with standalone_cli_env(data_home=tmp_path / 'keys') as environment:
        environment.update(LC_ALL='C', PYTHONUTF8='0', PYTHONCOERCECLOCALE='0')
        result = run_in_process_group(
            [sys.executable, '-X', 'utf8=0', '-c', code, str(root),
             str(tmp_path / 'target'), str(tmp_path / 'output')],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=25, start_new_session=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('mode', ['utf8-mode', 'explicit-utf8', 'binary'])
def test_input_codec_overrides_preserve_complete_native_payload(tmp_path, mode):
    code = r'''
import locale, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from core.sandbox import sandbox
mode = sys.argv[4]
assert bool(sys.flags.utf8_mode) == (mode == 'utf8-mode')
if mode != 'utf8-mode':
    assert locale.getencoding().lower() in ('ascii', 'ansi_x3.4-1968')
target, output = Path(sys.argv[2]), Path(sys.argv[3])
target.mkdir(); output.mkdir()
payload = 'owned \u03bb'
options = {'text': True}
if mode == 'explicit-utf8':
    options['encoding'] = 'utf-8'
elif mode == 'binary':
    payload = payload.encode('utf-8')
    options = {'text': False}
with sandbox(profile='strict', target=str(target), output=str(output)) as run:
    actual = run(['/bin/cat'], input=payload, capture_output=True,
                 check=True, timeout=15, **options)
assert actual.stdout == payload
assert type(actual.stdout) is type(payload)
assert actual.sandbox_info['mount_ns_active'] is True
'''
    root = Path(__file__).resolve().parents[3]
    utf8_mode = '1' if mode == 'utf8-mode' else '0'
    with standalone_cli_env(data_home=tmp_path / 'keys') as environment:
        environment.update(LC_ALL='C', PYTHONUTF8=utf8_mode, PYTHONCOERCECLOCALE='0')
        result = run_in_process_group(
            [sys.executable, '-X', f'utf8={utf8_mode}', '-c', code, str(root),
             str(tmp_path / 'target'), str(tmp_path / 'output'), mode],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=25, start_new_session=True)
    assert result.returncode == 0, result.stderr
