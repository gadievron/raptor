"""Installed-dependency probes must not load Python from a target directory."""
import json
import os
from pathlib import Path
import subprocess
import sys

from core.security.python_probe import run_python_probe


def test_probe_ignores_target_cwd_and_startup_environment(tmp_path, monkeypatch):
    target = tmp_path/'target'
    target.mkdir()
    home = tmp_path/'home'
    home.mkdir()
    scratch = tmp_path/'scratch'
    scratch.mkdir()
    marker = target/'executed'
    payload = f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\n'
    for module in ('json', 'sitecustomize', 'usercustomize'):
        (target/(module+'.py')).write_text(payload+'raise RuntimeError("target module loaded")\n')
    # Negative control: a normal -c import really can load this target file.
    control = subprocess.run([sys.executable, '-c', 'import json'], cwd=target,
        env={'HOME': str(home), 'PATH': os.defpath}, capture_output=True, timeout=10)
    assert control.returncode != 0 and marker.exists()
    marker.unlink()
    monkeypatch.chdir(target)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('PYTHONPATH', str(target))
    monkeypatch.setenv('PYTHONUSERBASE', str(target))
    monkeypatch.setenv('PYTHONSTARTUP', str(target/'sitecustomize.py'))
    monkeypatch.setenv('RAPTOR_PROBE_CANARY', 'strip-me')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'fake-audit-canary')
    result = run_python_probe(sys.executable,
        "import json, os, sys; print(json.dumps({'cwd': os.getcwd(), "
        "'tmpdir': os.environ.get('TMPDIR'), 'paths': sys.path, "
        "'unsafe_env': sorted(k for k in os.environ if k in "
        "('PYTHONPATH', 'PYTHONUSERBASE', 'PYTHONSTARTUP', 'AWS_SECRET_ACCESS_KEY', 'RAPTOR_PROBE_CANARY'))}))",
        timeout=10, tmpdir=str(scratch))
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value['cwd'] == os.sep
    assert value['tmpdir'] == str(scratch)
    assert str(target) not in value['paths']
    assert value['unsafe_env'] == []
    assert not marker.exists()


def test_probe_preserves_installed_user_site_packages(tmp_path, monkeypatch):
    home = tmp_path/'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    executable = getattr(sys, '_base_executable', None) or sys.executable
    layout = run_python_probe(executable,
        'import json, site; print(json.dumps([site.ENABLE_USER_SITE, site.getusersitepackages()]))',
        timeout=10)
    assert layout.returncode == 0, layout.stderr
    enabled, directory = json.loads(layout.stdout)
    assert enabled, 'base interpreter unexpectedly disables user-site packages'
    site = Path(directory)
    assert site.is_relative_to(home)
    site.mkdir(parents=True)
    (site/'_raptor_probe_user_dependency.py').write_text('VALUE = 42\n')
    result = run_python_probe(executable,
        'import _raptor_probe_user_dependency as dependency; print(dependency.VALUE)', timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == b'42'
