"""First-use download integrity, atomic publication, and sandbox resolution."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
INSTALLER = ROOT / '.devcontainer/codeql-bootstrap.py'
pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux container installer')


def archive_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, content, mode in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode & 0o777
            if stat.S_ISLNK(mode):
                info.type = tarfile.SYMTYPE
                info.linkname = content
                archive.addfile(info)
            elif stat.S_ISDIR(mode):
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                data = content.encode('utf-8')
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


@pytest.fixture
def installer(tmp_path, monkeypatch):
    namespace = runpy.run_path(str(INSTALLER))
    state = namespace['ensure_installed'].__globals__
    monkeypatch.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
    monkeypatch.delenv('RAPTOR_CODEQL_AUTO_INSTALL', raising=False)
    payload = archive_bytes([
        ('codeql/codeql', f'#!/bin/sh\nprintf "{state["VERSION"]}\\n"\n', stat.S_IFREG | 0o755),
        ('codeql/LICENSE.md', 'upstream terms', stat.S_IFREG | 0o644),
        ('codeql/legal/license', '../LICENSE.md', stat.S_IFLNK | 0o777),
    ])
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setitem(state, '_asset', lambda: ('test.tar.gz', digest, len(payload)))
    calls = []

    class Response(io.BytesIO):
        def geturl(self):
            return 'https://release-assets.githubusercontent.com/test.zip'

    def open_url(url, **kwargs):
        calls.append(url)
        return Response(payload)

    monkeypatch.setitem(state, 'urlopen', open_url)
    return state, payload, calls


def test_install_verifies_reuses_and_preserves_terms(installer):
    state, payload, calls = installer
    path = state['ensure_installed']()
    assert path.is_file() and os.access(path, os.X_OK)
    assert (path.parent / 'LICENSE.md').read_text() == 'upstream terms'
    assert (path.parent / 'legal/license').is_symlink()
    assert (path.parent / 'legal/license').read_text() == 'upstream terms'
    assert state['ensure_installed']() == path
    assert len(calls) == 1


def test_hash_mismatch_does_not_publish_and_retry_succeeds(installer, monkeypatch):
    state, payload, calls = installer
    original = state['urlopen']

    class Corrupt(io.BytesIO):
        def geturl(self):
            return 'https://release-assets.githubusercontent.com/test.zip'

    monkeypatch.setitem(state, 'urlopen', lambda *a, **k: Corrupt(payload[:-1] + b'!'))
    with pytest.raises(RuntimeError, match='SHA-256'):
        state['ensure_installed']()
    assert not (state['_cache_root']() / state['VERSION']).exists()
    assert not list(state['_cache_root']().glob('.install-*'))
    monkeypatch.setitem(state, 'urlopen', original)
    assert state['ensure_installed']().is_file()


def test_interrupted_download_leaves_no_installation(installer, monkeypatch):
    state, _, _ = installer

    def interrupted(path, *args):
        path.write_bytes(b'partial')
        raise OSError('interrupted')

    monkeypatch.setitem(state, '_download', interrupted)
    with pytest.raises(OSError, match='interrupted'):
        state['ensure_installed']()
    assert not (state['_cache_root']() / state['VERSION']).exists()
    assert not list(state['_cache_root']().glob('.install-*'))


def test_status_and_opt_out_do_not_download(installer, monkeypatch, capsys):
    state, _, calls = installer
    assert state['main'](['--raptor-status']) == 0
    assert json.loads(capsys.readouterr().out)['installed'] is False
    assert calls == []
    monkeypatch.setenv('RAPTOR_CODEQL_AUTO_INSTALL', '0')
    assert state['main'](['version']) == 1
    assert calls == []
    assert state['main'](['--raptor-install']) == 0
    assert len(calls) == 1


@pytest.mark.parametrize('entry', [
    ('codeql/../../outside', 'bad', stat.S_IFREG | 0o644),
    ('/codeql/outside', 'bad', stat.S_IFREG | 0o644),
    ('codeql/escape', '../../outside', stat.S_IFLNK | 0o777),
])
def test_archive_cannot_escape_stage(installer, tmp_path, entry):
    state, _, _ = installer
    path = tmp_path / 'bad.tar.gz'
    path.write_bytes(archive_bytes([entry]))
    with pytest.raises(RuntimeError):
        state['_extract'](path, tmp_path / 'stage')
    assert not (tmp_path / 'outside').exists()


def test_nested_symlink_cannot_create_outside_entries(installer, tmp_path):
    state, _, _ = installer
    path = tmp_path / 'bad.tar.gz'
    path.write_bytes(archive_bytes([
        ('codeql/link', '../../outside', stat.S_IFLNK | 0o777),
        ('codeql/link/child', 'target', stat.S_IFLNK | 0o777),
    ]))
    with pytest.raises(RuntimeError):
        state['_extract'](path, tmp_path / 'stage')
    assert not (tmp_path / 'outside').exists()


def test_concurrent_first_uses_download_once(installer, tmp_path):
    state, payload, _ = installer
    archive = tmp_path / 'download.tar.gz'
    archive.write_bytes(payload)
    counter = tmp_path / 'downloads'
    code = '''import pathlib, runpy, sys, shutil, time, hashlib
n = runpy.run_path(sys.argv[1]); g = n['ensure_installed'].__globals__
payload = pathlib.Path(sys.argv[2]).read_bytes()
g['_asset'] = lambda: ('test.tar.gz', hashlib.sha256(payload).hexdigest(), len(payload))
def download(path, *args):
    with open(sys.argv[3], 'a') as stream: stream.write('download\\n')
    time.sleep(.15)
    path.write_bytes(payload)
g['_download'] = download
print(n['ensure_installed']())
'''
    children = [subprocess.Popen([sys.executable, '-c', code, str(INSTALLER),
                                  str(archive), str(counter)], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
                for _ in range(2)]
    try:
        results = [child.communicate(timeout=15) for child in children]
        assert all(child.returncode == 0 for child in children), results
        assert results[0][0] == results[1][0]
        assert counter.read_text().splitlines() == ['download']
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()


def test_resolves_distribution_before_sandbox_and_aborts_on_failure(tmp_path, monkeypatch):
    from packages.codeql._bootstrap import resolve_bootstrap

    binary = tmp_path / 'distribution/codeql'
    binary.parent.mkdir()
    binary.write_text('#!/bin/sh\n')
    binary.chmod(0o755)
    wrapper = tmp_path / 'raptor-codeql-bootstrap'
    wrapper.write_text('#!/bin/sh\nprintf "%s\\n" "' + str(binary) + '"\n')
    wrapper.chmod(0o755)
    assert resolve_bootstrap(str(wrapper)) == str(binary)
    wrapper.write_text('#!/bin/sh\nexit 1\n')
    with pytest.raises(RuntimeError, match='first-use installation failed'):
        resolve_bootstrap(str(wrapper))


def test_regular_cli_never_invokes_bootstrap(tmp_path, monkeypatch):
    from packages.codeql import _bootstrap

    monkeypatch.setattr(_bootstrap.subprocess, 'run', lambda *a, **k: pytest.fail('unexpected subprocess'))
    assert _bootstrap.resolve_bootstrap('/opt/custom/codeql') == '/opt/custom/codeql'


def test_operator_opt_out_survives_subprocess_environment(tmp_path, monkeypatch):
    from packages.codeql._bootstrap import resolve_bootstrap

    wrapper = tmp_path / 'raptor-codeql-bootstrap'
    wrapper.write_text('#!/bin/sh\ntest "$RAPTOR_CODEQL_AUTO_INSTALL" != 0\n')
    wrapper.chmod(0o755)
    monkeypatch.setenv('RAPTOR_CODEQL_AUTO_INSTALL', '0')
    with pytest.raises(RuntimeError, match='first-use installation failed'):
        resolve_bootstrap(str(wrapper))


def test_container_style_symlink_finds_adjacent_manifest(tmp_path):
    launcher = tmp_path / 'libexec/raptor-codeql-bootstrap'
    launcher.parent.mkdir()
    launcher.write_bytes(INSTALLER.read_bytes())
    launcher.chmod(0o755)
    manifest = launcher.with_name('github-release-pins.json')
    manifest.write_bytes(INSTALLER.with_name('github-release-pins.json').read_bytes())
    command = tmp_path / 'bin/codeql'
    command.parent.mkdir()
    command.symlink_to(launcher)
    result = subprocess.run([str(command), '--raptor-status'], text=True,
                            capture_output=True, check=True, timeout=10)
    assert json.loads(result.stdout)['version']
    manifest.unlink()
    failed = subprocess.run([str(command), '--raptor-status'], text=True,
                            capture_output=True, timeout=10)
    assert failed.returncode != 0 and 'release pins unavailable' in failed.stderr


@pytest.mark.parametrize('builder', ['get_safe_env', 'get_llm_env'])
def test_opt_out_survives_launcher_and_child_environment(builder, tmp_path, monkeypatch):
    from core.config import RaptorConfig

    monkeypatch.setenv('RAPTOR_CODEQL_AUTO_INSTALL', '0')
    monkeypatch.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
    code = '''import os, runpy, sys
from core.config import RaptorConfig
assert os.environ['RAPTOR_CODEQL_AUTO_INSTALL'] == '0'
assert RaptorConfig.get_safe_env()['RAPTOR_CODEQL_AUTO_INSTALL'] == '0'
n = runpy.run_path(sys.argv[1]); g = n['ensure_installed'].__globals__
def download(*args):
    raise AssertionError('opt-out was lost: attempted download')
g['_download'] = download
assert n['main'](['--raptor-resolve']) == 1
'''
    subprocess.run([sys.executable, '-c', code, str(INSTALLER)],
                   env=getattr(RaptorConfig, builder)(), check=True,
                   capture_output=True, text=True, timeout=15)
    assert not (tmp_path / 'cache').exists()


@pytest.mark.parametrize('args', [['version', '--format=terse'], ['--version'],
                                  ['--raptor-resolve-existing']])
def test_version_and_existing_resolution_never_download(installer, args):
    state, _, calls = installer
    assert state['main'](args) == 1
    assert not calls and not state['_cache_root']().exists()


def test_version_probe_can_reuse_installed_distribution(installer, monkeypatch):
    state, _, calls = installer
    cli = state['ensure_installed']()
    executions = []
    monkeypatch.setattr(state['os'], 'execv', lambda *args: executions.append(args))
    assert state['main'](['version', '--format=terse']) == 0
    assert executions == [(str(cli), [str(cli), 'version', '--format=terse'])]
    assert len(calls) == 1


@pytest.fixture
def diagnostic_launcher(tmp_path, monkeypatch):
    launcher = tmp_path / 'libexec/raptor-codeql-bootstrap'
    launcher.parent.mkdir()
    marker = tmp_path / 'download-attempted'
    launcher.write_text('#!/usr/bin/env python3\nimport runpy, sys\nfrom pathlib import Path\n'
                        f'n = runpy.run_path({str(INSTALLER)!r})\n'
                        'def download(*args):\n'
                        f'    Path({str(marker)!r}).write_text("attempted")\n'
                        '    raise RuntimeError("unexpected diagnostic download")\n'
                        'n["ensure_installed"].__globals__["_download"] = download\n'
                        'raise SystemExit(n["main"](sys.argv[1:]))\n')
    launcher.chmod(0o755)
    command = tmp_path / 'bin/codeql'
    command.parent.mkdir()
    command.symlink_to(launcher)
    monkeypatch.setenv('PATH', str(command.parent) + os.pathsep + os.environ['PATH'])
    monkeypatch.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
    monkeypatch.delenv('RAPTOR_CODEQL_AUTO_INSTALL', raising=False)
    monkeypatch.delenv('CODEQL_CLI', raising=False)
    return command, marker


def test_diagnostic_consumers_do_not_install_or_record_errors(diagnostic_launcher, monkeypatch):
    from core.recall.score import collect_toolchain
    from core.run.provenance import tool_version
    import packages.codeql as codeql

    command, marker = diagnostic_launcher
    # Exercise the actual launcher, without running unrelated installed tools.
    monkeypatch.setattr('shutil.which', lambda name: str(command) if name == 'codeql' else None)
    assert 'codeql' not in collect_toolchain()
    assert tool_version('codeql') is None
    assert codeql.version() is None
    assert not marker.exists()
    assert not command.parents[1].joinpath('cache').exists()


def test_failed_version_output_is_not_recorded(tmp_path, monkeypatch):
    from core.recall.score import collect_toolchain
    from core.run.provenance import tool_version
    import packages.codeql as codeql

    command = tmp_path / 'codeql'
    command.write_text('#!/bin/sh\necho "failure banner" >&2\nexit 1\n')
    command.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    monkeypatch.delenv('CODEQL_CLI', raising=False)
    monkeypatch.setattr('shutil.which', lambda name: str(command) if name == 'codeql' else None)
    assert 'codeql' not in collect_toolchain()
    assert tool_version('codeql') is None
    assert codeql.version() is None


@pytest.mark.parametrize('dispatcher,keyless', [(False, False), (True, False), (True, True)])
def test_raptor_script_dispatch_preserves_operator_opt_out(tmp_path, monkeypatch, dispatcher, keyless):
    from types import SimpleNamespace
    import raptor

    child = tmp_path / 'assert-preference.py'
    child.write_text('import os\nfrom core.config import RaptorConfig\n'
                     'assert os.environ["RAPTOR_CODEQL_AUTO_INSTALL"] == "0"\n'
                     'assert RaptorConfig.get_safe_env()["RAPTOR_CODEQL_AUTO_INSTALL"] == "0"\n')
    monkeypatch.setenv('RAPTOR_CODEQL_AUTO_INSTALL', '0')
    monkeypatch.setattr(raptor, '_get_or_start_dispatcher', lambda **kwargs: object() if dispatcher else None)
    monkeypatch.setattr(raptor, '_worker_keyless_enabled', lambda: keyless)
    monkeypatch.setattr(raptor, '_announce_env_direct_downgrade', lambda *args: None)

    def spawn(_dispatcher, *, cmd, label, env):
        assert env['RAPTOR_CODEQL_AUTO_INSTALL'] == '0'
        return SimpleNamespace(wait=lambda: subprocess.run(cmd, env=env, timeout=15, check=False).returncode)

    monkeypatch.setattr('core.llm.dispatcher.spawn.spawn_worker', spawn)
    # Give the test child the same import mechanism as RAPTOR's real scripts.
    child.write_text(f'import sys\nsys.path.insert(0, {str(ROOT)!r})\n' + child.read_text())
    assert raptor._run_script(child, []) == 0


def test_bundle_download_uses_pinned_release_stream(installer):
    state, _, calls = installer
    state['ensure_installed']()
    assert calls == [f'https://github.com/github/codeql-action/releases/download/{state["RELEASE_TAG"]}/test.tar.gz']


def test_bundle_preserves_safe_internal_hardlink(installer, tmp_path):
    state, _, _ = installer
    archive = tmp_path / 'hardlinks.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        original = tarfile.TarInfo('codeql/LICENSE.md')
        original.size = 5
        bundle.addfile(original, io.BytesIO(b'terms'))
        link = tarfile.TarInfo('codeql/legal/LICENSE-copy')
        link.type = tarfile.LNKTYPE
        link.linkname = 'codeql/LICENSE.md'
        bundle.addfile(link)
    root = state['_extract'](archive, tmp_path / 'stage')
    assert (root / 'legal/LICENSE-copy').read_text() == 'terms'
    assert (root / 'legal/LICENSE-copy').stat().st_ino == (root / 'LICENSE.md').stat().st_ino


@pytest.mark.parametrize('kind,linkname', [
    (tarfile.LNKTYPE, '../../outside'),
    (tarfile.LNKTYPE, '/etc/passwd'),
    (tarfile.FIFOTYPE, ''),
    (tarfile.CHRTYPE, ''),
])
def test_tar_special_files_and_escaping_hardlinks_are_rejected(installer, tmp_path, kind, linkname):
    state, _, _ = installer
    archive = tmp_path / 'unsafe.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        member = tarfile.TarInfo('codeql/unsafe')
        member.type = kind
        member.linkname = linkname
        bundle.addfile(member)
    with pytest.raises(RuntimeError):
        state['_extract'](archive, tmp_path / 'stage')
    assert not (tmp_path / 'outside').exists()


def test_tar_extraction_bound_is_enforced_before_writing(installer, tmp_path, monkeypatch):
    state, payload, _ = installer
    archive = tmp_path / 'too-large.tar.gz'
    archive.write_bytes(payload)
    monkeypatch.setitem(state, 'MAX_EXTRACTED_BYTES', 1)
    with pytest.raises(RuntimeError, match='extraction bounds'):
        state['_extract'](archive, tmp_path / 'stage')
    assert not (tmp_path / 'stage/codeql/codeql').exists()
