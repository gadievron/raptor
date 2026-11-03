"""Ruby discovery admits installed code without reading account configuration."""
import json
import subprocess

import pytest

from core.sandbox.ruby_paths import ruby_tool_runtime


@pytest.fixture
def layout(tmp_path, monkeypatch):
    from core.sandbox import python_paths, ruby_paths
    home = tmp_path / 'account'
    (home / 'bin').mkdir(parents=True)
    (home / 'lib/ruby').mkdir(parents=True)
    (home / 'lib/libruby.so.3.3').write_bytes(b'owned runtime')
    ruby = home / 'bin/ruby3.3'
    ruby.write_bytes(b'owned interpreter')
    launcher = home / 'bin/one_gadget'
    launcher.write_text('#!' + str(ruby) + '\n')
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    monkeypatch.setattr(ruby_paths, '_home_roots', lambda: (home,))
    monkeypatch.setattr(python_paths, '_home_roots', lambda: (home,))
    return home, launcher, scratch


def _query(monkeypatch, roots, callback=None):
    from core import sandbox
    def run(command, **options):
        assert '--disable-gems' in command
        assert options['target'] == options['output'] == options['cwd']
        assert options['readable_paths'] == []
        assert options['restrict_reads'] and options['fake_home'] and options['strict_env']
        assert options['stdin'] == subprocess.DEVNULL
        assert options['max_capture_bytes'] == 64 * 1024
        if callback:
            callback(command, options)
        return subprocess.CompletedProcess(command, 0, json.dumps(
            dict(paths=roots, version='3.3.0', engine='ruby')), '')
    monkeypatch.setattr(sandbox, 'run', run)


def _gem_root(root):
    for directory in ('gems', 'specifications', 'extensions'):
        (root / directory).mkdir(parents=True)
    return root


def test_runtime_is_narrow_and_query_has_no_target_grant(layout, tmp_path, monkeypatch):
    home, launcher, scratch = layout
    gems = _gem_root(tmp_path / 'installed-gems')
    _query(monkeypatch, [str(gems)])
    paths, environment = ruby_tool_runtime(str(launcher), str(scratch))
    assert str(home) not in paths and str(home / 'lib') not in paths
    assert str(home / 'lib/ruby') in paths
    assert str(home / 'lib/libruby.so.3.3') in paths
    assert str(gems) not in paths
    assert all(str(gems / child) in paths for child in ('gems', 'specifications', 'extensions'))
    assert environment == ['GEM_HOME=' + str(scratch / '.home/.gem'), 'GEM_PATH=' + str(gems)]


@pytest.mark.parametrize('folder', ['.gem', '.local/share/gem'])
def test_user_gems_survive_private_home(layout, monkeypatch, folder):
    home, launcher, scratch = layout
    root = _gem_root(home / folder / 'ruby/3.3.0')
    _query(monkeypatch, [])
    paths, environment = ruby_tool_runtime(str(launcher), str(scratch))
    assert str(root / 'gems') in paths
    assert 'GEM_PATH=' + str(root) in environment
    assert str(home) not in paths


def test_gem_directory_symlink_cannot_grant_account_secrets(layout, tmp_path, monkeypatch):
    _, launcher, scratch = layout
    root = tmp_path / 'gem-root'
    (root / 'specifications').mkdir(parents=True)
    secret = tmp_path / 'credentials'
    secret.mkdir()
    (root / 'gems').symlink_to(secret, target_is_directory=True)
    _query(monkeypatch, [str(root)])
    paths, environment = ruby_tool_runtime(str(launcher), str(scratch))
    assert str(secret) not in paths
    assert 'GEM_PATH=' + str(root) not in environment


def test_unknown_launcher_is_not_executed(tmp_path, monkeypatch):
    from core import sandbox
    launcher = tmp_path / 'shim'
    launcher.write_text('#!/bin/sh\nexit 99\n')
    def refuse(*args, **kwargs):
        pytest.fail('unknown launcher was executed')
    monkeypatch.setattr(sandbox, 'run', refuse)
    assert ruby_tool_runtime(str(launcher), str(tmp_path)) == ([], [])


@pytest.mark.parametrize('kind', ['bad-json', 'bad-shape', 'nonzero', 'refusal'])
def test_bad_discovery_cannot_supply_grants(layout, monkeypatch, kind):
    from core import sandbox
    _, launcher, scratch = layout
    def run(command, **options):
        if kind == 'refusal':
            raise sandbox.SandboxSetupError('owned refusal')
        return subprocess.CompletedProcess(command, 1 if kind == 'nonzero' else 0,
                                           '[]' if kind == 'bad-shape' else 'not JSON', '')
    monkeypatch.setattr(sandbox, 'run', run)
    with pytest.raises(sandbox.SandboxSetupError):
        ruby_tool_runtime(str(launcher), str(scratch))


def test_explicit_operator_gem_root_is_used(layout, tmp_path, monkeypatch):
    from core.sandbox import state
    _, launcher, scratch = layout
    root = _gem_root(tmp_path / 'unusual-location' / 'ruby-gems')
    _query(monkeypatch, [])
    monkeypatch.setattr(state, '_cli_sandbox_tool_paths', [str(root)])
    paths, environment = ruby_tool_runtime(str(launcher), str(scratch))
    assert str(root / 'gems') in paths
    assert 'GEM_PATH=' + str(root) in environment
