"""Browser dispatch contracts without accounts, real services or a browser."""
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest

from packages.web import _browser_driver as driver
from packages.web import _browser_sandbox as boundary


from core.testing.module_bindings import patch_module_attribute

import packages.web._browser_sandbox as _tempfile_owner


@pytest.fixture(autouse=True)
def _owned_tempfile_namespace(monkeypatch):
    """Share temporary-root faults only among this file's consumers."""
    from core.testing.tempdirs import private_tempfile_module
    import packages.web._browser_sandbox as consumer_0

    private = private_tempfile_module(consumer_0.tempfile)
    monkeypatch.setattr(consumer_0, "tempfile", private)
    monkeypatch.setitem(globals(), "tempfile", private)


@pytest.fixture(autouse=True)
def selected_nonroot_driver(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(driver, 'os', SimpleNamespace(environ=os.environ, defpath=os.defpath, getuid=lambda: 1001))


@pytest.mark.parametrize('waived', [False, True])
@pytest.mark.parametrize('diagnostics', [False, True])
def test_inner_sandbox_is_explicit_and_outer_policy_is_unchanged(tmp_path, monkeypatch, waived, diagnostics):
    from core import sandbox
    from core.sandbox import landlock
    from packages.web.browser import _launch_options
    monkeypatch.setattr(landlock, 'check_landlock_available', lambda: True)
    monkeypatch.setattr(landlock, '_get_landlock_abi', lambda: 4)
    monkeypatch.setenv('NODE_OPTIONS', '--require=/hostile/entry.js')
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('SECRET_KEY', 'owned-secret')
    monkeypatch.setenv('DEBUG', 'operator:*')
    seen = []
    def run(command, **options):
        seen.append(options)
        assert options['profile'] == 'chromium'
        assert str(Path(config['node']).parent) in options['tool_paths']
        assert config['node'] not in options['tool_paths']
        assert options['restrict_reads'] and options['fake_home'] is False
        for name in ('HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME'):
            assert Path(options['env'][name]).is_dir()
            assert Path(options['env'][name]).is_relative_to(tmp_path)
        assert options['limits']['nproc'] == 256
        assert options['exclude_tmp_baseline'] and options['require_fresh_procfs']
        assert options['strict_env'] and options['strip_trust_markers']
        assert options['stdin'] == 0 and options['capture_output'] is False
        assert options['allowed_tcp_ports'] == [443]
        assert options['env'].get('DEBUG') == ('pw:browser' if diagnostics else None)
        assert not {'NODE_OPTIONS', '_RAPTOR_TRUSTED', 'SECRET_KEY'} & options['env'].keys()
        assert options['cwd'] == str(tmp_path)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(sandbox, 'run', run)
    config = dict(node='/owned/playwright/driver/node', cli='/owned/cli.js', work=str(tmp_path), reads=[], ports=[443], diagnostics=diagnostics)
    assert _launch_options(allow_unsandboxed_chromium=waived)['chromium_sandbox'] is not waived
    assert driver.run_driver(config, ['/owned/cli.js', 'run-driver']) == 0
    assert len(seen) == 1


@pytest.mark.parametrize('previous', [None, '/operator/node'])
@pytest.mark.parametrize('proxy_server,proxy_port', [('http://proxy.invalid:8080', 8080), ('proxy.invalid:8080', 8080), ('socks5://proxy.invalid', 1080)])
def test_launcher_restores_environment_and_keeps_controls_outside_work(tmp_path, monkeypatch, previous, proxy_server, proxy_port):
    node, cli = tmp_path/'node', tmp_path/'package/cli.js'
    node.write_text('owned runtime')
    cli.parent.mkdir()
    cli.write_text('owned driver')
    module = ModuleType('playwright._impl._driver')
    module.compute_driver_executable = lambda: (str(node), str(cli))
    monkeypatch.setitem(sys.modules, 'playwright._impl._driver', module)
    monkeypatch.setattr(boundary, '_require_browser_containment', lambda: None)
    monkeypatch.setattr(boundary, '_DRIVER_DIAGNOSTICS', True)
    monkeypatch.setattr(boundary, 'browser_runtime_paths', lambda *a: [str(tmp_path/'cache')])
    if previous is None:
        monkeypatch.delenv('PLAYWRIGHT_NODEJS_PATH', raising=False)
    else:
        monkeypatch.setenv('PLAYWRIGHT_NODEJS_PATH', previous)
    long_base = tmp_path / ('long-session-' * 8)
    long_base.mkdir()
    monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(long_base))
    launched = []
    closed = []
    class Factory:
        def start(self):
            launcher = Path(os.environ['PLAYWRIGHT_NODEJS_PATH'])
            launched.append(launcher)
            import json
            config = json.loads((launcher.parent/'driver.json').read_text())
            assert len(os.fsencode(config['work'] + '/org.chromium.Chromium.123456/SingletonSocket')) < 104
            assert Path(config['work']).parent == launcher.parent
            assert not launcher.is_relative_to(Path(config['work']))
            assert config['ports'] == sorted([proxy_port, 8443])
            assert config['diagnostics'] is True
            raise RuntimeError('owned startup refusal')
        def __exit__(self, *args):
            closed.append(True)
    with boundary.confined_driver('https://target.invalid:8443', proxy={'server':proxy_server}) as start:
        assert os.environ.get('PLAYWRIGHT_NODEJS_PATH') == previous
        with pytest.raises(RuntimeError, match='startup refusal'):
            start(Factory)
        assert os.environ.get('PLAYWRIGHT_NODEJS_PATH') == previous
        assert launched[0].exists()
    assert not launched[0].exists()
    assert closed == [True]


def test_runtime_grants_refuse_home_and_shared_tmp(monkeypatch):
    for root in (str(Path.home()), '/tmp', '/'):
        monkeypatch.setenv('PLAYWRIGHT_BROWSERS_PATH', root)
        with pytest.raises(ValueError, match='dedicated'):
            boundary.browser_runtime_paths()


def test_waiver_requires_boolean():
    from packages.web.browser import _launch_options
    with pytest.raises(TypeError):
        _launch_options(allow_unsandboxed_chromium='false')


def test_outer_profile_refuses_missing_namespaces(tmp_path, monkeypatch):
    from core.sandbox import context, state, SandboxSetupError
    monkeypatch.setattr(state, '_cli_sandbox_profile', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    if sys.platform != 'linux':
        monkeypatch.setattr(context, 'check_seatbelt_available', lambda: False)
    else:
        monkeypatch.setattr(context, 'check_net_available', lambda: False)
    with pytest.raises(SandboxSetupError):
        with context.sandbox(profile='chromium', target=str(tmp_path), output=str(tmp_path)):
            pytest.fail('outer profile degraded instead of refusing')


def test_driver_rejects_undeclared_command_before_dispatch(tmp_path, monkeypatch):
    from core import sandbox
    monkeypatch.setattr(sandbox, 'run', lambda *a, **k: pytest.fail('unexpected execution'))
    config = dict(cli='/owned/cli.js')
    with pytest.raises(ValueError, match='Unexpected'):
        driver.run_driver(config, ['/owned/other.js', 'run-driver'])


def test_inner_waiver_does_not_waive_linux_landlock(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from core.sandbox import landlock, SandboxSetupError
    monkeypatch.setattr(driver, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(landlock, 'check_landlock_available', lambda: False)
    with pytest.raises(SandboxSetupError, match='Landlock'):
        driver.run_driver(dict(cli='/owned/cli.js'), ['/owned/cli.js', 'run-driver'])


def test_cli_waiver_requires_browser(monkeypatch):
    from packages.web import scanner
    monkeypatch.setattr(sys, 'argv', ['web', '--url', 'https://owned.invalid', '--allow-unsandboxed-chromium'])
    with pytest.raises(SystemExit) as raised:
        scanner.main()
    assert raised.value.code == 2


@pytest.mark.parametrize('override', [dict(skip_mount_ns=True), dict(skip_pid_ns=True),
                                     dict(landlock_required=False), dict(rootfs='/owned/image')])
def test_browser_backend_refuses_host_proc_and_fallback_lanes(tmp_path, monkeypatch, override):
    from core.sandbox import _spawn
    patch_module_attribute(monkeypatch, _spawn, 'os', 'getuid', lambda: 1001)
    options = dict(target=str(tmp_path), output=str(tmp_path), block_network=False,
                   nproc_limit=0, limits={}, writable_paths=[str(tmp_path)],
                   readable_paths=[], allowed_tcp_ports=[443], seccomp_profile='chromium',
                   seccomp_block_udp=False, env={}, cwd=str(tmp_path), timeout=1)
    options.update(override)
    with pytest.raises(ValueError, match='Chromium profile requires'):
        _spawn.run_sandboxed(['/bin/true'], **options)


@pytest.mark.parametrize('oversized', [False, True])
def test_private_launcher_reads_bounded_control_directory(tmp_path, monkeypatch, oversized):
    import json
    control = tmp_path/'driver.json'
    control.write_text(' ' * 65537 if oversized else json.dumps({'cli':'/owned/cli.js'}))
    monkeypatch.setattr(sys, 'path', list(sys.path))
    monkeypatch.setattr(sys, 'argv', ['driver', str(tmp_path), '/owned/cli.js', 'run-driver'])
    seen = []
    def run(config, arguments):
        seen.append((config, arguments))
        return 0
    monkeypatch.setattr(driver, 'run_driver', run)
    assert driver.main() == (126 if oversized else 0)
    assert len(seen) == (0 if oversized else 1)


def test_linux_root_operator_cannot_enter_proc_write_profile(monkeypatch):
    from types import SimpleNamespace
    from core.sandbox import SandboxSetupError
    monkeypatch.setattr(driver, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(driver.os, 'getuid', lambda: 0)
    with pytest.raises(SandboxSetupError, match='non-root'):
        driver.run_driver(dict(cli='/owned/cli.js'), ['/owned/cli.js', 'run-driver'])


def test_driver_accepts_same_installed_cli_through_symlink(tmp_path, monkeypatch):
    from core import sandbox
    from core.sandbox import landlock
    actual = tmp_path/'runtime'
    actual.mkdir()
    cli = actual/'cli.js'
    cli.write_text('owned runtime')
    alias = tmp_path/'runtime-alias'
    alias.symlink_to(actual, target_is_directory=True)
    monkeypatch.setattr(landlock, 'check_landlock_available', lambda: True)
    monkeypatch.setattr(landlock, '_get_landlock_abi', lambda: 4)
    seen = []
    def run(command, **options):
        seen.append(command)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(sandbox, 'run', run)
    config = dict(node='/usr/bin/node', cli=str(cli), work=str(tmp_path), reads=[], ports=[443])
    assert driver.run_driver(config, [str(alias/'cli.js'), 'run-driver']) == 0
    assert seen[0][-2:] == [str(cli), 'run-driver']


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_preflight_rejects_absent_outer_backend_before_transport(monkeypatch, platform):
    from types import SimpleNamespace
    from core.sandbox import probes
    monkeypatch.setattr(boundary, 'sys', SimpleNamespace(platform=platform))
    monkeypatch.setattr(probes, 'check_mount_available', lambda: False)
    monkeypatch.setattr(probes, 'check_seatbelt_available', lambda: False)
    with pytest.raises(RuntimeError, match='Browser containment requires'):
        boundary._require_browser_containment()


def test_live_browser_suite_does_not_launch_during_collection(monkeypatch):
    import importlib.util
    from packages.web import browser
    monkeypatch.setattr(browser, 'browser_available', lambda: pytest.fail('browser started during collection'))
    path = Path(__file__).with_name('test_browser_live.py')
    spec = importlib.util.spec_from_file_location('owned_browser_collection', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


@pytest.mark.parametrize('render_result,frame,available', [(2, b'\x89PNG\r\n\x1a\n', True),
                                                               (None, b'\x89PNG\r\n\x1a\n', False),
                                                               (2, b'invalid frame', False)])
def test_nested_seatbelt_probe_uses_real_confined_browser_without_waiver(monkeypatch, render_result, frame, available):
    from unittest.mock import MagicMock
    from packages.web import browser
    seen = []
    engine = MagicMock()
    engine.__enter__.return_value = engine
    engine._launch_kwargs = {}
    page = engine._context.new_page.return_value
    page.evaluate.return_value = render_result
    page.screenshot.return_value = frame
    def factory(origin, **options):
        assert boundary._INNER_PROBE_STATE.active is True
        assert origin == 'http://127.0.0.1:1'
        assert options == {'allow_unsandboxed_chromium': False}
        seen.append(origin)
        return engine
    monkeypatch.setattr(browser, 'BrowserEngine', factory)
    boundary.macos_nested_seatbelt_available.cache_clear()
    try:
        assert boundary.macos_nested_seatbelt_available() is available
        assert boundary.macos_nested_seatbelt_available() is available
        assert len(seen) == 1
        assert engine._proxy_settings() is None
        assert engine._launch_kwargs == {'timeout': 10_000}
        assert engine._timeout_ms == 5_000
        page.set_content.assert_called_once_with('<html><body>Browser sandbox probe</body></html>', timeout=5_000)
        page.screenshot.assert_called_once_with(timeout=5_000)
        page.evaluate.assert_called_once_with('1 + 1')
        page.close.assert_called_once()
        engine.__exit__.assert_called_once()
        assert boundary._INNER_PROBE_STATE.active is False
    finally:
        boundary.macos_nested_seatbelt_available.cache_clear()


@pytest.mark.parametrize('error', [PermissionError('owned'), subprocess.TimeoutExpired('owned', 5)])
def test_nested_seatbelt_probe_refuses_errors_and_timeouts(monkeypatch, error):
    from unittest.mock import MagicMock
    from packages.web import browser
    engine = MagicMock()
    engine.__enter__.return_value = engine
    engine._launch_kwargs = {}
    engine._context.new_page.side_effect = error
    monkeypatch.setattr(browser, 'BrowserEngine', lambda *args, **kwargs: engine)
    boundary.macos_nested_seatbelt_available.cache_clear()
    try:
        assert boundary.macos_nested_seatbelt_available() is False
        assert boundary._INNER_PROBE_STATE.active is False
        engine.__exit__.assert_called_once()
    finally:
        boundary.macos_nested_seatbelt_available.cache_clear()


def test_mac_probe_recursion_guard_is_thread_local_and_retains_outer_check(monkeypatch):
    from types import SimpleNamespace
    from core.sandbox import probes
    import threading
    monkeypatch.setattr(boundary, 'sys', SimpleNamespace(platform='darwin'))
    monkeypatch.setattr(probes, 'check_seatbelt_available', lambda: True)
    monkeypatch.setattr(boundary, 'macos_nested_seatbelt_available', lambda: False)
    monkeypatch.setattr(boundary._INNER_PROBE_STATE, 'active', True, raising=False)
    boundary.require_inner_sandbox_compatibility(True)
    refused = []
    def other_thread():
        try:
            boundary.require_inner_sandbox_compatibility(True)
        except RuntimeError:
            refused.append(True)
    thread = threading.Thread(target=other_thread)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive() and refused == [True]
    monkeypatch.setattr(probes, 'check_seatbelt_available', lambda: False)
    with pytest.raises(RuntimeError, match='requires usable Seatbelt'):
        boundary.require_inner_sandbox_compatibility(True)


@pytest.mark.parametrize('available', [False, True])
def test_required_mac_inner_policy_tracks_kernel_nesting_capability(monkeypatch, available):
    from types import SimpleNamespace
    from core.sandbox import probes
    monkeypatch.setattr(boundary, 'sys', SimpleNamespace(platform='darwin'))
    monkeypatch.setattr(probes, 'check_seatbelt_available', lambda: True)
    monkeypatch.setattr(boundary, 'macos_nested_seatbelt_available', lambda: available)
    if available:
        boundary.require_inner_sandbox_compatibility(True)
    else:
        with pytest.raises(RuntimeError, match='--allow-unsandboxed-chromium'):
            boundary.require_inner_sandbox_compatibility(True)


def test_explicit_mac_inner_waiver_does_not_probe_or_waive_outer_policy(monkeypatch):
    from types import SimpleNamespace
    from core.sandbox import probes
    monkeypatch.setattr(boundary, 'sys', SimpleNamespace(platform='darwin'))
    monkeypatch.setattr(boundary, 'macos_nested_seatbelt_available', lambda: pytest.fail('inner probe under explicit waiver'))
    boundary.require_inner_sandbox_compatibility(False)
    monkeypatch.setattr(probes, 'check_seatbelt_available', lambda: False)
    with pytest.raises(RuntimeError, match='requires usable Seatbelt'):
        boundary._require_browser_containment()


@pytest.mark.parametrize('waived', [False, True])
def test_native_browser_case_skips_missing_optional_playwright_before_setup(monkeypatch, waived):
    import importlib.util
    monkeypatch.setitem(sys.modules, 'playwright', None)
    monkeypatch.setitem(sys.modules, 'playwright.sync_api', None)
    path = Path(__file__).with_name('test_browser_sandbox_native.py')
    spec = importlib.util.spec_from_file_location('owned_optional_browser_case', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # None setup objects ensure the skip precedes filesystem/server startup.
    with pytest.raises(pytest.skip.Exception, match='optional Playwright dependency'):
        module.test_real_browser_javascript_and_explicit_inner_policy(None, None, waived, None)
