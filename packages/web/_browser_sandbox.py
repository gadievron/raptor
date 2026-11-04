"""Private Playwright driver launcher: Node and Chromium share one outer jail."""
from contextlib import contextmanager, suppress
from functools import lru_cache
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit

from core.atomic_fs import write_new_text

_ENV_LOCK = threading.RLock()
# Enabled only by owned native-test fixtures; never inherit operator DEBUG.
_DRIVER_DIAGNOSTICS = False


@lru_cache(maxsize=1)
def macos_nested_seatbelt_available():
    """Probe applying a second inherited profile, without launching a browser.

    Even allow-default profiles can be refused by the platform. This probes
    kernel capability, not permission to relax the actual browser policy.
    """
    profile = '(version 1)(allow default)'
    command = ['/usr/bin/sandbox-exec', '-p', profile,
               '/usr/bin/sandbox-exec', '-p', profile, '/usr/bin/true']
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                env={'PATH': os.defpath, 'LC_ALL': 'C'},
                                timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def require_inner_sandbox_compatibility(enabled):
    if enabled and sys.platform == 'darwin':
        from core.sandbox.probes import check_seatbelt_available
        if not check_seatbelt_available():
            raise RuntimeError('Browser containment requires usable Seatbelt')
        if not macos_nested_seatbelt_available():
            raise RuntimeError(
                'macOS refuses nested Seatbelt profiles, so Chromium cannot '
                'enable its inner sandbox inside RAPTOR containment. '
                'Use --allow-unsandboxed-chromium to explicitly waive only '
                'the inner layer; RAPTOR outer confinement remains required.')


def browser_runtime_paths(executable=None):
    """Grant installed browser resources read-only, never an ambient HOME."""
    cache = os.environ.get('PLAYWRIGHT_BROWSERS_PATH')
    if cache == '0':
        import playwright
        cache = str(Path(playwright.__file__).parent / 'driver/package/.local-browsers')
    elif not cache:
        if sys.platform == 'darwin':
            cache = str(Path.home() / 'Library/Caches/ms-playwright')
        else:
            cache = str(Path(os.environ.get('XDG_CACHE_HOME', str(Path.home()/'.cache'))) / 'ms-playwright')
    paths = [Path(cache).resolve()]
    if executable:
        selected = Path(executable).resolve()
        bundle = next((p for p in selected.parents if p.suffix == '.app'), None)
        paths.append(bundle or selected.parent)
    from core.sandbox.python_paths import _home_roots
    forbidden = {Path(p).resolve() for p in ('/', '/tmp', '/var/tmp', *_home_roots())}
    for path in paths:
        if any(path == root or path in root.parents for root in forbidden):
            raise ValueError('Browser runtime must be in a dedicated installation directory')
    return [str(path) for path in paths if path.exists()]


def _require_browser_containment():
    """Fail before Playwright starts a transport when prerequisites are absent.

    Delivery is checked again by the strict profile in the child. This early
    gate avoids creating a partially initialised async client on known failures.
    """
    from core.sandbox import probes
    if sys.platform == 'darwin':
        if not probes.check_seatbelt_available():
            raise RuntimeError('Browser containment requires usable Seatbelt')
    elif sys.platform == 'linux':
        from core.sandbox import landlock, seccomp
        if os.getuid() == 0:
            raise RuntimeError('Browser containment requires a non-root Linux operator')
        if not probes.check_mount_available():
            raise RuntimeError('Browser containment requires usable mount/PID namespaces')
        if not seccomp.check_seccomp_available():
            raise RuntimeError('Browser containment requires usable libseccomp')
        if not landlock.check_landlock_available() or landlock._get_landlock_abi() < 4:
            raise RuntimeError('Browser containment requires Landlock ABI 4+')
    else:
        raise RuntimeError('Browser containment requires Linux or macOS')


@contextmanager
def confined_driver(base_url, executable=None, proxy=None):
    """Temporarily select a private executable using Playwright's Node override.

    The override is restored immediately after transport startup. Serialise that
    brief process-global environment change; browser operations remain concurrent.
    Control files are outside the child's writable work directory.
    """
    _require_browser_containment()
    from playwright._impl._driver import compute_driver_executable
    with _ENV_LOCK:
        node, cli = compute_driver_executable()
    node = shutil.which(node) or node
    if not Path(node).is_file():
        raise RuntimeError('Playwright Node runtime is missing')
    # Chromium's singleton uses a pathname Unix socket under TMPDIR.
    # Session/pytest scratch paths can exceed sockaddr_un even when writable.
    # Keep this owned, reaper-covered directory short on Linux and macOS.
    private_base = '/tmp'
    with tempfile.TemporaryDirectory(prefix='raptor-web-browser-', dir=private_base) as private:
        root = Path(private)
        work = root / 'work'
        work.mkdir(mode=0o700)
        ports = {urlsplit(base_url).port or (443 if urlsplit(base_url).scheme == 'https' else 80)}
        if proxy:
            server = proxy['server']
            parsed = urlsplit(server if '://' in server else 'http://' + server)
            default_port = 1080 if parsed.scheme in ('socks4', 'socks5', 'socks5h') else (443 if parsed.scheme == 'https' else 80)
            ports.add(parsed.port if parsed.port is not None else default_port)
        cache_paths = browser_runtime_paths(executable)
        config = dict(node=str(Path(node).resolve()), cli=str(Path(cli).resolve()),
                      work=str(work), reads=cache_paths, ports=sorted(ports), diagnostics=_DRIVER_DIAGNOSTICS)
        cache = os.environ.get('PLAYWRIGHT_BROWSERS_PATH')
        if cache == '0':
            config['browsers'] = '0'
        elif cache:
            config['browsers'] = str(Path(cache).resolve())
        else:
            config['browsers'] = cache_paths[0] if cache_paths else ''
        control = root / 'driver.json'
        write_new_text(control, json.dumps(config), mode=0o600)
        launcher = root / 'node'
        helper = Path(__file__).with_name('_browser_driver.py')
        write_new_text(launcher, '#!/bin/sh\nexec ' + shlex.join([
            sys.executable, '-I', '-B', str(helper), str(root)]) + ' "$@"\n', mode=0o700)
        def start(factory):
            with _ENV_LOCK:
                previous = os.environ.get('PLAYWRIGHT_NODEJS_PATH')
                os.environ['PLAYWRIGHT_NODEJS_PATH'] = str(launcher)
                try:
                    manager = factory()
                    try:
                        return manager.start()
                    except BaseException:
                        # Startup can fail after the transport child exists.
                        # Close the public context manager before removing its
                        # private launcher/control files; preserve the cause.
                        close = getattr(manager, '__exit__', None)
                        if close is not None:
                            with suppress(Exception):
                                close(None, None, None)
                        raise
                finally:
                    if previous is None:
                        os.environ.pop('PLAYWRIGHT_NODEJS_PATH', None)
                    else:
                        os.environ['PLAYWRIGHT_NODEJS_PATH'] = previous
        yield start
