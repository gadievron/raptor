"""Native browser and driver boundaries; owned loopback pages/processes only."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import sys
import threading

import pytest

pytestmark = [pytest.mark.slow, pytest.mark.integration,
              pytest.mark.linux_native, pytest.mark.darwin_native]


@pytest.fixture(autouse=True)
def native_host(monkeypatch):
    from packages.web import _browser_sandbox
    monkeypatch.setattr(_browser_sandbox, '_DRIVER_DIAGNOSTICS', True)
    if sys.platform == 'linux':
        from core.sandbox.probes import check_mount_available
        from core.sandbox.landlock import check_landlock_available, _get_landlock_abi
        if not check_mount_available() or not check_landlock_available() or _get_landlock_abi() < 4:
            pytest.skip('native mount/PID namespace and Landlock ABI 4+ required')
    elif sys.platform == 'darwin':
        from core.sandbox.probes import check_seatbelt_available
        if not check_seatbelt_available():
            pytest.skip('native Seatbelt required')
    else:
        pytest.skip('native Linux or macOS required')


def test_owned_driver_cannot_escape_outer_boundary(tmp_path, request):
    from core.sandbox.python_paths import python_runtime_tool_paths
    from packages.web._browser_driver import run_driver
    work, tools = tmp_path/'work', tmp_path/'tools'
    work.mkdir()
    tools.mkdir()
    secret = tmp_path/'secret'
    secret.write_text('owned private canary')
    outside = tmp_path/'forbidden'
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    request.addfinalizer(listener.close)
    script = tools/'probe.py'
    script.write_text('''import json, os, pathlib, socket, sys
work, secret, outside = map(pathlib.Path, sys.argv[2:5])
try: connection = socket.create_connection(('127.0.0.1', int(sys.argv[5])), timeout=1)
except OSError: pass
else:
    connection.close()
    raise AssertionError('unapproved TCP port reachable')
for path in (secret, outside):
    try: path.read_bytes()
    except OSError: pass
    else: raise AssertionError('outside read allowed')
    try: path.write_text('forbidden')
    except OSError: pass
    else: raise AssertionError('outside write allowed')
assert os.environ['HOME'] != str(secret.parent)
if sys.platform == 'linux':
    assert os.getuid() == 1000 and os.geteuid() == 1000
    try: fd = os.open('/proc/1/mem', os.O_RDONLY)
    except OSError: pass
    else:
        os.close(fd)
        raise AssertionError('private init memory readable')
    for path in ('/proc/sys/kernel/hostname', '/proc/sysrq-trigger', '/proc/1/mem'):
        try: fd = os.open(path, os.O_WRONLY)
        except OSError: pass
        else:
            os.close(fd)
            raise AssertionError('protected proc control writable: ' + path)
(work/'proof.json').write_text(json.dumps({'contained': True}))
''')
    # The production wrapper admits only the driver argument vector. The owned
    # script receives its fixture arguments in a generated Python entry shim.
    shim = tools/'cli.py'
    shim.write_text('import runpy,sys\nsys.argv='+repr([str(script),'run-driver',str(work),str(secret),str(outside),str(listener.getsockname()[1])])+'\nrunpy.run_path('+repr(str(script))+',run_name="__main__")\n')
    config = dict(node=sys.executable, cli=str(shim), work=str(work),
                  reads=python_runtime_tool_paths(), ports=[443])
    assert run_driver(config, [str(shim), 'run-driver']) == 0
    assert json.loads((work/'proof.json').read_text()) == {'contained': True}
    assert secret.read_text() == 'owned private canary'
    assert not outside.exists()


@pytest.mark.parametrize('waived', [False, True])
def test_real_browser_javascript_and_explicit_inner_policy(tmp_path, monkeypatch, waived, record_property):
    from packages.web._browser_sandbox import macos_nested_seatbelt_available
    if sys.platform == 'darwin' and not waived and not macos_nested_seatbelt_available():
        from packages.web.browser import BrowserEngine
        with pytest.raises(RuntimeError, match='macOS refuses nested Seatbelt'):
            with BrowserEngine('http://127.0.0.1'):
                pytest.fail('required inner sandbox was silently waived')
        record_property('chromium_inner_policy', 'required-refused-nesting-unavailable')
        return
    record_property('chromium_inner_policy', 'explicit-waiver' if waived else 'required-enabled')
    from packages.web.browser import BrowserEngine
    public = tmp_path/'public'
    public.mkdir()
    (public/'index.html').write_text('<html><body><script>let a=document.createElement("a");a.href="/owned-js";a.textContent="owned";document.body.appendChild(a)</script></body></html>')
    server = ThreadingHTTPServer(('127.0.0.1', 0), partial(SimpleHTTPRequestHandler, directory=str(public)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Owned target: never use an operator proxy or network account.
    for name in ('HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy'):
        monkeypatch.delenv(name, raising=False)
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with BrowserEngine(base, allow_unsandboxed_chromium=waived) as engine:
            rendered = engine.render(base+'/index.html')
            assert rendered is not None
            assert base+'/owned-js' in rendered.links
            cdp = engine._browser.new_browser_cdp_session()
            arguments = cdp.send('Browser.getBrowserCommandLine')['arguments']
            assert ('--no-sandbox' in arguments) is waived
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
