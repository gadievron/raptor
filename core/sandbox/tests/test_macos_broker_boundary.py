"""Query Seatbelt decisions without contacting host brokers or account state."""
import json
import sys

import pytest

from core.sandbox import seatbelt

pytestmark = [pytest.mark.integration, pytest.mark.slow, pytest.mark.darwin_native]


@pytest.mark.parametrize('profile', ['full', 'strict', 'debug', 'frida', 'chromium'])
@pytest.mark.parametrize('audit', [False, True])
def test_native_broker_denials_survive_specialized_profiles(tmp_path, profile, audit):
    if sys.platform != 'darwin':
        pytest.skip('macOS Seatbelt required')
    from core.sandbox import run
    from core.sandbox.probes import check_seatbelt_available
    from core.sandbox.python_paths import python_runtime_tool_paths

    if not check_seatbelt_available():
        pytest.skip('Seatbelt required')
    # The fixed prefix argtypes matter for Apple's arm64 variadic ABI.
    # sandbox_check only asks about policy; no service is contacted.
    script = '''
import ctypes, json, os
lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
check = lib.sandbox_check
check.restype = ctypes.c_int
check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
# Positive controls distinguish a functioning query from a blanket error.
assert check(os.getpid(), b'mach-lookup', 2,
             ctypes.c_char_p(b'com.apple.system.logger')) == 0
assert check(os.getpid(), b'mach-register', 2,
             ctypes.c_char_p(b'org.raptor.test.nonexistent')) == 0
services = SERVICES
results = {}
for operation in ('mach-lookup', 'mach-register'):
    for service in services:
        answer = check(os.getpid(), operation.encode(), 2,
                       ctypes.c_char_p(service.encode()))
        assert answer > 0, (operation, service, answer)
        results[operation + ':' + service] = answer
print(json.dumps(results))
'''.replace('SERVICES', repr(seatbelt.MACOS_BLOCKED_BROKER_SERVICES))
    work = tmp_path / 'work'
    work.mkdir()
    result = run(
        [sys.executable, '-I', '-S', '-c', script],
        target=str(work), output=str(work), profile=profile,
        audit=audit, audit_verbose=audit,
        restrict_reads=True, fake_home=True,
        tool_paths=python_runtime_tool_paths(),
        exclude_tmp_baseline=True, require_fresh_procfs=True,
        capture_output=True, text=True, timeout=30, max_capture_bytes=8192,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.sandbox_info['containment_tier'] == 'seatbelt'
    decisions = json.loads(result.stdout)
    assert len(decisions) == 2 * len(seatbelt.MACOS_BLOCKED_BROKER_SERVICES)
    assert all(value > 0 for value in decisions.values())
