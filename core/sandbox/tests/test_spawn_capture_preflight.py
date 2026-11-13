"""Direct backend capture-limit admission, stopped before setup or fork."""

from types import SimpleNamespace

import pytest

from core.sandbox import _spawn
from core.testing.module_views import module_function_view


class BeforeSetup(BaseException):
    pass


def _call(cap):
    def stop_before_setup(descriptor):
        raise BeforeSetup()

    private = module_function_view(_spawn, bindings={"os": SimpleNamespace(fstat=stop_before_setup)})
    private.run_sandboxed(
        ["/bin/true"], target=None, output=None, block_network=True,
        nproc_limit=64, limits={}, writable_paths=[], readable_paths=None,
        allowed_tcp_ports=None, seccomp_profile=None, seccomp_block_udp=False,
        env={}, cwd=None, timeout=1, pass_fds=(0,), max_capture_bytes=cap,
    )


@pytest.mark.parametrize("cap,kind", [("invalid", ValueError), (float("nan"), ValueError),
                                      (float("inf"), OverflowError)])
def test_invalid_capture_limit_refuses_before_setup(cap, kind):
    with pytest.raises(kind):
        _call(cap)


@pytest.mark.parametrize("cap", [None, -1, 0, "4", 4])
def test_valid_capture_limit_reaches_descriptor_validation(cap):
    with pytest.raises(BeforeSetup):
        _call(cap)
