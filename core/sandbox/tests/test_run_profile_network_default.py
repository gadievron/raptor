"""The one-shot wrapper must preserve profile defaults and explicit overrides."""

from contextlib import contextmanager
from subprocess import CompletedProcess

import pytest

from core.sandbox import context
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("profile", [None, "full", "none", "network-only", "target_run", "frida"])
@pytest.mark.parametrize("override", [None, False, True])
def test_run_preserves_network_default_or_override(profile, override):
    supplied = {}
    result = CompletedProcess(["owned-no-execution"], 0)

    @contextmanager
    def capture(**kwargs):
        supplied.update(kwargs)
        yield lambda *args, **kw: result

    view = module_function_view(context, bindings={"sandbox": capture})
    kwargs = {} if override is None else {"block_network": override}
    assert view.run(["owned-no-execution"], profile=profile, **kwargs) is result
    assert supplied["profile"] == profile
    expected = context._UNSET if override is None else override
    assert supplied["block_network"] is expected
