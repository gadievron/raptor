"""Sanitised probe fixtures own only their intended consumer transport."""

from contextlib import nullcontext
import os
import subprocess

import pytest

from packages.sca import resolvers
from packages.sca.resolvers import yarn
from packages.sca.resolvers.tests import test_probe_env_hygiene as native


@pytest.mark.parametrize("name,consumer,other", [
    ("test_check_tool_uses_sanitised_env", resolvers, yarn),
    ("test_yarn_version_probe_uses_sanitised_env", yarn, resolvers),
], ids=["availability", "yarn"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_probe_env_fixture_owns_transport_and_restores_state(name, consumer, other, failure):
    original_namespace, original_run = consumer.subprocess, subprocess.run
    original_other = other.subprocess
    original_cache = resolvers._CHECK_TOOL_CACHE
    cache_values = dict(original_cache)
    keys = ("LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS")
    original_env = {key: (key in os.environ, os.environ.get(key)) for key in keys}
    expected = pytest.raises(failure, match="owned probe body failure") if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            getattr(native, name)(patch)
            assert subprocess.run is original_run
            assert consumer.subprocess is not original_namespace
            assert consumer.subprocess.run is not original_run
            assert consumer.subprocess.TimeoutExpired is original_namespace.TimeoutExpired
            assert other.subprocess is original_other
            if failure:
                raise failure("owned probe body failure")
    assert consumer.subprocess is original_namespace
    assert subprocess.run is original_run
    assert other.subprocess is original_other
    assert resolvers._CHECK_TOOL_CACHE is original_cache
    assert original_cache == cache_values
    assert {key: (key in os.environ, os.environ.get(key)) for key in keys} == original_env
