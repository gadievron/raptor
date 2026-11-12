"""Resolver fixture transports never replace shared process entry points."""

from contextlib import nullcontext
import importlib
import subprocess

import pytest

from core.sandbox import context
from core.sandbox.errors import SandboxFloorError
from core.testing.module_state import isolated_module_state
from packages.sca import resolvers
from packages.sca.resolvers.tests import test_resolvers as native


def _borrowed():
    consumers = {importlib.import_module(type(r).__module__) for r in resolvers._RESOLVERS}
    return {owner: {name: getattr(owner, name) for name in ("_run", "subprocess")}
            for owner in [resolvers, *consumers]}


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_exec_fixture_owns_aliases_and_transports(failure, tmp_path):
    borrowed = _borrowed()
    shared_run, shared_sandbox = subprocess.run, context.run
    shared_net, shared_seccomp = context.check_net_available, context._seccomp
    private_name = vars(native).get("_resolver_exec_context")
    with isolated_module_state(resolvers, {"_CHECK_TOOL_CACHE": {}}):
        with pytest.MonkeyPatch.context() as patch:
            # Match the directory's existing explicit unit-test policy.
            patch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
            cache = native._reset_sandbox_probe_caches.__wrapped__(patch)
            next(cache)
            fixture = native._isolate_resolver_exec_patches.__wrapped__(patch, None)
            owned = next(fixture)
            try:
                assert owned.run_untrusted.__code__ is context.run_untrusted.__code__
                assert owned.run_untrusted_networked.__code__ is context.run_untrusted_networked.__code__
                assert owned.check_net_available() is False
                assert owned._seccomp.check_seccomp_available() is False
                for consumer in borrowed:
                    assert consumer._run is resolvers._run
                    assert consumer.subprocess is native.subprocess
                expected = pytest.raises(failure, match="owned resolver scope failure") if failure else nullcontext()
                with expected:
                    native.test_npm_run_routes_through_sandbox_with_proxy(patch, tmp_path)
                    assert subprocess.run is shared_run
                    assert context.run is shared_sandbox
                    assert context.check_net_available is shared_net
                    assert context._seccomp is shared_seccomp
                    if failure:
                        raise failure("owned resolver scope failure")
            finally:
                try:
                    fixture.close()
                finally:
                    cache.close()
    assert subprocess.run is shared_run
    assert context.run is shared_sandbox
    assert context.check_net_available is shared_net
    assert context._seccomp is shared_seccomp
    assert vars(native).get("_resolver_exec_context") is private_name
    for consumer, before in borrowed.items():
        for name, value in before.items():
            assert getattr(consumer, name) is value


def test_actual_trust_wrapper_still_refuses_without_optin(tmp_path):
    calls = []
    with isolated_module_state(resolvers, {"_CHECK_TOOL_CACHE": {}}):
        with pytest.MonkeyPatch.context() as patch:
            patch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
            cache = native._reset_sandbox_probe_caches.__wrapped__(patch)
            next(cache)
            fixture = native._isolate_resolver_exec_patches.__wrapped__(patch, None)
            next(fixture)
            try:
                native._patch_exec(patch, lambda *a, **k: calls.append((a, k)))
                with pytest.raises(SandboxFloorError):
                    resolvers._run(["owned-tool-never-spawned"], cwd=tmp_path,
                                   timeout=1, proxy_hosts=[], block_network=True)
                assert calls == []
            finally:
                try:
                    fixture.close()
                finally:
                    cache.close()
