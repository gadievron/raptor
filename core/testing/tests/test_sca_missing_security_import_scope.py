"""Missing security dependencies are simulated only in the SCA switchboard."""
import builtins
from contextlib import nullcontext

import pytest

from core.security import cc_trust, codeql_trust
from packages.sca.tests import test_trust_switchboard as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_missing_security_fixture_preserves_global_state(failure):
    importer = builtins.__import__
    resolve = native.resolve_repo_trust
    view = native.module_function_view
    overrides = (cc_trust._trust_override_set, codeql_trust._trust_override_set)
    setters = (cc_trust.set_trust_override, codeql_trust.set_trust_override)
    refusals = []
    results = []

    def checked(module, *, import_hook=None):
        assert module is native._scan_args

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            try:
                return import_hook(name, *args, **kwargs)
            except ImportError as exc:
                assert name in ("core.security.cc_trust", "core.security.codeql_trust")
                assert str(exc) == "blocked for test: " + name
                refusals.append(name)
                raise

        private = view(module, import_hook=observed)
        original = private.resolve_repo_trust
        assert original.__code__ is resolve.__code__

        def run(args):
            result = original(args)
            assert result is args.trust_repo is True
            results.append(result)
            if failure:
                raise failure("owned body failure")
            return result

        private.resolve_repo_trust = run
        return private

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        native._no_project_trust_markers.__wrapped__(owner)
        calls = native.override_spy.__wrapped__(owner)
        owner.setattr(native, "module_function_view", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.TestResolveRepoTrust().test_survives_missing_security_modules(patch)
        assert refusals == ["core.security.cc_trust", "core.security.codeql_trust"]
        assert results == [True]
        assert calls == {"cc": [], "codeql": []}
        assert native.resolve_repo_trust is resolve
        assert builtins.__import__ is importer
        assert (cc_trust._trust_override_set, codeql_trust._trust_override_set) == overrides
    assert (cc_trust.set_trust_override, codeql_trust.set_trust_override) == setters
    assert native.module_function_view is view
