"""Web DNS fixtures leave unrelated numeric socket resolution untouched."""
from contextlib import nullcontext
import builtins
import socket

import pytest

from packages.web import client, external_validators
from packages.web.tests import test_infra_hardening as native


@pytest.mark.parametrize("name", [
    "test_private_host_recognizes_hostnames_by_resolution",
    "test_hostname_colliding_with_block_wording_is_resolved_not_blocked",
], ids=["private-host", "client-validation"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_web_dns_fixture_owns_only_its_lookup(name, outcome):
    resolver, importer = socket.getaddrinfo, builtins.__import__
    namespace = client.socket
    descriptor = vars(external_validators.ExternalValidatorRunner)["_is_private_host"]
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            if name == "test_private_host_recognizes_hostnames_by_resolution":
                lookup = native._private_host_lookup.__wrapped__()
                assert lookup[0].__code__ is descriptor.__func__.__code__
                getattr(native, name)(patch, lookup)
            else:
                getattr(native, name)(patch)
                assert client.socket is not namespace
            assert socket.getaddrinfo is resolver
            assert builtins.__import__ is importer
            assert vars(external_validators.ExternalValidatorRunner)["_is_private_host"] is descriptor
            answers = socket.getaddrinfo("127.0.0.1", 443, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
            assert {answer[4][0] for answer in answers} == {"127.0.0.1"}
            if outcome:
                raise outcome("owned body failure")
    assert client.socket is namespace
    assert socket.getaddrinfo is resolver
    assert builtins.__import__ is importer
    assert vars(external_validators.ExternalValidatorRunner)["_is_private_host"] is descriptor
