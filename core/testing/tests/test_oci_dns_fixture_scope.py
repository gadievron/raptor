"""Registry DNS fixtures leave unrelated numeric socket lookups unchanged."""
from contextlib import contextmanager, nullcontext
import socket

import pytest

from core.oci import registry_hosts
from core.oci.tests import conftest as native
from core.oci.tests import test_blob_redirects as redirects
from core.oci.tests import test_registry_hosts as hosts


_CASES = [
    "default",
    "test_resolved_loopback_refused",
    "test_resolved_nat64_metadata_refused",
    "test_resolved_any_bad_address_refuses",
    "test_resolved_all_global_passes",
    "test_unresolvable_host_refused",
    "test_resolution_gate_ip_literal_skips_dns",
    "test_client_refuses_registry_resolving_to_loopback",
    "test_client_refuses_registry_resolving_to_nat64_metadata",
    "test_redirect_target_held_to_address_policy",
]


@pytest.mark.parametrize("case", _CASES)
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_oci_dns_fixture_restores_private_lookup(case, outcome):
    namespace, resolver = registry_hosts.socket, socket.getaddrinfo
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            native._stub_getaddrinfo.__wrapped__(patch)
            registry_hosts.validate_resolved_registry_addresses("innocent.example")
            if case == "test_redirect_target_held_to_address_policy":
                getattr(redirects, case)(patch)
            elif case != "default":
                getattr(hosts, case)(patch)
            assert socket.getaddrinfo is resolver
            assert registry_hosts.socket is not namespace
            assert registry_hosts.socket.gaierror is socket.gaierror
            answers = socket.getaddrinfo("127.0.0.1", 443, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
            assert {answer[4][0] for answer in answers} == {"127.0.0.1"}
            if outcome:
                raise outcome("owned body failure")
    assert registry_hosts.socket is namespace
    assert socket.getaddrinfo is resolver


@pytest.mark.parametrize("name", [
    "test_offsite_redirect_followed_and_auth_confined",
    "test_offsite_hop_is_terminal_and_empty_body_is_loud",
    "test_cdn_error_carries_status_detail",
])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_redirect_fixture_owns_proxy_lookup_and_cache(name, outcome):
    from core.oci import client
    from core.sandbox import proxy

    cache, values = client._cdn_hosts_extended, set(client._cdn_hosts_extended)
    extension, factory = client._extend_proxy_for_cdn_host, proxy.get_proxy
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            native._stub_getaddrinfo.__wrapped__(patch)
            with contextmanager(redirects._inert_proxy_extension.__wrapped__)(patch) as extensions:
                getattr(redirects, name)(extensions)
                assert extensions == [("cdn.example",)]
                assert client._cdn_hosts_extended is not cache
                assert client._cdn_hosts_extended == {"cdn.example"}
                assert proxy.get_proxy is factory
                assert client._extend_proxy_for_cdn_host is not extension
                if outcome:
                    raise outcome("owned body failure")
    assert client._cdn_hosts_extended is cache
    assert cache == values
    assert proxy.get_proxy is factory
    assert client._extend_proxy_for_cdn_host is extension
