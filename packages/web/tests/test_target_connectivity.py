"""Target proxy admission and on-wire header checks."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from packages.web.origin_verify import HEADER_NAME, read_value
from packages.web.scanner import WebScanner, build_arg_parser
from packages.web.tests.http_server import start_http_server


class _Target(BaseHTTPRequestHandler):
    received: list[dict[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).received.append(dict(self.headers))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def target_server(request):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    start_http_server(server, lambda callback, *args: request.addfinalizer(lambda: callback(*args)))
    _Target.received = []
    return f"http://127.0.0.1:{server.server_port}"


@pytest.mark.integration
def test_target_header_reaches_both_real_clients(target_server, tmp_path):
    value = "a" * 64
    scanner = WebScanner(
        target_server, out_dir=tmp_path / "scan", origin_verify=value,
        block_private_ips=False,
    )
    assert scanner.client.get("/").status_code == 200
    assert scanner._make_principal_client().get("/").status_code == 200
    assert len(_Target.received) == 2
    assert all(headers.get(HEADER_NAME) == value for headers in _Target.received)


def test_target_host_admitted_before_client_construction(monkeypatch, tmp_path):
    from core.llm import egress
    from core.sandbox import proxy

    admitted = []
    monkeypatch.setattr(egress, "_enabled", True)
    monkeypatch.setattr(proxy, "get_proxy", lambda hosts: admitted.extend(hosts))
    scanner = WebScanner(
        "https://target.example/path", out_dir=tmp_path / "scan",
        required_hosts=["Login.Example.Net", "login.example.net"],
    )
    assert admitted == ["target.example", "login.example.net"]
    assert scanner.client.base_url == "https://target.example/path"


def test_unicode_target_uses_transport_idna_form(monkeypatch):
    from core.llm import egress
    from core.sandbox import proxy
    from urllib3.util import parse_url

    admitted = []
    monkeypatch.setattr(egress, "_enabled", True)
    monkeypatch.setattr(proxy, "get_proxy", lambda hosts: admitted.extend(hosts))
    egress.register_web_target("https://faß.de/path")
    egress.register_web_target("https://[::1]/")
    egress.register_web_target("https://svc_name.internal/")
    assert admitted == ["xn--fa-hia.de", "::1", "svc_name.internal"]
    assert admitted[0] == parse_url("https://faß.de/path").host


@pytest.mark.parametrize("url", [
    "https://*.example.net", "https://example.net*", "ftp://example.net",
])
def test_proxy_admission_rejects_wildcards_and_non_http(url):
    from core.llm.egress import register_web_target

    with pytest.raises(ValueError):
        register_web_target(url)


def test_private_origin_file_and_cli(tmp_path):
    value = "b" * 64
    secret = tmp_path / "origin.secret"
    secret.write_text(value + "\n")
    secret.chmod(0o600)
    assert read_value(secret) == value
    args = build_arg_parser().parse_args([
        "--url", "https://target.example", "--origin-verify-file", str(secret),
    ])
    assert args.origin_verify_file == str(secret)
    secret.chmod(0o644)
    with pytest.raises(ValueError) as error:
        read_value(secret)
    assert value not in str(error.value)
    secret.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(secret)
    with pytest.raises(ValueError):
        read_value(link)


def test_required_hosts_cli_trims_environment_and_keeps_host_only(monkeypatch):
    from packages.web.egress_hosts import required_host

    monkeypatch.setenv("RAPTOR_WEB_REQUIRED_HOSTS", " sso.example.net , assets.example.net ")
    args = build_arg_parser().parse_args(["--url", "https://target.example"])
    assert args.required_host == ["sso.example.net", "assets.example.net"]
    assert required_host("Login.Example.Net") == "login.example.net"
    for value in ("https://login.example.net", "*.example.net", "login.example.net:443"):
        with pytest.raises(ValueError):
            required_host(value)


def test_origin_header_reaches_private_ffuf_config_without_argv(tmp_path):
    from packages.web.discovery import DiscoveryResult
    from packages.web.ffuf import FfufConfig, FfufRunner
    from packages.web.origin_verify import with_origin_header

    value = "a" * 64
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("admin\n")
    scanner = WebScanner(
        "https://target.example", out_dir=tmp_path / "scan",
        ffuf_config=FfufConfig(wordlist=wordlist, filter_size=0),
        origin_verify=value,
    )
    scanner.session = SimpleNamespace(authenticated=True, mode="bearer", token="token")
    config = scanner._enriched_ffuf_config(DiscoveryResult())
    assert config.headers == ("Authorization: Bearer token", f"{HEADER_NAME}: {value}")
    assert with_origin_header((f"x-origin-verify: {'b' * 64}",), value) == (
        f"{HEADER_NAME}: {value}",
    )

    runner = FfufRunner(scanner.base_url, tmp_path)
    private_config = tmp_path / "ffuf.toml"
    assert f"{HEADER_NAME}: {value}" in runner.build_config_file_content(config)
    command = runner.build_command(config, tmp_path / "results.json", config_file=private_config)
    assert value not in " ".join(command)


def test_origin_header_reaches_nuclei_private_config(tmp_path, monkeypatch):
    from packages.web.external_validators import NucleiConfig

    value = "a" * 64
    scanner = WebScanner(
        "https://target.example", out_dir=tmp_path / "scan",
        external_validators=["nuclei"],
        nuclei_config=NucleiConfig(headers=("X-Test: one",)),
        origin_verify=value,
    )
    observed = []

    class CapturingRunner:
        def __init__(self, **kwargs):
            observed.append(kwargs["nuclei_config"])

        def run(self, _findings, _validators):
            return []

    monkeypatch.setattr("packages.web.scanner.ExternalValidatorRunner", CapturingRunner)
    scanner._phase_external_validation([])
    assert observed[0].headers == ("X-Test: one", f"{HEADER_NAME}: {value}")
