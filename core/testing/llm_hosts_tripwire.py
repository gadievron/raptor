"""Linux CI hostname/TLS tripwire. Only ``serve --hosts-file`` needs root.

Run this file directly: the privileged listener imports only stdlib and the
adjacent socket-attribution helper. It never constructs an LLM client.
"""

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import os
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from typing import TYPE_CHECKING

# Direct execution deliberately avoids core.testing's SDK-heavy __init__.
if TYPE_CHECKING or __package__:
    from .llm_connections import active_tests, attribute_connection
else:
    from llm_connections import active_tests, attribute_connection


def endpoint_hosts(repo, model_files=()):
    """Published native/broker endpoints plus explicitly supplied configs.

    SDK metadata supplies Bedrock regions without credential discovery or
    network calls. Arbitrary future api_base hosts cannot be guessed.
    """
    urls = ["https://api.anthropic.com", "https://aiplatform.googleapis.com"]
    regions = {os.environ.get("AWS_REGION", "us-east-1"),
               os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
               os.environ.get("RAPTOR_BEDROCK_REGION", "us-east-1")}
    source = ast.parse((repo / "core/llm/model_data.py").read_text())
    for node in source.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "PROVIDER_ENDPOINTS" for t in node.targets
        ):
            urls.extend(ast.literal_eval(node.value).values())
    # Shared comment-aware parser, only in the unprivileged prepare command.
    from core.json import load_json_with_comments
    registry = repo / "core/llm/model_brokers/registry.json"
    if registry.exists():
        urls.extend(row["upstream_base_url"]
                    for row in load_json_with_comments(registry)["brokers"])
    for path in model_files:
        data = load_json_with_comments(path)
        rows = data.get("models", []) if isinstance(data, dict) else data
        urls.extend(row["api_base"] for row in rows if row.get("api_base"))
        regions.update(row["region"] for row in rows if row.get("region"))
    for key in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "AZURE_OPENAI_ENDPOINT"):
        if os.environ.get(key):
            urls.append(os.environ[key])
    try:
        import botocore.session
        session = botocore.session.get_session()
        for partition in session.get_available_partitions():
            regions.update(session.get_available_regions("bedrock-runtime", partition))
    except ImportError:
        pass
    for region in regions:
        suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
        urls.extend((f"https://bedrock-runtime.{region}.{suffix}",
                     f"https://bedrock-runtime-fips.{region}.{suffix}",
                     f"https://bedrock-mantle.{region}.api.aws",
                     f"https://bedrock-runtime.{region}.api.aws"))
    location = os.environ.get("VERTEX_LOCATION") or os.environ.get("CLOUD_ML_REGION") or "us-central1"
    urls.extend((f"https://{location}-aiplatform.googleapis.com",
                 f"https://aiplatform.{location}.rep.googleapis.com"))
    hosts, ports = set(), set()
    for url in urls:
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host or host == "localhost":
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            # Hostnames go into /etc/hosts; reject whitespace/control injection.
            host = host.encode("idna").decode("ascii").lower()
            if not all(c.isalnum() or c in ".-" for c in host):
                raise ValueError(f"invalid endpoint hostname: {host!r}")
            hosts.add(host)
            ports.add(parsed.port or (443 if parsed.scheme == "https" else 80))
    return {"hosts": sorted(hosts), "ports": sorted(ports)}


def serve(directory, hosts_file, stop, ports=None):
    """Accept first, attribute, then offer an untrusted TLS certificate.

    Both IPv4 and IPv6 loopback are bound. Connections count even if TLS
    fails, certificate verification is disabled, or attribution is unknown.
    """
    manifest = json.loads((directory / "endpoints.json").read_text())
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=raptor-ci-tripwire.invalid"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=15)
    key.chmod(0o600)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(cert, key)
    original = None
    selector = selectors.DefaultSelector()
    sockets = []
    try:
        for port in ports if ports is not None else manifest["ports"]:
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                sock = socket.socket(family)
                sockets.append(sock)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, port))
                sock.listen(64)
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ)
        if hosts_file is not None:
            original = hosts_file.read_text()
            (directory / "hosts-before.txt").write_text(original)
            entries = "".join(f"{ip} {host}\n" for host in manifest["hosts"]
                              for ip in ("127.0.0.1", "::1"))
            # Prepend so an existing entry cannot precede the tripwire.
            retained = []
            for line in original.splitlines(keepends=True):
                content, marker, comment = line.partition("#")
                words = content.split()
                if len(words) > 1 and any(h.lower() in manifest["hosts"] for h in words[1:]):
                    aliases = [h for h in words[1:] if h.lower() not in manifest["hosts"]]
                    if aliases:
                        retained.append(" ".join([words[0], *aliases]) +
                                        (" #" + comment.rstrip("\n") if marker else "") + "\n")
                else:
                    retained.append(line)
            hosts_file.write_text(entries + "".join(retained))
        (directory / "ready.json").write_text(json.dumps({
            "pid": os.getpid(), "addresses": [s.getsockname() for s in sockets],
        }))
        while not stop():
            for ready, _ in selector.select(timeout=0.1):
                conn, _ = ready.fileobj.accept()
                contexts = active_tests(directory)
                row = {"time_ns": time.time_ns(), **attribute_connection(conn, contexts)}
                recorded = False

                def record(name=None):
                    nonlocal recorded
                    if not recorded:
                        row["hostname"] = name
                        with (directory / "connections.jsonl").open("a") as out:
                            out.write(json.dumps(row) + "\n")
                        recorded = True

                try:
                    conn.settimeout(0.5)
                    # The callback observes SNI before certificate verification.
                    tls.set_servername_callback(lambda sock, name, ctx: record(name))
                    with tls.wrap_socket(conn, server_side=True) as secured:
                        secured.close()  # Never proxy or perform inference.
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    conn.close()
                    record()  # Includes non-TLS and incomplete-handshake attempts.
    finally:
        if original is not None:
            hosts_file.write_text(original)
        for sock in sockets:
            sock.close()
        selector.close()
        (directory / "ready.json").unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "serve", "wait", "stop"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--models", type=Path, action="append", default=[])
    parser.add_argument("--hosts-file", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        sys.path.insert(0, str(args.repo.resolve()))
        args.directory.mkdir(parents=True, exist_ok=True)
        (args.directory / "endpoints.json").write_text(json.dumps(
            endpoint_hosts(args.repo.resolve(), args.models), indent=2,
        ) + "\n")
    elif args.command == "stop":
        ready = args.directory / "ready.json"
        if ready.exists():
            pid = int(json.loads(ready.read_text())["pid"])
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if (pid <= 1 or str(Path(__file__).resolve()).encode() not in command
                    or str(args.directory.resolve()).encode() not in command):
                raise SystemExit("Refusing to stop an unrelated process")
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while ready.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            if ready.exists():
                raise SystemExit("LLM hostname tripwire did not stop")
        journal = args.directory / "connections.jsonl"
        if journal.exists() and journal.stat().st_size:
            raise SystemExit(f"Unexpected LLM connection attempts: {journal}")
    elif args.command == "wait":
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if (args.directory / "ready.json").exists():
                return
            time.sleep(0.1)
        raise SystemExit("LLM hostname tripwire failed to start")
    else:
        if sys.platform != "linux":
            raise SystemExit("Hostname/socket attribution tripwire requires Linux")
        stopped = False

        def shutdown(signum, frame):
            nonlocal stopped
            stopped = True

        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        serve(args.directory, args.hosts_file, lambda: stopped)


if __name__ == "__main__":
    main()
