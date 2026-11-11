"""Controls for the credential watcher's namespace attribution."""

import io
import os
import threading
import time
from types import SimpleNamespace

import pytest

from core.testing.module_views import module_function_view

from . import test_fresh_procfs_contract as contract


def _observe(tmp_path, scenario):
    stop = threading.Event()
    targets = []
    images = {}
    namespaces = {}
    reads = {}

    class Thread:
        def __init__(self, *, target):
            targets.append(target)

        def start(self):
            pass

        def join(self):
            assert stop.is_set()

    def readlink(path):
        if path == "/proc/self/ns/user":
            return "user:[host]"
        pid = path.split("/")[2]
        index = reads.get(pid, 0)
        reads[pid] = index + 1
        pair = namespaces[pid]
        return pair[min(index, len(pair) - 1)]

    def open_image(path, mode):
        assert mode == "rb"
        assert path.endswith("/environ")
        return io.BytesIO(images[path.split("/")[2]])

    def driver(path, beacon, payload, *, timeout, extra_env):
        assert path == tmp_path and timeout == 150
        names = tuple(extra_env)

        def image(live):
            entries = [beacon.encode() + b"=1"]
            entries.extend(
                name.encode() + b"="
                + (extra_env[name].encode() if live else b"")
                for name in names
                if scenario != "missing-name" or name != "GITHUB_TOKEN"
            )
            return b"\0".join(entries) + b"\0"

        images["101"] = image(scenario == "payload-leak")
        namespaces["101"] = ("user:[payload]", "user:[payload]")
        if scenario == "sibling":
            images["102"] = image(True)
            namespaces["102"] = ("user:[sibling]", "user:[sibling]")
        elif scenario in {"transition", "payload-transition"}:
            images["102"] = image(True)
            namespaces["102"] = (
                ("user:[payload]", "user:[sibling]")
                if scenario == "payload-transition"
                else ("user:[host]", "user:[payload]")
            )
        (tmp_path / "credential-payload-userns").write_text(
            "user:[payload]\n", encoding="utf-8",
        )
        assert len(targets) == 1
        targets[0]()
        return SimpleNamespace(stdout="RC=0", stderr="")

    private = module_function_view(contract, bindings={
        "os": module_function_view(os, bindings={
            "getpid": lambda: 999,
            "listdir": lambda path: list(images),
            "readlink": readlink,
        }),
        "threading": module_function_view(threading, bindings={
            "Thread": Thread,
            "Event": lambda: stop,
        }),
        "time": module_function_view(time, bindings={
            "sleep": lambda seconds: stop.set(),
        }),
        "open": open_image,
        "_drive_run_in_subprocess": driver,
    })
    private.test_agent_credentials_scrubbed_from_chain_environ(tmp_path)


@pytest.mark.parametrize(
    "scenario", ["clean", "sibling", "transition", "payload-transition"],
)
def test_observer_accepts_only_stable_payload_namespace(tmp_path, scenario):
    _observe(tmp_path, scenario)


def test_observer_still_rejects_payload_credentials(tmp_path):
    with pytest.raises(AssertionError) as caught:
        _observe(tmp_path, "payload-leak")
    message = str(caught.value)
    for name in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN",
                 "ANTHROPIC_CUSTOM_HEADERS", "GITHUB_TOKEN"):
        assert "101:" + name in message


def test_observer_still_requires_credential_names(tmp_path):
    with pytest.raises(AssertionError, match="empty the value, not remove the name"):
        _observe(tmp_path, "missing-name")
