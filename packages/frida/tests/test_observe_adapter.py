"""Tests for frida observe_adapter — events.jsonl to ObserveProfile."""

from __future__ import annotations

import json
from pathlib import Path

from packages.frida.observe_adapter import events_to_observe_profile


def _write_events(path: Path, events: list[dict]) -> Path:
    path.write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )
    return path


def _send_event(category: str, fn: str, args: list) -> dict:
    return {
        "ts": 1.0,
        "type": "send",
        "payload": {"category": category, "fn": fn, "args": args, "tid": 1},
    }


class TestEventsToObserveProfile:
    def test_file_read(self, tmp_path):
        events = [_send_event("file", "open", ["/etc/passwd", 0])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/etc/passwd" in profile.paths_read
        assert not profile.paths_written

    def test_file_write(self, tmp_path):
        events = [_send_event("file", "write", ["/tmp/out.txt", 512])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/out.txt" in profile.paths_written
        assert not profile.paths_read

    def test_file_stat(self, tmp_path):
        events = [_send_event("file", "stat", ["/usr/lib/libc.so.6"])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/usr/lib/libc.so.6" in profile.paths_stat

    def test_network_connect(self, tmp_path):
        events = [_send_event("network", "connect", ["10.0.0.1", 8080, "AF_INET"])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert len(profile.connect_targets) == 1
        ct = profile.connect_targets[0]
        assert ct.ip == "10.0.0.1"
        assert ct.port == 8080
        assert ct.family == "AF_INET"

    def test_open_with_write_flags(self, tmp_path):
        events = [_send_event("file", "open", ["/tmp/out.log", 0o102])]  # O_CREAT|O_WRONLY
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/out.log" in profile.paths_written
        assert "/tmp/out.log" not in profile.paths_read

    def test_deduplicates(self, tmp_path):
        events = [
            _send_event("file", "open", ["/etc/passwd", 0]),
            _send_event("file", "open", ["/etc/passwd", 0]),
            _send_event("file", "open", ["/etc/passwd", 0]),
        ]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert profile.paths_read.count("/etc/passwd") == 1

    def test_non_send_events_ignored(self, tmp_path):
        events = [
            {"ts": 1.0, "type": "error", "error": {"description": "boom"}},
            _send_event("file", "open", ["/etc/hosts", 0]),
        ]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert profile.paths_read == ["/etc/hosts"]

    def test_missing_file_returns_empty(self, tmp_path):
        profile = events_to_observe_profile(tmp_path / "nope.jsonl")
        assert not profile.paths_read
        assert not profile.paths_written
        assert not profile.connect_targets

    def test_malformed_lines_tolerated(self, tmp_path):
        content = "NOT JSON\n" + json.dumps(_send_event("file", "read", ["/data"])) + "\n{truncated\n"
        path = tmp_path / "events.jsonl"
        path.write_text(content, encoding="utf-8")
        profile = events_to_observe_profile(path)
        assert "/data" in profile.paths_read

    def test_connect_string_port_coerced(self, tmp_path):
        events = [{"ts": 1.0, "type": "send", "payload": {
            "category": "network", "fn": "connect",
            "args": ["192.168.1.1", "443", "AF_INET6"], "tid": 1,
        }}]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert len(profile.connect_targets) == 1
        assert profile.connect_targets[0].port == 443

    def test_connect_missing_args_skipped(self, tmp_path):
        events = [_send_event("network", "connect", ["10.0.0.1"])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert not profile.connect_targets

    def test_empty_path_skipped(self, tmp_path):
        events = [_send_event("file", "open", ["", 0])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert not profile.paths_read

    def test_write_supersedes_earlier_read(self, tmp_path):
        """A path read then written should appear in paths_written only."""
        events = [
            _send_event("file", "open", ["/tmp/data.bin", 0]),
            _send_event("file", "write", ["/tmp/data.bin"]),
        ]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/data.bin" in profile.paths_written
        assert "/tmp/data.bin" not in profile.paths_read


    def test_openat_list_format(self, tmp_path):
        """openat args are [dirfd, path, flags] — path at index 1, flags at 2."""
        events = [_send_event("file", "openat", [-100, "/proc/self/maps", 0])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/proc/self/maps" in profile.paths_read

    def test_openat_list_write_flags(self, tmp_path):
        """openat with O_WRONLY|O_CREAT → written."""
        events = [_send_event("file", "openat", [-100, "/tmp/out.log", 0o101])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/out.log" in profile.paths_written
        assert "/tmp/out.log" not in profile.paths_read

    def test_o_creat_alone_is_not_write(self, tmp_path):
        """O_CREAT alone (no O_WRONLY/O_RDWR) = O_RDONLY|O_CREAT → still a read."""
        events = [_send_event("file", "open", ["/tmp/maybe.db", 0o100])]  # O_CREAT only
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/maybe.db" in profile.paths_read
        assert "/tmp/maybe.db" not in profile.paths_written

    def test_null_byte_in_path_skipped(self, tmp_path):
        """Paths with embedded null bytes are rejected."""
        events = [_send_event("file", "open", ["/etc/shadow\x00.log", 0])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert not profile.paths_read

    def test_max_events_cap(self, tmp_path):
        """Event processing stops at max_events."""
        events = [_send_event("file", "open", [f"/file_{i}", 0]) for i in range(200)]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path, max_events=50)
        assert len(profile.paths_read) == 50

    def test_statx_classified_as_stat(self, tmp_path):
        """statx and fstatat are stat operations (both take dirfd, path)."""
        events = [
            _send_event("file", "statx", [-100, "/usr/lib/libz.so", 0]),
            _send_event("file", "fstatat", [-100, "/proc/version", 0]),
        ]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/usr/lib/libz.so" in profile.paths_stat
        assert "/proc/version" in profile.paths_stat

    def test_unlink_classified_as_write(self, tmp_path):
        """unlink and unlinkat are write operations."""
        events = [
            _send_event("file", "unlink", ["/tmp/target.tmp"]),
            _send_event("file", "unlinkat", [-100, "/tmp/other.tmp", 0]),
        ]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/target.tmp" in profile.paths_written
        assert "/tmp/other.tmp" in profile.paths_written

    def test_mkdir_classified_as_write(self, tmp_path):
        """mkdir is a write operation."""
        events = [_send_event("file", "mkdir", ["/tmp/newdir"])]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/newdir" in profile.paths_written

    def test_readlink_classified_as_stat(self, tmp_path):
        """readlink/readlinkat are stat operations."""
        events = [
            _send_event("file", "readlink", ["/proc/self/exe"]),
            _send_event("file", "readlinkat", [-100, "/usr/bin/python3", 0]),
        ]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/proc/self/exe" in profile.paths_stat
        assert "/usr/bin/python3" in profile.paths_stat


class TestDictArgsFormat:
    """Tests for the real api-trace.js dict format (args as JS object)."""

    def _dict_event(self, category, fn, args_dict):
        return {"ts": 1.0, "type": "send",
                "payload": {"category": category, "fn": fn, "args": args_dict, "tid": 1}}

    def test_open_read(self, tmp_path):
        events = [self._dict_event("file", "open",
                                   {"path": "/etc/passwd", "flags": 0, "ret": 3})]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/etc/passwd" in profile.paths_read

    def test_open_write_flags(self, tmp_path):
        events = [self._dict_event("file", "open",
                                   {"path": "/tmp/out", "flags": 0o101, "ret": 4})]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert "/tmp/out" in profile.paths_written
        assert "/tmp/out" not in profile.paths_read

    def test_write_no_path(self, tmp_path):
        """write() with fd-only dict has no extractable path."""
        events = [self._dict_event("file", "write",
                                   {"fd": 4, "count": 100, "ret": 100})]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert not profile.paths_written

    def test_connect_no_ip(self, tmp_path):
        """connect() with fd-only (real template) produces no ConnectTarget."""
        events = [self._dict_event("network", "connect", {"fd": 5, "ret": 0})]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert not profile.connect_targets

    def test_connect_with_ip(self, tmp_path):
        """Custom template that emits IP/port/family in dict format."""
        events = [self._dict_event("network", "connect",
                                   {"ip": "10.0.0.1", "port": 443, "family": "AF_INET"})]
        path = _write_events(tmp_path / "events.jsonl", events)
        profile = events_to_observe_profile(path)
        assert len(profile.connect_targets) == 1
        assert profile.connect_targets[0].ip == "10.0.0.1"
