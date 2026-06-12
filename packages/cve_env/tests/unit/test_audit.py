"""Audit writer round-trip + filesystem layout."""

from __future__ import annotations

from pathlib import Path

from cve_env.agent.audit import AuditEntry, AuditWriter, _sanitize_cve_id


def test_sanitize_cve_id_strips_separators() -> None:
    assert _sanitize_cve_id("CVE-2018-7600") == "CVE-2018-7600"
    # `.` and `-` are kept (safe in filenames); `/` is replaced.
    assert _sanitize_cve_id("../etc/passwd") == ".._etc_passwd"
    assert _sanitize_cve_id("CVE:../x") == "CVE_.._x"
    assert _sanitize_cve_id("") == "UNKNOWN"
    assert _sanitize_cve_id("$$$") == "___"


def test_writer_appends_and_reads_back(tmp_path: Path) -> None:
    writer = AuditWriter(run_id="run-001", root=tmp_path)
    writer.write(
        cve_id="CVE-2018-7600",
        entry=AuditEntry(
            turn=1,
            status="llm_turn",
            llm_message={"stop_reason": "tool_use"},
            input_tokens=780,
            output_tokens=64,
            cost_usd=0.0164,
        ),
    )
    writer.write(
        cve_id="CVE-2018-7600",
        entry=AuditEntry(
            turn=2,
            status="tool_ok",
            tool_name="vulhub_lookup",
            tool_input={"cve_id": "CVE-2018-7600"},
            tool_result={"path": "vulhub/drupal/CVE-2018-7600"},
        ),
    )
    entries = writer.read(cve_id="CVE-2018-7600")
    assert len(entries) == 2
    assert entries[0]["turn"] == 1
    assert entries[0]["status"] == "llm_turn"
    assert entries[1]["tool_name"] == "vulhub_lookup"


def test_writer_separate_file_per_cve(tmp_path: Path) -> None:
    writer = AuditWriter(run_id="run-002", root=tmp_path)
    writer.write(cve_id="CVE-A", entry=AuditEntry(turn=1, status="tool_ok"))
    writer.write(cve_id="CVE-B", entry=AuditEntry(turn=1, status="tool_ok"))
    assert (tmp_path / "run-002" / "CVE-A.jsonl").exists()
    assert (tmp_path / "run-002" / "CVE-B.jsonl").exists()
    assert writer.read(cve_id="CVE-C") == ()


# -- Phase 67.0 TDD safety net ------------------------------------------------
# Phase 67 audit issue #4 (severity 9): two-write split (json.dumps then "\n")
# with no flush/fsync. A crash between the two writes leaves a partial line.
# The reader uses splitlines + json.loads which crashes on malformed lines
# instead of skipping them. 67.2 ships a single atomic write + a tolerant
# reader that skips malformed lines.


def test_phase67_audit_write_atomic_or_partial_recovery(tmp_path: Path) -> None:
    """Phase 67.2 contract: a partial line left by a crash between
    ``json.dumps`` and ``"\\n"`` writes must NOT crash the reader. The
    reader must skip malformed lines (or the writer must use a single
    atomic write so partial lines never appear).

    Today: ``read()`` calls json.loads on every non-empty line → a partial
    JSON line raises JSONDecodeError. Forensic risk: a crashed bench leaves
    one bad line in some CVE's JSONL; the next ``read()`` of that file
    aborts triage entirely.
    """
    writer = AuditWriter(run_id="run-atomic", root=tmp_path)
    # Write a complete entry first.
    writer.write(
        cve_id="CVE-X",
        entry=AuditEntry(turn=1, status="llm_turn", tool_name="nvd_lookup"),
    )
    # Simulate a crash mid-write: append a partial JSON line that's missing
    # the closing brace + newline. The two-write split makes this state
    # achievable in production.
    path = tmp_path / "run-atomic" / "CVE-X.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"turn": 2, "status": "llm_turn", "tool_name":')
    # Then write a complete entry after recovery.
    writer.write(
        cve_id="CVE-X",
        entry=AuditEntry(turn=3, status="tool_ok", tool_name="github_fetch"),
    )
    # Reader must not crash; it must skip the partial line and surface the
    # clean entries.
    entries = writer.read(cve_id="CVE-X")
    turns = [e["turn"] for e in entries]
    assert 1 in turns, "first complete entry must be returned"
    assert 3 in turns, "recovery entry must be returned"


# -- Phase 53-impl.1 (Cand 3) tool_input_by_id state threading -----------------
# Phase 52 + 53-inv finding: tool_input is captured at llm_turn site (loop.py
# :1193-1201) but NOT at tool_result writer site (:1370-1378), because no
# parallel ``tool_input_by_id`` state dict exists. _StreamState has
# ``tool_name_by_id`` (loop.py:294) — used at :1227 to retrieve tool name for
# the tool_result handler — but no input counterpart. Result: ALL tool_ok /
# tool_error / recovery audit entries have empty ``tool_input: {}`` across ALL
# tool types (Bash, docker_build, image_resolve, verify, etc.). Judge sampled
# CVE-2024-45302 audit JSONL = 10/10 tool_ok entries empty. Fix: parallel
# state dict.


import pytest

from cve_env.agent.loop import _StreamState


def test_phase53_impl1_stream_state_has_tool_input_by_id_field() -> None:
    """Cand 3 state-threading contract: `_StreamState` MUST expose a
    `tool_input_by_id: dict[str, dict]` field parallel to `tool_name_by_id`.

    Today: AttributeError on `state.tool_input_by_id` because field doesn't
    exist. Fix: add field with `default_factory=dict` to `_StreamState`.
    """
    state = _StreamState()
    assert hasattr(state, "tool_input_by_id"), (
        "Phase 53-impl.1 Cand 3 fix missing: _StreamState should expose "
        "tool_input_by_id parallel to tool_name_by_id"
    )
    assert isinstance(state.tool_input_by_id, dict)
    assert state.tool_input_by_id == {}, "field must default to empty dict"


def test_phase53_impl1_tool_input_round_trips_via_state() -> None:
    """Cand 3 round-trip contract: setting `state.tool_input_by_id[id] = {...}`
    at llm_turn write site (mirrors loop.py:1156) and retrieving at tool_result
    site (mirrors :1227 pattern) MUST preserve the input dict verbatim.

    Without the new state field, this raises AttributeError at the SET step.
    """
    state = _StreamState()
    # Mirror loop.py:1156 set site — capture at llm_turn handler
    state.tool_input_by_id["tool_use_id_1"] = {"command": "ls /tmp", "description": "list /tmp"}
    state.tool_input_by_id["tool_use_id_2"] = {"image": "nginx:1.0", "container_port": 8080}
    # Mirror loop.py:1370 area retrieve site — at tool_result writer
    retrieved_1 = state.tool_input_by_id.get("tool_use_id_1", {})
    retrieved_2 = state.tool_input_by_id.get("tool_use_id_2", {})
    retrieved_missing = state.tool_input_by_id.get("nonexistent_id", {})
    assert retrieved_1 == {"command": "ls /tmp", "description": "list /tmp"}
    assert retrieved_2 == {"image": "nginx:1.0", "container_port": 8080}
    assert retrieved_missing == {}, "missing IDs return empty dict (safe default)"


def test_phase53_impl1_tool_input_by_id_parallels_tool_name_by_id() -> None:
    """Cand 3 structural contract: `tool_input_by_id` MUST be a parallel
    mapping to `tool_name_by_id` — same key shape (SDK block.id strings),
    same lifecycle (set at llm_turn handler, read at tool_result handler),
    same default factory.

    This pins the design symmetry so future audits can grep for both fields
    together and know they have the same key universe.
    """
    state = _StreamState()
    # Both must be dicts initialized empty
    assert isinstance(state.tool_name_by_id, dict)
    assert isinstance(state.tool_input_by_id, dict)
    # Parallel set: same key for both maps
    block_id = "msg_abc123"
    state.tool_name_by_id[block_id] = "docker_build"
    state.tool_input_by_id[block_id] = {"context_dir": "/tmp/cve-X", "dockerfile_text": "FROM nginx"}
    # Parallel retrieval works for both
    assert state.tool_name_by_id.get(block_id) == "docker_build"
    assert state.tool_input_by_id.get(block_id) == {
        "context_dir": "/tmp/cve-X",
        "dockerfile_text": "FROM nginx",
    }


def test_phase53_impl1_audit_writer_serializes_tool_input_on_tool_result(tmp_path: Path) -> None:
    """Cand 3 regression-lock: `AuditWriter` already supports `tool_input` on
    tool_result-shape entries (verified at write_appends_and_reads_back line 38).
    This test pins that the writer contract STAYS — Phase 53-impl.1's loop.py
    fix relies on it. If a future refactor drops tool_input field from
    AuditEntry serialization, this test fails immediately.

    End-user contract: post-Phase-53-impl.1, downstream forensic queries like
    `jq '.tool_input.command' bench50-*/CVE-*.jsonl` return real commands on
    tool_ok / tool_error / recovery entries, not all empty dicts.
    """
    writer = AuditWriter(run_id="phase53-impl1", root=tmp_path)
    # Write a tool_result-shape entry with tool_input populated (what the
    # fixed loop.py will produce when threading state.tool_input_by_id):
    writer.write(
        cve_id="CVE-2024-X",
        entry=AuditEntry(
            turn=5,
            status="tool_ok",
            tool_name="docker_build",
            tool_input={"context_dir": "/tmp/cve-X", "image_tag": "test:1.0"},
            tool_result={"ok": True, "image_id": "sha256:abc"},
        ),
    )
    entries = writer.read(cve_id="CVE-2024-X")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["status"] == "tool_ok"
    assert entry["tool_name"] == "docker_build"
    # This is the contract Phase 53-inv Cand 3 fix enables:
    assert entry["tool_input"] == {
        "context_dir": "/tmp/cve-X",
        "image_tag": "test:1.0",
    }, "tool_input must round-trip; cannot be empty {} on tool_ok entries"


# -- Security hardening: secret redaction + owner-only file mode ---------------
# The agent has a built-in host Bash, so a command line could carry a token; the
# audit JSONL is append-only and may be shared for debugging. Redact secrets and
# restrict the files to the owner. Redaction must be a no-op for benign build
# text (image tags, paths, reasons).


def test_audit_redacts_github_token_in_tool_io(tmp_path: Path) -> None:
    writer = AuditWriter(run_id="sec-redact", root=tmp_path)
    token = "ghp_" + "A" * 36
    writer.write(
        cve_id="CVE-SEC-1",
        entry=AuditEntry(
            turn=1,
            status="tool_ok",
            tool_name="Bash",
            tool_input={"command": f'curl -H "Authorization: Bearer {token}" https://x'},
            tool_result={"stdout": f"cloned https://x-access-token:{token}@github.com/o/r"},
        ),
    )
    raw = (tmp_path / "sec-redact" / "CVE-SEC-1.jsonl").read_text()
    assert token not in raw, "raw GitHub token must not be persisted to the audit log"
    assert "[REDACTED]" in raw
    # Structure + non-secret context survive (host kept, key kept).
    entry = writer.read(cve_id="CVE-SEC-1")[0]
    assert "command" in entry["tool_input"]
    assert "github.com/o/r" in entry["tool_result"]["stdout"]


def test_audit_does_not_redact_benign_build_text(tmp_path: Path) -> None:
    writer = AuditWriter(run_id="sec-benign", root=tmp_path)
    writer.write(
        cve_id="CVE-SEC-2",
        entry=AuditEntry(
            turn=1,
            status="tool_ok",
            tool_name="docker_build",
            tool_input={"image_tag": "nginx:1.21.0", "context_dir": "/tmp/cve-x"},
            tool_result={"reason": "built ok", "image_id": "sha256:abc"},
        ),
    )
    entry = writer.read(cve_id="CVE-SEC-2")[0]
    assert entry["tool_input"] == {"image_tag": "nginx:1.21.0", "context_dir": "/tmp/cve-x"}
    raw = (tmp_path / "sec-benign" / "CVE-SEC-2.jsonl").read_text()
    assert "[REDACTED]" not in raw, "benign build text must not trip redaction"


def test_audit_files_are_owner_only(tmp_path: Path) -> None:
    import stat

    writer = AuditWriter(run_id="sec-perms", root=tmp_path)
    writer.write(cve_id="CVE-SEC-3", entry=AuditEntry(turn=1, status="tool_ok"))
    run_dir = tmp_path / "sec-perms"
    jsonl = run_dir / "CVE-SEC-3.jsonl"
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700, "run dir must be 0700"
    assert stat.S_IMODE(jsonl.stat().st_mode) == 0o600, "audit file must be 0600"
