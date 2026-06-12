"""S29 Phase D — bench-replay verify-dispatch test.

Discovers every ``verify`` tool call recorded in
``output/agentic/manual-*/CVE-*.jsonl`` audit files, replays each
through :func:`~cve_env.tools.verify.verify` with all I/O surfaces
mocked to succeed, and asserts that no step is schema-rejected
(i.e. no step returns ``"unknown check type"``).

Skipped on a fresh clone where no audit files are present so CI stays
green without needing a pre-seeded corpus.
"""

from __future__ import annotations

import json
import pathlib
from contextlib import ExitStack
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cve_env.tools.run_in_container import ExecResult
from cve_env.tools.verify import verify

# ---------------------------------------------------------------------------
# Corpus discovery
# ---------------------------------------------------------------------------

_AUDIT_ROOT = (
    pathlib.Path(__file__).parent.parent.parent.parent / "output" / "agentic"
)

# 2026-05-26 build-only purification: the active-probe check types
# ``http_payload_check`` / ``tcp_payload_check`` were renamed to
# ``http_request_check`` / ``tcp_probe_check``. Audit recordings made before the
# rename legitimately use the old names, which the current ``verify()`` now
# reports as "unknown check type" — by design (no back-compat aliases; the old
# names are retired). The assertion below TOLERATES these specific retired types
# so pre-rename recordings still replay (exercising their other, still-valid
# steps) while a genuinely-unknown type (a real schema regression) still fails.
_RETIRED_CHECK_TYPES = frozenset({"http_payload_check", "tcp_payload_check"})


def _collect_verify_cases() -> list[tuple[str, dict[str, Any]]]:
    """Return (case_id, verify_kwargs) for every verify call in the corpus."""
    cases: list[tuple[str, dict[str, Any]]] = []
    for jsonl in sorted(_AUDIT_ROOT.glob("manual-*/CVE-*.jsonl")):
        run_id = jsonl.parent.name
        with jsonl.open() as fh:
            for line in fh:
                if '"verify"' not in line:
                    continue
                obj = json.loads(line)
                if obj.get("tool_name") != "verify":
                    continue
                tool_input = obj.get("tool_input") or {}
                if not isinstance(tool_input.get("plan"), list):
                    continue  # result line (empty ti) or double-encoded plan string; skip
                raw_cve = obj.get("cve_id", "UNKNOWN")
                cve_id = raw_cve.split()[0]
                turn = obj.get("turn", 0)
                cases.append((f"{cve_id}@{run_id}:t{turn}", tool_input))
    return cases


_VERIFY_CASES = _collect_verify_cases()


# ---------------------------------------------------------------------------
# Socket partial-mock (mirrors test_e2e_pipeline._FakeTCPSocket / test_verify)
# ---------------------------------------------------------------------------


class _FakeTCPSocket:
    def __init__(self) -> None:
        self.closed = False

    def settimeout(self, _t: float) -> None:
        pass

    def sendall(self, _data: bytes) -> None:
        pass

    def recv(self, n: int) -> bytes:
        return b"+PONG\r\n"[:n]

    def close(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# I/O mock fixture (mirrors _e2e_io_mocked pattern from test_e2e_pipeline.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def _verify_io_mocked() -> Any:
    """Mock all I/O surfaces so verify() dispatches without real containers."""
    with ExitStack() as stack:
        subproc = MagicMock()
        subproc.return_value.returncode = 0
        subproc.return_value.stdout = (
            '{"Status": "running", "Running": true, "ExitCode": 0}'
        )
        subproc.return_value.stderr = ""
        stack.enter_context(patch("cve_env.utils.run.subprocess.run", subproc))

        # stability_wait calls time.sleep — mock it so plans with 90-120s
        # waits don't hit the pytest 60s timeout.
        stack.enter_context(patch("cve_env.tools.verify.time.sleep", MagicMock()))

        req_mock = MagicMock()
        req_mock.return_value.status_code = 200
        req_mock.return_value.content = b"ok"
        req_mock.return_value.text = "ok"
        stack.enter_context(patch("cve_env.tools.verify.requests.request", req_mock))

        stack.enter_context(
            patch(
                "cve_env.tools.verify.socket.create_connection",
                MagicMock(return_value=_FakeTCPSocket()),
            )
        )

        exec_mock = MagicMock(
            return_value=ExecResult(
                ok=True,
                container_id="replay_cid",
                command="id",
                exit_code=0,
                stdout="ok",
                stderr="",
                duration_s=0.001,
            )
        )
        stack.enter_context(
            patch(
                "cve_env.tools.verify._run_in_container.run_in_container",
                exec_mock,
            )
        )
        yield


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _VERIFY_CASES,
    reason="no audit JSONLs present — skip on fresh clone / CI without corpus",
)
@pytest.mark.parametrize(("case_id", "verify_input"), _VERIFY_CASES)
def test_bench_replay_verify_no_schema_rejection(
    case_id: str,
    verify_input: dict[str, Any],
    _verify_io_mocked: None,  # noqa: PT019
) -> None:
    """Replay a recorded verify call; assert no step is schema-rejected."""
    result = verify(**verify_input)
    bad = [
        r
        for r in result["results"]
        if "unknown check type" in (r.get("reason") or "")
        and r.get("type") not in _RETIRED_CHECK_TYPES  # tolerate intentionally-retired types
    ]
    assert not bad, (
        f"{case_id}: verify() schema-rejected {len(bad)} step(s): "
        + ", ".join(r.get("reason", "") for r in bad)
    )
