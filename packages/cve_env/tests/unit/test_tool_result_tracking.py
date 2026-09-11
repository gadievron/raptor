"""State-tracker behaviors in :func:`cve_env.agent.loop._track_tool_result`:

* the specific-version-marker credit must pin the CVE's own version when
  it is known (any incidental ``\\d+.\\d+`` — e.g. an ``HTTP/1.1 200``
  liveness marker — must not satisfy the build-path gate);
* fused auto-builds (dockerfile_gen/source_build with a nested
  ``build.ok``) count as a docker build for every docker_built_ok
  consumer;
* has_built latches only on SUCCESSFUL build-tool results, so a failed
  docker_build followed by an image-pull pivot is graded as an
  image-pulled run.
"""

from __future__ import annotations

from cve_env.agent.loop import _StreamState, _track_tool_result


def _passing_verify_payload(expected_stdout: str, command: str) -> dict:
    return {
        "passed": True,
        "results": [
            {
                "type": "exec_check",
                "passed": True,
                "details": {
                    "command": command,
                    "expected_stdout_contains": expected_stdout,
                },
            },
        ],
    }


def _track(state: _StreamState, tool: str, payload: dict, **kw) -> None:
    _track_tool_result(state, tool, payload, refusal_event_count=0, **kw)


# ── specific version marker vs. the CVE's own version ─────────────────────


def test_incidental_protocol_digits_do_not_credit_version_marker() -> None:
    """`expected_stdout_contains="HTTP/1.1 200"` matches \\d+.\\d+ but pins
    nothing; with the CVE version known it must not satisfy the gate."""
    state = _StreamState()
    _track(
        state,
        "verify",
        _passing_verify_payload("HTTP/1.1 200", "curl -sI localhost"),
        cve_version="2.4.49",
    )
    assert state.passing_verify_has_specific_version_marker is False


def test_cve_version_literal_in_marker_credits_gate() -> None:
    state = _StreamState()
    _track(
        state,
        "verify",
        _passing_verify_payload("Apache/2.4.49", "apache2 -v"),
        cve_version="2.4.49",
    )
    assert state.passing_verify_has_specific_version_marker is True


def test_unknown_cve_version_falls_back_to_digit_shape() -> None:
    """With no usable version literal, the digits-shape heuristic is the
    best available signal and keeps crediting."""
    state = _StreamState()
    _track(
        state,
        "verify",
        _passing_verify_payload("Foo/3.1", "foo --version"),
        cve_version="",
    )
    assert state.passing_verify_has_specific_version_marker is True


# ── fused auto-build visibility ────────────────────────────────────────────


def test_fused_build_sets_docker_built_ok() -> None:
    state = _StreamState()
    _track(
        state,
        "dockerfile_gen",
        {"ok": True, "build": {"ok": True, "image_tag": "cve-env-local:x"}},
    )
    assert state.docker_built_ok is True


def test_fused_build_failure_does_not_set_docker_built_ok() -> None:
    state = _StreamState()
    _track(state, "dockerfile_gen", {"ok": True, "build": {"ok": False}})
    assert state.docker_built_ok is False


# ── has_built latches on success only ──────────────────────────────────────


def test_failed_docker_build_does_not_latch_has_built() -> None:
    state = _StreamState()
    _track(state, "docker_build", {"ok": False, "reason": "build_failed"})
    assert state.has_built is False


def test_successful_docker_build_latches_has_built() -> None:
    state = _StreamState()
    _track(state, "docker_build", {"ok": True, "image_tag": "t"})
    assert state.has_built is True
