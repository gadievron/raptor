"""S28 (2026-05-04): lock tests for prompt EXACT-SCHEMAS section.

bench50-20260504-010418 surfaced two prompt-side gaps:

(E1.2 — CVE-2018-16509 turn 71): agent passed `plan` as a JSON-stringified
list. SDK rejected: `'[...]' is not of type 'array'`. SYSTEM_PROMPT must
warn explicitly that plan is a list, not a stringified JSON.

(E1.2 — same bench): tcp_probe_check has no explicit `{"type": ...}`
JSON template in EXACT-SCHEMAS section, so the agent infers from the
cross-protocol table at prompts.py:682-720, sometimes incorrectly.

S28 follow-up tests (test-quality audit):
- JSON template syntactic validity (catch typos that break agent parsing)
- B8-class signature parity: every kwarg the prompt advertises for each
  check function must be accepted by that function (catches future
  prompt↔runtime drift across all 7 check types).
"""

from __future__ import annotations

import inspect
import json
import re
from typing import Any

import pytest

from cve_env.agent.prompts import SYSTEM_PROMPT
from cve_env.tools import verify as _verify_mod


def test_prompt_warns_plan_must_be_list_not_string() -> None:
    """plan must be a LIST not a stringified JSON. Catch the
    CVE-2018-16509-class mistake at prompt-time."""
    # Wording-flexible: must mention plan + list + warning against
    # stringification (one of: "string", "stringified", "JSON-stringif").
    text = SYSTEM_PROMPT.lower()
    # Must mention plan-as-list explicitly
    assert "plan" in text
    assert "list" in text
    # Must include explicit anti-stringify warning
    has_warning = any(
        s in text
        for s in (
            "not a string",
            "not a stringified",
            "do not pass plan as a string",
            "plan must be a list",
        )
    )
    assert has_warning, (
        "SYSTEM_PROMPT must warn agent against passing plan as a "
        "JSON-stringified list (CVE-2018-16509 bench failure)."
    )


def test_tcp_probe_check_has_exact_schema_in_prompt() -> None:
    """tcp_probe_check needs an explicit {"type": "tcp_probe_check", ...}
    JSON example with named kwargs, alongside the other check schemas
    (container_status, http_check, log_check, stability_wait, exec_check,
    http_request_check). Without it, the agent has to infer from the
    cross-protocol table and uses synonyms like `host` instead of host_ip
    (CVE-2018-2628 turn 19 — fixed by E1.1 alias but the prompt-side
    schema gap is the upstream cause)."""
    # Locate the EXACT-SCHEMAS section (anchored on container_status)
    # and assert tcp_probe_check has its own JSON template within it.
    text = SYSTEM_PROMPT
    # Must contain a {"type": "tcp_probe_check", ...} example with
    # at least one canonical kwarg (send_text, host_ip, or host_port).
    assert '"type": "tcp_probe_check"' in text, (
        "SYSTEM_PROMPT EXACT-SCHEMAS section must contain a literal "
        '`{"type": "tcp_probe_check", ...}` JSON template.'
    )
    # Must advertise at least one of the canonical kwargs (not synonym)
    has_canonical_kwarg = any(
        k in text
        for k in ('"send_text"', '"host_port"', '"expected_response_contains"')
    )
    assert has_canonical_kwarg, (
        "tcp_probe_check JSON template must reference canonical "
        "kwargs (send_text / host_port / expected_response_contains), "
        "not just LLM-synonyms."
    )


# --- S28 follow-up: JSON template syntactic validity --------------------


def test_tcp_probe_check_template_in_prompt_is_valid_json() -> None:
    """The tcp_probe_check JSON template must parse as valid JSON.
    Catches typos (trailing commas, unescaped quotes, unbalanced braces)
    that would let the agent copy-paste a syntactically broken example."""
    # Match a single-line JSON object starting with `{"type": "tcp_probe_check"`.
    # Allow embedded escaped quotes / backslashes in the value.
    pattern = re.compile(
        r'(\{"type":\s*"tcp_probe_check"[^{}]*\})',
        re.DOTALL,
    )
    matches = pattern.findall(SYSTEM_PROMPT)
    assert matches, (
        'could not locate `{"type": "tcp_probe_check", ...}` '
        "JSON block in SYSTEM_PROMPT"
    )
    # Try to parse each candidate; at least one must parse cleanly.
    parsed_ok: list[dict[str, object]] = []
    errors: list[str] = []
    for raw in matches:
        try:
            obj = json.loads(raw)
            parsed_ok.append(obj)
        except json.JSONDecodeError as exc:
            errors.append(f"{exc}: {raw[:120]}")
    assert parsed_ok, (
        f"no tcp_probe_check JSON template parsed cleanly. errors: {errors}"
    )
    # And the parsed example must use canonical kwargs (not synonyms),
    # so the agent learns the right names.
    obj = parsed_ok[0]
    assert obj["type"] == "tcp_probe_check"
    has_canonical_kwarg = any(
        k in obj for k in ("host_port", "send_text", "expected_response_contains")
    )
    assert has_canonical_kwarg, (
        f"tcp_probe_check template must use canonical kwargs; got keys={list(obj)}"
    )


# --- S28 follow-up: B8-class signature parity (parameterized) -----------


# (function_name, kwargs_the_prompt_advertises). The advertised kwargs are
# the canonical names the prompt's EXACT-SCHEMAS section shows. If the
# function signature drifts apart from this set, the agent will hit
# `unexpected keyword argument` (B8-class). This test catches that drift
# at unit-test time rather than mid-bench.
_ADVERTISED_KWARGS: dict[str, dict[str, object]] = {
    # container_status: prompt shows `{"type": "container_status"}` (no kwargs).
    "check_container_status": {"container_id": "cid"},
    # http_check: prompt shows path, expected_status, require_nonempty_body.
    "check_http": {
        "host_ip": "127.0.0.1",
        "host_port": 8080,
        "path": "/",
        "expected_status": [200, 403],
        "require_nonempty_body": True,
    },
    # log_check: prompt shows expected_patterns.
    "check_logs": {
        "container_id": "cid",
        "expected_patterns": ["Started"],
    },
    # stability_wait: prompt shows wait_seconds.
    "stability_wait": {"container_id": "cid", "wait_seconds": 10},
    # exec_check: prompt shows command, expected_exit, expected_stdout_contains, workdir (B8 fix).
    "check_exec": {
        "container_id": "cid",
        "command": "redis-cli ping",
        "expected_exit": 0,
        "expected_stdout_contains": "PONG",
        "workdir": "/srv/app",
    },
    # http_request_check: prompt shows method/path/payload/field_name
    # /expected_status/expected_response_contains.
    "check_http_request": {
        "host_ip": "127.0.0.1",
        "host_port": 8080,
        "method": "POST",
        "path": "/",
        "request_body": "x",
        "field_name": "search",
        "expected_status": [200],
        "expected_response_contains": "uid=",
    },
    # tcp_probe_check (E1.2 added template): host_port, send_text, expected_response_contains.
    "check_tcp_probe": {
        "host_ip": "127.0.0.1",
        "host_port": 6379,
        "send_text": "PING",
        "expected_response_contains": "+PONG",
    },
}


# --- S28.1.c T6: alias-dict completeness vs prompt narrative -----------


def test_prompt_warns_lifecycle_only_smoke_is_insufficient() -> None:
    """S28.1.g A (2026-05-04): Phase 49.1 functional-smoke metric counts
    only exec_check + http_request_check + tcp_probe_check (active
    behavior); http_check (lifecycle GET) does NOT count. bench50-
    20260504-010418 had 6/16 ✓BUILT CVEs without smoke — all HTTP-exploit
    CVEs that did 3x http_check + 1-2 exec_check (lifecycle 200 +
    version), missing http_request_check (active injection).

    The prompt's existing Phase 48 rule says "2-3 functional verbs"
    counting http_check; the BENCH metric (Phase 49.1) counts only
    active types. SYSTEM_PROMPT must explicitly bridge the two: warn
    that http_check is liveness, not active; aim for ≥3 active checks
    (or ≥1 http_request_check + ≥2 exec_check) for HTTP CVEs.

    Without this warning, the agent will keep producing lifecycle-only
    plans on HTTP-exploit CVEs, missing the smoke target."""
    text = SYSTEM_PROMPT
    # Must reference Phase 49.1 metric explicitly. This is a specific
    # bridging anchor between the prompt's "2-3 functional verbs" rule
    # (which counts http_check) and the bench's smoke metric (which
    # does NOT count http_check). The existing prompt has "lifecycle 200"
    # + "active check" mentions but no explicit metric anchor — agents
    # don't get told the bench is grading active-only.
    assert "Phase 49.1" in text, (
        "SYSTEM_PROMPT must reference Phase 49.1 metric explicitly so the "
        "agent learns the bench grades smoke on active-only checks "
        "(exec_check / http_request_check / tcp_probe_check), excluding "
        "http_check. bench50-20260504-010418 had 6/16 ✓BUILT lacking "
        "smoke per Phase 49.1 — all HTTP-exploit CVEs that did 3x "
        "http_check (lifecycle) + 1-2 exec_check (version), no payload."
    )
    # The new rule should also explicitly call out the antipattern.
    has_antipattern_warning = any(
        s in text
        for s in (
            "3x http_check",
            "3 http_check",
            "http_check alone",
            "http_check is liveness",
            "lifecycle-only",
        )
    )
    assert has_antipattern_warning, (
        "SYSTEM_PROMPT must warn against the 'lifecycle-only' antipattern "
        "(3x http_check + version-only) explicitly. Existing 'liveness "
        "probe' wording is too soft — agents are still producing the "
        "antipattern."
    )


def test_tcp_payload_aliases_in_prompt_match_runtime_dict() -> None:
    r"""The prompt's `Aliases accepted: \`host\`→\`host_ip\`, ...` narrative
    (added by S28 E1.2) must match the runtime _TCP_PROBE_KEY_ALIASES
    dict exactly. Catches drift where the prompt teaches the agent an
    alias the runtime doesn't accept (or vice versa).

    Specifically catches the bug-class where E1.1 fixed `host` but the
    prompt narrative + runtime drift apart: if someone removes `host`
    from either side, this test goes RED."""
    from cve_env.tools.verify import _TCP_PROBE_KEY_ALIASES

    # The narrative line: "Aliases accepted: `a`→`b`, `c`→`d`, ...."
    m = re.search(r"Aliases accepted:\s*([^.]+)\.", SYSTEM_PROMPT)
    assert m, (
        "tcp_probe_check section in SYSTEM_PROMPT must list "
        "'Aliases accepted: ...' (added by S28 E1.2)"
    )
    text = m.group(1)
    pairs = re.findall(r"`(\w+)`\s*→\s*`(\w+)`", text)
    assert pairs, f"could not parse alias pairs from narrative: {text!r}"
    for alias, canonical in pairs:
        actual = _TCP_PROBE_KEY_ALIASES.get(alias)
        assert actual == canonical, (
            f"prompt advertises {alias!r}→{canonical!r} but runtime "
            f"_TCP_PROBE_KEY_ALIASES says {alias!r}→{actual!r}"
        )


# --- S28.1.c T7: dispatcher-path parameterized --------------------------


class _FakeTCPSocket:
    """Minimal partial mock of the socket interface check_tcp_probe uses.
    Mirrors test_verify.py:709-736 pattern locally to avoid cross-file
    fixture import."""

    def __init__(self, response: bytes = b"") -> None:
        self._response = response
        self.closed = False

    def settimeout(self, _t: float) -> None:
        pass

    def sendall(self, _data: bytes) -> None:
        pass

    def recv(self, n: int) -> bytes:
        return self._response[:n]

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def _all_check_io_mocked() -> Any:
    """Stack-patch every I/O path verify() dispatches into so the
    parametrized test can exercise dispatcher logic without docker /
    network.

    Yields a dict of the four mocks so tests can assert per-step
    routing correctness:

      `subproc`  — subprocess.run (used by container_status,
                   log_check; also transitively by stability_wait
                   via check_container_status, and by every step via
                   the auto-prepended container_status)
      `req`      — requests.request (used by http_check,
                   http_request_check)
      `sock`     — socket.create_connection (used by tcp_probe_check)
      `exec`     — _run_in_container.run_in_container (used by
                   exec_check)
    """
    from contextlib import ExitStack
    from unittest.mock import MagicMock, patch

    from cve_env.tools.run_in_container import ExecResult

    with ExitStack() as stack:
        # Container inspect / docker logs (subprocess.run)
        subproc = MagicMock()
        subproc.return_value.returncode = 0
        subproc.return_value.stdout = (
            '{"Status": "running", "Running": true, "ExitCode": 0}'
        )
        subproc.return_value.stderr = ""
        stack.enter_context(patch("cve_env.utils.run.subprocess.run", subproc))
        # HTTP (requests.request)
        req_mock = MagicMock()
        req_mock.return_value.status_code = 200
        req_mock.return_value.content = b"hello"
        req_mock.return_value.text = "hello"
        stack.enter_context(patch("cve_env.tools.verify.requests.request", req_mock))
        # TCP (socket.create_connection)
        sock_factory = MagicMock(return_value=_FakeTCPSocket(response=b"+PONG\r\n"))
        stack.enter_context(
            patch("cve_env.tools.verify.socket.create_connection", sock_factory)
        )
        # Container exec (run_in_container.run_in_container)
        exec_mock = MagicMock(
            return_value=ExecResult(
                ok=True,
                container_id="cid",
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
        yield {
            "subproc": subproc,
            "req": req_mock,
            "sock": sock_factory,
            "exec": exec_mock,
        }


_DISPATCH_FIXTURES: dict[str, dict[str, Any]] = {
    "container_status": {"type": "container_status"},
    "http_check": {
        "type": "http_check",
        "path": "/",
        "expected_status": [200],
        "require_nonempty_body": True,
    },
    "log_check": {"type": "log_check", "expected_patterns": ["x"]},
    "stability_wait": {"type": "stability_wait", "wait_seconds": 0},
    "exec_check": {
        "type": "exec_check",
        "command": "id",
        "expected_exit": 0,
        "expected_stdout_contains": "ok",
    },
    "http_request_check": {
        "type": "http_request_check",
        "method": "POST",
        "path": "/",
        "payload": "x",
        "field_name": "k",
        "expected_status": [200],
        "expected_response_contains": "hello",
    },
    "tcp_probe_check": {
        "type": "tcp_probe_check",
        "host_port": 8080,
        "send_text": "PING",
        "expected_response_contains": "+PONG",
    },
}


@pytest.mark.usefixtures("_all_check_io_mocked")
@pytest.mark.parametrize(
    "step",
    [_DISPATCH_FIXTURES[k] for k in sorted(_DISPATCH_FIXTURES)],
    ids=sorted(_DISPATCH_FIXTURES),
)
def test_verify_dispatches_advertised_schemas_without_exception(
    step: dict[str, Any],
) -> None:
    """Dispatcher-path coverage: every check schema the prompt
    advertises must dispatch through verify() without exception
    (TypeError, KeyError, etc.).

    Catches bugs the signature-only test misses:
    - Wrong alias dict picked for a check type
    - Missing pop pattern (e.g., the `tcp_host_ip = tcp_kwargs.pop(
      'host_ip', host_ip)` pattern from S28 E1.1 dispatcher fix)
    - Outright dispatch crash (KeyError, AttributeError on result shape)

    Does NOT catch (covered by sibling test
    `test_verify_dispatches_advertised_schemas_to_correct_io`):
    - Step→function routing bug (e.g., tcp_probe_check accidentally
      routed to check_http would still pass this test because every
      mock returns success-like values)

    Doesn't assert `passed=True` — mocks may not satisfy all check
    semantics."""
    from cve_env.tools.verify import verify

    out = verify(container_id="cid", host_ip="127.0.0.1", host_port=8080, plan=[step])
    assert out is not None
    assert "passed" in out, f"verify did not return a result dict: {out}"
    assert isinstance(out.get("results"), list), (
        f"verify result missing 'results' list: {out}"
    )


# Per step type, which mocks must be CALLED and which must NOT be called.
# `subproc` is always called transitively via the auto-prepended
# container_status (_canonicalize_plan), so it appears in `must_call`
# for every step.
_ROUTING_EXPECTATIONS: dict[str, dict[str, list[str]]] = {
    # container_status uses _inspect_state → subprocess.run
    "container_status": {
        "must_call": ["subproc"],
        "must_not_call": ["req", "sock", "exec"],
    },
    # http_check → requests.request
    "http_check": {"must_call": ["subproc", "req"], "must_not_call": ["sock", "exec"]},
    # log_check → subprocess.run (docker logs)
    "log_check": {"must_call": ["subproc"], "must_not_call": ["req", "sock", "exec"]},
    # stability_wait → check_container_status → subprocess.run (no separate I/O)
    "stability_wait": {
        "must_call": ["subproc"],
        "must_not_call": ["req", "sock", "exec"],
    },
    # exec_check → _run_in_container.run_in_container
    "exec_check": {"must_call": ["subproc", "exec"], "must_not_call": ["req", "sock"]},
    # http_request_check → requests.request
    "http_request_check": {
        "must_call": ["subproc", "req"],
        "must_not_call": ["sock", "exec"],
    },
    # tcp_probe_check → socket.create_connection
    "tcp_probe_check": {
        "must_call": ["subproc", "sock"],
        "must_not_call": ["req", "exec"],
    },
}


@pytest.mark.parametrize(
    ("step_type", "expectations"),
    sorted(_ROUTING_EXPECTATIONS.items()),
    ids=sorted(_ROUTING_EXPECTATIONS),
)
def test_verify_dispatches_advertised_schemas_to_correct_io(
    _all_check_io_mocked: dict[str, Any],  # noqa: PT019  (need fixture VALUE for assertions, not just side-effect)
    step_type: str,
    expectations: dict[str, list[str]],
) -> None:
    """Routing-correctness: each step type must dispatch to the
    correct I/O backend.

    Catches bugs the no-exception test misses:
    - Step accidentally routed to a different function (e.g., the
      `elif ctype == "tcp_probe_check"` branch wrongly calling
      `check_http(...)`). Without this assertion such a bug would pass
      `_dispatches_advertised_schemas_without_exception` because every
      mocked I/O returns success-like values.

    Per-step `must_call` includes `subproc` for every step because
    verify() always auto-prepends a `container_status` step (via
    `_canonicalize_plan`), which uses `_inspect_state → subprocess.run`."""
    from cve_env.tools.verify import verify

    step = _DISPATCH_FIXTURES[step_type]
    mocks = _all_check_io_mocked
    verify(container_id="cid", host_ip="127.0.0.1", host_port=8080, plan=[step])
    for name in expectations["must_call"]:
        assert mocks[name].called, (
            f"step {step_type!r} must call {name!r} I/O but it was NOT called"
        )
    for name in expectations["must_not_call"]:
        assert not mocks[name].called, (
            f"step {step_type!r} routed to {name!r} I/O but should not have "
            f"({mocks[name].call_count} calls). Routing bug — likely the "
            f"`elif ctype == {step_type!r}` branch in verify() dispatch"
        )


@pytest.mark.parametrize(
    ("func_name", "canonical_kwargs"),
    sorted(_ADVERTISED_KWARGS.items()),
    ids=sorted(_ADVERTISED_KWARGS),
)
def test_check_function_accepts_advertised_kwargs(
    func_name: str, canonical_kwargs: dict[str, object]
) -> None:
    """B8-class regression spec: every kwarg the prompt advertises for a
    check function must be accepted by that function's signature.

    Uses inspect.signature.bind() to verify the call shape WITHOUT
    executing the function (no mocks required). A TypeError here means
    the prompt is teaching the agent a kwarg the runtime will reject —
    same root cause as B8 (check_exec(workdir=)) and S28 E1.1
    (check_tcp_probe(host=))."""
    func = getattr(_verify_mod, func_name, None)
    assert func is not None, f"{func_name} not exported by cve_env.tools.verify"
    sig = inspect.signature(func)
    try:
        sig.bind(**canonical_kwargs)
    except TypeError as exc:
        pytest.fail(
            f"{func_name} signature rejects an advertised kwarg from "
            f"prompts.py EXACT-SCHEMAS: {exc}. "
            f"Advertised kwargs: {sorted(canonical_kwargs)}; "
            f"function params: {list(sig.parameters)}."
        )


# A2–A8 prompt rule lock-tests (CVE forensic fixes, 2026-05-05)


def test_prompt_source_build_no_tag_fallback_to_dockerfile_gen() -> None:
    """A2: prompt must instruct agent to use dockerfile_gen when no tag matched,
    NOT give_up. CVE-2020-15014: agent gave up on no_tag_matched."""
    assert "no tag matched" in SYSTEM_PROMPT
    # Must mention dockerfile_gen as the recovery action
    idx = SYSTEM_PROMPT.index("no tag matched")
    context = SYSTEM_PROMPT[max(0, idx - 50) : idx + 300]
    assert "dockerfile_gen" in context, (
        f"Prompt section near 'no tag matched' must mention dockerfile_gen, got: {context!r}"
    )


def test_prompt_has_turn_budget_priority_rule() -> None:
    """A3: prompt must have a T-5 turn budget priority rule directing agent to
    call docker_compose_up/docker_run + verify instead of fetching more sources.
    CVE-2019-11043: hit final_turn_cap 2 tool calls from success."""
    assert "5 or fewer turns remaining" in SYSTEM_PROMPT, (
        "Prompt must contain explicit T-5 rule '5 or fewer turns remaining'"
    )
    # Must mention the recovery action (verify or docker_compose_up)
    idx = SYSTEM_PROMPT.index("5 or fewer turns remaining")
    context = SYSTEM_PROMPT[max(0, idx - 50) : idx + 400]
    assert "verify" in context or "docker_compose_up" in context, (
        f"T-5 rule must mention verify or docker_compose_up, got: {context!r}"
    )


def test_prompt_stale_tmp_cleanup() -> None:
    """A4: prompt must advise clearing stale /tmp state before staging files."""
    assert "rm -rf /tmp/cve-" in SYSTEM_PROMPT, (
        "Prompt must contain A4 stale /tmp cleanup rule 'rm -rf /tmp/cve-'"
    )


def test_prompt_zip_content_type_check() -> None:
    """A7: prompt must advise verifying zip file is a valid ZIP before unzip."""
    assert "grep -q ZIP" in SYSTEM_PROMPT, (
        "Prompt must contain A7 zip validation rule 'grep -q ZIP'"
    )


def test_prompt_local_vs_registry_images() -> None:
    """A8: prompt must clarify that docker_build images are local-only and
    require docker_run, not docker_compose_up."""
    assert "exist ONLY" in SYSTEM_PROMPT or "exist only" in SYSTEM_PROMPT, (
        "Prompt must contain A8 local-vs-registry rule ('exist ONLY locally')"
    )


def test_prompt_ghostscript_smoke_test() -> None:
    """A5: prompt must recommend nullpage/dBATCH smoke for GS instead of
    showpage (which exits 1 without page content)."""
    assert "nullpage" in SYSTEM_PROMPT, (
        "Prompt must contain A5 GS smoke rule mentioning 'nullpage'"
    )
    assert "dBATCH" in SYSTEM_PROMPT, (
        "Prompt must contain A5 GS smoke rule mentioning '-dBATCH'"
    )


def test_prompt_indirect_poc_verification() -> None:
    """A6: prompt must advise verifying RCE exploits via side-effects
    (file written, env var, callback) rather than embedding verbatim payloads."""
    assert "content-policy" in SYSTEM_PROMPT or "content policy" in SYSTEM_PROMPT, (
        "Prompt must contain A6 indirect PoC rule mentioning content-policy"
    )
    assert (
        "side effect" in SYSTEM_PROMPT
        or "side-effect" in SYSTEM_PROMPT
        or "side effects" in SYSTEM_PROMPT
    ), "Prompt must mention side-effect verification for A6 rule"


def test_prompt_post_docker_run_verify_required() -> None:
    """F-7 (regression-lock): Phase 37.6 commitment rule. After docker_run
    returns ok=true, the agent's next tool call MUST be verify (or ONE Bash
    diag call followed by verify). The rule prevents the F-7 anti-pattern
    where agent ends turn after launching container but before calling verify.
    Forensic case: CVE-2019-3396 in V1 smoke bench50-20260505-022003 —
    docker_run ok=true at T7, end_turn at T8 with no verify call.

    This test locks the rule in place so a future prompt edit can't silently
    remove it.
    """
    # Rule must reference Phase 37.6 explicitly (so triage can find it)
    assert "Phase 37.6" in SYSTEM_PROMPT, (
        "F-7 rule must include Phase 37.6 marker for triage"
    )
    # Rule must direct agent to verify after docker_run
    idx = SYSTEM_PROMPT.index("Phase 37.6")
    context = SYSTEM_PROMPT[max(0, idx - 50) : idx + 600]
    assert "docker_run" in context and "verify" in context, (
        f"F-7 rule must mention docker_run + verify; got: {context!r}"
    )
    # Rule must say MUST (strong language)
    assert "MUST" in context, (
        f"F-7 rule must use 'MUST' (commitment language); got: {context!r}"
    )
    # Rule must forbid end_turn before verify
    assert "end_turn" in context and ("Do NOT" in context or "do NOT" in context), (
        f"F-7 rule must explicitly forbid premature end_turn; got: {context!r}"
    )


def test_prompt_phase41_post_compose_up_and_post_build_chains() -> None:
    """Phase 41 (2026-05-16): extension of the Phase 37.6 commitment rule.

    Two new chains:
    (a) After `docker_compose_up.ok=true`, agent's next call MUST be `verify`.
    (b) After `docker_build.ok=true`, agent's next call MUST be `docker_run`
        (not Bash for inspection).

    Forensic from Phase 38 bench50-20260516-103837:
    - 4 vulhub-compose CVEs (CVE-2024-0428, 13408, 1677, 22291) called
      docker_compose_up 4-9× each, never reached verify, all turn_cap.
    - 4 CVEs (CVE-2024-10749, 12828, 1353, 22087) reached docker_build.ok=true
      then end_turn without docker_run — Phase 7.3 caught these as
      quit_without_verify_or_giveup.

    This rule has the same shape as Phase 24E #29 source-build pivot
    (deterministic trigger + deterministic action) which shipped 2026-05-13
    and achieved 73% in-run pivot success at n=11. Phase 24E shape proves
    prompt-only rules CAN work when the trigger is tool_result.ok=true AND
    the action is a specific next tool.
    """
    # Rule must be tagged for triage
    assert "Phase 41 commitment rule" in SYSTEM_PROMPT, (
        "Phase 41 chain extension missing tag in SYSTEM_PROMPT"
    )
    idx = SYSTEM_PROMPT.index("Phase 41 commitment rule")
    context = SYSTEM_PROMPT[idx : idx + 1200]

    # (a) post-compose_up → verify
    assert "docker_compose_up" in context and "verify" in context, (
        f"Phase 41 rule must mention docker_compose_up + verify; got: {context!r}"
    )

    # (b) post-build → docker_run
    assert "docker_build" in context and "docker_run" in context, (
        f"Phase 41 rule must mention docker_build + docker_run; got: {context!r}"
    )

    # MUST language (strong commitment)
    assert "MUST" in context, (
        f"Phase 41 rule must use 'MUST' commitment language; got: {context!r}"
    )

    # Anchored to Phase 24E #29 shape (so triage knows this is a
    # post-deterministic-trigger rule per past-bench-lessons §0).
    assert "Phase 24E" in context or "73%" in context, (
        f"Phase 41 rule must reference the Phase 24E shape it follows; got: {context!r}"
    )


def test_prompt_research_only_fast_fail() -> None:
    """P0-4: prompt must direct agent to give_up(no_image) early when image_resolve
    returns no candidates AND no GitHub repo exists. bench200 evidence: 45 of 100
    CVEs took research-only path, 0 succeeded — wasted ~$30/bench in futile spirals
    (avg 21 turns, $0.30-0.90 each). Triggered by user request 2026-05-05."""
    has_rule = (
        "no candidates" in SYSTEM_PROMPT
        or "0 candidates" in SYSTEM_PROMPT
        or "no image candidates" in SYSTEM_PROMPT
    )
    assert has_rule, (
        "Prompt must contain P0-4 research-only fast-fail rule mentioning "
        "'no candidates' / '0 candidates' / 'no image candidates'"
    )
    # The rule must direct to give_up
    for phrase in ("no candidates", "0 candidates", "no image candidates"):
        if phrase in SYSTEM_PROMPT:
            idx = SYSTEM_PROMPT.index(phrase)
            context = SYSTEM_PROMPT[max(0, idx - 100) : idx + 300]
            assert "give_up" in context, (
                f"P0-4 rule near '{phrase}' must direct agent to give_up; "
                f"got context: {context!r}"
            )
            break


def test_prompt_two_fail_pivot_rule() -> None:
    """P0-5: prompt must direct agent to pivot strategy after 2 consecutive
    docker_build failures with the same reason_class (avoid blind retry storms).
    bench200 evidence: CVE-2022-32101 wasted $1.80 on 14 GPG cert retries before
    pivoting at T61; pivot at T48 would have saved $0.50. Triggered 2026-05-05."""
    # Must mention 2-fail threshold (numeric or word)
    has_count = (
        "2 consecutive" in SYSTEM_PROMPT
        or "two consecutive" in SYSTEM_PROMPT
        or "second failure" in SYSTEM_PROMPT
        or "after 2 failures" in SYSTEM_PROMPT
    )
    # Must mention pivot or strategy change
    has_pivot = (
        "pivot" in SYSTEM_PROMPT
        or "different base" in SYSTEM_PROMPT
        or "change strategy" in SYSTEM_PROMPT
    )
    assert has_count, (
        "P0-5 rule must specify the 2-failure trigger: "
        "'2 consecutive' / 'two consecutive' / 'second failure' / 'after 2 failures'"
    )
    assert has_pivot, (
        "P0-5 rule must direct pivot: 'pivot' / 'different base' / 'change strategy'"
    )
    # Must specifically reference docker_build (so the rule applies in the right context)
    for count_phrase in (
        "2 consecutive",
        "two consecutive",
        "second failure",
        "after 2 failures",
    ):
        if count_phrase in SYSTEM_PROMPT:
            idx = SYSTEM_PROMPT.index(count_phrase)
            context = SYSTEM_PROMPT[max(0, idx - 100) : idx + 400]
            assert "docker_build" in context, (
                f"P0-5 rule near '{count_phrase}' must reference docker_build; "
                f"got context: {context!r}"
            )
            break


def test_prompt_p_a8_bash_source_reads_route_through_github_fetch() -> None:
    """P-A8 (B-18 fix, 2026-05-06): the prompt must direct the agent
    AWAY from Bash cat/sed/head/tail/grep on source-extension files
    (.php/.py/.go/etc.) and TOWARD github_fetch (which sanitizes
    source bodies via B-17). Empirical: 2 refusals across smoke10 +
    experiment were both Bash-on-vulnerable-source-file."""
    assert "P-A8" in SYSTEM_PROMPT, "P-A8 marker missing"
    idx = SYSTEM_PROMPT.index("P-A8")
    block = SYSTEM_PROMPT[idx : idx + 2000]
    # Must direct toward github_fetch
    assert "github_fetch" in block, "P-A8 must direct agent to github_fetch"
    # Must list at least 3 source file extensions explicitly
    n_exts = sum(
        1
        for ext in (".php", ".py", ".go", ".java", ".rb", ".js", ".c", ".cpp")
        if ext in block
    )
    assert n_exts >= 3, f"P-A8 must list ≥3 source extensions; found {n_exts}"
    # Must reference Bash as the FORBIDDEN path
    assert "Bash" in block, "P-A8 must mention Bash"
    # Must explain WHY (AUP / refusal)
    assert "AUP" in block or "refusal" in block.lower(), (
        "P-A8 must reference AUP/refusal as the reason"
    )


def test_prompt_p0_7_refusal_recovery_marker() -> None:
    """P0-7 (2026-05-06): prompt must direct agent to recover from refusals
    by reframing (env-construction not exploit), substituting indirect-PoC
    verify, and giving up after 2 consecutive refusals. bench50-20260505-231537
    evidence: 2/43 CVEs hit refusals (CVE-2022-25396 T44, CVE-2022-27413 T66)
    and the agent had no prompt-level recovery guidance — both runs continued
    past refusal but never landed verify_passed. Marker test: confirms the
    rule TEXT is present in SYSTEM_PROMPT.

    Pair this with the behavioral test below (F-5 lesson: marker assertion
    alone proves text presence, not behavior)."""
    assert "P0-7" in SYSTEM_PROMPT, "P0-7 marker missing from SYSTEM_PROMPT"
    # Must mention refusal-recovery reframe + indirect-PoC + give_up after 2x
    assert "refusal" in SYSTEM_PROMPT.lower(), "P0-7 must reference 'refusal'"
    # The reframe instruction must appear
    assert (
        "environment-construction" in SYSTEM_PROMPT
        or "vulnerable Docker environment" in SYSTEM_PROMPT
    ), (
        "P0-7 must contain reframing language ('environment-construction' "
        "or 'vulnerable Docker environment')"
    )
    # Must direct to give_up with content_policy reason after 2 refusals
    idx = SYSTEM_PROMPT.index("P0-7")
    context = SYSTEM_PROMPT[idx : idx + 1500]
    assert "2 consecutive" in context or "two consecutive" in context, (
        "P0-7 must specify 2-refusal threshold"
    )
    assert "content_policy" in context, (
        "P0-7 must direct give_up(reason='content_policy', ...)"
    )


def test_prompt_phase_52_1_explicit_prepatch_version_marker() -> None:
    """Phase 52.1 (2026-05-06): version-assertion exec_check's
    expected_stdout_contains MUST match the EXACT pre-patch CVE-vulnerable
    version string (e.g., 'Apache/2.4.49') — not just the package name
    ('Apache'). Without this, a generic version-discovery exec_check passes
    against ANY deployed version, defeating the Phase 52 gate's purpose."""
    assert "Phase 52.1" in SYSTEM_PROMPT, "Phase 52.1 marker missing from SYSTEM_PROMPT"
    idx = SYSTEM_PROMPT.index("Phase 52.1")
    block = SYSTEM_PROMPT[idx : idx + 2000]
    # Must reference expected_stdout_contains (the field being tightened)
    assert "expected_stdout_contains" in block, (
        "Phase 52.1 must reference expected_stdout_contains"
    )
    # Must reference pre-patch / vulnerable version language
    has_prepatch = "pre-patch" in block.lower() or "vulnerable version" in block.lower()
    assert has_prepatch, "Phase 52.1 must reference 'pre-patch' / 'vulnerable version'"


def test_prompt_phase_52_1_explicit_prepatch_version_behavioral() -> None:
    """Phase 52.1 BEHAVIORAL test (F-5 lesson): the rule must (a) show a
    GOOD/BAD example contrast so the agent has a concrete model, and
    (b) explicitly tie the pre-patch version to nvd_lookup's
    versionEndExcluding/version fields (so the agent knows where to source
    the string)."""
    idx = SYSTEM_PROMPT.index("Phase 52.1")
    block = SYSTEM_PROMPT[idx : idx + 2000]
    # GOOD/BAD contrast — both labels must appear in the block
    has_good = "GOOD:" in block
    has_bad = "BAD:" in block
    assert has_good and has_bad, (
        "Phase 52.1 must contrast GOOD: vs BAD: examples so the agent "
        "has a concrete model of loose vs tight assertions"
    )
    # Must point at NVD source for the pre-patch string
    has_nvd_source = "nvd_lookup" in block and (
        "versionEndExcluding" in block or "version" in block
    )
    assert has_nvd_source, (
        "Phase 52.1 must direct the agent to nvd_lookup's "
        "versionEndExcluding / version fields as the source of truth"
    )
    # Must specify failure contract: deployed != pre-patch → exec_check fails
    has_failure_contract = (
        "FAIL" in block or "must fail" in block.lower() or "differs" in block.lower()
    )
    assert has_failure_contract, (
        "Phase 52.1 must state the failure contract: if deployed version "
        "differs from pre-patch, exec_check must fail"
    )


def test_prompt_p0_x_end_of_run_discipline_marker() -> None:
    """P0-X (2026-05-06): every CVE run MUST end with verify(passed=True) OR
    give_up(reason=...) — never silently. bench50-20260505-231537 evidence:
    4/43 CVEs ended in `no_verify_pass` with no give_up call; the runtime had
    to infer give-up from absence of further tool calls. Marker test confirms
    the rule TEXT is present."""
    assert "P0-X" in SYSTEM_PROMPT, "P0-X marker missing from SYSTEM_PROMPT"
    idx = SYSTEM_PROMPT.index("P0-X")
    block = SYSTEM_PROMPT[idx : idx + 1500]
    assert "verify" in block, "P0-X must reference verify"
    assert "give_up" in block, "P0-X must reference give_up"
    # The (a) / (b) structure or equivalent must direct one of two terminations
    assert ("(a)" in block and "(b)" in block) or "EITHER" in block.upper(), (
        "P0-X must enumerate the two valid terminations (verify-pass OR give_up)"
    )


def test_prompt_p0_x_end_of_run_discipline_behavioral() -> None:
    """P0-X BEHAVIORAL test (F-5 lesson): the rule must explicitly forbid
    silent end-of-run AND name the kinds of conditions that warrant give_up
    (so the agent reading sequentially knows which reasons are valid). Tests
    structural completeness, not just text presence."""
    idx = SYSTEM_PROMPT.index("P0-X")
    block = SYSTEM_PROMPT[idx : idx + 1500]
    # Must have explicit "never silent end" prohibition
    has_prohibition = "NEVER" in block and ("silently" in block or "without" in block)
    # Must enumerate at least 2 valid give_up reasons so the agent knows
    # what to put in the reason field
    enumerated_reasons = sum(
        1
        for keyword in (
            "rate_limited",
            "no_image",
            "source_not_found",
            "verify-fail",
            "refusal",
            "budget",
            "content_policy",
        )
        if keyword in block
    )
    assert has_prohibition, (
        "P0-X must explicitly forbid silent end-of-run "
        "(NEVER end without (a) verify-pass or (b) give_up)"
    )
    assert enumerated_reasons >= 2, (
        f"P0-X must enumerate at least 2 give_up reason classes so the "
        f"agent knows valid reasons; found {enumerated_reasons} in block"
    )


def test_prompt_p0_7_refusal_recovery_behavioral() -> None:
    """P0-7 BEHAVIORAL test (F-5 lesson): the rule must do more than appear
    in the prompt — it must surround give_up + content_policy + reframe in
    a single coherent block, so the agent reading sequentially gets all
    three pieces of guidance together. Tests structural coherence, not just
    text presence."""
    idx = SYSTEM_PROMPT.index("P0-7")
    block = SYSTEM_PROMPT[idx : idx + 1500]
    # All three semantic pieces must co-occur within the P0-7 section:
    # 1) reframing direction
    has_reframe = (
        "I'm building a vulnerable Docker environment" in block
        or "environment-construction" in block
    )
    # 2) indirect-PoC substitute (file in /tmp / canary / banner regex)
    has_indirect = (
        "/tmp" in block
        or "canary" in block
        or "banner" in block
        or "P-A6" in block
        or "indirect-PoC" in block
    )
    # 3) give_up escape after 2 refusals
    has_giveup = (
        ("2 consecutive" in block or "two consecutive" in block)
        and "give_up" in block
        and "content_policy" in block
    )
    assert has_reframe, "P0-7 missing reframe instruction"
    assert has_indirect, "P0-7 missing indirect-PoC substitute guidance"
    assert has_giveup, "P0-7 missing give_up(content_policy) escape after 2 refusals"


def test_phase_24b_version_assertion_rule_present():
    """Phase 24B (2026-05-13): SYSTEM_PROMPT must explicitly direct the agent
    to include the version literal in expected_stdout_contains for the
    version-discovery exec_check, AND mention the runtime auto-inject
    fallback so the agent knows the runtime catches omissions.

    Without this rule, the agent often populates expected_stdout_contains
    with the product name only (no version digits per \\d+\\.\\d+), and
    the Phase 52.1 strict-marker gate demotes plain `success` to
    `verified_partial`. CVE-2024-10234 Phase 22→23 path-variance is the
    canonical case this rule + the paired runtime injector close.
    """
    assert "Phase 24B" in SYSTEM_PROMPT, (
        "Phase 24B version-assertion rule missing tag in SYSTEM_PROMPT"
    )
    assert (
        "version literal" in SYSTEM_PROMPT
        and "expected_stdout_contains" in SYSTEM_PROMPT
    ), (
        "Phase 24B rule missing the 'version literal in expected_stdout_contains' directive"
    )
    # The rule mentions the auto-inject fallback so the agent knows the
    # runtime catches the omission case.
    assert (
        "AUTO-INJECT" in SYSTEM_PROMPT
        or "auto-inject" in SYSTEM_PROMPT
        or "auto_inject" in SYSTEM_PROMPT
        or "AUTO-INJECTS" in SYSTEM_PROMPT
    ), "Phase 24B rule missing the runtime auto-inject fallback note"


def test_phase_24e_recovery_prompt_bundle_present():
    """Phase 24E (2026-05-13): three recovery prompt rules — #27 (verify-
    iteration), #29 (source-build → dockerfile_gen pivot), #34 (read-the-
    hint). Empirical from Phases 22+23: verify-iteration is the dominant
    winning pattern (7/7 Phase 23 wins) but agent quits at first-fail
    inconsistently; source-build pivot was the difference between Phase 22
    fails and Phase 23 wins (CVE-2024-10749). All three rules ship as a
    single bundle per L-class isolation (prompt-only, no runtime change).
    """
    assert "Phase 24E" in SYSTEM_PROMPT, (
        "Phase 24E recovery prompt bundle missing tag in SYSTEM_PROMPT"
    )
    # #27 Verify-iteration: agent must read reason + iterate, not quit
    assert (
        "Verify-iteration" in SYSTEM_PROMPT and "MODIFY ONE CHECK" in SYSTEM_PROMPT
    ), "Phase 24E #27 verify-iteration rule missing"
    # #29 Source-build pivot to dockerfile_gen
    assert (
        "Source-build" in SYSTEM_PROMPT
        and "dockerfile_gen pivot" in SYSTEM_PROMPT
        and "no_tag_matched" in SYSTEM_PROMPT
    ), "Phase 24E #29 source-build pivot rule missing"
    # #34 Read-the-hint before retrying build-stage tools
    assert "Read-the-hint" in SYSTEM_PROMPT and "next_step_hint" in SYSTEM_PROMPT, (
        "Phase 24E #34 read-the-hint rule missing"
    )


def test_prompt_forbids_raw_bash_docker_pull() -> None:
    """Phase B (docker-pull hang): SYSTEM_PROMPT must forbid raw `docker pull`
    via the Bash tool to pre-warm images.

    A raw `Bash docker pull` is unbounded and hangs the whole run until the
    wall-guard. The build tools (docker_run / docker_compose_up) pull images
    themselves and are timeout-bounded; if an image is slow/unavailable the
    agent must pivot to source_build, not pull manually.
    """
    text = SYSTEM_PROMPT.lower()
    assert "docker pull" in text, (
        "SYSTEM_PROMPT must mention `docker pull` to warn against it"
    )
    assert "do not" in text or "don't" in text, (
        "SYSTEM_PROMPT must contain a prohibition ('do not'/'don't')"
    )
    # The prohibition must be co-located with both `docker pull` and `Bash`.
    idx = text.index("docker pull")
    window = text[max(0, idx - 200) : idx + 450]
    assert "bash" in window, (
        f"docker-pull prohibition must reference the Bash tool, got: {window!r}"
    )
    assert "do not" in window or "don't" in window, (
        f"docker-pull guidance must be an explicit prohibition, got: {window!r}"
    )
    # And it must steer toward the source_build pivot.
    assert "source_build" in window, (
        f"docker-pull prohibition must steer toward source_build, got: {window!r}"
    )
