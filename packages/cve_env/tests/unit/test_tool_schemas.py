"""CI gate: assert all 10 tools register at import time with valid schemas.

This is the direct inverse of cve-build's `CVE_BUILD_RECOVERY_STRATEGIES`
bug (recovery strategies were unregistered at bench time, so the 3070 LOC
recovery layer had never run in its bench). Here, tools self-register
at module import with NO env var gate; this test asserts that fact and
fails CI if anything drifts.
"""

from __future__ import annotations

import pytest
from claude_agent_sdk import SdkMcpTool, create_sdk_mcp_server

from cve_env.agent.tools import ALL_TOOLS, TOOL_NAMES, get_tool_by_name

EXPECTED_NAMES: tuple[str, ...] = (
    "nvd_lookup",
    "github_fetch",
    "image_resolve",
    "dockerfile_gen",
    "source_build",
    "docker_build",
    "docker_run",
    "docker_compose_up",
    "run_in_container",
    "verify",
    "give_up",
)

# Each tool's required top-level input parameter names. The schema is
# ``dict[param_name, Annotated[...]]``; we assert the keys match what
# the plan specifies so a silent schema drift fails CI.
REQUIRED_PARAMS: dict[str, set[str]] = {
    "nvd_lookup": {"cve_id"},
    "github_fetch": {"owner", "repo", "path", "ref"},
    "image_resolve": {"product", "version", "host_arch"},
    "dockerfile_gen": {
        "base_image",
        "install_steps",
        "workdir",
        "cmd",
        "ports",
        "copy_ops",
        "cve_named_packages",
        "apt_unsafe",
        "build",
        "context_dir",
        "image_tag",
    },
    "source_build": {"source_url", "product", "version"},
    "docker_build": {"context_dir", "dockerfile_text", "image_tag"},
    "docker_run": {"image", "container_port", "run_id", "cve_id", "platform"},
    "docker_compose_up": {"compose_yaml_path", "cve_id", "platform"},
    "run_in_container": {"container_id", "command", "timeout_seconds", "workdir"},
    "verify": {"container_id", "host_ip", "host_port", "plan"},
    "give_up": {"reason", "detail"},
}


def test_exactly_eleven_tools_registered() -> None:
    assert len(ALL_TOOLS) == 11


def test_all_tools_are_mcp_tool_instances() -> None:
    for t in ALL_TOOLS:
        assert isinstance(t, SdkMcpTool), f"{t} is not an SdkMcpTool"


def test_canonical_name_list_matches() -> None:
    names = tuple(t.name for t in ALL_TOOLS)
    assert names == EXPECTED_NAMES
    assert TOOL_NAMES == EXPECTED_NAMES


def test_no_duplicate_tool_names() -> None:
    names = [t.name for t in ALL_TOOLS]
    assert len(names) == len(set(names))


def test_every_tool_has_a_description() -> None:
    for t in ALL_TOOLS:
        assert t.description, f"{t.name} has no description"
        # Descriptions should be substantive: the agent reads these to choose tools.
        assert len(t.description) >= 40, (
            f"{t.name} description too short ({len(t.description)} chars)"
        )


@pytest.mark.parametrize(("tool_name", "expected"), sorted(REQUIRED_PARAMS.items()))
def test_tool_input_schema_has_expected_params(tool_name: str, expected: set[str]) -> None:
    t = get_tool_by_name(tool_name)
    assert isinstance(t.input_schema, dict)
    actual = set(t.input_schema.keys())
    assert actual == expected, (
        f"{tool_name}: schema keys {actual} != expected {expected}"
    )


def test_get_tool_by_name_hits() -> None:
    assert get_tool_by_name("nvd_lookup").name == "nvd_lookup"


def test_get_tool_by_name_misses_raise_keyerror() -> None:
    with pytest.raises(KeyError):
        get_tool_by_name("nonexistent_tool")


def test_all_tools_can_be_assembled_into_an_mcp_server() -> None:
    """The SDK's create_sdk_mcp_server validates tool shapes on construction."""
    server = create_sdk_mcp_server(name="cve_env", version="0.0.0", tools=ALL_TOOLS)
    assert server is not None
