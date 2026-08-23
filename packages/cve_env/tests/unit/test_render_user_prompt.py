"""Contract tests for ``prompts.render_user_prompt``.

Phase 20A.3 (2026-05-12): introduced ``run_id`` parameter so the agent
uses the canonical cli-side run_id when calling ``docker_run`` and
``docker_compose_up``. Pre-20A.3 the agent invented its own (typically
``cve-env-{cve_id_slug}``) which never matched cli's audit-side
``manual-{ts}`` — Phase 4 auto-cleanup filter silently missed every
container. Phase 20A.1 made cleanup robust by filtering on
``cve-env.cve-id`` instead, but the canonical-run_id-in-prompt fix
here closes the architectural mismatch.
"""

from __future__ import annotations

from cve_env.agent.prompts import render_user_prompt
from cve_env.models import CveRecord, HostInfo


def _cve() -> CveRecord:
    return CveRecord(
        cve_id="CVE-2014-0160",
        product="OpenSSL",
        version="1.0.1f",
        description="Memory disclosure in heartbeat extension",
        references=("https://example.com/cve",),
    )


def _host() -> HostInfo:
    return HostInfo(arch="aarch64", os="darwin", docker_backend="colima")


def test_render_user_prompt_omits_run_id_section_when_empty() -> None:
    """Default ``run_id=""`` produces no Run-identifier section.
    Preserves the pre-20A.3 prompt shape for callers that don't pass
    run_id (e.g., tests, scripts that build the prompt directly)."""
    out = render_user_prompt(_cve(), _host())
    assert "# Run identifier" not in out
    assert "run_id" not in out  # only the section heading mentions it


def test_render_user_prompt_includes_run_id_section_when_provided() -> None:
    """Non-empty ``run_id`` injects a ``# Run identifier`` section
    instructing the agent to pass the canonical value to docker tools."""
    out = render_user_prompt(_cve(), _host(), run_id="manual-1778631213")
    assert "# Run identifier" in out
    # The exact value must appear (agent will copy it verbatim).
    assert "manual-1778631213" in out
    # Instruction to use it in tool calls must be present.
    assert "docker_run" in out
    assert "run_id=" in out, "agent must be told which arg to use"


def test_render_user_prompt_run_id_section_appears_before_imperative() -> None:
    """The run_id section must appear BEFORE the closing
    'Build a reproducible...' imperative so the agent reads it as
    setup, not as a footnote after the build instruction.
    """
    out = render_user_prompt(_cve(), _host(), run_id="manual-99999")
    run_id_idx = out.find("# Run identifier")
    build_idx = out.find("Build a reproducible Docker environment")
    assert run_id_idx > 0, "run_id section must exist"
    assert build_idx > 0, "build imperative must exist"
    assert run_id_idx < build_idx, (
        f"run_id section (at {run_id_idx}) must precede build imperative "
        f"(at {build_idx}) so the agent reads it as setup."
    )


def test_render_user_prompt_run_id_escapes_via_repr() -> None:
    """run_id is rendered via ``{run_id!r}`` so the agent's tool call
    arg appears as a Python-quoted literal — clear and unambiguous.
    """
    out = render_user_prompt(_cve(), _host(), run_id="manual-1778631213")
    # Repr-quoted form ('manual-...') must appear so agent copies it as-is.
    assert "'manual-1778631213'" in out, (
        "run_id must be rendered as a quoted literal (via {run_id!r}) so "
        "the agent passes it verbatim, not parsed as a bareword"
    )


def test_render_user_prompt_cve_fields_still_present_with_run_id() -> None:
    """Sanity: adding the run_id section did not break the CVE/Host
    blocks above it.
    """
    out = render_user_prompt(_cve(), _host(), run_id="manual-12345")
    assert "CVE-2014-0160" in out
    assert "OpenSSL" in out
    assert "1.0.1f" in out
    assert "arch: aarch64" in out
