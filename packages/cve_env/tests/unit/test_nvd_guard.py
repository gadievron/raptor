"""Tests for Phase 35.4: nvd_lookup 1-call-per-CVE guard.

The guard lives in :mod:`cve_env.agent.tools` and is reset by the build()
loop at the start of each CVE via :func:`reset_nvd_lookup_state`.
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from cve_env.agent.tools import nvd_lookup, reset_nvd_lookup_state

def _call(args: dict[str, Any]) -> dict[str, Any]:
    """Synchronous wrapper for the async tool. Tools are SdkMcpTool
    instances; the actual async function is exposed on .handler."""
    return asyncio.run(nvd_lookup.handler(args))

# --- Blacklist removal (2026-06-08) contract tests ---------------------------
# The static proprietary-vendor blacklist (data file + _detect_proprietary_vendor
# pre-screen + proprietary_vendor_hint) is removed. Proprietary detection is now
# agent-reasoned (give_up after probing finds nothing) + the default-OFF
# proprietary-verify gate. These two tests lock that the machinery is gone.

def test_blacklist_symbols_removed() -> None:
    """The static-blacklist machinery must no longer exist on cve_env.agent.tools."""
    import cve_env.agent.tools as t

    for sym in (
        "_detect_proprietary_vendor",
        "_load_proprietary_vendors",
        "_references_have_oss_host",
        "_OSS_REFERENCE_HOSTS",
        "_PROPRIETARY_VENDORS_CACHE",
    ):
        assert not hasattr(t, sym), f"{sym} should be removed (blacklist abandoned)"

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_nvd_lookup_never_emits_proprietary_vendor_hint(mock_payload: Any) -> None:
    """A former-blacklist CPE vendor (cisco) must NOT get a proprietary_vendor_hint:
    the agent reaches give_up(proprietary) by its own reasoning, not a static list."""
    import json

    reset_nvd_lookup_state()
    mock_payload.return_value = {
        "ok": True,
        "cve_id": "CVE-2099-00001",
        "cpes": [{"vendor": "cisco", "product": "ios", "version": "1.0"}],
    }
    result = _call({"cve_id": "CVE-2099-00001"})
    parsed = json.loads(result["content"][0]["text"])
    assert "proprietary_vendor_hint" not in parsed

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_first_call_proxies_to_payload(mock_payload: Any) -> None:
    """Phase 35.4: the FIRST nvd_lookup call passes through normally."""
    reset_nvd_lookup_state()
    mock_payload.return_value = {"ok": True, "cve_id": "CVE-2018-7600"}
    result = _call({"cve_id": "CVE-2018-7600"})
    # Tool wrapper returns {"content": [{"type":"text","text":"<json>"}]}
    # so we just check that the underlying payload was called.
    mock_payload.assert_called_once_with("CVE-2018-7600")
    assert "content" in result

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_second_call_allowed_for_recovery(mock_payload: Any) -> None:
    """Phase 35.4 + 39.4a: the SECOND nvd_lookup call is now ALLOWED
    (recovery scenario after a refusal / transport blip). Only the 3rd
    call is blocked. Threshold bumped from 1 to 2 after CVE-2022-4547
    regression in bench50-20260428-205830 — agent hit API refusal at
    turn 25, blocked from legitimate recovery research at turn 40.
    """
    reset_nvd_lookup_state()
    mock_payload.return_value = {"ok": True}
    _call({"cve_id": "CVE-2018-7600"})  # 1st call OK
    mock_payload.reset_mock()
    # 2nd call should ALSO go through (not blocked).
    _call({"cve_id": "CVE-2018-7600"})
    mock_payload.assert_called_once_with("CVE-2018-7600")

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_third_call_blocked(mock_payload: Any) -> None:
    """Phase 35.4 + 39.4a: the THIRD nvd_lookup call is hard-rejected
    (clearly thrash, matches CVE-2021-23639's 3-call pattern).
    """
    reset_nvd_lookup_state()
    mock_payload.return_value = {"ok": True}
    _call({"cve_id": "CVE-2018-7600"})  # 1st OK
    _call({"cve_id": "CVE-2018-7600"})  # 2nd OK (recovery)
    mock_payload.reset_mock()
    result = _call({"cve_id": "CVE-2018-7600"})  # 3rd → blocked
    mock_payload.assert_not_called()
    import json

    text = result["content"][0]["text"]
    parsed = json.loads(text)
    assert parsed["ok"] is False
    assert parsed["blocked"] is True
    assert "already" in parsed["reason"]
    assert "next_step_hint" in parsed

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_reset_unblocks_for_next_cve(mock_payload: Any) -> None:
    """Phase 35.4: reset_nvd_lookup_state() (called at each CVE start by
    the build loop) clears the guard so the next CVE can call nvd_lookup
    once.
    """
    reset_nvd_lookup_state()
    mock_payload.return_value = {"ok": True}
    _call({"cve_id": "CVE-2018-7600"})  # 1st call OK
    # New CVE — bench loop calls reset.
    reset_nvd_lookup_state()
    mock_payload.reset_mock()
    _call({"cve_id": "CVE-2021-44228"})  # 1st call for new CVE: OK
    mock_payload.assert_called_once_with("CVE-2021-44228")

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_block_message_steers_agent_to_alternatives(
    mock_payload: Any,
) -> None:
    """Phase 35.4 + 39.4a: the block response includes a next_step_hint
    listing docker_build / docker_run / verify / give_up so the agent
    knows what to do instead of re-researching. Triggers on the 3rd call.
    """
    reset_nvd_lookup_state()
    mock_payload.return_value = {"ok": True}
    _call({"cve_id": "CVE-2018-7600"})  # 1st
    _call({"cve_id": "CVE-2018-7600"})  # 2nd
    result = _call({"cve_id": "CVE-2018-7600"})  # 3rd → blocked

    import json

    text = result["content"][0]["text"]
    parsed = json.loads(text)
    hint = parsed["next_step_hint"]
    assert "docker_build" in hint
    assert "docker_run" in hint
    assert "verify" in hint
    assert "give_up" in hint

# Kernel quick-fail pre-screen tests ----------------------------------

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_kernel_hint_fires_on_linux_kernel_only_cve(mock_payload: Any) -> None:
    """Kernel quick-fail (2026-05-24): a CVE whose only affected component
    is the Linux kernel gets `kernel_unsupported_hint` steering the agent
    to immediate give_up(arch_incompatible) — containers share the host
    kernel so there's no buildable artifact. Models CVE-2022-0847 (Dirty
    Pipe)."""
    import json

    reset_nvd_lookup_state()
    mock_payload.return_value = {
        "ok": True,
        "cve_id": "CVE-2022-0847",
        "cpes": [
            {
                "vendor": "linux",
                "product": "linux_kernel",
                "version": "5.16.0",
                "cpe": "cpe:2.3:o:linux:linux_kernel:5.16.0:*:*:*:*:*:*:*",
            }
        ],
    }
    result = _call({"cve_id": "CVE-2022-0847"})
    parsed = json.loads(result["content"][0]["text"])
    assert "kernel_unsupported_hint" in parsed
    hint = parsed["kernel_unsupported_hint"]
    assert "give_up" in hint
    assert "arch_incompatible" in hint
    assert "kernel" in hint.lower()

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_kernel_hint_not_fired_when_other_component_present(mock_payload: Any) -> None:
    """Guard: a userspace CVE that merely lists the kernel as a platform CPE
    (alongside a real application component) must NOT be quick-failed — it
    may be buildable. Conservative 'exclusively linux_kernel' gate."""
    import json

    reset_nvd_lookup_state()
    mock_payload.return_value = {
        "ok": True,
        "cve_id": "CVE-2099-0001",
        "cpes": [
            {"vendor": "linux", "product": "linux_kernel", "version": "5.15.0"},
            {"vendor": "apache", "product": "http_server", "version": "2.4.0"},
        ],
    }
    result = _call({"cve_id": "CVE-2099-0001"})
    parsed = json.loads(result["content"][0]["text"])
    assert "kernel_unsupported_hint" not in parsed

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_kernel_hint_not_fired_for_non_kernel_cve(mock_payload: Any) -> None:
    """Guard: a normal application CVE gets no kernel hint."""
    import json

    reset_nvd_lookup_state()
    mock_payload.return_value = {
        "ok": True,
        "cve_id": "CVE-2018-7600",
        "cpes": [{"vendor": "drupal", "product": "drupal", "version": "8.5.0"}],
    }
    result = _call({"cve_id": "CVE-2018-7600"})
    parsed = json.loads(result["content"][0]["text"])
    assert "kernel_unsupported_hint" not in parsed

# Phase 43.S3A: OSS-reference override tests --------------------------

# =============================================================================
# #4 (2026-05-24): no_image → source_build structural assist. nvd_lookup stashes
# a github repo from references; image_resolve's no_image path hands it to the
# agent as a source_build_candidate (the give_up(no_image)-without-source_build
# class, e.g. CVE-2022-1813).
# =============================================================================

def test_extract_github_repo_canonical() -> None:
    from cve_env.agent.tools import _extract_github_repo

    assert (
        _extract_github_repo(
            {"references": [{"url": "https://github.com/yogeshojha/rengine/issues/1"}]}
        )
        == "https://github.com/yogeshojha/rengine"
    )
    assert (
        _extract_github_repo({"references": ["https://github.com/o/r.git"]})
        == "https://github.com/o/r"
    )
    # advisory/non-repo github paths skipped; no-github → ""
    assert (
        _extract_github_repo(
            {"references": [{"url": "https://github.com/advisories/GHSA-xxxx"}]}
        )
        == ""
    )
    assert (
        _extract_github_repo({"references": [{"url": "https://example.com/x"}]}) == ""
    )

@patch("cve_env.agent.tools._nvd_lookup.nvd_lookup_payload")
def test_nvd_lookup_stashes_github_repo(mock_payload: Any) -> None:
    import cve_env.agent.tools as tools

    reset_nvd_lookup_state()
    mock_payload.return_value = {
        "ok": True,
        "cve_id": "CVE-2022-1813",
        "references": [{"url": "https://github.com/owner/proj/releases"}],
    }
    _call({"cve_id": "CVE-2022-1813"})
    assert tools._LAST_CVE_GITHUB_REPO == "https://github.com/owner/proj"
    reset_nvd_lookup_state()
    assert tools._LAST_CVE_GITHUB_REPO == ""

def test_extract_github_repo_references_urls_alt_schema() -> None:
    """Golden: lock the shared URL-extraction branches before Pass C extracts
    a `_reference_urls` helper. Covers the `references_urls` alt schema (line
    248), the schemeless-url skip (251), and the <2-path-segments case."""
    from cve_env.agent.tools import _extract_github_repo

    # alt schema: references_urls is a list[str] (not references[].url)
    assert (
        _extract_github_repo(
            {"references_urls": ["https://github.com/acme/widget/blob/main/x"]}
        )
        == "https://github.com/acme/widget"
    )
    # schemeless ref is skipped (no "://")
    assert _extract_github_repo({"references": ["github.com/acme/widget"]}) == ""
    # single path segment is not a repo
    assert (
        _extract_github_repo({"references": [{"url": "https://github.com/owneronly"}]})
        == ""
    )

@patch("cve_env.agent.tools._image_resolve.image_resolve_to_payload")
def test_image_resolve_no_image_with_repo_yields_source_build_candidate(
    mock_ir: Any,
) -> None:
    import asyncio
    import json

    import cve_env.agent.tools as tools

    reset_nvd_lookup_state()
    tools._LAST_CVE_GITHUB_REPO = "https://github.com/owner/proj"  # noqa: SLF001
    mock_ir.return_value = {"ok": True, "decision": "not_found", "image_ref": ""}
    env = asyncio.run(
        tools.image_resolve.handler({"product": "proj", "version": "1.0"})
    )
    out = json.loads(env["content"][0]["text"])
    assert out.get("source_build_candidate") == "https://github.com/owner/proj"
    assert "source_build" in out.get("next_step_hint", "")
    reset_nvd_lookup_state()

@patch("cve_env.agent.tools._image_resolve.image_resolve_to_payload")
def test_image_resolve_no_image_no_repo_no_candidate(mock_ir: Any) -> None:
    import asyncio
    import json

    import cve_env.agent.tools as tools

    reset_nvd_lookup_state()  # no repo stashed
    mock_ir.return_value = {"ok": True, "decision": "not_found", "image_ref": ""}
    env = asyncio.run(
        tools.image_resolve.handler({"product": "proj", "version": "1.0"})
    )
    out = json.loads(env["content"][0]["text"])
    assert "source_build_candidate" not in out

@patch("cve_env.agent.tools._image_resolve.image_resolve_to_payload")
def test_image_resolve_found_image_no_candidate(mock_ir: Any) -> None:
    import asyncio
    import json

    import cve_env.agent.tools as tools

    reset_nvd_lookup_state()
    tools._LAST_CVE_GITHUB_REPO = "https://github.com/owner/proj"  # noqa: SLF001
    mock_ir.return_value = {"ok": True, "decision": "native", "image_ref": "redis:6.2"}
    env = asyncio.run(
        tools.image_resolve.handler({"product": "redis", "version": "6.2"})
    )
    out = json.loads(env["content"][0]["text"])
    assert "source_build_candidate" not in out
    reset_nvd_lookup_state()
