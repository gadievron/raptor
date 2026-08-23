"""Robustness tests for finding_id / crash_id sanitisation at output-
file write sites.

``_safe_id`` (packages/llm_analysis/cc_dispatch.py) is the shared
sanitiser for identifier-derived filenames. agent.py builds four output
paths from ``finding_id`` (validation / analysis / exploit / patch
files) and crash_agent.py builds three from ``crash_id`` (analysis /
exploit / exploit-response); all must route the identifier through
``_safe_id`` so a hostile id (path separators, NUL, traversal, over-long
SARIF rule URIs) can never steer the write location or crash the write.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# packages/llm_analysis/tests/... → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from packages.llm_analysis.cc_dispatch import _safe_id

# ----------------------------------------------------------------------
# _safe_id behaviour
# ----------------------------------------------------------------------


def test_identity_for_already_safe_ids():
    """Filenames for well-formed ids must not change — _safe_id is the
    identity for [A-Za-z0-9._-]+ (without a literal ``..`` run) within
    the length cap."""
    for fid in (
        "finding-1",
        "CWE_787.rule-3",
        "semgrep.c.lang.security.insecure-use-strcpy-fn",
        "a" * 80,
        "x.y-z_9",
    ):
        assert _safe_id(fid) == fid


def test_path_separators_sanitised():
    out = _safe_id("../../etc/passwd")
    assert "/" not in out
    assert ".." not in out


def test_backslash_and_nul_sanitised():
    out = _safe_id("a\\b\x00c")
    assert "\\" not in out
    assert "\x00" not in out


def test_long_id_capped_with_disambiguating_suffix():
    a = _safe_id("prefix-" + "a" * 200 + "-tail1")
    b = _safe_id("prefix-" + "a" * 200 + "-tail2")
    assert len(a) <= 80
    assert len(b) <= 80
    # Ids differing only past the cap must not collide.
    assert a != b


def test_empty_id_falls_back_to_unknown():
    assert _safe_id("") == "unknown"
    assert _safe_id("   ") == "unknown"


# ----------------------------------------------------------------------
# Write sites route the identifier through _safe_id
# ----------------------------------------------------------------------


def _f_string_id_interpolations(source: str, ident: str) -> list[str]:
    """Return f-string interpolations of ``ident`` used to build output
    filenames, e.g. ``f"{vuln.finding_id}_patch.md"``."""
    return re.findall(
        rf'f"[^"]*\{{[^{{}}"]*\b{ident}[^{{}}"]*\}}[^"]*\.(?:json|cpp|md|txt)"',
        source,
    )


def test_agent_write_sites_use_safe_id():
    source = (REPO / "packages/llm_analysis/agent.py").read_text()
    sites = _f_string_id_interpolations(source, "finding_id")
    assert sites, "expected finding_id-derived output filenames in agent.py"
    for site in sites:
        assert "_safe_id(" in site, f"raw finding_id in filename: {site!r}"


def test_crash_agent_write_sites_use_safe_id():
    source = (REPO / "packages/llm_analysis/crash_agent.py").read_text()
    sites = _f_string_id_interpolations(source, "crash_id")
    assert sites, "expected crash_id-derived output filenames in crash_agent.py"
    for site in sites:
        assert "_safe_id(" in site, f"raw crash_id in filename: {site!r}"
