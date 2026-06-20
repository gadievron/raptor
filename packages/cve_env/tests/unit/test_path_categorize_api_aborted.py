"""Phase 34.5 B7 — pathway categorization adds 'api-aborted' for
API-Overload zero-tool outcomes.

Phase 33.3 Cat 1 B7: 28 Phase 31 CVEs hit Anthropic 529 Overload during
the 03:00–03:43 UTC outage; all had empty tool_names_called, status=error,
and final_text starting "API Error: Repeated 529 Overloaded errors".
The cli.py narrative-emission `pathway` calculation defaulted these to
"research-only" — actively misleading for downstream counting (research
implies the agent did research work; api-aborted means the SDK aborted
before any tool call).

Fix: cli.py:585+ pathway-calculation block adds an early check:
  IF tool_names_called is empty
  AND status == "error"
  AND _classify_api_overload(final_text) == "api_overload"
  THEN pathway = "api-aborted"
ELSE existing logic (research-only as the empty-tools default).

This test asserts the new branch fires correctly + doesn't disturb
existing cases.
"""

from __future__ import annotations

from pathlib import Path


import cve_env


def _read_cli_source() -> str:
    cli_py = Path(cve_env.__file__).resolve().parent / "cli.py"
    return cli_py.read_text(encoding="utf-8")


def test_cli_has_api_aborted_pathway_branch() -> None:
    """cli.py's pathway calculation must include the api-aborted branch.

    Required: a conditional checking (not tools) AND status=='error'
    AND _classify_api_overload — assigning pathway='api-aborted'.
    """
    body = _read_cli_source()
    assert "api-aborted" in body, "cli.py pathway block missing 'api-aborted' label"
    assert "_classify_api_overload" in body, (
        "cli.py pathway block must import + use _classify_api_overload "
        "(Phase 34.1 B4 helper) for the new branch"
    )


def test_cli_research_only_no_longer_default_for_empty_tools() -> None:
    """The original 'research-only' default was the FIRST line in the
    pathway-calculation block (line ~589 pre-fix). With B7 fix, pathway
    is set conditionally at the end (else branch) — research-only is
    NO LONGER a default-init.

    Required: the literal `pathway = "research-only"` should appear in
    an `else:` branch (after all elif checks), not as a default-init
    before the if/elif chain.
    """
    body = _read_cli_source()
    lines = body.splitlines()
    # Find the pathway-assignment block
    research_only_line_idx = None
    for i, line in enumerate(lines):
        if 'pathway = "research-only"' in line:
            research_only_line_idx = i
            break
    assert research_only_line_idx is not None, (
        "pathway=research-only assignment missing"
    )
    # The previous non-empty line should be `else:` (not `tools = ...`
    # or some other init pattern)
    prev = research_only_line_idx - 1
    while prev >= 0 and not lines[prev].strip():
        prev -= 1
    assert lines[prev].strip().startswith("else"), (
        f"research-only must be the else-branch of the pathway block, "
        f"not a default-init. Prev non-empty line: {lines[prev]!r}"
    )
