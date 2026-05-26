"""Sandbox-integration smoke test.

Verifies that swapping ``default_client()`` from the bare
:class:`UrllibClient` to an :class:`EgressClient` (routed through
``core.sandbox.proxy``) is **transparent** to the pipeline — same
fixture, same options, same canned upstream responses must produce a
byte-identical ``findings.json``.

Approach: a single fixture, two runs.

  Run 1: ``http=StubHttp()`` populates a :class:`JsonCache` with every
         OSV / KEV / EPSS response the Tier A fixture exercises, and
         captures the findings as the baseline.

  Run 2: ``http=default_client()`` (an :class:`EgressClient` — actually
         constructed; the in-process proxy starts up) plus
         ``options.offline=True`` against the same warm cache. The
         pipeline never reaches the proxy because every lookup is a
         cache hit, but the EgressClient is fully wired into every
         ``OsvClient`` / ``KevClient`` / ``EpssClient`` and would have
         been used had the cache been cold. Findings must match.

What this test guarantees:

  - ``packages.sca.default_client()`` constructs without raising
    (the proxy singleton starts cleanly).
  - ``EgressClient`` is API-compatible with :class:`HttpClient`
    (passing it as ``http=...`` to ``run_sca`` does not break the
    pipeline).
  - The swap doesn't accidentally drop or alter any finding.

What it does NOT exercise (out of scope here):

  - Real proxy CONNECT round-trip — would need a localhost HTTPS
    stub or live api.osv.dev. Belongs in an integration job, not
    the unit test suite.
  - Off-allowlist refusal — covered by core/http/tests/test_egress_backend.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.json import JsonCache
from packages.sca import default_client
from packages.sca.pipeline import RunOptions, run_sca
from packages.sca.tests.test_tier_a_e2e import StubHttp, _build_fixture


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_egress_swap_is_transparent_to_findings(tmp_path: Path) -> None:
    """Run 1 with StubHttp warms the cache + captures baseline findings.
    Run 2 with default_client()+offline=True against the same cache
    must produce byte-identical findings."""

    target = tmp_path / "repo"
    _build_fixture(target)

    cache = JsonCache(root=tmp_path / "cache")

    # ------------------------------------------------------------------
    # Run 1: StubHttp populates cache and produces baseline findings.
    # ------------------------------------------------------------------
    out_a = tmp_path / "out_stub"
    result_a = run_sca(
        target=target, output_dir=out_a,
        options=RunOptions(enable_llm_review=False, enable_triage=False),
        http=StubHttp(), cache=cache,
    )
    baseline = _read_json(result_a.findings_path)

    # ------------------------------------------------------------------
    # Run 2: real default_client() (EgressClient) + offline=True.
    # The proxy spins up; cache hits short-circuit every network call.
    # ------------------------------------------------------------------
    out_b = tmp_path / "out_egress"
    egress = default_client()
    # Sanity: the swap did construct an EgressClient (not the bare
    # UrllibClient). If this regresses — e.g., the factory falls back
    # silently when a sandbox subsystem fails to import — the smoke
    # test should fail loudly here, not pass on an unrelated path.
    from core.http.egress_backend import EgressClient
    assert isinstance(egress, EgressClient), (
        f"default_client() must return EgressClient, got {type(egress).__name__}"
    )

    result_b = run_sca(
        target=target, output_dir=out_b,
        options=RunOptions(offline=True, enable_llm_review=False,
                           enable_triage=False),
        http=egress, cache=cache,
    )
    swapped = _read_json(result_b.findings_path)

    # ------------------------------------------------------------------
    # Byte-identical findings.json — the integration plan's contract.
    # ------------------------------------------------------------------
    if baseline != swapped:
        # Render a focused diff so a regression is obvious in CI logs.
        baseline_keys = {(r.get("vuln_type"), r.get("sca", {}).get("name"),
                           r.get("sca", {}).get("version"))
                          for r in baseline}
        swapped_keys = {(r.get("vuln_type"), r.get("sca", {}).get("name"),
                          r.get("sca", {}).get("version"))
                         for r in swapped}
        only_baseline = baseline_keys - swapped_keys
        only_swapped = swapped_keys - baseline_keys
        pytest.fail(
            "EgressClient swap altered findings:\n"
            f"  only in StubHttp run:    {sorted(only_baseline)}\n"
            f"  only in EgressClient run: {sorted(only_swapped)}"
        )
