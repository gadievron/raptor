"""Stage 3E-a — image_resolve aggregate per-call budget (RED test).

behavioral-audit-2026-05-27.md F3 (judge-verified): a single image_resolve call
can run ~1430s — 10 candidates x ~70s (inspect + backoff + inspect) + a 30s
cooldown re-probe of all 10 — which alone approaches the 1440s bench wall. The
3A connectivity breaker does NOT cover this: image_resolve IS an MCP tool, so it
is tool-in-flight and the breaker is suppressed for its whole duration.

Fix: a monotonic per-call deadline (CVE_ENV_IMAGE_RESOLVE_BUDGET_S, default 600s)
checked before each probe and before each cooldown re-probe; on breach, stop
probing and return with the existing rate_limited/not_found pivot hint.

RED until the budget exists: with slow probes and a tiny budget, image_resolve
must stop EARLY (well under the time it would take to probe all candidates +
cooldown retry), not run the full cascade.
"""

from __future__ import annotations

import time
from typing import Any

from cve_env.tools import _image_resolve_state as _state
from cve_env.tools import image_resolve as ir


def _slow_miss(_cand: str) -> tuple[None, str]:
    """A probe that takes real wall-time and always misses (rate-limited)."""
    # Real time.sleep -- test relies on wall-clock. May be flaky under heavy
    # CI load. The 1.5s assertion has ~10x headroom over the 0.15s sleep.
    time.sleep(0.15)
    return (None, "rate_limited")


def test_image_resolve_enforces_per_call_budget(monkeypatch: Any) -> None:
    """With a 0.45s budget and ~0.15s/probe, image_resolve must abort the
    cascade early (a handful of probes), not run all 10 candidates + the 30s
    cooldown re-probe of another 10.
    """
    _state.reset_rate_limit_budget()
    monkeypatch.setenv("CVE_ENV_IMAGE_RESOLVE_BUDGET_S", "0.45")
    monkeypatch.setattr(ir, "_inspect_ref", _slow_miss)
    # Make the cooldown sleeps instant so RED reflects PROBE time, not the 30s
    # wait (and so the committed test is fast); the budget uses real monotonic.
    monkeypatch.setattr(_state, "_RATE_LIMIT_COOLDOWN_S", 0)
    monkeypatch.setattr(_state, "_TRANSPORT_COOLDOWN_S", 0)

    start = time.monotonic()
    res = ir.image_resolve(product="testprod", version="1.0", host_arch="amd64")
    elapsed = time.monotonic() - start

    assert not res.ok
    assert elapsed < 1.5, (
        f"image_resolve ran {elapsed:.2f}s on slow probes — the per-call budget "
        f"(CVE_ENV_IMAGE_RESOLVE_BUDGET_S=0.45) did not stop the cascade "
        f"(it probed all candidates + the cooldown re-probe). F3 wall-hang."
    )
    assert len(res.candidates_tried) < 8, (
        f"probed {len(res.candidates_tried)} candidates — budget should have cut "
        f"the cascade short well before all 10 (+10 cooldown retry)."
    )
