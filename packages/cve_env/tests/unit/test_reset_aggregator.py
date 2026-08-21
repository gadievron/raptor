"""W1-4 (2026-06-02 review): per-CVE tool-state reset aggregator.

build() reset 5 per-CVE tool module states via hand-wired calls
(reset_failed_attempts / reset_active_stacks / reset_rate_limit_budget /
reset_nvd_lookup_state / reset_docker_build_state). A new tool's reset was easy to
forget. This locks a single registry-driven ``reset_all_tool_state()`` so the set
is in one place. RED until the aggregator + registry exist.
"""

from __future__ import annotations

from typing import Any


def test_reset_all_tool_state_invokes_every_registered_handler(
    monkeypatch: Any,
) -> None:
    from cve_env.agent import tools as T

    seen: list[int] = []
    handlers = tuple(
        (lambda i=i: seen.append(i)) for i in range(len(T._PER_CVE_RESET_HANDLERS))
    )
    monkeypatch.setattr(T, "_PER_CVE_RESET_HANDLERS", handlers)
    T.reset_all_tool_state()
    assert sorted(seen) == list(range(len(handlers))), "every registered reset must run"


def test_reset_registry_contains_all_five_resets() -> None:
    from cve_env.agent import tools as T
    from cve_env.tools.docker_build import reset_docker_build_state
    from cve_env.tools.docker_compose_up import reset_active_stacks
    from cve_env.tools.docker_run import reset_failed_attempts
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    reg = T._PER_CVE_RESET_HANDLERS
    for fn in (
        reset_failed_attempts,
        reset_active_stacks,
        reset_rate_limit_budget,
        reset_docker_build_state,
        T.reset_nvd_lookup_state,
    ):
        assert fn in reg, f"{fn.__name__} missing from the per-CVE reset registry"
    assert len(reg) == 5
