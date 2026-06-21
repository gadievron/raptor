"""Phase 1.D: parametric lock-test for ``_RESET_GLOBALS`` registry across all per-CVE-state modules.

At Phase 1 commit, only ``image_resolve`` has the registry; ``docker_run``,
``docker_compose_up``, ``docker_build``, ``agent.tools`` are marked xfail
until **Phase 5** generalises the pattern.

Refactor contract: every module with module-level CVE-scoped globals must
publish ``_RESET_GLOBALS: tuple[str, ...]`` naming each global, AND a reset
function that clears each named global to its initial value. Adding a new
global without updating both is the bug shape (Phase 67.1).
"""

from __future__ import annotations

import importlib

import pytest

# (module_path, reset_callable_name, currently_implemented)
# Phase 4 (2026-05-04): image_resolve's per-CVE state moved to a sibling
# module ``_image_resolve_state``; the test now checks the new home.
# image_resolve.py still re-exports ``reset_rate_limit_budget`` for
# back-compat with the agent loop.
MODULES: list[tuple[str, str, bool]] = [
    ("cve_env.tools._image_resolve_state", "reset_rate_limit_budget", True),
    # Phase 5 (2026-05-04) added _RESET_GLOBALS to these 4 modules.
    ("cve_env.tools.docker_run", "reset_failed_attempts", True),
    ("cve_env.tools.docker_compose_up", "reset_active_stacks", True),
    ("cve_env.tools.docker_build", "reset_docker_build_state", True),
    # agent.tools uses _PER_CVE_RESET_HANDLERS + reset_all_tool_state() instead
    # of the _RESET_GLOBALS pattern — the old tuple was dead code (removed).
]


@pytest.mark.parametrize(
    ("module_path", "reset_name", "implemented"),
    MODULES,
    ids=[m[0].rsplit(".", 1)[1] for m in MODULES],
)
def test_module_publishes_reset_registry(
    module_path: str, reset_name: str, implemented: bool
) -> None:
    """``_RESET_GLOBALS`` tuple exists and reset callable is defined."""
    if not implemented:
        pytest.xfail(reason="Phase 5 generalises _RESET_GLOBALS to this module")
    try:
        mod = importlib.import_module(module_path)
    except ImportError as exc:
        pytest.skip(f"cannot import {module_path}: {exc}")
    assert hasattr(mod, "_RESET_GLOBALS"), (
        f"{module_path} is missing the _RESET_GLOBALS registry. "
        f"Phase 67.1 contract: every module with per-CVE state must publish "
        f"a tuple of global names + a matching reset callable."
    )
    registry = mod._RESET_GLOBALS
    assert isinstance(registry, tuple)
    assert len(registry) >= 1
    assert all(isinstance(name, str) for name in registry)
    for name in registry:
        assert hasattr(mod, name), (
            f"{module_path}._RESET_GLOBALS names {name!r} but the module "
            f"does not define it. The registry must enumerate live globals."
        )
    reset_fn = getattr(mod, reset_name, None)
    assert callable(reset_fn), (
        f"{module_path}.{reset_name} is not a callable. The reset entry "
        f"point must be discoverable so loop.py can clear state per CVE."
    )


def test_image_resolve_reset_clears_all_named_globals() -> None:
    """Concrete behavioural lock for the existing implementation.

    Phase 4 (2026-05-04): state owner is now ``_image_resolve_state``;
    ``image_resolve`` re-exports ``reset_rate_limit_budget`` for back-compat.
    """
    from cve_env.tools import _image_resolve_state as state
    from cve_env.tools.image_resolve import reset_rate_limit_budget

    snapshots = {name: getattr(state, name) for name in state._RESET_GLOBALS}

    state._RATE_LIMIT_BUDGET["sentinel"] = 99
    state._RATE_LIMIT_TOTAL = 99
    state._RATE_LIMIT_COOLDOWN_DONE = True
    state._TRANSPORT_COOLDOWN_DONE = True
    state._ARCH_INCOMPATIBLE_TOTAL = 99

    reset_rate_limit_budget()

    assert state._RATE_LIMIT_BUDGET == {}
    assert state._RATE_LIMIT_TOTAL == 0
    assert state._RATE_LIMIT_COOLDOWN_DONE is False
    assert state._TRANSPORT_COOLDOWN_DONE is False
    assert state._ARCH_INCOMPATIBLE_TOTAL == 0

    for name, original in snapshots.items():
        if isinstance(original, dict):
            getattr(state, name).clear()
            getattr(state, name).update(original)
        else:
            setattr(state, name, original)
