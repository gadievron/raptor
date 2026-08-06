"""Phase 1.D: lock the public-import surface so refactor moves preserve back-compat.

Phase 3 moves ``has_functional_smoke``, ``_ACTIVE_PROBE_TYPES``,
``_compute_verify_quality_warning`` from ``verify.py`` to ``_smoke.py``.
Phase 4 moves ``reset_rate_limit_budget`` + globals from ``image_resolve.py``
to ``_image_resolve_state.py``. Both phases ship re-exports so external
callers (loop.py, tests, ad-hoc scripts) keep working.

Anti-fragility contract #5 (public API stable): if any of these imports
breaks, refactor regressed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("claude_agent_sdk")

import importlib

_has_sdk = importlib.util.find_spec("claude_agent_sdk") is not None

# (module_path, attr_name)
PUBLIC_API: list[tuple[str, str]] = [
    # Phase 3 surface — must remain importable from verify.py post-extraction
    ("cve_env.tools.verify", "verify"),
    ("cve_env.tools.verify", "has_functional_smoke"),
    ("cve_env.tools.verify", "_ACTIVE_PROBE_TYPES"),
    ("cve_env.tools.verify", "_compute_verify_quality_warning"),
    # Phase 4 surface — must remain importable from image_resolve.py post-extraction
    ("cve_env.tools.image_resolve", "image_resolve"),
    ("cve_env.tools.image_resolve", "reset_rate_limit_budget"),
    # Other tool entry points (refactor scope adjacent — Phase 5 adds _RESET_GLOBALS here)
    ("cve_env.tools.docker_run", "reset_failed_attempts"),
    ("cve_env.tools.docker_compose_up", "reset_active_stacks"),
    ("cve_env.tools.docker_build", "reset_docker_build_state"),
    # Agent loop import path used in production
    ("cve_env.agent.loop", "_classify_verify_outcome"),
    ("cve_env.agent.loop", "_map_status"),
]

@pytest.mark.parametrize(("module_path", "attr_name"), PUBLIC_API)
def test_public_attr_importable(module_path: str, attr_name: str) -> None:
    """Each (module, attr) tuple must be importable end-to-end."""
    if "agent.loop" in module_path and not _has_sdk:
        pytest.skip("claude_agent_sdk not installed")
    mod = importlib.import_module(module_path)
    assert hasattr(mod, attr_name), (
        f"{module_path}.{attr_name} is not importable. "
        f"If a refactor moved it to a sibling module, ensure the original "
        f"location re-exports it (anti-fragility contract #5)."
    )
    obj = getattr(mod, attr_name)
    assert obj is not None
