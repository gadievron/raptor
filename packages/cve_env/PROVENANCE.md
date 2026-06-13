# Provenance

This package was imported from the standalone repository **gadievron/cve-env**.

- Source: `gadievron/cve-env` @ `ba9f91c` ("Initial release: cve-env — agentic CVE → Docker environment builder")
- Imported: 2026-06-12
- Layout change on import: `src/cve_env/` → `packages/cve_env/cve_env/` (flat package, mirroring `packages/cve_diff/`). All `cve_env.*` imports are absolute and unchanged.
- Not copied: `pyproject.toml`, `uv.lock`, virtualenvs, caches, `cve-env.toml.example`. Dependencies are declared in the repo-root `requirements.txt` per raptor's "no per-package build config" convention.

Phase 1 of the integration is a behavior-preserving lift-and-shift: cve-env keeps its own agent loop (claude-agent-sdk), Docker tooling, dockerfile generation, config, and HTTP layer. It adopts **zero** raptor `core/` modules in this phase. Selective `core/` adoption is deferred to a later phase behind behavior-equivalence checks.

## Divergences from the imported snapshot

The vendored copy tracks upstream `gadievron/cve-env` with cherry-picked fixes applied on top of the `ba9f91c` snapshot:

- **Cost-floor on interrupted exits** (this PR) — ports upstream cve-env `89917d8` (PR #2): floors `total_cost_usd` by engine turn count when a build ends on an interrupted status with no token usage (the Claude Code session-auth case), so interrupted runs no longer log ~$0. Files: `cve_env/config.py` (`estimate_cost_from_turns`), `cve_env/agent/loop.py` (`_floor_cost` + `_INTERRUPTED_EXIT_STATUSES`), `tests/unit/test_cost_floor_non_clean_exit.py`.
