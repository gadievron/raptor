# Provenance

This package was imported from the standalone repository **gadievron/cve-env**.

- Source: `gadievron/cve-env` @ `ba9f91c` ("Initial release: cve-env — agentic CVE → Docker environment builder")
- Imported: 2026-06-12
- Layout change on import: `src/cve_env/` → `packages/cve_env/cve_env/` (flat package, mirroring `packages/cve_diff/`). All `cve_env.*` imports are absolute and unchanged.
- Not copied: `pyproject.toml`, `uv.lock`, virtualenvs, caches, `cve-env.toml.example`. Dependencies are declared in the repo-root `requirements.txt` per raptor's "no per-package build config" convention.

Phase 1 of the integration is a behavior-preserving lift-and-shift: cve-env keeps its own agent loop (claude-agent-sdk), Docker tooling, dockerfile generation, config, and HTTP layer. It adopts **zero** raptor `core/` modules in this phase. Selective `core/` adoption is deferred to a later phase behind behavior-equivalence checks.

## Divergences from the imported snapshot

The vendored copy tracks upstream `gadievron/cve-env` with cherry-picked fixes applied on top of the `ba9f91c` snapshot:

- **Cost-floor on interrupted exits** (this PR) — ports upstream cve-env `89917d8` (PR #2): floors `total_cost_usd` by engine turn count when a build ends on an interrupted status, so interrupted runs no longer log ~$0. Files: `cve_env/config.py` (`estimate_cost_from_turns`), `cve_env/agent/loop.py` (`_floor_cost` + `_INTERRUPTED_EXIT_STATUSES`), `tests/unit/test_cost_floor_non_clean_exit.py`.
  - **Follow-up (same PR):** ports the upstream session-auth-stub fix — the floor was gated on `input_tokens == 0 and output_tokens == 0`, but Claude Code session auth emits a tiny *nonzero* token stub (`in=10, out=2`), so the gate never matched in production and the floor was dead code. The gate now keys on interrupted-status membership only (the floor is a `max()` bounded by the budget cap, so it only raises). Found by a live 6-CVE smoke (`CVE-2019-11043` turn_cap logged `$0.095` for 97 turns).
- **Token double-count on cumulative ResultMessage.usage** (this PR) — ports upstream cve-env PR #4 (merged `43731d5`): `state.total_*_tokens` accumulated from BOTH per-message `AssistantMessage.usage` AND the session-cumulative `ResultMessage.usage` (SDK `types.py` "Cumulative API usage for the session"), double-counting tokens ~2x. Fix: merge the cumulative RM usage via `max()` (new `_merge_cumulative_tokens`), keeping the per-message `_accum_tokens` += path. Benign for cost under session auth (the token estimate never wins `_floor_cost`'s `max()`); fixes telemetry / API-key over-report. Files: `cve_env/agent/loop.py` (`_merge_cumulative_tokens` + RM-site call), `tests/unit/test_token_double_count.py`. Validated by the 2026-06-14 token A/B bench (benign-equivalent to the remove-RM alternative).
