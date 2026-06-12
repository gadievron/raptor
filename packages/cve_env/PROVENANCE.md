# Provenance

This package was imported from the standalone repository **gadievron/cve-env**.

- Source: `gadievron/cve-env` @ `ba9f91c` ("Initial release: cve-env — agentic CVE → Docker environment builder")
- Imported: 2026-06-12
- Layout change on import: `src/cve_env/` → `packages/cve_env/cve_env/` (flat package, mirroring `packages/cve_diff/`). All `cve_env.*` imports are absolute and unchanged.
- Not copied: `pyproject.toml`, `uv.lock`, virtualenvs, caches, `cve-env.toml.example`. Dependencies are declared in the repo-root `requirements.txt` per raptor's "no per-package build config" convention.

Phase 1 of the integration is a behavior-preserving lift-and-shift: cve-env keeps its own agent loop (claude-agent-sdk), Docker tooling, dockerfile generation, config, and HTTP layer. It adopts **zero** raptor `core/` modules in this phase. Selective `core/` adoption is deferred to a later phase behind behavior-equivalence checks.
