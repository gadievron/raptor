---
description: Describe a target — language mix, build system, catalog match, target-specific tool gaps, cost estimate. Read-only; no commands executed.
dispatch: libexec/raptor-describe --target <path>
---

# /describe

Tell me what THIS target is. **Read-only**: /describe inspects the tree and prints a description. It never executes target code, never runs builds, never recommends operator-typed shell commands.

**Complementary to `/doctor`**: /doctor is the host-level diagnostic ("is RAPTOR set up on this machine"); /describe is the target-level pre-flight ("what is this target and what would RAPTOR do with it"). Operators typically run both at first contact with a new target: `/doctor` once per host, `/describe` per target.

## Usage

```
/describe <target>           Operator-facing text block
/describe <target> --json    Machine-readable JSON (for CI / dashboards)
```

If `<target>` is omitted, the active project's target is used (see CLAUDE.md DEFAULT TARGET DIRECTORY).

## Execute

When invoked, run:

```
libexec/raptor-describe --target <resolved_target> [--json]
```

Resolve `<resolved_target>` per CLAUDE.md (active project → `$RAPTOR_CALLER_DIR` → ask). Pass through `--json` if the operator supplied it.

## Example output

```
Target analysis:
  Languages: C++ (100%)
  Build system: autotools
  Size: ~74k LOC, 194 source files
  Detected type: c.userspace-daemon

Defaults for this target type:
  /scan baseline packs: security-audit, command-injection, owasp-top-ten
  /agentic preferred dirs: src/http, src/net, src/protocols, src/notification, src/api
  Pipeline: understand-map → scan-with-codeql → agentic-with-validate

Target-specific tool gaps:
  ⚠ CodeQL (2.23.8)              — DB build needs libtool for autotools build system
      hint: sudo apt install libtool
  ✓ Coccinelle (1.3)             — C rule pack applicable to target
  ⚠ Binary oracle                — no build artefacts found — will activate after build

Cost estimate (when running /agentic): $25-$50, 40-75 min

For host-level setup, run `raptor doctor`.
To start analysis, run `raptor.py agentic --repo <target>` (prints same estimate at start; runs sandboxed).
```

## What /describe does NOT do

- **No runnable commands.** /describe never recommends `./configure`, `make`, `apt install`, or any shell command the operator should type. A Makefile can do anything (`rm -rf /`, exfiltrate, format disk); recommending the operator type `make` against arbitrary target code is a security boundary RAPTOR doesn't cross.
- **No execution.** Description only. Target code is never invoked.
- **No host diagnostics.** Binary presence, API keys, env vars — all live in `/doctor`. /describe only checks target-specific signals (build deps for THIS build system, rule pack vs THIS language, etc.).

When RAPTOR needs to build the target (for /codeql's database, for /agentic's binary-oracle enrichment), it'll do so inside its own sandbox — not by telling you to type `make`.

## Substrate

`packages/describe/` — composes existing substrates:
- `core/run/target_types` (catalog-driven defaults; QoL #17)
- `core/run/estimator` (cost/time hints; QoL #21)
- `packages/codeql/language_detector` + `build_detector` (language + build-system inference)
- `core/build/recipe` (build-command construction — kept as future /codeql consumer; not invoked by /describe)
