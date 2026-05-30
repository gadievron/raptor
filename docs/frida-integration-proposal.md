# Frida integration - design proposal (v2)

**Status:** Proposal · **Audience:** @Splinters-io (+ @grokjc / @gadievron) · **Author:** @ZephrFish (collaborator)
**Context:** PR #57 was closed with the author's note "we might have to trash this one." PR #496 (`raptor doctor`) cherry-picked the self-check shape from #57 cleanly. Frida itself is unowned upstream; this doc proposes how a v2 lands without re-creating #57's scope problems.

This is a **proposal**, not a finished design. Where the right call is unclear it's marked **OPEN**. Edit freely.

---

## Goals

1. **Dynamic confirmation of LLM-flagged sinks.** RAPTOR's biggest signal-loss happens when the LLM marks a finding `is_exploitable: true` for a sink that never executes at runtime. Frida is the substrate that closes that gap.
2. **Native macOS dynamic analysis.** `rr` only exists on Linux; macOS users today have no equivalent for `/crash-analysis` or function tracing. Frida fills it.
3. **Mobile / remote targets.** SSL pinning bypass, API tracing, secret hunting in mobile apps and embedded Linux - first-class targets, not afterthoughts.
4. **No vendored binaries.** Frida is large and architecture-specific; require the operator to install `frida-tools` (host) and `frida-server` (target). `raptor doctor` reports availability.

## Non-goals (v1)

- Replacing `rr` or AFL++ - Frida is complementary, not a substitute.
- Building an LLM-driven autonomous instrumentation loop on day one. (#57's `autonomous.py` was 732 lines of agent code that didn't integrate with `raptor_agentic`'s dispatch; v2 should reuse `core/orchestration/` infrastructure.)
- Vendoring or shipping Frida binaries.

---

## What to lift from PR #57 (with attribution)

| File | Verdict | Why |
|------|---------|-----|
| `packages/frida/templates/api-trace.js` | **Keep, light revision** | General-purpose, the most-used hook pattern. |
| `packages/frida/templates/ssl-unpin.js` | **Keep** | Mobile pinning bypass is table stakes. |
| `packages/frida/templates/memory-scan.js` | **Keep** | Useful with `/validate --runtime` confirming a "secret leaks" finding. |
| `packages/frida/templates/crypto-trace.js` | **Keep** | Detects weak-crypto findings dynamically. |
| `packages/frida/templates/anti-debug.js` | **Keep, gate behind `--unsafe-attach`** | Useful but easy to misuse. |
| `packages/frida/templates/binary-environment.js` | **OPEN** | Overlap with the existing `core/binary/` substrate (cap-fingerprinting in PR #545). Decide whether to keep or fold into core/binary. |
| `packages/frida/scanner.py` | **Rewrite small** | Good shape; doesn't use `libexec/raptor-run-lifecycle` or active-project resolution. |
| `packages/frida/autonomous.py` (732 lines) | **Defer** | Replace with `core/orchestration/agentic_passes.py`-style integration into `/agentic` and `/validate`. Don't ship an independent agent loop. |
| `packages/frida/interactive.py` | **Defer / drop** | Frida already has a REPL (`frida -p PID`); a RAPTOR-flavoured REPL is low value vs. the cost of maintaining a TTY-aware Python loop. |
| `packages/frida/methodology.py` | **Fold into SKILL.md** | Prose belongs in the skill doc, not Python. |
| `packages/frida/platform.py` | **Keep, simplify** | Platform detection is fine; cut the Windows/iOS branches you don't test. |
| `packages/frida/binary_context_analyzer.py` | **OPEN** | Possibly redundant with `packages/exploit_feasibility/` - review for overlap. |
| `docs/frida/SETUP_*.md` | **Keep** | Setup docs per platform are useful as-is. |
| `docs/frida/FRIDA_INTEGRATION.md`, `INTEGRATION_ARCHITECTURE.md`, `QUICKSTART.md` | **Rewrite** to match v2 shape | Originals assume `raptor-cli`, hardcoded paths. |

**Lift mechanism:** When v2 lands, the JS templates carry `// Originally authored by @Splinters-io (PR #57)` headers; Python files credit in commit body. No silent reuse.

---

## v2 architecture - fits current RAPTOR conventions

Follows the pattern proven by `raptor doctor` (PR #496): a thin shell entry, a Python module, a slash-command skill, and `libexec/` orchestration with lifecycle management.

```
bin/raptor frida ...                # shell route, no claude required
  → libexec/raptor-frida             # lifecycle: raptor-run-lifecycle start/complete/fail
      → python3 -m core.dynamic.frida.cli ...

raptor.py mode "frida"               # internal dispatch (libexec wrapper calls this)

.claude/skills/frida/SKILL.md        # /frida slash command, documents templates + workflow

core/dynamic/frida/                  # the substrate
  __init__.py
  cli.py                             # argparse + dispatch
  runner.py                          # spawn / attach / remote, event capture, output
  templates/                         # JS templates lifted from #57
    api-trace.js
    ssl-unpin.js
    memory-scan.js
    crypto-trace.js
    anti-debug.js
  platform.py                        # platform detection (simplified)
  tests/
    test_runner.py                   # unit tests with mocked frida.core
    test_cli.py
    fixtures/

core/config/__init__.py              # add "frida" to RaptorConfig.TOOL_DEPS
core/startup/init.py                 # check_tools picks it up automatically

docs/frida/                          # operator-facing docs (lifted from #57, revised)
  QUICKSTART.md
  SETUP_MACOS.md
  SETUP_LINUX.md
  SETUP_ANDROID.md
  SETUP_IOS.md
  SETUP_WINDOWS.md                   # OPEN - only if you actually test on Windows
```

**Output layout** (lifecycle-managed):
```
out/projects/<project>/frida-<timestamp>/      # if active project
out/frida_<timestamp>/                         # otherwise

  events.jsonl                                 # one JSON event per line
  frida-report.md                              # operator summary
  metadata.json                                # target, template, host, duration
  script.js                                    # the actual script that ran (template or user)
  annotations/                                 # per-function annotations if integrated with /annotate
```

---

## CLI surface (v1)

```
raptor frida --target <pid|name|bundle-id|binary> [--template <name> | --script <path>]
             [--host <ip>[:port]] [--duration <seconds>] [--spawn] [--unsafe-attach]
```

- `--target` accepts:
  - integer PID
  - process name (e.g. `Safari`)
  - bundle ID (iOS/Android, requires `--host` or USB device)
  - filesystem path (implies `--spawn`)
- `--template <name>` - one of the curated templates above.
- `--script <path>` - operator-supplied JS file.
- `--host <ip>[:port]` - connect to a remote `frida-server` (default port 27042).
- `--duration <seconds>` - run for N seconds then detach cleanly (default: 60).
- `--spawn` - explicitly spawn-and-attach when `--target` is a binary path.
- `--unsafe-attach` - required for templates / modes that need PTRACE_ATTACH or `task_for_pid` on macOS. Off by default. Logs an audit line. The eventual sandbox envelope (see below) is bypassed when this is set.

**Examples:**
```bash
# Local: trace API calls in a process by name
raptor frida --target Safari --template api-trace --duration 30

# Mobile: bypass SSL pinning via USB device (spawn by bundle id)
raptor frida --target com.example.app --template ssl-unpin --usb --spawn --duration 120

# Remote frida-server on the LAN
raptor frida --target target-binary --template api-trace --host 10.10.20.1

# Spawn a local binary with a custom script
raptor frida --target ./vulnerable-bin --script ./my-hook.js --spawn
```

---

## Integration points with existing pipelines

The single most valuable bit isn't the standalone `/frida` command - it's the integration. Roadmap, post-v1:

### `/validate --runtime` (largest payoff)

`/validate` Stage C ("sanity check") today asks the LLM "does the code match? is the flow real? is it reachable?" - but "reachable" is inferred, not observed. With Frida:

- Stage C2 (new): for findings where the sink is a hookable function (open/exec/sql/etc.), launch a frida session, trigger the suspected attack path, observe whether the sink fires.
- Result: a `runtime_confirmed: true|false|unreachable` field per finding. Turns "LLM thinks this is exploitable" into "we watched the sink execute."

### `/crash-analysis` on macOS

`rr` is Linux-only. macOS users have no record-replay debugger; `/crash-analysis` is currently `gdb` + symbolicated cores. With Frida:

- `function-trace-generator-agent` gets a Frida backend on macOS (Linux still prefers `rr` for determinism).
- Output format matches the existing `function-tracing` skill - same downstream consumer.

### `/agentic` dynamic verification

Post-analysis, optional pass: for every finding where `is_exploitable: true` AND the binary is available, run a frida confirmation against the suspected sink. Mirrors the existing `--validate` flag pattern.

### `/exploit` PoC introspection

For generated PoCs, attach frida to the target during PoC execution and capture: leaked addresses, gadget hits, control-flow at the moment of corruption. Goes into the PoC report as evidence.

---

## Threat model - Frida + RAPTOR's sandbox

Frida-instrumented targets are **untrusted** by definition (we're analysing them to find bugs). The existing `core/sandbox/` substrate (Landlock + seccomp on Linux, seatbelt on macOS, egress allowlist via proxy) needs to extend to Frida sessions.

| Mode | Sandbox posture |
|------|-----------------|
| Spawn local binary with template | Run frida + target inside `run_untrusted_networked` envelope; egress allowlist; no `$HOME` access. |
| Attach to local PID | Same envelope; the PID must already be running outside our control, so we just observe. |
| Remote frida-server (`--host`) | The target's already remote; envelope still applies to local frida client process to constrain *its* egress. |
| `--unsafe-attach` | Bypasses sandbox; logs an audit line; required for system-process attach (PTRACE/task_for_pid). |

**OPEN:** Whether `frida-server` on the target host should be RAPTOR-managed (start/stop via SSH) or always operator-managed (we just connect). I lean operator-managed for v1 - RAPTOR-managed adds an SSH key and remote-exec surface that doesn't pay for itself yet.

---

## Doctor / banner signalling

Already wired in this proposal's accompanying patch:

```python
# core/config/__init__.py TOOL_DEPS
"frida":    {"binary": "frida",     "severity": "required", "affects": "/frida"},
```

`raptor doctor` and the SessionStart banner now show frida availability. `/frida` lists as "unavailable" when the binary is missing; lifecycle still creates the run dir + fails with a clear message rather than crashing on import.

---

## Phasing - three landable PRs

Don't repeat #57's mistake of one 18K-line bundled PR. Three reviewable chunks:

### PR 1 - Scaffolding (~600 LOC, lands first)

- `core/config/__init__.py`: add `frida` to TOOL_DEPS *(done in this proposal's patch)*
- `.claude/skills/frida/SKILL.md`: alpha stub *(done in this proposal's patch)*
- `docs/frida/QUICKSTART.md` + `SETUP_MACOS.md` + `SETUP_LINUX.md` (lifted, revised)
- 5 JS templates in `core/dynamic/frida/templates/` (lifted, with author-attribution headers)
- **No runner yet** - templates discoverable, no execution path.

### PR 2 - Runner + `/frida` command (~1500 LOC)

- `core/dynamic/frida/{cli,runner,platform}.py` + tests
- `libexec/raptor-frida` with lifecycle integration
- `bin/raptor frida` route + `raptor.py` mode entry
- Updates docs/frida/* to v2 shape
- Includes remote-host (`--host`) support out of the gate

### PR 3 - Pipeline integrations (~1000 LOC, may split further)

- `/validate --runtime` (Stage C2 with frida confirmation)
- `function-trace-generator-agent` macOS backend
- `/agentic` optional post-pass for dynamic verification

Autonomous LLM-guided mode (the old `autonomous.py`) is **not** in any of these PRs. If it ships later, it goes through `core/orchestration/` and dispatches like every other LLM pass.

---

## What's already done in this proposal's companion patch

The fork this proposal ships from already has:
- `core/config/__init__.py` TOOL_DEPS entry for `frida` ✅
- `.claude/skills/frida/SKILL.md` alpha stub ✅

Both are scoped to land cleanly as PR 1 above. The runner code is **not** written - that's PR 2 and warrants @Splinters-io's design hand because the dispatch model, output schema, and `--unsafe-attach` semantics are decisions worth aligning on first.

---

## Open questions

1. **Templates location**: `packages/frida/templates/` (PR #57's choice, treats Frida as a "package" alongside `packages/codeql/` etc.) vs. `core/dynamic/frida/templates/` (treats it as a runtime substrate alongside `core/sandbox/`). I lean `core/dynamic/` because Frida is dynamic-analysis infrastructure consumed by multiple commands, not a package with one CLI surface.
2. **`raptor frida` vs `/frida`**: keep both (CLI works without claude, skill works inside claude session, like `agentic`/`scan`), or skill-only? I lean keep-both - `raptor doctor` proved the value of claude-free entry points.
3. **Remote frida-server lifecycle**: operator-managed (recommended for v1) vs. RAPTOR-managed-via-SSH (later)?
4. **Schema for `events.jsonl`**: design now or let runner emit raw frida messages and add a schema layer once consumers (`/validate`, `function-trace-generator`) exist?
5. **eBPF**: separate proposal entirely, Linux-only, targets `/fuzz` and `/crash-analysis` syscall tracing. Don't bundle.

---

## Operational note from the field

While drafting this, I attempted `frida-ps -H 10.10.20.1` from a freshly installed `frida-tools 14.8.2` against a host with frida supposedly running. The host pinged (26ms RTT) but every common `frida-server` port (27042–27045, 1337, 8888) refused connection. Likely `frida-server` was bound to `127.0.0.1` rather than `0.0.0.0` - the default-bind on most server builds.

**Implication for SETUP_*.md:** the remote-frida-server install docs need a prominent "bind to 0.0.0.0 or use SSH-forward" callout. Add it to `SETUP_LINUX.md` and (when written) `SETUP_ANDROID.md` / `SETUP_IOS.md`.

---

## Decision asks for @Splinters-io

1. Confirm you're good with the **template attribution** model above (`// Originally authored by @Splinters-io (PR #57)` headers + commit-body credit).
2. **PR 1 ready to ship?** It's just the doctor wiring + skill stub + templates with attribution. Low risk, opens the door for PR 2.
3. **Templates location** - `packages/` vs. `core/dynamic/`? Either's fine; the answer constrains PR 1.
4. **Are you taking PR 2 yourself**, or would a collaboration shape (you on runner design + Splinters' templates / me on the boring lifecycle wiring + tests) work better?
5. **Anything in your in-progress rewrite** that should preempt this design? - if you've already moved past it, throw this away.
