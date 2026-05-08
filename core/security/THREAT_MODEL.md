# RAPTOR Threat Model — LLM consumers and target source

## Scope

This document codifies the security invariants that govern any code path
where a RAPTOR component reads target source code via an LLM, dispatches a
Claude Code sub-agent, or feeds LLM-derived artefacts to downstream
consumers. It does NOT cover deterministic analysis (Semgrep, CodeQL, AST
walkers) — those have their own threat profile.

Codified here so future code reviews can validate against it without
re-deriving the model from scratch.

## Invariants

### I1. No source-trust gate

> No code path makes a security decision based on a "this repo is
> trusted" claim about *target source*. Every target is treated as
> adversarial source.

The gate that *does* exist (`core.security.cc_trust.check_repo_claude_trust`)
checks for **config-file poisoning** — a target's `.claude/settings.json`,
`.claude/settings.local.json`, or `.mcp.json` containing dangerous fields
(apiKeyHelper, hooks, env overrides, dangerous env vars, stdio MCP servers).
That's a different threat from "the source code might prompt-inject the
LLM". I1 says we don't gate on the source-content threat at all — the
defence comes from I2 + I3, not from refusing to dispatch.

### I2. Defence comes from sandbox bounds + output treatment

#### I2-(a). Kernel-level sandbox bounds tool effects.

The `core.sandbox` stack composes three filesystem-isolation layers:

1. **mount namespace** (when available) — bind-mounts a fresh
   read-only rootfs containing only system dirs (`/usr`, `/lib`,
   `/etc`, `/bin`, `/sbin`, `/dev`, `/proc`, `/sys`) plus the
   caller-supplied `target=` and `output=` paths. `$HOME` is NOT
   bind-mounted; from inside the sandbox, paths under `/home/...`
   simply do not exist (ENOENT).
2. **user namespace** with UID remapping — same-UID processes on
   the host (e.g., other things this operator is running) become
   different UIDs from the sandbox's perspective. `/proc/<host_pid>/`
   reads return EACCES.
3. **Landlock** — file-system access control list. With
   `restrict_reads=True`, denies reads outside an explicit allowlist
   (system dirs + target + output + caller-supplied `readable_paths`).
   With `restrict_reads=False` (the historic default), only writes
   are restricted; reads are allowed everywhere visible.

**Critical fallback property** — `mount namespace` engagement requires
unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=0`).
On Ubuntu 24.04+, hardened containers, and similar host configurations
this sysctl is `=1` by default, so mount-ns is unavailable. Operators
without sudo cannot change this. In that case the sandbox falls back to
**Landlock-only mode**:

| Threat | mount-ns active | Landlock-only mode |
|---|---|---|
| Read `~/.aws/credentials` etc. | path doesn't exist (ENOENT) | readable unless `restrict_reads=True` |
| Read `/proc/<host_pid>/environ` | UID-remap → EACCES | readable to same-UID processes |
| Read `/tmp/<other_app_file>` | private /tmp inside sandbox | shared with host |

**Therefore: in Landlock-only mode, `restrict_reads=True` is the
load-bearing defence**, not defence-in-depth. Callsites that dispatch
LLM-driven sub-agents on hostile source must set it explicitly.
`run_untrusted()` and `run_untrusted_networked()` set `restrict_reads=True`
by default for this reason; ad-hoc `sandbox_run()` callers do not.

#### I2-(b). Downstream consumers treat LLM-derived artefacts as adversarial.

A prompt-injected LLM can produce a structurally-valid JSON output that
is semantically poisoned: hidden entry points, fake sinks, mislabelled
trust boundaries, misranked attack surface. The kernel sandbox cannot
prevent this — the LLM's own response is the channel.

Consumers of LLM-derived artefacts (`context-map.json`, `flow-trace-*.json`,
finding analyses, exploit/patch suggestions) must NOT treat them as
authoritative. Specific obligations:

- `/validate` Stage 0 importing context-map.json: do not trust entry-point
  / sink claims unverified; cross-check against deterministic analysis.
- Operator-facing reports: no auto-execution / no auto-merging of
  LLM-suggested patches.
- `/agentic` enrichment: weight LLM hot-spots against deterministic
  scanner findings; do not let the LLM-derived ranking override.
- `/exploit` / `/patch` outputs: treat as draft; require operator
  approval before any privileged action.

This invariant is currently **partially satisfied across the codebase.**
Per-consumer hardening is its own line of work.

### I3. cc_trust narrowed to config-file poisoning

`check_repo_claude_trust` blocks `.claude/settings.json`,
`.claude/settings.local.json`, `.mcp.json` patterns that would override
the sub-agent's hooks, tool list, env, or load malicious MCP servers.
**This is a different threat from source-level prompt injection** and
the gate stays in place for it. Source-level adversarial intent is
addressed by I2, not by cc_trust.

The `--trust-repo` CLI flag overrides cc_trust for operators who have
manually verified a target. It does NOT relax I2; LLM-driven sandboxes
still treat source as adversarial.

## Common confusions

### "Landlock default is read-everywhere → sandbox is leaky"

Misreads the layering. Landlock alone is read-everywhere by default,
but it's not deployed alone. When mount-ns is active, the child's view
of the filesystem is restricted *before* Landlock runs — paths outside
the bind-mount set don't exist, regardless of Landlock policy. The
"leaky" claim only holds in Landlock-only mode (mount-ns unavailable).

### "We can require the operator to enable userns"

We cannot. Operators without sudo on shared hosts, hardened CI
runners, locked-down enterprise machines cannot flip the sysctl.
The design must assume mount-ns may be unavailable.

### "cc_trust gates source-level prompt injection"

It does not. cc_trust gates config-file poisoning. Source-level
prompt injection is bounded by sandbox + output-handling per I2.

## Cross-references

- `core/sandbox/context.py` — sandbox implementation
- `core/security/cc_trust.py` — config-file-poisoning gate (I3)
- `core/security/prompt_envelope.py` — input-side anti-prompt-injection (related but not the source-level defence)
- `project_credential_isolation.md` — adjacent initiative on subprocess-credential exfil
- `project_sandbox_enhancements.md` — adjacent initiative tracking

## Open work

Tracked separately, not blocking I1/I2/I3:
- Per-call-site `restrict_reads=True` migration for ad-hoc `sandbox_run` consumers (per-toolchain audits required for build-tool callers).
- Per-consumer output-handling hardening to satisfy I2-(b).
- /validate Bash discipline (typed validation-helper enum instead of generic Bash).
