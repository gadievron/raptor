# Troubleshooting

**Related documentation:**
[Sandbox](sandbox.md) |
[Dependencies](dependencies.md) |
[LLM Providers](llm.md) |
[Static Analysis](static-analysis.md)


## Self-test

After an install, upgrade, or environment change, run the smoke suite
before debugging individual commands:

```bash
libexec/raptor-self-test
```

The default tier makes **no LLM calls**: children run with a scrubbed
environment (API keys, dispatcher socket, Ollama, and the `claude` CLI
all hidden) plus an isolated `HOME`, so it never touches your real
`~/.raptor`, project registry, or caches.  Everything runs in a
temporary scratch directory that is deleted on success (kept on failure,
or with `--keep`).  It exercises the command surface end to end:
doctor, describe, scan, CodeQL scan-only, SCA, agentic (no-LLM paths),
fuzz plan-only, exploit feasibility, project and run lifecycle,
annotate, diagram, review, coverage, and the audit mechanical sweep.

Two opt-in tiers extend it:

| Flag | Adds |
|------|------|
| `--with-llm` | Budget-capped LLM runs (`/audit`, `/agentic` analysis, `/ask`); default total under ~$2, tunable with `--max-llm-cost` and `--model` |
| `--deep` | Long-running mechanical extras (binary-oracle end-to-end) |

Other useful flags: `--list` (show cases), `--only <substr>` (filter,
repeatable), `--json <file>` (machine-readable results),
`--timeout <seconds>` (per-case cap).  Exit codes: 0 all selected cases
passed or were skipped, 1 any failure, 2 usage error.  Run it from a
RAPTOR session (or with the libexec trust marker set, as for any
libexec script).


## Sandbox

### Exit code 3: sandbox cannot engage

The `SandboxSetupError` includes `reason` and `instructions` fields with
the specific fix. RAPTOR does not auto-degrade — if you can't fix the
underlying cause, downgrade explicitly: `--sandbox network-only` or
`--sandbox none`.

### Mount namespace on Ubuntu 24.04+

AppArmor blocks unprivileged user namespaces by default. Both are required:
```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
sudo apt install uidmap
```

### Tool binary invisible inside sandbox (exit code 127)

Tools installed outside the mount-namespace bind tree (`~/.local/bin/`,
`/opt/homebrew/bin/`) aren't visible. Pass `tool_paths=[<bin_dir>]` to the
sandbox call, or install the tool to a standard system path.


## Coccinelle

### Version too old (need >= 1.3)

Ubuntu 22.04 and 24.04 ship 1.1.1 via `apt`, which can't parse some rules.
Install from source:
```bash
git clone https://github.com/coccinelle/coccinelle.git
cd coccinelle && ./configure && make && sudo make install
```


## CodeQL

### "Failed to download pack" through sandbox

Allowlist these hosts in your egress proxy:
`ghcr.io`, `codeload.github.com`, `objects.githubusercontent.com`,
`pkg-containers.githubusercontent.com`.

### Build timeout with fingerprint sanitisation

Host fingerprint sanitisation caps at 4 CPUs, throttling parallel builds on
larger machines. Pass `cpu_count=HOST_CPU_COUNT` (value `-1`) to preserve
the real core count.

### "JDK not found" despite being installed

`get_safe_env()` strips `JAVA_HOME` by design. Install the JDK to a
standard location (`/usr/lib/jvm/`) so auto-detection finds it, or pass
the path explicitly.


## LLM providers

### Rate limiting (HTTP 429)

RAPTOR retries with backoff and halves concurrency automatically. If it
still exhausts, the run continues with the findings it has.

### Timed-out calls

Timeout-class failures are retried once by the client (per-call
`timeout_retry_cap`, default 1); orchestrators may layer one
reduced-context retry on top. Each call's disposition is recorded in
the run's `llm-telemetry.jsonl` with its `call_class`.

### Temperature rejected (Anthropic >= 4.7)

Anthropic dropped the `temperature` parameter for reasoning-tier models.
RAPTOR handles this automatically — if you hit it anyway, the model name
wasn't recognised. Check the model identifier in `models.json`.


## Semgrep

### Registry packs unreachable

A 3-second probe to `semgrep.dev:443` runs first. If it fails, registry
packs are dropped and only local rules run. For airgapped deployments,
pre-cache:
```bash
engine/semgrep/tools/cache-packs.py update
```

### Zero findings when findings expected

Semgrep scans git-tracked files only — check `git status` for untracked
files.


## Fuzzing

### macOS

macOS blocks AFL++'s fork server and shared memory. RAPTOR auto-routes
to the orchestrator path (libFuzzer / radare2-assisted) when AFL++ is
unusable, but for real AFL++ fuzzing use Linux.


## Validation pipeline

### Stage C hallucination

A file path doesn't exist or code doesn't match source. Stage C records
the failed sanity check on the finding (it does not change statuses);
Stage D then rules the finding out.

### Stage B stuck

After 5 attempts on a branch without progress, validation logs to
`disproven.json` and tries a different path. Check PROXIMITY to see
whether it's converging.
