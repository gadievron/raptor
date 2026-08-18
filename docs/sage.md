# SAGE Persistent Memory

RAPTOR integrates with [SAGE](https://github.com/l33tdawg/sage) (Sovereign
Agent Governed Experience) -- a consensus-validated persistent memory system
-- to enable cross-session learning across all analysis workflows.  Memories
go through BFT consensus, carry confidence scores, and decay over time; only
committed memories are ever returned to a consumer.

SAGE is opt-in.  If you don't set it up, nothing connects to it and RAPTOR
runs exactly as before with zero SAGE context loaded.  When SAGE is
installed, every integration point degrades gracefully: if the sidecar is
down, hooks no-op, agents work without memory, and no scan, fuzzing, or
analysis workflow is affected.

**Related documentation:**
[core concepts](concepts.md#sage-persistent-memory) |
[commands](commands.md#sage) |
[audit](audit.md) |
[security model](security.md) |
[dependencies](dependencies.md)


## Architecture

RAPTOR uses a **hybrid integration** approach:

1. **SDK Layer** (Python runtime): the `core/sage/` module wraps the
   `sage-agent-sdk` to provide persistent memory for Python pipelines
   (fuzzing memory, audit hooks, SCA short-circuits, CodeQL build recall)

2. **MCP Layer** (Claude Code agents): all 16 RAPTOR agents connect to SAGE
   via MCP (stdio transport) for persistent memory across sessions

```
RAPTOR
├── Claude Code Agents (16)
│   └── SAGE MCP (stdio) ─────────┐
├── Python Packages                │
│   ├── Fuzzing Memory (SDK) ──────┤
│   ├── Audit / SCA hooks ─────────┤
│   └── LLM Analysis ─────────────┤
│                                  ▼
│                           ┌─────────────┐
│                           │  SAGE Node  │
│                           │  (Docker)   │
│                           └──────┬──────┘
│                                  │
│                           ┌──────┴──────┐
│                           │   Ollama    │
│                           │ (embeddings)│
│                           └─────────────┘
```


## Quick Start

### 1. Install the SDK

```bash
pip install sage-agent-sdk httpx
```

### 2. Run the setup script

```bash
libexec/raptor-sage-setup
```

One command does everything; re-runs are safe (see *Reinstall / re-seed*
below):

- Verifies prerequisites (`sage-agent-sdk`, jq, docker, curl, the stdio
  wrapper).
- Migrates the SAGE_HOME volume mount if upgrading from the old `.sage-gui`
  layout (automatic, non-destructive -- see *Upgrading and migrating* below).
- Auto-detects GPU vs CPU and picks the embedding model accordingly (see
  *CPU vs GPU* below).
- `docker compose -f core/sage/docker-compose.yml up -d` -- starts SAGE
  (port 8090) and Ollama (port 11435), both loopback-bound.
- Waits for SAGE health.
- Seeds institutional knowledge (30+ exploitation primitives and
  mitigations, system prompts, 10 expert personas, methodology,
  exploitability heuristics).
- Registers all 16 RAPTOR agents on the SAGE network.
- Generates the stdio MCP entry in `./.mcp.json` (replaces any stale SSE
  config; preserves other MCP servers you've registered).
- Sets `SAGE_ENABLED=true` in `.claude/settings.local.json` so Claude Code
  propagates the flag into RAPTOR subprocesses (Python-pipeline opt-in).
- Runs a smoke test against the MCP wrapper (non-fatal if it fails).
- Captures the server's boot payload and records it as operator-authorized
  in `.sage/boot-payload.authorized` (see `core/sage/CLAUDE.md` for the
  trust semantics).
- Generates the per-install HMAC row-authentication key if absent (see
  *HMAC key setup* below).

### 3. Restart Claude Code

Restart so Claude Code picks up the new MCP registration.

### Check status

```bash
libexec/raptor-sage-setup --status
```

Reports whether the sidecar is running, health, embedding provider and
model, Ollama state, memory count, the MCP entry, and boot-payload
authorization/drift.

### Reinstall / re-seed

`libexec/raptor-sage-setup` is safe to re-run at any time.  The seed and
register steps query SAGE for each item's tag (`primitive:rop-chain`,
`agent:raptor-scan`, etc.) before proposing, so re-runs skip entries
already present and only propose what's missing.  Output tells you which
category each item fell into:

```
stored:  primitive:rop-chain
skipped: primitive:stack-canary (already seeded)
partial: raptor-scan (filled in missing half from a prior partial run)
```

To deliberately re-propose everything -- e.g. after a SAGE volume wipe,
schema migration, or knowledge-base refresh -- use `--force` on the
underlying scripts directly:

```bash
python3 core/sage/scripts/seed_sage_knowledge.py --force
python3 core/sage/scripts/register_agents.py --force
```

### Tear down

```bash
libexec/raptor-sage-setup --uninstall
```

Stops the docker sidecar, removes the SAGE entry from `.mcp.json` and the
`SAGE_ENABLED` key from `.claude/settings.local.json` (deletes either file
if it becomes empty), and removes the recorded boot payload.  Data volumes
are preserved -- use `docker compose -f core/sage/docker-compose.yml down
-v` to wipe them.  The HMAC key is never removed by uninstall.


## HMAC key setup

SAGE recall feeds *mechanical* decisions: skipping an LLM call for a
function already proven clean, suppressing a known false positive,
appending AFL flags, replaying a CodeQL build command, replaying a proven
checker rule into an audit sweep.  Memory content is written by multiple
flows -- including reflection of LLM output and federated peers -- so a
poisoned row would otherwise become machine behaviour.  Rows intended for
mechanical consumption therefore carry an HMAC-SHA256 token that only this
install can mint.

**Verified rows are trusted recall; unverified recall is hint-only by
design.**  A row whose token is missing or fails verification (legacy
pre-MAC rows, federated/foreign rows, tampered rows) never drives a
mechanical decision -- the hooks behave exactly as if no memory existed,
and the row's text at most surfaces as a human-visible hint.

### What the key protects

Every store-side hook in `core/sage/hooks.py` appends a trailing
`` [mac:<64 hex>]`` token to the row content, computed over the exact
decision fields the consumer will act on (never the surrounding prose).
Recall-side consumers strip the token, re-derive the decision fields from
the parsed values, and verify before acting.  Concretely gated:

- Cross-run false-positive suppression (`recall_prior_finding_verdict`)
- CodeQL build-command replay (`infer_codeql_build_from_sage_recall_row` --
  an unverified row yields the command only as an operator hint, never a
  replayable build)
- Mechanical AFL flag inference (`infer_afl_fuzz_flags_from_sage_recall_row`)
- Confirmed-malicious SCA short-circuits
- Audit hypothesis-verdict skip (`clean`/`dormant` re-review skip)
- Proven-rule replay into audit sweeps (`recall_verified_proven_rules`)
- Study/teach concept skip and seed gates

### Where the key lives

```
$XDG_DATA_HOME/raptor/rowmac.key        (default: ~/.local/share/raptor/rowmac.key)
```

32 random bytes, file mode 0600, directory 0700.  The key deliberately
lives *outside* the repo tree: several sandbox profiles grant children
repo-root read, and a sandboxed target that could read an in-repo key
could mint valid tokens for poisoned rows -- defeating the mechanism.

### Key lifecycle -- no manual step needed

`libexec/raptor-sage-setup` pre-creates the key at install time, and the
library also creates it automatically (atomically, race-tolerant) on the
first stamped store if setup never ran.  Every *new* row earns its token
without any operator action -- there is nothing to generate by hand.

Rows stored *before* the key existed, or via paths that don't stamp,
carry no token and stay hint-only permanently.  They re-earn trust as
the same knowledge is re-stored: the pipelines re-propose verdicts,
build outcomes, and strategies in normal use, and `/sage corroborate
<id>` is the operator flow for independently backing a memory you have
manually confirmed.

### Permissions matter

The key must be a regular file, owned by you, mode 0600, in a 0700
directory.  Verification fails closed on a suspect key: loose
group/other permission bits, wrong ownership, or a key reached through a
symlink cause minting to refuse and recall to demote to hint-only, with
a single loud warning naming the remedy.  Fix with `chmod 600` /
`chown`, and replace any symlinked key with a regular file (then
investigate how the symlink got there -- the key must never resolve into
a sandbox-readable tree).

### How to check it's working

```bash
ls -l ~/.local/share/raptor/rowmac.key    # regular file, 32 bytes, -rw-------
```

- Rows stored by the pipeline hooks end with a `[mac:...]` token
  (`/sage list` shows raw content).
- At debug log level, demotions are explicit: `recall row has no MAC
  token — mechanical use demoted to hint` / `recall row failed MAC
  verification — mechanical use demoted to hint`.

### What hint-only demotion looks like

Nothing breaks -- that is the point -- but a row that fails verification
(pre-key rows, foreign/federated rows, tampered rows, or a suspect key
file) loses its mechanical effect:

- Findings with a prior `false_positive`/`not_exploitable` verdict are
  re-analysed instead of suppressed.
- Recalled CodeQL build commands demote to operator hints.
- No AFL flags are inferred from prior fuzzing strategies.
- Audit re-runs re-review functions already proven `clean`/`dormant`.
- Proven checker rules are re-synthesised instead of replayed.
- Study/teach concept recall stops short-circuiting LLM dispatch.

Unverified rows remain visible as hints and recall context.

### Key rotation and loss

There is no rotation machinery, deliberately.  Deleting or losing the
key demotes every previously stamped row to a hint -- permanently, since
old tokens can never verify under a new key -- and rows re-earn
mechanical status as new outcomes are stored.  Memories decay anyway, so
key loss is a graceful reset, not an incident.  Setup never touches an
existing key, and uninstall never removes it.  **When moving hosts, the
key must travel with the SAGE data volumes** -- see *Moving to a new
host* below.  See [security.md](security.md) for the full rationale.


## CPU vs GPU

### Setup-time model selection

`libexec/raptor-sage-setup` probes for a GPU with `nvidia-smi` and picks
the embedding model:

| Hardware | Model | Speed |
|----------|-------|-------|
| GPU | `nomic-embed-text` (137M F16, 768 dims) | ~0.1s/embed |
| CPU-only | `snowflake-arctic-embed:m` (110M, 768 dims, CPU-optimised) | ~3s/embed |

Both models are 768-dimensional, so the SAGE vector store works with
either -- moving a volume between GPU and CPU machines does **not** require
a re-seed.

To force a specific model, export the override before running setup:

```bash
export SAGE_EMBED_MODEL=nomic-embed-text SAGE_EMBED_DIM=768
libexec/raptor-sage-setup
```

For GPU passthrough into the Ollama container, uncomment the `deploy:`
block in `core/sage/docker-compose.yml`.

### Runtime behaviour

The Python hooks probe Ollama (`/api/ps`) once per process and only treat
the host as GPU-backed when the embedding model is fully VRAM-resident:

- **CPU-only hosts disable the automated pipeline hooks by default** --
  per-row embeds are too slow for automated sweeps.  The MCP tools
  (`sage_recall` etc.) and the `/sage` CLI still work for manual use.
  Set `SAGE_FORCE_CPU=1` to run the pipeline hooks on CPU anyway.
- Recall concurrency is 4 workers with a GPU, 2 without
  (`SAGE_RECALL_WORKERS` overrides, capped at 8).
- On CPU, embeddings bypass SAGE's `/v1/embed` passthrough (which has a
  30s server-side ceiling) and call Ollama directly with a 60s timeout.

Expect a fresh recall pass over a large study list to take seconds on GPU
and minutes on CPU.  If a GPU host misreports as CPU-only behind a
corporate proxy, note that RAPTOR already exempts loopback from proxy env
vars for its own probes; check `docker compose -f
core/sage/docker-compose.yml ps` and `curl http://localhost:11435/api/ps`.


## Use cases

All of these are automatic once SAGE is installed; none require operator
action beyond running the normal commands.

### Persistent knowledge across audit runs

`/audit` stores a verdict row per reviewed hypothesis, keyed by file,
function, hypothesis hash, and a hash of the function's source.  On
re-audit, functions whose source is unchanged and whose prior verdict was
`clean` or `dormant` are skipped -- findings and suspicious results are
always re-tested.  Tool-confirmed observations ("semgrep confirmed
unchecked memcpy length in this pattern") are stored to the global
methodology domain for cross-target transfer.

### Proven-rule recall and replay into sweeps

When a synthesised checker rule graduates into the on-disk rule library
(`packages/checker_synthesis`), its metadata (engine, CWE, rule id, body
hash, TP/FP counts, dual-control state) is indexed in SAGE.  Later audits
-- including on *other* targets -- recall these rows by engine + CWE and
replay the rule directly instead of re-synthesising, provided the row's
HMAC verifies, the quality gate passes (TP rate >= 80%, dual control,
tested on 3+ targets), and the on-disk rule body still hashes to the
stamped value.  Sweep hits from a replayed rule carry provenance
`sage:<rule_id>`.

### Prior-run observations seeding session context

At audit prep, up to 5 prior-run observations relevant to the target are
recalled and seeded into session context.  These are hint-only by design
(prose, not MAC-gated) and pass through the same sanitise-and-injection-
scan gate that live observations get before any prompt re-entry.

### Spec promotion from operator annotations

`/annotate add <file> <function> --status sink` (or `entry_point` /
`finding`) with a human source promotes any matching IRIS taint spec to
`xref_backed`, widening next-run taint coverage across the pipelines that
load the IRIS store.  LLM-sourced annotations never promote.

### Cross-run false-positive suppression

`/agentic` and `/codeql` store per-finding verdicts; findings previously
ruled `false_positive` or `not_exploitable` are suppressed on later runs
as long as the surrounding source is unchanged (hash-checked) and the row
verifies.

### CodeQL build reliability

Successful build commands and failure modes are remembered per repo;
later `/codeql` runs replay a verified prior build command instead of
re-detecting, and surface unverified ones as operator hints.

### Fuzzing strategy priors

`/fuzz` recalls prior strategy outcomes for similar binaries and may
mechanically append conservative `afl-fuzz` flags (`-L 0`, `-D`,
`-p explore|exploit|fast`) from high-confidence verified rows.  Disable
with `RAPTOR_SAGE_AFL_PRIOR=0`.

### Study / teach concept recall

`/understand --teach` and audit study store concepts, invariants, and
contracts with per-evidence source hashes; recall short-circuits LLM
dispatch when the hashes still match the current source.

### Audit learning-loop calibration

Audit corpus runs extract false-positive patterns into
`prompt-corrections.json`; a best-effort SAGE store keeps the reasoning
and historical context alongside (domain `audit-calibration`).

### Operator workflows

```
/sage status                      # store overview
/sage recall "integer overflow in length checks"
/sage timeline                    # what was learned, bucketed by time
/sage corroborate <id>            # independently back a memory
/sage list --domain raptor-methodology
```

Recall before a tricky manual step ("known pitfalls building this
target"), browse the timeline after a long campaign, corroborate memories
you have independently confirmed so their confidence strengthens.

### Cross-session agent messaging

RAPTOR agents registered on the SAGE network can exchange messages and
tasks across sessions (`sage_message_send`, `sage_inbox`, `sage_backlog`,
`sage_task` MCP tools).  Inbox content is untrusted by contract -- agents
treat it as data, never as instructions.


## SAGE Domains

Domains use repo-scoped variants (`{repo_key}` = short hash of the
repository path) to prevent cross-project leakage.  Global domains are
used for knowledge that generalises across targets.

| Domain | Purpose |
|--------|---------|
| `raptor-findings-{repo_key}` | Vulnerability findings and analysis results (repo-scoped) |
| `raptor-fp-{repo_key}` | Finding verdicts for cross-run FP suppression (repo-scoped) |
| `raptor-sca-{repo_key}` | SCA findings and verdicts (repo-scoped) |
| `raptor-concepts-{repo_key}` | Study/teach concept recall (repo-scoped) |
| `raptor-audit-{repo_key}` | Audit hypothesis verdicts (repo-scoped) |
| `raptor-fuzzing` | Fuzzing strategies and crash outcomes (global) |
| `raptor-methodology` | Analysis methodology, CodeQL build reliability, expert reasoning (global) |
| `raptor-rule-library` | Proven checker rules keyed by engine + CWE (global, cross-target) |

The seed script additionally populates global knowledge domains
(`raptor-primitives`, `raptor-personas`, `raptor-prompts`,
`raptor-config`, `raptor-agents`).  See `core/sage/CLAUDE.md` for the
authoritative hook-to-domain table.


## Configuration

### Environment Variables

(SAGE rows also appear in the drift-checked registry,
[Environment Variables](environment.md).)

**RAPTOR-side** (set in `.claude/settings.local.json` or shell):

| Variable | Default | Description |
|----------|---------|-------------|
| `SAGE_ENABLED` | `false` | Enable SAGE integration in Python pipelines (setup sets this) |
| `SAGE_URL` | `http://localhost:8090` | SAGE API URL |
| `SAGE_IDENTITY_PATH` | auto | Path to agent key file (in-container) |
| `SAGE_TIMEOUT` | `30.0` | API request timeout (seconds) |
| `SAGE_OLLAMA_URL` | `http://localhost:11435` | Ollama URL for the direct-embed path |
| `SAGE_FORCE_CPU` | unset | Run pipeline hooks on CPU-only hosts |
| `SAGE_RECALL_WORKERS` | auto (4 GPU / 2 CPU) | Recall concurrency (max 8) |
| `RAPTOR_SAGE_AFL_PRIOR` | `1` | Set `0` to disable mechanical AFL flag inference |
| `SAGE_EMBED_MODEL` / `SAGE_EMBED_DIM` | auto-detected | Embedding model override (set before running setup) |

**Container-side** (set in `core/sage/docker-compose.yml`, passed to the
SAGE container):

| Variable | Value | Description |
|----------|-------|-------------|
| `SAGE_HOME` | `/root/.sage` | SAGE data directory inside the container |
| `SAGE_EMBEDDING_PROVIDER` | `openai-compatible` | Embedding backend (`ollama`, `openai-compatible`, or `hash`) |
| `SAGE_EMBEDDING_BASE_URL` | `http://ollama:11434` | Ollama API URL (container-internal) |
| `SAGE_EMBEDDING_MODEL` | `${SAGE_EMBED_MODEL}` | Embedding model name (auto-detected) |
| `SAGE_EMBEDDING_DIMENSION` | `${SAGE_EMBED_DIM}` (768) | Embedding vector dimension |
| `REST_ADDR` | `0.0.0.0:8080` | SAGE REST API listen address (mapped to loopback 8090) |

If `SAGE_EMBEDDING_PROVIDER` is unset, SAGE defaults to `hash` -- keyword
matching only, no semantic recall.  The compose file sets a real provider
so semantic embeddings are active out of the box.

### MCP Configuration

`.mcp.json` is `.gitignore`d and managed by `libexec/raptor-sage-setup`.
The setup script generates the entry inline using stdio transport via the
`libexec/raptor-sage-mcp` wrapper:

```json
{
  "mcpServers": {
    "sage": {
      "command": "/path/to/raptor/libexec/raptor-sage-mcp",
      "args": [],
      "env": {
        "SAGE_PROVIDER": "claude-code",
        "SAGE_PROJECT": "raptor",
        "SAGE_IDENTITY_PATH": "/root/.sage/agents/raptor-claude-code/agent.key"
      }
    }
  }
}
```

The wrapper `exec`s into `docker compose exec -T sage /usr/local/bin/sage-gui mcp`,
wiring Claude Code's stdin/stdout directly to the SAGE MCP process inside
the container.  No SSE, no HTTP, no OAuth.

The setup script replaces `.mcpServers.sage` entirely on each run (stale
`type`/`url` fields from an old SSE config are removed).  Other MCP
servers are preserved.  Uninstall removes only the SAGE entry.


## How It Works

### Fuzzing Memory (SDK)

The `SageFuzzingMemory` class extends `FuzzingMemory` to store knowledge
in SAGE while keeping JSON as a local cache:

```python
from core.sage.memory import SageFuzzingMemory

memory = SageFuzzingMemory()  # Drop-in replacement

# Same API as FuzzingMemory
memory.record_strategy_success("AFL_CMPLOG", binary_hash, 5, 2)
best = memory.get_best_strategy(binary_hash)
```

### Claude Code Agents (MCP)

SAGE usage instructions live in `core/sage/CLAUDE.md` and are
conditionally loaded by RAPTOR's root `CLAUDE.md` only when the
`sage_inception` tool is present (i.e. when `.mcp.json` registers SAGE,
i.e. only when a user has actually run `libexec/raptor-sage-setup`).  The
full list of 30+ MCP tools is available via the MCP server's tool
discovery; the core tools are:

```
sage_inception          # Boot persistent memory
sage_turn               # Every turn: recall + store
sage_remember           # Store important findings
sage_recall             # Check for known patterns
sage_reflect            # After tasks: dos and don'ts
sage_forget             # Deprecate a memory
sage_list               # List memories (with domain filter)
sage_status             # Memory store overview
sage_register           # Register an agent
sage_reinstate          # Reinstate a deprecated memory
sage_rename             # Rename a memory
sage_link               # Link two memories
sage_corroborate        # Independently back a memory
sage_backlog            # Open tasks
sage_task               # Create or update a task
sage_timeline           # Time-bucketed activity view
sage_scope_list / sage_scope_get  # Scope management
sage_inbox              # Agent inbox
sage_message_send / sage_messages_receive  # Agent messaging
sage_gov_propose / sage_gov_vote / sage_gov_status  # Governance
```

### Graceful Degradation

All SAGE operations are wrapped in try/except.  If SAGE is unavailable:

- Python packages fall back to JSON storage
- Claude Code agents work normally without memory
- No scans, fuzzing, or analysis workflows are affected


## Upgrading and migrating

### Upgrading the sidecar

The SAGE image is version-pinned in `core/sage/docker-compose.yml`.  To
upgrade: bump the pin, then re-run `libexec/raptor-sage-setup`.  The
setup run recreates the containers, re-verifies embeddings, re-captures
the server's boot payload, and re-authorizes it (printing a diff of the
payload when it changed).  Data volumes carry over untouched; the seed
and register steps skip everything already present.

### Changing the embedding model

Export `SAGE_EMBED_MODEL` (and `SAGE_EMBED_DIM` if it differs) and re-run
setup.  Models with the same vector dimension (both defaults are 768) are
interchangeable without a re-seed.  Switching to a model with a
*different* dimension invalidates the stored vectors -- wipe the volumes
(`docker compose -f core/sage/docker-compose.yml down -v`) and re-seed
with `--force`.

### Migrating memory data across versions

The docker-compose volume mount changed from `/root/.sage-gui` (SAGE <=
6.6.5) to `/root/.sage` (SAGE 11.x).  When `libexec/raptor-sage-setup`
detects an existing container with the old mount, it automatically
migrates the data:

1. Stops the sage service (retains the container).
2. Copies data from both `/root/.sage-gui` (volume) and `/root/.sage`
   (writable layer -- agent keys, ledger) to a host-side backup.
3. If the destination volume is empty: full copy via a disposable
   container.  If it already has data: detects collisions (byte-for-byte
   via `cmp -s`) and classifies them.  Collisions on critical state
   (`agent.key`, `vault.key`, `config.yaml`, `data/sage.db`,
   `data/badger/*`, `data/cometbft/*`) abort migration -- both versions
   preserved for operator review.  Non-critical collisions keep the
   destination version.  After collision checks, merges only files
   missing from the destination.
4. Verifies every critical file and directory present in the backup
   exists byte-for-byte in the destination.  Copy, comparison, merge,
   validation, and marker failures all abort before container recreation
   and preserve the backup for recovery.
5. Writes a `.migration-complete` marker (only if all checks pass).
6. Preserves the backup directory for operator verification -- the script
   prints its path and the operator removes it manually after checking.

On an already-migrated setup (container mounts `/root/.sage`), the
migration exits immediately -- no backup is created and no data is
touched.

### When re-seeding is needed

Normal setup re-runs never need it -- the seed and register scripts are
idempotent (tag-checked).  Re-seed with `--force` after: a volume wipe
(`down -v`), an embedding-dimension change, a SAGE schema migration that
drops memories, or a deliberate knowledge-base refresh (updated
primitives/personas in the RAPTOR tree).

### Moving to a new host

The memory and its trust anchor live in two places, and **they must move
together**:

1. **SAGE data volumes** (`sage_data`, `ollama_data`) -- the memories
   themselves.  Copy via `docker volume` export/import or by migrating
   `/var/lib/docker/volumes` per your usual docker practice.
2. **The HMAC row key** -- `$XDG_DATA_HOME/raptor/rowmac.key` (default
   `~/.local/share/raptor/rowmac.key`).  Include it in host backups and
   migrations alongside the volumes; restore it with `chmod 600` in a
   0700 directory before the first RAPTOR run on the new host.

Moving or rebuilding a host *without* the key file permanently demotes
every stamped row: a fresh key is minted automatically on the new host,
old tokens can never verify under it, and the rows stay hint-only
forever.  There is no re-stamping tool -- if that happens, either restore
the old key file from backup, or accept the reset and let the mechanical
loops rebuild as new outcomes are stored (deliberately deleting the key
has exactly this effect and is the supported way to reset row trust).


## Troubleshooting

### SAGE not responding

```bash
# Check if containers are running
docker compose -f core/sage/docker-compose.yml ps

# Check SAGE health
curl http://localhost:8090/health

# Check logs
docker compose -f core/sage/docker-compose.yml logs sage
```

### Embedding model not loaded

```bash
# Check which embedding provider SAGE is using
docker compose -f core/sage/docker-compose.yml exec -T sage printenv SAGE_EMBEDDING_PROVIDER

# Check Ollama models
curl http://localhost:11435/api/tags

# Pull the model manually (substitute the model reported by --status)
docker compose -f core/sage/docker-compose.yml exec ollama ollama pull snowflake-arctic-embed:m
```

If `SAGE_EMBEDDING_PROVIDER` prints empty or `hash`, SAGE is running with
keyword matching only -- semantic recall will be degraded.  Check that
`core/sage/docker-compose.yml` sets it in the sage service's environment
block.

### Verified rules suddenly hint-only

If recall that used to drive mechanical decisions (FP suppression, build
replay, proven-rule replay, review skips) abruptly demotes to hints,
look for the rowmac refusal warning in the logs (emitted once per
suspect key path):

```
rowmac: refusing key <path> — <reason>. Row MACs will not mint or
verify (mechanical recall demoted to hint-only) until this is fixed: <remedy>
```

then check the key file:

```bash
ls -l ~/.local/share/raptor/rowmac.key
```

Verification fails closed on a suspect key (see *Permissions matter*
under *HMAC key setup*), and the warning's remedy names the fix:

- group/other permission bits → `chmod 600 <path>`
- wrong owner → investigate the foreign-owned key; restore your own
  0600 key file
- symlink (or not a regular file) → remove it and investigate how it
  got there; a fresh key is created on the next store

Distinguish this from a merely *absent* key: no warning fires, a fresh
key self-mints on the first stamped store, and only rows stamped under
an older key stay hint-only.  If the key is gone or was replaced (host
rebuild without carrying it over), previously stamped rows are
permanently hint-only; see *Moving to a new host*.

### Memory not persisting

SAGE uses BFT consensus -- memories must be committed before they appear
in recall.  With `create_empty_blocks_after=5s`, this happens within
seconds on a single-node setup.
