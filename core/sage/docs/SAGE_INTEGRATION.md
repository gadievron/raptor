# SAGE Integration for RAPTOR

RAPTOR integrates with [SAGE](https://github.com/l33tdawg/sage) (Sovereign Agent Governed Experience) — a consensus-validated persistent memory system — to enable cross-session learning across all analysis workflows.

## Architecture

RAPTOR uses a **hybrid integration** approach:

1. **SDK Layer** (Python runtime): `core/sage/` module wraps the `sage-agent-sdk` to provide persistent memory for Python packages (fuzzing memory, exploit feasibility, analysis pipeline)

2. **MCP Layer** (Claude Code agents): All 16 Claude Code agents connect to SAGE via MCP (stdio transport) for persistent memory across sessions

```
RAPTOR
├── Claude Code Agents (16)
│   └── SAGE MCP (stdio) ─────────┐
├── Python Packages                │
│   ├── Fuzzing Memory (SDK) ──────┤
│   ├── Exploit Feasibility ───────┤
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

SAGE is opt-in. If you don't set it up, `.mcp.json` stays absent, nothing
connects to port 8090, and RAPTOR runs exactly as before with zero SAGE
context loaded into Claude Code.

### 1. Install the SDK

```bash
pip install sage-agent-sdk httpx
```

### 2. Run the setup script

```bash
libexec/raptor-sage-setup
```

One command does everything; re-runs are safe (see *Reinstall / re-seed* below):

- Verifies prerequisites (`sage-agent-sdk`, jq, docker, curl, the stdio wrapper).
- Migrates the SAGE_HOME volume mount if upgrading from the old `.sage-gui` layout
  (automatic, non-destructive — see *Volume migration* below).
- `docker compose -f core/sage/docker-compose.yml up -d` — starts SAGE (port
  8090) and Ollama (port 11435, model `nomic-embed-text`).
- Waits for SAGE health.
- Seeds institutional knowledge (30+ primitives, 25+ mitigations, system
  prompts, 10 expert personas, methodology, exploitability heuristics).
- Registers all 16 RAPTOR agents on the SAGE network.
- Generates the stdio MCP entry in `./.mcp.json` (replaces any stale SSE
  config; preserves other MCP servers you've registered).
- Sets `SAGE_ENABLED=true` in `.claude/settings.local.json` so Claude Code
  propagates the flag into RAPTOR subprocesses (Python-pipeline opt-in).
- Runs a smoke test against the MCP wrapper (non-fatal if it fails).

### 3. Restart Claude Code

Restart so Claude Code picks up the new MCP registration.

### Reinstall / re-seed

`libexec/raptor-sage-setup` is safe to re-run at any time. The seed and
register steps query SAGE for each item's tag (`primitive:rop-chain`,
`agent:raptor-scan`, etc.) before proposing, so re-runs skip entries
already present and only propose what's missing. Output tells you
which category each item fell into:

```
stored:  primitive:rop-chain
skipped: primitive:stack-canary (already seeded)
partial: raptor-scan (filled in missing half from a prior partial run)
```

To deliberately re-propose everything — e.g. after a SAGE volume wipe,
schema migration, or knowledge-base refresh — use `--force` on the
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
if it becomes empty). Data volumes are preserved — use `docker compose -f
core/sage/docker-compose.yml down -v` to wipe them.

## SAGE Domains

Repo-scoped domains use a `{repo_key}` suffix (SHA-256 prefix of the target
path) to prevent cross-project leakage. Global domains apply across targets.

| Domain | Scope | Purpose |
|--------|-------|---------|
| `raptor-findings-{repo_key}` | repo | Vulnerability findings and analysis results |
| `raptor-sca-{repo_key}` | repo | SCA findings and verdicts |
| `raptor-fp-{repo_key}` | repo | Finding verdicts for cross-run FP suppression |
| `raptor-fuzzing` | global | Fuzzing strategies and crash outcomes |
| `raptor-methodology` | global | Analysis methodology and expert reasoning |
| `raptor-rule-library` | global | Proven checker rules (engine + CWE keyed, cross-target) |
| `raptor-concepts` | global | Study concept recall (planned) |

See `core/sage/CLAUDE.md` for the authoritative domain list and hook table.

## Configuration

### Environment Variables

**RAPTOR-side** (set in `.claude/settings.local.json` or shell):

| Variable | Default | Description |
|----------|---------|-------------|
| `SAGE_ENABLED` | `false` | Enable SAGE integration in Python pipelines |
| `SAGE_URL` | `http://localhost:8090` | SAGE API URL |
| `SAGE_IDENTITY_PATH` | auto | Path to agent key file (in-container) |
| `SAGE_TIMEOUT` | `15.0` | API request timeout (seconds) |

**Container-side** (set in `docker-compose.yml`, passed to the SAGE container):

| Variable | Value | Description |
|----------|-------|-------------|
| `SAGE_HOME` | `/root/.sage` | SAGE data directory inside the container |
| `SAGE_EMBEDDING_PROVIDER` | `ollama` | Embedding backend (`ollama`, `openai-compatible`, or `hash`) |
| `SAGE_EMBEDDING_BASE_URL` | `http://ollama:11434` | Ollama API URL (container-internal) |
| `SAGE_EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model name |
| `REST_ADDR` | `0.0.0.0:8080` | SAGE REST API listen address |

If `SAGE_EMBEDDING_PROVIDER` is unset, SAGE defaults to `hash` — keyword
matching only, no semantic recall. The docker-compose.yml sets it to `ollama`
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
wiring Claude Code's stdin/stdout directly to the SAGE MCP process inside the
container. No SSE, no HTTP, no OAuth.

The setup script replaces `.mcpServers.sage` entirely on each run (stale
`type`/`url` fields from an old SSE config are removed). Other MCP servers
are preserved. Uninstall removes only the SAGE entry.

### Volume Migration

The docker-compose volume mount changed from `/root/.sage-gui` (SAGE <= 6.6.5)
to `/root/.sage` (SAGE 11.x). When `libexec/raptor-sage-setup` detects an
existing container with the old mount, it automatically migrates the data:

1. Stops the sage service (retains the container).
2. Copies data from both `/root/.sage-gui` (volume) and `/root/.sage`
   (writable layer — agent keys, ledger) to a host-side backup.
3. If the destination volume is empty: full copy via a disposable container.
   If it already has data: merges only files that don't exist in the
   destination (preserves existing state, adds missing agent keys).
4. Writes a `.migration-complete` marker.
5. Preserves the backup directory for operator verification — the script
   prints its path and the operator removes it manually after checking.

On an already-migrated setup (container mounts `/root/.sage`), the function
exits immediately — no backup is created and no data is touched.

## How It Works

### Fuzzing Memory (SDK)

The `SageFuzzingMemory` class extends `FuzzingMemory` to store knowledge in SAGE while keeping JSON as a local cache:

```python
from core.sage.memory import SageFuzzingMemory

memory = SageFuzzingMemory()  # Drop-in replacement

# Same API as FuzzingMemory
memory.record_strategy_success("AFL_CMPLOG", binary_hash, 5, 2)
best = memory.get_best_strategy(binary_hash)

# New: semantic recall from SAGE
similar = await memory.recall_similar("heap overflow strategies for ASLR binaries")
```

### Claude Code Agents (MCP)

SAGE usage instructions live in `core/sage/CLAUDE.md` and are conditionally
loaded by RAPTOR's root `CLAUDE.md` only when the `sage_inception` tool is
present (i.e. when `.mcp.json` registers SAGE, i.e. only when a user has
actually run `libexec/raptor-sage-setup`). The tools exposed via MCP:

```
sage_inception          # Boot persistent memory
sage_turn               # Every turn: recall + store
sage_remember           # Store important findings
sage_recall             # Check for known patterns
sage_reflect            # After tasks: dos and don'ts
```

### Graceful Degradation

All SAGE operations are wrapped in try/except. If SAGE is unavailable:
- Python packages fall back to JSON storage
- Claude Code agents work normally without memory
- No scans, fuzzing, or analysis workflows are affected

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

# Pull model manually
docker compose -f core/sage/docker-compose.yml exec ollama ollama pull nomic-embed-text
```

If `SAGE_EMBEDDING_PROVIDER` prints empty or `hash`, SAGE is running with
keyword matching only — semantic recall will be degraded. Check that the
docker-compose.yml has `SAGE_EMBEDDING_PROVIDER=ollama` in the sage service's
environment block.

### Memory not persisting

SAGE uses BFT consensus — memories must be committed before they appear in recall. With `create_empty_blocks_after=5s`, this happens within seconds on a single-node setup.
