# SAGE Integration for RAPTOR

RAPTOR integrates with [SAGE](https://github.com/l33tdawg/sage) (Sovereign Agent Governed Experience) — a consensus-validated persistent memory system — to enable cross-session learning across all analysis workflows.

## Architecture

RAPTOR uses a **hybrid integration** approach:

1. **SDK Layer** (Python runtime): `core/sage/` module wraps the `sage-agent-sdk` to provide persistent memory for Python packages (fuzzing memory, exploit feasibility, analysis pipeline)

2. **MCP Layer** (Claude Code agents): All 16 Claude Code agents connect to SAGE via MCP for persistent memory across sessions

```
RAPTOR
├── Claude Code Agents (16)
│   └── SAGE MCP ──────────────────┐
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

- Verifies `sage-agent-sdk` is importable by `python3`.
- Merges the SAGE entry from `core/sage/mcp-entry.json` into `./.mcp.json`
  (creates the file if absent, deep-merges if you already have other MCP
  servers registered).
- Sets `SAGE_ENABLED=true` in `.claude/settings.local.json` so Claude Code
  propagates the flag into RAPTOR subprocesses (Python-pipeline opt-in —
  the MCP side is `.mcp.json`).
- `docker compose -f docker-compose.sage.yml up -d` — starts SAGE (port
  8090) and Ollama (port 11435, model `nomic-embed-text`).
- Waits for SAGE health.
- Seeds institutional knowledge (30+ primitives, 25+ mitigations, system
  prompts, 10 expert personas, methodology, exploitability heuristics).
- Registers all 16 RAPTOR agents on the SAGE network.

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
docker-compose.sage.yml down -v` to wipe them.

## SAGE Domains

| Domain | Purpose |
|--------|---------|
| `raptor-findings` | Vulnerability findings and analysis results |
| `raptor-fuzzing` | Fuzzing strategies, crash patterns, exploit techniques |
| `raptor-crashes` | Crash analysis patterns and root causes |
| `raptor-forensics` | OSS forensics evidence and investigation patterns |
| `raptor-exploits` | Exploit development patterns and constraints |
| `raptor-methodology` | Analysis methodology and expert reasoning |
| `raptor-campaigns` | Campaign history and outcomes |
| `raptor-reports` | Report structures and templates |
| `raptor-agents` | Agent role definitions and capabilities |
| `raptor-primitives` | Exploitation primitives and dependency graphs |
| `raptor-prompts` | LLM system prompts and personas |
| `raptor-personas` | Expert persona definitions |
| `raptor-config` | Configuration knowledge |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SAGE_ENABLED` | `false` | Enable SAGE integration |
| `SAGE_URL` | `http://localhost:8090` | SAGE API URL |
| `SAGE_IDENTITY_PATH` | auto | Path to agent key file |
| `SAGE_TIMEOUT` | `15.0` | API request timeout (seconds) |

### MCP Configuration

`.mcp.json` is `.gitignore`d and managed by `libexec/raptor-sage-setup`.
The template fragment lives at `core/sage/mcp-entry.json`:

```json
{
  "mcpServers": {
    "sage": {
      "type": "sse",
      "url": "http://localhost:8090/mcp/sse"
    }
  }
}
```

The setup script deep-merges this fragment into `./.mcp.json`, preserving
any other MCP servers you've registered. Uninstall removes only the SAGE
entry and leaves everything else in place.

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
docker compose -f docker-compose.sage.yml ps

# Check SAGE health
curl http://localhost:8090/health

# Check logs
docker compose -f docker-compose.sage.yml logs sage
```

### Embedding model not loaded

```bash
# Check Ollama models
curl http://localhost:11435/api/tags

# Pull model manually
docker compose -f docker-compose.sage.yml exec ollama ollama pull nomic-embed-text
```

### Memory not persisting

SAGE uses BFT consensus — memories must be committed before they appear in recall. With `create_empty_blocks_after=5s`, this happens within seconds on a single-node setup.
