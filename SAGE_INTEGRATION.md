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

### 1. Start SAGE sidecar

```bash
docker compose -f docker-compose.sage.yml up -d
```

This starts:
- **SAGE** on port 8090 (consensus-validated memory)
- **Ollama** on port 11435 (embedding model: nomic-embed-text)

### 2. Install SDK (optional, for Python integration)

```bash
pip install sage-agent-sdk httpx
```

### 3. Seed institutional knowledge

```bash
python3 core/sage/scripts/seed_sage_knowledge.py --sage-url http://localhost:8090
```

This extracts and stores:
- 30+ exploitation primitives with dependency graphs
- 25+ mitigation identifiers
- LLM system prompts (analysis, exploit, patch)
- 10 expert personas (~1,748 lines of domain expertise)
- Analysis/exploit/validation methodology
- Signal exploitability heuristics
- Semgrep configuration knowledge

### 4. Register agents

```bash
python3 core/sage/scripts/register_agents.py --sage-url http://localhost:8090
```

Registers all 16 RAPTOR agents on the SAGE network with role definitions.

### 5. Restart Claude Code

Restart your Claude Code session so it picks up the `.mcp.json` config and connects to SAGE MCP.

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
| `SAGE_URL` | `http://localhost:8080` | SAGE API URL |
| `SAGE_IDENTITY_PATH` | auto | Path to agent key file |
| `SAGE_TIMEOUT` | `15.0` | API request timeout (seconds) |
| `SAGE_FALLBACK_JSON` | `true` | Fall back to JSON when SAGE unavailable |

### MCP Configuration

The `.mcp.json` file configures Claude Code to connect to SAGE:

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

SAGE instructions live in `CLAUDE.md` (single source of truth) — all agents inherit them automatically:

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
curl http://localhost:8090/v1/health

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
