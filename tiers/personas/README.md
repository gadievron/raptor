# RAPTOR Expert Personas

Expert methodologies extracted from RAPTOR's Python analysis code.

## Pipeline Mapping

Each persona serves a distinct moment in the security analysis pipeline:

| Persona | Pipeline moment | Python call site |
|---------|----------------|------------------|
| `security_researcher` | Finding triage + dataflow validation | `autonomous_analyzer.py`, `dataflow_validator.py` |
| `exploit_developer` | PoC generation (CodeQL) | `autonomous_analyzer.py` |
| `crash_analyst` | Crash root-cause triage | `crash_agent.py` |
| `binary_exploitation_specialist` | Crash PoC generation | `crash_agent.py` |
| `patch_engineer` | Remediation guidance | (Claude Code only) |
| `penetration_tester` | Web payload generation | (Claude Code only) |
| `fuzzing_strategist` | Fuzzing strategy decisions | (Claude Code only) |

## Consumption paths

1. **Python** — `core/llm/methodology.py` loads the file, strips
   frontmatter/header comments, and appends the body to the system
   prompt for Gemini/Ollama/etc.

2. **Claude Code** — agent definitions reference persona files
   (e.g. crash-analyzer-agent reads `crash_analyst.md`); operators
   can also request personas explicitly.

## Adding a persona

Create `tiers/personas/<role>.md` with `# ` header comment lines
(stripped by the loader) followed by the methodology body. Wire it
into the relevant Python call site with
`load_methodology("personas/<role>.md")`.
