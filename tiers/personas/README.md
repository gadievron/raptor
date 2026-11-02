# RAPTOR Expert Personas

Expert methodologies extracted from RAPTOR's Python analysis code.

## Choosing a persona

Eight expert personas are available on demand. Load one when you want a different perspective on a finding or a specific technique:

```
Exploit Developer (Mark Dowd)                  Exploit PoC generation
Crash Analyst (Charlie Miller / Halvar Flake)  Crash analysis and exploitability assessment
Security Researcher                            General adversarial code review
Patch Engineer                                 Secure fix generation
Penetration Tester                             Realistic attack scenario assessment
Web Researcher (James Kettle)                  Web endpoint research (smuggling, cache poisoning, SSRF)
Fuzzing Strategist                             Corpus design and triage
Binary Exploitation Specialist                 ROP, heap, and memory corruption
```

Tell Claude which one to use, e.g. "Use the Binary Exploitation Specialist".

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
| `web_researcher` | Web endpoint research (smuggling, cache poisoning, SSRF) | (Claude Code only) |
| `fuzzing_strategist` | Fuzzing strategy decisions | (Claude Code only) |

## Consumption paths

1. **Python** — `core/llm/methodology.py` loads the file, strips
   frontmatter/header comments, and appends the body to the system
   prompt for Gemini/Ollama/etc.

2. **Claude Code** — agent definitions reference persona files
   (e.g. crash-analyzer reads `crash_analyst.md`); operators
   can also request personas explicitly.

## Adding a persona

Create `tiers/personas/<role>.md` with `# ` header comment lines
(stripped by the loader) followed by the methodology body. Wire it
into the relevant Python call site with
`load_methodology("personas/<role>.md")`.
