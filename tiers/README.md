# RAPTOR Tiers Structure

## Purpose

Methodology and guidance files consumed by two paths:

1. **Claude Code** — CLAUDE.md progressive-loading rules read guidance files
   on demand; agent definitions reference persona files on spawn.
2. **Python orchestration** — `core/llm/methodology.py` injects persona
   content into LLM system prompts (Gemini, Ollama, etc.).

---

## Structure

```
tiers/
├── analysis-guidance.md     # Post-scan exploit feasibility triage
├── exploit-guidance.md      # Active exploit development constraints
├── recovery.md              # General error recovery
├── validation-recovery.md   # Validation stage error recovery
│
└── personas/                # Expert methodologies
    ├── security_researcher.md
    ├── exploit_developer.md
    ├── crash_analyst.md
    ├── binary_exploitation_specialist.md
    ├── fuzzing_strategist.md
    ├── patch_engineer.md
    ├── penetration_tester.md
    └── README.md
```

---

## Loading

**Guidance files** — auto-loaded by CLAUDE.md progressive loading rules:
- `analysis-guidance.md` — after scan completes
- `exploit-guidance.md` — when developing exploits
- `recovery.md` — on general errors
- `validation-recovery.md` — on validation stage errors

**Personas** — loaded two ways:
- Claude Code: on explicit request or via agent definitions
- Python: `load_methodology("personas/<name>.md")` injects into system prompts

Token cost is zero until loaded; 400–1000 tokens when active.

---

## File Naming

`[role].md` — lowercase with underscores (e.g. `security_researcher.md`).
