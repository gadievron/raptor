---
description: Project threat model — show, initialise, lint, diff, report, build, refresh, export
dispatch: libexec/raptor-threat-model <command> [args]
---

# /threat-model — Project Threat Model

Manage the project-owned threat model that guides `/agentic`, `/understand`,
and `/validate`.

## Usage

```bash
/threat-model [command] [args]
```

## Commands

| Command | Description |
|---------|-------------|
| `show [project]` | Show the active/project threat model summary |
| `init [project]` | Create a blank project threat model |
| `export [project]` | Print `THREAT_MODEL.md` |
| `sync [project]` | Re-render `THREAT_MODEL.md` from JSON |
| `lint [project]` | Run quality gates over the saved model |
| `diff [project] --context-map <path>` | Compare the saved model against a fresh `/understand` map |
| `report [project] [--context-map <path>]` | Write `threat-model-report.md` with threats, evidence, drift and quality gates |
| `add --field <field> --value <text>` | Add a value to a string-list field (e.g. focus_areas, assets) |
| `remove --field <field> --value <text>` | Remove a value from a string-list field |
| `build [agentic args]` | Run the `/understand`-backed threat-model-only phase |
| `refresh [agentic args]` | Rebuild and overwrite the project model |
| `use-stale [agentic args]` | Build while explicitly allowing stale `/understand` fallback |
| `help` | Show wrapper help |

With no command, defaults to `show`.

## Execution

Run threat-model commands via Bash:

```bash
libexec/raptor-threat-model <command> [args]
```

Examples:

```bash
libexec/raptor-threat-model show
libexec/raptor-threat-model init
libexec/raptor-threat-model lint
libexec/raptor-threat-model report
libexec/raptor-threat-model build --repo /path/to/code
libexec/raptor-threat-model refresh --repo /path/to/code
libexec/raptor-threat-model use-stale --repo /path/to/code
```

`build`, `refresh`, and `use-stale` call the existing agentic
`--threat-model-only` path. `show`, `init`, `export`, `sync`, `lint`,
`diff`, and `report` call the existing project threat-model path. Do not
manually recreate the logic in the slash command.

## Output

Run the command via Bash, then output the result verbatim in a fenced code
block. Do not summarise, truncate, or paraphrase; the user needs the exact
model paths and handoff paths.

ARGUMENTS: $ARGS
