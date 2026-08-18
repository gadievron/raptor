---
description: Manage RAPTOR projects — create, list, status, coverage, findings, diff, merge, report, clean, export
dispatch: libexec/raptor-project-manager <subcommand> [args]
---

# /project — Project Management

Manage projects — named workspaces that corral analysis runs into one directory.

## Usage

```
/project <subcommand> [args]
```

## Subcommands

| Command | Description |
|---------|-------------|
| `help [subcommand]` | Show help (detailed if subcommand given) |
| `create <name> --target <path> [-d <desc>] [--output-dir <dir>] [--binary <path> ...] [--require-target-type <kind>]` | Create a new project |
| `list` | Show all projects (* marks active) |
| `status [<name>]` | Show project summary with run history |
| `coverage [<name>] [--detailed] [--fail-under <pct>]` | Show tool coverage summary (or per-file table; `--fail-under` gates CI) |
| `binary <add\|remove\|list\|clear> [<path>]` | Manage persisted debug binaries for binary-oracle enrichment |
| `provenance [<name>]` | Provenance rollup across all runs |
| `show <run>` | One run's provenance detail |
| `threat-model <action> [args]` | Manage the project threat-model artefact |
| `correlate [<name>]` | Cross-run finding correlation |
| `findings [<name>] [--detailed]` | Show merged findings (or per-finding detail) |
| `annotations [<name>] [--status S] [--source S] [--file PATH] [--cwe X] [--rule-id P] [--grep T] [--since 7d]` | List annotations across all runs (project-level overrides run-level) |
| `annotations-diff <run-a> <run-b>` | Compare annotation state between two runs |
| `none` | Clear the active project |
| `use [<name>]` | Set active project (no arg = show current, `none` = clear) |
| `delete <name> [--purge] [--yes]` | Remove project (--purge also deletes output) |
| `rename <old> <new>` | Rename a project |
| `notes <name> [<text>] [--file <path>]` | View or update notes |
| `description <name> [<text>]` | View or update description |
| `add <name> <dir> [--target <path>]` | Add existing runs to a project |
| `remove <name> <run> --to <path>` | Move a run out of the project |
| `report [<name>]` | Generate merged report across all runs |
| `diff <name> <run1> <run2>` | Compare findings between two runs |
| `merge [<name>] [--type <type>] [--yes]` | Merge runs per command type (destructive) |
| `clean [<name>] [--keep <n>] [--dedup] [--dry-run] [--yes]` | Delete old runs, keep latest n |
| `export <name> <path> [--force]` | Export project as zip (prints sha256) |
| `import <path> [--force] [--sha256 <hash>]` | Import project from zip |
| `trust [<marker>] [<name>]` | List trust assertions (markers + binaries count), or set a marker: `config` / `build` / `dynamic` |
| `untrust <marker> [<name>]` | Remove a trust marker |
| `set [<key> <value>] [<name>]` | List settings, or set a registry key (`description`, `notes`, `threat-model`, `target-kind`, `build-command[.<lang>]`) |
| `unset <key> [<name>]` | Remove a setting |
| `get <key> [<name>]` | Print one setting's bare value (exit 1 when unset) |

## Execution

Run project commands via the Bash tool:

```bash
libexec/raptor-project-manager <subcommand> [args]
```

For destructive commands (`merge`, `clean`, `delete --purge`), confirm with the user before running with `--yes`.

## Output

Run the command via Bash, then output the result verbatim in a fenced code block. Do not summarise, truncate, or paraphrase — the user needs exact run names, paths, sizes, and status values.

## Active project

When a project is active (via `/project use <name>`), subsequent commands write their output to the project directory instead of generating timestamped dirs under `out/`.

ARGUMENTS: $ARGS
