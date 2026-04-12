---
description: Manage RAPTOR projects — create, list, status, coverage, findings, diff, merge, report, clean, export
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
| `create <name> --target <path> [-d <desc>]` | Create a new project |
| `list` | Show all projects (* marks active) |
| `status [<name>]` | Show project summary with run history |
| `coverage [<name>] [--detailed]` | Show tool coverage summary (or per-file table) |
| `findings [<name>] [--detailed]` | Show merged findings (or per-finding detail) |
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
| `clean [<name>] [--keep <n>] [--dry-run] [--yes]` | Delete old runs, keep latest n |
| `export <name> <path> [--force]` | Export project as zip (prints sha256) |
| `import <path> [--force] [--sha256 <hash>]` | Import project from zip |

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
