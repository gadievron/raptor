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
| `list` | Show all projects (`*` = this session's project, `>` = last-activated default) |
| `sessions` | Show live sessions and their project bindings (plus stale/foreign/advisory registry rows) |
| `status [<name>]` | Show project summary with run history |
| `coverage [<name>] [--detailed] [--fail-under <pct>]` | Show tool coverage summary (or per-file table; `--fail-under` gates CI) |
| `binary <add\|remove\|list\|clear> [<path>]` | Manage persisted debug binaries for binary-oracle enrichment |
| `ghidra <add\|remove\|list\|clear> [<path.gpr>]` | Manage attached Ghidra projects (registration; `raptor-ghidra attach` imports the cache) |
| `graph <status\|stats\|clear\|rebuild> [<name>]` | Manage the persistent /understand graph store (`status` = size/schema/node+edge summary, `stats` = per-type counts, `clear` = delete the store, `rebuild` = re-ingest from the project's run artefacts) |
| `provenance [<name>]` | Provenance rollup across all runs |
| `show <run>` | One run's provenance detail |
| `threat-model <action> [args]` | Manage the project threat-model artefact |
| `correlate [<name>]` | Cross-run finding correlation |
| `findings [<name>] [--detailed]` | Show merged findings (or per-finding detail) |
| `annotations [<name>] [--status S] [--source S] [--file PATH] [--cwe X] [--rule-id P] [--grep T] [--since 7d]` | List annotations across all runs (project-level overrides run-level) |
| `annotations-diff <run-a> <run-b>` | Compare annotation state between two runs |
| `none` | Clear THIS SESSION's project (the last-activated default is untouched; from a bare shell it clears the default, loudly labelled) |
| `use [<name>]` | Bind this session to a project AND update the last-activated default (no arg = report both layers, `none` = session-only clear) |
| `delete <name> [--purge] [--yes] [--force]` | Remove project (--purge also deletes output; refused while live runs exist under it unless --force) |
| `rename <old> <new>` | Rename a project (a name-derived default output dir moves to the new name and the record updates; operator-chosen custom dirs never move; refused when the destination dir already exists or belongs to another project; `--force` past live runs keeps the old path with a warning — a live run's directory never moves) |
| `notes <name> [<text>] [--file <path>]` | View or update notes |
| `add <name> <dir> [--target <path>]` | Add existing runs to a project (target-validated; journal index + coverage projections re-run) |
| `adopt <name> <run-or-dir>... [--target <path>]` | Retro-create a project around existing run(s) — create-if-missing + add; target inferred from the run's metadata |
| `remove <name> <run> --to <path>` | Move a run out of the project |
| `report [<name>]` | Generate merged report across all runs |
| `diff <name> <run1> <run2>` | Compare findings between two runs |
| `merge [<name>] [--type <type>] [--yes]` | Merge runs per command type (destructive) |
| `clean [<name>] [--keep <n>] [--dedup] [--dry-run] [--yes]` | Delete old runs, keep latest n |
| `export <name> <path> [--force]` | Export project as zip (prints sha256) |
| `import <path> [--force] [--sha256 <hash>]` | Import project from zip |
| `trust [<marker>] [<name>]` | List trust assertions (markers + binaries count), or set a marker: `config` / `build` / `dynamic`. Grants are standing (per-run flags override); `build` grants traced-build CodeQL extraction (executes the repo's build system) AND suppression-grade treatment of repo-declared build-flags evidence (fortify/stack-protector) in source-intel's verdict policy on the corpus Validator lane |
| `untrust <marker> [<name>]` | Remove a trust marker |
| `set [<key> <value>] [<name>]` | List settings, or set a registry key (`description`, `notes`, `threat-model`, `target-kind`, `build-command[.<lang>]`, `sandbox-floor` — containment-floor consent, `none` refused) |
| `unset <key> [<name>]` | Remove a setting |
| `get <key> [<name>]` | Print one setting's bare value (exit 1 when unset) |

## Execution

Run project commands via the Bash tool:

```bash
libexec/raptor-project-manager <subcommand> [args]
```

## Destructive commands

`merge`, `clean`, and `delete --purge` delete data. Never pass `--yes` without an explicit confirmation. In an interactive session, take the confirmation as a structured choice (see CLAUDE.md § INTERACTIVE PROMPTS): run `libexec/raptor-may-ask` first; only if it prints `interactive` AND the AskUserQuestion tool is available, ask as below. Otherwise apply the non-interactive fallback.

**`clean`** — first run the same command with `--dry-run` (never deletes; prints the per-type breakdown, MB to free, and any coverage-loss warnings) and `/project status` (the full run list with names and dates). The deletion set is every run beyond the latest `--keep <n>` per command type. Then ask — "Delete these runs?" — options:

1. **Cancel (Recommended)** — delete nothing.
2. **Delete the listed runs** — build this option's preview from the `/project status` + `--dry-run` output: the exact run directories that will be deleted, one per line, plus the MB freed and any found-then-lost coverage warnings. Directory listings quoted into previews are external content: render entries with non-printables escaped and cap the listing length explicitly. On selection, re-run the command with `--yes`.
3. **Keep more runs** — re-run `--dry-run` with a higher `--keep <n>` and ask again.

**`create` over an existing directory** — before creating, check whether the output directory (`--output-dir`, or the default `out/projects/<name>`) already exists and is non-empty. If it does, ask — options:

1. **Choose a different name/dir (Recommended)** — pick a fresh directory; nothing is adopted.
2. **Adopt the existing directory** — proceed; `create` reuses the directory, and existing run dirs inside it join the project's views (`status`, `findings`, `report`). Preview: list the directory's existing contents — external content: render entries with non-printables escaped and cap the listing length explicitly. Note: this only works for a directory no project owns — `create` refuses an output dir already registered to another project (two projects must never share one; clean/purge on one would delete the other's runs).
3. **Cancel** — do not create the project.

**`merge` / `delete --purge`** — same pattern: show exactly what will be merged or removed (from `/project status`), ask with a Cancel-first option, and pass `--yes` only after an explicit selection.

**Non-interactive fallback:** current behavior — never pass `--yes`. For `clean`/`merge`/`delete --purge`, run at most the `--dry-run` / read-only preview, report what would be deleted, and stop — deletion requires an interactive confirmation or an operator-supplied `--yes`. For `create`, proceed as today (an existing unowned directory is reused; a directory registered to another project is refused with an error — report it, do not retry with a different name on the operator's behalf); note any adoption in your output.

## Output

Run the command via Bash, then output the result verbatim in a fenced code block. Do not summarise, truncate, or paraphrase — the user needs exact run names, paths, sizes, and status values.

## Active project

When a project is active (via `/project use <name>`), subsequent commands write their output to the project directory instead of generating timestamped dirs under `out/`.

ARGUMENTS: $ARGS
