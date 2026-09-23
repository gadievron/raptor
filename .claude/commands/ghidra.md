---
description: Ghidra RE bridge — attach, import, diff, decompile, export findings
dispatch: libexec/raptor-ghidra <subcommand> [args]
---

# /ghidra - Ghidra RE Bridge

Import, query, and diff Ghidra `.gpr` projects, and export RAPTOR
findings back into them. The sandboxed `analyzeHeadless` subprocess is
the default engine (the JVM parses attacker-controlled project data);
in-process pyghidra engages only when headless is absent, or with
`RAPTOR_GHIDRA_IN_PROCESS=1` (operator trust assertion — no sandbox).
Raw binaries get a Ghidra project created for them first; without a
Ghidra install they degrade to r2, then objdump.

## Subcommands

```
/ghidra attach <project.gpr> [--enrich] [--decompile-all] [--timeout <s>]
/ghidra detach [<project.gpr>]
/ghidra status
/ghidra import <project.gpr | binary> [--out <dir>] [--enrich] [--decompile-all] [--timeout <s>]
/ghidra diff <old.gpr> <new.gpr> [--matched] [--program <name>] [--decompile-all] [--out <dir>] [--label-old <v1>] [--label-new <v2>] [--json] [--timeout <s>]
/ghidra decompile <project.gpr> <function_name_or_addr> [--timeout <s>]
/ghidra list <project.gpr>
/ghidra export <out-dir> [--to <project.gpr>] [--target <path>]
```

### attach / detach / status

Persistent binding to the active RAPTOR project. `attach` registers
the `.gpr` on the project (`ghidra_projects`, also managed via
`/project ghidra add|remove|list|clear`), imports it, and caches the
database under
`<project output>/ghidra-attach/<name>-<hash>/re-database.json` (the
hash disambiguates same-named attachments, e.g. two firmware
versions; run management skips the `ghidra-attach` directory by name,
and it must NOT be dot-prefixed — Ghidra refuses project paths
containing hidden directories). The import runs under the sandbox
when `analyzeHeadless` is on `PATH`; with only pyghidra installed it
falls back in-process (logged — an operator trust call, same as
`RAPTOR_GHIDRA_IN_PROCESS=1`). Analysis runs (/agentic) then inject
the CACHED types and xrefs into review prompts automatically —
decompilation blocks appear only when the attach ran with
`--decompile-all` (a plain attach caches metadata without
decompilation, and a plain RE-attach discards previously cached
decompilation — the CLI warns). Cache-only by design: the
attacker-controlled bundle is parsed at attach time, never unprompted
at run start. Note the two engines differ in extraction fidelity
(comment/type counts can shift when an attachment is re-imported by
the other engine). `export` without `--to` syncs findings into every
attached project. `detach` with no argument releases all attachments;
`status` lists attachments and their cache state. `--wait` on
attach/detach blocks on a busy project lock instead of failing fast.
The binding is operator-initiated only — nothing harvests `.gpr`
files from the scanned repo, and cached databases are read
exclusively from RAPTOR-owned output locations.

### import

One-shot import of a Ghidra project into RAPTOR's REDatabase format.
Exports functions, xrefs, types, comments, segments, imports, exports,
strings, and bookmarks to `re-database.json`.

Engine fallback: a sandboxed `analyzeHeadless` (from `PATH`) is the
default; with only pyghidra installed the import runs in-process.

Passing a **raw binary** instead of a `.gpr` first CREATES a Ghidra
project from it — sandboxed `analyzeHeadless -import` with full
auto-analysis, written to
`<out-dir>/ghidra-project/<binary-stem>/raptor.gpr` (a RAPTOR-owned,
symlink-free location) — then continues through the normal project
import, so `--decompile-all` and `--enrich` apply. The create step is
minutes-long on large binaries; an unset `--timeout` defaults to
3600s for it. An occupied destination (a re-run) is a TERMINAL error
— pass the existing `.gpr` directly to reuse it, or remove the
directory; it never degrades, since the fallback would overwrite the
existing full-fidelity `re-database.json`. Only when no Ghidra
install is present, or the create itself fails (the reason is
printed; a failed create removes its own partial project files), does
the import degrade to the r2 importer, then objdump (reduced
fidelity: no decompilation or types; noted in the database metadata).

- `--enrich` — also run r2 analysis on the binary and merge results
- `--decompile-all` — decompile every function (slow on large binaries)
- `--program <name>` — specific program in a multi-binary project
- `--timeout <s>` — headless import timeout (default 300, or 3600
  with `--decompile-all` / for the raw-binary create step)

### diff

Cross-version comparison of two Ghidra projects. Matches functions by
name and reports added/removed/changed functions, comment deltas, and
import changes. Human output ends with the priority review targets
(added/changed functions, auto-named excluded); `--json` emits the full
`version-diff.json` document instead.

- `--label-old` / `--label-new` — human labels for the versions
- `--matched` — match functions across versions by the tier cascade
  (exact name → normalized decompilation hash → string/import anchors →
  call-graph propagation → decompilation similarity) instead of by
  name. Use whenever either side is stripped or symbols were renamed:
  renamed functions report as changes (with `name_new` and the match
  tier) rather than an added+removed pair, a pure rename or rebase does
  not read as a code change, and ambiguous functions stay unmatched
  rather than being force-paired. A pair whose structure matches but
  whose hex constants differ reports `constants changed`; call-target
  differences (mapped through the match) report `call targets
  changed`. Writes `binary-match.json` (pairs with tier + score,
  unmatched sets, stats) next to `version-diff.json`. Matching
  quality depends on decompilation coverage — import both projects
  with `--decompile-all` first for best results (the CLI hints when
  coverage is low).

**Patch-diff workflow** (find what a security fix changed): import the
pre-patch and post-patch binaries into two `.gpr` projects, run
`/ghidra diff old.gpr new.gpr --matched`, then start the audit from
the changed functions — they carry each pair's match tier so low-tier
(similarity-matched) pairs get verified first.

### decompile

Decompile a single function on demand. Accepts a function name or hex
address. Order: cached decompilation from a prior `--decompile-all`
import (no JVM), then the sandboxed persistent decompile server, then
in-process pyghidra (only when in-process is the preferred engine),
then objdump disassembly from a cached `re-database.json` (degraded).

### list

List programs (imported binaries) inside a Ghidra project.

### export

Write RAPTOR findings from an output directory into the Ghidra project
as comments and bookmarks (operator reviews them in Ghidra). Without
`--to`, exports to every ATTACHED project; with `--to`, to that .gpr
explicitly. All sources (agentic results, audit journal, annotations)
are gathered into ONE apply pass; counts printed are submissions —
names that don't resolve in the binary are skipped during apply.
Ghidra project comments travel the other way only as review-prompt
context — never into `/annotate` (annotations are human-written only).
