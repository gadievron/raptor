# Threat Models in RAPTOR

RAPTOR treats the threat model as a proper project artefact, not a bit of
vague chat that disappears once the model context rolls over. Before we ask
agents to go hunting, we give them a crisp view of what
matters, where trust changes hands, what noise to ignore, and how a finding
must be proved before anyone gets excited.

This is very much inspired by the better bits of modern agentic security work:
map the target, pick focus areas, verify independently, dedupe by root cause,
and re-attack patches instead of assuming a diff magically fixed the issue.
Less vibes, more evidence.

## What Gets Created

For each project RAPTOR can keep:

- `threat-model.json` - canonical machine-readable model used by RAPTOR
- `THREAT_MODEL.md` - readable Markdown version for humans

The JSON is the source of truth.

## Create One

Start with a normal project:

```bash
raptor project create myapp --target /path/to/code
raptor project use myapp
```

The least faffy way is to let `/agentic` do the whole thing:

```bash
python3 raptor.py agentic --repo /path/to/code --threat-model --validate
```

`--threat-model` implies `--understand`, creates the artefacts when they do not
exist yet, and hands unchecked-flow candidates into the normal analysis
pipeline. Existing project threat models are preserved by default because this
is operator-owned context, not disposable scanner output. Use
`--threat-model-refresh` when you deliberately want to overwrite the project
model from the latest map. If Semgrep or CodeQL miss something the map already
proved is interesting, RAPTOR still has a candidate to work with instead of
just shrugging at an empty SARIF pile.

If RAPTOR cannot produce a fresh `/understand` map, it may find an older one
for the same target. Fresh old maps can be reused, but stale maps are refused
by default because analysing yesterday's attack surface is a bit pants. Pass
`--threat-model-use-stale` only when you have checked the drift and want that
older map anyway.

For a quick demo or first-look run:

```bash
python3 raptor.py agentic --repo /path/to/code --threat-model-only
```

That runs the map, creates or reuses the threat model, writes candidate SARIF,
then exits.

If you only want to manage the project artefact manually, initialise it with
`/threat-model init` (see [The /threat-model Command](#the-threat-model-command)), which is equivalent to the raw CLI:

```bash
raptor project threat-model init
```

If you have already run `/understand --map`, you can seed it from the generated
`context-map.json`:

```bash
raptor project threat-model init --from-context-map out/projects/myapp/understand_20260605_090000/context-map.json
```

That pulls in mapped entry points, trust boundaries, sinks, unchecked flows,
hardcoded secrets, and turns them into starter focus areas. It is not meant to
be perfect first time. It gives you a decent first pass so you can tidy it up
without starting from a blank page.

## The `/threat-model` Command

`/threat-model` is the first-class command surface for managing the artefact
day to day, once it exists. It dispatches to `libexec/raptor-threat-model
<command> [args]`, which is deliberately a thin router and not a second
implementation: `show`/`init`/`export`/`sync`/`lint`/`diff`/`report`/`add`/`remove`
call through to the project-manager's threat-model path, and
`build`/`refresh`/`use-stale` call through to `/agentic`'s
`--threat-model-only` phase. With no command given, it defaults to `show`.

| Command | Does |
|---|---|
| `show [project]` | Show the active/project threat model summary |
| `init [project]` | Create a blank project threat model (or seed one via `--from-context-map <path>`) |
| `export [project]` | Print `THREAT_MODEL.md` |
| `sync [project]` | Re-render `THREAT_MODEL.md` from the JSON |
| `lint [project]` | Run quality gates over the saved model |
| `diff [project] --context-map <path>` | Compare the saved model against a fresh `/understand` map |
| `report [project] [--context-map <path>]` | Write `threat-model-report.md` with threats, evidence, drift and quality gates |
| `add --field <field> --value <text>` | Add a value to a string-list field (e.g. `focus_areas`, `assets`) |
| `remove --field <field> --value <text>` | Remove a value from a string-list field |
| `build [agentic args]` | Run the `/understand`-backed threat-model-only phase |
| `refresh [agentic args]` | Rebuild and overwrite the project model |
| `use-stale [agentic args]` | Build while explicitly allowing stale `/understand` fallback |
| `help` | Show wrapper help |

```bash
libexec/raptor-threat-model show
libexec/raptor-threat-model show --json
libexec/raptor-threat-model lint
libexec/raptor-threat-model diff --context-map out/understand_20260605_090000/context-map.json
libexec/raptor-threat-model report
```

`raptor project status` also shows whether a threat model exists and how many
focus areas it has, as a quicker check than the full `show` output.

## What To Put In It

Keep it punchy. A useful threat model does not need to read like a bank policy
document.

- assets: what would hurt if it went wrong
- entry points: where an attacker can start
- trust boundaries: where data changes from trusted-ish to untrusted
- trusted inputs: what RAPTOR should not waste time treating as attacker-owned
- untrusted inputs: requests, files, messages, metadata, dependencies, config
- in-scope vulnerability classes: the bugs that matter for this target
- out-of-scope classes: the stuff that is probably theoretical nonsense here
- focus areas: the places agents should look first
- known bug shapes: patterns we have seen before and want variants of
- verification expectations: what proof is good enough
- patch validation expectations: how to re-test fixes properly

The important bit: out-of-scope does not mean "never mention it". It means
"do not burn half a day on this unless the code gives us real evidence".

## How RAPTOR Uses It

When a project has a threat model, `/agentic` passes a compact threat-model
block into the `/understand` pre-pass, autonomous finding analysis, and the
`/validate` post-pass.

The agents are told to use it as operator-owned context, not as proof. So it can
raise or lower priority, steer variant hunting, and reduce rubbish, but a
finding still needs code evidence or an oracle-backed validation result.

Good outcomes should come from things RAPTOR can actually stand behind:

- sandbox replay
- CodeQL proof or refutation
- fuzzer crash and replay
- web exploitation evidence
- manual confirmation where that is the honest answer

## Why This Helps

Without a project threat model, agents are good at producing plausible queues
of possible bugs. With one, RAPTOR can be much more deliberate:

- spend more time around real trust boundaries
- avoid re-reporting known rubbish
- group findings by root cause rather than by scanner line number
- validate against the right attacker model
- re-attack patches so "fixed" means something

That is the direction of travel: RAPTOR should not just find more things. It
should get better at finding the right things, proving them, and knowing when a
patch actually killed the bug rather than just moved the furniture around.

For sandbox isolation levels available to threat-modelled agentic runs
(including `--sandbox strict` for autonomous work on hostile repos), see
[`sandbox.md`](sandbox.md).
