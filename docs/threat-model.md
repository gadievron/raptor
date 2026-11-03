# Threat Models in RAPTOR

[Documentation index](README.md)

A project threat model records assets, entry points, trust boundaries, review
priorities, and the evidence required to confirm findings. RAPTOR keeps it as
a persistent project artefact and uses it to guide analysis across runs.

Use this feature to define the security assumptions of the target you are
reviewing. For RAPTOR's own defences, see [security](security.md),
[agent security](agent-security.md), and [sandbox](sandbox.md).
For project commands, see the [command reference](commands.md#project).

**Related documentation:**
[Audit](audit.md) |
[Concepts](concepts.md) |
[Agent Security](agent-security.md)

**On this page:**

- [What Gets Created](#what-gets-created)
- [Create One](#create-one)
- [Inspect It](#inspect-it)
- [What To Put In It](#what-to-put-in-it)
- [How RAPTOR Uses It](#how-raptor-uses-it)
- [Strict Sandbox Mode](#strict-sandbox-mode)
- [Why This Helps](#why-this-helps)

## What Gets Created

For each project RAPTOR can keep:

- `threat-model.json` - canonical machine-readable model used by RAPTOR
- `THREAT_MODEL.md` - readable Markdown version for humans

The JSON is the source of truth; the Markdown is its human-readable view.

## Create One

Start with a normal project:

```bash
raptor project create myapp --target /path/to/code
raptor project use myapp
```

To generate the model as part of an analysis run:

```bash
python3 raptor.py agentic --repo /path/to/code --threat-model --validate
```

`--threat-model` implies `--understand`, creates the artefacts when they do not
exist yet, and hands unchecked-flow candidates into the normal analysis
pipeline. Existing project threat models are preserved by default because this
is operator-owned context, not disposable scanner output. Use
`--threat-model-refresh` when you deliberately want to overwrite the project
model from the latest map. Mapped unchecked flows can become analysis candidates
even when Semgrep or CodeQL produce no matching findings. They still require
validation.

If RAPTOR cannot produce a fresh `/understand` map, it may find an older one for
the same target. An existing map can be reused if it passes freshness checks;
stale maps are refused by default. Pass `--threat-model-use-stale` only when you
have checked the drift and want that older map anyway.

For a quick demo or first-look run:

```bash
python3 raptor.py agentic --repo /path/to/code --threat-model-only
```

That runs the map, creates or reuses the threat model, writes candidate SARIF,
then exits.

If you only want to manage the project artefact manually, initialise it with:

```bash
raptor project threat-model init
```

If you have already run `/understand --map`, you can seed it from the generated
`context-map.json`:

```bash
raptor project threat-model init --from-context-map out/projects/myapp/understand_20260605_090000/context-map.json
```

That pulls in mapped entry points, trust boundaries, sinks, unchecked flows,
hardcoded secrets, and turns them into starter focus areas. Secret VALUES are
redacted before they reach the threat-model artifacts — `threat-model.json`,
`THREAT_MODEL.md`, and report output carry `[REDACTED]` markers with the
variable name and file:line kept readable, never the literal credential. Review
the generated focus areas against the target before using them to guide an
analysis.

## Inspect It

```bash
raptor project threat-model show
raptor project threat-model show --json
raptor project threat-model export
raptor project status
```

`project status` shows whether a threat model exists and how many focus
areas it has. Beyond `show`/`export`, the subcommand surface also covers
`lint` (structural checks), `diff` (compare against the map), `report`,
`sync`, and `add`/`remove` for focus areas.

## What To Put In It

Keep entries specific to the target and actionable for a reviewer.

- assets: what would hurt if it went wrong
- entry points: where an attacker can start
- trust boundaries: where data changes from trusted-ish to untrusted
- trusted inputs: what RAPTOR should not waste time treating as attacker-owned
- untrusted inputs: requests, files, messages, metadata, dependencies, config
- in-scope vulnerability classes: the bugs that matter for this target
- out-of-scope classes: vulnerability classes excluded by the engagement
- focus areas: the places agents should look first
- known bug shapes: patterns we have seen before and want variants of
- verification expectations: what proof is good enough
- patch validation expectations: how to re-test fixes properly

Out-of-scope entries lower review priority. Concrete evidence can still
justify reporting a finding.

## How RAPTOR Uses It

When a project has a threat model, `/agentic` passes a compact threat-model
block into the `/understand` pre-pass, autonomous finding analysis, and the
`/validate` post-pass.

When the project also has `/understand` graph memory, RAPTOR adds a compact
graph-risk block built from unchecked source-to-sink paths. This gives the
model real attack-surface memory rather than just operator prose:

```text
Graph-backed risks from /understand memory:
- EP-003 GET /search -> SINK-004 template render: no output encoding (high)
```

That graph block is treated as target-derived signal. Use it for
priority and context; `/validate` or another oracle must confirm the claim.

The agents are told to use it as operator-owned context, not as proof. So it can
raise or lower priority, steer variant hunting, and reduce irrelevant candidates, but a
finding still needs code evidence or an oracle-backed validation result.

Good outcomes should come from things RAPTOR can actually stand behind:

- sandbox replay
- CodeQL proof or refutation
- fuzzer crash and replay
- web exploitation evidence
- manual confirmation where that is the honest answer

## Strict Sandbox Mode

Use `--sandbox strict` when the run requires the stricter containment contract.

```bash
python3 raptor.py agentic --repo /path/to/code --sandbox strict
```

`full` is the default profile. `strict` refuses when required isolation is
unavailable. The containment floor also governs which degraded hosts can run
untrusted code; see [sandbox profiles](sandbox.md#profiles) and the
[containment floor](sandbox.md#containment-floor) for the complete contract.

## Why This Helps

Without a project threat model, agents are good at producing plausible queues
of possible bugs. With one, RAPTOR can be much more deliberate:

- spend more time around real trust boundaries
- avoid re-reporting known false positives
- group findings by root cause rather than by scanner line number
- validate against the right attacker model
- re-attack patches so "fixed" means something

Use these priorities to evaluate findings and check whether a patch removes
the underlying defect.
