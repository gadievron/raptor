# Threat Models in RAPTOR

RAPTOR now treats the threat model as a proper project artefact, not a bit of
vague chat that disappears once the model context rolls over. The idea is
simple: before we ask agents to go hunting, we give them a crisp view of what
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

The JSON is the source of truth. The Markdown is there so the team can read it
without needing to squint at a blob of JSON.

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
hardcoded secrets, and turns them into starter focus areas. It is not meant to
be perfect first time. It gives you a decent first pass so you can tidy it up
without starting from a blank page.

## Inspect It

```bash
raptor project threat-model show
raptor project threat-model show --json
raptor project threat-model export
raptor project status
```

`project status` now shows whether a threat model exists and how many focus
areas it has.

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

## Strict Sandbox Mode

There is also a new `--sandbox strict` profile for the awkward agentic cases
where degrading silently would be daft.

```bash
raptor agentic /path/to/code --sandbox strict
```

`full` is still the normal default and will warn if the host cannot provide a
layer. `strict` fails closed if the platform isolation backend is unavailable.
On Linux, if target/output isolation is requested, it also requires mount
namespaces. That is deliberately less forgiving, because autonomous work on a
hostile repo should not quietly continue with a weaker sandbox and a cheery
shrug.

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
