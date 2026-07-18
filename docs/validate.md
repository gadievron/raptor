# The `/validate` Guide — Exploitability Validation

The `/validate` command proves that a vulnerability finding is **real**, **reachable**,
and **exploitable** before you spend time writing an exploit or a patch. It exists to
kill three categories of waste:

1. **Findings that don't exist** — hallucinated files, functions, or code.
2. **Findings that aren't reachable** — dead code, test-only paths, unrealistic preconditions.
3. **Findings that can't be exploited** — the bug is real, but system mitigations block every viable technique.

This guide covers what the command does and how to read its output. The step-by-step
methodology lives in the skill (`.claude/skills/exploitability-validation/`) and stays
there — this page is the operator's-eye view.

---

## What `/validate` does: a staged pipeline

`/validate` is **not** an automatic, flagless step that fires in the background. You
invoke it against a target, and it runs a fixed sequence of stages, in order:

```
0 → A → B → C → D → E → F → 1
```

The letters and numbers mean different things:

- **Letter stages (A, B, C, D, F)** are LLM reasoning. When you run `/validate` in
  Claude Code, *you (Claude) are the LLM* performing this work.
- **Number stages (0, E, 1)** are mostly mechanical — Python/`libexec` scripts that
  build inventory, analyse binary constraints, and generate the report.

| Stage | Type | What it does |
|-------|------|--------------|
| **0** | Mechanical | Inventory — build `checklist.json`, the ground-truth list of everything to check. |
| **A** | LLM | One-shot assessment — quick exploitability read, plus a proof-of-concept attempt. |
| **B** | LLM | Systematic analysis — attack trees, hypotheses, evidence, proximity tracking. |
| **C** | LLM | Sanity check — open each file, confirm the code is verbatim and the source→sink flow is real. |
| **D** | LLM | Ruling — final status per finding, plus CVSS vector selection. |
| **E** | Mechanical | Feasibility — binary constraint analysis. **Memory-corruption findings only.** |
| **F** | LLM | Self-review — "what did I get wrong?" Catches misclassifications and weak evidence. |
| **1** | Mechanical | Outputs — CVSS scoring, schema validation, report generation. Never changes verdicts. |

Two rules are worth committing to memory:

- **Stage E only runs for memory-corruption vulnerabilities** (buffer overflow, format
  string, use-after-free, heap overflow). Web and injection findings skip it.
- **Stage 1 never changes a verdict.** It computes scores and writes the report from
  whatever the reasoning stages already decided.

For the full methodology — prep scripts, per-stage gates, working-doc formats — read
`.claude/skills/exploitability-validation/PIPELINE.md` and `SKILL.md`. Do not expect a
"no flags needed, it just runs" experience: the value comes from the staged sequence,
and every stage is mandatory (except E for non-memory-corruption findings).

### Running it

```bash
# Validate every vulnerability type in a codebase
/validate ./src

# Focus on one class
/validate ./webapp --vuln-type command_injection

# Validate pre-existing scanner findings (skips the Stage A discovery pass)
/validate ./src --findings scanner-results.json

# Memory corruption, with a binary for Stage E feasibility
/validate ./vuln_app --vuln-type format_string --binary ./build/vuln

# Share an output directory with /understand
/validate ./src --out out/shared-run/
```

See [commands.md](commands.md) for the complete flag list.

---

## The two-layer model

`/validate` answers two different questions, and it takes two different kinds of
evidence to answer them. This is the two-layer validation model.

### Layer 1 — Exploitability validation (source-level)

**Question: is this finding real and reachable?**

| Aspect | Details |
|--------|---------|
| **Stages** | 0, A, B, C, D, F |
| **Input** | Source code + scanner findings |
| **Validates** | File exists, code matches verbatim, source→sink flow is real, not test/dead code |
| **Output** | Validated findings with working PoCs |
| **Lives in** | `.claude/skills/exploitability-validation/` |

### Layer 2 — Exploit feasibility (binary-level)

**Question: can this be exploited given the system's mitigations?**

| Aspect | Details |
|--------|---------|
| **Stage** | E (memory corruption only) |
| **Input** | Compiled binary |
| **Validates** | PIE, NX, stack canary, RELRO, glibc mitigations, ROP gadget quality, input bad-bytes |
| **Output** | A feasibility verdict + `chain_breaks` (what won't work) + `what_would_help` |
| **Lives in** | `packages/exploit_feasibility/` |

Layer 2 does empirical checks a static tool like `checksec` cannot: it actually probes
whether glibc blocks `%n`, whether `strcpy` null-bytes make a target address
unwritable, and whether any usable ROP gadgets exist. See
[exploit-feasibility.md](exploit-feasibility.md) for the details.

### When each layer applies

Every finding goes through Layer 1. Only memory-corruption findings continue into
Layer 2 — for web and injection bugs, "exploitability" is decided entirely at the
source level.

| Vulnerability type | Layer 1 (source) | Layer 2 (binary) |
|--------------------|:----------------:|:----------------:|
| Command injection  | Yes | No |
| SQL injection      | Yes | No |
| XSS                | Yes | No |
| Path traversal     | Yes | No |
| Buffer overflow    | Yes | **Yes** |
| Format string      | Yes | **Yes** |
| Use-after-free     | Yes | **Yes** |
| Heap overflow      | Yes | **Yes** |

---

## Reading the verdict: `final_status`

After Stage E, each memory-corruption finding carries a `final_status` derived from its
feasibility verdict. This is the field to read when deciding what to act on. Values are
snake_case in the JSON; the prose equivalents below are how they appear in reports and
chat.

| Feasibility verdict | `final_status` (JSON) | Means |
|---------------------|-----------------------|-------|
| `likely` / `likely_exploitable` | `exploitable` | Exploitable — standard techniques should work. |
| `difficult` | `confirmed_constrained` | Confirmed (Constrained) — primitives exist but are hard to chain. |
| `unlikely` | `confirmed_blocked` | Confirmed (Blocked) — no viable path under current mitigations. |
| `not_applicable` | `confirmed` | Confirmed — real and reachable; feasibility not applicable (e.g. a web vuln). |
| `binary_not_found` | `confirmed_unverified` | Confirmed (Unverified) — analysis incomplete (no binary, or the check could not run). |

A finding that fails Layer 1's sanity or ruling checks does not reach Stage E — it is
recorded as Ruled Out (`ruled_out`), and disproven hypotheses are tracked separately as
Disproven (`disproven`). Downstream steps such as `/exploit` skip Ruled Out, Disproven,
and Confirmed (Blocked) findings.

---

## The MUST-GATEs

The pipeline enforces eight validation gates. They exist because, left unchecked,
models sample instead of reading all the code, hedge with "if" and "maybe" instead of
verifying, and dismiss findings that turn out to be real. Full definitions are in
`.claude/skills/exploitability-validation/SKILL.md`.

| Gate | Rule | Prevents |
|------|------|----------|
| **GATE-1** (Assume-Exploit)   | Investigate as if exploitable until proven otherwise. | Premature dismissal |
| **GATE-2** (Strict-Sequence)  | Follow the methodology; present additional ideas separately at the end. | Methodology drift |
| **GATE-3** (Checklist)        | Track coverage against `checklist.json`. | Incomplete coverage |
| **GATE-4** (No-Hedging)       | Verify every "if / maybe / uncertain" claim — never leave it hanging. | Unverified hedging |
| **GATE-5** (Full-Coverage)    | Check all code. No sampling, estimating, or guessing. | Missed vulnerabilities |
| **GATE-6** (Proof)            | Show the vulnerable code for every finding. | Hallucinations |
| **GATE-7** (Consistency)      | Verify `vuln_type`, `severity`, and `status` match the description and proof. | Misclassifications |
| **GATE-8** (PoC-Evidence)     | A PoC needs observable evidence — a crash, changed output, callback. "Ran without error" is not evidence. | Unverified PoCs |

---

## Validation output

A run writes to a timestamped directory (or the project directory, or the `--out`
directory you passed). The layout:

```
out/exploitability-validation-<timestamp>/
├── checklist.json          # Stage 0: ground truth — every function/line to check
├── findings.json           # Cumulative findings; each stage merges into it
├── attack-surface.json     # Stage B: sources, sinks, trust boundaries
├── attack-tree.json        # Stage B: knowledge graph of the attack surface
├── hypotheses.json         # Stage B: tested exploitation hypotheses + status
├── disproven.json          # Stage B: failed approaches (what was tried, why it failed)
├── attack-paths.json       # Stage B: paths attempted + proximity scores + blockers
├── exploit-context.json    # Stage E: binary feasibility context (memory corruption only)
├── build/                  # Stage 0: scratch dir for compiling and running PoCs
├── diagrams.md             # Stage 1: Mermaid visual maps
├── summary.txt             # Stage 1: the findings/coverage summary printed to chat
└── validation-report.md    # Stage 1: the human-readable report
```

Notes:

- **`findings.json` is the record of truth.** Each stage writes a small `stage-X.json`
  that a prep script merges in and then deletes, so the per-stage files are transient —
  read `findings.json`, not the stage files.
- **`validation-report.md`** is the thing to read first. It groups findings by status
  and carries the proof, PoC evidence, and CVSS vectors.
- **`disproven.json` is not noise.** It documents what was tried and failed — the
  audit trail behind a Ruled Out verdict.

---

## Reasoning about dataflow findings: the five questions

Much of the Layer 1 reasoning (Stages C and D especially) comes down to one judgement:
a scanner reported a source→sink dataflow — is it *genuinely* exploitable, or a false
positive? The mental model is five questions. Answer them in order; the first "no" that
holds usually settles the finding.

1. **Source control** — Is the source actually attacker-controlled? An HTTP parameter
   is; a hardcoded constant or a build-time config value is not.
2. **Sanitizer effectiveness** — Do the sanitizers on the path truly prevent
   exploitation for *this* vulnerability class?
3. **Bypass** — If there is a sanitizer, can it be circumvented (encoding,
   case-sensitivity, incomplete filtering, wrong vuln class)?
4. **Reachability** — Can an attacker actually trigger this code path, or is it gated
   by auth/authz or unrealistic preconditions?
5. **Attack complexity** — If it is exploitable, how hard is it, and what payload works?

### Worked examples

**Example 1 — Weak crypto → Ruled Out.** A scanner flags
`Cipher.getInstance("AES/CBC/PKCS5Padding")`. Walking the questions: the algorithm
string is a **hardcoded constant** (Q1: not attacker-controlled). Changing it would
require modifying the source, not sending input. The mode is weak, but it is not a
runtime-exploitable vulnerability. Verdict: **Ruled Out** — a configuration issue, not
an exploitable finding.

**Example 2 — SQL injection with a weak sanitizer → Exploitable.** The source is
`request.getParameter("id")` (Q1: fully attacker-controlled). The path applies
`input.replace("'", "''")` (Q2: a sanitizer is present) but it only escapes single
quotes — a double-quoted or `UNION`-based payload sails past it (Q3: bypassable). The
tainted value reaches `executeQuery("SELECT ... WHERE id=" + id)` with no auth gate
(Q4: reachable). A payload like `?id=1" OR 1=1--` works with low complexity (Q5).
Verdict: **Exploitable**, with the bypass and payload recorded as evidence.

**Example 3 — XSS with an effective sanitizer → Ruled Out.** The source is again an
HTTP parameter (Q1: attacker-controlled), but the value passes through
`StringEscapeUtils.escapeHtml4(name)` before reaching the HTML writer. That is correct
HTML-entity encoding for this sink, with no known bypass (Q2 effective, Q3 no bypass).
The dangerous characters never reach the output as markup. Verdict: **Ruled Out** —
properly mitigated.

The point of the framework: a real vulnerability needs a "yes" at Q1 **and** either no
effective sanitizer or a working bypass **and** a reachable path. A single well-founded
"no" is enough to rule a finding out — but under GATE-1 you assume it is exploitable and
prove the "no" from the code, rather than guessing it.

---

## See also

- [commands.md](commands.md) — full `/validate` flag reference and workflow placement.
- [exploit-feasibility.md](exploit-feasibility.md) — how Layer 2 binary analysis works.
- `.claude/skills/exploitability-validation/PIPELINE.md` — the stage naming convention.
- `.claude/skills/exploitability-validation/SKILL.md` — gates, config, and per-stage detail.
