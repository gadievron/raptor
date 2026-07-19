# The `/validate` Guide — Exploitability Validation

The `/validate` command proves that a vulnerability finding is **real**, **reachable**,
and **exploitable** before you spend time writing an exploit or a patch. It exists to
kill three categories of waste:

1. **Findings that don't exist** — hallucinated files, functions, or code.
2. **Findings that aren't reachable** — dead code, test-only paths, unrealistic preconditions.
3. **Findings that can't be exploited** — the bug is real, but system mitigations block every viable technique.

The step-by-step methodology lives in the skill
(`.claude/skills/exploitability-validation/`) and stays there; this page is the
operator's-eye view — what the command does and how to read its output.

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

Two rules:

- **Stage E only runs for memory-corruption vulnerabilities** (buffer overflow, format
  string, use-after-free, heap overflow). Web and injection findings skip it.
- **Stage 1 never changes a verdict.** It computes scores and writes the report from
  whatever the reasoning stages already decided.

For the full methodology — prep scripts, per-stage gates, working-doc formats — read
`.claude/skills/exploitability-validation/PIPELINE.md` and `SKILL.md`. The value comes
from the staged sequence, and every stage is mandatory (except E for
non-memory-corruption findings).

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
| `exploitable` | `exploitable` | Exploitable — standard techniques should work. |
| `likely_exploitable` | `likely_exploitable` | Likely exploitable — usable primitives, some uncertainty remains. |
| `difficult` | `confirmed_constrained` | Confirmed (Constrained) — primitives exist but are hard to chain. |
| `unlikely` | `confirmed_blocked` | Confirmed (Blocked) — no viable path under current mitigations. |
| `not_applicable` | `confirmed` | Confirmed — real and reachable; feasibility not applicable (e.g. a web vuln). |
| `binary_not_found` | `confirmed_unverified` | Confirmed (Unverified) — analysis incomplete (no binary, or the check could not run). |

A finding that fails Layer 1's sanity or ruling checks does not reach Stage E — it is
recorded as Ruled Out (`ruled_out`), and disproven hypotheses are tracked separately as
Disproven (`disproven`). Downstream steps such as `/exploit` skip Ruled Out, Disproven,
and Confirmed (Blocked) findings.

### Non-memory-corruption verdicts: `_derive_verdict_from_source`

Web/injection findings never enter Stage E (no binary feasibility check runs), so they
need a verdict derived from Stage B/C source-level analysis alone. `_derive_verdict_from_source`
(`packages/exploitability_validation/orchestrator.py`) does that, reading the
`chain_breaks` and `what_would_help` lists Stage B/C attached to the finding:

| `chain_breaks` | `what_would_help` | Verdict | Rationale |
|:---:|:---:|---|---|
| present | present | `difficult` | Blockers exist, but so do routes around them. |
| present | empty | `unlikely` | Blockers exist and nothing was found to work around them. |
| empty | present | `difficult` | No blockers found, but open unknowns remain — not fully confirmed. |
| empty | empty | `likely_exploitable` | No blockers, no open unknowns. |

**Precondition cap:** if the finding also carries non-trivial `preconditions` (e.g.
"requires uid 0", "requires local access") and the rule above would land on
`likely_exploitable`, the verdict is capped down to `difficult` instead — a real
precondition means it isn't a clean "just send the payload" case even when nothing
else blocks it.

The derived verdict is then mapped to `final_status` for these findings via
`_finalize_non_memory_findings`'s own `verdict_mapping`: `exploitable` → `exploitable`,
`likely_exploitable` → `likely_exploitable`, `difficult` → `confirmed_constrained`,
`unlikely` → `confirmed_blocked`, `unknown` / `error` → `confirmed_unverified`. This is
a separate mapping from the memory-corruption `final_status` table above — it runs for
findings that skip Stage E entirely.

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

## SARIF ingestion & deduplication

When `--findings` points at a SARIF file, Stage 0 converts each result into an internal
finding and deduplicates so the same underlying bug reported by multiple tools (e.g.
Semgrep + CodeQL both flagging the same line) collapses into one finding instead of
being counted, and reviewed, twice. Two dedup passes cooperate, both in
`packages/exploitability_validation/orchestrator.py`:

1. **At SARIF conversion** (`convert_sarif_result`) — the rule ID is normalized to a
   canonical `vuln_type` (`normalize_rule_id()`), then a fingerprint is computed: the
   SARIF tool's own `fingerprints.primaryLocationLineHash` if present (this is the
   validation orchestrator's own key naming, distinct from the SARIF-spec
   `partialFingerprints` key the upstream `/agentic`/`/scan` merge dedup uses below),
   otherwise `"{file}:{line}:{normalized_vuln_type}"`. A result whose fingerprint was
   already seen is dropped.
2. **After ingestion** (`_deduplicate_findings`) — a second, coarser pass runs over the
   full findings list (whether it came from SARIF conversion or a pre-existing findings
   JSON) keyed on **`(file, line, vuln_type)`**. This catches duplicates that survive
   step 1 because they carried different tool-supplied fingerprints.

The key is on the *normalized* vuln type, not the raw rule ID, so `CWE-89`,
`java/sql-injection`, and a Semgrep rule ID all ending up as `sql_injection` will dedup
against each other even though their raw rule IDs differ.

This is distinct from the SARIF-merge dedup used upstream by `/agentic` and `/scan`
(`core/sarif/parser.py`, keyed on `(ruleId, uri, startLine, endLine, startColumn,
partialFingerprint)`), which runs earlier, when raw SARIF files from multiple tools are
merged before `/validate` ever loads them.

---

## Validation output

A run writes to a timestamped directory (or the project directory, or the `--out`
directory you passed). The layout:

```
out/validate_<target>_<timestamp>_pidNNNNN/
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
