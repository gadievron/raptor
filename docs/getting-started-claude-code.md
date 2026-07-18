# Getting Started: Driving RAPTOR with Claude Code

RAPTOR is built to be driven from [Claude Code](https://docs.claude.com/en/docs/claude-code)
in plain English. You describe what you want to test; Claude picks the right
slash command, runs it, reads the results, and explains what it found. This is
the first stop for new users — clone, set up an LLM, and run your first scan.

For the full command catalog, see [commands.md](commands.md) — the single source
of truth for every slash command. This page teaches the setup and the workflow;
`commands.md` is the reference you keep open beside it.

---

## Setup (through Claude Code)

Four steps. Let Claude Code do the installs — just tell it what you want.

```bash
# 1. Clone and open in Claude Code
git clone https://github.com/gadievron/raptor.git
cd raptor
claude

# 2. Let Claude handle setup (talk to it, it runs the commands)
"Install Python packages from requirements.txt"
"Install semgrep"                                 # external tool, needed by /scan

# 3. Set up an LLM — choose ONE
"Set my ANTHROPIC_API_KEY to [your-key]"          # cloud, best quality
# OR
"Install Ollama and pull deepseek-r1 model"       # local, free, private

# 4. Run your first scan
/scan - check this repo for vulnerabilities
```

**Optional tools** — Claude Code offers to install these when a command needs them:

| Tool | Used for |
|------|----------|
| AFL++ | Binary fuzzing (`/fuzz`) |
| CodeQL | Deep dataflow static analysis (`/codeql`, and `/scan`/`/agentic` deeper passes) |
| rr + GDB | Crash analysis (`/crash-analysis`). Linux x86_64 only — `rr` has no macOS/Windows build. |

---

## How you talk to it

Just talk naturally. You do not need to memorise flags — describe the goal and
Claude maps it to a command:

```
/scan - find secrets and SQL injection in this directory
/fuzz - test ./myapp for crashes for 5 minutes
/web  - scan https://localhost:3000 for XSS
/agentic - do a full autonomous review of this repo
/raptor - I'm not sure what I need, help me secure this app
```

**Short form is canonical.** `/scan`, `/fuzz`, `/web` are the going-forward
names. The longer `/raptor-scan`, `/raptor-fuzz`, `/raptor-web` forms still work
as back-compat aliases, but prefer the short form.

**What Claude does with your request:** understands it in plain English → runs
the right RAPTOR command → analyses the results with adversarial prioritisation
→ explains the vulnerabilities → offers exploits, patches, and next steps. You
stay in a conversation the whole way; nothing is applied to your code unless you
say so.

---

## The command catalog (orientation)

The commands are grouped by where they sit in a security workflow. This is a map,
not the full reference — each group links into [commands.md](commands.md) for
params, examples, and the in-depth guides.

| Group | What lives here | Representative commands |
|-------|-----------------|-------------------------|
| **Plan & Setup** | Host/target pre-flight, projects, threat model | `/doctor`, `/describe`, `/project` |
| **Discover** | Static scanners, SCA, fuzzing, the orchestrator | `/agentic`, `/scan`, `/codeql`, `/sca`, `/fuzz`, `/web` |
| **Understand** | Adversarial code comprehension | `/understand`, `/binary` |
| **Analyse** | LLM analysis over existing findings, crashes | `/analyze`, `/crash-analysis` |
| **Validate** | Prove findings are real, reachable, exploitable | `/validate` |
| **Exploit & Patch** | PoCs and fixes (beta) | `/exploit`, `/patch`, `/cve-diff` |
| **Report & Manage** | Diagrams, annotations, scorecards | `/diagram`, `/annotate`, `/scorecard` |
| **Forensics** | GitHub forensic investigation | `/oss-forensics` |

A few entries worth calling out for newcomers:

- **`/agentic`** is the flagship. It runs the whole autonomous workflow — scan →
  dedup → prep → per-finding validate+analyse → self-review → optional
  consensus/judge/aggregate → exploit PoCs → patches → cross-finding analysis.
  Everything lands in `out/`; nothing is applied to your code. Reach for this
  when you want the most comprehensive pass rather than a single tool.
- **`/scan`** is the fast static pass: Semgrep by default, with CodeQL available
  for deeper passes. It emits SARIF findings and does **no** LLM analysis by
  itself — the LLM validation/analysis layer is what `/agentic` adds on top.
- **`/codeql`** is CodeQL-only deep dataflow analysis — slower than Semgrep, but
  finds tainted flows, use-after-free, and injection chains Semgrep misses.

See [commands.md](commands.md) for the complete catalog and every flag.

---

## Expert personas

RAPTOR ships expert methodologies (extracted from its own Python analysis code)
that you can invoke on demand for focused review. They load only when you ask for
them — **0 tokens until invoked** — and live in `tiers/personas/`.

**Invocation idiom** — name the persona and the task:

```
"Use exploit developer persona to create a working PoC for finding #42"
"Use crash analyst persona to analyse this AFL++ crash"
"Use fuzzing strategist persona to recommend AFL parameters"
"Use patch engineer persona to write a production-ready fix"
```

**Persona → purpose** (10 personas; source files live in `tiers/personas/`):

| Persona | Purpose |
|---------|---------|
| Exploit Developer | Generate working PoCs — real code, no TODO templates |
| Crash Analyst | Root-cause analysis of binary crashes |
| Security Researcher | Deep vulnerability validation, false-positive detection |
| Offensive Security Researcher | Exploitation feasibility — what's actually exploitable vs theoretical |
| Patch Engineer | Production-ready secure patches, not recommendations |
| Penetration Tester | Web payload generation |
| Fuzzing Strategist | Fuzzing decisions and AFL parameter selection |
| Binary Exploitation Specialist | Turning a crash into a working exploit |
| CodeQL Dataflow Analyst | Dataflow-path validation |
| CodeQL Finding Analyst | Triaging CodeQL findings (Mark Dowd methodology) |

---

## How Claude prioritises findings

When a scan returns many findings, Claude does not read them top-to-bottom — it
orders them adversarially so the highest-impact issues surface first.

**Priority order:**

1. **Secrets** — instant compromise, no exploitation needed
2. **Input validation** — SQLi, XSS, command injection (common, highly exploitable)
3. **Authentication** — broken access control (critical impact)
4. **Cryptography** — weak algorithms, hardcoded keys (data protection)
5. **Configuration** — debug mode, insecure defaults (security baseline)

**You can override this.** Tell Claude to use a different order for your threat
model (e.g. "prioritise auth and crypto — this is an internal-only service").

---

## Where results go

Every command writes to the `out/` directory regardless of how you invoked it.
A typical scan run looks like:

```
out/scan_<repo>_<timestamp>/
├── semgrep_*.sarif                  # Semgrep findings
├── codeql_*.sarif                   # CodeQL findings (if enabled)
├── scan_metrics.json                # statistics
├── autonomous_analysis_report.json  # LLM analysis (agentic runs)
├── exploits/                        # generated PoC code
└── patches/                         # secure fixes
```

In Claude Code these are read and summarised for you automatically; from the
shell you read the files directly. (With an active `/project`, runs land in the
project directory instead of a timestamped `out/` folder.)

---

## Troubleshooting

**No findings returned.** The most common cause is a missing `.git/` — Semgrep
needs the repository to be git-initialised. Other causes: wrong policy groups, or
a language the ruleset does not cover. Ask Claude "why no findings?" and it will
help diagnose.

**LLM errors.** RAPTOR falls back automatically (cloud → local Ollama), but if
analysis is failing outright, check:

- API key is set: `echo $ANTHROPIC_API_KEY`
- The account has sufficient credits
- Network connectivity to the provider
- If using Ollama: the server is running and the model is pulled

**Template / placeholder exploits or patches.** If a generated exploit is a stub
with TODO comments, or a patch reads as a recommendation rather than code, invoke
the specialist persona to finish it: "Use exploit developer persona to create a
working exploit for finding #X" or "Use patch engineer persona to write a
production-ready patch".
