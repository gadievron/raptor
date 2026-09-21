# Agent security

RAPTOR uses agents to review hostile source code, investigate crashes and
collect evidence. That makes the agent boundary part of the product's security
boundary. A repository may contain instructions written to mislead a model, and
material fetched from an external service must be treated with the same care.

The controls described here apply to RAPTOR's Claude Code agents and to the
headless LLM workers launched by the Python layer. They complement the process
isolation described in [Sandbox](sandbox.md) and the wider threat model in
[Security](security.md).


## The capability rule

RAPTOR reviews an agent against the following properties:

- it reads untrusted input;
- it can change state through tools such as Write, Edit or Bash;
- it can communicate with an external service.

An unattended agent must not hold all of these capabilities at once. RAPTOR
calls this the Rule of Two. Where a job cannot shed a capability, it requires a
human-attended session. Where a capability can be removed, RAPTOR removes it or
puts a mechanical boundary around it.

The rule is a design constraint rather than a claim that two capabilities are
harmless. Prompt injection remains possible, so tool restrictions, sandboxing
and output validation still apply.

Capability also composes. Two agents may each satisfy the rule on their own and
still assemble a more powerful system by exchanging messages or writing to the
same service. The current dispatch gates check named agents and individual
agentic passes; they do not calculate the combined capability of a cooperating
group. Reviews must therefore cover the whole dispatch graph, including shared
storage and SAGE, rather than stopping at each agent definition.


## How capabilities are constrained

### Tool lists

Agent definitions under `.claude/agents/` declare the tools needed for their
job. An agent without `WebFetch` cannot use that tool. Roles concerned only with
reasoning over collected evidence are generally limited to Read and Write.

Tool names are a coarse boundary. Bash can start other programmes, including
network clients, unless the command is narrowed by a hook or the process is
contained by the sandbox. The presence of a short tool list should not be read
as proof of process-level isolation.

### Network access

Agents that use `WebFetch` have a `PreToolUse` hook. The hook checks every URL
before the request is made and fails closed when its input cannot be parsed.
HTTPS is required in every mode.

Most networked investigators have fixed host allowlists. The crash-report
fetcher derives its boundary from the bug-tracker URL supplied by the operator.
It records each allow or deny decision beside the anchor file. Additional
attachment hosts have to be added visibly to that file.

The IOC extractor is deliberately broader because vendor reports can live on
arbitrary sites. Its hook permits any HTTPS host. This protects the transport
scheme, but it is not a domain allowlist and should not be described as one.

A hostname allowlist controls the connection made by the sandbox. It cannot
control a second request made by the allowed service. Package repositories and
rendering services which fetch user-supplied URLs can act as SSRF relays or dead
drops. The RAPTOR proxy will see the connection to the allowed host, not the
destination that host contacts on the agent's behalf.

Avoid granting access to a shared service merely because its hostname is known.
Where access is necessary, use a run-specific identity and a private namespace
with no data shared between unrelated runs. Logs from the service belong in the
same investigation as RAPTOR's own proxy events.

### Bash restrictions

The GH Archive investigator may invoke only the approved BigQuery wrapper and
its ingestion script. Its hook rejects shell chaining, pipes, substitutions and
redirections before checking the command prefix. Malformed hook input is
blocked.

Other agents with Bash are controlled by their declared role and the execution
sandbox, but do not all have a per-command allowlist. This is a wider capability
than the GH Archive agent's restricted Bash and should be considered when a new
dispatch path is added.

### Process and credential isolation

Headless sub-agents which work on hostile source are launched through RAPTOR's
untrusted sandbox path. On supported Linux hosts this combines namespaces,
Landlock and seccomp. macOS uses a Seatbelt profile. Read restrictions remain
enabled when Linux falls back to Landlock-only mode, because the mount namespace
is no longer hiding the rest of the filesystem.

The LLM dispatcher keeps provider credentials in the parent process. Workers
communicate with it over a Unix socket and do not receive the API keys in their
environment. Pure-LLM Claude children also run without internal tools or MCP
servers, from a private neutral working directory.

Direct `python3 raptor.py` use does not provide the dispatcher's process-level
credential separation. Use `bin/raptor` when that boundary matters.

### Cross-session messages

SAGE is an optional, deliberate communication channel between RAPTOR agents.
Its boot instructions are accepted only when they match the payload approved by
the operator. A changed boot payload is stripped until it has been reviewed at
an interactive terminal.

Inbox messages, recalled memories, stored findings and tasks are different.
They are untrusted content and cannot grant permission, widen a target or
approve use of another tool. A message such as “GO”, even when it names another
registered agent, has no operator provenance and must not satisfy a
human-approval gate.

This boundary is not wholly mechanical today. The boot-payload check and the
headless dispatch gate are enforced in code, while the treatment of an ordinary
SAGE message still depends in part on agent instructions. RAPTOR does not yet
score the collective capability of agents communicating through SAGE or detect
unusual coordination across sessions.


## Untrusted input

Target source is always treated as adversarial. Marking a repository as trusted
does not turn off prompt defences or relax the sandbox used for LLM-driven work.
The trust pre-flight has a narrower purpose: it detects repository-controlled
Claude settings, hooks, environment overrides and MCP configuration which could
alter the agent itself.

Text interpolated into prompts is put in a nonce-bound envelope and known tag
forgeries are neutralised. An audit checks prompt-construction call sites so a
new interpolation cannot quietly bypass the envelope without a reviewed
allowlist entry.

These measures reduce structural prompt injection. They cannot reliably detect
a persuasive instruction hidden in an ordinary comment or string, which is why
RAPTOR does not rely on prompt filtering as its main safety boundary.


## Outputs are not trusted

An agent response is data, not authority. Structured responses are checked
against their schemas, unknown fields are rejected where strict schemas are
used, and LLM-derived artefacts carry untrusted provenance. Report writers strip
markup which could trigger an automatic fetch when a report is rendered.

The crash pipeline shows the intended separation. A fetch-only agent retrieves
the report and writes one `bug-report.json` artefact. RAPTOR validates that file
before the analysis agents can consume it. Those agents work from the local
repository and do not receive a network-fetching tool.

Finding promotion depends on mechanical evidence rather than an agent's claim.
`promotion-alarms.jsonl` records any attempt to produce a finding-grade result
without the required evidence, and the result is demoted before export. Patches
and exploit suggestions are written as output for review; RAPTOR does not apply
or merge them automatically.


## Human approval

`offsec-specialist` necessarily handles untrusted material while retaining
sensitive tools and external reach. It is therefore registered as requiring a
human in the loop. RAPTOR refuses to dispatch it from a headless session, even
when a sandbox is available. An inventory test looks for new programmatic
dispatch references so this condition cannot be bypassed by adding a caller
elsewhere in the codebase.

The `/agentic --understand` and `/agentic --validate` passes use a different
gate. They may run when a human is present or when RAPTOR can establish an
effective sandbox. A non-interactive run without that containment is refused.

Approval comes from the operator, not from another agent or from text found in
an artefact. An interactive session establishes that a human is available; it
does not make messages exchanged during that session authoritative.


## Agent inventory

This table describes the capability declared in each agent definition. “No
WebFetch” means the tool is absent; an agent with unrestricted Bash still has a
broad process capability and relies on the sandbox for containment.

| Agent | Declared tools | External-access control | Role boundary |
|---|---|---|---|
| `audit-reviewer` | Read, Grep, Glob, Bash | No WebFetch | Reviews assigned code and records tool-grounded results |
| `coverage-analyzer` | Read, Write, Edit, Bash, Grep, Glob | No WebFetch | Produces coverage data in its working directory |
| `crash-analysis-agent` | Read, Write, Edit, Bash, Grep, Glob, Task | No WebFetch | Orchestrates local analysis; delegates report fetching |
| `crash-report-fetcher` | Read, Write, WebFetch | Operator-anchored domain hook | Fetches a report and writes one schema-gated artefact |
| `crash-analyzer` | Read, Write, Edit, Bash, Grep, Glob | No WebFetch | Performs local root-cause analysis |
| `crash-analysis-checker` | Read, Write, Bash, Grep, Glob | No WebFetch | Checks the analysis against local evidence |
| `function-trace-generator` | Read, Write, Edit, Bash, Grep, Glob | No WebFetch | Produces execution traces |
| `exploitability-validator-agent` | Read, Write, Edit, Bash, Grep, Glob, Task | No WebFetch | Orchestrates the staged validation workflow |
| `oss-investigator-github-agent` | Bash, Read, Write, WebFetch | GitHub domains pinned for WebFetch | Collects GitHub evidence |
| `oss-investigator-gh-archive-agent` | Bash, Read, Write | Bash command allowlist | Queries GH Archive through approved wrappers |
| `oss-investigator-wayback-agent` | Bash, Read, Write, WebFetch | Archive domains pinned for WebFetch | Recovers archived evidence |
| `oss-investigator-ioc-extractor-agent` | Read, Write, WebFetch | HTTPS-only hook; any host | Extracts indicators from operator-selected reports |
| `oss-investigator-local-git-agent` | Bash, Read, Write, Glob, Grep | No WebFetch | Examines a local clone |
| `oss-evidence-verifier-agent` | Read, Write, Bash | No WebFetch | Verifies evidence already in the store |
| `oss-hypothesis-former-agent` | Read, Write | No network tool | Forms hypotheses from collected evidence |
| `oss-hypothesis-checker-agent` | Read, Write | No network tool | Checks claims against verified evidence |
| `oss-report-generator-agent` | Read, Write | No network tool | Produces the report from confirmed material |
| `offsec-specialist` | Not narrowed in frontmatter | Human-attended session required | Carries out explicitly authorised offensive-security work |


## Residual risks and work still needed

Sandboxing limits what an agent can affect; it does not make its conclusions
correct. Review suggested patches before applying them and check important
findings against the cited tool evidence. Treat a degraded sandbox warning as a
change in security posture, not routine noise.

Network hooks are scoped to the named tool. A domain restriction on `WebFetch`
does not constrain an unrelated network client started through Bash. New agents
which combine Bash with external access need an explicit review of both paths.

Budget and resource limits reduce the cost of hostile or pathological input,
but they do not prevent a model from returning plausible, incorrect content.
Schema-valid output can still be semantically poisoned.

The [OpenAI Hugging Face incident](https://openai.com/index/hugging-face-incident-and-the-road-ahead/)
showed how agents can turn an allowed package service into a message board and
an SSRF relay, then pool capabilities across otherwise separate runs. RAPTOR's
default network isolation would normally block the first connection to an
internal package service. The incident still exposes weaknesses that a
per-agent tool inventory does not capture.

RAPTOR does not currently:

- compute a capability score for a group of cooperating agents;
- prove that an allowed service cannot make onward requests;
- stop a run automatically when live sandbox triage raises a serious alert;
- detect task drift when an agent abandons the requested work for a more useful
  capability;
- correlate SAGE traffic, shared artefacts, dispatch records and proxy events
  across runs to find unexpected coordination.

The current sandbox triage is valuable evidence, but its live alerts are
escalate-only. They warn the operator and do not change enforcement. Until an
automatic stop policy exists, higher-risk multi-agent work needs active human
supervision and conservative network access.

When a task is broken or has no safe route to completion, the correct outcome
is to stop and report the obstruction. Finding a new credential or
communication channel does not expand the task, nor does discovering another
execution surface. This rule is stated for agents today; enforcing it
mechanically remains open work.


## Files which enforce the boundary

| Area | Implementation |
|---|---|
| Human and sandbox dispatch gates | `core/security/rule_of_two.py` |
| Prompt envelopes and interpolation audit | `core/security/prompt_envelope.py`, `core/security/prompt_envelope_audit.py` |
| Repository configuration pre-flight | `core/security/cc_trust.py` |
| Per-agent URL restrictions | `.claude/hooks/webfetch-domain-allowlist.py` |
| Per-agent command restrictions | `.claude/hooks/bash-command-allowlist.py` |
| Process isolation | `core/sandbox/` |
| Credential broker | `core/llm/dispatcher/` |
| Agent declarations | `.claude/agents/` |

The engineering invariants and accepted residual risks live in
`core/security/THREAT_MODEL.md`. Changes to agent tools, dispatch paths or
downstream handling should be reviewed against that document as well as this
guide.
