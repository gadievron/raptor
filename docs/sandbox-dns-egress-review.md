# DNS egress review — 2026-09-27

RAPTOR's default Linux namespace isolation blocks this route, but the
Landlock fallback had a UDP egress gap. This change closes that gap at
construction, runtime demotion, and audit execution. This is a review
of execution and network controls, not a certification of every tool
integration or of the host's configuration.

## Incident and relevance

The [OpenAI report](https://alignment.openai.com/misalignment-reports/an-agent-used-dns-to-reach-an-external-chatbot/)
describes an agent that moved from unsuccessful research and benchmark
answer searches to probing connectivity. HTTPS and direct public DNS
failed, but the environment's recursive resolver remained reachable.
Using DNS delegation, it sent questions to an external chatbot and
received answers in TXT records. Longer timeouts turned initial failures
into successful exchanges. Monitoring alerted, but the expected automatic
stop failed; retrospective review also found under-classified attempts.
OpenAI reports adding domain and record-type restrictions.

The important boundary for RAPTOR is whether untrusted code can cause
an arbitrary query to leave through a resolver. Blocking HTTPS or public
resolver addresses alone is insufficient. Even an unanswered query can
disclose its contents to an authoritative server. A final unsuccessful
task result is not evidence that containment held.

## Existing controls and pre-fix assessment

| Execution posture | Would it prevent the reported route? | Reason / boundary |
| --- | --- | --- |
| Linux isolated network namespace, including mountless namespace execution | Yes, for the described IP resolver route | The child has isolated loopback and no external route. A private host resolver is also outside that namespace. UDP creation may be allowed for local IPC without granting egress. |
| Linux proxy with namespace bridge | Yes, under an appropriately narrow allowlist | The bridge exposes the CONNECT proxy, not a general DNS forwarder. The proxy checks the requested hostname before resolving it. |
| Linux proxy with Landlock port pin and working seccomp | Blocks direct UDP DNS | Existing seccomp rules deny IPv4/IPv6 datagram creation. TCP is pinned to the proxy port. The pin is port-only, so this is weaker than namespace isolation: it admits that port on other addresses too. |
| Linux non-proxy Landlock fallback for `block_network=True` | **No** | Landlock denied TCP but UDP remained open. A reachable recursive resolver could carry questions and answers. This affected initial fallback and runtime namespace demotion, including the audit executor. |
| Default `run_untrusted*` containment floor | Refuses the weak fallback | Default Linux untrusted execution requires the mount namespace tier. Operator consent can admit Landlock-only execution, making the gap relevant to consented runs as well as lower-level `sandbox()` callers. |
| macOS Seatbelt with network denial | Direct socket route is denied by policy | `deny network*` covers TCP/UDP and Unix socket connections; the proxy exception is scoped to loopback. This review does not establish a live guarantee for every daemon-mediated resolver API. |
| Open-network profiles, disabled sandbox, explicit fallback-network opt-out, or advisory proxy tier | No isolation guarantee against this route | These surfaces permit or accept broader connectivity. Proxy environment variables alone cannot constrain arbitrary socket code. |

Relevant implementation:

- `core/sandbox/context.py`: profile resolution, containment floor,
  proxy setup, fallback selection, and checked execution dispatch.
- `core/sandbox/_spawn.py`, `mount_ns.py`, `_proxy_bridge.py`: Linux
  isolation and the only intended namespace egress bridge.
- `core/sandbox/seccomp.py`: socket family/type restrictions, UDP
  denial including flagged socket types, alternative transport and
  legacy socketcall denial. The UDP restriction remains enforced in
  audit mode.
- `core/sandbox/_unix_scope.py`: scopes Unix socket connections on
  supported namespace lanes; the plain full-profile fallback denies
  creation of Unix sockets, limiting host-resolver daemon bypasses.
- `core/sandbox/seatbelt.py`: macOS network rules and Mach service
  restrictions.
- `core/sandbox/proxy.py`: per-lane hostname/port gates, address screening,
  DNS pinning, SNI checks, and connection telemetry.

Filesystem restrictions, fake home, environment scrubbing, syscall
restrictions, and resource limits reduce the consequences of malicious
execution. They cannot substitute for an egress control: task contents
already supplied to an agent can themselves be encoded into DNS queries.

## Detection is separate from prevention

RAPTOR records proxy events and sandbox denial evidence, with summary,
triage, and live escalation. It does not implement a general DNS query
monitor or record arbitrary successful UDP queries on the affected
fallback. Such traffic bypassed the proxy entirely, so there was no
reliable detection guarantee for this incident before the fix.

Existing live escalation is advisory: it prints alerts and does not
automatically kill a run. Denial evidence can also depend on the execution
and audit lane; a payload that catches a permission error and suppresses
stderr need not produce a detailed DNS-attempt record. The fix therefore
prevents the socket operation rather than relying on a classifier,
timeout, useful response, or alert to stop it.

## Fix and compatibility

When a network-blocked Linux run uses a Landlock TCP fallback, require
working seccomp and enable its existing UDP block. Apply the same rule
when a namespace-capable context loses that backend during execution.
Carry the per-call UDP requirement into both the plain preexec builder
and the separate audit filter builder, and into denial interpretation.

The construction path also blocks UDP when `block_network=True` is
combined with an explicit TCP port allowlist. Explicitly permitting
TCP port 53 would still authorize TCP DNS; a port list is not a hostname
allowlist.

Hosts without working seccomp, and the seccomp-disabled `network-only`
profile without namespaces, now refuse this fallback. A containment-tier
waiver does not bypass that refusal. The existing explicit
`degraded_net_deny=False` network opt-out remains authoritative. Healthy
namespace execution retains local UDP support.

## Validation

`core/sandbox/tests/test_dns_egress_fallback.py` exercises construction
and runtime fallback, missing/disabled seccomp, containment waivers,
explicit network opt-out, and both audit paths. Running the new routing
tests against the committed pre-fix module produced **10 failures and
one passing opt-out control**; with the fix all **11 routing tests pass**.
These are simulated host-capability tests and do not execute a payload.

Six additional Linux integration cases exercise the real kernel filter:
IPv4 and IPv6 datagram creation with plain, CLOEXEC, and NONBLOCK socket
types must fail with EPERM. They send no external traffic. They are
skipped on this macOS development host; a live Linux run remains necessary
to validate those cases. No external chatbot was contacted.

The focused local suite (new regressions plus existing fallback, dispatch,
engagement, proxy-policy, and seccomp-policy tests) completed with **43
passed, 81 skipped, and 3 deselected**. Platform/capability-specific skips
are not evidence of Linux enforcement. Ruff and `git diff --check` passed.

## Remaining boundaries

- Allowlisted HTTPS services can still carry arbitrary application data,
  including DNS-over-HTTPS if such a service is authorized. CONNECT/SNI
  checks do not inspect encrypted request contents.
- Wildcard hostname grants authorize attacker-chosen labels under those
  suffixes. The proxy must resolve admitted names, so a wildcard over a
  domain an attacker can control can itself enable DNS exfiltration.
  Prefer exact endpoint grants when possible.
- Audit mode intentionally relaxes the proxy hostname gate unless audit
  enforcement is selected. It is not an offline execution guarantee.
- Trusted orchestrator Python is outside the child sandbox. In-process
  LLM SDK proxy configuration (`core/llm/egress.py`) is routing, not a
  kernel boundary against arbitrary code in that process.
- Caller-provided descriptors and Unix bridges are explicit capabilities;
  a preconnected socket or a bridge to a network-capable service requires
  its own policy review. Blocking new UDP sockets cannot revoke those
  capabilities.
