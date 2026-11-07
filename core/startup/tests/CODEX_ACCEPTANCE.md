# Codex scan isolation acceptance

This is a developer acceptance procedure for the Codex integration. It
supplements `test_codex_native_acceptance.py`: the app-server preflight tests
do not prove model-driven lifecycle hooks or scanner isolation work.

Launch the integration against a small, disposable fixture and request this
command in the normal Codex tool sandbox, using the fixture's absolute path:

```bash
python3 raptor.py scan --repo /tmp/raptor-codex-smoke --sandbox strict
```

`strict` explicitly requests RAPTOR's shared fail-closed scan policy. It is
not a Codex-specific override of the default `full` profile. Early strict
preflight requires the shared scan-preflight change to be present on the branch.

If nested namespaces are unavailable, expect isolation-failure exit code **3**
before scanner work starts. That validates refusal behavior, not successful
scan acceptance. Compare namespace availability in the launching terminal and
the normal Codex tool sandbox; a read-only installation or outer sandbox does
not establish the scanner's own isolation.

Do not automatically retry with elevated permissions or a weaker profile.
Successful scan acceptance requires the fixture scan to complete under the
requested isolation, with no hook failures. Record hook timeouts separately;
a successful lightweight diagnostic command does not resolve earlier timeouts.


## Title capability preflight

The opt-in native suite checks `thread/name/set` and `thread/read` against
separate temporary threads without starting a model turn. It verifies title
round trips, manual replacement, and that another thread is unchanged.
This proves the installed app-server's naming API, not lifecycle integration.

The two-client title test additionally checks a private Unix-socket server:
one client owns the temporary threads and another applies the shared title
policy through the production adapter. It asserts that the owner receives
`thread/name/updated`, native feedback acknowledges a request, manual names
survive a project change, and the other thread is unchanged. It makes no model calls and never opens a
user's existing thread. Its WebSocket dependency is optional and guarded;
install the `codex` extra to include it. The test permits a longer RPC budget
than production hooks; API acceptance does not establish live hook latency.

```bash
uv sync --locked --group dev --extra grammars --extra codex
RAPTOR_CODEX_NATIVE_ACCEPTANCE=1 uv run --extra grammars --extra codex python -m pytest \
  core/startup/tests/test_codex_native_acceptance.py -m integration -k 'title or names'
```

Automatic naming runs after SessionStart publication and validated Stop
restoration. The adapter discovers the authenticated owner's advertised Unix
listener, or an owner-held native control listener, then checks Linux peer
credentials before speaking to it. Socket aliases are resolved to a private
canonical parent; the peer check uses the connected descriptor, so a pathname
replacement cannot reconnect the client to another server. Unsupported or
ambiguous discovery skips naming. A new stdio app-server is not a connection
to the active TUI's server. Do not infer support from `/rename`, fabricate
Claude's `sessionTitle` hook output, or edit Codex's database/transcript as a naming mechanism.

Do not change the launcher to start an extra app-server merely to make this
test pass. A lifecycle adapter must establish that its connection reaches the
server owning the authenticated firing session. A `--no-daemon` session need
not expose such a connection; missing transport must leave naming optional,
without changing command approvals, session ownership or launch behavior.

Concurrent instances must select titles by their authenticated native thread
identity, including when several threads share a server. Never select the
latest thread, infer a thread from a project bookmark, or use one global
current-session file. Installation protection is independent of naming:
runtime sockets and title state belong outside the read-only checkout, with
private permissions. Sharing the installation must not share title state
between threads or let one launch clean up another launch's runtime files.

The adapter re-reads the title before a write and preserves a manual change
observed during that interval. The native naming API has no compare-and-set
operation, so this cannot make a simultaneous UI rename atomic. A later
observed custom name latches the shared policy's manual-name preference.
The 750 ms RPC budget is independent of the native hook timeout; a slow
update is optional, and only later native feedback confirms a request.

## Hook failure evidence

Record hook UI failures independently of tool exit status. A tool returning
zero does not establish that its PostToolUse or Stop hook completed. Capture
the event label and exact error, including timeout duration. Keep namespace
refusals, hook failures, and scan results as separate acceptance observations.

## Lifecycle performance

Metadata hooks restore only authenticated session and output context. Provider
credentials remain in the full environment path used by analysis dispatches.
The broker receives its parent-validated operator snapshot over a bounded
private startup pipe, avoiding a duplicate source-inventory scan in the child.
No snapshot is added to argv or a persistent handoff file.

After updating this protocol, exit the old Codex session and start a fresh
launcher session. An old broker is rejected with a restart message. Check Stop
after a startup-only turn as well as PostToolUse and Stop after a diagnostic.
A successful command does not establish that the later Stop hook succeeded.
Existing hook timeouts remain unchanged; record startup and hook timings
separately from model response time and namespace diagnostics.
