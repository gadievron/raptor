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

Automatic naming still needs an adapter connected to the server hosting the
firing session, with authenticated RAPTOR context and the shared title policy.
In particular, a new stdio app-server is not a connection to the active TUI's
server. Do not infer support from `/rename`, fabricate Claude's `sessionTitle`
hook output, or edit Codex's database/transcript as a naming mechanism.

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
