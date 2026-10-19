# Codex session ownership

Codex root sessions can share one app-server process. RAPTOR therefore keeps
two identities: the logical root session and the stamped live process hosting
it. The shared `.active` bookmark still seeds new sessions; each existing
session keeps its own binding, including an explicit binding to none.

## Storage and compatibility

Claude and ordinary launcher entries retain their existing
`sessions.d/<pid>`, `<pid>.run`, and `<pid>.run.lock` layout and v2 entry format.
Codex root entries use `sessions.d/codex/<sha256(root-id)>/<pid>` with the same
entry, ledger, and lock implementations. A root ID is validated before hashing;
it is never interpolated into a pathname. `RAPTOR_REGISTRY_HOME` relocates all
these locations through the existing registry resolver.

The new launcher clears inherited Codex context before starting a new harness.
Within a running Codex workflow, trusted RAPTOR children retain the existing
session credential and root ID. Target-bound environments continue stripping
them through `RaptorConfig.TARGET_ENV_STRIP_SET`.

Global project rename/delete, pin-witness discovery, and drain operations visit
all namespaces. Each operation still uses the original per-ledger lock and
compare-and-swap rules. Internal traversal selects directories through a
`ContextVar`; it does not switch the process environment. Session rows retain
their directory identity so equal PIDs do not overwrite each other.

## Run ownership and retirement

Codex run metadata adds `session_harness=codex`, the root `session_id`, and a
`session_generation` hash of the private credential. It retains the process
PID/starttime/boot/namespace stamps. No raw credential is added to run metadata.
Claude metadata retains its existing shape and session-ID environment sources.

Contention, abandonment, Stop, and SessionEnd distinguish roots and generations,
including roots hosted by the same PID. Reentrant starts preserve the original
logical owner. Ledger mirroring follows the recorded owner rather than the
caller. Resume updates the logical owner and targets the previous namespace
when marking its old ledger record interrupted.

SessionEnd records retirement before scanning runs. Retirement is an immutable,
empty `.ended-<pid>-<credential-hash>` marker created with
`core.atomic_fs.write_new_text(mode=0o600)`. It needs no ledger lock. An old
generation's marker cannot retire a successor, and a slow finalization scan
does not postpone retirement. The markers are process-lifetime state, not a
power-loss journal; after reboot the existing process stamps invalidate the
old owner independently. Marker files are retained with the namespace.

Restarting an ended root mints a new credential and clears its old ledger under
the existing session lock. Its old run metadata and subagent aliases do not
gain ownership of the new generation. Other roots in the same process retain
their tokens, bindings, and ledgers.

## Native hooks and subagents

Native SessionStart supplies the root ID. SubagentStart associates its
`agent_id` with that root through a private, generation-bound alias. Alias
resolution is limited to one hop. It cannot replace an existing root or an
alias belonging to another root. RAPTOR command bootstrap resolves the alias;
it does not create an independent subagent project binding. Missing or invalid
context fails explicitly rather than selecting a root from PID ancestry.

The root/session-tree policy follows the [Codex app-server contract](https://learn.chatgpt.com/docs/app-server).
The hook relationship and SessionEnd behavior follow the
[native hook contract](https://learn.chatgpt.com/docs/hooks).
External clients must preserve this root relationship; an unmapped child thread
does not silently inherit an arbitrary root. Native fork/resume/subagent behavior depends on the client version; tested
Linux versions and observations are recorded below.

Changed hook definitions require native hook review. Restart or resume after
updating from the former PID-only Codex implementation; existing in-flight
PID-only Codex records are not silently migrated or relabeled. Automatic
compaction keeps the same live context without rerendering the startup hook.

## Security and locking review

| Invariant | Implementation and checks |
| --- | --- |
| Claude registry/schema and matching rules remain compatible | Default registry path and entry schema retained; legacy Claude substring matching and distinct EPERM policies retained; existing session, project, metadata, hook, pin, and launcher suites exercised. |
| A physical PID cannot select another Codex root | Scoped resolver requires a matching credential; no ancestry or parent-PID fallback for scoped calls. |
| Helpers cannot masquerade as owners | Codex names are restricted to CLI/app-server names, including Linux comm truncation; sandbox and exec helper names and PID 1 are rejected. |
| A stale end cannot revoke a successor | Retirement is keyed to the credential generation, not just PID or root ID; generation rotation and live shared-process revocation tested. |
| SessionEnd cannot wait on a busy ledger before recording retirement | Exclusive generation-marker creation takes no ledger lock; tested while the ledger lock is held. |
| Alias claims are serialized | Root/alias publications use the same stable per-context lock, held across read/check/write. Separate-process competing claims tested. |
| A delayed publisher cannot replace a successor's credential | Root publication holds publication lock then the scoped ledger lock through generation revalidation, context replacement, and broker readiness. Seeding releases its ledger lock before publication; broker readers do not take it. A concurrent-seeding test checks this exclusion. |
| No lock-inode replacement protocol | Writers never unlink publication or broker lock files. Publication checks the lock inode after acquisition and bounds contention; invalid lock files fail closed. |
| Symlink/FIFO input cannot steer startup I/O | Existing descriptor-pinned, bounded context I/O retained; namespace traversal refuses symlink directories; unsafe publication locks and retirement symlinks tested. |
| Broker replacement does not race a retiring generation | Successor waits for the existing server lock; it does not delete the lock or start a second live broker. |
| Namespace traversal does not change unrelated entry locking | Existing entry/ledger RMW functions run in a selected scope; original lock ordering and per-record CAS are reused. |
| Native command approval remains authoritative | No PreToolUse rewrite, allow decision, shell startup shim, or trust bypass was added. |

`core.json` supplies canonical serialization and bounded parsing for new
context/alias data. Descriptor-pinned startup writes retain their existing
implementation: the generic path-based atomic writer does not provide the same
directory-descriptor contract. Publication locking remains strict because the
generic `fs_lock` intentionally degrades to unlocked operation on failure.

This is attribution and isolation between cooperating RAPTOR sessions, not an
OS security boundary against arbitrary code running as the operator. The
existing legacy entry parser and ledger writer have not been replaced. Their
private-registry and stable-location assumptions still apply. Registry location
must not change during a locked operation. macOS/Windows behavior requires separate acceptance evidence. Native Linux
client evidence is recorded below.

## Coverage tracking

The read-coverage hooks (`plugins/coverage/libexec/raptor-hook-read` and its
Python test twin `core/coverage/track_read.py`) resolve the active run via the
session ledger. Under Codex they must look in the scoped sub-namespace
(`sessions.d/codex/<sha256(context-id)>/`) rather than the base `sessions.d/`
directory. Without scoping, a Codex hook process looks for a ledger that does
not exist at the base path, silently losing coverage attribution.

When `RAPTOR_CODEX_CONTEXT_ID` is present, the Bash hook delegates to
`core.coverage.track_read` using an isolated Python interpreter. The import
root comes from the installed hook's location, overriding inherited
`RAPTOR_DIR`; neither cwd nor `PYTHONPATH` selects its implementation. The
legacy Claude Bash route remains separate and retains its existing behavior.
Without an explicit root context, `CLAUDECODE` takes precedence over inherited
Codex flags; a separately started Claude process must not lose legacy coverage
because its launching shell happened to be Codex. Explicit scoped credentials
still select the root for a trusted Claude backend working within a Codex run.

The shared Codex consumer uses `session_scope.directory` and the authenticated
session resolver. Missing or invalid PID/token/context, dead owners, retired
generations, and rotated credentials attribute nothing; there is no global
bookmark or ancestry fallback. Candidate metadata must match the PID and all
logical owner fields, including harness and generation. Authentication is
rechecked after ledger lookup and after reading the hook payload, before the
append. This prevents a delayed payload from acquiring a successor's run.
An append already in progress at retirement can still finish in the old run;
this is observational coverage, not an atomic revocation/append transaction.

Scope, credential, context, and broker hashes use `core.hash` rather than
external binaries. No token is passed to a hashing subprocess as an argument.
Codex ledger reads use `core.source.read_bytes_capped`; run metadata and
payloads use bounded `core.json` parsing. Manifest writes use
`core.atomic_fs.open_hardened_append`, refusing symlinks and special files.

## Metadata and ledger serialization

Start, resume, and terminal transitions retain the run's metadata lock while
writing their ledger mirrors. Where a project operation lock is needed, it precedes the metadata
lock; individual ledger locks come last; cross-owner resume releases each ledger lock before acquiring
the next. The ledger functions do not acquire the metadata lock. Barrier
regression tests force start/interrupt, interrupt/resume, and resume/interrupt
interleavings for both legacy Claude and Codex paths.

These are serialized writer transitions, not a multi-file transaction.
Unlocked observers can still see a brief metadata/ledger mismatch, and a crash
between writes can leave a stale mirror. Existing ledger locks deliberately
degrade on acquisition failure; the tests establish the normal locking path,
not an unconditional durability guarantee on failed locks or unsupported file
systems. Changing that shared legacy policy requires separate review.

## Separate baseline finding

A baseline-only reproduction on commit `254338065` found that a reentrant
non-Codex start from session B preserves session A in run metadata but adds a
running record to B's ledger as well. The reproduction loads unmodified
baseline session and metadata modules with temporary operator state. This is
bookkeeping evidence, not proof of a security vulnerability. The legacy path
is intentionally unchanged here; its intended semantics need a separate
review before changing that behavior.

## Native acceptance still required

Linux verification on 2026-10-18 used Codex 0.163.0 and Claude Code
2.1.299. Native Codex startup/resume, project binding across independent shell
calls, explicit none, and scan lifecycle completed. The scan reported reduced
coverage (eight registry packs unavailable) and sandbox/runtime warnings;
this is not full scanner coverage evidence.

A real Codex app-server, with trusted hooks and startup model turns, verified
two root conversations sharing a PID, independent bindings, native root fork,
parent survival, retirement of one root while another remains usable, and an
actual command-approval denial that left its marker absent. A native subagent
resolved to the root, and its intentionally failing RAPTOR command produced a
consumed receipt and a failure marker only on the selected run. Both live run
statuses stayed running, leaving terminal decisions to the workflow finalizer.
In this client version the child Bash environment carries the child thread ID,
while PostToolUse reports the root session ID; receipts deliberately correlate
using the restored root context and native call ID. A regression test pins
this observed contract.

Native Claude completed project creation, binding persistence, explicit none,
and a mechanical scan using a temporary allow rule limited to the exact test
command. All 26 verification packs recorded exit 0 with no dropped packs. The
initial test driver timed out before capturing that process exit. A final
attached rerun with a sufficient Bash timeout returned exit 0; its tool result
reported no error or interruption, and its lifecycle record was completed.
A native resume with the temporary artifact directory explicitly granted
verified the outputs and final none/use behavior. No persistent permission or trust files
were edited by the tests. Non-Linux behavior remains unverified. Detailed
evidence and driver limitations are recorded in the review handoff.

Retain a temporary operator registry when repeating native acceptance; finish
any remaining checklist items before claiming complete client parity:

1. Claude: project create/use/none, a local mechanical scan, reentrant workflow
   dispatch, completion/failure, and restart/resume with the normal hooks.
2. Codex CLI: the same project/scan journey, reviewed hook definitions, and
   restart/resume after upgrading the former PID-only session state.
3. One Codex app-server hosting two root conversations: independent bindings
   and running runs; ending one root must not affect the other's run or token.
4. Native forks and subagents: confirm actual root/thread IDs, alias delivery,
   shared root bindings, and receipt attribution from child tool calls.
5. Native command denial/approval: confirm neither alias registration nor
   outcome bookkeeping rewrites or approves denied commands.

These checks require the actual client trust flow. Do not bypass native trust
or command approval to turn an acceptance failure into a passing result.
