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
does not silently inherit an arbitrary root. Native fork/resume/subagent
behavior still needs live acceptance testing with the supported client version.

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
must not change during a locked operation. macOS/Windows behavior and actual
native multi-root/fork/subagent turns require separate acceptance evidence.

## Coverage tracking

The read-coverage hooks (`plugins/coverage/libexec/raptor-hook-read` and its
Python test twin `core/coverage/track_read.py`) resolve the active run via the
session ledger. Under Codex they must look in the scoped sub-namespace
(`sessions.d/codex/<sha256(context-id)>/`) rather than the base `sessions.d/`
directory. Without scoping, a Codex hook process looks for a ledger that does
not exist at the base path, silently losing coverage attribution.

Both twins detect a Codex context via `RAPTOR_CODEX_CONTEXT_ID` in the
environment, compute the SHA-256 scope hash, and resolve the ledger from the
scoped directory. A defense-in-depth check after the PID comparison verifies
that the run metadata's `session_id` matches the current context ID, so a
stale or misrouted record cannot cross-attribute between roots sharing a PID.
The bash twin uses `sha256sum` (Linux) with a `shasum -a 256` (macOS) fallback.

## Separate baseline finding

A baseline-only reproduction on commit `254338065` found that a reentrant
non-Codex start from session B preserves session A in run metadata but adds a
running record to B's ledger as well. The reproduction loads unmodified
baseline session and metadata modules with temporary operator state. This is
bookkeeping evidence, not proof of a security vulnerability. The legacy path
is intentionally unchanged here; its intended semantics need a separate
review before changing that behavior.

## Native acceptance still required

The regression tests include real same-user broker processes and concurrent
claiming subprocesses. Their synthetic owners use native-shaped process names;
they are not evidence of actual Codex model turns or a live Claude session.

Before release, use a temporary operator registry in fresh trusted native
sessions and verify:

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
