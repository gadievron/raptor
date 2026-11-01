# Temporary files and cleanup

RAPTOR keeps analysis results in the configured output directory. Temporary
files have a separate lifetime and may be removed when their work finishes.

The launcher selects a temporary base from `RAPTOR_WORK_DIR`, then `TMPDIR`.
With neither set, Linux uses `/tmp` and macOS uses its OS-provided private
temporary directory. An unusable explicit base fails startup. Each launcher
session gets a private subdirectory; the operator's base directory remains
owned by the operator and is never recursively removed by RAPTOR.

Direct helper invocations preserve their initial `TMPDIR`. They clean only
operation directories they create, without taking ownership of that base.

Inspect recorded launcher scratch without starting a frontend:

```bash
bin/raptor cleanup --list
bin/raptor cleanup --dry-run
```

These commands work even if the current `TMPDIR` is unusable. Run them with
the same account and `RAPTOR_REGISTRY_HOME` override as the original launch.
They locate custom temporary bases through private ownership records rather
than searching the installation or every directory under `/tmp`.

Normal cleanup removes only directories whose process-tree closure has been
established:

```bash
bin/raptor cleanup
bin/raptor cleanup --session SESSION_ID
```

A missing PID or old timestamp is insufficient proof. `retained` means RAPTOR
cannot establish that the directory is unused. `cleanup-error` means removal
could not finish, for example because permissions changed or a mount remains.
A later cleanup can retry an interrupted removal.

If you have independently verified that a retained session is no longer
needed, explicitly authorize removing that one session:

```bash
bin/raptor cleanup --session SESSION_ID --force
```

This can interrupt processes still using its scratch. It does not bypass
filesystem identity checks, follow symlinks, remove another session, or delete
an operator-supplied temporary base. Copy anything you want to keep into a
durable output directory before removing session scratch.

## Optional cgroup tracking on Linux

The launcher first tries an existing writable cgroup v2 delegation. Where
available, it can request a temporary delegated scope from the systemd user
manager. This needs no sudo and changes no persistent service configuration.
The supervisor remains outside the frontend's group and filesystem sandbox.

On session exit, the supervisor stops remaining processes in its group and
waits for the group to become empty. Tracking does not impose memory, CPU,
or process-count limits. An unrestricted frontend can start work outside its
group, so an empty group alone does not authorize deleting its scratch.
These sessions remain `retained` for explicit cleanup after you have checked
that no other programs need their temporary files.

If tracking is unavailable or attachment fails before the command starts,
interactive launches ask whether to continue; pressing Enter accepts.
Non-interactive launches require `--allow-degraded-cleanup` before any
frontend passthrough `--`:

```bash
bin/raptor --allow-degraded-cleanup [other-options] [target]
```

This approval accepts retained session scratch. It does not waive sandbox
requirements or resource limits required by an individual analysis tool.
If a supervisor crashes, normal cleanup retains uncertain scratch; it does
not kill unrelated work or infer that files are unused from a missing PID.
