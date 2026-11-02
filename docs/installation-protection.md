# Installation protection

On Linux, start RAPTOR with:

```bash
bin/raptor --protect-install
```

This experimental, opt-in mode makes RAPTOR's installation and launch control
metadata read-only for the session and its descendants. It is an independent
backstop to RAPTOR's tool sandboxes: direct filesystem writes cannot patch the installed helpers, hooks, skills,
rules, or Python modules, even after a tool sandbox is bypassed.
It also protects the Python interpreter and installed library paths selected
by the launcher. Updating those dependencies requires an ordinary session.

Your home directory, Claude account and settings, editor state, projects, and
temporary files retain their normal filesystem permissions. Existing `HOME`,
`CLAUDE_CONFIG_DIR`, `EDITOR`, and `VISUAL` settings are preserved. No account
state is copied, moved, or redirected. Remove `--protect-install` on your next
launch to edit or update RAPTOR normally.

## What stays writable

RAPTOR's `out/`, the selected `RAPTOR_OUT_DIR`, and private session scratch stay
writable. Generated programs can still execute where tool policies permit;
output is not mounted `noexec`. Files under the installation outside designated
writable output stay read-only, including project-local frontend settings.

The installation's parent directories have their names pinned by private bind
mounts, preventing a descendant from renaming an ancestor and substituting a
new installation at the expected pathname. Their other contents remain writable
according to normal permissions, including Claude's atomic configuration saves,
locks, and Vim history. Known bind-mount aliases of installed files are sealed
too. These mounts exist only inside the protected process tree.

## Requirements and installation layout

Protection requires Linux user, mount, and PID namespaces and recursive
`mount_setattr` support (Linux 5.12 or newer). Host security policy may disable
these facilities. Initially, installation, dependency mounts, and their ancestor directories must use local
ext2/3/4, XFS, tmpfs, ramfs, or F2FS filesystems. Other filesystems, including
OverlayFS, Btrfs, ZFS, remote mounts, and loop-backed images, are not yet
supported: writable backing
paths can invalidate a pathname-only read-only guarantee. If requested
protection cannot be established, RAPTOR refuses
to start rather than silently continuing unprotected. This mode is unavailable
on macOS; ordinary launches and session scratch continue to work there.

Installation files must be independent copies, without hardlinks. A writable
hardlink elsewhere would otherwise provide a route around a read-only mount.
Startup checks file metadata for such links and fails with the affected path.
It does not hash the entire installation for this check. For uv-managed
dependencies, install using copy mode, for example:

```bash
uv sync --locked --link-mode copy --reinstall
```

External targets of installation symlinks also become protected. Do not link
writable user state into the installation as if it were installed content.
Keep the installation in its own directory, rather than using the home directory
itself as the installation root. Python bytecode is prepared before protection;
source-matching caches are reused and protected descendants do not write caches.

Protected RAPTOR helper startup also narrows Python's search path to declared,
read-only installation and dependency paths. Writable output, scratch and
unrelated search paths are removed; writable bytecode-cache prefixes are
cleared. Installed user-site dependencies remain available when their paths
are protected. Ordinary launches retain their existing import behavior.
This is startup import hygiene, not a Python sandbox: it cannot undo hooks
that ran before RAPTOR's bootstrap or stop running code from changing import
machinery, calling `exec()`, or loading code explicitly.

## Status and troubleshooting

RAPTOR's in-session startup banner confirms when kernel protection is active.
Denied writes normally report `Read-only file system`; applications may wrap or
suppress that error. Preserve tool stderr when reporting a failure. There is no
separate activity monitor or guaranteed notification for every attempted write.

Nested tool sandboxes retain their own enforcement. Protection adds no network
policy and does not make ordinary user configuration immutable. A compromised
frontend can still modify writable settings or ordinary user files; this mode
is installation integrity, not complete session containment. It cannot constrain
an independent process outside the protected tree or a kernel compromise.
Services outside the tree, including user services started through IPC, can
still act on behalf of a compromised process; this mode does not isolate IPC.

Protected session lists are local to that launch; project definitions and the
active project bookmark remain shared.

Closing the frontend ends its protected process tree. The outside cleanup
controller retains its host view and removes session scratch only after verified
termination. If termination cannot be verified, inspect retained scratch with
`bin/raptor cleanup --list`.

For acceptance testing with an existing account, an independent configuration
copy remains useful. Select that copy explicitly with `CLAUDE_CONFIG_DIR`; it is
not required for normal protected launches. Never overwrite or migrate your live
Claude settings just to test protection.
