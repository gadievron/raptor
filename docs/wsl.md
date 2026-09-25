# Running RAPTOR under WSL

**Related documentation:**
[Sandbox](sandbox.md) |
[Dependencies](dependencies.md) |
[Environment Variables](environment.md) |
[Troubleshooting](troubleshooting.md)

RAPTOR runs on WSL2 (Windows Subsystem for Linux). WSL2 is a real
Linux kernel in a lightweight VM, so the analysis pipeline behaves as
on any Linux host; the differences that matter are the kernel build
(stock WSL2 kernels ship without Landlock), the Windows-interop
mounts (`/mnt/c` and friends), and a couple of tools that need
hardware or Windows-side services. WSL1 is not a supported target —
it emulates Linux syscalls rather than running a Linux kernel, and
the sandbox layers RAPTOR's untrusted-exec contract requires are not
available there. On a detected WSL1 host, sandboxed execution
refuses outright with the upgrade remedy (see
[WSL1: refusal, not degradation](#wsl1-refusal-not-degradation)).

The startup banner and `raptor doctor` print a WSL section on WSL
hosts covering the points below for your specific machine.


## Setup

Inside your WSL2 distro, install RAPTOR exactly as on native Linux
([dependencies](dependencies.md)) and launch with `bin/raptor`. Two
placement rules save the most pain:

* **Keep the RAPTOR checkout, analysis targets, and output
  directories on the distro's Linux filesystem** (your home
  directory, ext4) — not under `/mnt/c`. See
  [Windows-interop mounts](#windows-interop-mounts-mntc) below.
* Launch from the distro side (a WSL shell), not from a Windows
  shell pointed into the distro.


## Landlock and the untrusted-exec floor

RAPTOR's untrusted-execution contract floors at the `mount-ns` tier,
whose Landlock layer needs kernel support ([sandbox](sandbox.md),
"Containment floor"). Stock WSL2 kernels ship without Landlock, so
on an unmodified WSL2 install untrusted-exec runs refuse (fail
closed) with a message naming the remedies. There are three:

### Option A — custom kernel with Landlock

WSL2 lets you boot your own kernel via `.wslconfig`. Build (or
obtain) a WSL2 kernel with `CONFIG_SECURITY_LANDLOCK=y` (Landlock is
upstream since 5.13; Microsoft's kernel source is at
`microsoft/WSL2-Linux-Kernel`). Keep `-microsoft-standard` in the
kernel release string (`CONFIG_LOCALVERSION` — Microsoft's tree
keeps it by default): RAPTOR's WSL detection keys on it, and a
custom kernel without it reads as plain Linux — the WSL-gated
sandbox hardening and the banner/doctor advisories no longer engage.
Then in `%UserProfile%\.wslconfig` on the Windows side:

```ini
[wsl2]
kernel=C:\\wsl\\bzImage
# Landlock must also be in the active LSM list. This list is the
# kernel's default stack with landlock prepended — match it to YOUR
# kernel's CONFIG_LSM and verify after boot (see below).
kernelCommandLine = lsm=landlock,lockdown,yama,integrity,apparmor,bpf
```

Then `wsl --shutdown` from Windows and relaunch the distro.

If your shipped kernel already builds Landlock (check with
`zgrep CONFIG_SECURITY_LANDLOCK /proc/config.gz` when available),
the `kernelCommandLine` line alone — without a custom `kernel=` —
may be all you need.

**Verify on your kernel** (kernel builds and default LSM stacks
vary, so treat the recipe as a template, not a guarantee):

```bash
cat /sys/kernel/security/lsm     # should list landlock
sudo dmesg | grep -i landlock    # "LSM: initializing ... landlock"
```

The RAPTOR startup banner is the end-to-end check: `sandbox ✓ (...)`
should include `landlock:abiN`.

### Option B — consent to the ns-only tier

If you stay on the stock kernel, consent explicitly to the `ns-only`
containment tier for untrusted work: namespaces, fresh procfs, and
seccomp stay enforced; the Landlock filesystem/TCP policy layer is
absent.

```bash
# per run
/agentic --repo <path> --sandbox-floor ns-only
# standing, per project
/project set sandbox-floor ns-only
```

Trade-off: this is a real containment reduction, and RAPTOR says so
every time the consent takes effect — the project setting prints a
banner line on each run it affects, and floor-related warnings name
the downgraded tier. Consent semantics, precedence, and the exact
guarantees of each tier are in [sandbox.md](sandbox.md).

### Option C — standing host-scoped consent

If this machine will stay on a stock (Landlock-less) WSL2 kernel,
you can record the ns-only consent once for the whole host instead
of repeating it per run or per project:

```bash
bin/raptor wsl-consent grant     # operator ceremony, at your terminal
bin/raptor wsl-consent status    # is the marker present? does it apply?
bin/raptor wsl-consent revoke    # remove it (floor returns to default)
```

`grant` is an operator ceremony: it shows exactly what will change
and the evidence it was granted against, requires the tier label
typed back, and **hard-refuses a non-TTY stdin** — an agent, script,
or pasted instruction cannot self-grant. `revoke` is deliberately
not gated (removing consent only raises the floor, so unattended
sessions may always revoke).

The marker (`~/.local/share/raptor/wsl-host-consent.json`,
machine-scoped, outside every sandbox-readable tree) is
**conditional, not a blanket downgrade**. It applies only while all
of these hold, and is inert otherwise:

* the running kernel identifies as WSL (inert on any other host);
* Landlock is unavailable — a kernel that gains Landlock makes the
  marker inert and the floor rises automatically (nothing to revoke);
* the kernel stays in the identity family the grant recorded
  (version updates within the family keep the consent; a
  kernel-flavour change makes it inert until re-granted);
* the marker validates: it is bound to this machine's identity (a
  copied marker is inert elsewhere), and a corrupt, tampered, or
  future-dated record is inert with one warning — failing closed to
  the normal refusal.

Precedence: the marker is the **lowest** consent surface — a per-run
`--sandbox-floor` or a project `sandbox-floor` setting always
overrides it (a project-set higher floor is never lowered by it),
and it never changes what `RAPTOR_ALLOW_DEGRADED_UNTRUSTED` means
where that is set. It only ever replaces the default refusal with
`ns-only`.

Visibility: while the marker applies, the startup banner's WSL
section and each affected run print one posture line ("untrusted
floor ns-only by host consent, granted <date> — Landlock unavailable
on this kernel"), and the per-call degraded-containment warnings
collapse to a single notice per process — the posture is a host
property, not per-call news.

**Residual exposure below the `mount-ns` tier on WSL** (applies to
any consented below-`mount-ns` floor — Option B and Option C alike):
without the mount tree, parts of the Windows-interop plumbing stay
reachable from sandboxed code — `/usr/lib/wsl` remains visible
through the wholesale `/usr` read grant, `binfmt_misc` remains
visible through `/proc`, and a `connect()` to the Windows-interop
pathname socket is not Landlock-governed at any current Landlock ABI
(ABI 6 scopes abstract sockets only). For hostile targets, set
`interop=false` in `/etc/wsl.conf` (`[interop]` section) to close
the Windows-side process channel at the source. The `/mnt` read
denial is part of the Landlock read allowlist and still applies on
the landlock-tier lanes.

### The refusal-boundary offer (interactive sessions)

When an untrusted-exec run refuses on a WSL host because the floor
requires the Landlock layer, the refusal message itself names the
remedies, including the grant command — that is the complete
non-interactive behaviour. An interactive session may additionally
put the decision in front of the operator as a structured choice,
per the INTERACTIVE PROMPTS doctrine in the root `CLAUDE.md`: run
`libexec/raptor-may-ask` first and ask only when it prints
`interactive` AND AskUserQuestion is available; ask at the run
boundary, after the refusal — never mid-pipeline. Quote the refusal
text with non-printables escaped. Options:

1. **Keep the refusal (Recommended)** — no consent; fix the kernel
   instead (Option A) for the full contract.
2. **Grant the standing host consent** — tell the operator to run
   `bin/raptor wsl-consent grant` **at their own terminal**. The CLI
   hard-refuses a non-TTY stdin, so the session cannot run it for
   them — never offer to. Once granted, re-run the refused command.
3. **Consent for this run / project only** — re-run with
   `--sandbox-floor ns-only`, or set the standing project consent
   with `/project set sandbox-floor ns-only` (Option B).

Non-interactive fallback (may-ask says `non-interactive`, errors, or
the tool is absent): do not ask — the refusal text plus the named
grant command already printed is the complete behaviour; report it
and stop. Never select a floor on the operator's behalf.


## Windows-interop mounts (`/mnt/c`)

WSL2 serves Windows drives to the distro over a 9p filesystem (the
drvfs automount family under `/mnt/<drive>`). Two properties matter
for analysis work:

* **Performance** — file I/O on `/mnt/c` is dramatically slower than
  the distro filesystem. Scans, inventory builds, CodeQL database
  creation, and fuzzing corpora all amplify per-file cost, so a
  target checkout on `/mnt/c` can slow a run by an order of
  magnitude.
* **Lock semantics** — `flock` on a 9p mount is client-local: locks
  are not shared with Windows or with other distros mounting the
  same drive. RAPTOR uses `flock` for run/registry coordination, so
  output directories on `/mnt/c` lose cross-context lock guarantees
  silently.

Keep the RAPTOR checkout, targets, and `out/` on the distro
filesystem; clone Windows-side repos into the distro rather than
scanning them in place. RAPTOR warns (warn-only — the run proceeds)
when a resolved default target, output directory, or project
target/output sits on such a mount.

### Artifact semantics on drvfs/9p

What "client-local" means for RAPTOR's durable artifacts (run
metadata, the coverage store, annotations, project registry state):
every `flock`-guarded read-modify-write stays fully correct among
processes **within one distro** — one 9p client behaves like a local
filesystem for its own processes. What silently disappears is the
cross-context guarantee: a Windows-side process, or a second WSL
distro mounting the same drive, is a different client and is not
excluded — concurrent cross-context writers degrade to
last-writer-wins. File mtimes behave the same way: another client's
writes can surface with stale attributes (the 9p attribute cache),
which skews mtime-based staleness/activity signals across contexts
while same-distro views stay coherent. Practical rule: artifacts on
the distro filesystem keep every guarantee; artifacts on `/mnt/<drive>`
are fine so long as exactly one distro touches them.

### Temp root (`TMPDIR`)

Do not point `TMPDIR` (or `RAPTOR_WORK_DIR`) at a drvfs/9p path.
This is the placement that breaks features rather than just
degrading them:

* **FIFO/named-pipe creation fails** on 9p — temp-backed plumbing
  that creates special files errors out instead of running slowly.
* **Many-small-file scratch work is drastically slower** — scratch
  lanes, sandbox staging, and extraction trees are exactly that
  shape, so per-file 9p round-trips dominate.

RAPTOR emits one strong warning per process (at the scratch/workdir
chokepoints, plus a banner/doctor line) when the temp root resolves
to such a mount. The remedy is to point the temp root back at the
distro filesystem before launching:

```bash
export TMPDIR=/tmp        # or any other Linux-filesystem path
```

Case sensitivity: drvfs directories are case-insensitive by default
(per-directory `case=` attributes can change this). RAPTOR's path
containment fails closed under case-spelling mismatches; the visible
effect of a case-insensitive checkout is cosmetic — two case-variant
spellings of one file can appear as distinct entries in inventories
and reports. When an inventory build over a target on such a mount
finds paths differing only by case, it logs an informational note
listing bounded example groups (`Foo.c / foo.c`): those entries may
be one on-disk file counted twice — duplicate-identity noise in
inventories, SARIF results, and suppression keys. The fail direction
is safe (duplicate analysis, split coverage marks — never a masked
finding) and keying is deliberately unchanged; deduplicate the
checkout (or clone into the distro filesystem) if the noise matters.

The launcher's PATH scrub drops the Windows-interop PATH entries
that WSL appends by default (they are world-writable under the
default drvfs automount and could shadow `python3`/`claude`); on WSL
this collapses multiple drops to one summary line (a single drop
keeps its per-entry line). `RAPTOR_ALLOW_UNSAFE_PATH=1` keeps them
if you accept the risk.


## Sandbox hardening on WSL

All of the following engages only when the running kernel identifies
as WSL; on any other Linux host the sandbox profile is unchanged.

### Windows-interop and driver masking (mount-ns tier)

WSL's Windows-interop lets a Linux process launch WINDOWS-side
executables — a channel that no Linux containment layer (namespaces,
Landlock, seccomp) governs. Inside the mount-ns sandbox view on a
WSL host:

* `/run/WSL` (the interop socket directory) is never visible — the
  per-sandbox `/run` tmpfs replaces it, and the environment scrub
  drops `WSL_INTEROP`/`WSLENV`, so the interop server is unreachable
  even though binfmt dispatch happens in the kernel regardless of
  the mount view.
* `/proc/sys/fs/binfmt_misc` (the interop exec registration view)
  and `/usr/lib/wsl` (Windows driver/GPU library mounts) are masked
  with empty read-only views.
* `/dev/dxg` (GPU paravirtualisation) is never created — the
  sandbox builds a minimal `/dev`.
* Caller-supplied readable/tool-path grants at or below any of
  these are refused loudly; the mask stays authoritative.

Tiers below mount-ns (`ns-only`, `mountless-ns`, `landlock`) have no
private mount view, so these surfaces retain their normal
allowlist-driven visibility there — one more reason the untrusted
floor defaults to `mount-ns`, and to prefer the host-level interop
switch below when analysing hostile code on WSL.

### `/mnt` is not ambiently readable to untrusted work

Under the restricted-read posture (`restrict_reads=True` — the
untrusted contract), read grants at or below `/mnt` are dropped from
the composed allowlist with a warning: the Windows filesystem must
not become a readable exfil surface through an ambient grant (a
derived readable path, a tool resolved through the interop PATH).
Explicit grants stay:

* **The run's target and output trees.** A target on `/mnt/c` is
  analysed exactly as before — point the run at it and the grant
  (and anything within its tree) is untouched.
* **Operator CLI grants** — `--sandbox-readable-path` /
  `--sandbox-tool-path` entries are exempt; they are also the
  per-run override the drop warning names.

The deny keys on the default automount root (`/mnt`); a non-default
`/etc/wsl.conf` `[automount] root` falls outside it.

### WSL1: refusal, not degradation

On a detected WSL1 host every sandboxed-execution path refuses with
a clear message: WSL1 has no Linux kernel, so no containment layer
can engage and there is nothing to degrade to. Upgrade the distro
(`wsl --set-version <distro> 2` from Windows, then
`wsl --shutdown`). The operator-explicit global disable
(`--sandbox none` / `--no-sandbox`) remains authoritative for runs
that genuinely want no sandbox. Kernels whose identity matches WSL
but not the WSL2 release token are treated as WSL1 — the refusal
direction — rather than assumed to be real kernels.

### Outer containment (host-level, recommended for hostile targets)

The in-sandbox masks reduce what sandboxed code can see; the
host-level switches remove the interop machinery itself and bound
the VM. In the distro's `/etc/wsl.conf`:

```ini
[interop]
enabled = false            # no Windows-process launch from the distro
appendWindowsPath = false  # no /mnt/c/... entries on PATH
```

and in `%UserProfile%\.wslconfig` on the Windows side, cap the VM
(`memory=`, `processors=`) and consider Hyper-V firewall rules for
egress control. Apply with `wsl --shutdown` and relaunch. These are
operator choices, not RAPTOR defaults — they affect the whole
distro, not just RAPTOR runs.


## Tool notes

| Tool | Status under WSL2 |
|------|-------------------|
| Semgrep, CodeQL, Joern, Coccinelle, tree-sitter | Work as on native Linux |
| AFL++ (`/fuzz`) | Works; use the distro filesystem for corpora/output. `afl-system-config` wants sysctl access — run it inside the distro |
| gdb | Works |
| rr (`/crash-analysis` recording) | Needs CPU performance counters, which WSL2 typically does not expose to the VM — expect recording to fail. The rest of `/crash-analysis` (ASAN, gdb, coverage legs) works |
| docker | Either enable Docker Desktop's WSL integration for the distro, or install Docker Engine inside the distro. Container-backed features (SAGE sidecar, `/cve-env`, env build-on-demand) need one of the two |
| frida | Works for targets inside the distro; Windows-side processes are out of scope |

The startup banner probes tools on your host — trust it over this
table when they disagree.


## Line endings (CRLF checkouts)

A CRLF-normalised checkout (e.g. cloned with `core.autocrlf=true`)
analyses correctly: RAPTOR's line model splits CRLF content to the
same line text as LF content, and the staleness-family hashes read
both encodings identically, so annotations and stored verdicts do
not churn between LF and CRLF checkouts of the same code. Byte-exact
surfaces (file-content hashes, patch application) are deliberately
encoding-sensitive — a byte-level mismatch between differently
encoded checkouts is a genuine re-validate signal, not an error.
When you have the choice, clone with `core.autocrlf=input` (LF
worktree) inside the distro; it is the encoding the wider Linux
toolchain expects.


## CI verification (the live-WSL leg)

The claims above that only a real WSL kernel can confirm — the 9p
magic on the automount, Landlock availability on the stock kernel,
flock/rename client-locality, the consent ceremony, the sandbox
masks, the WSL1 refusal — are exercised nightly by
[`wsl.yml`](../.github/workflows/wsl.yml) on a `windows-2022` runner
(WSL2 via the setup-wsl action; a probe job gates the leg and reports
a detected skip when the runner image cannot host WSL2).

What the leg verifies:

* **verify-live** — `.github/scripts/wsl_verify_live.py --section
  facts`: environment facts (kernel identity, LSM list, folding
  samples, perf surface) are recorded; expected values (V9FS magic on
  `/mnt/c`, Landlock absent on the stock kernel, flock double-acquire
  across two distros, mkfifo failure and the TMPDIR advisory latch on
  drvfs) are asserted — a mismatch fails the job.
* **wsl-tests** — `pytest -m wsl` plus the CRLF fixture set on three
  checkouts of the same tree: an ext4 LF clone, a git-materialized
  `core.autocrlf=true` twin, and the drvfs workspace view (which also
  runs the CRLF census on a case-insensitive mount and the
  nosemgrep/dead-scope suites over 9p).
* **sandbox-live** — the WSL sandbox/consent test files with the real
  kernel underneath, then the checklist `consent` section and
  `sandbox` section (mount-ns masks, PE-exec / interop-socket /
  binfmt-write probes, the nested-unshare mask-strip attempt, the
  `/run/WSL` re-grant refusal in both spellings, the `/mnt` target
  exemption).

  The consent ceremony is verified on BOTH sides of its TTY gate.
  The non-TTY refusal (exit 3, nothing written, the message naming
  the terminal requirement) is asserted directly — that is the
  load-bearing, CI-assertable path. The grant path is additionally
  driven through a pty the CI harness allocates, with the full
  transcript recorded (escaped) into the artifact. This does not
  undermine the gate: the gate is `sys.stdin.isatty()` by design,
  and its purpose is blocking accidental or scripted agent
  self-grants — an agent runs the CLI with a pipe or devnull stdin
  and stops at the refusal. A test harness allocating a pty on our
  own CI runner is exercising the grant path, not defeating the
  control; driving the ceremony programmatically anywhere else is
  exactly the behaviour the gate exists to stop.
* **wsl1-capture** — a `wsl-version 1` job recording WSL1 identity
  strings and `statfs` f_type words (the drvfs constant deliberately
  unmatched in code until captured here) and asserting the sandboxed
  execution refusal plus the `--sandbox none` escape.

Artifacts: each checklist section uploads a JSON artifact
(`wsl-verify-facts` / `wsl-verify-sandbox` / `wsl-verify-wsl1`,
14-day retention) with per-item status, values, and — for the grant
ceremony — the escaped pty transcript. The cross-client probes need a
second distro; the workflow installs one and names it through the
CI-only `RAPTOR_WSL_SECOND_DISTRO` knob (unset, those probes report
skipped-with-reason).
