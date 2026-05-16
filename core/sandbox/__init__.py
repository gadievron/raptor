"""Subprocess sandboxing via Linux user namespaces, Landlock, and seccomp.

Provides network, filesystem, and syscall-level isolation plus resource
limits for subprocesses that handle untrusted content. Falls back
gracefully when any layer is unavailable.

Six independent isolation layers (any combination may be active):
- User namespace (--user): unprivileged root-mapping foundation that
  all other ns layers need. No external effect on its own.
- Network namespace (--net): blocks all network access — no interfaces
  inside the sandbox. Used in the `full` / `debug` / `network-only`
  profiles. Runs alongside the optional egress proxy, never combined.
- PID namespace (--pid --fork): hides host PIDs from the sandbox,
  blocking kill() / ptrace against host processes. The sandboxed
  command runs as PID 1 in its own namespace.
- IPC namespace (--ipc): isolates SysV shm / sem / message queues. A
  compromised child can't use host-wide IPC resource-limits to DoS
  other processes, nor read same-UID apps' shm segments by key.
- Mount namespace (pivot_root onto a fresh tmpfs): implemented in
  `core/sandbox/mount_ns.py` + `core/sandbox/_spawn.py`. The parent
  process tempfile.mkdtemp's a random-name root dir, forks a child,
  the child unshares user/mount/ipc namespaces, the parent runs
  `newuidmap`/`newgidmap` to set up the 0-->caller_uid mapping, the
  child then does all mount operations via ctypes BEFORE Landlock
  install (Landlock blocks mount topology changes on kernel 6.15+),
  pivot_roots into the tmpfs, installs Landlock + seccomp, unshares
  pid-ns and fork-execs the target as PID 1. Per-sandbox `/tmp` and
  `/run`, host `/usr`/`/lib`/`/etc` etc. bind-mounted read-only,
  caller's target + output bind-mounted at their ORIGINAL absolute
  paths (no argv rewriting needed). Requires the `uidmap` package
  AND no AppArmor block on unprivileged user-ns. On Ubuntu 24.04+
  with default `kernel.apparmor_restrict_unprivileged_userns=1`
  mount-ns is blocked and we fall back cleanly to Landlock-only. The
  probe emits a one-shot INFO message naming the missing prerequisite
  (AppArmor sysctl OR missing uidmap).
- Landlock (kernel 5.13+): filesystem restriction + TCP allowlist
  (NET_CONNECT_TCP ABI v4+, kernel 6.7+). Default: write-restricted
  (writes only to `output` + `/tmp` + specific safe /dev files),
  read-wide. When `restrict_reads=True` is set, reads are also
  restricted (default allowlist: system dirs + target + output).
  Independent of namespaces — works on its own if ns unavailable.
- Seccomp-bpf (libseccomp): blocklist of escape-vector syscalls.
  Returns EPERM to the target — graceful failure, actionable
  diagnostics. Unresolved-architecture syscalls are skipped with a
  one-shot warning. SCMP_FLTATR_ACT_BADARCH = KILL_PROCESS, set
  explicitly so 32-bit-compat entry (int 0x80, x32) can't bypass.

Integrity guard: `check_landlock_available()` fork-runs a functional
self-test on first call — installs a ruleset with
`handled_access_fs = WRITE_FILE | READ_FILE`, no allow rules, attempts
both write and read of a probe file. Either succeeding means Landlock
looks engaged but isn't enforcing. The sandbox flags this as
`Landlock unavailable` with an ERROR log. The test suite also has a
regression that compiles a C probe reading LANDLOCK_ACCESS_FS_* from
<linux/landlock.h> and asserts our Python constants match — catches
UAPI bit-value drift at CI time.

Resource rlimits (memory, file size, CPU time, NPROC, CORE) always
apply regardless of which isolation layers are available.

Egress proxy (use_egress_proxy=True + proxy_hosts=[...]):
  A per-RAPTOR-process asyncio daemon-thread HTTPS-CONNECT proxy.
  When enabled, the child:
  - Sees HTTPS_PROXY / https_proxy / HTTP_PROXY / http_proxy (all
    cases) pointing at 127.0.0.1:<ephemeral port>.
  - Has Landlock's TCP allowlist pinned to that port only.
  - Has seccomp UDP blocked (AF_INET/AF_INET6 SOCK_DGRAM → EPERM) so
    DNS exfil is closed — the proxy resolves hostnames on behalf of
    the child.
  The proxy enforces a hostname allowlist, rejects CONNECT targets
  containing non-printable characters (defeats terminal-escape
  injection into proxy logs), rejects resolved IPs that are not
  globally routable via `ipaddress.is_global` (covers loopback,
  RFC1918, CGNAT 100.64/10, link-local, multicast, 6to4, reserved,
  TEST-NET, benchmarking ranges), honours upstream HTTPS_PROXY from
  the parent env for corporate networks, and honours NO_PROXY.
  Each run() call registers with the proxy to receive a per-run
  event buffer that is immune to flood-push-out (previously a
  CONNECT-flood to an allowlisted host could push an earlier denied
  CONNECT out of a shared 1024-entry ring before the sandbox ended,
  masking the attack in post-mortem review). Per-run slices are
  returned in `result.sandbox_info["proxy_events"]`; a sandbox()
  context also accumulates every run()'s slice into `run.events`
  for a unified audit view. Events are persisted to
  `{output}/proxy-events.jsonl`. The JSONL writer uses O_NOFOLLOW +
  O_NONBLOCK + fstat(S_ISREG) to defeat child-planted symlinks
  (would redirect the parent's append outside `output`) and FIFOs
  (would hang the parent forever).

Fake HOME (fake_home=True):
  Creates `{output}/.home/` (0700) with pre-populated XDG subdirs
  and overrides the child's HOME/XDG_*_HOME to point there. Tools
  see a fresh, empty home rather than the user's real home with
  credentials in it. Defaults True on `run_untrusted()`. Pre-
  populate `{output}/.home/` before invoking if the child needs
  specific files there (e.g. an auth token).
  The parent-side `os.makedirs` of `.home` and its XDG subdirs
  lstat-checks each path first and refuses if the caller reuses
  `output` from a prior sandbox and an earlier child replaced the
  dir with a symlink, FIFO, or other non-regular inode — without
  this, os.makedirs would resolve the symlink and create subdirs
  inside the attacker-chosen location outside `output`.

Log-output hygiene:
  RAPTOR logs attacker-influenced strings in several places (argv
  filenames from scanned repos, subprocess stderr / ASAN bug_type,
  CONNECT hosts from the egress proxy). A live-terminal operator
  watching those logs could otherwise be ANSI-escape-injected:
  colour flips, window-title spoofing, cursor-movement to overwrite
  prior lines with forged "all clear" entries.
  `core.security.log_sanitisation.escape_nonprintable()` replaces
  non-printable chars with `\\xHH` literals before logging; the
  proxy's CONNECT parser uses the predicate form
  `has_nonprintable()` to reject such requests outright with a 400
  Bad Request.

Threat model — what the sandbox DOES protect against:
- Outbound network from sandboxed processes (namespace --net removes all
  interfaces, inherited by all descendants). Alternative: egress proxy
  with hostname allowlist and UDP block (closes DNS exfil).
- Filesystem writes outside `/tmp` + `output` (Landlock, ABI 1+).
  `/dev/null` and `/dev/tty` are granted per-file for shell-script
  compatibility (`cmd >/dev/null 2>&1`) without opening /dev wholesale.
- Credential exfiltration via file read (restrict_reads=True):
  default allowlist is system dirs + target + output + /tmp + safe
  /dev files. $HOME, /dev/shm, /var, /root, /mnt are all denied.
- Cross-process /proc/<host_pid>/environ reads (restrict_reads=True):
  restrict_reads triggers a PID-namespace unshare so the kernel's
  per-ns /proc access check denies the child access to any host-pid
  /proc/<pid>/environ — even though /proc is wholesale allowlisted at
  the Landlock layer. Works without mount-ns (the kernel's ns check
  is independent of the /proc mount). Blocks ANTHROPIC_API_KEY / SSH
  / AWS env exfil from the parent RAPTOR process in Landlock-only
  mode.
- Cross-directory rename/link (Landlock REFER, ABI 2+).
- Truncation of files outside writable paths (Landlock TRUNCATE, ABI 3+).
- TCP connect() to non-allowlisted ports (Landlock NET_CONNECT_TCP,
  ABI 4+; only useful when `block_network=False`).
- DNS / UDP exfiltration under egress-proxy mode — seccomp blocks
  AF_INET/AF_INET6 SOCK_DGRAM; proxy resolves target hostnames.
- Hostname-level egress control — egress proxy enforces allowlist by
  CONNECT host, not just port (unlike Landlock's port-only allowlist).
- Unix-domain-socket creation (`socket(AF_UNIX, ...)`) — blocked by
  seccomp, closes the `connect("/var/run/docker.sock")` escape vector.
  (`socketpair(AF_UNIX)` is NOT blocked — it returns an isolated pair
  with no external address; blocking broke Rust's std::process spawn
  without closing any real attack.)
- AF_PACKET / AF_NETLINK / SOCK_RAW sockets — blocked by seccomp.
- `ptrace()` of any process — blocked by seccomp in `full`, allowed in
  `debug` profile for gdb/rr use.
- `process_vm_readv` / `process_vm_writev` cross-process memory access
  — blocked by seccomp.
- `keyctl` / `add_key` / `request_key` kernel keyring manipulation —
  blocked by seccomp.
- `bpf` / `userfaultfd` / `perf_event_open` kernel-attack surface —
  blocked by seccomp.
- `io_uring_setup` / `io_uring_enter` / `io_uring_register` — blocked
  by seccomp. Closes the io_uring-bypasses-Landlock gap on kernels
  5.13–6.2 (kernel 6.3+ integrated io_uring with Landlock).
- `kcmp` (process resource comparison / side-channel), `pidfd_getfd`
  (cross-process FD theft), `name_to_handle_at` / `open_by_handle_at`
  (file-handle-based bypass of path checks) — blocked by seccomp.
- `ioctl(fd, TIOCSTI, ...)` tty-injection escape — blocked by seccomp.
  Also blocks TIOCCONS (console redirect) and TIOCSCTTY (controlling
  tty acquisition) as defence-in-depth.
- `kill()` of host processes — PID namespace hides host PIDs; attacker
  inside sandbox sees ns-local PIDs only.
- SysV IPC cross-process access — IPC namespace isolates shm/sem/msg.
- Fork bombs — RLIMIT_NPROC=1024 applied via `prlimit --nproc` wrapper
  inside the user namespace (ns-local UID nobody has zero pre-existing
  processes so the limit bounds the sandbox without affecting host
  work). Configurable via `~/.config/raptor/sandbox.json`.
- Privilege escalation via setuid binaries (PR_SET_NO_NEW_PRIVS).
- Core-dump credential exfil — RLIMIT_CORE=0 suppresses core dumps; a
  crashed child can't leak the contents of files it read into its
  memory through `/proc/sys/kernel/core_pattern` handlers.
- Per-process CPU time and single-file size (rlimits).
  NOTE: these are per-process limits, not aggregate — a process that
  writes many separate files within RLIMIT_FSIZE each is not bounded.
  RLIMIT_AS (virtual memory) is disabled by default because ASAN-
  instrumented binaries reserve ~56 TiB of shadow-memory VA on
  x86_64, and any finite limit breaks them. Memory containment
  belongs to an external cgroup v2 `memory.max`.
- PATH hijack of the sandbox's own setup binaries — `unshare`,
  `prlimit`, `/bin/sh`, `mount`, `mkdir` are resolved against a
  hardcoded safe bin-dir list (`/usr/sbin`, `/usr/bin`, `/sbin`,
  `/bin`, `/usr/local/bin`), NOT the inherited PATH. Closes the
  "malicious .envrc poisons PATH before the sandbox builds itself"
  class of bypass. A missing binary is a HARD FAIL
  (FileNotFoundError) rather than a fallback to bare-name PATH
  lookup — the system that lacks util-linux in `/usr/bin` is
  exactly the system most likely to have a polluted PATH.
- Parent-env code injection — `bin/raptor` strips `LD_PRELOAD`,
  `LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH`, `PYTHON{STARTUP,
  PATH, HOME, USERBASE, BREAKPOINT, INSPECT}`, `OPENSSL_CONF`,
  `SSLKEYLOGFILE`, `NODE_{OPTIONS, PATH, EXTRA_CA_CERTS}`,
  `BASH_ENV`, `ENV` before exec'ing Python / Claude Code so a
  hostile parent env can't inject into the launcher chain or into
  any `bash -c` / `sh -c` invocation Claude Code's Bash tool makes.
- Child-env injection — `get_safe_env()` uses an ALLOWLIST (not just
  a blocklist): only PATH, HOME, XDG_*, LANG, LC_*, TERM, TZ, USER
  etc. survive into subprocesses. Future unknown auto-load env vars
  (new GCONV_PATH-style runtime quirks) can't silently reach children.
  DANGEROUS_ENV_VARS blocklist is additionally applied as belt-and-
  braces on the `get_safe_env` → `os.environ` path (CLASSPATH,
  MAVEN_OPTS, GRADLE_OPTS, CARGO_HOME, GEM_HOME, BUNDLE_GEMFILE,
  PHPRC, PHP_INI_SCAN_DIR, GIT_EXEC_PATH, GIT_TEMPLATE_DIR,
  EMACSLOADPATH, DOCKER_CONFIG, DOCKER_HOST, REQUESTS_CA_BUNDLE,
  CURL_CA_BUNDLE, SSL_CERT_FILE, SSL_CERT_DIR, plus the base LD_*
  / PYTHON* / JAVA_TOOL_OPTIONS / GIT_SSH_COMMAND / KUBECONFIG /
  etc. set). Caller-supplied `env=` is NOT filtered against the
  blocklist — callers legitimately use names from it as defensive
  neutralisers (e.g. `GIT_CONFIG_GLOBAL=/dev/null` to isolate git
  from user config). `env=None` is treated as "no env kwarg" (not
  "inherit os.environ wholesale" which is subprocess's default).
- Socket FDs via `pass_fds=[...]` — `sandbox().run()` stats each
  pass_fds entry and rejects S_ISSOCK. Pipes (S_ISFIFO) still pass.
  Closes the "inherited Unix-socket FD reaches /var/run/docker.sock"
  vector without breaking legitimate pipe-based stdin passing.
- `shell=True` misuse — rejected with TypeError. subprocess with
  shell=True reinterprets argv into `sh -c argv[0] argv[1:]`, which
  silently mangles our `unshare ... -- cmd` list construction AND
  is a shell-injection surface for any caller whose argv contains
  attacker-influenced strings.
- Controlling-tty keystroke-sniff — `run_untrusted()` defaults
  `start_new_session=True` so the child is a new session leader
  with no controlling tty, and `stdin=subprocess.DEVNULL` so fd 0
  isn't a tty either. A sandboxed tool running under an interactive
  RAPTOR invocation can't open `/dev/tty` to passively read
  operator keystrokes. (TIOCSTI injection is separately blocked by
  seccomp.)
- Child-planted symlink TOCTOU on parent-side writes into `output`:
  `{output}/proxy-events.jsonl` is opened with O_NOFOLLOW + fstat
  S_ISREG check; `{output}/.home/{,.config,.cache,.local,...}` are
  lstat-checked for symlink/FIFO/device before `os.makedirs`. A
  child that pre-plants these paths as symlinks to `~/.bashrc` /
  `~/.ssh/authorized_keys` / arbitrary user-writable files cannot
  redirect the parent's post-sandbox writes outside the sandbox
  boundary.
- Landlock self-test TOCTOU — the forked self-test uses
  `tempfile.mkstemp` (atomic O_EXCL|O_CREAT on a random suffix)
  rather than a per-pid predictable path; a same-user attacker
  that pre-plants `/tmp/.raptor_landlock_selftest_<pid>` as a
  symlink can no longer have the self-test truncate arbitrary
  user-writable files and write "x" to them.
- Fail-closed Landlock install — if `prctl(PR_SET_NO_NEW_PRIVS)` or
  `landlock_restrict_self` fails inside preexec after
  `check_landlock_available()` reported Landlock was ready, the
  child aborts via `os._exit(126)` rather than continuing under
  weaker-than-expected isolation. Parent sees a subprocess failure
  and can investigate.

What the sandbox does NOT protect against:
- Reads outside restrict_reads mode — Landlock is read-everywhere by
  default so build tools work. A PoC started with
  `restrict_reads=False` can read /etc/passwd, /proc/*, the entire
  source tree. `run_untrusted()` defaults `restrict_reads=True` so
  PoC execution doesn't need explicit opt-in.
- /dev/shm cross-sandbox visibility WITHOUT mount-ns — on Ubuntu
  24.04 the AppArmor sysctl blocks mount-ns, so /dev/shm remains
  host-shared. Under `restrict_reads=True` we exclude /dev wholesale
  from the read allowlist (granting specific safe files instead),
  which closes the /dev/shm read path. But mount-ns would be
  stronger (per-sandbox tmpfs). Operator can enable it: see the
  startup message for the exact sysctl.
- Host-shared `/tmp` WITHOUT mount-ns — child can create / delete /
  symlink files in the host's `/tmp`. Other same-UID host processes
  that write predictable `/tmp` paths without O_NOFOLLOW can be
  symlink-raced. Mount-ns mounts a fresh tmpfs at `/tmp` inside the
  sandbox and closes this; Landlock-only mode does not.
- Nested `unshare(CLONE_NEWUSER|CLONE_NEWNS)` on distros WITHOUT the
  `kernel.apparmor_restrict_unprivileged_userns=1` sysctl — we can't
  block unshare/setns/mount at the seccomp layer because our own
  bootstrap uses the `unshare` CLI AFTER seccomp is installed in
  preexec. A child on such a distro can create a nested user-ns
  with CAP_SYS_ADMIN-in-ns and experiment with bind-mount tricks.
  Landlock rules bind to dentries (not paths) and inherit into
  nested namespaces, so bind-mounts don't grant new dentry access;
  NO_NEW_PRIVS blocks seccomp drop. Bounded but not ironclad.
- UDP outbound when `block_network=False` AND no egress proxy —
  Landlock's network rule is TCP-connect only. For full network-off
  set `block_network=True` (the `full` profile default). For
  hostname-allowlisted outbound use `use_egress_proxy=True` which
  also blocks UDP via seccomp.
- Host fingerprinting via /proc/version, /etc/os-release, /proc/cpuinfo,
  /etc/machine-id, /sys/class/dmi/id/*. Tightening these would break
  real PoCs (glibc CPU-feature detection, ASAN's /proc/self/maps,
  dynamic linker's /etc/ld.so.cache). Accepted residual.
- Cross-PID-ns `/proc/<host_pid>/{cmdline,comm,status,stat}` —
  `/proc` stays host-shared under Landlock-only mode (no mount-ns);
  PID-ns isolation applies the kernel's ptrace-gated protection
  only to `environ` / `maps` / `mem`, NOT to cmdline/comm/status/
  stat. A child can enumerate host processes (PPid chain, argv
  parameters, comm strings) though not their environments or
  memory. Same-UID Linux baseline behaviour; sandbox-independent.
- /proc/<host_pid>/environ when `restrict_reads=False` — Landlock is
  read-everywhere by default, so without restrict_reads a child in
  Landlock-only mode can read host-pid /proc/<pid>/environ directly.
  `run_untrusted()` defaults `restrict_reads=True` which also triggers
  the PID-ns unshare.
- Detection-evasion via forged stderr — a compromised child can
  print fake `Permission denied: <writable-path>` lines to suppress
  `_check_blocked` evidence (observe.py matches on the pattern and
  skips the "blocked" alert if the captured path is within
  writable_paths). Enforcement-side: unaffected (Landlock already
  blocked the real attempt). Audit-side: attackers can hide their
  tracks. Same applies to proxy-event flood masking, though per-
  sandbox buffers (see Egress proxy above) eliminate the cross-
  sandbox flood variant.
- Fork bombs under `profile=none` — no user namespace to anchor
  RLIMIT_NPROC against, so the limit would kill host-UID work.
  `profile=none` is explicit opt-out.
- Kernel 0day. No in-process mitigation possible.
- Older Landlock ABI bypass: on ABI < 2 `rename` / `hardlink` across
  writable boundaries; on ABI < 3 `O_TRUNC` on files outside writable
  paths (though DAC may still block); on ABI < 4 `allowed_tcp_ports`
  does not engage — the egress proxy's hostname allowlist is still
  enforced at the CONNECT layer, but the child can connect to
  arbitrary TCP ports directly. One-shot warning per process names
  each missing-ABI gap.
- Seccomp bypass via arch-missing syscalls on exotic architectures
  (libseccomp returns negative for unknown names). One-shot warning
  lists any unresolved syscalls so operators can decide.
- `pass_fds` non-socket FD abuse — pipes and regular-file FDs are
  allowed through. Sockets are rejected (see above). Callers passing
  `close_fds=False` are rejected with TypeError.
- Caller `env=` override bypasses `get_safe_env()` entirely —
  neither the allowlist nor the DANGEROUS_ENV_VARS blocklist is
  applied. Explicit `env=` is a "you know what you're doing"
  signal. Logged at INFO so the override is auditable.
- Tools that hardcode `/home/<user>/...` paths (not via `$HOME`)
  bypass `fake_home` and hit the real path → EACCES under
  restrict_reads. Real fix needs mount-ns.
- Concurrent sandbox attribution — each sandbox() registered with
  the egress proxy receives every tunnel event that happens during
  its registration window, including events driven by OTHER
  concurrent sandboxes. `caller_label` is stamped per-sandbox so
  post-hoc filtering can separate them, but cross-sandbox mixing at
  event-generation time would need per-CONNECT source-port mapping
  that we don't do.
- Caller-side file reads from `output` — the sandbox hardens its
  OWN post-sandbox reads/writes (proxy-events.jsonl, fake_home).
  Consumer code that reads generated files from `output` (SARIF
  parsers, scan-result loaders) must use their own O_NOFOLLOW /
  validation if they want to defend against child-planted symlinks
  redirecting their reads. Not the sandbox module's job to audit.
- `SHELL` / `TERM` env vars are in the allowlist — low risk in
  practice (most tools hardcode `/bin/sh` rather than exec $SHELL,
  and TERM is a terminfo lookup key not a shell-evaluated string),
  but a tool that does `os.system($SHELL + ...)` would follow an
  attacker-set SHELL, and ncurses has historical CVEs around
  crafted TERM values. Accepted residual — stripping either would
  break legitimate coloured output and shell-invocation paths.

Profiles (downgrade path for tools that need a blocked capability):
- `full` (default): net-ns + Landlock + seccomp + rlimits.
- `debug`: full, but seccomp permits ptrace (for gdb/rr).
- `network-only`: drops Landlock AND seccomp; keeps net-ns.
- `none`: rlimits only. Last resort.
Set via `--sandbox <profile>` on the CLI. CLI flag is AUTHORITATIVE
— it wins over caller-supplied `profile=` and `disabled=True`.

Startup banner shows which layers are available:
  sandbox ✓ (net+mount+landlock)  — full isolation
  sandbox ✓ (net+landlock)        — common on Ubuntu 24.04
  sandbox ✓ (landlock)            — container without user namespaces
  sandbox ✗                       — no isolation available

Sandboxing by tool type:
- PoC execution, LLM-generated code: `run_untrusted()` — full sandbox
  with restrict_reads=True + fake_home=True by default.
- Claude sub-agents, CodeQL pack download: `sandbox()` with
  `use_egress_proxy=True, proxy_hosts=[...]` — full network isolation
  except hostname-allowlisted HTTPS through the local proxy.
- Scanners, compilers against attacker-derived code (gcc, semgrep,
  CodeQL): `run_untrusted()` or `sandbox(block_network=True)`. Some
  tools need HOME writable (semgrep's cache, maven's ~/.m2) — caller
  redirects HOME via env or fake_home pre-population.
- Binary-analysis tools on RAPTOR-chosen paths (readelf, nm, strings,
  objdump): `run_trusted()` — env-sanitised, rlimited, no namespace
  overhead.
- GDB / debugger: `sandbox(profile="debug")` + fake_home.

Two entrypoints for 90% of callers:
    from core.sandbox import run_trusted, run_untrusted

    # Trusted tool on a RAPTOR-chosen binary — no ns, no Landlock
    run_trusted(["readelf", "-h", binary_path],
                capture_output=True, text=True)

    # Untrusted code — full sandbox + restrict_reads + fake_home
    run_untrusted(["./poc", "arg"], target=work_dir, output=work_dir)

For bespoke isolation or multi-command blocks, use the context manager:
    from core.sandbox import sandbox

    with sandbox(use_egress_proxy=True,
                 proxy_hosts=["api.anthropic.com"],
                 target=repo, output=out,
                 caller_label="my-agent") as run:
        run(["claude", ...])

Module layout:
- state.py       — module-level mutable state (caches, flags, warn-once)
- profiles.py    — PROFILES constant + _SANDBOX_KWARGS
- probes.py      — check_net_available, check_mount_available,
                   safe-bin-dir resolver (hard-fail on missing util-linux)
- landlock.py    — preexec builder + check_landlock_available with
                   runtime functional self-test (tempfile.mkstemp).
                   Fail-closed (os._exit 126) on restrict_self failure.
- seccomp.py     — seccomp preexec builder, syscall+ioctl+socket-family
                   filter, explicit BADARCH=KILL_PROCESS
- preexec.py     — rlimit composition, user-config loading
- mount.py       — legacy shell-mount-script builder. Superseded by
                   mount_ns.py + _spawn.py and no longer called from
                   sandbox().run(); retained only because a handful of
                   tests cover its argv-injection defences (`--`
                   separator, shlex.quote). Delete when those assertions
                   are ported to mount_ns.
- mount_ns.py    — ctypes-based mount syscalls (make-rprivate, tmpfs
                   root, bind mounts, pivot_root). Runs inside the
                   forked child after newuidmap, BEFORE Landlock
                   install — Landlock on kernel 6.15+ blocks mount
                   topology changes, so ordering is load-bearing.
- _spawn.py      — run_sandboxed(): fork-based alternative to
                   subprocess.Popen(preexec_fn=...). Parent does
                   newuidmap on the child's PID (setuid-root helper,
                   bypasses the /proc/self/uid_map EPERM that direct
                   unprivileged writes hit). Used when mount-ns is
                   engaged; bypassed for Landlock-only which stays on
                   the subprocess+preexec path.
- observe.py     — result interpretation, blocked-stderr detection,
                   SIGSYS labelling for seccomp kills; ASAN bug_type
                   and attempted_path are sanitised via
                   core.security.log_sanitisation
- cli.py         — add_cli_args / apply_cli_args / set_cli_profile
- proxy.py       — EgressProxy (asyncio CONNECT tunnel, hostname
                   allowlist, upstream HTTPS_PROXY support). Per-
                   sandbox event registration (register_sandbox /
                   unregister_sandbox) replaces the old shared
                   ring buffer; each sandbox's buffer is isolated
                   from concurrent-sandbox flood pushout.
- context.py     — sandbox() context manager + run/run_trusted/
                   run_untrusted wrappers; wires proxy, fake_home,
                   restrict_reads, event attachment, stdin=DEVNULL,
                   start_new_session, shell=True reject, env=None
                   normalisation (caller-supplied env= passes through
                   verbatim, logged at INFO — see "What the sandbox
                   does NOT protect against").
- __init__.py    — this file (docstring + re-exports)

Related shared helpers (core.security):
- log_sanitisation.py  — escape_nonprintable() / has_nonprintable().
                         Used by cmd_display, ASAN bug_type, proxy
                         CONNECT-target rejection. Shared so other
                         RAPTOR components (SARIF parsers, report
                         generators) can reuse the same primitive.
- env_sanitisation.py  — strip_env_vars() / intersect_env_vars().
                         Used by get_safe_env() to apply the
                         DANGEROUS_ENV_VARS blocklist on top of the
                         allowlist.
"""

# Public re-exports — the surface other code imports from `core.sandbox`.
from .cli import (
    add_cli_args,
    apply_cli_args,
    disable_from_cli,
    set_cli_profile,
)
from .context import run, run_trusted, run_untrusted, run_untrusted_networked, sandbox
from .landlock import check_landlock_available, _get_landlock_abi
from .observe import _BLOCKED_PATTERNS, _check_blocked, _interpret_result, _path_within
from .observe_profile import (
    OBSERVE_FILENAME, ConnectTarget, ObserveProfile, parse_observe_log,
)
from .preexec import _DEFAULT_LIMITS, _load_user_limits, _make_preexec_fn
from .mount import _build_mount_script
from .probes import (
    check_mount_available, check_net_available, check_sandbox_available,
    check_seatbelt_available,
)
from .profiles import DEFAULT_PROFILE, PROFILES, _SANDBOX_KWARGS
from .seccomp import check_seccomp_available

# Re-exports for private symbols some tests / callers depend on.
# Keeping them at the package level preserves backward compatibility while
# the real definitions live in focused submodules.
from . import state as _state

_cache_lock = _state._cache_lock


def __getattr__(name):
    """Forward reads of private state names to the `state` submodule.

    This preserves `import core.sandbox as mod; mod._cli_sandbox_profile`
    after the module split — the real definition lives in
    `core.sandbox.state`, but tests and old callers still work against
    the package namespace.

    Only forwards attributes that actually exist in `state`; everything
    else raises AttributeError per normal Python semantics.
    """
    if hasattr(_state, name):
        return getattr(_state, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Note: `__getattr__` above handles READS of state names through the
# package, but WRITES (`core.sandbox._cli_sandbox_profile = X`) do not
# flow through __getattr__ and would set a NEW attribute on the package
# instead of the state submodule. Tests that need to mutate sandbox
# state should write via `core.sandbox.state.<name> = X` — the conftest
# fixture already does this.

__all__ = [
    # Context manager and convenience wrappers
    "sandbox", "run", "run_trusted", "run_untrusted", "run_untrusted_networked",
    # CLI surface
    "add_cli_args", "apply_cli_args", "disable_from_cli", "set_cli_profile",
    # Availability probes (exposed for the startup banner)
    "check_sandbox_available", "check_net_available",
    "check_mount_available", "check_landlock_available",
    "check_seatbelt_available",
    "check_seccomp_available",
    # Named profiles
    "PROFILES", "DEFAULT_PROFILE", "_SANDBOX_KWARGS",
    # Private re-exports kept for backward compatibility — see the
    # block comment above; tests + a few internal callers reach into
    # these names directly so the public name stays stable.
    "_get_landlock_abi",
    "_BLOCKED_PATTERNS", "_check_blocked", "_interpret_result", "_path_within",
    "OBSERVE_FILENAME", "ConnectTarget", "ObserveProfile", "parse_observe_log",
    "_DEFAULT_LIMITS", "_load_user_limits", "_make_preexec_fn",
    "_build_mount_script",
]
