"""Host-fingerprint sanitisation overlay for sandboxed children.

Opt-in via `sandbox(..., sanitise_host_fingerprint=True)`. When engaged,
the mount-ns child bind-mounts canonical files over the host's identity
surfaces and the spawn machinery sets a canonical UTS namespace +
sched_setaffinity mask:

  /proc/cpuinfo                          → N blocks, host flags preserved
  /proc/version                          → "Linux version <host-release>\\n"
  /proc/cmdline                          → canonical stub
  /proc/stat                             → aggregate + N per-cpu lines
  /etc/os-release                        → Debian 12 stub
  /etc/machine-id                        → deterministic-pseudo-random
  /etc/hostname                          → "localhost"
  /sys/class/dmi/id/sys_vendor           → "QEMU"
  /sys/class/dmi/id/product_name         → "Standard PC (i440FX + PIIX, 1996)"
  /sys/devices/system/cpu/online         → 0..N-1
  /sys/devices/system/cpu/possible       → 0..N-1
  uname() nodename                       → "localhost"
  uname() domainname                     → "localdomain"
  sched_getaffinity                      → bits 0..N-1

Persona = "boring Debian 12 cloud VM on QEMU/KVM with Intel Xeon" —
picked for hide-intent (most common Linux workload; doesn't tip off
the sandbox). All sentinel-looking values that would identify us as
analysis infrastructure ("sandbox" hostname, all-zero machine-id,
"Generic x86_64 CPU" model) are deliberately avoided.

What's PRESERVED from the host (capability surface, not identity):
  - /proc/cpuinfo `flags` line (SMEP/SMAP detection in
    packages/exploit_feasibility, SIMD dispatch, ASAN shadow-mem)
  - uname() sysname (always "Linux"), release (kernel version for
    exploit_feasibility's `uname -r`), machine (arch — shellcode
    payload dispatch needs it)
  - /proc/sys/kernel/{randomize_va_space, kptr_restrict,
    yama/ptrace_scope}, /proc/sys/vm/mmap_min_addr (mitigation reads)
  - /proc/self/* (maps, exe, status, auxv — ASAN, GDB, pwntools
    context.aslr depend on real values)

Residuals (documented; not addressed by this module):
  - CPUID asm bypass — direct cpuid execution reads real CPU; fix
    needs ptrace syscall rewriting + userspace emulator (out of scope).
  - AT_HWCAP auxiliary vector — kernel-supplied at exec; not file-based.
  - Vendor preservation via flags-line — Intel-vs-AMD distinguishable
    via flag-set differences (e.g. AMD-specific flags). Trade-off for
    SIMD compat.

Platform support: Linux only. macOS lacks unprivileged bind-mount +
UTS-namespace primitives, and most host-identity reads on macOS are
syscall/IOKit-based (sysctlbyname, IORegistryEntry) — not file-based.
`is_supported()` returns False on non-Linux; callers should soft-
degrade with a one-shot WARNING (matching the pattern used by
restrict_reads when Landlock is unavailable).
"""

from __future__ import annotations

import ctypes
import ctypes.util as _ctypes_util
import hashlib
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# === Public sentinels ===

# Sentinel for the `cpu_count` argument meaning "preserve the host's
# actual CPU count" — build_persona resolves it from
# len(os.sched_getaffinity(0)) at build time, and set_cpu_affinity
# becomes a no-op (the existing host mask already matches).
#
# Use case: callers like `codeql database create` that engage a
# target-repo parallel build (make -j$(nproc), mvn -T NC). Pinning
# to the default cpu_count=4 on a 32-core CI host causes ~8x build
# slowdown and pushes long builds past CODEQL_TIMEOUT.
# HOST_CPU_COUNT preserves real parallelism while still masking
# identity (model name, vendor, microcode, hostname, machine-id,
# DMI, /proc/version, etc.).
#
# Caveat: leaks CPU count to the target (a 32-core operator is
# distinguishable from a 4-core operator). Acceptable when the
# caller's primary motivation is anti-analysis identity masking,
# not full anti-fingerprint capability masking.
HOST_CPU_COUNT = -1


# === Persona constants ===

# Hostname / domainname — applied via sethostname() / setdomainname()
# inside the UTS namespace. Use the most universal default; "sandbox"
# / "analyst" / "malware" are all known anti-analysis triggers.
_HOSTNAME = "localhost"
_DOMAINNAME = "localdomain"

# /etc/machine-id: deterministic-pseudo-random per RAPTOR install.
# Identical across runs from one install (cross-run determinism),
# different across installs (defeats published-fingerprint attacks
# where a malware author who knows RAPTOR can pre-compute a literal
# hash to match against — the seed includes the install path which
# is operator-specific).
#
# All-zeros (which we initially considered) is a known sandbox tell:
# it indicates pre-systemd-machine-id-setup early boot or some
# minimal containers, both unusual for "real" hosts. A literal
# "sha256('raptor-sandbox-v1')" was the prior implementation but
# being open-source it was a single grep away from a one-line bypass.
def _derive_machine_id() -> str:
    # Use RAPTOR_DIR (operator's install path) as the per-install
    # entropy. Falls back to this module's directory if RAPTOR_DIR
    # is unset — that path is also install-specific.
    seed = os.environ.get("RAPTOR_DIR") or os.path.dirname(
        os.path.abspath(__file__)
    )
    return hashlib.sha256(
        b"raptor-fingerprint-v1\0" + seed.encode("utf-8", errors="replace")
    ).hexdigest()[:32]


_MACHINE_ID = _derive_machine_id()

_OS_RELEASE = (
    'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
    'NAME="Debian GNU/Linux"\n'
    'VERSION_ID="12"\n'
    'VERSION="12 (bookworm)"\n'
    'VERSION_CODENAME=bookworm\n'
    'ID=debian\n'
    'HOME_URL="https://www.debian.org/"\n'
    'SUPPORT_URL="https://www.debian.org/support"\n'
    'BUG_REPORT_URL="https://bugs.debian.org/"\n'
)

# /proc/cmdline: generic VM-ish boot. Avoids known-VM markers like
# console=ttyS0 (a QEMU/virt tell beyond just QEMU DMI).
_CMDLINE = "BOOT_IMAGE=/boot/vmlinuz root=/dev/vda1 ro quiet\n"

# DMI: canonical QEMU/KVM strings. Mirrors what a default-built QEMU
# Standard PC presents — extremely common workload identity.
_DMI_SYS_VENDOR = "QEMU\n"
_DMI_PRODUCT_NAME = "Standard PC (i440FX + PIIX, 1996)\n"

# /proc/cpuinfo block — per-processor. Per-CPU fields are templated
# with the processor index and the global cpu_count. The `flags` field
# is templated with the host's actual flags so capability dispatch
# (SMEP/SMAP detection, SIMD, ASAN shadow-mem) keeps working.
#
# Identity triple = (family 6, model 85, stepping 7, microcode 0x5003901):
# real values for Intel Xeon Silver 4214 (Skylake-X / Cascade Lake) —
# one of the most common server SKUs on EC2/GCE/Azure. Picking ANY
# real (family, model, stepping, microcode) tuple defeats the
# `(f, m, s, mc) ∈ known_real_set` anti-analysis check; the family=6
# model=1 stepping=0 microcode=0x0 combination we initially shipped
# was the equivalent of a 1995 Pentium Pro on first boot — instantly
# anomalous.
#
# `cpu MHz` and `bogomips` carry small deterministic offsets from the
# round number rather than exact `2400.000` / `4800.00` — real CPUs
# report `2399.9xx` / `4799.9xx` with sub-Hz jitter, and a "≡ 0 mod
# 100" check is a soft tell that costs us nothing to defeat.
_CPUINFO_TEMPLATE = """processor\t: {processor}
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz
stepping\t: 7
microcode\t: 0x5003901
cpu MHz\t\t: 2199.998
cache size\t: 16896 KB
physical id\t: 0
siblings\t: {cpu_count}
core id\t\t: {processor}
cpu cores\t: {cpu_count}
apicid\t\t: {processor}
initial apicid\t: {processor}
fpu\t\t: yes
fpu_exception\t: yes
cpuid level\t: 22
wp\t\t: yes
flags\t\t: {flags}
bugs\t\t:
bogomips\t: 4399.99
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 46 bits physical, 48 bits virtual
power management:
"""


@dataclass(frozen=True)
class Persona:
    """A materialised host-fingerprint persona ready for bind-mounting.

    `files`: absolute target path → temp source path. Each entry is
    bind-mounted source→target by `apply_overlay()` inside the
    mount-ns child.

    `cpu_count`: number of logical CPUs the persona claims. The
    cpuinfo file already contains the matching number of `processor`
    blocks; this field is held separately so the spawn machinery can
    pin sched_setaffinity to a matching mask (kept in sync = no
    cross-check sandbox tell).

    `hostname`, `domainname`: applied via sethostname() / setdomainname()
    inside the UTS namespace by the spawn machinery — held separate from
    `files` because the UTS-ns + syscall path is the only way to affect
    uname() output. Bind-mounting /etc/hostname alone wouldn't change
    what gethostname() returns.
    """
    files: dict[str, str]
    cpu_count: int
    hostname: str = _HOSTNAME
    domainname: str = _DOMAINNAME


def build_persona(tmpdir: Path, cpu_count: int) -> Persona:
    """Materialise persona files under `tmpdir` and return the Persona.

    cpu_count must be >= 1 OR the HOST_CPU_COUNT sentinel. When the
    sentinel is passed, cpu_count is resolved to the host's actual
    schedulable CPU count via len(os.sched_getaffinity(0)) — useful
    for callers that engage target parallel builds (codeql database
    create runs make/mvn/gradle, which need the real CPU count to
    avoid build serialisation). set_cpu_affinity for that resolved
    value is a no-op (matches the existing mask) so no CPU pin is
    applied. The persona.cpu_count attribute reflects the resolved
    integer either way.

    The /proc/cpuinfo file will contain `cpu_count` `processor`
    blocks; the matching `sched_setaffinity` mask is the caller's
    responsibility (see `set_cpu_affinity`).

    Reads the host's /proc/cpuinfo `flags` line ONCE so all per-CPU
    blocks share the same flag set. Host flags are preserved
    deliberately: SIMD dispatch (ASAN, glibc, JITs) and SMEP/SMAP
    feasibility detection in packages/exploit_feasibility key off
    them. Empty string if host /proc/cpuinfo unreadable — handled
    gracefully (tools fall back to default code paths).
    """
    if cpu_count == HOST_CPU_COUNT:
        cpu_count = len(os.sched_getaffinity(0))
    if cpu_count < 1:
        raise ValueError(
            f"cpu_count must be >= 1 or HOST_CPU_COUNT, got {cpu_count}"
        )
    tmpdir = Path(tmpdir)
    tmpdir.mkdir(parents=True, exist_ok=True)

    files: dict[str, str] = {}

    # /proc/cpuinfo — N blocks separated by blank lines (kernel format).
    flags = _read_host_cpu_flags()
    blocks = [
        _CPUINFO_TEMPLATE.format(
            processor=i, cpu_count=cpu_count, flags=flags,
        )
        for i in range(cpu_count)
    ]
    files["/proc/cpuinfo"] = _write(tmpdir / "cpuinfo", "\n".join(blocks))

    # /proc/version — trim host's version to "Linux version <release>".
    files["/proc/version"] = _write(tmpdir / "version", _trim_proc_version())

    # /proc/cmdline — canonical stub.
    files["/proc/cmdline"] = _write(tmpdir / "cmdline", _CMDLINE)

    # /etc/{os-release, machine-id, hostname}
    files["/etc/os-release"] = _write(tmpdir / "os-release", _OS_RELEASE)
    files["/etc/machine-id"] = _write(tmpdir / "machine-id", _MACHINE_ID + "\n")
    files["/etc/hostname"] = _write(tmpdir / "hostname", _HOSTNAME + "\n")

    # /sys/class/dmi/id/ — sys_vendor + product_name only.
    # The omitted identity files (board_serial, product_uuid, etc.)
    # remain host-real but are typically blocked by Landlock's
    # restrict_reads allowlist (DMI dir isn't on the default list).
    dmi_dir = tmpdir / "dmi"
    dmi_dir.mkdir(exist_ok=True)
    files["/sys/class/dmi/id/sys_vendor"] = _write(
        dmi_dir / "sys_vendor", _DMI_SYS_VENDOR,
    )
    files["/sys/class/dmi/id/product_name"] = _write(
        dmi_dir / "product_name", _DMI_PRODUCT_NAME,
    )

    # /sys/devices/system/cpu/{online,possible} — match cpu_count.
    # Single-CPU systems write "0" (not "0-0") to match kernel format.
    cpu_range = f"0-{cpu_count - 1}\n" if cpu_count > 1 else "0\n"
    files["/sys/devices/system/cpu/online"] = _write(
        tmpdir / "cpu_online", cpu_range,
    )
    files["/sys/devices/system/cpu/possible"] = _write(
        tmpdir / "cpu_possible", cpu_range,
    )

    # /proc/{stat,uptime,loadavg} — internally consistent fake-uptime
    # set. The earlier draft shipped /proc/stat with btime=1700000000
    # and processes=1 while letting host /proc/uptime leak through —
    # a malware cross-check seeing "system booted 2 years ago but has
    # been up 4 hours" would flag immediately. Now all three derive
    # from the same fake-uptime value: btime = now - uptime, uptime
    # = the value, loadavg shows a plausible low-load system.
    #
    # Fake uptime is deterministic per RAPTOR install (same seed as
    # _MACHINE_ID) so cross-run output is stable for one operator,
    # but jitters across installs (defeats published-fingerprint).
    # Range chosen to look like a multi-day-uptime production VM:
    # ~3 days to ~30 days.
    fake_uptime_s, fake_processes = _derive_uptime_and_processes()
    btime = int(_now()) - fake_uptime_s

    stat_lines = ["cpu  100 0 50 1000 0 0 0 0 0 0\n"]
    for i in range(cpu_count):
        stat_lines.append(f"cpu{i} 100 0 50 1000 0 0 0 0 0 0\n")
    stat_lines.append(
        f"intr 0\nctxt 0\nbtime {btime}\n"
        f"processes {fake_processes}\nprocs_running 1\n"
        f"procs_blocked 0\nsoftirq 0\n"
    )
    files["/proc/stat"] = _write(tmpdir / "stat", "".join(stat_lines))

    # /proc/uptime — two floats: total uptime seconds + idle seconds.
    # idle ≈ uptime * cpu_count (each CPU accumulates idle independently).
    # Real systems report idle ≈ 0.97 * uptime * cpu_count on a low-load
    # box; we pick 0.95 to leave a small "we've done some work" signal.
    idle = int(fake_uptime_s * cpu_count * 0.95)
    files["/proc/uptime"] = _write(
        tmpdir / "uptime", f"{fake_uptime_s}.00 {idle}.00\n",
    )

    # /proc/loadavg — low-load values + a plausible "running/total
    # tasks" pair + last-pid (matches `processes` in /proc/stat for
    # internal consistency).
    files["/proc/loadavg"] = _write(
        tmpdir / "loadavg",
        f"0.08 0.12 0.10 1/{fake_processes // 100} {fake_processes}\n",
    )

    return Persona(files=files, cpu_count=cpu_count)


def _now() -> float:
    """Wrapped for monkeypatching in tests."""
    import time
    return time.time()


def _derive_uptime_and_processes() -> tuple[int, int]:
    """Pick a fake uptime + processes counter, deterministic per
    RAPTOR install. Uptime in [3 days, 30 days], processes in
    [10000, 200000] — both plausible production-VM ranges.

    Seed is the same as _MACHINE_ID so a single install consistently
    presents the same uptime + processes across runs of the same
    target. Different installs see different values (cross-operator
    output drift, but local determinism).
    """
    seed = os.environ.get("RAPTOR_DIR") or os.path.dirname(
        os.path.abspath(__file__)
    )
    h = hashlib.sha256(
        b"raptor-fingerprint-uptime-v1\0" + seed.encode("utf-8", errors="replace")
    ).digest()
    # 3 days = 259200; 30 days = 2592000. Range = 2332800.
    uptime = 259200 + (int.from_bytes(h[:4], "big") % 2332800)
    # 10000 ≤ processes ≤ 210000
    processes = 10000 + (int.from_bytes(h[4:8], "big") % 200000)
    return uptime, processes


def _write(path: Path, content: str) -> str:
    """Helper: write content, return absolute path as str."""
    path.write_text(content)
    return str(path)


def _read_host_cpu_flags() -> str:
    """Return the host's /proc/cpuinfo `flags` line value (space-
    separated flag names; no `flags\\t:` prefix).

    Empty string on failure — handled gracefully by build_persona.
    """
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("flags"):
                    _, _, value = line.partition(":")
                    return value.strip()
    except OSError:
        pass
    return ""


def _trim_proc_version() -> str:
    """Return host /proc/version with build-host/compiler/timestamp
    fingerprint stripped, preserving only `Linux version <release>`.

    Example: "Linux version 6.8.0-49-generic (buildd@...) (gcc ...) #49-..."
             becomes "Linux version 6.8.0-49-generic\\n"
    """
    try:
        with open("/proc/version") as f:
            raw = f.read().strip()
    except OSError:
        return "Linux version unknown\n"
    m = re.match(r"^(Linux version \S+)", raw)
    if not m:
        return "Linux version unknown\n"
    return m.group(1) + "\n"


# === libc bindings ===
# Python's os module exposes neither sethostname nor setdomainname
# (only os.uname() for reading). Both syscalls require CAP_SYS_ADMIN
# in the UTS namespace owner's user-ns — granted automatically inside
# our user-ns (where we map to uid 0) PROVIDED CLONE_NEWUTS was
# included in the unshare flags.

_libc: ctypes.CDLL | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(_ctypes_util.find_library("c"), use_errno=True)
    return _libc


def set_uts(hostname: str, domainname: str) -> None:
    """Set hostname + domainname in the current UTS namespace.

    Must be called from inside the sandbox child AFTER
    unshare(CLONE_NEWUTS|CLONE_NEWUSER) AND AFTER the parent's
    newuidmap has run (we need uid 0 in the ns for CAP_SYS_ADMIN).

    Raises OSError on failure. Caller decides whether to abort the
    sandbox or degrade silently.
    """
    libc = _get_libc()
    h = hostname.encode()
    d = domainname.encode()
    if libc.sethostname(h, len(h)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"sethostname({hostname!r}): {os.strerror(err)}")
    if libc.setdomainname(d, len(d)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"setdomainname({domainname!r}): {os.strerror(err)}")


def set_cpu_affinity(cpu_count: int) -> int:
    """Pin the calling process to logical CPUs 0..cpu_count-1.

    Returns the count actually applied (may be less than requested if
    the host doesn't have that many CPUs available in the current
    affinity set; we clamp rather than fail because the persona's
    other CPU surfaces — /proc/cpuinfo blocks, /sys/cpu/online — can
    still claim cpu_count without contradiction; the only cross-check
    a paranoid binary could do is sched_getaffinity().popcount()
    vs cpuinfo count, and clamping creates that one tell. Logged at
    INFO so the operator knows the persona partially degraded.

    Raises OSError only if sched_setaffinity fails for non-clamp
    reasons (kernel error, EPERM in some namespace setups).
    """
    if cpu_count < 1:
        raise ValueError(f"cpu_count must be >= 1, got {cpu_count}")
    available = os.sched_getaffinity(0)
    effective = min(cpu_count, len(available))
    if effective < cpu_count:
        logger.info(
            "sanitise_host_fingerprint: cpu_count=%d requested but only "
            "%d CPUs available in this affinity set; clamping. The persona's"
            " /proc/cpuinfo will still report %d processors — a paranoid "
            "binary cross-checking sched_getaffinity() popcount against "
            "cpuinfo could detect the discrepancy.",
            cpu_count, effective, cpu_count,
        )
    # Pick the lowest-numbered available CPUs so the mask is contiguous
    # starting at 0, matching the persona's `/sys/cpu/online` range.
    mask = set(sorted(available)[:effective])
    os.sched_setaffinity(0, mask)
    return effective


def apply_overlay(persona: Persona, root_prefix: str = "") -> None:
    """Bind-mount each persona file over its target path.

    MUST be called inside the mount-ns child BEFORE pivot_root —
    because the persona's source files live in the parent's /tmp,
    which becomes inaccessible post-pivot (the fresh per-sandbox
    tmpfs mounted at {root}/tmp shadows it).

    The target path resolution is prefixed by `root_prefix` so the
    caller can target `{root}/proc/cpuinfo` etc. while the sandbox
    is still in its pre-pivot setup. After pivot_root, those binds
    are visible at the un-prefixed path (`/proc/cpuinfo`) — same
    mechanism as the /usr, /lib bind-mounts that setup_mount_ns
    does earlier.

    Must run AFTER setup_mount_ns has bind-mounted /proc, /etc, /sys
    into {root} (otherwise the target paths don't exist), and BEFORE
    Landlock install (kernel 6.15+ blocks mount topology changes
    after landlock_restrict_self).

    Failure handling: a single failing bind-mount logs at debug and
    continues. Partial coverage is better than no coverage, and some
    kernels/configs may not support bind-over for specific paths.
    Tests assert per-file content visibility under a full setup.
    """
    # Use the same _mount wrapper as mount_ns.py to keep OSError
    # semantics identical across the module boundary.
    from .mount_ns import _mount, MS_BIND
    for target, source in persona.files.items():
        inside = f"{root_prefix}{target}"
        if not os.path.exists(inside):
            logger.debug(
                "fingerprint: target %s does not exist; "
                "skipping bind-mount", inside,
            )
            continue
        try:
            _mount(source, inside, None, MS_BIND)
        except OSError as e:
            logger.debug(
                "fingerprint: bind %s → %s failed: %s",
                source, inside, e,
            )


def is_supported() -> bool:
    """Return True if the host platform can apply fingerprint sanitisation.

    Linux only. macOS lacks unprivileged bind-mount + UTS namespace
    primitives, and most host-identity reads there are syscall- or
    IOKit-based (sysctlbyname, IORegistryEntry) — not file-based, so
    file substitution wouldn't catch them. Recommended path for
    untrusted-binary analysis on macOS: run RAPTOR in a Linux VM
    (Virtualization.framework, since macOS 13).
    """
    return sys.platform == "linux"
