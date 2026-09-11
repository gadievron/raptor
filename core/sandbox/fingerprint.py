r"""Host-fingerprint sanitisation overlay for sandboxed children.

Opt-in via `sandbox(..., sanitise_host_fingerprint=True)`. When engaged,
the mount-ns child bind-mounts canonical files over the host's identity
surfaces and the spawn machinery sets a canonical UTS namespace +
sched_setaffinity mask:

  /proc/cpuinfo                          → N blocks, host flags preserved
  /proc/version                          → "Linux version <host-release>\n"
  /proc/cmdline                          → canonical stub
  /proc/stat                             → aggregate + N per-cpu lines
  /proc/uptime                           → fake uptime + derived idle
  /proc/loadavg                          → low-load stub, consistent
                                           with /proc/stat processes
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
import errno
import hashlib
import heapq
import logging
import os
import threading
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


def _host_cpu_count() -> int:
    """Schedulable CPU count, portable across platforms.

    Linux exposes the cpuset-aware count via ``os.sched_getaffinity``;
    on platforms without it (macOS, Windows) fall back to
    ``os.cpu_count()``. Mirrors the guard in ``core.tuning`` so
    ``build_persona(cpu_count=HOST_CPU_COUNT)`` does not raise
    ``AttributeError`` off Linux.
    """
    getaff = getattr(os, "sched_getaffinity", None)
    if getaff is not None:
        return len(getaff(0))
    return os.cpu_count() or 1


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
    # Per-install entropy from this module's own directory — install-
    # specific AND environment-independent. The previous env-first
    # form (RAPTOR_DIR with a module-dir fallback) made the persona
    # identity depend on whether RAPTOR_DIR happened to be exported:
    # the same install produced different machine-id (and every value
    # derived from the seed) between launcher-spawned and bare-shell
    # invocations, breaking the cross-run determinism this constant
    # promises.
    seed = os.path.dirname(os.path.abspath(__file__))
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
# One coherent "boring QEMU/SeaBIOS VM" story: every world-readable
# DMI identity file agrees with every other. Values mirror a stock
# QEMU i440FX guest.
_DMI_STORY = {
    "sys_vendor": "QEMU\n",
    "product_name": "Standard PC (i440FX + PIIX, 1996)\n",
    "product_family": "\n",
    "product_version": "pc-i440fx-8.2\n",
    "bios_vendor": "SeaBIOS\n",
    "bios_version": "1.16.3-debian-1.16.3-2\n",
    "bios_date": "04/01/2014\n",
    "bios_release": "0.0\n",
    "board_vendor": "QEMU\n",
    "board_name": "Standard PC (i440FX + PIIX, 1996)\n",
    "board_version": "pc-i440fx-8.2\n",
    "chassis_vendor": "QEMU\n",
    "chassis_type": "1\n",
    "chassis_version": "pc-i440fx-8.2\n",
    # World-readable identity stragglers: modalias CONCATENATES the
    # whole DMI table (bvnAmazonEC2...pn<instance-type> on cloud
    # hosts — the loudest single file), and asset tags / SKU can
    # carry inventory ids (the EC2 instance id rides
    # board_asset_tag). Empty is what stock QEMU reports for
    # tags/SKU; modalias is synthesized from the story below.
    "board_asset_tag": "\n",
    "chassis_asset_tag": "\n",
    "product_sku": "\n",
}

# dmi:bvn<bios_vendor>bvr<bios_version>bd<bios_date>... — the kernel
# concatenates the table into ONE world-readable line; it must agree
# with every per-file value above or the mask refutes itself.
_DMI_STORY["modalias"] = (
    "dmi:bvn{bv}:bvr{bvr}:bd{bd}:br{br}:svn{sv}:pn{pn}:pvr{pvr}:"
    "rvn{rv}:rn{rn}:rvr{rvr}:cvn{cv}:ct{ct}:cvr{cvr}:sku{sku}:\n".format(
        bv=_DMI_STORY["bios_vendor"].strip(),
        bvr=_DMI_STORY["bios_version"].strip(),
        bd=_DMI_STORY["bios_date"].strip(),
        br=_DMI_STORY["bios_release"].strip(),
        sv=_DMI_STORY["sys_vendor"].strip(),
        pn=_DMI_STORY["product_name"].strip(),
        pvr=_DMI_STORY["product_version"].strip(),
        rv=_DMI_STORY["board_vendor"].strip(),
        rn=_DMI_STORY["board_name"].strip(),
        rvr=_DMI_STORY["board_version"].strip(),
        cv=_DMI_STORY["chassis_vendor"].strip(),
        ct=_DMI_STORY["chassis_type"].strip(),
        cvr=_DMI_STORY["chassis_version"].strip(),
        sku=_DMI_STORY["product_sku"].strip(),
    ))
# /sys/class/dmi/id/uevent is the modalias's TWIN: the kernel frames
# the identical concatenated table as "MODALIAS=dmi:...". Masking one
# and not the other hands the whole real story back in one read.
_DMI_STORY["uevent"] = "MODALIAS=" + _DMI_STORY["modalias"]

# /proc/stat jiffy unit. USER_HZ is 100 on every mainstream Linux
# build (it is the userspace-visible clock tick, fixed for ABI
# compatibility regardless of the kernel's internal CONFIG_HZ);
# tools converting jiffies to seconds divide by this.
_USER_HZ = 100


def _cpumask_str(cpu_count: int) -> str:
    """Kernel-format cpumask for the claimed CPU count: comma-separated
    32-bit words, each zero-padded to 8 hex digits (the shape both
    /sys/.../node0/cpumap and /proc/schedstat's domain masks print).
    One formatter for every mask surface — a width or grouping
    disagreement between two files claiming the same CPUs is a
    one-read contradiction."""
    mask = (1 << cpu_count) - 1
    words = []
    while True:
        words.append(f"{mask & 0xffffffff:08x}")
        mask >>= 32
        if not mask:
            break
    return ",".join(reversed(words))

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
    # Fail-closed switch, set from sandbox(require_sanitisation=True):
    # apply_overlay treats a missing target or a failed bind as a
    # setup FAILURE (raise → mount-ns 'M' status) instead of skipping.
    # Riding on the persona keeps the whole spawn plumbing unchanged.
    strict: bool = False


def build_persona(tmpdir: Path, cpu_count: int,
                  strict: bool = False) -> Persona:
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
        cpu_count = _host_cpu_count()
    if cpu_count < 1:
        msg = f"cpu_count must be >= 1 or HOST_CPU_COUNT, got {cpu_count}"
        raise ValueError(msg)
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

    # /proc/sys/kernel/random/boot_id — host-real value is a stable
    # host identifier ACROSS every sandbox on the machine (correlate
    # two runs = same victim). Derive a per-install UUID from the
    # machine-id seed; consistent with /etc/machine-id by
    # construction, different across installs.
    # Independent digest: slicing the machine-id would make the two
    # values 30/32-nibble-identical — a one-line detector. Same seed,
    # different domain separator.
    _bid = hashlib.sha256(
        b"raptor-boot-id-v1\0" + _MACHINE_ID.encode()).hexdigest()
    _boot_id = (f"{_bid[0:8]}-{_bid[8:12]}-4{_bid[13:16]}-"
                f"a{_bid[17:20]}-{_bid[20:32]}")
    files["/proc/sys/kernel/random/boot_id"] = _write(
        tmpdir / "boot_id", _boot_id + "\n",
    )
    files["/etc/machine-id"] = _write(tmpdir / "machine-id", _MACHINE_ID + "\n")
    files["/etc/hostname"] = _write(tmpdir / "hostname", _HOSTNAME + "\n")

    # /sys/class/dmi/id/ — one CONSISTENT vendor story across every
    # world-readable identity file. Masking only sys_vendor +
    # product_name left bios_vendor/board_vendor reading the host's
    # real platform ("QEMU" beside "Amazon EC2" is itself a detector).
    # The root-only files (product_serial, product_uuid, *_serial)
    # are unreadable from the sandbox uid and stay unmasked.
    dmi_dir = tmpdir / "dmi"
    dmi_dir.mkdir(exist_ok=True)
    for _dmi_name, _dmi_val in _DMI_STORY.items():
        files[f"/sys/class/dmi/id/{_dmi_name}"] = _write(
            dmi_dir / _dmi_name, _dmi_val,
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

    # /proc/uptime idle: idle ≈ uptime * cpu_count (each CPU
    # accumulates idle independently). Real systems report idle ≈
    # 0.97 * uptime * cpu_count on a low-load box; we pick 0.95 to
    # leave a small "we've done some work" signal. Computed before
    # /proc/stat because the stat jiffies derive from the same value.
    idle_s = int(fake_uptime_s * cpu_count * 0.95)

    # /proc/stat cpu jiffies must agree with the fabricated uptime:
    # the earlier hardcoded "cpu 100 0 50 1000" summed to ~11.5s of
    # CPU time at USER_HZ=100 while /proc/uptime claimed days — a
    # cross-checking detector flags the contradiction instantly.
    # Derive from fake_uptime_s instead: idle is exactly the
    # /proc/uptime idle figure in jiffies; the busy remainder splits
    # user/system 3:2 — a plausible low-load production box.
    idle_jiffies = idle_s * _USER_HZ
    user_jiffies = int(fake_uptime_s * cpu_count * 0.03) * _USER_HZ
    system_jiffies = int(fake_uptime_s * cpu_count * 0.02) * _USER_HZ
    stat_lines = [
        f"cpu  {user_jiffies} 0 {system_jiffies} {idle_jiffies} "
        f"0 0 0 0 0 0\n"
    ]
    stat_lines.extend(f"cpu{i} {user_jiffies // cpu_count} 0 "
            f"{system_jiffies // cpu_count} "
            f"{idle_jiffies // cpu_count} 0 0 0 0 0 0\n" for i in range(cpu_count))
    stat_lines.append(
        f"intr 0\nctxt 0\nbtime {btime}\n"
        f"processes {fake_processes}\nprocs_running 1\n"
        f"procs_blocked 0\nsoftirq 0\n"
    )
    files["/proc/stat"] = _write(tmpdir / "stat", "".join(stat_lines))

    files["/proc/uptime"] = _write(
        tmpdir / "uptime", f"{fake_uptime_s}.00 {idle_s}.00\n",
    )

    # /proc/loadavg — low-load values + a plausible "running/total
    # tasks" pair + last-pid (matches `processes` in /proc/stat for
    # internal consistency).
    # Per-CPU accounting files: their COLUMN/ROW count is a cpu-count
    # cross-check one read away (/proc/interrupts headers, softirqs
    # columns, schedstat rows all showed the host's CPUs beside the
    # story's N). Minimal internally-consistent stubs — a probe that
    # cross-references the VALUES against real interrupt controllers
    # is already active analysis.
    _hdr = "          " + "".join(f"CPU{i}       " for i in range(cpu_count))
    _timer_row = "LOC:" + "".join(
        f"{(fake_uptime_s * 250) // cpu_count:>11}" for i in range(cpu_count))
    files["/proc/interrupts"] = _write(
        tmpdir / "interrupts",
        _hdr.rstrip() + "\n" + _timer_row
        + "   Local timer interrupts\n",
    )
    _si_names = ("HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
                 "TASKLET", "SCHED", "HRTIMER", "RCU")
    _si_lines = ["                    "
                 + "".join(f"CPU{i}       " for i in range(cpu_count))]
    for _si_i, _si in enumerate(_si_names):
        _si_val = (fake_uptime_s * (17 + _si_i * 3)) // cpu_count
        _si_lines.append(f"{_si + ':':>12}" + "".join(
            f"{_si_val:>11}" for i in range(cpu_count)))
    files["/proc/softirqs"] = _write(
        tmpdir / "softirqs", "\n".join(_si_lines) + "\n")
    _ss_lines = ["version 15", f"timestamp {fake_uptime_s * _USER_HZ}"]
    for _i in range(cpu_count):
        _ss_lines.append(
            f"cpu{_i} 0 0 0 0 0 0 "
            f"{int(fake_uptime_s * 1e7)} {int(fake_uptime_s * 2e6)} "
            f"{fake_processes * 40}")
        _ss_lines.append(f"domain0 {_cpumask_str(cpu_count)} "
                         + " ".join(["0"] * 36))
    files["/proc/schedstat"] = _write(
        tmpdir / "schedstat", "\n".join(_ss_lines) + "\n")

    # NUMA node cpu lists: /sys/devices/system/node/node0/{cpulist,
    # cpumap} showed the host range beside the masked cpu dir.
    _node_dir = tmpdir / "node0"
    _node_dir.mkdir(exist_ok=True)
    _cpu_range_str = f"0-{cpu_count - 1}" if cpu_count > 1 else "0"
    files["/sys/devices/system/node/node0/cpulist"] = _write(
        _node_dir / "cpulist", _cpu_range_str + "\n")
    files["/sys/devices/system/node/node0/cpumap"] = _write(
        _node_dir / "cpumap", _cpumask_str(cpu_count) + "\n")

    # /etc/passwd and /etc/group: the host copies name the OPERATOR
    # (login, home path, group) to any target that reads them — the
    # persona claims a neutral box, so it supplies neutral system
    # tables. uid 0 matches what the target sees via getuid(); the
    # "sandbox" user matches USER/LOGNAME on fake-home runs.
    files["/etc/passwd"] = _write(
        tmpdir / "passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "sandbox:x:1000:1000:sandbox:/home/sandbox:/bin/bash\n",
    )
    files["/etc/group"] = _write(
        tmpdir / "group",
        "root:x:0:\n"
        "daemon:x:1:\n"
        "bin:x:2:\n"
        "nogroup:x:65534:\n"
        "sandbox:x:1000:\n",
    )

    files["/proc/loadavg"] = _write(
        tmpdir / "loadavg",
        f"0.08 0.12 0.10 1/{fake_processes // 100} {fake_processes}\n",
    )

    # /proc/meminfo — the host's real MemTotal survives every other
    # mask and sizes the machine exactly (a 512-GiB box claiming to
    # be a desktop VM is its own tell). Fabricate a consistent
    # boring-VM story: ~4 GiB per claimed CPU minus the small
    # firmware/kernel reservation every real machine shows (an EXACT
    # power of two never appears on live Linux), ~40% available, no
    # swap. Residuals: sysinfo(2) bypasses procfs and still returns
    # host figures, and /proc/vmstat stays host-real — both
    # unmaskable without syscall emulation; documented tells of the
    # same class as CPUID/AT_HWCAP.
    _mem_reserved_kb = 97848 + (
        int(_MACHINE_ID[:4], 16) % 4096)  # per-install, plausible
    _mem_total_kb = cpu_count * 4 * 1024 * 1024 - _mem_reserved_kb
    _mem_avail_kb = int(_mem_total_kb * 0.4)
    _mem_free_kb = int(_mem_total_kb * 0.25)
    files["/proc/meminfo"] = _write(
        tmpdir / "meminfo",
        f"MemTotal:       {_mem_total_kb} kB\n"
        f"MemFree:        {_mem_free_kb} kB\n"
        f"MemAvailable:   {_mem_avail_kb} kB\n"
        f"Buffers:        {_mem_total_kb // 100} kB\n"
        f"Cached:         {_mem_total_kb // 8} kB\n"
        f"SwapCached:     0 kB\n"
        f"Active:         {_mem_total_kb // 4} kB\n"
        f"Inactive:       {_mem_total_kb // 8} kB\n"
        f"SwapTotal:      0 kB\n"
        f"SwapFree:       0 kB\n"
        f"Dirty:          64 kB\n"
        f"Writeback:      0 kB\n"
        f"Shmem:          {_mem_total_kb // 64} kB\n"
        f"Slab:           {_mem_total_kb // 32} kB\n"
        f"CommitLimit:    {_mem_total_kb // 2} kB\n"
        f"Committed_AS:   {_mem_total_kb // 3} kB\n"
        f"AnonPages:      {_mem_total_kb // 6} kB\n"
        f"Mapped:         {_mem_total_kb // 24} kB\n"
        f"KernelStack:    {max(_mem_total_kb // 2048, 2048)} kB\n"
        f"PageTables:     {max(_mem_total_kb // 1024, 4096)} kB\n"
        f"SReclaimable:   {_mem_total_kb // 48} kB\n"
        f"SUnreclaim:     {_mem_total_kb // 96} kB\n"
        f"VmallocTotal:   34359738367 kB\n"
        f"VmallocUsed:    {_mem_total_kb // 128} kB\n",
    )

    return Persona(files=files, cpu_count=cpu_count, strict=strict)


def _now() -> float:
    """Wrapped for monkeypatching in tests."""
    import time
    return time.time()


def _derive_uptime_and_processes() -> tuple[int, int]:
    """Pick a fake uptime + processes counter, deterministic per
    RAPTOR install. Uptime in [3 days, 30 days], processes in
    [10000, 209999] — both plausible production-VM ranges.

    Seed is the same as _MACHINE_ID so a single install consistently
    presents the same uptime + processes across runs of the same
    target. Different installs see different values (cross-operator
    output drift, but local determinism).
    """
    # Environment-independent, like _derive_machine_id: an env-first
    # RAPTOR_DIR read made the fake uptime/processes (and the meminfo
    # figures seeded from _MACHINE_ID) differ between env-set and
    # env-unset invocations of the same install.
    seed = os.path.dirname(os.path.abspath(__file__))
    h = hashlib.sha256(
        b"raptor-fingerprint-uptime-v1\0" + seed.encode("utf-8", errors="replace")
    ).digest()
    # 3 days = 259200; 30 days = 2592000. Range = 2332800.
    uptime = 259200 + (int.from_bytes(h[:4], "big") % 2332800)
    # 10000 ≤ processes ≤ 209999
    processes = 10000 + (int.from_bytes(h[4:8], "big") % 200000)
    return uptime, processes


def _write(path: Path, content: str) -> str:
    """Helper: write content, return absolute path as str."""
    path.write_text(content, encoding="utf-8")
    return str(path)


def _read_host_cpu_flags() -> str:
    r"""Return the host's /proc/cpuinfo `flags` line value (space-
    separated flag names; no `flags\t:` prefix).

    Empty string on failure — handled gracefully by build_persona.
    """
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("flags"):
                    _, _, value = line.partition(":")
                    return value.strip()
    except OSError:
        pass
    return ""


def _trim_proc_version() -> str:
    r"""Return host /proc/version with build-host/compiler/timestamp
    fingerprint stripped, preserving only `Linux version <release>`.

    Example: "Linux version 6.8.0-49-generic (buildd@...) (gcc ...) #49-..."
             becomes "Linux version 6.8.0-49-generic\n"
    """
    try:
        with open("/proc/version", encoding="utf-8") as f:
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
_libc_lock = threading.Lock()


def _get_libc() -> ctypes.CDLL:
    """Lazy-init the shared libc CDLL binding.

    Double-checked locking: pre-fix two threads racing on first
    access each constructed their own ``ctypes.CDLL`` object and
    wrote to the global; second one wins but the first's calls
    referenced a now-orphaned handle. Practical impact small
    (CDLL is just a thin handle wrapper) but the race is real.
    Lock ensures exactly-once construction.
    """
    global _libc
    if _libc is not None:
        return _libc
    with _libc_lock:
        if _libc is None:
            _libc = ctypes.CDLL(
                _ctypes_util.find_library("c"), use_errno=True,
            )
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
        msg = f"cpu_count must be >= 1, got {cpu_count}"
        raise ValueError(msg)
    if not hasattr(os, "sched_getaffinity"):
        msg = "set_cpu_affinity requires Linux (sched_setaffinity syscall)"
        raise NotImplementedError(msg)
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
    mask = set(heapq.nsmallest(effective, available))
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

    EXCEPT under ``persona.strict`` (sandbox(require_sanitisation=
    True)): a fail-closed persona request must not silently run with
    host-real /proc/cpuinfo etc., so a missing target or a failed
    bind RAISES. This runs pre-exec in the mount-ns child — the raise
    propagates through setup_mount_ns to the spawn child's setup
    handler, which reports the typed 'M' setup status; context.py
    refuses the Landlock-only degrade for a required persona and
    surfaces SandboxSetupError instead.
    """
    # Use the same _mount wrapper as mount_ns.py to keep OSError
    # semantics identical across the module boundary.
    from .mount_ns import _mount, MS_BIND

    # /sys/devices/system/cpu directory LISTING: masking online/
    # possible alone left readdir showing the host's real cpuN
    # entries — the claimed CPU count contradicted one `ls`. Stack a
    # tmpfs over the directory and populate exactly cpu_count stub
    # dirs plus empty mount points for the persona's control files
    # (the file loop below binds their content). Topology internals
    # under cpuN/ read ENOENT — the accepted stub-dir cost; a probe
    # that cross-checks THOSE is already doing active analysis the
    # tracer lane exists to flag. Failure: skip (or raise under
    # strict), same policy as the per-file binds.
    _cpu_dir = f"{root_prefix}/sys/devices/system/cpu"
    if os.path.isdir(_cpu_dir):
        try:
            _mount("tmpfs", _cpu_dir, "tmpfs", 0, "mode=755")
            for _i in range(persona.cpu_count):
                os.makedirs(f"{_cpu_dir}/cpu{_i}", exist_ok=True)
            _cpu_range = (f"0-{persona.cpu_count - 1}\n"
                          if persona.cpu_count > 1 else "0\n")
            for _stub, _content in (
                    ("online", _cpu_range), ("possible", _cpu_range),
                    ("present", _cpu_range), ("offline", "\n"),
                    ("kernel_max", f"{persona.cpu_count - 1}\n")):
                with open(f"{_cpu_dir}/{_stub}", "w",
                          encoding="utf-8") as _f:
                    _f.write(_content)
        except OSError as exc:
            if persona.strict:
                raise
            logger.debug("fingerprint: cpu-dir overlay failed: %s", exc)

    # Same readdir cross-check exists one directory over: /sys/devices/
    # system/node/node0 and /sys/bus/cpu/devices both enumerate the
    # host's real cpuN entries. Tmpfs each and populate cpu_count
    # symlinks into the (already masked) cpu dir; node0 also gets empty
    # cpulist/cpumap mount points so the persona file loop below can
    # bind its content over them (everything else under node0 reads
    # ENOENT — the same accepted stub-dir cost as cpuN/ topology).
    # Symlink targets are RELATIVE, matching what the kernel emits
    # (readlink on an absolute-target cpuN entry is its own tell).
    for _enum_dir, _link_prefix in (
            (f"{root_prefix}/sys/devices/system/node/node0",
             "../../cpu/"),
            (f"{root_prefix}/sys/bus/cpu/devices",
             "../../../devices/system/cpu/")):
        if not os.path.isdir(_enum_dir):
            continue
        try:
            _mount("tmpfs", _enum_dir, "tmpfs", 0, "mode=755")
            for _i in range(persona.cpu_count):
                os.symlink(f"{_link_prefix}cpu{_i}",
                           f"{_enum_dir}/cpu{_i}")
            if _enum_dir.endswith("/node0"):
                for _stub in ("cpulist", "cpumap"):
                    with open(f"{_enum_dir}/{_stub}", "w",
                              encoding="utf-8"):
                        pass
        except OSError as exc:
            if persona.strict:
                raise
            logger.debug("fingerprint: cpu-enum overlay failed for "
                         "%s: %s", _enum_dir, exc)

    for target, source in persona.files.items():
        inside = f"{root_prefix}{target}"
        if not os.path.exists(inside):
            if target.startswith("/sys/class/dmi/"):
                # DMI files are OPTIONAL host inventory (many VMs
                # ship no board_*/asset entries at all). A missing
                # target reads ENOENT inside too — consistent with a
                # platform that lacks the entry, and nothing
                # host-real leaks through — so strict personas skip
                # rather than abort.
                continue
            if persona.strict:
                raise FileNotFoundError(
                    errno.ENOENT,
                    f"fingerprint overlay target missing under "
                    f"require_sanitisation: {inside}",
                )
            logger.debug(
                "fingerprint: target %s does not exist; "
                "skipping bind-mount", inside,
            )
            continue
        try:
            _mount(source, inside, None, MS_BIND)
        except OSError as e:
            if persona.strict:
                raise OSError(
                    e.errno or 0,
                    f"fingerprint overlay bind failed under "
                    f"require_sanitisation: {source} -> {inside}: {e}",
                ) from e
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
