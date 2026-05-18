"""Adversarial end-to-end tests for host-fingerprint sanitisation.

Each test runs a malware-style anti-analysis check INSIDE the sandbox
and asserts the check concludes "I'm on a real Debian VM, not a
sandbox." If any of these tests fails, an attacker writing roughly
that check would detect RAPTOR's sandbox and refuse to execute its
payload, defeating the analysis.

Categories covered (drawn from public anti-analysis literature like
Joe Sandbox / Cuckoo / Pafish / al-khaser):

  - Hostname / domainname sentinel checks
  - DMI vendor/product blacklist
  - CPU identity triple lookup ((family, model, stepping) anomalies)
  - machine-id well-known-bad list
  - CPU count anomaly (==1 → sandbox heuristic)
  - cpuinfo + sched_getaffinity cross-check
  - cpuinfo + /sys/devices/system/cpu cross-check
  - cpuinfo + /proc/stat cross-check (per-cpu line count)
  - btime + uptime cross-check (must agree)
  - os-release ID + dynamic linker cache (we don't claim Ubuntu and
    then ship Debian's cache, etc.)
  - Round-number checks on bogomips / MHz
  - Published-fingerprint defence (machine-id NOT the trivial
    sha256("raptor-sandbox-v1"))
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="adversarial fingerprint tests are Linux-only",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


class TestAdversarialFingerprint(unittest.TestCase):
    """Each test spawns a sandbox with sanitise_host_fingerprint=True
    and runs an adversary's fingerprint check. The check exits 0 if
    "looks like a real system", nonzero (with diagnostic on stderr) if
    "this is a sandbox." We assert exit 0 — meaning the persona
    successfully defeats that specific anti-analysis pattern."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap + sysctl=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.persona_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.persona_dir.cleanup)
        from core.sandbox.fingerprint import build_persona
        # cpu_count=4 (the production default) — exercises the multi-CPU
        # path and the "not == 1" anti-analysis heuristic.
        self.persona = build_persona(Path(self.persona_dir.name), cpu_count=4)

    def _spawn_check(self, sh_script: str):
        """Run an anti-analysis check script and return CompletedProcess."""
        from core.sandbox._spawn import run_sandboxed
        return run_sandboxed(
            ["sh", "-c", sh_script],
            target=self.tmp.name, output=self.tmp.name,
            block_network=True,
            nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
            writable_paths=[self.tmp.name, "/tmp"],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None,
            seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
            persona=self.persona,
        )

    def _assert_undetected(self, script: str, message: str = ""):
        r = self._spawn_check(script)
        if r.returncode != 0:
            self.fail(
                f"sandbox DETECTED by anti-analysis check {message!r}: "
                f"stdout={r.stdout!r} stderr={r.stderr!r} rc={r.returncode}"
            )

    # === Hostname checks (Pafish/al-khaser pattern) ===

    def test_hostname_not_in_sandbox_blacklist(self):
        script = textwrap.dedent("""
            HN=$(hostname)
            for bad in sandbox cuckoo malware analyst sample raptor; do
                if echo "$HN" | grep -qi "$bad"; then
                    echo "DETECTED hostname=$HN matches $bad" >&2
                    exit 1
                fi
            done
            exit 0
        """)
        self._assert_undetected(script, "hostname blacklist")

    # === DMI vendor blacklist (most common anti-analysis check) ===

    def test_dmi_vendor_not_virtualbox_or_vmware(self):
        script = textwrap.dedent("""
            V=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo absent)
            P=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo absent)
            for bad in VirtualBox innotek "VMware" Parallels Xen Bochs; do
                if echo "$V $P" | grep -q "$bad"; then
                    echo "DETECTED DMI sys_vendor/product mentions $bad: $V / $P" >&2
                    exit 1
                fi
            done
            exit 0
        """)
        self._assert_undetected(script, "DMI vendor blacklist")

    # === CPU identity triple sanity ===

    def test_cpuinfo_identity_triple_is_known_real(self):
        """A malware author maintains a small allowlist of (family,
        model, stepping) tuples corresponding to real shipped CPUs.
        Our persona must hit a known-real tuple."""
        script = textwrap.dedent("""
            FAMILY=$(awk -F: '/^cpu family/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
            MODEL=$(awk -F: '/^model[^ ]/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
            STEPPING=$(awk -F: '/^stepping/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
            TRIPLE="$FAMILY-$MODEL-$STEPPING"
            # Real known-good Intel triples (Skylake-X / Cascade Lake /
            # Ice Lake / various Coffee Lake server SKUs).
            case "$TRIPLE" in
                6-85-7|6-85-6|6-85-4|6-106-6|6-142-10|6-158-10|6-79-1|6-63-2|6-45-7)
                    exit 0 ;;
            esac
            echo "DETECTED implausible (family,model,stepping)=$TRIPLE" >&2
            exit 1
        """)
        self._assert_undetected(script, "CPU identity triple")

    def test_cpuinfo_microcode_is_not_zero(self):
        script = textwrap.dedent("""
            MC=$(awk -F: '/^microcode/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
            if [ "$MC" = "0x0" ] || [ -z "$MC" ]; then
                echo "DETECTED microcode is 0x0 / absent: $MC" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "microcode anomaly")

    def test_cpuinfo_bogomips_not_exact_round_hundred(self):
        script = textwrap.dedent("""
            BOGO=$(awk -F: '/^bogomips/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
            # Strip the fractional part and check it's non-zero — real
            # CPUs have sub-Hz jitter in their bogomips report.
            FRAC=$(echo "$BOGO" | cut -d. -f2)
            if [ "$FRAC" = "00" ]; then
                echo "DETECTED suspiciously round bogomips $BOGO" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "bogomips precision")

    # === machine-id checks ===

    def test_machine_id_is_not_all_zeros(self):
        script = textwrap.dedent("""
            MID=$(cat /etc/machine-id)
            if echo "$MID" | grep -qE '^0+$'; then
                echo "DETECTED machine-id is all zeros: $MID" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "machine-id all zeros")

    def test_machine_id_is_not_naive_published_hash(self):
        """A malware author with our source code would pre-compute
        sha256('raptor-sandbox-v1') and literal-match. Per-install
        seeding defeats that — assert the literal naive value isn't
        what we ship."""
        import hashlib
        naive = hashlib.sha256(b"raptor-sandbox-v1").hexdigest()[:32]
        script = textwrap.dedent(f"""
            MID=$(cat /etc/machine-id)
            if [ "$MID" = "{naive}" ]; then
                echo "DETECTED machine-id is the naive published-fingerprint hash" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "published-fingerprint machine-id")

    # === CPU count heuristics ===

    def test_cpu_count_is_at_least_two(self):
        """Single-CPU systems are unusual for production workloads.
        Persona default cpu_count=4 defeats `nproc == 1 → sandbox`."""
        script = textwrap.dedent("""
            N=$(nproc)
            if [ "$N" -lt 2 ]; then
                echo "DETECTED only $N CPU available" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "single-CPU heuristic")

    def test_cpuinfo_count_matches_sched_getaffinity(self):
        """Cross-check: cpuinfo blocks must equal sched_getaffinity
        popcount. Disagreement reveals fakery."""
        script = textwrap.dedent("""
            CINFO=$(grep -c '^processor' /proc/cpuinfo)
            AFF=$(python3 -c 'import os; print(len(os.sched_getaffinity(0)))')
            if [ "$CINFO" != "$AFF" ]; then
                echo "DETECTED cpuinfo=$CINFO != affinity=$AFF" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "cpuinfo vs affinity cross-check")

    def test_cpuinfo_count_matches_sys_cpu_online(self):
        script = textwrap.dedent("""
            CINFO=$(grep -c '^processor' /proc/cpuinfo)
            ONLINE=$(cat /sys/devices/system/cpu/online)
            # Parse "0-3" → 4, "0" → 1, "0,2-3" → 3 (etc.)
            COUNT=$(python3 -c '
import sys
s = sys.argv[1]
total = 0
for part in s.split(","):
    if "-" in part:
        a, b = part.split("-")
        total += int(b) - int(a) + 1
    else:
        total += 1
print(total)
' "$ONLINE")
            if [ "$CINFO" != "$COUNT" ]; then
                echo "DETECTED cpuinfo=$CINFO != cpu/online=$COUNT" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "cpuinfo vs cpu/online cross-check")

    def test_cpuinfo_count_matches_proc_stat(self):
        """/proc/stat shows one cpu line per CPU. Mismatch reveals
        the persona only patched cpuinfo and forgot about /proc/stat."""
        script = textwrap.dedent("""
            CINFO=$(grep -c '^processor' /proc/cpuinfo)
            # cpu0, cpu1, cpu2, cpu3 — but NOT the aggregate "cpu " line.
            STAT=$(awk '/^cpu[0-9]+ /' /proc/stat | wc -l)
            if [ "$CINFO" != "$STAT" ]; then
                echo "DETECTED cpuinfo=$CINFO != /proc/stat cpus=$STAT" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "cpuinfo vs /proc/stat cross-check")

    # === Uptime / btime consistency ===

    def test_uptime_btime_internally_consistent(self):
        """uptime + btime should ≈ current time. A persona that fakes
        btime but leaves uptime host-real (or vice versa) shows >>1hr
        discrepancy — the original draft was 2+ years off."""
        script = textwrap.dedent("""
            UPTIME=$(awk '{print int($1)}' /proc/uptime)
            BTIME=$(awk '/^btime/{print $2}' /proc/stat)
            NOW=$(date +%s)
            EXPECTED=$((NOW - UPTIME))
            # btime should be within 60 seconds of (now - uptime). Real
            # systems show a few seconds of skew due to clock drift; we
            # allow 60s as a wide margin.
            DIFF=$((BTIME - EXPECTED))
            DIFF=${DIFF#-}  # absolute value
            if [ "$DIFF" -gt 60 ]; then
                echo "DETECTED btime=$BTIME vs now-uptime=$EXPECTED differ by $DIFF s" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "btime vs uptime cross-check")

    def test_processes_counter_is_plausibly_large(self):
        """/proc/stat `processes` is the cumulative fork count since
        boot. `1` means only init ever forked — implausible for any
        running system."""
        script = textwrap.dedent("""
            P=$(awk '/^processes/{print $2}' /proc/stat)
            if [ "$P" -lt 100 ]; then
                echo "DETECTED implausibly low process counter: $P" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "processes counter")

    # === OS / distro consistency ===

    def test_os_release_matches_apt_present(self):
        """We claim Debian via /etc/os-release. apt/dpkg presence is
        a soft cross-check — debian without dpkg is suspect. Our
        sandbox bind-mounts /usr/bin RO from the HOST, so dpkg
        availability depends on the operator's machine. Don't require
        dpkg; instead, require that os-release's ID is in the
        Debian-family allowlist (a real cross-check)."""
        script = textwrap.dedent("""
            . /etc/os-release
            case "$ID" in
                debian|ubuntu|raspbian|kali|mint|pop|elementary)
                    exit 0 ;;
            esac
            echo "DETECTED os-release ID is implausible: $ID" >&2
            exit 1
        """)
        self._assert_undetected(script, "os-release ID")

    # === Domain / gethostname consistency ===

    def test_etc_hostname_matches_gethostname(self):
        """If /etc/hostname says foo but gethostname() says bar, it's
        a sandbox tell (real init scripts keep them in sync). Our
        persona binds /etc/hostname AND calls sethostname()."""
        script = textwrap.dedent("""
            FILE=$(cat /etc/hostname 2>/dev/null || echo absent)
            SYS=$(hostname)
            if [ "$FILE" != "$SYS" ]; then
                echo "DETECTED /etc/hostname=$FILE vs hostname()=$SYS" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "hostname file vs syscall")

    # === Capability surface preserved (regression guard) ===

    def test_capability_surface_intact_smep(self):
        """An exploit_feasibility-style check: does the cpuinfo flags
        line still report SMEP/SMAP? If sanitisation accidentally
        clobbered the flags line, kernel-exploit analysis breaks."""
        script = textwrap.dedent("""
            if grep -q '^flags.*smep' /proc/cpuinfo; then
                exit 0
            fi
            # Older Atom / very old Xeon systems lack SMEP — that's
            # not a sandbox tell. Tolerate by checking that SOME
            # post-2010 flag is present (sse2 is the minimum).
            if grep -q '^flags.*sse2' /proc/cpuinfo; then
                exit 0
            fi
            echo "DETECTED cpuinfo flags line looks empty / not host-derived" >&2
            exit 1
        """)
        self._assert_undetected(script, "capability surface SMEP")

    def test_capability_surface_intact_aslr_sysctl(self):
        """exploit_feasibility reads /proc/sys/kernel/randomize_va_space.
        Sanitisation must NOT touch /proc/sys/."""
        script = textwrap.dedent("""
            V=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
            # Must be 0, 1, or 2 (any kernel-valid value). Empty or
            # missing means we accidentally masked this sysctl.
            case "$V" in
                0|1|2) exit 0 ;;
            esac
            echo "DETECTED sysctl randomize_va_space=$V (expected 0/1/2)" >&2
            exit 1
        """)
        self._assert_undetected(script, "ASLR sysctl preserved")

    def test_capability_surface_uname_release_real(self):
        """exploit_feasibility runs `uname -r`. Must return the real
        kernel release, not "6.0.0-generic" or other stub."""
        script = textwrap.dedent("""
            R=$(uname -r)
            # The real kernel release on the host. We assert it's NON-
            # generic (no exact match against a known stub string).
            for stub in "6.0.0-generic" "unknown" "0.0.0" "5.0.0-generic"; do
                if [ "$R" = "$stub" ]; then
                    echo "DETECTED uname release looks stub'd: $R" >&2
                    exit 1
                fi
            done
            # Sanity: real kernel releases have a digit somewhere
            if ! echo "$R" | grep -q '[0-9]'; then
                echo "DETECTED kernel release has no digit: $R" >&2
                exit 1
            fi
            exit 0
        """)
        self._assert_undetected(script, "uname -r preserved")
