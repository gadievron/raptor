"""Unit tests for core.sandbox.fingerprint.

Covers the pure-data parts: persona generation, file content shape,
hide-intent invariants, cpu_count consistency, host-flag preservation.

Tests that exercise the mount-ns / UTS-ns / sched_setaffinity wiring
(which require fork + unshare + CAP_SYS_ADMIN) live in the integration
test module (test_e2e_sandbox.py) and run against a real sandbox.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

from core.sandbox.fingerprint import (
    HOST_CPU_COUNT,
    _HOSTNAME,
    _DOMAINNAME,
    _MACHINE_ID,
    _OS_RELEASE,
    _read_host_cpu_flags,
    _trim_proc_version,
    build_persona,
    is_supported,
    set_cpu_affinity,
)


# --- HOST_CPU_COUNT sentinel ---

def test_host_cpu_count_sentinel_resolves_to_host(tmp_path):
    """build_persona(cpu_count=HOST_CPU_COUNT) must resolve to the
    host's actual schedulable CPU count via os.sched_getaffinity(0).
    Persona.cpu_count is the resolved int, not the sentinel."""
    expected = len(os.sched_getaffinity(0))
    persona = build_persona(tmp_path, cpu_count=HOST_CPU_COUNT)
    assert persona.cpu_count == expected, (
        f"sentinel resolved to {persona.cpu_count}, expected {expected}"
    )


def test_host_cpu_count_sentinel_yields_n_cpuinfo_blocks(tmp_path):
    """With the sentinel, /proc/cpuinfo claims as many processors as
    the host has available — preserves capability surface for callers
    that need real parallelism (codeql, parallel builds)."""
    expected = len(os.sched_getaffinity(0))
    build_persona(tmp_path, cpu_count=HOST_CPU_COUNT)
    content = (tmp_path / "cpuinfo").read_text()
    indices = [
        m for m in content.splitlines() if m.startswith("processor\t:")
    ]
    assert len(indices) == expected


def test_host_cpu_count_sentinel_value_is_negative():
    """Sentinel must be < 1 so existing ValueError paths don't
    accidentally accept it. Using -1 (conventional "unset" / "not
    applicable")."""
    assert HOST_CPU_COUNT < 1
    assert HOST_CPU_COUNT != 0  # 0 might be confused with "no CPUs"


def test_build_persona_still_rejects_invalid_negative(tmp_path):
    """Any negative value OTHER than HOST_CPU_COUNT must still raise."""
    import pytest as _pytest
    # Pick a negative that isn't the sentinel.
    bad = HOST_CPU_COUNT - 1
    with _pytest.raises(ValueError, match="cpu_count must be >= 1"):
        build_persona(tmp_path, cpu_count=bad)


# --- Constants / shape ---

def test_machine_id_is_32_lowercase_hex():
    """machine-id must look like a real /etc/machine-id (32 lowercase
    hex, no dashes)."""
    assert len(_MACHINE_ID) == 32, _MACHINE_ID
    assert re.fullmatch(r"[0-9a-f]{32}", _MACHINE_ID), _MACHINE_ID


def test_machine_id_is_not_all_zeros():
    """All-zeros machine-id is a known sandbox tell (only seen during
    pre-systemd-machine-id-setup early boot)."""
    assert _MACHINE_ID != "0" * 32


def test_machine_id_is_not_naive_published_hash():
    """The first draft used hashlib.sha256(b'raptor-sandbox-v1') which
    open-source publishes the exact bytes — any attacker can pre-
    compute it and bypass with a literal-string match. Per-install
    seed (RAPTOR_DIR or this module's path) defeats that."""
    import hashlib as _hashlib
    naive = _hashlib.sha256(b"raptor-sandbox-v1").hexdigest()[:32]
    assert _MACHINE_ID != naive, (
        "machine-id must NOT be the naive published-fingerprint hash; "
        "current derivation should mix in install-path entropy"
    )


def test_hostname_is_localhost_not_sentinel():
    """Hide-intent: hostname must avoid analysis-tool sentinels."""
    assert _HOSTNAME == "localhost"
    assert _DOMAINNAME == "localdomain"


def test_os_release_does_not_mention_raptor_or_sandbox():
    """Hide-intent invariant: nothing in persona names RAPTOR, sandbox,
    analysis, malware, or analyst."""
    lower = _OS_RELEASE.lower()
    for tell in ("raptor", "sandbox", "analysis", "malware", "analyst"):
        assert tell not in lower, (
            f"hide-intent violation: os-release contains {tell!r}"
        )


def test_os_release_is_canonical_debian_12():
    """Persona is "boring Debian 12 cloud VM"; os-release must reflect
    that consistently."""
    assert 'ID=debian' in _OS_RELEASE
    assert 'VERSION_ID="12"' in _OS_RELEASE
    assert 'bookworm' in _OS_RELEASE.lower()


# --- build_persona input validation ---

def test_build_persona_rejects_zero_cpu_count(tmp_path):
    with pytest.raises(ValueError, match="cpu_count must be >= 1"):
        build_persona(tmp_path, cpu_count=0)


def test_build_persona_rejects_negative_cpu_count(tmp_path):
    # -1 is the HOST_CPU_COUNT sentinel (covered separately). Pick a
    # negative that isn't a sentinel.
    with pytest.raises(ValueError, match="cpu_count must be >= 1"):
        build_persona(tmp_path, cpu_count=-2)


# --- build_persona output shape ---

def test_build_persona_creates_all_expected_targets(tmp_path):
    persona = build_persona(tmp_path, cpu_count=4)
    expected = {
        "/proc/cpuinfo", "/proc/version", "/proc/cmdline", "/proc/stat",
        "/proc/uptime", "/proc/loadavg",
        "/etc/os-release", "/etc/machine-id", "/etc/hostname",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/devices/system/cpu/online",
        "/sys/devices/system/cpu/possible",
    }
    assert set(persona.files) == expected


def test_build_persona_every_source_file_exists(tmp_path):
    persona = build_persona(tmp_path, cpu_count=2)
    for target, source in persona.files.items():
        assert Path(source).is_file(), (
            f"source for {target} does not exist: {source}"
        )


def test_persona_targets_are_absolute_paths(tmp_path):
    """All target paths must be absolute — the mount-ns child bind-mounts
    at literal paths and a relative target would silently fail."""
    persona = build_persona(tmp_path, cpu_count=2)
    for target in persona.files:
        assert target.startswith("/"), (
            f"persona target is not absolute: {target}"
        )


def test_persona_cpu_count_reflects_input(tmp_path):
    persona = build_persona(tmp_path, cpu_count=8)
    assert persona.cpu_count == 8


def test_persona_carries_canonical_hostname(tmp_path):
    persona = build_persona(tmp_path, cpu_count=1)
    assert persona.hostname == "localhost"
    assert persona.domainname == "localdomain"


# --- /proc/cpuinfo content ---

def test_cpuinfo_has_n_processor_blocks(tmp_path):
    persona = build_persona(tmp_path, cpu_count=4)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    blocks = re.findall(r"^processor\t: \d+$", content, re.MULTILINE)
    assert len(blocks) == 4, content


def test_cpuinfo_processor_indices_are_contiguous_from_zero(tmp_path):
    persona = build_persona(tmp_path, cpu_count=3)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    indices = [
        int(m.group(1))
        for m in re.finditer(r"^processor\t: (\d+)$", content, re.MULTILINE)
    ]
    assert indices == [0, 1, 2]


def test_cpuinfo_single_cpu(tmp_path):
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    indices = re.findall(r"^processor\t: (\d+)$", content, re.MULTILINE)
    assert indices == ["0"]


def test_cpuinfo_siblings_and_cores_match_cpu_count(tmp_path):
    persona = build_persona(tmp_path, cpu_count=4)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    # All `siblings` and `cpu cores` entries should report cpu_count.
    siblings = re.findall(r"^siblings\t: (\d+)$", content, re.MULTILINE)
    cores = re.findall(r"^cpu cores\t: (\d+)$", content, re.MULTILINE)
    assert siblings == ["4"] * 4
    assert cores == ["4"] * 4


def test_cpuinfo_flags_preserved_from_host(tmp_path):
    """flags line must equal the host's flags (capability preserved).
    SMEP/SMAP/SIMD dispatch in packages/exploit_feasibility key off
    these. Empty is acceptable only if host /proc/cpuinfo is unreadable
    (non-Linux, restricted /proc) — in CI on Linux it should be non-empty.
    """
    host_flags = _read_host_cpu_flags()
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    fake_flags_line = next(
        l for l in content.splitlines() if l.startswith("flags")
    )
    _, _, fake_flags = fake_flags_line.partition(":")
    assert fake_flags.strip() == host_flags


@pytest.mark.skipif(
    sys.platform != "linux", reason="host /proc/cpuinfo only on Linux",
)
def test_host_flags_includes_sse_on_x86_linux():
    """Sanity check that we're actually reading host flags on a normal
    x86 Linux test host — catches a class of bug where the regex grabs
    the wrong line."""
    flags = _read_host_cpu_flags()
    # Every x86 CPU since 2003 has 'sse'; this is just to confirm the
    # parser is producing real content, not a smoke test of the CPU.
    if "x86" in os.uname().machine:
        assert "sse" in flags, f"flags read but no 'sse' present: {flags!r}"


def test_cpuinfo_model_name_is_canonical_xeon(tmp_path):
    """Model name must be plausible-real (hide-intent), not "Generic
    x86_64 CPU" or other sentinel strings. Uses a real Xeon SKU
    so a `(family, model, stepping) ∈ known_real_set` check doesn't
    flag the persona."""
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    assert "Intel(R) Xeon(R)" in content
    for tell in ("Generic", "FAKE", "Sandbox", "Virtual CPU"):
        assert tell not in content, (
            f"hide-intent violation: cpuinfo contains {tell!r}"
        )


def test_cpuinfo_identity_triple_is_plausibly_real(tmp_path):
    """family/model/stepping must NOT be the (6,1,0) Pentium-Pro-on-
    first-boot signature we initially shipped. Any modern Xeon SKU
    works; this test pins to the Skylake-X identity (family 6, model
    85, stepping 7) we chose, so a refactor that drops to defaults
    is caught at CI."""
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    assert "cpu family\t: 6" in content
    assert "model\t\t: 85" in content
    assert "stepping\t: 7" in content


def test_cpuinfo_microcode_is_plausible_revision(tmp_path):
    """microcode revision must look like a real revision (non-zero
    hex), not 0x0 (the "kernel has not loaded microcode yet" state
    which is rare on production systems)."""
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    micro_lines = [l for l in content.splitlines() if "microcode" in l]
    assert micro_lines, "no microcode line in cpuinfo"
    # All microcode values present, none all-zero, all valid hex.
    for l in micro_lines:
        value = l.partition(":")[2].strip()
        assert value.startswith("0x"), l
        assert int(value, 16) > 0, f"microcode is zero/empty: {l!r}"


def test_cpuinfo_bogomips_is_not_round_hundred(tmp_path):
    """bogomips with an exact 0.00 fractional part is a soft tell.
    Real CPUs report values like 4799.95 / 4399.99 / etc."""
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    bogo_lines = [l for l in content.splitlines() if l.startswith("bogomips")]
    assert bogo_lines
    for l in bogo_lines:
        value = float(l.partition(":")[2].strip())
        # Must be slightly off from a round hundred. 4800.00 → fail,
        # 4399.99 → pass.
        assert int(value * 100) % 100 != 0, (
            f"bogomips is too round: {l!r}"
        )


def test_cpuinfo_bugs_line_is_empty(tmp_path):
    """bugs line exposes mitigation posture (Meltdown/Spectre variants).
    Must be empty value."""
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cpuinfo"]).read_text()
    bugs_lines = [l for l in content.splitlines() if l.startswith("bugs")]
    assert bugs_lines
    for line in bugs_lines:
        _, _, value = line.partition(":")
        assert value.strip() == "", f"bugs line not empty: {line!r}"


# --- /proc/version trim ---

def test_trim_proc_version_regex_strips_suffix():
    """Direct test of the trim against a synthetic kernel string —
    avoids depending on the host's actual /proc/version."""
    sample = (
        "Linux version 6.8.0-49-generic (buildd@lcy02-amd64-072) "
        "(gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld 2.42) "
        "#49-Ubuntu SMP PREEMPT_DYNAMIC Wed Aug 28 16:33:25 UTC 2024"
    )
    m = re.match(r"^(Linux version \S+)", sample)
    assert m is not None
    assert m.group(1) == "Linux version 6.8.0-49-generic"


@pytest.mark.skipif(
    sys.platform != "linux", reason="/proc/version only on Linux",
)
def test_trim_proc_version_against_host_strips_fingerprint():
    """End-to-end: _trim_proc_version reads host /proc/version, returns
    a single line starting with 'Linux version ' with no compiler /
    build-host / timestamp tokens (those contain (, @, or #)."""
    result = _trim_proc_version()
    assert result.startswith("Linux version "), result
    assert result.endswith("\n"), result
    assert result.count("\n") == 1, result
    body = result.rstrip("\n")
    assert "(" not in body, f"compiler/buildhost not stripped: {body!r}"
    assert "@" not in body, f"buildhost not stripped: {body!r}"
    assert "#" not in body, f"build number not stripped: {body!r}"


# --- /proc/cmdline ---

def test_cmdline_is_canonical_vm_boot(tmp_path):
    """cmdline must be generic-VM-ish: BOOT_IMAGE + root + ro + quiet.
    Must NOT contain console=ttyS0 (a stronger virtualisation tell)."""
    persona = build_persona(tmp_path, cpu_count=1)
    content = Path(persona.files["/proc/cmdline"]).read_text()
    assert "BOOT_IMAGE=" in content
    assert "root=/dev/" in content
    assert "console=ttyS0" not in content


# --- /sys/devices/system/cpu/ ---

def test_cpu_online_multi_cpu_uses_range(tmp_path):
    persona = build_persona(tmp_path, cpu_count=4)
    online = Path(persona.files["/sys/devices/system/cpu/online"]).read_text()
    assert online.strip() == "0-3"


def test_cpu_online_single_cpu_no_range(tmp_path):
    """Single-CPU systems write just `0`, not `0-0` — matches kernel."""
    persona = build_persona(tmp_path, cpu_count=1)
    online = Path(persona.files["/sys/devices/system/cpu/online"]).read_text()
    assert online.strip() == "0"


def test_cpu_possible_matches_online(tmp_path):
    """possible and online must agree — disagreement is a tell."""
    persona = build_persona(tmp_path, cpu_count=2)
    online = Path(persona.files["/sys/devices/system/cpu/online"]).read_text()
    possible = Path(persona.files["/sys/devices/system/cpu/possible"]).read_text()
    assert online == possible


# --- /proc/stat ---

def test_proc_stat_has_aggregate_plus_n_per_cpu_lines(tmp_path):
    persona = build_persona(tmp_path, cpu_count=4)
    stat = Path(persona.files["/proc/stat"]).read_text()
    cpu_lines = [l for l in stat.splitlines() if l.startswith("cpu")]
    # Expected: 1 aggregate "cpu " + 4 per-cpu lines "cpu0".."cpu3"
    assert len(cpu_lines) == 5
    assert cpu_lines[0].startswith("cpu ")
    for i in range(4):
        assert any(l.startswith(f"cpu{i} ") for l in cpu_lines)


def test_proc_stat_includes_required_kernel_fields(tmp_path):
    """Tools that parse /proc/stat (htop, monitoring) expect these
    fields. Missing them can crash the parser."""
    persona = build_persona(tmp_path, cpu_count=1)
    stat = Path(persona.files["/proc/stat"]).read_text()
    for field in ("intr ", "ctxt ", "btime ", "processes ", "softirq "):
        assert field in stat, f"missing /proc/stat field: {field!r}"


# --- DMI ---

def test_dmi_sys_vendor_is_qemu(tmp_path):
    """QEMU is plausible (most cloud workloads); avoids VirtualBox /
    innotek / VMware sandbox tells."""
    persona = build_persona(tmp_path, cpu_count=1)
    sv = Path(persona.files["/sys/class/dmi/id/sys_vendor"]).read_text()
    assert sv.strip() == "QEMU"


def test_dmi_product_name_is_standard_pc(tmp_path):
    persona = build_persona(tmp_path, cpu_count=1)
    pn = Path(persona.files["/sys/class/dmi/id/product_name"]).read_text()
    assert "Standard PC" in pn


# --- sched_setaffinity ---

def test_set_cpu_affinity_rejects_zero():
    with pytest.raises(ValueError, match="cpu_count must be >= 1"):
        set_cpu_affinity(0)


@pytest.mark.skipif(
    sys.platform != "linux", reason="sched_setaffinity is Linux-only",
)
def test_set_cpu_affinity_pins_to_one_cpu_when_one_requested():
    """Pin to CPU 0; sched_getaffinity should return exactly {0}.
    Saves and restores the original mask so this test doesn't bleed
    into siblings."""
    original = os.sched_getaffinity(0)
    try:
        effective = set_cpu_affinity(1)
        new = os.sched_getaffinity(0)
        assert effective == 1
        assert new == {0}
    finally:
        os.sched_setaffinity(0, original)


@pytest.mark.skipif(
    sys.platform != "linux" or len(os.sched_getaffinity(0)) < 2,
    reason="needs Linux + >= 2 available CPUs",
)
def test_set_cpu_affinity_pins_to_two_when_two_requested():
    original = os.sched_getaffinity(0)
    try:
        effective = set_cpu_affinity(2)
        new = os.sched_getaffinity(0)
        assert effective == 2
        # Mask should be contiguous from 0 to match persona's cpu_online range.
        assert new == {0, 1}
    finally:
        os.sched_setaffinity(0, original)


@pytest.mark.skipif(
    sys.platform != "linux", reason="sched_setaffinity is Linux-only",
)
def test_set_cpu_affinity_clamps_to_available(caplog):
    """If cpu_count exceeds available CPUs, clamp and log INFO. Logged
    so operators can see the persona partially degraded."""
    import logging
    original = os.sched_getaffinity(0)
    try:
        with caplog.at_level(logging.INFO, logger="core.sandbox.fingerprint"):
            effective = set_cpu_affinity(len(original) + 1000)
        assert effective == len(original)
        assert any(
            "clamping" in rec.message.lower() for rec in caplog.records
        )
    finally:
        os.sched_setaffinity(0, original)


# --- Platform support ---

def test_is_supported_returns_true_on_linux():
    if sys.platform == "linux":
        assert is_supported() is True
    else:
        assert is_supported() is False
