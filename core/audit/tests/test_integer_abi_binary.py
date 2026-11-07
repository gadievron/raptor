"""Binary platform selection takes precedence over host analysis assumptions."""

import struct

import pytest

from core.audit import integer_abi
from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config
from core.binary.tests.test_pe_facts import build_pe
from packages.binary_analysis.tests.test_macho_facts import build_fat, build_thin


def _elf(bits, machine, *, osabi=0, endian="little"):
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "little" else 2, 1, osabi]) + bytes(8)
    fmt = "HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"
    return ident + struct.pack(("<" if endian == "little" else ">") + fmt,
                               2, machine, 1, 0, 0, 0, 0, 64 if bits == 64 else 52, 0, 0, 0, 0, 0)


@pytest.fixture(autouse=True)
def _host_must_not_be_consulted(monkeypatch):
    monkeypatch.setattr(integer_abi, "host_integer_abi",
                        lambda: pytest.fail("binary audit must not inherit the host ABI"))


@pytest.mark.parametrize("image,profile", [
    pytest.param(_elf(32, 3), "ilp32", id="elf-i386"),
    pytest.param(_elf(64, 62), "lp64", id="elf-amd64"),
    pytest.param(_elf(32, 62), "ilp32", id="elf-x32-not-amd64-lp64"),
    pytest.param(_elf(64, 183), "lp64", id="elf-aarch64"),
    pytest.param(_elf(32, 2, osabi=6, endian="big"), "ilp32", id="solaris-sparc32"),
    pytest.param(_elf(64, 43, osabi=6, endian="big"), "lp64", id="solaris-sparc64"),
    pytest.param(build_pe(), "llp64", id="windows-pe64-long-is-32"),
    pytest.param(build_pe(machine=0x14c, magic=0x10b), "ilp32", id="windows-pe32"),
    pytest.param(build_thin([], bits=32, cputype=7), "ilp32", id="macho-x86"),
    pytest.param(build_thin([]), "lp64", id="macho-amd64"),
])
def test_binary_platform_reaches_config_and_proof_identity(tmp_path, image, profile):
    target = tmp_path / "program"
    target.write_bytes(image)
    opts = AuditPipelineOpts(target_path=target, out_dir=tmp_path / "out")
    config = _build_orchestrator_config(opts, None, ["test"], ReviewMode.SECURITY)
    abi = integer_abi.resolve_integer_abi(config.integer_abi)
    assert abi is not None
    assert abi.source == "binary-platform"
    expected = integer_abi.INTEGER_ABIS[profile]
    assert (abi.int_bits, abi.long_bits) == (expected.int_bits, expected.long_bits)
    assert opts.integer_abi == abi.record()
    assert integer_abi.integer_abi_key(abi) != integer_abi.integer_abi_key(profile)


@pytest.mark.parametrize("image", [
    pytest.param(b"\x7fELF", id="truncated-elf"),
    pytest.param(_elf(64, 0xffff), id="unknown-machine"),
    pytest.param(_elf(64, 3), id="contradictory-elf-class-and-machine"),
    pytest.param(_elf(64, 62, osabi=13), id="nonstandard-elf-platform"),
    pytest.param(build_pe(subsystem=10), id="efi-is-not-windows"),
    pytest.param(build_pe(machine=0x14c), id="contradictory-pe-headers"),
    pytest.param(build_fat([build_thin([]), build_thin([], bits=32, cputype=7)]), id="universal-macho"),
    pytest.param(b"ghidra project", id="project-not-an-image"),
])
def test_unsupported_binary_never_falls_back_to_host(tmp_path, image):
    target = tmp_path / "program"
    target.write_bytes(image)
    assert integer_abi.select_integer_abi(None, target_path=target) == "unknown"
    opts = AuditPipelineOpts(target_path=target, out_dir=tmp_path)
    config = _build_orchestrator_config(opts, None, ["test"], ReviewMode.SECURITY)
    assert config.integer_abi is None


def test_explicit_override_precedes_binary_platform(tmp_path, monkeypatch):
    target = tmp_path / "program"
    target.write_bytes(build_pe())
    monkeypatch.setattr(integer_abi, "binary_integer_abi",
                        lambda *args: pytest.fail("explicit override must not rederive ABI"))
    assert integer_abi.select_integer_abi("ilp32", target_path=target) == "ilp32"
    assert integer_abi.select_integer_abi("unknown", target_path=target) == "unknown"
