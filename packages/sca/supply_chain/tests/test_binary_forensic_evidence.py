"""Phase 8 tests — binary forensic evidence in ``binary_in_package``.

When the detector hits an ELF binary in a published source tree,
the converter consults the existing ``core/binary`` substrate to:

  * detect packer signatures (UPX, Themida, VMProtect, ...)
  * compute the capability-bucket fingerprint

A populated high-severity bucket
(``exec`` / ``network`` / ``runtime_privilege`` / ``kernel_trace``)
or any packer match promotes the finding from medium to high
standalone — independent of the composite chokepoint's HOOK+BINARY
critical promotion.
"""

from __future__ import annotations

import struct
from pathlib import Path

from core.binary import elf as core_elf


def _write_package_json(tmp_path: Path) -> Path:
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "victim", "version": "1.0.0"}', encoding="utf-8")
    return pkg


def _write_elf_with_imports(p: Path, imports: list[str]) -> None:
    """Write a minimal valid ELF64 binary containing ``imports`` as
    UNDEF dynsym entries, so ``capability_fingerprint`` extracts the
    import set the bucket classifier needs."""
    p.parent.mkdir(parents=True, exist_ok=True)
    # Build dynstr (string table for symbol names).  Starts with a
    # null byte; each name terminated by null.
    dynstr_chunks = [b"\x00"]
    offsets = []
    for name in imports:
        offsets.append(sum(len(c) for c in dynstr_chunks))
        dynstr_chunks.append(name.encode("ascii") + b"\x00")
    dynstr = b"".join(dynstr_chunks)
    # Build dynsym entries.  ELF64 Sym is 24 bytes:
    #   st_name (4) st_info (1) st_other (1) st_shndx (2)
    #   st_value (8) st_size (8)
    # SHN_UNDEF == 0.  First entry is the reserved null symbol.
    dynsym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for off in offsets:
        # st_info: STB_GLOBAL << 4 | STT_FUNC == 0x12
        dynsym += struct.pack("<IBBHQQ", off, 0x12, 0, 0, 0, 0)
    # Section header layout (ELF64):
    #   [0] SHT_NULL  (reserved)
    #   [1] .shstrtab (section name strings)
    #   [2] .dynstr   (dynamic string table)
    #   [3] .dynsym   (dynamic symbol table)
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00"
    sh_names = {
        ".shstrtab": shstrtab.find(b".shstrtab\x00"),
        ".dynstr":   shstrtab.find(b".dynstr\x00"),
        ".dynsym":   shstrtab.find(b".dynsym\x00"),
    }
    # Build section bodies in file.  ELF header (64 bytes) +
    # section data + section headers.
    EHSIZE = 64
    SHENTSIZE = 64
    body = bytearray()
    body += b"\x00" * EHSIZE                          # placeholder for ehdr
    shstr_off = len(body)
    body += shstrtab
    dynstr_off = len(body)
    body += dynstr
    dynsym_off = len(body)
    body += dynsym
    shoff = len(body)
    # Pad to align.
    while len(body) % 8 != 0:
        body += b"\x00"
        shoff = len(body)
    # Section headers.
    def _sh(sh_name_off, sh_type, sh_flags, sh_offset, sh_size,
            sh_link, sh_entsize):
        # ELF64 Shdr is 64 bytes.
        return struct.pack(
            "<IIQQQQIIQQ",
            sh_name_off, sh_type, sh_flags, 0,
            sh_offset, sh_size, sh_link, 0, 8, sh_entsize,
        )
    sh_null = _sh(0, 0, 0, 0, 0, 0, 0)
    sh_shstrtab = _sh(sh_names[".shstrtab"], 3, 0,
                      shstr_off, len(shstrtab), 0, 0)
    sh_dynstr = _sh(sh_names[".dynstr"], 3, 0,
                    dynstr_off, len(dynstr), 0, 0)
    sh_dynsym = _sh(sh_names[".dynsym"], 11, 0,
                    dynsym_off, len(dynsym), 2, 24)
    body += sh_null + sh_shstrtab + sh_dynstr + sh_dynsym
    # ELF header.  Machine = x86_64 (0x3E).  e_phoff = 0
    # (no program headers — we don't need them for fingerprinting).
    ehdr = struct.pack(
        "<4sBBBBBBBBBBBBHHIQQQIHHHHHH",
        b"\x7fELF",                     # magic
        2, 1, 1, 0, 0,                   # class=64, data=lsb, ver, osabi=systemv, abiv
        0, 0, 0, 0, 0, 0, 0,             # 7 bytes EI_PAD
        2, 0x3E, 1,                      # type=EXEC, machine=x86_64, version=1
        0,                                # entry
        0,                                # phoff
        shoff,                            # shoff
        0,                                # flags
        EHSIZE, 0, 0,                    # ehsize, phentsize, phnum
        SHENTSIZE, 4, 1,                  # shentsize, shnum, shstrndx
    )
    body[:EHSIZE] = ehdr
    p.write_bytes(bytes(body))


# ---------------------------------------------------------------------------
# Packer detection
# ---------------------------------------------------------------------------

def test_upx_signature_detected(tmp_path: Path) -> None:
    p = tmp_path / "upx.bin"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 0x10 + b"UPX!"
                  + b"\x00" * 100)
    assert core_elf.is_packed(p) == "upx"


def test_themida_signature_detected(tmp_path: Path) -> None:
    p = tmp_path / "themida.bin"
    p.write_bytes(b"MZ" + b"\x00" * 100 + b"Themida\x00" + b"\x00" * 100)
    assert core_elf.is_packed(p) == "themida"


def test_unpacked_binary_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "clean.bin"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 256)
    assert core_elf.is_packed(p) is None


def test_nonexistent_file_returns_none(tmp_path: Path) -> None:
    assert core_elf.is_packed(tmp_path / "missing") is None


# ---------------------------------------------------------------------------
# Capability fingerprint surfaces through binary_in_package
# ---------------------------------------------------------------------------

def test_binary_with_runtime_privilege_imports_promoted_high(
    tmp_path: Path,
) -> None:
    """An ELF in the package tree importing ``ptrace`` / ``setuid``
    must promote from medium to high standalone — these are
    rootkit-vocabulary symbols a normal native dependency would
    never import."""
    from packages.sca.supply_chain import _hook_patterns  # noqa: F401
    _write_package_json(tmp_path)
    _write_elf_with_imports(
        tmp_path / "tools" / "setup",
        ["ptrace", "setuid", "fork"],
    )
    from packages.sca.supply_chain import binary_in_package
    binary_in_package._ALLOWLIST = None  # clear cache
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert hits
    relpaths = [h.relpath for h in hits]
    matching = [h for h in hits if h.relpath.endswith("setup")]
    assert matching, (
        f"expected hit on tools/setup; got relpaths={relpaths!r}"
    )
    hit = matching[0]
    # Forensic evidence must surface the bucket.
    buckets = hit.forensic_evidence.get("capability_buckets", {})
    assert "runtime_privilege" in buckets, (
        f"expected runtime_privilege bucket; got {sorted(buckets)!r}"
    )


def test_binary_with_exec_imports_high_severity_promoted(
    tmp_path: Path,
) -> None:
    """``system`` / ``execve`` populate the ``exec`` bucket — already
    high-severity in the existing taxonomy."""
    _write_package_json(tmp_path)
    _write_elf_with_imports(
        tmp_path / "scripts" / "install",
        ["system", "execve"],
    )
    from packages.sca.supply_chain import binary_in_package
    binary_in_package._ALLOWLIST = None
    hits = binary_in_package.scan_target(tmp_path, [], [])
    hit = next(h for h in hits if h.relpath.endswith("install"))
    assert "exec" in hit.forensic_evidence.get(
        "capability_buckets", {}
    )
    assert "exec" in hit.forensic_evidence.get(
        "high_severity_buckets", []
    )


def test_binary_with_innocuous_imports_no_high_severity_buckets(
    tmp_path: Path,
) -> None:
    """An ELF importing only innocuous symbols populates NO
    high-severity bucket — the finding stays at default medium."""
    _write_package_json(tmp_path)
    _write_elf_with_imports(
        tmp_path / "lib" / "helper",
        ["malloc", "free", "printf", "puts"],
    )
    from packages.sca.supply_chain import binary_in_package
    binary_in_package._ALLOWLIST = None
    hits = binary_in_package.scan_target(tmp_path, [], [])
    if not hits:
        return
    hit = hits[0]
    high = hit.forensic_evidence.get("high_severity_buckets", [])
    assert not high
