"""Fold-detection identity and subprocess text-decode hardening tests
for :mod:`core.analysis.binary_oracle`."""
from __future__ import annotations

from pathlib import Path

import core.analysis.binary_oracle as bo_mod


def _stub_tools(monkeypatch, subs, demangled_map=None, nm=None):
    monkeypatch.setattr(bo_mod.shutil, "which", lambda t: f"/usr/bin/{t}")
    monkeypatch.setattr(bo_mod, "read_build_id", lambda p: "cafebabe")
    monkeypatch.setattr(
        bo_mod, "_nm_symbols_status", lambda p: (dict(nm or {}), True),
    )
    monkeypatch.setattr(bo_mod, "_parse_dwarf", lambda p: (subs, []))
    monkeypatch.setattr(
        bo_mod, "_demangle_linkage_names",
        lambda names: dict(demangled_map or {}),
    )


def test_dual_spelling_single_die_is_not_folded(monkeypatch, tmp_path):
    """ONE DWARF subprogram indexed under both its DW_AT_name spelling
    and the demangled-linkage canonical spelling (template-argument
    spelling drift) shares one low_pc across two names — that is one
    function, not an identical-code fold. Both spellings must read
    ``symbol_present``."""
    die = bo_mod._SubprogramDIE(
        name="Decompress<long unsigned int>",
        namespace_path="snappy",
        low_pc=0x100,
        linkage_name="_ZN6snappyMangledE",
    )
    demangled = "snappy::Decompress<unsigned long>(unsigned long)"
    canonical = bo_mod._qualified_from_demangled(demangled)
    assert canonical  # sanity: the canonical spelling resolves
    assert canonical != die.qualified_name

    _stub_tools(
        monkeypatch, {0x10: die},
        demangled_map={"_ZN6snappyMangledE": demangled},
    )
    fake_bin = tmp_path / "fixture-binary"
    fake_bin.write_bytes(b"\x7fELF-stub")

    verdicts = bo_mod.classify_binary_evidence(
        [die.qualified_name, canonical], fake_bin,
    )
    assert verdicts[die.qualified_name].classification == "symbol_present"
    assert verdicts[canonical].classification == "symbol_present"


def test_real_icf_fold_of_two_distinct_functions_still_detected(
    monkeypatch, tmp_path,
):
    """Two DISTINCT subprograms sharing one low_pc (linker ICF) must
    still classify ``folded`` — the dual-spelling fix must not weaken
    genuine fold detection."""
    die_a = bo_mod._SubprogramDIE(name="copy_bytes", low_pc=0x200)
    die_b = bo_mod._SubprogramDIE(name="move_bytes", low_pc=0x200)
    _stub_tools(monkeypatch, {0x10: die_a, 0x20: die_b})
    fake_bin = tmp_path / "fixture-binary"
    fake_bin.write_bytes(b"\x7fELF-stub")

    verdicts = bo_mod.classify_binary_evidence(
        ["copy_bytes", "move_bytes"], fake_bin,
    )
    assert verdicts["copy_bytes"].classification == "folded"
    assert verdicts["move_bytes"].classification == "folded"


def test_folded_verdict_reaches_alternate_spelling(monkeypatch, tmp_path):
    """A genuinely-folded function looked up under its demangled-
    canonical (alternate) spelling still reads ``folded``."""
    die_a = bo_mod._SubprogramDIE(
        name="copy<long unsigned int>", namespace_path="ns",
        low_pc=0x300, linkage_name="_Zmangled",
    )
    die_b = bo_mod._SubprogramDIE(name="move_bytes", low_pc=0x300)
    demangled = "ns::copy<unsigned long>(unsigned long)"
    canonical = bo_mod._qualified_from_demangled(demangled)
    assert canonical and canonical != die_a.qualified_name

    _stub_tools(
        monkeypatch, {0x10: die_a, 0x20: die_b},
        demangled_map={"_Zmangled": demangled},
    )
    fake_bin = tmp_path / "fixture-binary"
    fake_bin.write_bytes(b"\x7fELF-stub")

    verdicts = bo_mod.classify_binary_evidence([canonical], fake_bin)
    assert verdicts[canonical].classification == "folded"


def test_run_status_decodes_with_replacement(monkeypatch, tmp_path):
    """The sandboxed tool invocation must pass errors="replace" so
    non-UTF-8 tool output degrades instead of raising
    UnicodeDecodeError on sandbox-degraded hosts."""
    import core.sandbox as sandbox_mod

    captured: dict = {}

    class _Proc:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured.update(kwargs)
        return _Proc()

    monkeypatch.setattr(sandbox_mod, "run", fake_run)
    out, ok = bo_mod._run_status(["readelf", "-n", str(tmp_path / "b")])
    assert ok and out == "ok\n"
    assert captured.get("errors") == "replace"
    assert captured.get("encoding") == "utf-8"


def test_autodetect_has_dwarf_decodes_with_replacement(monkeypatch, tmp_path):
    """Same hardening on the autodetect probe's readelf call."""
    import core.analysis.binary_oracle_autodetect as ad_mod
    import core.sandbox as sandbox_mod

    elf = tmp_path / "cand"
    elf.write_bytes(b"\x7fELF" + b"\0" * 16)

    captured: dict = {}

    class _Proc:
        returncode = 0
        stdout = ".debug_info\n"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured.update(kwargs)
        return _Proc()

    monkeypatch.setattr(sandbox_mod, "run", fake_run)
    assert ad_mod._has_dwarf(Path(elf)) is True
    assert captured.get("errors") == "replace"
    assert captured.get("encoding") == "utf-8"
