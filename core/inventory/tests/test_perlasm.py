"""Tests for perlasm generator detection + generated-asm inventory.

Hermetic by construction: no perl, no sandbox, no network — the
sandboxed execution seam (``core.sandbox.context.run_untrusted``) is
stubbed at its import source, so these tests exercise detection,
flavour derivation, caching, gap flagging and inventory enrichment
without ever running target code.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import core.inventory.perlasm as perlasm
from core.inventory.perlasm import (
    GENERATED_PREFIX,
    PerlasmGenerator,
    _cache_key,
    derive_flavour,
    detect_perlasm_generators,
    enrich_inventory_with_perlasm,
    generate_asm,
    run_perlasm_pass,
)

# The structural preamble shape shared by openssl perlasm generators:
# xlate driver lookup + $flavour/$output argv handling.
PERLASM_PREAMBLE = """\
#! /usr/bin/env perl
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\\.\\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\\.| ? shift : undef;

$0 =~ m/(.*[\\/\\\\])[^\\/\\\\]+$/; $dir=$1;
( $xlate="${dir}%(driver)s.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/%(driver)s.pl" and -f $xlate) or
die "can't locate %(driver)s.pl";

open OUT,"| \\"$^X\\" $xlate $flavour \\"$output\\"";
*STDOUT=*OUT;
$code=<<___;
.globl	demo_kernel
demo_kernel:
	ret
___
print $code;
close STDOUT or die;
"""

EMITTED_ASM = """\
.globl\tdemo_kernel
.type\tdemo_kernel,%function
demo_kernel:
\tret
"""


def _write_generator(target: Path, rel: str, driver: str = "arm-xlate") -> Path:
    p = target / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(PERLASM_PREAMBLE % {"driver": driver})
    return p


@pytest.fixture
def target(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    return t


@pytest.fixture
def fake_sandbox(monkeypatch):
    """Stub run_untrusted at its import source; records invocations."""
    calls = []

    def _stub(cmd, **kwargs):
        calls.append((list(cmd), dict(kwargs)))
        Path(cmd[3]).write_text(EMITTED_ASM)

        class _Proc:
            returncode = 0
            stderr = ""
        return _Proc()

    import core.sandbox.context as ctx
    monkeypatch.setattr(ctx, "run_untrusted", _stub)
    return calls


class TestDetection:
    def test_structural_signature_detected(self, target):
        _write_generator(target, "crypto/aes/asm/aes-demo-armv8.pl")
        gens = detect_perlasm_generators(target)
        assert len(gens) == 1
        g = gens[0]
        assert g.rel_path == "crypto/aes/asm/aes-demo-armv8.pl"
        assert g.driver == "arm-xlate"
        assert len(g.sha256) == 64

    def test_detection_is_content_based_not_path_based(self, target):
        # Same preamble outside any asm/ directory still matches.
        _write_generator(target, "tools/gen.pl", driver="x86_64-xlate")
        gens = detect_perlasm_generators(target)
        assert [g.driver for g in gens] == ["x86_64-xlate"]

    def test_plain_perl_script_not_detected(self, target):
        p = target / "scripts" / "helper.pl"
        p.parent.mkdir(parents=True)
        p.write_text("#!/usr/bin/env perl\nprint \"hello\";\n")
        assert detect_perlasm_generators(target) == []

    def test_xlate_driver_itself_excluded(self, target):
        p = target / "crypto" / "perlasm" / "arm-xlate.pl"
        p.parent.mkdir(parents=True)
        p.write_text(PERLASM_PREAMBLE % {"driver": "arm-xlate"})
        assert detect_perlasm_generators(target) == []

    def test_symlinked_generator_skipped(self, target):
        real = _write_generator(target, "crypto/aes/asm/real.pl")
        (target / "crypto" / "link.pl").symlink_to(real)
        gens = detect_perlasm_generators(target)
        assert [g.rel_path for g in gens] == ["crypto/aes/asm/real.pl"]


class TestFlavourDerivation:
    def _gen(self, target, driver):
        path = _write_generator(target, "crypto/x/asm/g.pl", driver=driver)
        return detect_perlasm_generators(target)[0] if path else None

    def test_arm_family_defaults_to_linux64(self, target):
        gen = self._gen(target, "arm-xlate")
        assert derive_flavour(gen, target) == (
            "linux64", "driver-family default for arm-xlate",
        )

    def test_x86_64_family_defaults_to_elf(self, target):
        gen = self._gen(target, "x86_64-xlate")
        flavour, _ = derive_flavour(gen, target)
        assert flavour == "elf"

    def test_unknown_family_yields_gap(self, target):
        gen = self._gen(target, "ppc-xlate")
        flavour, reason = derive_flavour(gen, target)
        assert flavour is None
        assert "ppc-xlate" in reason

    def test_build_metadata_wins(self, target):
        gen = self._gen(target, "arm-xlate")
        (target / "configdata.pm").write_text(
            'our %config = (\n  "perlasm_scheme" => "ios64",\n);\n'
        )
        assert derive_flavour(gen, target) == (
            "ios64", "build-metadata (configdata.pm)",
        )


class TestGenerationAndCache:
    def test_sandboxed_generation_and_cache_hit(self, target, tmp_path,
                                                fake_sandbox):
        gen = detect_perlasm_generators(
            target := self._with_gen(target)
        )[0]
        cache = tmp_path / "cache"
        cached, gap = generate_asm(gen, "linux64", target, cache)
        assert gap is None
        assert cached is not None and cached.read_text() == EMITTED_ASM
        # argv is list-based: perl, generator, flavour, output.
        cmd, kwargs = fake_sandbox[0]
        assert cmd[0] == "perl" and cmd[2] == "linux64"
        assert kwargs["profile"] == "strict"
        assert kwargs["target"] == str(target)
        assert kwargs["output"] == str(cache)
        # Second call: cache hit, no new sandbox invocation.
        again, gap = generate_asm(gen, "linux64", target, cache)
        assert again == cached and gap is None
        assert len(fake_sandbox) == 1

    def test_cache_key_varies_by_flavour_and_content(self, target):
        gen = detect_perlasm_generators(self._with_gen(target))[0]
        k1 = _cache_key(gen, "linux64")
        k2 = _cache_key(gen, "ios64")
        assert k1 != k2
        gen2 = PerlasmGenerator(
            path=gen.path, rel_path=gen.rel_path, driver=gen.driver,
            sha256="0" * 64,
        )
        assert _cache_key(gen2, "linux64") != k1

    def test_sandbox_refusal_is_a_gap(self, target, tmp_path, monkeypatch):
        from core.sandbox.errors import SandboxSetupError
        import core.sandbox.context as ctx

        def _refuse(cmd, **kwargs):
            raise SandboxSetupError("landlock unavailable")

        monkeypatch.setattr(ctx, "run_untrusted", _refuse)
        gen = detect_perlasm_generators(self._with_gen(target))[0]
        cached, gap = generate_asm(gen, "linux64", target, tmp_path / "c")
        assert cached is None
        assert "sandbox refused" in gap and "NOT executed" in gap

    def test_generator_failure_is_a_gap(self, target, tmp_path, monkeypatch):
        import core.sandbox.context as ctx

        def _fail(cmd, **kwargs):
            class _Proc:
                returncode = 2
                stderr = "syntax error at line 3"
            return _Proc()

        monkeypatch.setattr(ctx, "run_untrusted", _fail)
        gen = detect_perlasm_generators(self._with_gen(target))[0]
        cached, gap = generate_asm(gen, "linux64", target, tmp_path / "c")
        assert cached is None
        assert "exited 2" in gap and "syntax error" in gap

    def test_empty_output_is_a_gap(self, target, tmp_path, monkeypatch):
        import core.sandbox.context as ctx

        def _silent(cmd, **kwargs):
            class _Proc:
                returncode = 0
                stderr = ""
            return _Proc()

        monkeypatch.setattr(ctx, "run_untrusted", _silent)
        gen = detect_perlasm_generators(self._with_gen(target))[0]
        cached, gap = generate_asm(gen, "linux64", target, tmp_path / "c")
        assert cached is None
        assert "no output" in gap

    @staticmethod
    def _with_gen(target: Path) -> Path:
        _write_generator(target, "crypto/aes/asm/aes-demo-armv8.pl")
        return target


class TestPassAndGaps:
    def test_no_perl_is_a_loud_gap(self, target, tmp_path, monkeypatch):
        _write_generator(target, "crypto/aes/asm/g.pl")
        monkeypatch.setattr(perlasm.shutil, "which", lambda _: None)
        res = run_perlasm_pass(target, cache_dir=tmp_path / "c")
        assert res.file_records == []
        assert len(res.gaps) == 1
        assert "perl not installed" in res.gaps[0]
        assert "NOT analysed" in res.gaps[0]

    def test_generator_cap_is_a_gap(self, target, tmp_path, fake_sandbox,
                                    monkeypatch):
        monkeypatch.setattr(perlasm.shutil, "which", lambda _: "/usr/bin/perl")
        _write_generator(target, "crypto/a/asm/a.pl")
        _write_generator(target, "crypto/b/asm/b.pl")
        res = run_perlasm_pass(target, cache_dir=tmp_path / "c",
                               max_generators=1)
        assert len(res.file_records) == 1
        assert any("cap (1) reached" in g for g in res.gaps)

    def test_unknown_flavour_family_is_a_gap(self, target, tmp_path,
                                             fake_sandbox, monkeypatch):
        monkeypatch.setattr(perlasm.shutil, "which", lambda _: "/usr/bin/perl")
        _write_generator(target, "crypto/bn/asm/ppc.pl", driver="ppc-xlate")
        res = run_perlasm_pass(target, cache_dir=tmp_path / "c")
        assert res.file_records == []
        assert any("ppc-xlate" in g and "NOT" in g for g in res.gaps)

    def test_no_generators_zero_cost(self, target, tmp_path):
        res = run_perlasm_pass(target, cache_dir=tmp_path / "c")
        assert res.generators == [] and res.gaps == []


class TestEnrichment:
    def _inventory(self):
        return {
            "total_files": 1, "total_items": 2, "total_functions": 2,
            "total_sloc": 10,
            "files": [{"path": "crypto/aes/asm/aes-demo-armv8.pl",
                       "language": "perl", "items": []}],
        }

    def test_records_language_and_provenance(self, target, tmp_path,
                                             fake_sandbox, monkeypatch):
        monkeypatch.setattr(perlasm.shutil, "which", lambda _: "/usr/bin/perl")
        _write_generator(target, "crypto/aes/asm/aes-demo-armv8.pl")
        inv = self._inventory()
        enrich_inventory_with_perlasm(inv, target, cache_dir=tmp_path / "c")
        generated = [f for f in inv["files"]
                     if f["language"] == "asm-generated"]
        assert len(generated) == 1
        rec = generated[0]
        assert rec["path"] == (
            f"{GENERATED_PREFIX}/crypto/aes/asm/aes-demo-armv8.pl.linux64.S"
        )
        prov = rec["perlasm"]
        assert prov["generator"] == "crypto/aes/asm/aes-demo-armv8.pl"
        assert prov["flavour"] == "linux64"
        assert prov["flavour_source"].startswith("driver-family default")
        assert Path(prov["generated_path"]).is_file()
        # The emitted kernel is an enumerable, reviewable unit.
        assert [i["name"] for i in rec["items"]] == ["demo_kernel"]
        assert rec["items"][0]["metadata"]["visibility"] == "exported"
        # Totals were bumped.
        assert inv["total_files"] == 2
        assert inv["total_functions"] == 3
        assert inv["perlasm"]["generators_detected"] == 1
        assert inv["perlasm"]["analysed"] == 1

    def test_gaps_land_in_limitations(self, target, tmp_path, monkeypatch):
        monkeypatch.setattr(perlasm.shutil, "which", lambda _: None)
        _write_generator(target, "crypto/aes/asm/g.pl")
        inv = self._inventory()
        enrich_inventory_with_perlasm(inv, target, cache_dir=tmp_path / "c")
        assert any(
            lim.startswith("perlasm coverage gap:") and "perl not installed" in lim
            for lim in inv["limitations"]
        )
        assert inv["perlasm"]["analysed"] == 0

    def test_kill_switch(self, target, tmp_path, monkeypatch):
        monkeypatch.setitem(os.environ, "RAPTOR_NO_PERLASM", "1")
        _write_generator(target, "crypto/aes/asm/g.pl")
        inv = self._inventory()
        enrich_inventory_with_perlasm(inv, target, cache_dir=tmp_path / "c")
        assert "perlasm" not in inv and len(inv["files"]) == 1

    def test_config_flag_off(self, target, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "PERLASM_INVENTORY", False,
                            raising=False)
        _write_generator(target, "crypto/aes/asm/g.pl")
        inv = self._inventory()
        enrich_inventory_with_perlasm(inv, target, cache_dir=tmp_path / "c")
        assert "perlasm" not in inv

    def test_no_generators_leaves_inventory_untouched(self, target, tmp_path):
        inv = self._inventory()
        before = {k: v for k, v in inv.items() if k != "files"}
        enrich_inventory_with_perlasm(inv, target, cache_dir=tmp_path / "c")
        assert "perlasm" not in inv
        assert {k: v for k, v in inv.items() if k != "files"} == before
