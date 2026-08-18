"""Tests for the zero-length loop-entry check over generated asm.

The three fixtures under ``fixtures/perlasm/`` are real excerpts of
the assembly emitted (sandboxed) by openssl-4.0.1's perlasm
generators — the two vulnerable AES-CBC-HMAC kernels the external
harness found (#9/#10) plus the conforming sha512 sibling. Provenance
comments in each fixture name the generator and flavour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.asm_zero_len_loop import (
    DETECTOR_NAME,
    asm_findings_to_mechanical,
    check_zero_length_loop_entry,
    scan_inventory_asm,
)

FIXTURES = Path(__file__).parent / "fixtures" / "perlasm"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


class TestRealKernelFixtures:
    """The observed finding class, anchored on real generated output."""

    def test_sha1_kernel_flagged(self):
        findings = check_zero_length_loop_entry(
            _fixture("aes-sha1-armv8.linux64.S")
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["function"] == "asm_aescbc_sha1_hmac"
        assert f["loop_label"] == ".Lenc_short_loop"
        assert f["counter"] == "x10"
        assert f["length_source"] == "x2"
        # The store precedes the first in-body zero test.
        assert f["store_at_line"] < f["first_test_at_line"]
        # The cmp/b.lt dispatch that routes zero to the short path is
        # named as routing evidence.
        assert f["dispatch"] and ".Lenc_short_cases" in f["dispatch"]
        assert f["cwe"] == "CWE-191"

    def test_sha256_kernel_flagged(self):
        findings = check_zero_length_loop_entry(
            _fixture("aes-sha256-armv8.linux64.S")
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["function"] == "asm_aescbc_sha256_hmac"
        assert f["loop_label"] == ".Lenc_short_loop"
        assert f["counter"] == "x10"

    def test_sha512_sibling_conforms(self):
        """The leading ``cbz x11, .Lret`` guard suppresses the lead."""
        assert check_zero_length_loop_entry(
            _fixture("aes-sha512-armv8.linux64.S")
        ) == []


class TestSyntheticShapes:
    """Minimal synthetic AArch64 shapes for each decision branch."""

    VULN = """\
func:
\tlsr\tx10, x2, 4
.Lloop:
\tst1\t{v0.16b}, [x1], 16
\tsub\tx10, x10, 1
\tcbz\tx10, .Ldone
\tb\t.Lloop
\tcbnz\tx10, .Lloop
.Ldone:
\tret
"""

    def test_store_before_test_flagged(self):
        findings = check_zero_length_loop_entry(self.VULN)
        assert len(findings) == 1
        assert findings[0]["loop_label"] == ".Lloop"
        assert findings[0]["dispatch"] is None

    def test_leading_zero_guard_suppresses(self):
        guarded = self.VULN.replace(
            ".Lloop:", "\tcbz\tx10, .Ldone\n.Lloop:"
        )
        assert check_zero_length_loop_entry(guarded) == []

    def test_cmp_zero_guard_suppresses(self):
        guarded = self.VULN.replace(
            ".Lloop:", "\tcmp\tx10, #0\n\tb.eq\t.Ldone\n.Lloop:"
        )
        assert check_zero_length_loop_entry(guarded) == []

    def test_test_before_store_conforms(self):
        conforming = """\
func:
\tlsr\tx10, x2, 4
.Lloop:
\tsub\tx10, x10, 1
\tcbz\tx10, .Ldone
\tst1\t{v0.16b}, [x1], 16
\tcbnz\tx10, .Lloop
.Ldone:
\tret
"""
        assert check_zero_length_loop_entry(conforming) == []

    def test_fallthrough_of_magnitude_dispatch_guarded(self):
        """cmp C,#N / b.lt L: the fall-through region has C >= N."""
        asm = """\
func:
\tlsr\tx10, x2, 4
\tcmp\tx10, 12
\tb.lt\t.Lshort
.Lmain:
\tst1\t{v0.16b}, [x1], 16
\tsub\tx10, x10, 1
\tcbnz\tx10, .Lmain
.Lshort:
\tret
"""
        assert check_zero_length_loop_entry(asm) == []

    def test_short_path_of_magnitude_dispatch_flagged(self):
        """...but the b.lt target region receives C < N including 0."""
        asm = """\
func:
\tlsr\tx10, x2, 4
\tcmp\tx10, 12
\tb.lt\t.Lshort
\tret
.Lshort:
.Lloop:
\tst1\t{v0.16b}, [x1], 16
\tsub\tx10, x10, 1
\tcbnz\tx10, .Lloop
"""
        findings = check_zero_length_loop_entry(asm)
        assert len(findings) == 1
        assert findings[0]["dispatch"] is not None

    def test_subs_bne_loop_variant(self):
        asm = """\
func:
\tlsr\tx4, x2, 4
.Lloop:
\tstr\tq0, [x1], 16
\tsubs\tx4, x4, 1
\tb.ne\t.Lloop
"""
        findings = check_zero_length_loop_entry(asm)
        assert len(findings) == 1
        assert findings[0]["counter"] == "x4"

    def test_mov_copied_length_recognised(self):
        asm = """\
func:
\tmov\tx11, x2
\tlsr\tx12, x11, 6
.Lloop:
\tstp\tq0, q1, [x1], 32
\tsub\tx12, x12, 1
\tcbnz\tx12, .Lloop
"""
        assert len(check_zero_length_loop_entry(asm)) == 1

    def test_non_length_counter_ignored(self):
        asm = """\
func:
\tlsr\tx10, x20, 4
.Lloop:
\tst1\t{v0.16b}, [x1], 16
\tsub\tx10, x10, 1
\tcbnz\tx10, .Lloop
"""
        assert check_zero_length_loop_entry(asm) == []

    def test_loop_without_store_ignored(self):
        asm = """\
func:
\tlsr\tx10, x2, 4
.Lloop:
\tld1\t{v0.16b}, [x0], 16
\tsub\tx10, x10, 1
\tcbnz\tx10, .Lloop
"""
        assert check_zero_length_loop_entry(asm) == []

    def test_non_aarch64_input_yields_nothing(self):
        x86 = """\
aesni_cbc_sha1_enc:
\tmovq\t%rdi, %r8
.Lloop:
\tmovups\t%xmm0, (%rsi)
\tdecq\t%rdx
\tjnz\t.Lloop
\tret
"""
        assert check_zero_length_loop_entry(x86) == []

    def test_garbage_and_empty_input(self):
        assert check_zero_length_loop_entry("") == []
        assert check_zero_length_loop_entry("\x00\x01 not asm at all") == []

    def test_comments_stripped(self):
        commented = self.VULN.replace(
            ".Lloop:", "/* cbz x10, .Ldone (commented out) */\n.Lloop:"
        ).replace(
            "\tsub\tx10, x10, 1",
            "\tsub\tx10, x10, 1\t// decrement after the store",
        )
        assert len(check_zero_length_loop_entry(commented)) == 1


class TestMechanicalConversion:
    """Channel shape parity with semantic_findings_to_mechanical."""

    def test_mechanical_shape(self):
        findings = check_zero_length_loop_entry(
            _fixture("aes-sha1-armv8.linux64.S")
        )
        mech = asm_findings_to_mechanical(
            findings,
            file_path=".perlasm-generated/crypto/aes/asm/aes-sha1-armv8.pl.linux64.S",
            provenance="generated from crypto/aes/asm/aes-sha1-armv8.pl flavour=linux64",
        )
        assert len(mech) == 1
        mf = mech[0]
        assert set(mf) == {"file", "function", "detector", "line", "description"}
        assert mf["detector"] == DETECTOR_NAME
        assert mf["function"] == "asm_aescbc_sha1_hmac"
        assert mf["line"] > 0
        assert "CWE-191" in mf["description"]
        assert "detection-grade" in mf["description"]
        assert "flavour=linux64" in mf["description"]
        json.dumps(mech)  # serialisable for mechanical-findings.json

    def test_scan_inventory_asm(self, tmp_path):
        gen_s = tmp_path / "cached.S"
        gen_s.write_text(_fixture("aes-sha1-armv8.linux64.S"))
        checklist = {
            "files": [
                {"path": "crypto/aes/asm/aes-sha1-armv8.pl",
                 "language": "perl", "items": []},
                {"path": ".perlasm-generated/crypto/aes/asm/aes-sha1-armv8.pl.linux64.S",
                 "language": "asm-generated",
                 "perlasm": {
                     "generator": "crypto/aes/asm/aes-sha1-armv8.pl",
                     "flavour": "linux64",
                     "generated_path": str(gen_s),
                 }},
            ],
        }
        mech = scan_inventory_asm(checklist)
        assert len(mech) == 1
        assert mech[0]["file"].startswith(".perlasm-generated/")
        assert "aes-sha1-armv8.pl" in mech[0]["description"]

    @pytest.mark.parametrize("checklist", [
        None,
        {},
        {"files": []},
        {"files": [{"path": "x.S", "language": "asm-generated"}]},  # no path
        {"files": [{"path": "x.S", "language": "asm-generated",
                    "perlasm": {"generated_path": "/nonexistent/nope.S"}}]},
    ])
    def test_scan_inventory_asm_tolerates_bad_records(self, checklist):
        assert scan_inventory_asm(checklist) == []


@pytest.fixture(scope="module")
def prep_with_generated_asm(tmp_path_factory):
    """Real ``_compute_audit_prep`` over a checklist carrying an
    asm-generated record — the orchestrator routing seam, hermetic
    (no perl, no sandbox: the record is appended post-build, exactly
    the shape ``core.inventory.perlasm`` emits).
    """
    import os
    import subprocess
    import sys

    raptor_dir = Path(__file__).resolve().parents[3]
    target = tmp_path_factory.mktemp("perlasm_target")
    (target / "app.py").write_text(
        "def entry(data):\n    return data.strip()\n"
    )
    out = tmp_path_factory.mktemp("perlasm_out")
    env = dict(
        os.environ,
        CLAUDECODE="1",
        _RAPTOR_TRUSTED="1",
        PYTHONPATH=str(raptor_dir),
        RAPTOR_NO_PERLASM="1",
    )
    r = subprocess.run(
        [sys.executable, str(raptor_dir / "libexec" / "raptor-build-checklist"),
         str(target), str(out)],
        env=env, capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, f"build-checklist failed: {r.stderr}"

    cached = tmp_path_factory.mktemp("perlasm_cache") / "kernel.S"
    cached.write_text(_fixture("aes-sha1-armv8.linux64.S"))
    checklist_path = out / "checklist.json"
    checklist = json.loads(checklist_path.read_text())
    checklist["files"].append({
        "path": ".perlasm-generated/crypto/aes/asm/aes-sha1-armv8.pl.linux64.S",
        "language": "asm-generated",
        "lines": 128, "sloc": 100,
        "sha256": "0" * 64,
        "items": [{"name": "asm_aescbc_sha1_hmac", "kind": "function",
                   "line_start": 13, "line_end": 128, "checked_by": []}],
        "perlasm": {
            "generator": "crypto/aes/asm/aes-sha1-armv8.pl",
            "flavour": "linux64",
            "generated_path": str(cached),
        },
    })
    checklist_path.write_text(json.dumps(checklist))

    from core.audit.orchestrator import (
        OrchestratorConfig,
        _compute_audit_prep,
    )

    config = OrchestratorConfig(
        target_path=target,
        out_dir=out,
        resume=False,
        force=True,
        include_stale=False,
        enable_session_context=False,
        propagate_constraints=False,
    )
    prep = _compute_audit_prep(config)
    assert prep is not None, "prep returned None (checklist missing?)"
    return prep, out


class TestOrchestratorRouting:
    """The seam: asm leads reach the mechanical-findings channel."""

    def test_finding_routed_to_mechanical_channel(
            self, prep_with_generated_asm):
        prep, _ = prep_with_generated_asm
        key = (".perlasm-generated/crypto/aes/asm/"
               "aes-sha1-armv8.pl.linux64.S:asm_aescbc_sha1_hmac")
        entries = prep["mechanical_findings"].get(key, [])
        assert any(e["detector"] == DETECTOR_NAME for e in entries)

    def test_finding_persisted_to_disk(self, prep_with_generated_asm):
        _, out = prep_with_generated_asm
        mech = json.loads((out / "mechanical-findings.json").read_text())
        assert any(
            e["detector"] == DETECTOR_NAME
            for entries in mech.values() for e in entries
        )
