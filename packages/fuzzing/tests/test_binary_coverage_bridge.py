"""Binary-target fuzz coverage: PC traces onto the binary checklist."""

import json
import struct

from packages.fuzzing.coverage_bridge import (
    emit_binary_fuzz_coverage,
    find_pc_dumps,
)


def _checklist(tmp_path):
    cl = {
        "target_path": str(tmp_path / "t"),
        "target_kind": "binary",
        "files": [{
            "path": "binary:t",
            "language": "binary",
            "sha256": "ab" * 32,
            "items": [
                {"name": "vuln", "kind": "function",
                 "address": 0x1000, "size": 0x80},
                {"name": "quiet", "kind": "function",
                 "address": 0x2000, "size": 0x80},
            ],
        }],
    }
    (tmp_path / "checklist.json").write_text(json.dumps(cl))
    return cl


def _sancov(path, pcs):
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", 0xC0BFFFFFFFFFFF64))
        for pc in pcs:
            f.write(struct.pack("<Q", pc))


class TestBinaryFuzzCoverage:
    def test_pcs_map_to_functions(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov", [0x1004, 0x1040])

        out = emit_binary_fuzz_coverage(
            tmp_path, binary=binary, iterations=7, crashes=1,
        )
        assert out is not None
        doc = json.loads(out.read_text())
        funcs = doc["files"]["binary:t"]["functions"]
        assert set(funcs) == {"vuln"}
        assert funcs["vuln"]["pcs"] == 2
        assert doc["tool"] == "fuzz"
        assert doc["functions_analysed"] == [
            {"file": "binary:t", "function": "vuln"},
        ]

    def test_no_traces_no_output(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        assert emit_binary_fuzz_coverage(tmp_path, binary=binary) is None

    def test_no_binary_checklist_no_output(self, tmp_path):
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov", [0x1004])
        assert emit_binary_fuzz_coverage(tmp_path, binary=binary) is None

    def test_out_of_range_pcs_ignored(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov", [0x9999])
        assert emit_binary_fuzz_coverage(tmp_path, binary=binary) is None

    def test_dump_discovery(self, tmp_path):
        (tmp_path / "a.sancov").write_bytes(b"")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.drcov").write_bytes(b"")
        found = {p.name for p in find_pc_dumps(tmp_path)}
        assert found == {"a.sancov", "b.drcov"}

    def test_drcov_module_filtered_and_rebased(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        # minimal drcov: module table + one BB record for our module
        # (module-relative offset 0x1004 with base 0 = file-relative).
        header = (
            "DRCOV VERSION: 2\n"
            "Module Table: version 2, count 2\n"
            "Columns: id, base, end, entry, path\n"
            f"0, 0x0, 0x5000, 0x0, {binary}\n"
            "1, 0x7f0000000000, 0x7f0000100000, 0x0, /lib/other.so\n"
            "BB Table: 2 bbs\n"
        )
        import struct as _struct
        with open(tmp_path / "trace.drcov", "wb") as f:
            f.write(header.encode())
            f.write(_struct.pack("<IHH", 0x1004, 8, 0))   # ours
            f.write(_struct.pack("<IHH", 0x2004, 8, 1))   # other module
        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        assert out is not None
        doc = json.loads(out.read_text())
        funcs = doc["files"]["binary:t"]["functions"]
        # only OUR module's PC mapped; the other module's 0x2004
        # (which collides with 'quiet') must not leak in.
        assert set(funcs) == {"vuln"}


def _pie_checklist(tmp_path, n_funcs=24):
    """A denser checklist: base inference needs a vote quorum."""
    items = [
        {"name": f"fn{i:02d}", "kind": "function",
         "address": 0x1000 + i * 0x100, "size": 0x80}
        for i in range(n_funcs)
    ]
    cl = {
        "target_path": str(tmp_path / "t"),
        "target_kind": "binary",
        "files": [{
            "path": "binary:t", "language": "binary",
            "sha256": "ab" * 32, "items": items,
        }],
    }
    (tmp_path / "checklist.json").write_text(json.dumps(cl))
    return cl


class TestSancovPieBaseInference:
    BASE = 0x55555554000  # page-aligned runtime base

    def test_pie_trace_rebased_and_attributed(self, tmp_path):
        _pie_checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        # runtime-view PCs inside 12 distinct functions
        pcs = [self.BASE + 0x1000 + i * 0x100 + 0x10 for i in range(12)]
        _sancov(tmp_path / "run.sancov", pcs)

        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        assert out is not None
        doc = json.loads(out.read_text())
        funcs = doc["files"]["binary:t"]["functions"]
        assert len(funcs) == 12
        assert doc["meta"]["inferred_pie_bases"] == {
            "run.sancov": hex(self.BASE),
        }

    def test_per_trace_bases(self, tmp_path):
        """Two dumps from two processes with different ASLR bases."""
        _pie_checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        other = 0x7f0000000000
        _sancov(tmp_path / "a.sancov",
                [self.BASE + 0x1000 + i * 0x100 + 8 for i in range(10)])
        _sancov(tmp_path / "b.sancov",
                [other + 0x1000 + i * 0x100 + 8 for i in range(10, 20)])

        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        doc = json.loads(out.read_text())
        funcs = doc["files"]["binary:t"]["functions"]
        assert len(funcs) == 20
        assert doc["meta"]["inferred_pie_bases"] == {
            "a.sancov": hex(self.BASE), "b.sancov": hex(other),
        }

    def test_file_relative_trace_untouched(self, tmp_path):
        """Non-PIE (direct-view) PCs never get a base invented."""
        _pie_checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov",
                [0x1000 + i * 0x100 + 4 for i in range(8)])
        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        doc = json.loads(out.read_text())
        assert doc["meta"]["inferred_pie_bases"] == {}
        assert len(doc["files"]["binary:t"]["functions"]) == 8

    def test_no_quorum_contributes_nothing(self, tmp_path):
        """Too few PCs for a quorum: honest no-signal, no guessing."""
        _pie_checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov", [self.BASE + 0x1010,
                                          self.BASE + 0x1110])
        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        assert out is None  # nothing mapped, no record emitted

    def test_unaligned_delta_pins_neighbor_base_auditably(self, tmp_path):
        """A non-page-aligned delta cannot come from a real loader
        (mmap bases are page-aligned) — only from a forged or corrupt
        trace. Documented residual: on a REGULAR layout the aligned
        neighbor base validates and attribution shifts by one
        function. The defence is auditability, not refusal: the
        inferred base is recorded in meta, and attribution stays
        bounded by the checklist ranges."""
        _pie_checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        odd = self.BASE + 0x123  # unaligned true delta — forged trace
        _sancov(tmp_path / "run.sancov",
                [odd + 0x1000 + i * 0x100 + 8 for i in range(12)])
        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        assert out is not None
        doc = json.loads(out.read_text())
        # the aligned neighbor is what actually gets inferred — the
        # record must say so, so the shift is auditable
        assert doc["meta"]["inferred_pie_bases"] == {
            "run.sancov": hex(self.BASE),
        }
        assert len(doc["files"]["binary:t"]["functions"]) <= 12

    def test_partial_checklist_never_infers_intra_module_shift(
        self, tmp_path,
    ):
        """A file-relative dump whose PCs mostly fall OUTSIDE a
        partial checklist must not vote an intra-module shift into a
        "base" (that would re-attribute coverage to functions that
        never ran). The genuine in-range hits survive unshifted."""
        _pie_checklist(tmp_path)  # covers 0x1000..0x2800 only
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        pcs = [0x1000 + i * 0x100 + 8 for i in range(2)]      # 2 real hits
        pcs += [0x10000 + i * 0x340 + 4 for i in range(60)]   # module tail
        _sancov(tmp_path / "run.sancov", pcs)
        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        if out is None:
            return  # 2 direct hits below len//4 and no inference: fine
        doc = json.loads(out.read_text())
        assert doc["meta"]["inferred_pie_bases"] == {}
        funcs = set(doc["files"]["binary:t"]["functions"])
        assert funcs <= {"fn00", "fn01"}


class TestChecklistLoaderBounded:
    """checklist.json is read from the target-writable fuzz out dir —
    the same boundary the module's own trace caps defend. The loader
    must be byte-budgeted and shape-gated (a list-shaped file crashed
    the .get() walk)."""

    def test_list_shaped_checklist_returns_none(self, tmp_path):
        from packages.fuzzing.coverage_bridge import _load_binary_checklist

        (tmp_path / "checklist.json").write_text('["not", "a", "dict"]')
        assert _load_binary_checklist(tmp_path) is None

    def test_oversized_checklist_refused(self, tmp_path, monkeypatch):
        import packages.fuzzing.coverage_bridge as cb

        monkeypatch.setattr(cb, "MAX_CHECKLIST_BYTES", 64)
        (tmp_path / "checklist.json").write_text(
            '{"target_kind": "binary", "pad": "' + "x" * 256 + '"}')
        assert cb._load_binary_checklist(tmp_path) is None

    def test_valid_binary_checklist_still_loads(self, tmp_path):
        from packages.fuzzing.coverage_bridge import _load_binary_checklist

        (tmp_path / "checklist.json").write_text(
            '{"target_kind": "binary", "files": []}')
        cl = _load_binary_checklist(tmp_path)
        assert cl is not None and cl["target_kind"] == "binary"
