"""Adversarial battery for the ``core.binary.pe`` import /
delay-import / export walks.

Empirical attacks on the table walks, complementing the per-table
suites (``test_pe_imports`` / ``test_pe_exports``, whose builders
this file reuses):

  * seeded random byte-mutation fuzz over an import+export-rich
    image — 3 seeds x 10,000 mutations (30,000 total), header- and
    table-biased flips mixed with truncations, asserting the
    never-raises contract and a per-parse wall-clock bound
  * a differential no-fabrication probe: every extracted import /
    export / forwarder / DLL name must be a byte-substring of the
    crafted input — the walks may truncate or drop, but never
    invent bytes the file does not contain (the zero-fill rule
    supplies terminators, never name bytes)
  * u32-max declared counts and REAL cap boundaries (cap and
    cap + 1, both directions pinned) for export slots and import
    descriptors
  * self-referential name RVAs, a non-terminating thunk array
    filling its whole section, arrays aimed at headers
  * every hostile name in the rich image held to the render
    contract (``core.security.log_sanitisation``)
  * a wall-clock bound on the structurally-worst tables shape
    (descriptor cap + thunk budget + u32-max export claims)
"""

from __future__ import annotations

import random
import struct
import time

from core.binary import pe as pe_mod
from core.binary.pe import PeFacts, extract_pe_facts
from core.security.log_sanitisation import (
    escape_nonprintable,
    has_nonprintable,
)

from .test_pe_exports import build_export_section
from .test_pe_facts import PeSpec, Sec, build_pe
from .test_pe_imports import (
    DelayDll,
    ImpDll,
    RawThunk,
    build_delay_section,
    build_import_section,
)

_RDATA_CHARACTERISTICS = 0x40000040


def _rich_tables_image() -> bytes:
    """One image exercising every table-walk path: two import DLLs
    (hint/name + ordinal + raw-thunk shapes, one OFT=0 fallback),
    a v2 AND a legacy delay descriptor, exports with named /
    ordinal-only / forwarder / gap slots, hostile text in every
    name class, plus an overlay."""
    idata, imp_dir = build_import_section([
        ImpDll(name=b"KERNEL32.dll", entries=[
            (0x1F4, b"CreateFileW"), (0, b"Read\x1b[31mFile"), 42,
            RawThunk(0x8000_0000)]),
        ImpDll(name=b"EVIL\x07.dll", oft=False,
               entries=[(7, "bidi\u202efn".encode())]),
    ], va=0x3000)
    didat, delay_dir = build_delay_section([
        DelayDll(name=b"COMCTL32.dll", attributes=1,
                 entries=[(2, b"InitCommonControls"), 17]),
        DelayDll(name=b"OLD.dll", attributes=0),
    ], va=0x4000)
    edata, exp_dir = build_export_section(
        [0x1111, b"NTDLL.Rtl\x1b]0;Fwd", 0, 0x2222],
        [(b"alpha", 0), ("f\u202ewd".encode(), 1)],
        dll_name=b"RICH.dll", base=3, va=0x5000)
    return build_pe(PeSpec(
        dll_characteristics=0x4160,
        secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x200,
                vsize=0x2000),                     # raw/virtual skew
            Sec(name=b".idata", va=0x3000, data=idata,
                characteristics=_RDATA_CHARACTERISTICS),
            Sec(name=b".didat", va=0x4000, data=didat,
                characteristics=_RDATA_CHARACTERISTICS),
            Sec(name=b".edata", va=0x5000, data=edata,
                characteristics=_RDATA_CHARACTERISTICS),
        ],
        data_dirs={0: exp_dir, 1: imp_dir, 13: delay_dir},
        overlay=b"OVERLAY-BYTES" * 8,
    ))


def _collect_strings(facts: PeFacts) -> list[str]:
    """Every attacker-text string the table walks retained."""
    out: list[str] = []
    for dll in list(facts.imports) + list(facts.delay_imports):
        if dll.name:
            out.append(dll.name)
        out.extend(fn.name for fn in dll.functions if fn.name)
    if facts.exports is not None:
        exp = facts.exports
        if exp.dll_name:
            out.append(exp.dll_name)
        for sym in exp.named + exp.ordinal_only:
            if sym.name:
                out.append(sym.name)
            if sym.forwarder:
                out.append(sym.forwarder)
    return out


class TestMutationFuzz:
    def test_thirty_thousand_seeded_mutations_never_raise(
            self, tmp_path):
        """The never-raises contract under random damage, across
        THREE independent seeds (30,000 mutations total — every
        run replays the identical corpus). Flips are biased
        toward the headers and the table sections (the bytes
        every new walk consumes), mixed with truncations; each
        parse is individually time-bounded so no mutation can buy
        a pathological walk."""
        base = _rich_tables_image()
        p = tmp_path / "mut.exe"
        worst = 0.0
        for seed in (0x9E_FAC75B, 0x1B2B3C4D, 0x5EED0003):
            rng = random.Random(seed)
            for i in range(10_000):
                blob = bytearray(base)
                if i % 10 == 9:
                    blob = blob[:rng.randrange(1, len(blob))]
                for _ in range(rng.randint(1, 8)):
                    r = rng.random()
                    if r < 0.4:
                        pos = rng.randrange(min(0x400, len(blob)))
                    elif r < 0.8 and len(blob) > 0x400:
                        pos = rng.randrange(0x400, len(blob))
                    else:
                        pos = rng.randrange(len(blob))
                    blob[pos] = rng.randrange(256)
                p.write_bytes(bytes(blob))
                start = time.perf_counter()
                facts = extract_pe_facts(p)   # must never raise
                elapsed = time.perf_counter() - start
                worst = max(worst, elapsed)
                assert elapsed < 1.0, (
                    f"seed {seed:#x} mutation {i} took "
                    f"{elapsed:.3f}s — pathological walk")
                assert facts is None or isinstance(facts, PeFacts)
        assert worst < 1.0


class TestNoFabricatedReads:
    def test_every_name_is_a_byte_substring_of_the_input(
            self, tmp_path):
        """Differential probe on the pristine rich image: every
        retained name / forwarder decodes from bytes the file
        actually contains — the walks never materialise zero-fill
        or out-of-image bytes as text (the zero-fill rule may
        supply a TERMINATOR, never name bytes)."""
        blob = _rich_tables_image()
        p = tmp_path / "rich.exe"
        p.write_bytes(blob)
        facts = extract_pe_facts(p)
        assert facts is not None
        strings = _collect_strings(facts)
        # The rich image's walks are known-good: the probe must
        # actually see the full name population, not a degraded
        # remnant.
        assert len(strings) >= 10
        for text in strings:
            assert text.encode("utf-8") in blob, repr(text)

    def test_probe_holds_under_mutation(self, tmp_path):
        """The same probe over 2,000 seeded mutations: whatever a
        damaged table makes the walks retain, it is still made of
        input bytes. Names containing U+FFFD are skipped — the
        replacement character marks a lossy decode, so re-encoding
        cannot reproduce the raw bytes (decode fidelity, not
        fabrication)."""
        base = _rich_tables_image()
        rng = random.Random(0xD1FF_BEEF)
        p = tmp_path / "mutprobe.exe"
        checked = 0
        for _ in range(2_000):
            blob = bytearray(base)
            for _ in range(rng.randint(1, 6)):
                blob[rng.randrange(len(blob))] = rng.randrange(256)
            data = bytes(blob)
            p.write_bytes(data)
            facts = extract_pe_facts(p)
            if facts is None:
                continue
            for text in _collect_strings(facts):
                if not text or "\ufffd" in text:
                    continue
                assert text.encode("utf-8") in data, repr(text)
                checked += 1
        assert checked > 1_000     # the probe exercised real names


class TestRenderContractOnRichImage:
    def test_every_retained_name_renders_inert(self, tmp_path):
        """The rich image plants control bytes, an OSC sequence,
        a BEL and bidi overrides across DLL names, function names
        and a forwarder. Every retained string is data at rest and
        inert through the repo's render chokepoint."""
        p = tmp_path / "rich.exe"
        p.write_bytes(_rich_tables_image())
        facts = extract_pe_facts(p)
        assert facts is not None
        strings = _collect_strings(facts)
        hostile = [s for s in strings
                   if any(ord(c) < 0x20 or c == "\u202e"
                          for c in s)]
        assert len(hostile) >= 3      # the plants were retained
        for text in strings:
            assert not has_nonprintable(escape_nonprintable(text))


class TestRealCapBoundaries:
    def test_export_functions_at_the_real_cap(self, tmp_path):
        cap = pe_mod._MAX_EXPORT_FUNCTIONS
        p = tmp_path / "atcap.dll"
        p.write_bytes(_export_flood_image(cap))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.walked_function_count == cap
        assert "export_functions_capped" not in exp.caps_hit

    def test_export_functions_one_past_the_real_cap(self, tmp_path):
        cap = pe_mod._MAX_EXPORT_FUNCTIONS
        p = tmp_path / "pastcap.dll"
        p.write_bytes(_export_flood_image(cap + 1))
        start = time.perf_counter()
        facts = extract_pe_facts(p)
        elapsed = time.perf_counter() - start
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.declared_function_count == cap + 1
        assert exp.walked_function_count == cap
        assert "export_functions_capped" in exp.caps_hit
        assert elapsed < 2.0

    def test_import_thunks_per_dll_at_the_real_cap_boundary(
            self, tmp_path):
        """The per-DLL thunk cap at its REAL value, both
        directions — the record-shape bound must actually engage
        at 4096, not only at monkeypatched toy values (a lifted
        constant must fail this pin). Ordinal thunks keep the
        shape cheap; the whole-walk budget (16384) stays clear."""
        cap = pe_mod._MAX_IMPORT_THUNKS_PER_DLL
        p = tmp_path / "thunkat.exe"
        p.write_bytes(_import_image(
            [ImpDll(entries=[(i % 0xFFFF) + 1
                             for i in range(cap)])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports[0].thunk_count == cap
        assert "import_thunks_capped" not in facts.caps_hit

        q = tmp_path / "thunkpast.exe"
        q.write_bytes(_import_image(
            [ImpDll(entries=[(i % 0xFFFF) + 1
                             for i in range(cap + 1)])]))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert facts.imports[0].thunk_count == cap
        assert "import_thunks_capped" in facts.caps_hit

    def test_import_descriptors_at_the_real_cap_boundary(
            self, tmp_path):
        """The real descriptor cap, both directions: cap DLLs +
        terminator = complete; one more real descriptor = marked
        breach. (Each DLL walks one empty thunk array so the whole
        shape stays cheap.)"""
        cap = pe_mod._MAX_IMPORT_DESCRIPTORS
        at_cap = [ImpDll(name=b"d%04d.dll" % i, entries=[])
                  for i in range(cap)]
        p = tmp_path / "descat.exe"
        p.write_bytes(_import_image(at_cap))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.imports) == cap
        assert "import_descriptors_capped" not in facts.caps_hit

        past = at_cap + [ImpDll(name=b"one.more", entries=[])]
        q = tmp_path / "descpast.exe"
        q.write_bytes(_import_image(past))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert len(facts.imports) == cap
        assert "import_descriptors_capped" in facts.caps_hit


class TestResolverIndexEquivalence:
    def test_index_matches_reference_linear_scan(self):
        """The resolver's segment index must be observationally
        identical to the reference first-match-in-table-order
        linear scan (module invariant b) over a randomized layout
        of overlapping, gapped, skewed and zero-VirtualSize
        sections — every RVA in range plus every span boundary
        +/- 1."""
        rng = random.Random(0x5EC710)
        secs = []
        for i in range(64):
            va = rng.randrange(0x1000, 0x40000, 0x10)
            vsize = rng.choice([0, rng.randrange(1, 0x3000)])
            raw = rng.randrange(0, 0x2000)
            secs.append(pe_mod.PeSection(
                name=f".r{i}", virtual_address=va,
                virtual_size=vsize, raw_size=raw,
                raw_offset=0x400 + i * 0x100, characteristics=0))
        r = pe_mod._RvaResolver(secs, 0x400)

        def reference(rva: int):
            if rva < 0:
                return None
            for sec in secs:                 # table order
                extent = sec.virtual_size or sec.raw_size
                if extent <= 0:
                    continue
                if sec.virtual_address <= rva \
                        < sec.virtual_address + extent:
                    delta = rva - sec.virtual_address
                    raw_avail = (sec.raw_size - delta
                                 if delta < sec.raw_size else 0)
                    return (sec.raw_offset + delta
                            if raw_avail > 0 else None,
                            raw_avail, extent - delta)
            if rva < 0x400:
                return (rva, 0x400 - rva, 0x400 - rva)
            return None

        probes = set(range(0, 0x44000, 7))
        for sec in secs:
            extent = sec.virtual_size or sec.raw_size
            for p in (sec.virtual_address,
                      sec.virtual_address + extent):
                probes.update((p - 1, p, p + 1))
        for rva in probes:
            got = r.resolve(rva)
            want = reference(rva)
            got_t = (None if got is None else
                     (got.file_offset, got.raw_available,
                      got.virtual_available))
            assert got_t == want, hex(rva)


class TestSectionCountReadProduct:
    def _amp_export_image(self, n_decoys: int) -> bytes:
        """A max-shape export table (every name and every function
        slot aimed at one shared over-cap blob) behind
        ``n_decoys`` tiny decoy sections."""
        cap_f = pe_mod._MAX_EXPORT_FUNCTIONS
        cap_n = pe_mod._MAX_EXPORT_NAMES
        va = 0x200000
        body = bytearray(40)

        def add(data: bytes) -> int:
            rva = va + len(body)
            body.extend(data)
            while len(body) % 4:
                body.append(0)
            return rva

        blob = add(b"A" * (pe_mod._MAX_TABLE_NAME_BYTES + 64))
        names_rva = add(struct.pack("<%dI" % cap_n,
                                    *([blob] * cap_n)))
        ords_rva = add(struct.pack("<%dH" % cap_n,
                                   *range(cap_n)))
        funcs_rva = add(struct.pack("<%dI" % cap_f,
                                    *([blob] * cap_f)))
        dllname = add(b"AMP.dll\x00")
        struct.pack_into("<IIHHIIIIIII", body, 0, 0, 0, 0, 0,
                         dllname, 1, cap_f, cap_n, funcs_rva,
                         names_rva, ords_rva)
        secs = [Sec(name=b"d%06x" % i, va=0x2000 + i, data=b"",
                    vsize=1) for i in range(n_decoys)]
        secs.append(Sec(name=b".edata", va=va, data=bytes(body),
                        characteristics=_RDATA_CHARACTERISTICS))
        # size_of_headers must cover the decoy-scale section table
        # (the shape is the SECTION COUNT, not a clobbered table).
        return build_pe(PeSpec(secs=secs,
                               data_dirs={0: (va, len(body))},
                               size_of_headers=0x29000))

    def test_forwarder_heavy_export_table_parses_fast(
            self, tmp_path):
        """Every function slot forwarder-classified + every name
        aimed at one shared over-cap blob: the timing bound here is
        carried by the resolver's segment index (each read is
        bisect-cheap even at this read count) — the companion
        read-COUNT pin (TestBudgetReadStop) is what proves the
        spent-budget read-stop engages; a timing bound alone cannot
        tell a live stop from a fast inert one."""
        p = tmp_path / "fwdheavy.dll"
        p.write_bytes(self._amp_export_image(0))
        start = time.perf_counter()
        facts = extract_pe_facts(p)
        elapsed = time.perf_counter() - start
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.walked_name_count == pe_mod._MAX_EXPORT_NAMES
        assert "export_name_budget_exhausted" in exp.caps_hit
        assert elapsed < 1.0, f"forwarder-heavy took {elapsed:.2f}s"

    def test_max_sections_times_max_reads_parses_fast(
            self, tmp_path):
        """The sections x reads product (the resolver-scan
        regression): _MAX_SECTIONS - 1 decoy sections under the
        same max-shape table. Served from the segment index this
        is bisect-cheap; a per-read linear scan makes it ~100k
        reads x 4095 sections — tens of seconds from a sub-MB
        file."""
        p = tmp_path / "amp4k.dll"
        p.write_bytes(self._amp_export_image(
            pe_mod._MAX_SECTIONS - 1))
        start = time.perf_counter()
        facts = extract_pe_facts(p)
        elapsed = time.perf_counter() - start
        assert facts is not None
        assert len(facts.sections) == pe_mod._MAX_SECTIONS
        exp = facts.exports
        assert exp is not None
        assert exp.walked_function_count == \
            pe_mod._MAX_EXPORT_FUNCTIONS
        assert elapsed < 3.0, f"amp4k took {elapsed:.2f}s"
        # The retention backstop engaged AT ITS REAL VALUE: the
        # record stopped growing at the budget (within one
        # per-name cap of it), and stays bounded in absolute
        # terms whatever the constant is set to.
        retained = sum(
            len((s.name or "").encode())
            + len((s.forwarder or "").encode())
            for s in exp.named + exp.ordinal_only)
        assert "export_name_budget_exhausted" in exp.caps_hit
        assert retained <= pe_mod._MAX_TABLE_NAME_TOTAL_BYTES
        assert retained > (pe_mod._MAX_TABLE_NAME_TOTAL_BYTES
                           - 2 * pe_mod._MAX_TABLE_NAME_BYTES)
        assert retained < 9 * 1024 * 1024   # absolute record pin


class TestBudgetReadStop:
    def test_reads_stop_within_one_stride_of_the_overdraw(
            self, tmp_path, monkeypatch):
        """The spent-budget read-stop must be REAL, pinned by read
        COUNT — a timing bound cannot tell a live stop from an
        inert one that the resolver index keeps fast. On the
        forwarder-heavy shape the 8 MiB budget drains in
        4096-byte name + forwarder strides (~1k rows) and then
        OVERDRAWS mid-walk (the 8-byte dll name offsets the
        stride); ordered-fill zeroes the remainder on that first
        overdraw, so every later row must issue NO reads. Live
        stop: ~2.1k chokepoint reads. Inert stop (budget parked
        one stride short of zero forever): ~66k."""
        counts = {"reads": 0}
        real_read = pe_mod._RvaResolver.read

        def counting_read(resolver_self, f, rva, length):
            counts["reads"] += 1
            return real_read(resolver_self, f, rva, length)

        monkeypatch.setattr(pe_mod._RvaResolver, "read",
                            counting_read)
        p = tmp_path / "overdraw.dll"
        p.write_bytes(
            TestSectionCountReadProduct()._amp_export_image(0))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert "export_name_budget_exhausted" in exp.caps_hit
        # All 32768 name rows walked (counts stay honest) while
        # reads stopped within one stride of the overdraw: ~1024
        # pre-overdraw rows x 2 reads each, plus the handful of
        # structural reads (directory, dll name, 3 bulk arrays).
        assert exp.walked_name_count == pe_mod._MAX_EXPORT_NAMES
        assert counts["reads"] >= 2_048          # pre-stop work real
        assert counts["reads"] < 3_000, counts["reads"]


class TestSelfReferentialTables:
    def test_import_name_rvas_into_the_tables_themselves(
            self, tmp_path):
        """DLL-name and thunk RVAs aimed back into the descriptor
        array: bounded data-shaped noise, never a loop or a crash
        — the walks have no state that revisiting an RVA can
        corrupt."""
        idata, (va, size) = build_import_section(
            [ImpDll(entries=[RawThunk(0x3000),
                             RawThunk(0x3000 + 4)])], va=0x3000)
        arr = bytearray(idata)
        struct.pack_into("<I", arr, 12, va)    # Name → descriptor[0]
        p = tmp_path / "ouroboros.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".idata", va=va, data=bytes(arr),
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={1: (va, size)})))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.imports) == 1
        assert facts.imports[0].thunk_count == 2
        for text in _collect_strings(facts):
            assert len(text.encode("utf-8", "replace")) <= \
                3 * pe_mod._MAX_TABLE_NAME_BYTES


class TestNonTerminatingThunkArray:
    def test_array_filling_its_whole_section_is_bounded(
            self, tmp_path):
        """A thunk array of nothing but nonzero slots filling its
        section's raw AND virtual extent exactly: the walk stops
        at the extent (or the cap) with a marker — bounded time,
        bounded record, no exception."""
        n = 2_048
        idata = bytearray(40)      # 1 descriptor + terminator slot
        struct.pack_into("<IIIII", idata, 0, 0x3000 + 48, 0, 0,
                         0x3000 + 40, 0x3000 + 48)
        idata[40:46] = b"n.dll\x00"
        idata += b"\x00" * (48 - len(idata))
        flag = 0x8000_0000_0000_0000
        idata += b"".join((flag | (i % 0xFFFF or 1)).to_bytes(
            8, "little") for i in range(1, n + 1))
        p = tmp_path / "endless.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".idata", va=0x3000, data=bytes(idata),
                vsize=len(idata),
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={1: (0x3000, 40)})))
        start = time.perf_counter()
        facts = extract_pe_facts(p)
        elapsed = time.perf_counter() - start
        assert facts is not None
        dll = facts.imports[0]
        assert dll.thunk_count == n
        assert "import_thunks_unterminated" in dll.caps_hit
        assert elapsed < 1.0


class TestWallClockWorstShape:
    def test_maxed_tables_parse_fast(self, tmp_path):
        """The structurally-worst tables shape: hundreds of import
        DLLs each claiming dozens of hint/name thunks (driving the
        whole-walk thunk budget to exhaustion), plus u32-max
        export claims over a large virtual extent. The parse must
        stay interactive-fast — the two-direction regression bound
        for anyone raising the caps or budgets."""
        dlls = [ImpDll(name=b"m%03d.dll" % i,
                       entries=[(j, b"fn%02d" % j)
                                for j in range(64)])
                for i in range(300)]
        idata, imp_dir = build_import_section(dlls, va=0x3000)
        # .edata sits ABOVE the ~467 KB import extent so the two
        # virtual ranges never overlap (first-match resolution
        # would otherwise hand .idata bytes to the export walk).
        edata, _ = build_export_section(
            [0x1111], [(b"n", 0)], va=0x90000,
            n_funcs_override=0xFFFF_FFFF,
            n_names_override=0xFFFF_FFFF)
        p = tmp_path / "worst.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".idata", va=0x3000, data=idata,
                characteristics=_RDATA_CHARACTERISTICS),
            Sec(name=b".edata", va=0x90000, data=edata,
                vsize=0x40000,
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={0: (0x90000, len(edata)), 1: imp_dir})))
        start = time.perf_counter()
        facts = extract_pe_facts(p)
        elapsed = time.perf_counter() - start
        assert facts is not None
        # The budgets engaged: the thunk budget stops the import
        # walk mid-corpus; the export caps stop the u32-max claim.
        walked = sum(d.thunk_count for d in facts.imports)
        assert walked == pe_mod._MAX_IMPORT_THUNKS_TOTAL
        assert "import_thunk_budget_exhausted" in facts.caps_hit
        exp = facts.exports
        assert exp is not None
        assert "export_functions_capped" in exp.caps_hit
        assert elapsed < 2.0, f"worst shape took {elapsed:.3f}s"


def _export_flood_image(n_slots: int) -> bytes:
    """An export table with ``n_slots`` real (nonzero, non-
    forwarder) function slots and no names."""
    slots = [0x1000 + 4 * i for i in range(n_slots)]
    edata, exp_dir = build_export_section(slots, [], va=0x5000)
    return build_pe(PeSpec(secs=[
        Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
        Sec(name=b".edata", va=0x5000, data=edata,
            characteristics=_RDATA_CHARACTERISTICS),
    ], data_dirs={0: exp_dir}))


def _import_image(dlls: list[ImpDll]) -> bytes:
    idata, imp_dir = build_import_section(dlls, va=0x3000)
    return build_pe(PeSpec(secs=[
        Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
        Sec(name=b".idata", va=0x3000, data=idata,
            characteristics=_RDATA_CHARACTERISTICS),
    ], data_dirs={1: imp_dir}))
