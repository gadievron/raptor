"""Tests for core.audit.disasm_xcheck — verdict-time disassembly
cross-check for binary items.

Unit tests run everywhere (synthetic objdump text, no toolchain);
the compiled-fixture tests assemble a tiny ELF with cc and skip with
the missing tool named when the environment lacks cc/nm/objdump or
is not x86-64.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

import core.audit.disasm_xcheck as dx
from core.audit.disasm_xcheck import (
    TRIGGER_DROPPED_ARGUMENT,
    TRIGGER_IMMEDIATE_WIDTH,
    TRIGGER_REGISTER_LIVENESS,
    TRIGGER_SIBLING_ARGUMENT,
    classify_trigger,
    run_disasm_xcheck,
)


@pytest.fixture(autouse=True)
def _fresh_channel_state():
    dx._reset_for_tests()
    yield
    dx._reset_for_tests()


# ---------------------------------------------------------------------------
# Trigger taxonomy (bounded keyword+structure match)
# ---------------------------------------------------------------------------


class TestTriggerTaxonomy:
    def test_dropped_count_argument_with_register(self):
        t = classify_trigger(
            "the decompilation shows the count argument is missing at "
            "the call to validate_len — r8d is never loaded",
        )
        assert t is not None
        assert t.kind == TRIGGER_DROPPED_ARGUMENT
        assert t.register == "r8"
        assert "validate_len" in t.callees

    def test_ordinal_argument_maps_to_sysv_register(self):
        t = classify_trigger(
            "the fifth argument is never passed to check_size",
        )
        assert t is not None
        assert t.kind == TRIGGER_DROPPED_ARGUMENT
        assert t.register == "r8"
        assert "check_size" in t.callees

    def test_register_liveness_claim(self):
        t = classify_trigger(
            "rdx is not initialized before the indirect call",
        )
        assert t is not None
        assert t.kind == TRIGGER_REGISTER_LIVENESS
        assert t.register == "rdx"

    def test_sibling_argument_claim_binds_callee_not_register(self):
        # The live journal-row shape: register-unbound count-argument
        # claim with a tool-minted callee name in prose.
        t = classify_trigger(
            "the record array pointer at offset 0x2a is validated by "
            "FUN_00512340 for only a single 6-byte element (no count "
            "argument, unlike sibling calls that pass one)",
            function_name="FUN_00234560",
        )
        assert t is not None
        assert t.kind == TRIGGER_SIBLING_ARGUMENT
        assert t.register is None
        assert "FUN_00512340" in t.callees

    def test_sibling_argument_requires_a_callee(self):
        assert classify_trigger(
            "no count argument is passed",
        ) is None

    def test_width_claim_with_register(self):
        t = classify_trigger(
            "only the low 4 bytes of rax are checked before use",
        )
        assert t is not None
        assert t.kind == TRIGGER_IMMEDIATE_WIDTH
        assert t.register == "rax"
        assert t.claimed_width == 4

    def test_width_claim_in_bits(self):
        t = classify_trigger("only 32 bits of the header are validated")
        assert t is not None
        assert t.claimed_width == 4

    def test_plain_overflow_hypothesis_never_triggers(self):
        assert classify_trigger(
            "buffer overflow when copying attacker data into a stack "
            "buffer without a bounds check",
        ) is None

    def test_source_style_hypothesis_never_triggers(self):
        assert classify_trigger(
            "strcpy(dst, src) called with unvalidated src length; the "
            "caller does not check the return value",
        ) is None

    def test_argument_claim_without_any_binding_never_triggers(self):
        # "argument missing" but no register, no ordinal, no callee.
        assert classify_trigger(
            "an argument appears to be missing from the call",
        ) is None

    def test_empty_and_none_never_trigger(self):
        assert classify_trigger("") is None
        assert classify_trigger(None) is None  # type: ignore[arg-type]

    def test_hypothesis_truncated_at_cap_both_directions(self):
        pad = "x" * (dx.MAX_HYPOTHESIS_CHARS + 100)
        # Register named beyond the cap: not bound → no trigger.
        assert classify_trigger(
            pad + " the count argument is missing, r8d never loaded",
        ) is None
        # Same claim inside the cap: triggers.
        inside = (
            "the count argument is missing at the call to f, "
            "r8d is never loaded "
        )
        assert classify_trigger(
            inside + "y" * (dx.MAX_HYPOTHESIS_CHARS - len(inside) - 10),
        ) is not None

    def test_hostile_long_text_is_linear_enough(self):
        hostile = ("argument " * 200 + "\x1b[31m" + "a( " * 200)[
            : dx.MAX_HYPOTHESIS_CHARS + 500]
        classify_trigger(hostile)  # must simply return


class TestRegisterBindingDiscipline:
    def test_bare_legacy_register_names_do_not_bind_from_prose(self):
        assert classify_trigger(
            "the si argument is missing from the call to parse",
        ) is None

    def test_rsp_rbp_spellings_never_bind(self):
        # Frame/stack registers are never SysV arguments; the prose
        # collision ("the esp argument", "spl") must not mint a claim.
        assert classify_trigger(
            "the esp argument is missing from the call to parse",
        ) is None
        assert classify_trigger(
            "the spl argument is never set before the call to parse",
        ) is None

    def test_multiple_distinct_families_refuse_binding(self):
        # Quoted attacker prose steering: rdi named first, claim about
        # rdx — first-match binding would pick rdi (always written);
        # the discipline refuses instead of guessing.
        assert classify_trigger(
            'the code logs "rdi validated ok" and then rdx is never '
            "set before the call to memcpy",
        ) is None

    def test_ordinal_explicit_conflict_refuses(self):
        assert classify_trigger(
            "the fifth argument is never passed to check_size, "
            "spilled from rcx",
        ) is None
        assert classify_trigger(
            "rcx is copied first; the fifth argument is never passed "
            "to check_size",
        ) is None

    def test_same_family_spellings_still_bind(self):
        t = classify_trigger(
            "only 4 bytes of the length in edx are validated before "
            "the call to process; the upper half of rdx is never "
            "bounds-checked",
        )
        assert t is not None
        assert t.register == "rdx"

    def test_uppercase_spelling_binds(self):
        t = classify_trigger("R8D is never loaded before the call")
        assert t is not None
        assert t.register == "r8"

    def test_arg_number_shape_binds(self):
        t = classify_trigger("arg 5 is never passed to check_size")
        assert t is not None
        assert t.register == "r8"


class TestCalleeExtraction:
    def test_validated_by_shape(self):
        t = classify_trigger(
            "r8d is never set; the buffer is validated by "
            "check_bounds before the call",
        )
        assert t is not None
        assert "check_bounds" in t.callees

    def test_tool_minted_names_are_callees_anywhere_in_prose(self):
        t = classify_trigger(
            "no count argument reaches FUN_00401234 here",
            function_name="FUN_00405678",
        )
        assert t is not None
        assert t.kind == TRIGGER_SIBLING_ARGUMENT
        assert "FUN_00401234" in t.callees

    def test_own_name_is_not_a_callee(self):
        t = classify_trigger(
            "no count argument reaches FUN_00401234 here",
            function_name="FUN_00401234",
        )
        assert t is None  # only callee candidate was the item itself


# ---------------------------------------------------------------------------
# Predicate units (synthetic instruction windows)
# ---------------------------------------------------------------------------


def _insn(addr: int, mnem: str, ops: str = "") -> dx._Insn:
    return dx._Insn(address=addr, mnemonic=mnem, operands=ops)


class TestWriteKind:
    def test_full_width_plain_writes_are_strong(self):
        members = dx._DISASM_FAMILY_MEMBERS["r8"]
        assert dx._write_kind(_insn(1, "mov", "r8d,0x5"), members) \
            == dx.WRITE_KIND_STRONG
        assert dx._write_kind(_insn(1, "xor", "r8,r8"), members) \
            == dx.WRITE_KIND_STRONG
        assert dx._write_kind(_insn(1, "movzx", "r8d,ax"), members) \
            == dx.WRITE_KIND_STRONG

    def test_sub_width_aliases_are_weak(self):
        # r8b/r8w leave the upper bits stale — never refute-grade.
        members = dx._DISASM_FAMILY_MEMBERS["r8"]
        assert dx._write_kind(_insn(1, "mov", "r8b,0x1"), members) \
            == dx.WRITE_KIND_WEAK
        assert dx._write_kind(_insn(1, "mov", "r8w,ax"), members) \
            == dx.WRITE_KIND_WEAK

    def test_conditional_writes_are_weak(self):
        members = dx._DISASM_FAMILY_MEMBERS["r8"]
        assert dx._write_kind(_insn(1, "cmovne", "r8,rax"), members) \
            == dx.WRITE_KIND_WEAK
        members_a = dx._DISASM_FAMILY_MEMBERS["rax"]
        assert dx._write_kind(_insn(1, "setne", "al"), members_a) \
            == dx.WRITE_KIND_WEAK

    def test_reads_and_foreign_mnemonics_are_none(self):
        members = dx._DISASM_FAMILY_MEMBERS["r8"]
        assert dx._write_kind(_insn(1, "cmp", "r8d,0x5"), members) is None
        assert dx._write_kind(_insn(1, "push", "r8"), members) is None
        assert dx._write_kind(_insn(1, "mov", "eax,r8d"), members) is None
        # Unknown mnemonic → None in BOTH lanes (fail-safe).
        assert dx._write_kind(
            _insn(1, "vmovd", "r8d,xmm0"), members,
        ) is None

    def test_xchg_writes_both_operands(self):
        members = dx._DISASM_FAMILY_MEMBERS["r8"]
        assert dx._write_kind(_insn(1, "xchg", "rax,r8"), members) \
            == dx.WRITE_KIND_STRONG


class TestSiteAnalysis:
    """Refute-grade classification over synthetic windows."""

    MEMBERS = None

    def setup_method(self):
        self.members = dx._DISASM_FAMILY_MEMBERS["r8"]

    def _analyze(self, insns, call_index, head=True):
        insns = tuple(insns)
        reach = dx._entry_reachable(insns) if head else None
        return dx._analyze_site(
            insns, call_index, self.members,
            dx._branch_targets(insns), reach,
        )

    def test_branch_free_write_is_strong(self):
        insns = (
            _insn(0x10, "mov", "r8d,0x5"),
            _insn(0x16, "call", "40 <f>"),
        )
        a = self._analyze(insns, 1)
        assert a.strong and a.strong_kind == "branch-free"

    def test_conditional_skip_shape_is_weak(self):
        # P1: je lands between write and call — the call is reachable
        # without the write; refute-grade denied.
        insns = (
            _insn(0x10, "test", "rdi,rdi"),
            _insn(0x13, "je", "1b <f+0xb>"),
            _insn(0x15, "mov", "r8d,0x64"),
            _insn(0x1B, "call", "40 <p>"),
        )
        a = self._analyze(insns, 3)
        assert not a.strong
        assert a.weak_write

    def test_unreachable_decoy_shape_is_weak(self):
        # P7: jmp target between the linear decoy write and the call.
        insns = (
            _insn(0x10, "jmp", "18 <f+0x8>"),
            _insn(0x12, "mov", "r8d,0x5"),
            _insn(0x18, "call", "40 <p>"),
        )
        a = self._analyze(insns, 2)
        assert not a.strong
        assert a.weak_write

    def test_ret_between_write_and_call_denies_branch_free(self):
        insns = (
            _insn(0x10, "mov", "r8d,0x5"),
            _insn(0x16, "ret", ""),
            _insn(0x17, "call", "40 <p>"),
        )
        a = self._analyze(insns, 2, head=False)
        assert not a.strong

    def test_entry_dominating_write_is_strong(self):
        # The field-observed decompiler-artifact shape: write at
        # function entry, then a
        # branch over an early-out ret, then the call.
        insns = (
            _insn(0x00, "endbr64", ""),
            _insn(0x04, "movzx", "r8d,WORD PTR [rax+0x28]"),
            _insn(0x09, "test", "r8w,r8w"),
            _insn(0x0D, "jne", "20 <f+0x20>"),
            _insn(0x0F, "mov", "eax,0x1"),
            _insn(0x14, "ret", ""),
            _insn(0x20, "mov", "rsi,QWORD PTR [rdi+0x20]"),
            _insn(0x24, "call", "99 <v>"),
        )
        a = self._analyze(insns, 7)
        assert a.strong and a.strong_kind == "entry-dominating"

    def test_entry_domination_requires_window_head_at_entry(self):
        insns = (
            _insn(0x00, "movzx", "r8d,ax"),
            _insn(0x04, "jne", "20 <f>"),
            _insn(0x08, "ret", ""),
            _insn(0x09, "call", "99 <v>"),
        )
        a = self._analyze(insns, 3, head=False)
        assert not a.strong

    def test_intervening_call_disqualifies_entry_domination(self):
        # P10 economics: a helper call between the entry write and
        # the examined call clobbers caller-saved registers.
        insns = (
            _insn(0x00, "mov", "r8d,0x1"),
            _insn(0x06, "call", "50 <helper>"),
            _insn(0x0B, "call", "99 <v>"),
        )
        a = self._analyze(insns, 2)
        assert not a.strong

    def test_ret_ending_entry_region_severs_domination(self):
        # Entry write, then RET: the call below is reachable only
        # from OUTSIDE the entry path — the write dominates nothing
        # that matters.
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "ret", ""),
            _insn(0x07, "call", "99 <p>"),
        )
        a = self._analyze(insns, 2)
        assert not a.strong
        assert a.weak_write

    def test_jmp_past_call_severs_domination(self):
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "jmp", "d <f+0xd>"),
            _insn(0x08, "call", "99 <p>"),
            _insn(0x0D, "ret", ""),
        )
        a = self._analyze(insns, 2)
        assert not a.strong
        assert a.weak_write

    def test_conditional_branch_keeps_domination(self):
        # The sound control: a conditional branch whose target is
        # between write and call — every in-window path still passes
        # the entry write, and the call IS entry-reachable.
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "test", "rdi,rdi"),
            _insn(0x09, "je", "c <f+0xc>"),
            _insn(0x0B, "nop", ""),
            _insn(0x0C, "call", "99 <p>"),
        )
        a = self._analyze(insns, 4)
        assert a.strong and a.strong_kind == "entry-dominating"

    def test_entry_reachable_walk(self):
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "ret", ""),
            _insn(0x07, "call", "99 <p>"),
            _insn(0x0C, "ret", ""),
        )
        reach = dx._entry_reachable(insns)
        assert 0 in reach and 1 in reach
        assert 2 not in reach and 3 not in reach

    def test_lookback_cap_both_directions(self):
        # Write one instruction beyond the cap → not found AND the
        # capped walk refuses completeness; within the cap → strong.
        beyond = [_insn(0x1, "mov", "r8d,0x5")] + [
            _insn(i + 2, "nop") for i in range(dx.LOOKBACK_INSTRUCTIONS)
        ] + [_insn(0x999, "call", "40 <f>")]
        a = self._analyze(tuple(beyond), len(beyond) - 1, head=False)
        assert not a.strong and not a.weak_write
        assert not a.unwritten_complete

        within = [_insn(0x1, "mov", "r8d,0x5")] + [
            _insn(i + 2, "nop")
            for i in range(dx.LOOKBACK_INSTRUCTIONS - 2)
        ] + [_insn(0x999, "call", "40 <f>")]
        a2 = self._analyze(tuple(within), len(within) - 1, head=False)
        assert a2.strong

    def test_previous_call_bounds_the_segment(self):
        insns = (
            _insn(0x1, "mov", "r8d,0x5"),
            _insn(0x2, "call", "50 <g>"),
            _insn(0x3, "nop"),
            _insn(0x4, "call", "99 <f>"),
        )
        a = self._analyze(insns, 3, head=False)
        assert not a.strong
        assert a.unwritten_complete  # walked to the previous call


class TestUnresolvedJumpPoison:
    """In-window indirect-jump targets: a jump-table dispatch's landing
    site is invisible to ``_branch_targets``, and on a non-entry-anchored
    window (``entry_reach`` None) the targets set was the branch-free
    leg's ONLY reachability screen — so a strong write graded across the
    dispatch and a TRUE "not set on the dispatched path" claim was
    demoted. Pins both directions: unresolved jumps poison branch-free
    grade window-wide; resolved out-of-window jumps and entry-dominating
    writes are unaffected."""

    def setup_method(self):
        self.members = dx._DISASM_FAMILY_MEMBERS["r8"]

    def _analyze(self, insns, call_index, head=True):
        insns = tuple(insns)
        reach = dx._entry_reachable(insns) if head else None
        return dx._analyze_site(
            insns, call_index, self.members,
            dx._branch_targets(insns), reach,
        )

    def test_direct_jump_operands_are_resolved(self):
        assert not dx._has_unresolved_jump((
            _insn(0x10, "jmp", "18 <f+0x8>"),
            _insn(0x12, "je", "1b <f+0xb>"),
            _insn(0x14, "loop", "10 <f>"),
        ))

    def test_indirect_register_jump_is_unresolved(self):
        assert dx._has_unresolved_jump((_insn(0x10, "jmp", "rax"),))

    def test_indirect_memory_jump_is_unresolved(self):
        assert dx._has_unresolved_jump((
            _insn(0x10, "jmp", "QWORD PTR [rax*8+0x404060]"),
        ))

    def test_non_jump_indirection_is_not_a_jump(self):
        # Indirect CALLS fall through (callees return) and ret/traps
        # have no landing site — only jumps/branches need targets.
        assert not dx._has_unresolved_jump((
            _insn(0x10, "call", "rax"),
            _insn(0x12, "ret", ""),
            _insn(0x13, "ud2", ""),
        ))

    def test_indirect_jump_elsewhere_denies_branch_free_non_entry(self):
        # THE residual shape: non-entry-anchored window, indirect
        # dispatch earlier in the window — its landing site could lie
        # between the write and the call, so refute grade is refused
        # (the write still blocks corroboration: honest record).
        insns = (
            _insn(0x12, "jmp", "rax"),
            _insn(0x14, "mov", "r8d,0x5"),
            _insn(0x1A, "nop", ""),
            _insn(0x1B, "call", "40 <p>"),
        )
        a = self._analyze(insns, 3, head=False)
        assert not a.strong
        assert a.weak_write

    def test_indirect_memory_jump_also_denies_branch_free(self):
        insns = (
            _insn(0x12, "jmp", "QWORD PTR [rax*8+0x404060]"),
            _insn(0x1A, "mov", "r8d,0x5"),
            _insn(0x20, "call", "40 <p>"),
        )
        a = self._analyze(insns, 2, head=False)
        assert not a.strong
        assert a.weak_write

    def test_direct_out_of_window_jump_keeps_branch_free(self):
        # Boundary contract, other direction: a DIRECT jump that
        # leaves the window has a KNOWN target that cannot land
        # between write and call — refute grade stands.
        insns = (
            _insn(0x12, "jmp", "999 <other>"),
            _insn(0x14, "mov", "r8d,0x5"),
            _insn(0x1A, "call", "40 <p>"),
        )
        a = self._analyze(insns, 2, head=False)
        assert a.strong and a.strong_kind == "branch-free"

    def test_indirect_jump_keeps_entry_domination(self):
        # Scope pin: the poison is branch-free-only. An entry-region
        # write precedes every control transfer, so any in-window
        # path — the indirect dispatch included — passes it first
        # (external entries stay the documented residual).
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "test", "rdi,rdi"),
            _insn(0x09, "je", "e <f+0xe>"),
            _insn(0x0B, "jmp", "rax"),
            _insn(0x0E, "call", "99 <p>"),
        )
        a = self._analyze(insns, 4)
        assert a.strong and a.strong_kind == "entry-dominating"

    def test_strong_profile_excludes_poisoned_families(self):
        # The sibling lane's claimed-site (strong_only) detector
        # inherits the poison: families written only across an
        # indirect dispatch stay out of the refute-grade profile,
        # while the over-approximating sibling detector still counts
        # them (more shared registers = refutation strictly harder,
        # the safe direction).
        insns = (
            _insn(0x12, "jmp", "rax"),
            _insn(0x14, "mov", "r8d,0x5"),
            _insn(0x18, "mov", "edi,0x2"),
            _insn(0x1C, "call", "40 <p>"),
        )
        strong, _ = dx._site_arg_profile(
            insns, 3, dx._branch_targets(insns), None,
            strong_only=True,
        )
        assert "r8" not in strong and "rdi" not in strong
        weak, _ = dx._site_arg_profile(
            insns, 3, dx._branch_targets(insns), None,
            strong_only=False,
        )
        assert {"r8", "rdi"} <= weak


class TestXbeginBranchVocabulary:
    """``xbegin`` is a control transfer: a transaction abort jumps to
    its operand (the abort-handler landing site). The jump screens
    matched only ``j*``/``loop*``, so an xbegin whose abort target lay
    between a write and the call graded branch-free strong on BOTH
    anchorings — a false refute for a claim that is true on the abort
    path. Pins: a decodable abort target enters the branch-target set
    (denial between write and call), an undecodable operand poisons,
    the entry region ends at the xbegin, and ``xabort``/``xend`` do
    not over-poison."""

    def setup_method(self):
        self.members = dx._DISASM_FAMILY_MEMBERS["r8"]

    def _analyze(self, insns, call_index, head=True):
        insns = tuple(insns)
        reach = dx._entry_reachable(insns) if head else None
        return dx._analyze_site(
            insns, call_index, self.members,
            dx._branch_targets(insns), reach,
        )

    def test_xbegin_target_enters_branch_targets(self):
        # A decodable abort target is a branch target like any jcc's;
        # direct jumps keep contributing theirs (unchanged direction).
        targets = dx._branch_targets((
            _insn(0x10, "xbegin", "1d <f+0xd>"),
            _insn(0x16, "jmp", "24 <f+0x14>"),
        ))
        assert targets == frozenset({0x1D, 0x24})

    def test_xbegin_with_decodable_target_is_resolved(self):
        assert not dx._has_unresolved_jump((
            _insn(0x10, "xbegin", "1d <f+0xd>"),
        ))

    def test_xbegin_with_undecodable_operand_poisons(self):
        assert dx._has_unresolved_jump((_insn(0x10, "xbegin", ""),))
        assert dx._has_unresolved_jump((
            _insn(0x10, "xbegin", "<garbled>"),
        ))

    def test_xabort_and_xend_are_not_jumps(self):
        # No over-poison: xabort/xend carry no landing-site operand
        # for the screens (alongside the existing call/ret/trap pin).
        assert not dx._has_unresolved_jump((
            _insn(0x10, "xabort", "0x1"),
            _insn(0x13, "xend", ""),
        ))

    def test_abort_target_between_write_and_call_denies_non_entry(self):
        # THE probe shape, non-entry anchoring: the abort target lies
        # strictly between the write and the call, so the call is
        # reachable without the write — refute grade refused (the
        # write still blocks corroboration: honest record).
        insns = (
            _insn(0x12, "xbegin", "1a <f+0xa>"),
            _insn(0x18, "mov", "r8d,0x5"),
            _insn(0x1A, "nop", ""),
            _insn(0x1B, "call", "40 <p>"),
        )
        a = self._analyze(insns, 3, head=False)
        assert not a.strong
        assert a.weak_write

    def test_abort_target_between_write_and_call_denies_entry_anchored(
        self,
    ):
        # Same probe, entry-anchored: branch-free is denied by the
        # abort target, and entry domination is denied because the
        # straight-line entry region now ends AT the xbegin.
        insns = (
            _insn(0x00, "xbegin", "c <f+0xc>"),
            _insn(0x06, "mov", "r8d,0x5"),
            _insn(0x0C, "nop", ""),
            _insn(0x0D, "call", "40 <p>"),
        )
        assert dx._entry_cf_index(insns) == 0
        a = self._analyze(insns, 3)
        assert not a.strong
        assert a.weak_write

    def test_entry_write_before_xbegin_keeps_domination(self):
        # Scope pin, the other direction: a write BEFORE the xbegin
        # precedes every control transfer — the abort path passes it
        # too, so entry domination stands.
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "xbegin", "11 <f+0x11>"),
            _insn(0x0C, "call", "40 <p>"),
            _insn(0x11, "ret", ""),
        )
        a = self._analyze(insns, 2)
        assert a.strong and a.strong_kind == "entry-dominating"


class TestOperandWidth:
    def test_register_widths(self):
        assert dx._operand_width_bytes("rax,rdx") == 8
        assert dx._operand_width_bytes("eax,0x1234") == 4
        assert dx._operand_width_bytes("r8w,ax") == 2
        assert dx._operand_width_bytes("al,0x7f") == 1

    def test_memory_operand_widths(self):
        assert dx._operand_width_bytes("qword ptr [rip+0x10],0x1") == 8
        assert dx._operand_width_bytes("dword ptr [rax],ecx") == 4
        assert dx._operand_width_bytes("byte ptr [rax],0x1") == 1

    def test_zero_test_idiom_detection(self):
        assert dx._is_zero_test_idiom(_insn(1, "test", "rdx,rdx"))
        assert not dx._is_zero_test_idiom(_insn(1, "test", "rdx,rax"))
        assert not dx._is_zero_test_idiom(_insn(1, "cmp", "rdx,rdx"))
        assert not dx._is_zero_test_idiom(
            _insn(1, "test", "al,byte ptr [rax]"),
        )


class TestExcerptBounds:
    def test_excerpt_escapes_hostile_operand_bytes(self):
        insns = (
            _insn(0x10, "mov", "r8d,0x5"),
            _insn(0x16, "call", "40 <\x1b]0;evil\x07sym>"),
        )
        text = dx._excerpt_for(insns, [1])
        assert "\x1b" not in text
        assert "\\x1b" in text

    def test_excerpt_bounded_with_elision_marker(self):
        long_ops = "A" * 190
        insns = tuple(
            _insn(0x10 + i, "mov", f"r8d,{long_ops}") for i in range(12)
        ) + (_insn(0x99, "call", "40 <f>"),)
        text = dx._excerpt_for(insns, [len(insns) - 1])
        assert len(text) <= dx.MAX_EXCERPT_CHARS + 40
        assert "[excerpt elided]" in text

        small = dx._excerpt_for(
            (_insn(0x1, "mov", "r8d,0x5"),
             _insn(0x2, "call", "40 <f>")),
            [1],
        )
        assert "[excerpt elided]" not in small
        assert "0x1: mov r8d,0x5" in small

    def test_bound_excerpt_never_bisects_an_escape(self):
        # Hostile bytes right at the cap: the slice must not leave a
        # dangling half escape token before the marker.
        payload = ("z" * (dx.MAX_EXCERPT_CHARS - 2)) + "\x1b\x1b\x1b"
        out = dx._bound_excerpt(payload)
        assert out.endswith("...[excerpt elided]")
        head = out[: -len("\n...[excerpt elided]")]
        assert not head.endswith("\\")
        assert not head.endswith("\\x")
        assert not head.endswith("\\x1")

    def test_width_lane_excerpt_single_bound(self):
        # The width lane's excerpt is bounded ONCE at the chokepoint —
        # never two independently-bounded parts concatenated past cap.
        compares = tuple(
            _insn(0x100 + i, "cmp", "edx," + "b" * 190)
            for i in range(20)
        )
        window = dx._Window(
            insns=compares, file_format="elf64-x86-64",
            truncated=False, tool_ok=True,
        )
        trig = classify_trigger(
            "only 4 bytes of edx are validated in the check",
        )
        assert trig is not None
        res = dx._check_immediate_width(trig, window, {})
        assert len(res.excerpt) <= dx.MAX_EXCERPT_CHARS + 40


# ---------------------------------------------------------------------------
# ELF load info + address-space bias
# ---------------------------------------------------------------------------


class TestElfLoadInfo:
    def test_non_elf_returns_none(self, tmp_path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"MZ\x90\x00" + b"\0" * 128)
        assert dx._elf_load_info(f) is None

    def test_short_elf_returns_none(self, tmp_path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 20)
        assert dx._elf_load_info(f) is None


def _fake_seg(start: int, perms: str = "r-x") -> SimpleNamespace:
    return SimpleNamespace(start=start, permissions=perms)


class TestResolveBias:
    def test_no_db_no_fun_name_is_zero(self, tmp_path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x7fELF" + b"\0" * 60)
        assert dx._resolve_bias(None, f, "handler", 0x1000) \
            == (0, 0, dx.BIAS_SOURCE_NONE)

    def test_nonloaded_zero_start_blocks_are_ignored(self, monkeypatch,
                                                     tmp_path):
        # Ghidra records .shstrtab/_elfSectionHeaders at 0 with "---"
        # permissions; folding them in would read the base as 0.
        monkeypatch.setattr(dx, "_elf_load_info", lambda b: (0, True))
        db = SimpleNamespace(segments=[
            _fake_seg(0, "---"),
            _fake_seg(0x100000, "r--"),
            _fake_seg(0x16C000, "r-x"),
        ])
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x7fELF" + b"\0" * 60)
        assert dx._resolve_bias(db, f, "FUN_00234560", 0x234560) \
            == (0x100000, 0x100000, dx.BIAS_SOURCE_SEGMENTS)

    def test_name_derived_ghidra_convention_on_et_dyn(self, monkeypatch,
                                                      tmp_path):
        monkeypatch.setattr(dx, "_elf_load_info", lambda b: (0, True))
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x7fELF" + b"\0" * 60)
        assert dx._resolve_bias(None, f, "FUN_00234560", 0x234560) \
            == (0x100000, 0x100000, dx.BIAS_SOURCE_NAME)
        # ET_EXEC keeps its linked base — no name-derived correction.
        monkeypatch.setattr(dx, "_elf_load_info", lambda b: (0x400000,
                                                             False))
        assert dx._resolve_bias(None, f, "FUN_00401000", 0x401000) \
            == (0, 0, dx.BIAS_SOURCE_NONE)

    def test_precorrected_item_address_gets_item_bias_zero(
        self, monkeypatch, tmp_path,
    ):
        # The item address is one tool_bias BELOW its name-embedded
        # address: the caller already corrected it — correcting again
        # would decode one bias below the function.
        monkeypatch.setattr(dx, "_elf_load_info", lambda b: (0, True))
        db = SimpleNamespace(segments=[_fake_seg(0x100000, "r--")])
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x7fELF" + b"\0" * 60)
        assert dx._resolve_bias(db, f, "FUN_00234560", 0x134560) \
            == (0x100000, 0, dx.BIAS_SOURCE_SEGMENTS)

    def test_unparsable_elf_disables_correction(self, tmp_path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"NOPE" + b"\0" * 60)
        db = SimpleNamespace(segments=[_fake_seg(0x100000, "r--")])
        assert dx._resolve_bias(db, f, "FUN_00234560", 0x234560) \
            == (0, 0, dx.BIAS_SOURCE_NONE)


# ---------------------------------------------------------------------------
# Window parsing (synthetic objdump text — no toolchain)
# ---------------------------------------------------------------------------


_OBJDUMP_TEXT = """\
/tmp/x/fixture:     file format elf64-x86-64


Disassembly of section .text:

000000000040100f <target_fn>:
  40100f:\t41 b8 05 00 00 00    \tmov    r8d,0x5
  401015:\te8 f4 ff ff ff       \tcall   40100e <validator>
  40101a:\tc3                   \tret
"""

_OBJDUMP_TEXT_I386 = _OBJDUMP_TEXT.replace(
    "elf64-x86-64", "elf32-i386",
)


_PREFIXED_OBJDUMP = """\
/tmp/x/fixture:     file format elf64-x86-64


Disassembly of section .text:

000000000040100f <target_fn>:
  40100f:\t41 b8 05 00 00 00    \tmov    r8d,0x5
  401015:\tf3 c3                \trepz ret
  401017:\tf2 e9 00 00 00 00    \tbnd jmp 40101d <target_fn+0xe>
  40101d:\tf0 48 0f b1 0a       \tlock cmpxchg QWORD PTR [rdx],rcx
  401022:\t0f 0b                \tud2
"""


class TestPrefixFoldingAndTraps:
    def test_prefix_tokens_fold_to_the_real_mnemonic(self):
        w = dx._parse_window(_PREFIXED_OBJDUMP, 0x40100F, 0x401030)
        mnems = [i.mnemonic for i in w.insns]
        assert mnems == ["mov", "ret", "jmp", "cmpxchg", "ud2"]
        # The folded jmp keeps its target operand.
        assert w.insns[2].operands.startswith("40101d")

    def test_folded_ret_and_traps_are_control_flow(self):
        assert dx._is_control_flow("ret")
        assert dx._is_control_flow("ud2")
        assert dx._is_control_flow("hlt")
        assert dx._is_control_flow("int3")
        assert not dx._is_control_flow("cmpxchg")

    def test_traps_terminate_the_entry_walk(self):
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "ud2", ""),
            _insn(0x08, "call", "99 <p>"),
        )
        reach = dx._entry_reachable(insns)
        assert 1 in reach and 2 not in reach

    def test_trap_between_write_and_call_denies_refute_grade(self):
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "ud2", ""),
            _insn(0x08, "call", "99 <p>"),
        )
        members = dx._DISASM_FAMILY_MEMBERS["r8"]
        a = dx._analyze_site(
            insns, 2, members, dx._branch_targets(insns),
            dx._entry_reachable(insns),
        )
        assert not a.strong
        assert a.weak_write

    def test_conditional_both_targets_missing_call_denies(self):
        # Conditional branch whose BOTH outcomes bypass the call.
        insns = (
            _insn(0x00, "mov", "r8d,0x9"),
            _insn(0x06, "test", "rdi,rdi"),
            _insn(0x09, "je", "10 <f+0x10>"),
            _insn(0x0B, "jmp", "11 <f+0x11>"),
            _insn(0x10, "ret", ""),
            _insn(0x11, "ret", ""),
            _insn(0x12, "call", "99 <p>"),
        )
        members = dx._DISASM_FAMILY_MEMBERS["r8"]
        a = dx._analyze_site(
            insns, 6, members, dx._branch_targets(insns),
            dx._entry_reachable(insns),
        )
        assert not a.strong


class TestWindowParse:
    def test_parses_instructions_and_format(self):
        w = dx._parse_window(_OBJDUMP_TEXT, 0x40100F, 0x40101B)
        assert w.file_format == "elf64-x86-64"
        assert [i.mnemonic for i in w.insns] == ["mov", "call", "ret"]
        assert w.insns[0].operands == "r8d,0x5"
        assert w.truncated is False

    def test_out_of_window_addresses_are_dropped(self):
        w = dx._parse_window(_OBJDUMP_TEXT, 0x401015, 0x40101B)
        assert [i.mnemonic for i in w.insns] == ["call", "ret"]

    def test_output_line_cap_marks_truncated(self, monkeypatch):
        monkeypatch.setattr(dx, "MAX_OUTPUT_LINES", 4)
        w = dx._parse_window(_OBJDUMP_TEXT, 0x40100F, 0x40101B)
        assert w.truncated is True
        monkeypatch.setattr(dx, "MAX_OUTPUT_LINES", 4000)
        w2 = dx._parse_window(_OBJDUMP_TEXT, 0x40100F, 0x40101B)
        assert w2.truncated is False


# ---------------------------------------------------------------------------
# run_disasm_xcheck against synthetic tool output (no toolchain)
# ---------------------------------------------------------------------------


def _checklist(name: str, address: int, size: int) -> dict:
    return {"files": [{"path": "binary:fixture", "items": [
        {"name": name, "address": address, "size": size,
         "metadata": {}},
    ]}]}


_DROP_HYP = (
    "the decompilation shows the count argument is missing at the "
    "call to validator — r8d is never loaded before the call"
)


@pytest.fixture
def fake_binary(tmp_path) -> Path:
    b = tmp_path / "fixture"
    b.write_bytes(b"\x7fELF" + b"\0" * 60)
    return b


def _patch_objdump(monkeypatch, text: str):
    calls: list[dict] = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": argv, "kwargs": kwargs})
        return subprocess.CompletedProcess(argv, 0, stdout=text,
                                           stderr="")

    import core.sandbox

    monkeypatch.setattr(core.sandbox, "run", fake_run)
    monkeypatch.setattr(
        shutil, "which",
        lambda n: "/usr/bin/objdump" if n == "objdump" else None,
    )
    return calls


class TestRunSynthetic:
    def test_dropped_argument_refuted_on_materialized_register(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "refuted"
        assert res.rule_id == dx.RULE_DROPPED_ARGUMENT
        assert res.register == "r8"
        assert res.engine == "disasm"
        assert res.tier == "decoded_instruction"
        assert "mov r8d,0x5" in res.excerpt
        assert res.call_sites[0]["register_written"] is True
        assert res.call_sites[0]["write_grade"] == "branch-free"

    def test_never_promotes_and_never_suppresses_on_corroborate(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        text = _OBJDUMP_TEXT.replace("mov    r8d,0x5", "mov    edi,0x1")
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "corroborated"

    def test_sub_width_write_is_inconclusive_not_refuted(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # P2 shape: only r8b written — stale upper bits, claim TRUE.
        text = _OBJDUMP_TEXT.replace("mov    r8d,0x5", "mov    r8b,0x1")
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_conditional_write_is_inconclusive_not_refuted(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # P3 shape: cmov materializes on one path only, claim TRUE.
        text = _OBJDUMP_TEXT.replace(
            "mov    r8d,0x5", "cmovne r8,rax",
        )
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_bound_callee_matching_no_site_is_callsite_unresolved(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # P10 shape: the claimed callee is tail-called (jmp), the only
        # call site is an unrelated helper — never rebind to it.
        text = _OBJDUMP_TEXT.replace("<validator>", "<helper>")
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_CALLSITE_UNRESOLVED
        # The honest record still shows what WAS decoded, escaped.
        assert "call" in res.excerpt

    def test_prefixed_ret_between_write_and_call_never_refutes(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # `rep ret` (ubiquitous in older GCC output) parsed as a
        # fall-through let the write "reach" a call only external
        # entries reach — the folded mnemonic must terminate.
        text = _OBJDUMP_TEXT.replace(
            "  401015:\te8 f4 ff ff ff       \tcall   40100e <validator>",
            "  401015:\tf3 c3                \trepz ret\n"
            "  401017:\te8 f2 ff ff ff       \tcall   40100e <validator>",
        )
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0x10),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_trap_terminator_between_write_and_call_never_refutes(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        text = _OBJDUMP_TEXT.replace(
            "  401015:\te8 f4 ff ff ff       \tcall   40100e <validator>",
            "  401015:\t0f 0b                \tud2\n"
            "  401017:\te8 f2 ff ff ff       \tcall   40100e <validator>",
        )
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0x10),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_prefixed_jmp_past_the_call_never_refutes(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # `bnd jmp` (MPX) parsed as mnemonic "bnd" fell through both
        # classifiers; folded it is an unconditional jmp PAST the call.
        text = _OBJDUMP_TEXT.replace(
            "  401015:\te8 f4 ff ff ff       \tcall   40100e <validator>",
            "  401015:\tf2 e9 00 00 00 00    \tbnd jmp 40101c <target_fn+0xd>\n"
            "  401017:\te8 f2 ff ff ff       \tcall   40100e <validator>",
        )
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0x10),
            out_dir=tmp_path,
        )
        assert res.outcome != "refuted"

    def test_truncated_window_refuses_corroboration(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        text = _OBJDUMP_TEXT.replace("mov    r8d,0x5", "mov    edi,0x1")
        _patch_objdump(monkeypatch, text)
        monkeypatch.setattr(dx, "MAX_OUTPUT_LINES", 8)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WINDOW_INCOMPLETE

    def test_truncated_window_refuses_refutation(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # A truncated decode also hides branch targets that could
        # disqualify the write — refutation is refused, not just
        # corroboration.
        _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        monkeypatch.setattr(dx, "MAX_OUTPUT_LINES", 8)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome != "refuted"

    def test_unsupported_architecture_is_inconclusive(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _OBJDUMP_TEXT_I386)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_ARCH_UNSUPPORTED

    def test_unresolvable_address_is_inconclusive(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "unknown_fn", _DROP_HYP,
            checklist=None, out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_ADDRESS_UNRESOLVED

    def test_missing_binary_is_inconclusive(self, tmp_path):
        res = run_disasm_xcheck(
            tmp_path / "nope", "binary:fixture", "target_fn",
            _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_BINARY_UNRESOLVED

    def test_missing_objdump_is_skipped(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        monkeypatch.setattr(shutil, "which", lambda n: None)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "skipped"
        assert res.reason == dx.REASON_TOOL_UNAVAILABLE

    def test_sandboxed_invocation_shape(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        calls = _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert len(calls) == 1
        argv = calls[0]["argv"]
        kwargs = calls[0]["kwargs"]
        assert isinstance(argv, list)  # list argv — never a shell string
        assert argv[0] == "objdump"
        assert argv[-1] == str(fake_binary)
        assert kwargs["block_network"] is True
        assert kwargs["target"] == str(fake_binary.resolve().parent)
        assert kwargs["timeout"] == dx.PER_ITEM_TIMEOUT_S

    def test_window_cache_collapses_repeat_invocations(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        calls = _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        for _ in range(3):
            run_disasm_xcheck(
                fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
                checklist=_checklist("target_fn", 0x40100F, 0xC),
                out_dir=tmp_path,
            )
        assert len(calls) == 1

    def test_per_run_invocation_cap_skips_and_caches_nothing(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        calls = _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        monkeypatch.setattr(dx, "PER_RUN_INVOCATION_CAP", 1)
        first = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert first.outcome == "refuted"
        second = run_disasm_xcheck(
            fake_binary, "binary:fixture", "other_fn", _DROP_HYP,
            checklist=_checklist("other_fn", 0x402000, 0x40),
            out_dir=tmp_path,
        )
        assert second.outcome == "skipped"
        assert second.reason == dx.REASON_INVOCATION_CAP
        assert len(calls) == 1
        third = run_disasm_xcheck(
            fake_binary, "binary:fixture", "other_fn", _DROP_HYP,
            checklist=_checklist("other_fn", 0x402000, 0x40),
            out_dir=tmp_path / "run2",
        )
        assert third.reason != dx.REASON_INVOCATION_CAP
        assert len(calls) == 2

    def test_spawn_budget_key_is_resolved_path(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # Distinct spellings of one run dir share one budget — the
        # resolve() at the entry closes the aliasing.
        _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        monkeypatch.setattr(dx, "PER_RUN_INVOCATION_CAP", 1)
        (tmp_path / "run").mkdir()
        run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path / "run",
        )
        aliased = tmp_path / "x" / ".." / "run"
        second = run_disasm_xcheck(
            fake_binary, "binary:fixture", "other_fn", _DROP_HYP,
            checklist=_checklist("other_fn", 0x402000, 0x40),
            out_dir=aliased,
        )
        assert second.reason == dx.REASON_INVOCATION_CAP


_INDIRECT_NONENTRY_OBJDUMP = """\
/tmp/x/fixture:     file format elf64-x86-64


Disassembly of section .text:

0000000000401002 <target_fn>:
  401002:\tff e0                \tjmp    rax
  401004:\t41 b8 05 00 00 00    \tmov    r8d,0x5
  40100a:\t90                   \tnop
  40100b:\te8 fe ff ff ff       \tcall   40100e <validator>
  401010:\tc3                   \tret
"""


class TestIndirectJumpResidual:
    """End-to-end pin of the in-window indirect-jump residual: the
    checklist address (0x401000) sits below the first decoded
    instruction, so the window is NOT entry-anchored and the
    branch-free leg's only reachability screen is the decoded-target
    set — which an indirect dispatch's landing site never enters."""

    def test_indirect_dispatch_on_nonentry_window_never_refutes(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _INDIRECT_NONENTRY_OBJDUMP)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x401000, 0x11),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE
        # The write still blocks corroboration — the honest record.
        assert res.call_sites[0]["write_grade"] == "weak"

    def test_direct_out_of_window_jump_still_refutes(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # Boundary contract (other direction): the same non-entry
        # window with a DIRECT jump leaving the window — its known
        # target cannot land between write and call, so the
        # refute-grade write stands.
        text = _INDIRECT_NONENTRY_OBJDUMP.replace(
            "\tjmp    rax",
            "\tjmp    401080 <elsewhere>",
        )
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", 0x401000, 0x11),
            out_dir=tmp_path,
        )
        assert res.outcome == "refuted"
        assert res.call_sites[0]["write_grade"] == "branch-free"


class TestSyntheticWidthLane:
    def test_width_lane_never_refutes_even_with_register(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # Deliberate downgrade: a wider compare on the bound family
        # withholds corroboration but never demotes (a 64-bit null
        # check beside a 32-bit bounds check is a TRUE-finding shape).
        text = _OBJDUMP_TEXT.replace(
            "mov    r8d,0x5", "cmp    rax,rdx",
        )
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn",
            "only the low 4 bytes of rax are checked before use",
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WIDER_COMPARE

    def test_zero_test_idiom_excluded_from_width_evidence(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # P4 shape: test rdx,rdx (null check) + cmp edx (real bounds
        # check) — the TRUE claim corroborates, the zero test is not
        # width evidence.
        text = _OBJDUMP_TEXT.replace(
            "  40100f:\t41 b8 05 00 00 00    \tmov    r8d,0x5",
            "  40100f:\t48 85 d2             \ttest   rdx,rdx\n"
            "  401012:\t83 fa 10             \tcmp    edx,0x10",
        )
        _patch_objdump(monkeypatch, text)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "target_fn",
            "only 4 bytes of the length in edx are validated before "
            "the call to process; the upper half of rdx is never "
            "bounds-checked",
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            out_dir=tmp_path,
        )
        assert res.outcome == "corroborated"


# ---------------------------------------------------------------------------
# Sibling-differential lane (fake re-database, synthetic windows)
# ---------------------------------------------------------------------------


class _FakeDb:
    def __init__(self, functions, xrefs, segments=()):
        self.functions = functions
        self.xrefs = xrefs
        self.segments = list(segments)

    def function_by_address(self, addr):
        for f in self.functions:
            if f.address == addr:
                return f
        return None

    def function_containing_address(self, addr):
        for f in self.functions:
            if f.address <= addr < f.address + (f.size or 0):
                return f
        return None


def _fn(name, address, size):
    return SimpleNamespace(name=name, address=address, size=size)


def _xref(to_addr, from_addr):
    return SimpleNamespace(kind="call", to_addr=to_addr,
                           from_addr=from_addr)


_SIBLING_OBJDUMP = """\
/tmp/x/fixture:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <claimed>:
  401000:\t41 b8 05 00 00 00    \tmov    r8d,0x5
  401006:\tbf 02 00 00 00       \tmov    edi,0x2
  40100b:\te8 30 00 00 00       \tcall   401040 <sibcallee>
  401010:\tc3                   \tret

0000000000401011 <sib_a>:
  401011:\t41 b8 01 00 00 00    \tmov    r8d,0x1
  401017:\tbf 01 00 00 00       \tmov    edi,0x1
  40101c:\te8 1f 00 00 00       \tcall   401040 <sibcallee>
  401021:\tc3                   \tret

0000000000401022 <sib_b>:
  401022:\t41 b8 03 00 00 00    \tmov    r8d,0x3
  401028:\tbf 03 00 00 00       \tmov    edi,0x3
  40102d:\te8 0e 00 00 00       \tcall   401040 <sibcallee>
  401032:\tc3                   \tret

0000000000401033 <claimed_missing>:
  401033:\tbf 06 00 00 00       \tmov    edi,0x6
  401038:\te8 03 00 00 00       \tcall   401040 <sibcallee>
  40103d:\tc3                   \tret

0000000000401050 <claimed_weak>:
  401050:\t41 b0 06             \tmov    r8b,0x6
  401053:\tbf 06 00 00 00       \tmov    edi,0x6
  401058:\te8 e3 ff ff ff       \tcall   401040 <sibcallee>
  40105d:\tc3                   \tret

0000000000401060 <dec_rs1>:
  401060:\tbf 01 00 00 00       \tmov    edi,0x1
  401065:\tbe 02 00 00 00       \tmov    esi,0x2
  40106a:\te8 d1 ff ff ff       \tcall   401040 <sibcallee>
  40106f:\tc3                   \tret

0000000000401070 <dec_rs2>:
  401070:\tbf 01 00 00 00       \tmov    edi,0x1
  401075:\tbe 02 00 00 00       \tmov    esi,0x2
  40107a:\te8 c1 ff ff ff       \tcall   401040 <sibcallee>
  40107f:\tc3                   \tret

0000000000401080 <claimed_two>:
  401080:\t41 b8 05 00 00 00    \tmov    r8d,0x5
  401086:\tbf 01 00 00 00       \tmov    edi,0x1
  40108b:\te8 b0 ff ff ff       \tcall   401040 <sibcallee>
  401090:\t41 b8 06 00 00 00    \tmov    r8d,0x6
  401096:\tbf 02 00 00 00       \tmov    edi,0x2
  40109b:\te8 a0 ff ff ff       \tcall   401040 <sibcallee>
  4010a0:\tc3                   \tret
"""

_SIBLING_HYP = (
    "no count argument is passed to sibcallee here, unlike sibling "
    "calls that pass one"
)


def _sibling_db() -> _FakeDb:
    return _FakeDb(
        functions=[
            _fn("claimed", 0x401000, 0x11),
            _fn("sib_a", 0x401011, 0x11),
            _fn("sib_b", 0x401022, 0x11),
            _fn("claimed_missing", 0x401033, 0xB),
            _fn("sibcallee", 0x401040, 0x1),
            _fn("claimed_weak", 0x401050, 0xE),
            _fn("dec_rs1", 0x401060, 0x10),
            _fn("dec_rs2", 0x401070, 0x10),
            _fn("claimed_two", 0x401080, 0x21),
        ],
        xrefs=[
            _xref(0x401040, 0x40100B),
            _xref(0x401040, 0x40101C),
            _xref(0x401040, 0x40102D),
            _xref(0x401040, 0x401038),
        ],
    )


class TestSiblingDifferential:
    def test_matching_profile_refutes_the_unlike_siblings_claim(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        db = _sibling_db()
        # Siblings here are the two r8-passing callers; the r8-less
        # caller is not part of this claim's sibling population.
        db.xrefs = [x for x in db.xrefs if x.from_addr != 0x401038]
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "refuted"
        assert res.rule_id == dx.RULE_SIBLING_ARGUMENT
        assert res.call_sites[0]["missing"] == []
        assert "r8" in res.call_sites[0]["sibling_shared"]

    def test_arg1_only_intersection_refuses_to_adjudicate(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # An r8-less caller among the siblings shrinks the shared set
        # to arg1 alone — materialized at essentially every call
        # site, so it carries no count-argument signal. The lane must
        # refuse rather than refute against the weakest sample.
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=_sibling_db(),
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_SIBLING_SUBSTRATE

    def test_genuinely_missing_register_corroborates(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed_missing",
            _SIBLING_HYP,
            checklist=_checklist("claimed_missing", 0x401033, 0xB),
            out_dir=tmp_path, db=_sibling_db(),
        )
        assert res.outcome == "corroborated"
        assert "r8" in res.call_sites[0]["missing"]

    def test_weak_write_at_claimed_site_never_refutes_differential(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # The claimed site materializes r8 only through a sub-width
        # alias: the under-approximating claimed-site detector must
        # keep r8 out of the strong profile — refuting there would
        # launder a stale-upper-bits write into "the count is passed",
        # and corroborating would contradict the write's existence.
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        db = _sibling_db()
        db.xrefs = [x for x in db.xrefs if x.from_addr != 0x401038]
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed_weak",
            _SIBLING_HYP,
            checklist=_checklist("claimed_weak", 0x401050, 0xE),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "inconclusive"

    def test_fewer_than_min_siblings_is_inconclusive(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        db = _sibling_db()
        db.xrefs = [x for x in db.xrefs
                    if x.from_addr in (0x40100B, 0x40101C)]
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_SIBLING_SUBSTRATE

    def test_population_beyond_cap_blocks_refutation(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # The differential is only refute-sound over the FULL
        # attributable population — a sampled subset is
        # decoy-steerable, so truncation blocks refutation the way
        # call-site truncation does.
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        monkeypatch.setattr(dx, "MAX_SIBLING_SITES", 2)
        db = _sibling_db()
        # Population 3 (sib_a, sib_b, claimed_weak-as-sibling), cap 2:
        # the two sampled profiles agree on {r8, rdi}, but the unseen
        # third could be the real differential — refuse.
        db.xrefs = [
            _xref(0x401040, 0x40101C),
            _xref(0x401040, 0x40102D),
            _xref(0x401040, 0x401058),
        ]
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_SIBLING_SAMPLE_TRUNCATED
        assert res.window["sibling_sample_truncated"] is True

    def test_sampling_failure_blocks_refutation(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # An attributable sibling whose window cannot be decoded
        # (span past the window cap here) leaves the population
        # partially sampled — a decoy could hide in the gap, so
        # refutation is refused.
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        db = _sibling_db()
        db.xrefs = [x for x in db.xrefs if x.from_addr != 0x401038]
        # A third sibling site whose containing function starts one
        # full window-cap below its call.
        far = 0x401011 + dx.MAX_WINDOW_BYTES + 0x100
        db.functions.append(_fn("far_caller", 0x401011, far - 0x401011))
        db.xrefs.append(_xref(0x401040, far - 0x10))
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome != "refuted"
        assert res.window["sibling_sampling_incomplete"] is True

    def test_claimed_site_truncation_blocks_refutation(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # A claimed window with more matched callee sites than the
        # examination cap is only PARTIALLY checked — the unexamined
        # site could be the one genuinely missing the register, so
        # refutation is refused and the receipt says so.
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        monkeypatch.setattr(dx, "MAX_CALL_SITES", 1)
        db = _sibling_db()
        db.xrefs = [x for x in db.xrefs if x.from_addr != 0x401038]
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed_two", _SIBLING_HYP,
            checklist=_checklist("claimed_two", 0x401080, 0x21),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_SIBLING_SAMPLE_TRUNCATED
        assert res.window["claimed_sites_truncated"] is True

    def test_arg1_arg2_only_intersection_refuses(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # {rdi, rsi}-only shared sets are near-universal at call
        # sites — no count-argument signal; must refuse like {rdi}.
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        db = _sibling_db()
        db.xrefs = [
            _xref(0x401040, 0x40106A),  # dec_rs1: rdi+rsi only
            _xref(0x401040, 0x40107A),  # dec_rs2: rdi+rsi only
        ]
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_SIBLING_SUBSTRATE

    def test_decoy_flood_degenerates_to_refusal(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # The decoy-steering shape: arg1/arg2-only decoy callers mixed
        # with real count-passing siblings shrink the intersection to
        # the no-signal set — the TRUE claim must survive (no refute).
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        db = _sibling_db()
        db.xrefs = [
            _xref(0x401040, 0x40106A),  # decoy rdi+rsi
            _xref(0x401040, 0x40107A),  # decoy rdi+rsi
            _xref(0x401040, 0x40101C),  # real sib_a (r8+rdi)
            _xref(0x401040, 0x40102D),  # real sib_b (r8+rdi)
        ]
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed_missing",
            _SIBLING_HYP,
            checklist=_checklist("claimed_missing", 0x401033, 0xB),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome != "refuted"

    def test_unattributed_xref_sites_excluded_and_recorded(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # An xref from a gap region (no containing function in the
        # database) is not a sibling FUNCTION call site — excluded
        # from the population, counted in the receipt, and the clean
        # attributable population still adjudicates.
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        db = _sibling_db()
        db.xrefs = [x for x in db.xrefs if x.from_addr != 0x401038]
        db.xrefs.append(_xref(0x401040, 0x40FF00))  # gap region
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "refuted"
        assert res.window["sibling_unattributed"] == 1
        assert res.window["sibling_population"] == 2

    def test_no_db_is_inconclusive_substrate(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _SIBLING_OBJDUMP)
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "claimed", _SIBLING_HYP,
            checklist=_checklist("claimed", 0x401000, 0x11),
            out_dir=tmp_path, db=None,
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_SIBLING_SUBSTRATE


class TestGuessedBiasCap:
    """A name-convention (guessed) bias may corroborate but never
    refute — the suppression-authority doctrine for guessed
    configuration (the binary-oracle earns_suppression precedent)."""

    _GUESS_HYP = "r8d is never loaded before the call to validator"

    def _run(self, fake_binary, monkeypatch, tmp_path, text):
        _patch_objdump(monkeypatch, text)
        # ET_DYN, min PT_LOAD 0 → the FUN_-name leg guesses the
        # default image base; window decodes one bias below the item.
        monkeypatch.setattr(dx, "_elf_load_info", lambda b: (0, True))
        return run_disasm_xcheck(
            fake_binary, "binary:fixture", "FUN_0050100f",
            self._GUESS_HYP,
            checklist=_checklist("FUN_0050100f", 0x50100F, 0xC),
            out_dir=tmp_path, db=None,
        )

    def test_guessed_bias_refute_is_capped(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        res = self._run(fake_binary, monkeypatch, tmp_path,
                        _OBJDUMP_TEXT)
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_GUESSED_BIAS
        assert res.window["bias_source"] == dx.BIAS_SOURCE_NAME
        assert res.window["refute_capped"] == "guessed-bias"

    def test_guessed_bias_corroborate_passes_through(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        text = _OBJDUMP_TEXT.replace("mov    r8d,0x5", "mov    edi,0x1")
        res = self._run(fake_binary, monkeypatch, tmp_path, text)
        assert res.outcome == "corroborated"

    def test_measured_bias_refute_is_not_capped(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        monkeypatch.setattr(dx, "_elf_load_info", lambda b: (0, True))
        db = SimpleNamespace(
            segments=[_fake_seg(0x100000, "r-x")],
            functions=[], xrefs=[],
            function_by_address=lambda a: None,
            function_containing_address=lambda a: None,
        )
        res = run_disasm_xcheck(
            fake_binary, "binary:fixture", "FUN_0050100f",
            self._GUESS_HYP,
            checklist=_checklist("FUN_0050100f", 0x50100F, 0xC),
            out_dir=tmp_path, db=db,
        )
        assert res.outcome == "refuted"
        assert res.window["bias_source"] == dx.BIAS_SOURCE_SEGMENTS


# ---------------------------------------------------------------------------
# Refutation-gate wiring
# ---------------------------------------------------------------------------


@dataclass
class _Outcome:
    file: str = "binary:fixture"
    function: str = "target_fn"
    status: str = "suspicious"
    body: str = ""
    hypothesis: str = _DROP_HYP
    hypotheses: Optional[list] = None
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None


@dataclass
class _Config:
    target_path: Path = field(default_factory=lambda: Path("/nonexistent"))
    out_dir: Optional[Path] = None


def _counters() -> dict:
    return {"disasm_xcheck": SimpleNamespace(
        confirmed=0, refuted=0, inconclusive=0, skipped=0, errors=0,
    )}


class TestRefutationGateWiring:
    def test_source_items_never_dispatch_the_gate(self, monkeypatch):
        from core.audit.refutation import refute_hypothesis

        def _boom(*a, **k):
            raise AssertionError("gate dispatched for a source item")

        monkeypatch.setattr(dx, "classify_trigger", _boom)
        monkeypatch.setattr(dx, "run_disasm_xcheck", _boom)
        outcome = _Outcome(file="src/parser.c")
        assert refute_hypothesis(
            outcome, domain_model=None, checklist=None,
            config=_Config(),
        ) is None

    def test_non_matching_hypothesis_never_invokes_the_channel(
        self, monkeypatch,
    ):
        from core.audit.refutation import refute_hypothesis

        def _boom(*a, **k):
            raise AssertionError("channel invoked outside taxonomy")

        monkeypatch.setattr(dx, "run_disasm_xcheck", _boom)
        outcome = _Outcome(
            hypothesis="buffer overflow when copying attacker data "
                       "into a stack buffer",
        )
        counters = _counters()
        assert refute_hypothesis(
            outcome, domain_model=None, checklist=None,
            config=_Config(), tier_counters=counters,
        ) is None
        tc = counters["disasm_xcheck"]
        assert (tc.refuted, tc.confirmed, tc.inconclusive,
                tc.skipped, tc.errors) == (0, 0, 0, 0, 0)

    def test_refuted_demotes_with_receipt_and_journal_row(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        from core.audit.refutation import refute_hypothesis

        _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        counters = _counters()
        outcome = _Outcome()
        rv = refute_hypothesis(
            outcome, domain_model=None,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            config=_Config(target_path=fake_binary, out_dir=tmp_path),
            tier_counters=counters,
        )
        assert rv is not None
        assert rv.gate == "disasm_xcheck"
        assert rv.demote_to == "clean"
        assert rv.refuter_grade == "heuristic"
        assert dx.RULE_DROPPED_ARGUMENT in rv.reason
        assert counters["disasm_xcheck"].refuted == 1
        rows = [
            json.loads(line)
            for line in (tmp_path / ".audit-log.jsonl")
            .read_text().splitlines()
        ]
        receipt = [r for r in rows if r.get("action") == "disasm_xcheck"]
        assert len(receipt) == 1
        assert receipt[0]["engine"] == "disasm"
        assert receipt[0]["tier"] == "decoded_instruction"
        assert receipt[0]["outcome"] == "refuted"
        assert receipt[0]["claim_source"] == "hypothesis"
        assert "mov r8d,0x5" in receipt[0]["excerpt"]

    def test_empty_hypothesis_falls_back_to_body_claim(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        # Live binary rows journal suspicious verdicts with an empty
        # hypothesis and the claim in body prose — gate 7 must still
        # get its turn (refute_hypothesis used to exit early).
        from core.audit.refutation import refute_hypothesis

        _patch_objdump(monkeypatch, _OBJDUMP_TEXT)
        outcome = _Outcome(
            hypothesis="",
            body="[gate violation: earlier note] " + _DROP_HYP,
        )
        rv = refute_hypothesis(
            outcome, domain_model=None,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            config=_Config(target_path=fake_binary, out_dir=tmp_path),
            tier_counters=_counters(),
        )
        assert rv is not None and rv.gate == "disasm_xcheck"
        rows = [
            json.loads(line)
            for line in (tmp_path / ".audit-log.jsonl")
            .read_text().splitlines()
        ]
        receipt = [r for r in rows if r.get("action") == "disasm_xcheck"]
        assert receipt[0]["claim_source"] == "body"

    def test_corroborated_attaches_receipt_and_changes_nothing(
        self, fake_binary, monkeypatch, tmp_path,
    ):
        from core.audit.refutation import refute_hypothesis

        text = _OBJDUMP_TEXT.replace("mov    r8d,0x5", "mov    edi,0x1")
        _patch_objdump(monkeypatch, text)
        counters = _counters()
        outcome = _Outcome()
        rv = refute_hypothesis(
            outcome, domain_model=None,
            checklist=_checklist("target_fn", 0x40100F, 0xC),
            config=_Config(target_path=fake_binary, out_dir=tmp_path),
            tier_counters=counters,
        )
        assert rv is None  # verdict stands — never a promotion either
        assert outcome.status == "suspicious"
        assert outcome.evidence_tool == ""
        attached = outcome.disasm_xcheck  # type: ignore[attr-defined]
        assert attached["outcome"] == "corroborated"
        assert attached["engine"] == "disasm"
        assert counters["disasm_xcheck"].confirmed == 1

    def test_tool_confirmed_outcomes_bypass_the_gate(self, monkeypatch):
        from core.audit.refutation import refute_hypothesis

        def _boom(*a, **k):
            raise AssertionError("gate ran on tool-confirmed outcome")

        monkeypatch.setattr(dx, "run_disasm_xcheck", _boom)
        outcome = _Outcome(evidence_tool="semgrep:decompiler-rule")
        assert refute_hypothesis(
            outcome, domain_model=None, checklist=None,
            config=_Config(),
        ) is None


class TestTierRegistration:
    def test_disasm_xcheck_in_tier_table(self):
        from core.audit.orchestrator import _make_tier_counters

        assert "disasm_xcheck" in _make_tier_counters()


# ---------------------------------------------------------------------------
# Evidence-chain export
# ---------------------------------------------------------------------------


class TestEvidenceChainExport:
    def _outcome(self, **kw) -> SimpleNamespace:
        base = dict(
            file="binary:fixture", function="target_fn",
            line=0, status="suspicious",
            hypothesis=_DROP_HYP,
            review_result={"hypothesis": _DROP_HYP},
            evidence_tool="",
        )
        base.update(kw)
        return SimpleNamespace(**base)

    def test_pipeline_receipt_lands_in_evidence_chain(self):
        from core.audit.findings_export import build_graded_finding

        outcome = self._outcome()
        outcome.disasm_xcheck = {
            "outcome": "corroborated",
            "trigger": "dropped_argument",
            "reason": "no write to r8 in any complete pre-call segment",
            "rule_id": dx.RULE_DROPPED_ARGUMENT,
            "engine": "disasm",
            "tier": "decoded_instruction",
            "excerpt": "  0x40100f: mov edi,0x1",
        }
        finding = build_graded_finding(outcome)
        sources = [e["source"] for e in finding["evidence_chain"]]
        assert "mechanical:disasm" in sources
        entry = next(
            e for e in finding["evidence_chain"]
            if e["source"] == "mechanical:disasm"
        )
        assert "corroborated" in entry["description"]
        assert entry["confidence"] == "low"

    def test_receipt_never_lifts_exported_confidence(self):
        from core.audit.findings_export import build_graded_finding

        receipt = {
            "outcome": "corroborated", "reason": "r", "engine": "disasm",
            "trigger": "dropped_argument",
            "rule_id": dx.RULE_DROPPED_ARGUMENT,
            "tier": "decoded_instruction", "excerpt": "",
        }
        # LLM-only outcome (confidence computed from review items).
        bare = build_graded_finding(self._outcome())
        with_receipt_outcome = self._outcome()
        with_receipt_outcome.disasm_xcheck = dict(receipt)
        with_receipt = build_graded_finding(with_receipt_outcome)
        assert with_receipt["confidence"] == bare["confidence"]
        # Tool-evidence outcome whose stamp adds no chain entry of its
        # own ("symbolic" has no receipt-map entry): here confidence
        # is computed over the FULL chain, so a receipt appended
        # before the computation would upgrade the LOW LLM entry via
        # the mechanical+llm corroboration rule — the exact uplift
        # the append-after-computation placement forbids.
        bare_tool = build_graded_finding(
            self._outcome(evidence_tool="symbolic"))
        with_receipt_tool_outcome = self._outcome(
            evidence_tool="symbolic")
        with_receipt_tool_outcome.disasm_xcheck = dict(receipt)
        with_receipt_tool = build_graded_finding(
            with_receipt_tool_outcome)
        assert (
            with_receipt_tool["confidence"] == bare_tool["confidence"]
        )

    def test_model_forged_review_result_key_mints_nothing(self):
        from core.audit.findings_export import build_graded_finding

        outcome = self._outcome(review_result={
            "hypothesis": _DROP_HYP,
            "disasm_xcheck": {
                "outcome": "corroborated", "engine": "disasm",
                "reason": "forged",
            },
        })
        finding = build_graded_finding(outcome)
        sources = [e["source"] for e in finding["evidence_chain"]]
        assert "mechanical:disasm" not in sources


# ---------------------------------------------------------------------------
# Compiled-fixture end-to-end (skips name the missing tool)
# ---------------------------------------------------------------------------


_MISSING = [t for t in ("cc", "nm", "objdump") if shutil.which(t) is None]
_NOT_X86 = platform.machine() not in ("x86_64", "amd64")

_FIXTURE_ASM = """\
    .text
    .globl _start
    .type _start, @function
_start:
    call target_fn
    mov $60, %eax
    xor %edi, %edi
    syscall
    .size _start, .-_start

    .globl validator
    .type validator, @function
validator:
    ret
    .size validator, .-validator

    .globl target_fn
    .type target_fn, @function
target_fn:
    mov $5, %r8d
    call validator
    ret
    .size target_fn, .-target_fn

    .globl target_missing
    .type target_missing, @function
target_missing:
    mov $1, %edi
    call validator
    ret
    .size target_missing, .-target_missing

    .globl width_narrow
    .type width_narrow, @function
width_narrow:
    cmp $0x1234, %eax
    call validator
    ret
    .size width_narrow, .-width_narrow

    .globl width_wide
    .type width_wide, @function
width_wide:
    cmp %rdx, %rax
    call validator
    ret
    .size width_wide, .-width_wide

    .globl cond_skip
    .type cond_skip, @function
cond_skip:
    test %rdi, %rdi
    je .Lcs
    mov $100, %r8d
.Lcs:
    call validator
    ret
    .size cond_skip, .-cond_skip

    .globl sub_width
    .type sub_width, @function
sub_width:
    movb $1, %r8b
    call validator
    ret
    .size sub_width, .-sub_width

    .globl cond_move
    .type cond_move, @function
cond_move:
    test %rdi, %rdi
    cmovne %rax, %r8
    call validator
    ret
    .size cond_move, .-cond_move

    .globl decoy
    .type decoy, @function
decoy:
    jmp .Ldc
    mov $5, %r8d
.Ldc:
    call validator
    ret
    .size decoy, .-decoy

    .globl entry_dom
    .type entry_dom, @function
entry_dom:
    movzwl 0x28(%rax), %r8d
    test %r8w, %r8w
    jne .Led
    mov $1, %eax
    ret
.Led:
    mov 0x20(%rdi), %rsi
    call validator
    ret
    .size entry_dom, .-entry_dom

    .globl sib_extra
    .type sib_extra, @function
sib_extra:
    mov $9, %r8d
    call validator
    ret
    .size sib_extra, .-sib_extra

    .globl ret_cross
    .type ret_cross, @function
ret_cross:
    mov $9, %r8d
    ret
    call validator
    ret
    .size ret_cross, .-ret_cross

    .globl jmp_past
    .type jmp_past, @function
jmp_past:
    mov $9, %r8d
    jmp .Ljp
    call validator
.Ljp:
    ret
    .size jmp_past, .-jmp_past

    .globl cond_reach
    .type cond_reach, @function
cond_reach:
    mov $9, %r8d
    test %rdi, %rdi
    je .Lcr
    nop
.Lcr:
    call validator
    ret
    .size cond_reach, .-cond_reach

    .globl rep_cross
    .type rep_cross, @function
rep_cross:
    mov $9, %r8d
    rep ret
    call validator
    ret
    .size rep_cross, .-rep_cross

    .globl trap_cross
    .type trap_cross, @function
trap_cross:
    mov $9, %r8d
    ud2
    call validator
    ret
    .size trap_cross, .-trap_cross

    .globl bnd_past
    .type bnd_past, @function
bnd_past:
    mov $9, %r8d
    .byte 0xf2
    jmp .Lbp
    call validator
.Lbp:
    ret
    .size bnd_past, .-bnd_past

    .globl indirect_poison
    .type indirect_poison, @function
indirect_poison:
    test %rdi, %rdi
    je .Lip
    jmp *%rax
.Lip:
    mov $5, %r8d
    call validator
    ret
    .size indirect_poison, .-indirect_poison

    .globl indirect_entrydom
    .type indirect_entrydom, @function
indirect_entrydom:
    mov $9, %r8d
    test %rdi, %rdi
    je .Lie
    jmp *%rax
.Lie:
    call validator
    ret
    .size indirect_entrydom, .-indirect_entrydom

    .globl xbegin_poison
    .type xbegin_poison, @function
xbegin_poison:
    xbegin .Lxp
    mov $5, %r8d
    nop
.Lxp:
    nop
    call validator
    ret
    .size xbegin_poison, .-xbegin_poison

    .globl jmp_chain
    .type jmp_chain, @function
jmp_chain:
    mov $9, %r8d
    jmp .Ljc1
    nop
.Ljc1:
    jmp .Ljc2
    nop
.Ljc2:
    call validator
    ret
    .size jmp_chain, .-jmp_chain
"""


@pytest.fixture(scope="module")
def compiled_fixture(tmp_path_factory):
    if _MISSING:
        pytest.skip(f"toolchain missing: {', '.join(_MISSING)}")
    if _NOT_X86:
        pytest.skip(f"not an x86-64 host: {platform.machine()}")
    root = tmp_path_factory.mktemp("dxfixture")
    asm = root / "fixture.s"
    asm.write_text(_FIXTURE_ASM)
    binary = root / "fixture"
    proc = subprocess.run(
        ["cc", "-nostdlib", "-static", "-Wl,--build-id=none",
         "-o", str(binary), str(asm)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"cc could not assemble the fixture: {proc.stderr[:200]}")
    syms: dict[str, tuple[int, int]] = {}
    for line in subprocess.run(
        ["nm", "-S", "--format=posix", str(binary)],
        capture_output=True, text=True,
    ).stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            syms[parts[0]] = (int(parts[2], 16), int(parts[3], 16))
    return binary, syms


@pytest.fixture
def _direct_objdump(monkeypatch):
    """Route the sandbox seam to plain subprocess for the compiled
    fixture (the sandbox layers are exercised by their own suite; the
    invocation SHAPE is asserted in TestRunSynthetic)."""

    def fake_run(argv, **kwargs):
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=60,
        )

    import core.sandbox

    monkeypatch.setattr(core.sandbox, "run", fake_run)


class TestCompiledFixture:
    def _run(self, compiled_fixture, name: str, hypothesis: str,
             db=None):
        binary, syms = compiled_fixture
        addr, size = syms[name]
        return run_disasm_xcheck(
            binary, "binary:fixture", name, hypothesis,
            checklist=_checklist(name, addr, size), out_dir=None,
            db=db,
        )

    def test_decomp_dropped_count_claim_refuted_by_real_instructions(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(compiled_fixture, "target_fn", _DROP_HYP)
        assert res.outcome == "refuted"
        assert res.register == "r8"
        assert "mov r8d,0x5" in res.excerpt
        assert res.call_sites[0]["binding"] == "callee-bound"
        assert res.call_sites[0]["write_grade"] == "branch-free"

    def test_genuinely_missing_register_corroborates(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(compiled_fixture, "target_missing", _DROP_HYP)
        assert res.outcome == "corroborated"

    def test_conditional_skip_never_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "cond_skip",
            "the length in r8d is not set before the call to "
            "validator on the error path",
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_sub_width_alias_never_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "sub_width",
            "the size argument in r8 is never set before the call to "
            "validator; only stale data is present",
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_conditional_move_never_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "cond_move",
            "r8 is not initialized before the call to validator when "
            "the flag is clear",
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_unreachable_decoy_never_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "decoy",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_ret_ending_entry_never_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        # The call is reachable only from outside the entry path —
        # the entry write dominates nothing that matters.
        res = self._run(
            compiled_fixture, "ret_cross",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome != "refuted"

    def test_jmp_past_call_never_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "jmp_past",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome != "refuted"

    def test_conditional_branch_domination_still_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        # The sound control for the reachability gate: a conditional
        # branch between write and call keeps domination.
        res = self._run(
            compiled_fixture, "cond_reach",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome == "refuted"
        assert res.call_sites[0]["write_grade"] == "entry-dominating"

    def test_prefixed_ret_never_refutes_real_objdump(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "rep_cross",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome != "refuted"

    def test_trap_terminator_never_refutes_real_objdump(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "trap_cross",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome != "refuted"

    def test_prefixed_jmp_past_call_never_refutes_real_objdump(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "bnd_past",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome != "refuted"

    def test_indirect_dispatch_poisons_branch_free_real_objdump(
        self, compiled_fixture, _direct_objdump,
    ):
        # Jump-table-dispatch shape on real objdump output: the write
        # sits at the dispatch's possible landing region (`jmp *%rax`
        # could land between it and the call), so the true "not set
        # on the dispatched path" claim must survive.
        res = self._run(
            compiled_fixture, "indirect_poison",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_indirect_dispatch_keeps_entry_domination_real_objdump(
        self, compiled_fixture, _direct_objdump,
    ):
        # Scope control: the poison is branch-free-only — an
        # entry-region write precedes every control transfer,
        # indirect dispatch included.
        res = self._run(
            compiled_fixture, "indirect_entrydom",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome == "refuted"
        assert res.call_sites[0]["write_grade"] == "entry-dominating"

    def test_xbegin_abort_path_never_refutes_real_objdump(
        self, compiled_fixture, _direct_objdump,
    ):
        # TSX probe on real objdump output: the xbegin abort target
        # lands strictly between the write and the call, so the true
        # "not set on the abort path" claim must survive.
        res = self._run(
            compiled_fixture, "xbegin_poison",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WRITE_NOT_REFUTE_GRADE

    def test_jmp_chain_to_call_still_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        # Sound-refute control for the reachability walk: the write
        # reaches the call through an unconditional jmp chain on
        # every in-window path.
        res = self._run(
            compiled_fixture, "jmp_chain",
            "the count argument in r8d is never passed to validator",
        )
        assert res.outcome == "refuted"

    def test_entry_dominating_write_refutes(
        self, compiled_fixture, _direct_objdump,
    ):
        # The field-observed shape: count materialized at function entry,
        # branch over an early-out ret, call later.
        res = self._run(
            compiled_fixture, "entry_dom",
            "the count argument in r8d is missing at the call to "
            "validator — r8d is never loaded",
        )
        assert res.outcome == "refuted"
        assert res.call_sites[0]["write_grade"] == "entry-dominating"

    def test_width_claim_with_wider_compare_stays_inconclusive(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "width_wide",
            "only the low 4 bytes of rax are checked before use",
        )
        assert res.outcome == "inconclusive"
        assert res.reason == dx.REASON_WIDER_COMPARE

    def test_width_claim_corroborated_by_narrow_compare(
        self, compiled_fixture, _direct_objdump,
    ):
        res = self._run(
            compiled_fixture, "width_narrow",
            "only the low 4 bytes of eax are checked before use",
        )
        assert res.outcome == "corroborated"

    def test_bias_corrected_window_from_tool_space_checklist(
        self, compiled_fixture, _direct_objdump,
    ):
        # A Ghidra-style database: loaded segments one image-base
        # above the ELF vaddrs, checklist addresses in tool space.
        binary, syms = compiled_fixture
        addr, size = syms["target_fn"]
        info = dx._elf_load_info(binary)
        assert info is not None
        elf_base, _ = info
        shift = 0x100000
        db = _FakeDb(
            functions=[_fn("target_fn", addr + shift, size)],
            xrefs=[],
            segments=[_fake_seg(elf_base + shift, "r-x"),
                      _fake_seg(0, "---")],
        )
        res = run_disasm_xcheck(
            binary, "binary:fixture", "target_fn", _DROP_HYP,
            checklist=_checklist("target_fn", addr + shift, size),
            out_dir=None, db=db,
        )
        assert res.outcome == "refuted"
        assert res.window["bias"] == hex(shift)

    def test_sibling_lane_end_to_end_on_real_elf(
        self, compiled_fixture, _direct_objdump,
    ):
        # target_fn and entry_dom both call validator with r8
        # materialized; target_missing does not — the differential
        # corroborates its "no count argument" claim.
        binary, syms = compiled_fixture

        def fx(name):
            a, s = syms[name]
            return _fn(name, a, s)

        # Locate the call instruction addresses via the module's own
        # decoder (the xref from_addr convention).
        def call_addr(name):
            a, s = syms[name]
            w = dx._extract_window(binary, a, a + s, "")
            assert not isinstance(w, str)
            calls = dx._call_sites_in(w.insns)
            return w.insns[calls[0]].address

        hyp = ("no count argument is passed to validator here, "
               "unlike sibling calls that pass one")

        # Corroborate leg: claimed_missing vs two r8-passing siblings.
        db = _FakeDb(
            functions=[fx("target_fn"), fx("entry_dom"),
                       fx("target_missing"), fx("validator")],
            xrefs=[
                _xref(syms["validator"][0], call_addr("target_fn")),
                _xref(syms["validator"][0], call_addr("entry_dom")),
                _xref(syms["validator"][0],
                      call_addr("target_missing")),
            ],
        )
        a, s = syms["target_missing"]
        res = run_disasm_xcheck(
            binary, "binary:fixture", "target_missing", hyp,
            checklist=_checklist("target_missing", a, s),
            out_dir=None, db=db,
        )
        assert res.outcome == "corroborated"
        assert "r8" in res.call_sites[0]["missing"]

        # Refute leg: target_fn's siblings all materialize r8 — the
        # "unlike siblings" premise is contradicted.
        db2 = _FakeDb(
            functions=[fx("target_fn"), fx("entry_dom"),
                       fx("sib_extra"), fx("validator")],
            xrefs=[
                _xref(syms["validator"][0], call_addr("target_fn")),
                _xref(syms["validator"][0], call_addr("entry_dom")),
                _xref(syms["validator"][0], call_addr("sib_extra")),
            ],
        )
        a, s = syms["target_fn"]
        res2 = run_disasm_xcheck(
            binary, "binary:fixture", "target_fn", hyp,
            checklist=_checklist("target_fn", a, s),
            out_dir=None, db=db2,
        )
        assert res2.outcome == "refuted"
        assert "r8" in res2.call_sites[0]["sibling_shared"]
