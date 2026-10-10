"""Gate tests: caller-held-lock discharge in rescue_self_refuted.

The anti-self-refutation gate floors race-family self-refutations to
suspicious.  On static C functions, a dismissal whose operative safety
argument is a lock the CALLER holds across the call is instead
ACCEPTED (with a suppressions.jsonl record, ``dropped: false``) when
the TU-local caller-held-lock witness proves it.  These tests pin the
discharge, its record, and — most importantly — every shape that must
keep flooring: an unlocked second caller, out-of-family phrasings,
mixed lifetime claims, untrusted targets, structural-receipt
functions, Go sources (which must never consult this C-only witness),
and the record-or-refuse contract.

Module-level imports here deliberately avoid ``core.audit.caller_lock``
so the floor-stands regressions in this file also run against trees
that predate the witness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from core.audit.refutation import rescue_self_refuted

# ---------------------------------------------------------------------------
# Synthetic C fixtures written to disk
# ---------------------------------------------------------------------------

_CALLEE = """\
static int sample_collapse_range(struct inode *inode, loff_t offset,
\t\t\t\t loff_t len)
{
\tif (offset + len >= i_size_read(inode))
\t\treturn -EINVAL;
\treturn do_collapse(inode, offset, len);
}
"""

_CALLER_LOCKED = """
long sample_fallocate(struct file *file, int mode, loff_t offset,
\t\t      loff_t len)
{
\tstruct inode *inode = file_inode(file);
\tlong ret;

\tinode_lock(inode);

\tif (mode & FALLOC_FL_COLLAPSE_RANGE) {
\t\tret = sample_collapse_range(inode, offset, len);
\t} else {
\t\tret = -EOPNOTSUPP;
\t}

\tinode_unlock(inode);
\treturn ret;
}
"""

_CALLER_UNLOCKED = """
long sample_ioctl(struct inode *inode, loff_t offset, loff_t len)
{
\treturn sample_collapse_range(inode, offset, len);
}
"""

_REL = "fs/sample/file.c"

_TOCTOU_MECH = (
    "TOCTOU race (CWE-362, CWE-367): the i_size check at the top of "
    "sample_collapse_range can go stale before do_collapse runs — the "
    "check is outside any lock in this function"
)
_CALLER_HELD_COUNTER = (
    "The only caller sample_fallocate holds inode_lock(inode) across "
    "the call, so the check and the collapse execute in one serialized "
    "region"
)
_OWN_LOCK_COUNTER = (
    "The function takes its own spin_lock internally around the "
    "critical section"
)


@dataclass
class _Outcome:
    file: str = _REL
    function: str = "sample_collapse_range"
    status: str = "clean"
    line: int = 3
    body: str = ""
    hypothesis: str = ""
    hypotheses: Optional[list] = None
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None


@dataclass
class _Receipt:
    check_type: str = "shared_writer_race"
    function: str = "sample_collapse_range"
    file: str = _REL


@dataclass
class _Config:
    """Minimal OrchestratorConfig stand-in (base-compatible plumbing:
    the gate reads target_path/out_dir/repo_trusted off *config* when
    the explicit kwargs are not passed)."""

    target_path: Optional[Path] = None
    out_dir: Optional[Path] = None
    repo_trusted: bool = True


def _write_tu(tmp_path: Path, tu_text: str) -> Path:
    root = tmp_path / "target"
    p = root / _REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tu_text)
    return root


def _hyp(mechanism: str, counter: str = _CALLER_HELD_COUNTER) -> dict:
    return {"confidence": "refuted", "mechanism": mechanism,
            "counter": counter}


def _records(out_dir: Path) -> list:
    p = out_dir / "suppressions.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# Discharge (red on trees without the witness)
# ---------------------------------------------------------------------------


class TestDischarge:
    def test_caller_locked_tu_discharges_toctou_dismissal(self, tmp_path):
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE, target_path=target, out_dir=out,
            repo_trusted=True,
        )
        assert rv is None

    def test_discharge_writes_accept_record(self, tmp_path):
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
        )
        recs = _records(out)
        assert len(recs) == 1
        rec = recs[0]
        assert rec["verdict"] == "callerlock_witness_corroborates_dismissal"
        assert rec["dropped"] is False
        assert rec["rule_id"] == "audit:callerlock-witness"
        assert rec["file_path"] == _REL
        assert rec["function"] == "sample_collapse_range"
        assert rec["witness"] == "caller_lock"
        assert rec["floor_gate"] == "cwe_allowlist"
        assert rec["lock_class"] == "inode_lock"
        assert rec["lock_object"] == "inode"
        assert rec["call_sites"] == 1
        assert rec["callers"] == ["sample_fallocate"]

    def test_race_only_cwe_discharges_too(self, tmp_path):
        # CWE-362 without the TOCTOU tag: still in family, still
        # floored by the allowlist on the base tree, still discharged.
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "Race (CWE-362): i_size can change between the check and "
            "the collapse — no lock is taken in this function",
        )])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is None
        assert len(_records(out)) == 1


# ---------------------------------------------------------------------------
# Floor stands (must pass on every tree, before and after the witness)
# ---------------------------------------------------------------------------


class TestFloorStands:
    def test_unlocked_second_caller_floors(self, tmp_path):
        # The dismissal's claim is FALSE: a second TU-local caller
        # reaches the function without the lock.  The floor must hold
        # and no witness record may exist.
        target = _write_tu(
            tmp_path, _CALLEE + _CALLER_LOCKED + _CALLER_UNLOCKED,
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.gate == "anti_self_refutation"
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_address_taken_escape_floors(self, tmp_path):
        target = _write_tu(
            tmp_path,
            _CALLEE + _CALLER_LOCKED
            + "\nstatic const struct collapse_ops ops = {\n"
            "\t.collapse = sample_collapse_range,\n};\n",
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_out_of_family_own_lock_counter_floors_without_probe(
        self, tmp_path,
    ):
        # The counter attributes safety to the function's OWN locking
        # — not the caller's.  The fence must keep the witness out.
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH, _OWN_LOCK_COUNTER)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_mixed_race_and_lifetime_claim_floors(self, tmp_path):
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "Race and lifetime (CWE-362, CWE-416): the inode could be "
            "freed while sample_collapse_range runs",
        )])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_untrusted_repo_floors_without_probe(self, tmp_path):
        # TU-locality claims are launderable by a crafted tree — the
        # discharge arm runs only under the operator's repo-trust
        # assertion.
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(
                target_path=target, out_dir=out, repo_trusted=False,
            ),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_explicit_untrusted_overrides_config_trust(self, tmp_path):
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
            repo_trusted=False,
        )
        assert rv is not None
        assert _records(out) == []

    def test_structural_receipt_blocks_discharge(self, tmp_path):
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
            negative_space=[_Receipt()],
        )
        assert rv is not None
        assert _records(out) == []

    def test_unrecordable_discharge_refused(self, tmp_path):
        # No out_dir → the accept-with-record row cannot be written →
        # the discharge must not happen (never-silent contract).
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=None),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"

    def test_go_source_never_consults_witness(self, tmp_path):
        # A Go function with caller-held-lock phrasing must floor
        # with zero witness records — the witness is C-only by
        # construction (shared-writer shapes stay with their floor).
        root = tmp_path / "target"
        p = root / "pkg/stream/writer.go"
        p.parent.mkdir(parents=True)
        p.write_text(
            "package stream\n\n"
            "func (w *Writer) WriteBanner(b []byte) error {\n"
            "\treturn nil\n}\n",
        )
        out = tmp_path / "out"
        o = _Outcome(
            file="pkg/stream/writer.go",
            function="WriteBanner",
            hypotheses=[_hyp(
                "Race (CWE-362): concurrent WriteBanner calls "
                "interleave on w.out without a mutex",
                "Callers hold the display mutex across the call",
            )],
        )
        rv = rescue_self_refuted(
            o,
            source=(
                "func (w *Writer) WriteBanner(b []byte) error {\n"
                "\treturn nil\n}\n"
            ),
            config=_Config(target_path=root, out_dir=out),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_missing_target_path_floors(self, tmp_path):
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_TOCTOU_MECH)])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=None, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_pure_toctou_claim_never_floors_and_writes_no_record(
        self, tmp_path,
    ):
        # CWE-367 alone is outside the allowlist floor: the caller-lock
        # discharge arm must not fire.  The anti-self-refutation gate
        # catches the cross-function counter (keyword fallback detects
        # "caller" + "holds"), which is correct — but the caller-lock
        # gate itself must not manufacture a discharge record.
        target = _write_tu(tmp_path, _CALLEE + _CALLER_LOCKED)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "TOCTOU (CWE-367): the i_size check can go stale before "
            "the collapse under an unlocked window",
        )])
        rv = rescue_self_refuted(
            o, source=_CALLEE,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.gate == "anti_self_refutation"
        assert _records(out) == []


# ---------------------------------------------------------------------------
# Claim-phrasing fence
# ---------------------------------------------------------------------------


class TestClaimFence:
    def _fence(self):
        from core.audit.refutation import _callerlock_claim_in_family
        return _callerlock_claim_in_family

    def test_caller_holds_counter_in_family(self):
        fence = self._fence()
        assert fence(_TOCTOU_MECH, _CALLER_HELD_COUNTER)

    def test_caller_held_phrasings_in_family(self):
        fence = self._fence()
        for counter in (
            "the serialization is the caller-held inode_lock",
            "every caller takes _lock before calling this helper",
            "sample_fallocate holds i_rwsem across the call",
            "called with inode_lock held by the fallocate path",
            "the mutex is held by the caller for the whole call",
            "serialized by the caller via inode_lock",
        ):
            assert fence(_TOCTOU_MECH, counter), counter

    def test_own_locking_out_of_family(self):
        fence = self._fence()
        assert not fence(_TOCTOU_MECH, _OWN_LOCK_COUNTER)

    def test_no_lock_token_out_of_family(self):
        fence = self._fence()
        assert not fence(
            "Race (CWE-362): the size check can go stale",
            "the caller holds a reference for the whole call",
        )

    def test_single_threaded_claim_out_of_family(self):
        fence = self._fence()
        assert not fence(
            "Race (CWE-362): unlocked update of the shared counter",
            "the program is single-threaded at this point, locking "
            "is unnecessary",
        )

    def test_rcu_only_claim_out_of_family(self):
        fence = self._fence()
        assert not fence(
            "Race (CWE-362): the list walk is not under the lock",
            "readers are protected by RCU, no lock needed",
        )

    def test_callee_acquires_internally_out_of_family(self):
        fence = self._fence()
        assert not fence(
            "Race (CWE-362): unlocked field update",
            "the callee acquires the mutex internally",
        )

    def test_mechanism_may_carry_the_attribution(self):
        fence = self._fence()
        assert fence(
            "Race (CWE-362) dismissed: inode_lock is held by the "
            "caller around this helper",
            "",
        )
