"""Canonicalisation-generation verification for journal-row tokens.

A token attests one exact canonical byte form, and that form is a
shipped artifact: when it drifts between mint and verify, every honest
prior row demotes at once and a follow-on run re-buys reviews that were
already paid for (an exhaustive audit run of a large C codebase lost
1,490 prior verdicts to one such fold). These tests pin the
generation-aware verification that absorbs such drift WITHOUT weakening
the fail-closed posture:

* the token grammar is a closed enumeration (no normalising matches);
* a forged row — any MAC-covered byte flipped — fails EVERY supported
  generation and every enumerated form (the mutation matrix);
* legacy-generation and raw-form verification grant the same authority
  as the current form, and the index merge re-stamps upgraded rows;
* the ladder and the per-generation field vocabulary are bounded,
  closed sets kept in lockstep with the live schema.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.coverage import journal, journal_mac
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_entries,
    merge_into_index,
    now_iso,
)


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _entry(**kw) -> ReviewJournalEntry:
    base = dict(ts=now_iso(), run_id="run-x", file="a.c", function="f",
                verdict="clean", source_hash="ab12", line_start=1, line_end=2)
    base.update(kw)
    return ReviewJournalEntry(**base)


def _stamped_run(tmp_path: Path, **kw) -> tuple[Path, dict]:
    run = tmp_path / "run-gen"
    run.mkdir(exist_ok=True)
    append_entry(run, _entry(**kw))
    return run, json.loads((run / "review-journal.jsonl").read_text())


HEX = "a" * 64


# ---------------------------------------------------------------------------
# Token grammar: closed, non-normalising
# ---------------------------------------------------------------------------


class TestTokenGrammar:
    def test_bare_lowercase_hex_is_generation_one(self) -> None:
        assert journal_mac.parse_token(HEX) == (1, HEX)

    def test_tagged_generations_parse(self) -> None:
        assert journal_mac.parse_token(f"g2:{HEX}") == (2, HEX)
        assert journal_mac.parse_token(f"g17:{HEX}") == (17, HEX)
        assert journal_mac.token_generation(f"g2:{HEX}") == 2

    @pytest.mark.parametrize("bad", [
        f"g1:{HEX}",        # gen 1 has ONE shipped byte form: bare hex
        f"g01:{HEX}",       # leading zero — no alternate spellings
        f"g02:{HEX}",
        f"g1234:{HEX}",     # >3 digits — bounded generation numbers
        f"G2:{HEX}",        # uppercase tag never shipped
        f"g2:{HEX.upper()}",  # uppercase hex never shipped
        HEX.upper(),
        f" {HEX}",          # whitespace is not stripped, not normalised
        f"{HEX} ",
        f"g2: {HEX}",
        HEX[:-1],           # short hex
        f"{HEX}0",          # long hex
        f"g2:{HEX[:-1]}",
        f"g:{HEX}",
        f"g-2:{HEX}",
        "",
        "g2:",
    ])
    def test_malformed_tokens_parse_nowhere(self, bad: str) -> None:
        assert journal_mac.parse_token(bad) is None

    def test_non_string_tokens_parse_nowhere(self) -> None:
        for bad in (None, 7, b"g2:" + HEX.encode(), ["g2", HEX]):
            assert journal_mac.parse_token(bad) is None


# ---------------------------------------------------------------------------
# Ladder + vocabulary bounds (churn-prone limits: both directions)
# ---------------------------------------------------------------------------


class TestLadderBounds:
    def test_ladder_never_exceeds_max(self) -> None:
        # Too-large direction: each rung is one more forgeable byte
        # form and one more HMAC on every fold demote path.
        assert (len(journal_mac._KNOWN_GENERATIONS)
                <= journal_mac._GENERATION_LADDER_MAX)

    def test_ladder_always_holds_gen_one_and_current(self) -> None:
        # Too-small direction: dropping either rung demotes every
        # honest row still carrying its token — the mass forfeiture
        # this machinery exists to prevent.
        assert 1 in journal_mac._KNOWN_GENERATIONS
        assert (journal_mac.GENERATION_CURRENT
                in journal_mac._KNOWN_GENERATIONS)

    def test_every_generation_has_a_vocabulary(self) -> None:
        for gen in journal_mac._KNOWN_GENERATIONS:
            assert gen in journal_mac._GENERATION_VOCABULARY

    def test_vocabulary_lockstep_with_dataclass(self) -> None:
        """The current generation's vocabulary is exactly the live
        dataclass fields plus enumerated retired names — extending the
        schema without recording the field here fails this test, so
        the shipped vocabulary can never silently lag (rows stamping
        the new field would then demote on the raw-form rung), and it
        can never grow beyond what actually shipped (an unshipped
        vocabulary name would be a fuzzy allowance, not a record)."""
        vocab = journal_mac._GENERATION_VOCABULARY[
            journal_mac.GENERATION_CURRENT]
        live = journal._ENTRY_FIELD_NAMES
        assert live <= vocab
        assert vocab - live == journal_mac.RETIRED_ROW_FIELDS


# ---------------------------------------------------------------------------
# Mutation matrix: forged rows fail EVERY generation
# ---------------------------------------------------------------------------


#: MAC-covered content mutations — one per representative field class.
_MUTATIONS = [
    ("verdict", "finding"),
    ("source_hash", "ab13"),
    ("run_id", "run-y"),
    ("body", "planted prose"),
    ("line_start", 2),
    ("reused_from_run", "other-run"),
]


class TestMutationMatrix:
    @pytest.mark.parametrize(("field", "value"), _MUTATIONS)
    def test_gen1_token_fails_on_any_covered_byte_flip(
            self, tmp_path: Path, field: str, value) -> None:
        run, row = _stamped_run(tmp_path)
        row[field] = value
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run, fresh=True)[0]
        tier, reason = journal_mac.entry_provenance_detail(entry)
        assert tier == journal_mac.ROW_TAMPERED
        assert reason == journal_mac.REASON_HASH_MISMATCH

    @pytest.mark.parametrize(("field", "value"), _MUTATIONS)
    def test_gen2_token_fails_on_any_covered_byte_flip(
            self, tmp_path: Path, monkeypatch, field: str, value) -> None:
        """Same matrix under a (test-registered) generation 2: the
        tagged form is just as fail-closed."""
        monkeypatch.setattr(journal_mac, "GENERATION_CURRENT", 2)
        monkeypatch.setattr(
            journal_mac, "_KNOWN_GENERATIONS", frozenset({1, 2}))
        run, row = _stamped_run(tmp_path)
        assert str(row[journal_mac.TOKEN_KEY]).startswith("g2:")
        row[field] = value
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run, fresh=True)[0]
        tier, reason = journal_mac.entry_provenance_detail(entry)
        assert tier == journal_mac.ROW_TAMPERED
        assert reason == journal_mac.REASON_HASH_MISMATCH

    def test_genuine_rows_verify_on_both_generations(
            self, tmp_path: Path, monkeypatch) -> None:
        run, _row = _stamped_run(tmp_path)
        entry = load_entries(run, fresh=True)[0]
        assert journal_mac.entry_provenance_detail(entry) == (
            journal_mac.ROW_VERIFIED, journal_mac.REASON_CURRENT_FORM)

        monkeypatch.setattr(journal_mac, "GENERATION_CURRENT", 2)
        monkeypatch.setattr(
            journal_mac, "_KNOWN_GENERATIONS", frozenset({1, 2}))
        run2 = tmp_path / "run-g2"
        run2.mkdir()
        append_entry(run2, _entry(run_id="run-g2"))
        entry2 = load_entries(run2)[0]
        assert journal_mac.entry_provenance_detail(entry2) == (
            journal_mac.ROW_VERIFIED, journal_mac.REASON_CURRENT_FORM)
        # And the gen-1 row now verifies as LEGACY — same tier.
        assert journal_mac.entry_provenance_detail(entry) == (
            journal_mac.ROW_VERIFIED, journal_mac.REASON_LEGACY_GENERATION)

    def test_cross_generation_token_confusion_fails(
            self, tmp_path: Path, monkeypatch) -> None:
        """The generation is bound into the MAC message: relabelling a
        genuine token with another generation's tag never verifies in
        either direction."""
        monkeypatch.setattr(
            journal_mac, "_KNOWN_GENERATIONS", frozenset({1, 2}))
        run, row = _stamped_run(tmp_path)
        gen1_mac = row[journal_mac.TOKEN_KEY]

        row[journal_mac.TOKEN_KEY] = f"g2:{gen1_mac}"
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run, fresh=True)[0]
        tier, reason = journal_mac.entry_provenance_detail(entry)
        assert tier == journal_mac.ROW_TAMPERED
        assert reason == journal_mac.REASON_HASH_MISMATCH

        # Mint at gen 2, present bare (claiming gen 1).
        scrubbed = {k: v for k, v in row.items()
                    if k != journal_mac.TOKEN_KEY}
        gen2_token = journal_mac._mint(
            scrubbed, journal_mac._JOURNAL_DOMAIN, generation=2)
        assert gen2_token is not None and gen2_token.startswith("g2:")
        row[journal_mac.TOKEN_KEY] = gen2_token.removeprefix("g2:")
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run, fresh=True)[0]
        assert (journal_mac.entry_provenance(entry)
                == journal_mac.ROW_TAMPERED)

    def test_unknown_generation_fails_closed(self, tmp_path: Path) -> None:
        run, row = _stamped_run(tmp_path)
        row[journal_mac.TOKEN_KEY] = f"g9:{HEX}"
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run, fresh=True)[0]
        assert journal_mac.entry_provenance_detail(entry) == (
            journal_mac.ROW_TAMPERED, journal_mac.REASON_UNKNOWN_GENERATION)

    def test_malformed_token_fails_closed(self, tmp_path: Path) -> None:
        run, row = _stamped_run(tmp_path)
        row[journal_mac.TOKEN_KEY] = f"g01:{HEX}"
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run, fresh=True)[0]
        assert journal_mac.entry_provenance_detail(entry) == (
            journal_mac.ROW_TAMPERED, journal_mac.REASON_MALFORMED_TOKEN)


# ---------------------------------------------------------------------------
# Raw-form rung: lossy projection under version skew
# ---------------------------------------------------------------------------


def _skewed_reader(monkeypatch, dropped: str) -> None:
    """Simulate a reader whose dataclass round-trip loses *dropped* —
    the version-skew shape that read honest rows as tampered (the
    incident's field was the slim-clean ``body_offload`` pointer)."""
    real_to_dict = ReviewJournalEntry.to_dict

    def lossy_to_dict(self):
        d = real_to_dict(self)
        d.pop(dropped, None)
        return d

    monkeypatch.setattr(ReviewJournalEntry, "to_dict", lossy_to_dict)
    # raising=False: the name does not exist on pre-fix checkouts —
    # the same test file must run RED there, not error at setup.
    monkeypatch.setattr(
        journal, "_ENTRY_FIELD_NAMES",
        frozenset(journal._ENTRY_FIELD_NAMES) - {dropped}
        if hasattr(journal, "_ENTRY_FIELD_NAMES") else frozenset(),
        raising=False)


_OFFLOAD = {"sidecar": "review-journal-bodies.jsonl", "offset": 0,
            "bytes": 10, "sha256": "ab", "fields": ["body"]}


class TestRawFormRung:
    def test_lossy_projection_row_verifies_via_raw_form(
            self, tmp_path: Path, monkeypatch) -> None:
        run, _row = _stamped_run(tmp_path, body_offload=_OFFLOAD)
        _skewed_reader(monkeypatch, "body_offload")
        entry = load_entries(run, fresh=True)[0]
        assert "body_offload" not in entry.to_dict()  # projection IS lossy
        assert journal_mac.entry_provenance_detail(entry) == (
            journal_mac.ROW_VERIFIED, journal_mac.REASON_RAW_FORM)

    def test_raw_form_still_fails_on_forged_content(
            self, tmp_path: Path, monkeypatch) -> None:
        """The raw rung is verification, not tolerance: flip a covered
        byte in the persisted row and the skewed reader still demotes."""
        run, row = _stamped_run(tmp_path, body_offload=_OFFLOAD)
        row["verdict"] = "finding"
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        _skewed_reader(monkeypatch, "body_offload")
        entry = load_entries(run, fresh=True)[0]
        assert journal_mac.entry_provenance_detail(entry) == (
            journal_mac.ROW_TAMPERED, journal_mac.REASON_HASH_MISMATCH)

    def test_raw_form_refuses_fields_outside_shipped_vocabulary(
            self, tmp_path: Path, monkeypatch) -> None:
        """The covered-additive-field invariant survives the rung: a
        MAC-covered field OUTSIDE the enumerated shipped vocabulary
        (a future writer's possibly authority-bearing flag) demotes,
        exactly as test_covered_additive_field_demotes_to_tampered
        pins for the projection path."""
        run, row = _stamped_run(tmp_path)
        row.pop(journal_mac.TOKEN_KEY, None)
        row["future_field"] = {"authority": "gate"}
        row[journal_mac.TOKEN_KEY] = journal_mac.mint_row(row)
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run, fresh=True)[0]
        # Loader stashed the raw form (the extra key is unknown to the
        # dataclass), but the vocabulary bound refuses it.
        assert getattr(entry, journal_mac.RAW_FORM_ATTR, None) is not None
        assert journal_mac.entry_provenance_detail(entry) == (
            journal_mac.ROW_TAMPERED, journal_mac.REASON_HASH_MISMATCH)

    def test_programmatic_entries_have_no_raw_form(self) -> None:
        # The stash attests AS-LOADED bytes only; a constructed entry
        # verifies via the projection or not at all.
        assert getattr(_entry(), journal_mac.RAW_FORM_ATTR, None) is None


# ---------------------------------------------------------------------------
# Merge-time upgrade re-stamp
# ---------------------------------------------------------------------------


class TestMergeUpgrade:
    def _gen2_world(self, monkeypatch) -> None:
        monkeypatch.setattr(journal_mac, "GENERATION_CURRENT", 2)
        monkeypatch.setattr(
            journal_mac, "_KNOWN_GENERATIONS", frozenset({1, 2}))

    def test_verified_legacy_row_is_restamped_at_current_generation(
            self, tmp_path: Path, monkeypatch) -> None:
        project = tmp_path / "project"
        project.mkdir()
        run = tmp_path / "run1"
        run.mkdir()
        append_entry(run, _entry(run_id="run1"))  # gen-1 token

        self._gen2_world(monkeypatch)
        assert merge_into_index(project, run) == 1
        index = json.loads(
            (project / "review-journal-index.json").read_text())
        rows = [v for v in index["entries"].values() if isinstance(v, dict)]
        assert len(rows) == 1
        token = rows[0][journal_mac.TOKEN_KEY]
        assert token.startswith("g2:")
        assert journal_mac.verify_row(rows[0], token)

    def test_forged_legacy_row_is_stripped_not_upgraded(
            self, tmp_path: Path, monkeypatch) -> None:
        """The upgrade path only ever restates PROVEN provenance: a
        gen-1 token that fails verification is stripped (unstamped
        tier), never laundered into a fresh current-generation stamp."""
        project = tmp_path / "project"
        project.mkdir()
        run = tmp_path / "run1"
        run.mkdir()
        append_entry(run, _entry(run_id="run1"))
        jf = run / "review-journal.jsonl"
        row = json.loads(jf.read_text())
        row["verdict"] = "finding"  # covered byte flip, token kept
        jf.write_text(json.dumps(row) + "\n")

        self._gen2_world(monkeypatch)
        assert merge_into_index(project, run) == 1
        index = json.loads(
            (project / "review-journal-index.json").read_text())
        rows = [v for v in index["entries"].values() if isinstance(v, dict)]
        assert len(rows) == 1
        assert journal_mac.TOKEN_KEY not in rows[0]

    def test_current_generation_rows_keep_their_token_bytes(
            self, tmp_path: Path) -> None:
        # No gratuitous re-mint on the common path.
        project = tmp_path / "project"
        project.mkdir()
        run = tmp_path / "run1"
        run.mkdir()
        append_entry(run, _entry(run_id="run1"))
        original = json.loads(
            (run / "review-journal.jsonl").read_text(),
        )[journal_mac.TOKEN_KEY]
        assert merge_into_index(project, run) == 1
        index = json.loads(
            (project / "review-journal-index.json").read_text())
        rows = [v for v in index["entries"].values() if isinstance(v, dict)]
        assert rows[0][journal_mac.TOKEN_KEY] == original
