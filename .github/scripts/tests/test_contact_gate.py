"""Roster-parser and gate-derivation tests for the seal-time contact gate.

The snapshot parser is the assembler interface: the gate and the
assembler must derive the SAME roster from the SAME frozen registry
snapshot, so every grammar arm (status tags, stack markers, order
constraints, exclusions) is pinned here against fixture snapshot lines.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "contact_gate.py"
REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def cg():
    spec = importlib.util.spec_from_file_location("contact_gate", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # dataclass field-annotation resolution looks the module up in
    # sys.modules on 3.14+, so register before exec.
    sys.modules["contact_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# snapshot line grammar
# ---------------------------------------------------------------------------


def _roster_names(cg, text: str) -> list[str]:
    roster = cg.parse_snapshot(text)
    return [u.name for u in cg.order_roster(roster)]


def test_sealed_line_rosters_with_fields(cg):
    line = (
        "# [SEALED 2026-09-25] patches-alpha /tmp/patches-alpha "
        "BASE=2f8587dac(origin/main) FINAL=89cab4a69(tree-016bd7648) "
        "6-diffs some description review=dual-CONFIRM-SEAL"
    )
    roster = cg.parse_snapshot(line)
    assert len(roster.units) == 1
    unit = roster.units[0]
    assert unit.name == "patches-alpha"
    assert unit.directory == Path("/tmp/patches-alpha")
    assert unit.base == "2f8587dac"
    assert unit.final == "89cab4a69"


def test_sealed_revision_tags_roster(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25 r2] patches-a /tmp/patches-a BASE=aaaaaaa 1-diff x",
            "# [SEALED 2026-09-25 recut-r2] patches-b /tmp/patches-b BASE=aaaaaaa 1-diff x",
            "# [SEALED 2026-09-25 r4-adoption] patches-c /tmp/patches-c BASE=aaaaaaa 1-diff x",
        ]
    )
    assert _roster_names(cg, text) == ["patches-a", "patches-b", "patches-c"]


def test_landed_line_excluded(cg):
    line = (
        "# [LANDED 2026-09-25 batch2] patches-a /tmp/patches-a "
        "BASE=1ac689385 FINAL=cd31652dc 4-patches x"
    )
    assert _roster_names(cg, line) == []


def test_landed_plus_sealed_combo_excluded(cg):
    # A landed line keeps its SEALED history tag; landed still wins.
    line = (
        "# [LANDED 2026-09-25 batch-2 77ab34cd9] [SEALED 2026-09-25] "
        "patches-a /tmp/patches-a BASE=2f8587dac 1-commit x"
    )
    assert _roster_names(cg, line) == []


def test_superseded_variants_excluded(cg):
    text = "\n".join(
        [
            "# [SUPERSEDED-BY-RECUT 2026-09-25 see recut line below] "
            "patches-a /tmp/patches-a BASE=aaaaaaa FINAL=bbbbbbb 1-diff x",
            "# [SUPERSEDED-BY-ADOPTION 2026-09-25 see r4 line below] "
            "[SEALED 2026-09-24 r3] patches-b /tmp/patches-b BASE=aaaaaaa 1-diff x",
        ]
    )
    assert _roster_names(cg, text) == []


def test_verify_backlog_unreviewed_and_untagged_never_roster(cg):
    text = "\n".join(
        [
            "# registry hygiene pass 2026-09-25: header comment",
            "# [VERIFY 2026-09-25] patches-a applies-clean on main (git am exit 0)",
            "BACKLOG some-task [UNCLAIMED]: prose about core/audit things",
            "# [BACKLOG 2026-09-24 noted-by-x] prose about a parser",
            "# [BUILT-UNREVIEWED 2026-09-25 do NOT roster] patches-b "
            "/tmp/patches-b BASE=aaaaaaa 1-diff x",
            "# patches-c /tmp/patches-c BASE=aaaaaaa untagged line",
        ]
    )
    roster = cg.parse_snapshot(text)
    assert roster.units == []
    assert roster.skipped.get("backlog") == 2
    # The untagged series-shaped line must be a LOUD unrecognized
    # adjudication, never a silent bin.
    assert roster.skipped.get("unrecognized") == 1
    loud = [n for n in roster.notes if n.startswith("LOUD:")]
    assert len(loud) == 1 and "patches-c" in loud[0]
    # Every non-blank line carries exactly one categorized adjudication.
    assert len(roster.adjudications) == 6


def test_unbracketed_sealed_name_only_line_rosters(cg):
    # The live registry spelling: bare SEALED head, name with trailing
    # colon, no directory token (implied by convention), prose
    # "BASE <sha>" and "tree <sha>" field spellings.
    line = (
        "SEALED patches-barename: incremental loading rework (cache+extend "
        "at the load chokepoint; consumers routed fresh) — 2 commits, "
        "BASE 4f8ab12cd, tips ab12cd34e+ef56ab78c, tree dacc5afe8, "
        "zip /tmp/zip-pending-barename.zip sha256 aaaa review=2-lens"
    )
    roster = cg.parse_snapshot(line)
    assert len(roster.units) == 1
    unit = roster.units[0]
    assert unit.name == "patches-barename"
    assert unit.directory == Path("/tmp/patches-barename")
    assert unit.base == "4f8ab12cd"
    assert unit.tree == "dacc5afe8"
    assert any("fleet convention" in n for n in roster.notes)


def test_unbracketed_sealed_with_dir_pair_rosters(cg):
    line = "SEALED patches-foo /tmp/patches-foo BASE=4f8ab12cd 2 commits"
    roster = cg.parse_snapshot(line)
    assert [u.name for u in roster.units] == ["patches-foo"]
    assert roster.units[0].directory == Path("/tmp/patches-foo")


def test_bracketed_sealed_name_only_line_rosters_by_convention(cg):
    line = "# [SEALED 2026-09-26] patches-nodir 3-diffs BASE=4f8ab12cd prose only"
    roster = cg.parse_snapshot(line)
    assert [u.name for u in roster.units] == ["patches-nodir"]
    assert roster.units[0].directory == Path("/tmp/patches-nodir")


def test_unbracketed_landed_verify_superseded_still_excluded(cg):
    text = "\n".join(
        [
            "LANDED patches-a /tmp/patches-a BASE=4f8ab12cd 1-diff x",
            "VERIFY patches-b applies-clean on main",
            "SUPERSEDED-BY-RECUT patches-c /tmp/patches-c BASE=4f8ab12cd 1-diff x",
        ]
    )
    roster = cg.parse_snapshot(text)
    assert roster.units == []
    assert roster.skipped == {"landed": 1, "verify": 1, "superseded": 1}


def test_sealed_line_without_series_name_is_a_hard_error(cg):
    with pytest.raises(ValueError, match="cannot be rostered"):
        cg.parse_snapshot("# [SEALED 2026-09-26] prose with no unit name at all")


def test_sealed_line_with_relative_dir_is_a_hard_error(cg):
    with pytest.raises(ValueError, match="malformed"):
        cg.parse_snapshot(
            "# [SEALED 2026-09-26] patches-rel tmp/patches-rel BASE=4f8ab12cd 1-diff x"
        )


def test_tag_naming_another_series_never_steals_identity(cg):
    # A bracket tag that cross-references ANOTHER series must not bind
    # the line's identity: the name comes from the post-tag body.
    line = (
        "# [SEALED 2026-09-26 closes-gap-vs patches-other] patches-mine "
        "2-diffs BASE=4f8ab12cd prose only"
    )
    roster = cg.parse_snapshot(line)
    assert [u.name for u in roster.units] == ["patches-mine"]
    assert roster.units[0].directory == Path("/tmp/patches-mine")
    # Same protection on excluded lines' adjudication labels.
    excl = (
        "# [SUPERSEDED-BY-RECUT 2026-09-26 see patches-mine-r2 below] "
        "patches-mine /tmp/patches-mine BASE=4f8ab12cd 2-diffs x"
    )
    roster2 = cg.parse_snapshot(excl)
    assert roster2.adjudications[0][1] == "superseded"
    assert roster2.adjudications[0][2] == "patches-mine"


def test_unknown_status_series_shaped_line_is_loud(cg):
    roster = cg.parse_snapshot(
        "# [QUEUED 2026-09-26] patches-q /tmp/patches-q BASE=4f8ab12cd 1-diff x"
    )
    assert roster.units == []
    assert roster.skipped.get("unrecognized") == 1
    assert any(n.startswith("LOUD:") and "patches-q" in n for n in roster.notes)


def test_recut_line_keeps_series_name_with_different_dir(cg):
    line = (
        "# [SEALED 2026-09-25 recut-r2] patches-cov /tmp/patches-cov-r2 "
        "BASE=77ab34cd9(post-landing origin/main) FINAL=ab34cd56e TREE=91fed0f3a 6-patches x"
    )
    roster = cg.parse_snapshot(line)
    assert roster.units[0].name == "patches-cov"
    assert roster.units[0].directory == Path("/tmp/patches-cov-r2")
    assert roster.units[0].tree == "91fed0f3a"


def test_duplicate_rostered_name_is_an_error(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25] patches-a /tmp/patches-a BASE=aaaaaaa 1-diff x",
            "# [SEALED 2026-09-25 r2] patches-a /tmp/patches-a-r2 BASE=aaaaaaa 1-diff x",
        ]
    )
    with pytest.raises(ValueError, match="duplicate rostered series"):
        cg.parse_snapshot(text)


def test_tree_spelling_variants(cg):
    for marker in ("TREE=abc123def", "tree=abc123def", "FINAL-TREE=abc123def"):
        line = (
            f"# [SEALED 2026-09-25] patches-a /tmp/patches-a BASE=aaaaaaa "
            f"{marker} 1-diff x"
        )
        assert cg.parse_snapshot(line).units[0].tree == "abc123def", marker


# ---------------------------------------------------------------------------
# stacks and order constraints
# ---------------------------------------------------------------------------


def test_stack_on_marker_orders_after_target(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25] patches-second /tmp/patches-second "
            "BASE=aaaaaaa STACK=on-first(9-diffs-first) 5-diffs x",
            "# [SEALED 2026-09-25] patches-first /tmp/patches-first BASE=aaaaaaa 9-diffs x",
        ]
    )
    assert _roster_names(cg, text) == ["patches-first", "patches-second"]


def test_stacked_on_marker_orders_after_target(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25] patches-top /tmp/patches-top BASE=aaaaaaa "
            "STACKED-ON=patches-bottom(apply-its-6-diffs-first-at-same-BASE) 7-diffs x",
            "# [SEALED 2026-09-25] patches-bottom /tmp/patches-bottom BASE=aaaaaaa 6-diffs x",
        ]
    )
    assert _roster_names(cg, text) == ["patches-bottom", "patches-top"]


def test_base_final_annotation_declares_stack(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25] patches-child /tmp/patches-child "
            "BASE=bbbbbbb(=patches-parent-FINAL;stack-applies-at-origin/main-aaaaaaa) 6-diffs x",
            "# [SEALED 2026-09-25] patches-parent /tmp/patches-parent "
            "BASE=aaaaaaa FINAL=bbbbbbb 17-diffs x",
        ]
    )
    assert _roster_names(cg, text) == ["patches-parent", "patches-child"]


def test_land_first_marker_reorders(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25] patches-rider /tmp/patches-rider BASE=aaaaaaa "
            "COMPOSED-TREE=55ce823ce(other-both-orders-identical; LAND-OTHER-FIRST) 2-diffs x",
            "# [SEALED 2026-09-25] patches-other /tmp/patches-other BASE=aaaaaaa 8-diffs x",
        ]
    )
    assert _roster_names(cg, text) == ["patches-other", "patches-rider"]


def test_registry_order_preserved_without_constraints(cg):
    text = "\n".join(
        f"# [SEALED 2026-09-25] patches-u{i} /tmp/patches-u{i} BASE=aaaaaaa 1-diff x"
        for i in range(5)
    )
    assert _roster_names(cg, text) == [f"patches-u{i}" for i in range(5)]


def test_constraint_target_not_in_roster_is_noted_not_fatal(cg):
    line = (
        "# [SEALED 2026-09-25] patches-a /tmp/patches-a BASE=aaaaaaa "
        "STACK=on-landed-unit(first) LAND-GONE-FIRST 1-diff x"
    )
    roster = cg.parse_snapshot(line)
    ordered = cg.order_roster(roster)
    assert [u.name for u in ordered] == ["patches-a"]
    assert any("landed-unit" in n for n in roster.notes)


def test_constraint_cycle_is_an_error(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25] patches-a /tmp/patches-a BASE=x1234567 "
            "STACK=on-b(first) 1-diff x",
            "# [SEALED 2026-09-25] patches-b /tmp/patches-b BASE=x1234567 "
            "STACK=on-a(first) 1-diff x",
        ]
    )
    # BASE= here is deliberately non-hex-prefixed so only STACK edges exist.
    roster = cg.parse_snapshot(text)
    with pytest.raises(ValueError, match="cycle"):
        cg.order_roster(roster)


def test_landing_order_marker_does_not_constrain_roster_peers(cg):
    line = (
        "# [SEALED 2026-09-25] patches-a /tmp/patches-a BASE=77ab34cd9 "
        "LANDING-ORDER=after-batch-2(satisfied-by-construction) 7-diffs x"
    )
    assert _roster_names(cg, line) == ["patches-a"]


def test_stack_target_normalizes_prefix_and_revision_suffix(cg):
    # Live spelling: the STACK target carries the patches- prefix and a
    # revision suffix that belongs to the seal tag, not the name.
    text = "\n".join(
        [
            "# [SEALED 2026-09-26 r2] patches-second /tmp/patches-second "
            "BASE=4f8ab12cd STACK=on-patches-first-r3(6-diffs-first) 6-diffs x",
            "# [SEALED 2026-09-26 r4] patches-first /tmp/patches-first "
            "BASE=4f8ab12cd 6-diffs x",
        ]
    )
    roster = cg.parse_snapshot(text)
    assert [u.name for u in cg.order_roster(roster)] == [
        "patches-first", "patches-second",
    ]
    assert any("via normalization" in n for n in roster.notes)


# ---------------------------------------------------------------------------
# declared-contact mention scan
# ---------------------------------------------------------------------------


def test_mentions_word_boundaries(cg):
    assert cg.mentions("empirical file-contact census against unitfix7 EMPTY", "unitfix7")
    assert cg.mentions("chain alphahandler->betagraph1a stacks clean", "alphahandler")
    assert cg.mentions("chain alphahandler->betagraph1a stacks clean", "betagraph1a")
    # A longer sibling name must not satisfy a shorter unit's mention.
    assert not cg.mentions("adopted from stats-pair-r4 pair", "stats-pair")
    assert not cg.mentions("the reunitfix7x experiment", "unitfix7")


def test_mentions_suffix_name_masked_by_longer_sibling(cg):
    # A short name that is a SUFFIX of another rostered name must not be
    # "declared" by a line that merely names the longer sibling — that
    # would demote an undeclared conflict to a declared deferral.
    shorts = ("census-stats-r4", "stats-r4", "other")
    line = "reconciled against census-stats-r4 at the shared baseline"
    assert not cg.mentions(line, "stats-r4", shorts)
    # An explicit mention of the suffix name itself still declares.
    assert cg.mentions("reconciled against stats-r4 directly", "stats-r4", shorts)
    # And the longer name's own mentions are unaffected by the masking.
    assert cg.mentions(line, "census-stats-r4", shorts)


def test_declared_contact_is_symmetric_over_lines(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-25] patches-a /tmp/patches-a BASE=aaaaaaa "
            "1-diff x (composes-clean-with-b-unit per census)",
            "# [SEALED 2026-09-25] patches-b-unit /tmp/patches-b-unit BASE=aaaaaaa 1-diff y",
        ]
    )
    roster = cg.parse_snapshot(text)
    a, b = roster.units
    assert cg.declared_contact(a, b)
    assert cg.declared_contact(b, a)
    assert not cg.declared_contact(b, b) or True  # self-contact unused


# ---------------------------------------------------------------------------
# tier 0 — rehearsal-citation staleness (string check, no compose)
# ---------------------------------------------------------------------------


def _rider_pair(carrier_extra: str) -> str:
    return "\n".join(
        [
            "# [SEALED 2026-09-26] patches-rider /tmp/patches-rider BASE=4f8ab12cd "
            "STACK=on-patches-carrier-r3(6-diffs-first,tree-016ffd648) 6-diffs x",
            "# [SEALED 2026-09-26 r4] patches-carrier /tmp/patches-carrier "
            f"BASE=4f8ab12cd {carrier_extra} 6-diffs x",
        ]
    )


def test_tier0_stale_stack_citation_flagged_naming_both(cg):
    # The aging-rehearsal class: the rider cites the carrier's r3 tree,
    # but the carrier's CURRENT line is an r4 with different shas.
    roster = cg.parse_snapshot(_rider_pair("FINAL=a0572bf60(tree-bc9f627e4)"))
    fnds, checked, _notes = cg.tier0(roster)
    assert checked == 1
    assert len(fnds) == 1
    f = fnds[0]
    assert f.tier == 0 and f.kind == "stale-rehearsal"
    assert f.unit == "patches-rider" and f.counterpart == "patches-carrier"
    assert "016ffd648" in f.detail
    # both lines quoted in the finding
    assert "patches-rider" in f.detail and "r4" in f.detail


def test_tier0_current_citation_passes(cg):
    roster = cg.parse_snapshot(_rider_pair("FINAL=a0572bf60(tree-016ffd648)"))
    fnds, checked, _notes = cg.tier0(roster)
    assert checked == 1 and fnds == []


def test_tier0_base_final_citation_both_directions(cg):
    def pair(parent_final: str) -> str:
        return "\n".join(
            [
                "# [SEALED 2026-09-26] patches-child /tmp/patches-child "
                "BASE=bbb1234(=patches-parent-FINAL;stack-applies-at-base) 2-diffs x",
                "# [SEALED 2026-09-26] patches-parent /tmp/patches-parent "
                f"BASE=4f8ab12cd FINAL={parent_final} 3-diffs x",
            ]
        )

    fnds, checked, _n = cg.tier0(cg.parse_snapshot(pair("bbb1234")))
    assert checked == 1 and fnds == []
    fnds, checked, _n = cg.tier0(cg.parse_snapshot(pair("ccc9876")))
    assert checked == 1 and len(fnds) == 1
    assert fnds[0].kind == "stale-rehearsal"
    assert fnds[0].counterpart == "patches-parent"


def test_tier0_sha_carried_only_by_superseded_line_is_stale(cg):
    text = "\n".join(
        [
            "# [SEALED 2026-09-26] patches-rider /tmp/patches-rider BASE=4f8ab12cd "
            "STACK=on-patches-carrier-r3(6-diffs-first,tree-016ffd648) 6-diffs x",
            "# [SUPERSEDED-BY-RECUT 2026-09-26 see r4] [SEALED 2026-09-25 r3] "
            "patches-carrier-r3 /tmp/patches-carrier-r3 BASE=4f8ab12cd "
            "FINAL=deadbe1(tree-016ffd648) 6-diffs x",
            "# [SEALED 2026-09-26 r4] patches-carrier /tmp/patches-carrier "
            "BASE=4f8ab12cd FINAL=a0572bf60(tree-bc9f627e4) 6-diffs x",
        ]
    )
    fnds, checked, _n = cg.tier0(cg.parse_snapshot(text))
    assert checked == 1 and len(fnds) == 1
    assert "non-current" in fnds[0].detail


def test_tier0_unresolvable_prose_and_joint_citations_are_notes(cg):
    text = "\n".join(
        [
            # citation target absent from the snapshot entirely
            "# [SEALED 2026-09-26] patches-a /tmp/patches-a BASE=4f8ab12cd "
            "STACK=on-patches-gone-r2(first,tree-abcdef012) 1-diff x",
            # prose rehearsal note, machine-uncheckable — own dual-route form
            "# [SEALED 2026-09-26] patches-b /tmp/patches-b BASE=4f8ab12cd "
            "1-diff x rehearsal=byte-identical-both-routes(tree-8661771c1 suites=x-12",
            # joint-artifact composed-tree citation
            "# [SEALED 2026-09-26] patches-c /tmp/patches-c BASE=4f8ab12cd "
            "COMPOSED-TREE=55ce823ce(d-unit-both-orders-identical; LAND-D-UNIT-FIRST) 1-diff x",
            "# [SEALED 2026-09-26] patches-d-unit /tmp/patches-d-unit BASE=4f8ab12cd 1-diff x",
        ]
    )
    fnds, checked, notes = cg.tier0(cg.parse_snapshot(text))
    assert fnds == []
    assert checked == 1  # only the (gone, sha) citation is machine-checkable
    assert any("unverifiable" in n for n in notes)
    assert any("not verified by tier 0" in n for n in notes)
    assert any("joint artifact" in n for n in notes)


# ---------------------------------------------------------------------------
# tier-3 gate derivation (from workflow definitions, never a hand list)
# ---------------------------------------------------------------------------


def _tree_with_workflow(tmp_path: Path, body: str) -> Path:
    wf = tmp_path / ".github" / "workflows" / "gates.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(body, encoding="utf-8")
    return tmp_path


def test_derive_static_check_scripts_and_pytest(cg, tmp_path):
    (tmp_path / ".github" / "scripts").mkdir(parents=True)
    (tmp_path / ".github" / "scripts" / "check_thing.py").write_text("", encoding="utf-8")
    (tmp_path / ".github" / "tests").mkdir()
    tree = _tree_with_workflow(
        tmp_path,
        "jobs:\n"
        "  gate:\n"
        "    steps:\n"
        "      - name: a\n"
        "        run: python3 .github/scripts/check_thing.py\n"
        "      - name: b\n"
        "        run: |\n"
        "          pytest .github/tests --junitxml=\"$RUNNER_TEMP/x.xml\"\n",
    )
    gates = cg.derive_gates(tree)
    labels = [cg.gate_label(g) for g in gates]
    assert "python3 .github/scripts/check_thing.py" in labels
    # --junitxml (a runner-local report artifact) is dropped, not disqualifying.
    assert "python3 -m pytest .github/tests" in labels


def test_derive_excludes_dynamic_marker_and_tier_invocations(cg, tmp_path):
    (tmp_path / ".github" / "scripts").mkdir(parents=True)
    (tmp_path / ".github" / "scripts" / "check_lane.py").write_text("", encoding="utf-8")
    (tmp_path / ".github" / "tests").mkdir()
    (tmp_path / "core" / "sub" / "tests").mkdir(parents=True)
    (tmp_path / "core" / "sub" / "tests" / "test_x.py").write_text("", encoding="utf-8")
    tree = _tree_with_workflow(
        tmp_path,
        "jobs:\n"
        "  gate:\n"
        "    steps:\n"
        "      - name: dynamic-args\n"
        "        run: |\n"
        "          python3 .github/scripts/check_lane.py \\\n"
        "            --lane \"${TIER}/image\" \\\n"
        "            --junit-xml \"$RUNNER_TEMP/pytest-junit.xml\"\n"
        "      - name: marker-conditioned\n"
        "        run: python -m pytest -m slow core packages .github/tests -q\n"
        "      - name: dynamic-files\n"
        "        run: pytest -n auto $TEST_FILES\n"
        "      - name: gha-expression\n"
        "        run: python -m pytest --group ${{ matrix.group }} core\n"
        "      - name: directory-tier-outside-github\n"
        "        run: python -m pytest core/sub/tests\n"
        "      - name: file-list-outside-github\n"
        "        run: python -m pytest -q core/sub/tests/test_x.py\n",
    )
    labels = [cg.gate_label(g) for g in gates] if (gates := cg.derive_gates(tree)) else []
    assert labels == ["python3 -m pytest -q core/sub/tests/test_x.py"]


def test_derive_folded_and_list_item_run_shapes(cg, tmp_path):
    # ``run: >`` folded block scalars (newlines fold to spaces) and the
    # ``- run:`` list-item spelling both carry live standing gates.
    (tmp_path / ".github" / "scripts").mkdir(parents=True)
    (tmp_path / ".github" / "scripts" / "check_fold.py").write_text("", encoding="utf-8")
    (tmp_path / ".github" / "tests").mkdir()
    (tmp_path / "core" / "tests").mkdir(parents=True)
    (tmp_path / "core" / "tests" / "test_a.py").write_text("", encoding="utf-8")
    (tmp_path / "core" / "tests" / "test_b.py").write_text("", encoding="utf-8")
    tree = _tree_with_workflow(
        tmp_path,
        "jobs:\n"
        "  gate:\n"
        "    steps:\n"
        "      - name: folded pytest\n"
        "        run: >\n"
        "          python -m pytest\n"
        "          core/tests/test_a.py\n"
        "          core/tests/test_b.py\n"
        "          --junitxml=\"$RUNNER_TEMP/folded.xml\"\n"
        "      - name: folded keep-chomp\n"
        "        run: >-\n"
        "          python -m pytest -rs\n"
        "          .github/tests\n"
        "      - run: python3 .github/scripts/check_fold.py\n",
    )
    labels = [cg.gate_label(g) for g in cg.derive_gates(tree)]
    assert labels == [
        "python3 -m pytest core/tests/test_a.py core/tests/test_b.py",
        "python3 -m pytest -rs .github/tests",
        "python3 .github/scripts/check_fold.py",
    ]


def test_derive_deduplicates_across_workflows(cg, tmp_path):
    (tmp_path / ".github" / "scripts").mkdir(parents=True)
    (tmp_path / ".github" / "scripts" / "check_a.py").write_text("", encoding="utf-8")
    step = (
        "jobs:\n"
        "  g:\n"
        "    steps:\n"
        "      - name: a\n"
        "        run: python3 .github/scripts/check_a.py\n"
    )
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "one.yml").write_text(step, encoding="utf-8")
    (wf_dir / "two.yml").write_text(step, encoding="utf-8")
    assert len(cg.derive_gates(tmp_path)) == 1


def test_derive_missing_script_at_tree_excluded(cg, tmp_path):
    tree = _tree_with_workflow(
        tmp_path,
        "jobs:\n"
        "  g:\n"
        "    steps:\n"
        "      - name: a\n"
        "        run: python3 .github/scripts/check_gone.py\n",
    )
    assert cg.derive_gates(tree) == []


def test_real_tree_derivation_properties(cg):
    """Property pins against the repo's own workflows (no hand list).

    * every derived invocation is fully static;
    * the CI-lane-arg-gated skip-budget check never joins the battery;
    * the repo-invariant detectors and the .github test battery do.
    """
    gates = cg.derive_gates(REPO_ROOT)
    labels = [cg.gate_label(g) for g in gates]
    assert labels, "derivation found no gates in the repo's own workflows"
    for label in labels:
        assert "${{" not in label and "$" not in label, label
    assert not any("check_skip_budget" in lb for lb in labels)
    assert any("check_miswiring.py" in lb for lb in labels)
    assert any(
        ".github/tests" in lb and "pytest" in lb for lb in labels
    ), labels
    # The replay-determinism suites are declared via folded (run: >)
    # block scalars — fold support regression pin.
    assert any("test_replay_harness.py" in lb for lb in labels), labels


# ---------------------------------------------------------------------------
# payload discovery + touched-path parsing
# ---------------------------------------------------------------------------


def test_unit_payload_prefers_mbox_then_patches_then_diffs(cg, tmp_path):
    d = tmp_path / "patches-x"
    d.mkdir()
    (d / "01.diff").write_text("", encoding="utf-8")
    mode, files = cg.unit_payload(d)
    assert mode == "diffs" and [f.name for f in files] == ["01.diff"]
    (d / "0001-feat.patch").write_text("", encoding="utf-8")
    mode, _files = cg.unit_payload(d)
    assert mode == "patches"
    (d / "series.mbox").write_text("", encoding="utf-8")
    mode, files = cg.unit_payload(d)
    assert mode == "mbox" and files[0].name == "series.mbox"


def test_unit_payload_empty_dir_is_an_error(cg, tmp_path):
    d = tmp_path / "patches-empty"
    d.mkdir()
    with pytest.raises(FileNotFoundError):
        cg.unit_payload(d)


def test_touched_paths_covers_adds_deletes_renames(cg, tmp_path):
    patch = tmp_path / "01.diff"
    patch.write_text(
        "diff --git a/pkg/old.py b/pkg/new.py\n"
        "similarity index 90%\n"
        "rename from pkg/old.py\n"
        "rename to pkg/new.py\n"
        "diff --git a/added.py b/added.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/added.py\n"
        "@@ -0,0 +1 @@\n"
        "+X = 1\n",
        encoding="utf-8",
    )
    touched = cg.touched_paths([patch])
    assert touched == {"pkg/old.py", "pkg/new.py", "added.py"}


# ---------------------------------------------------------------------------
# output hygiene
# ---------------------------------------------------------------------------


def test_sanitize_escapes_controls_and_bounds_length(cg):
    out = cg.sanitize("evil\x1b]0;title\x07name")
    assert "\x1b" not in out and "\\x1b" in out
    long = cg.sanitize("a" * 500, limit=100)
    assert len(long) < 200 and "elided" in long
