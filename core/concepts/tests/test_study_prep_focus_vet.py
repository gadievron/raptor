"""Tests for the reading-list identifier focus vet in raptor-study-prep.

Defect shape (live-hit): the project concepts store's reading list can
carry a DIFFERENT tree's identifiers (another binary's FUN_* names).
Unvetted, those identifiers become the whole identifier focus, match
zero files in the current tree, and the study "succeeds" with zero
items — silently inheriting the old domain model.  The vet drops
non-resolving identifiers loudly (witnessing on the same key family
the pass-2 filter matches, so it never drops below what the filter
could reach), and an all-dropped focus falls back to the unfocused
default instead of an empty focus — unless another focus source
(--identifier, --correlate, concepts) is live.  study-loop's side of
the same seam: a store-inherited reading list must never re-scope a
run the operator explicitly focused.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

RAPTOR_DIR = Path(__file__).resolve().parents[3]
_PREP_PATH = RAPTOR_DIR / "libexec" / "raptor-study-prep"
_LOOP_PATH = RAPTOR_DIR / "libexec" / "raptor-study-loop"


def _load_prep() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "raptor_study_prep_focus_vet", str(_PREP_PATH))
    spec = importlib.util.spec_from_file_location(
        "raptor_study_prep_focus_vet", str(_PREP_PATH), loader=loader,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prep = _load_prep()

_DROP_LINE = ("reading-list identifiers resolve to no file in this "
              "tree — dropped from focus (different binary?)")


def _run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(  # noqa: PLW1510 - callers assert on returncode
        [sys.executable, str(script)] + args,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _make_tree(tmp_path: Path) -> Path:
    """A small current-tree stand-in (three functions, one struct)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "alpha.c").write_text(
        "struct alpha_ctx {\n    int a;\n};\n"
        "int alpha_ctx_new(void) { return 0; }\n",
        encoding="utf-8",
    )
    (repo / "beta.c").write_text(
        "int beta_ops_run(void) { return 1; }\n", encoding="utf-8",
    )
    (repo / "gamma.c").write_text(
        "int gamma_ops_run(void) { return 2; }\n", encoding="utf-8",
    )
    return repo


def _write_reading_list(path: Path, names: list[str]) -> None:
    """Pending identifier items, one per name.

    ``source_function`` is the anchor real producers stamp (the
    strongest identifier source in ``_load_reading_list``)."""
    items = [
        {
            "id": f"rl-{i}",
            "question": f"What does {name} do?",
            "source_command": "audit",
            "source_function": name,
            "resolved": False,
        }
        for i, name in enumerate(names)
    ]
    path.write_text(json.dumps({"items": items}), encoding="utf-8")


def _study_list(out_dir: Path) -> dict:
    return json.loads(
        (out_dir / "study-list.json").read_text(encoding="utf-8"))


def _item_names(out_dir: Path) -> set[str]:
    return {it["name"] for it in _study_list(out_dir)["items"]}


# ------------------------------------------------------------------
# Vet helper unit tests
# ------------------------------------------------------------------


class TestVetHelper:
    def test_partition_preserves_order(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text("int alpha(void) { return beta(); }\n",
                     encoding="utf-8")
        kept, dropped = prep._vet_reading_list_identifiers(
            ["FUN_00401a2c", "alpha", "FUN_00403000", "beta"], [f])
        assert kept == ["alpha", "beta"]
        assert dropped == ["FUN_00401a2c", "FUN_00403000"]

    def test_case_insensitive_like_pass2(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text("int Alpha_Ctx_new(void) { return 0; }\n",
                     encoding="utf-8")
        kept, dropped = prep._vet_reading_list_identifiers(
            ["ALPHA_CTX"], [f])
        assert kept == ["ALPHA_CTX"]
        assert dropped == []

    def test_unreadable_file_tolerated(self, tmp_path: Path) -> None:
        gone = tmp_path / "missing.c"
        real = tmp_path / "b.c"
        real.write_text("int alpha(void) { return 0; }\n",
                        encoding="utf-8")
        kept, dropped = prep._vet_reading_list_identifiers(
            ["alpha", "FUN_dead"], [gone, real])
        assert kept == ["alpha"]
        assert dropped == ["FUN_dead"]

    def test_empty_input(self, tmp_path: Path) -> None:
        assert prep._vet_reading_list_identifiers([], []) == ([], [])

    def test_type_suffix_family_witnesses(self, tmp_path: Path) -> None:
        """Matcher parity: ``sg_table_t`` is witnessed by a tree that
        spells only ``sg_table`` — the pass-2 filter's key family
        (bare, bare_no_t) can still match there, so the vet must keep
        the identifier instead of false-dropping it."""
        f = tmp_path / "a.c"
        f.write_text("struct sg_table { int nents; };\n",
                     encoding="utf-8")
        kept, dropped = prep._vet_reading_list_identifiers(
            ["sg_table_t"], [f])
        assert kept == ["sg_table_t"]
        assert dropped == []

    def test_struct_prefix_family_witnesses(self, tmp_path: Path) -> None:
        """``struct alpha_ctx`` is witnessed by a bare ``alpha_ctx``
        use — the prefix-stripped family key matches downstream."""
        f = tmp_path / "a.c"
        f.write_text("alpha_ctx x;\n", encoding="utf-8")
        kept, dropped = prep._vet_reading_list_identifiers(
            ["struct alpha_ctx"], [f])
        assert kept == ["struct alpha_ctx"]
        assert dropped == []


# ------------------------------------------------------------------
# Contamination shape through main()
# ------------------------------------------------------------------


class TestForeignReadingList:
    def test_foreign_identifiers_dropped_unfocused_fallback(
        self, tmp_path: Path,
    ) -> None:
        """All-foreign reading list: identifiers dropped loudly, the
        study proceeds with the unfocused default — never a silent
        zero-item success."""
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["FUN_00401a2c", "FUN_00403000"])
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        assert f"2 {_DROP_LINE}" in result.stderr
        assert "proceeding with the unfocused default scope" in result.stderr
        # Unfocused fallback: the tree's own items are studied.
        names = _item_names(out)
        assert "alpha_ctx_new" in names
        assert "beta_ops_run" in names
        # NO silent empty study.
        assert names, "study list must not be empty"
        data = _study_list(out)
        assert data["reading_list_dropped"] == 2
        assert "FUN_00401a2c" in data["reading_list_dropped_names"]

    def test_matching_identifiers_pass_through(
        self, tmp_path: Path,
    ) -> None:
        """A reading list that matches the current tree keeps its
        focusing authority — no drops, focus still narrows."""
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["alpha_ctx"])
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        assert _DROP_LINE not in result.stderr
        assert "reading list added 1 identifiers" in result.stderr
        names = _item_names(out)
        assert "alpha_ctx" in names
        # Focus retained: unrelated functions filtered out.
        assert "gamma_ops_run" not in names
        assert _study_list(out)["reading_list_dropped"] == 0

    def test_mixed_foreign_and_matching(self, tmp_path: Path) -> None:
        """Foreign identifiers drop; matching ones keep focusing."""
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["alpha_ctx", "FUN_deadbeef"])
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        assert f"1 {_DROP_LINE}" in result.stderr
        assert "proceeding with the unfocused default" not in result.stderr
        names = _item_names(out)
        assert "alpha_ctx" in names
        assert "gamma_ops_run" not in names  # focus survives the drop
        data = _study_list(out)
        assert data["reading_list_dropped"] == 1
        assert data["reading_list_dropped_names"] == ["FUN_deadbeef"]

    def test_legacy_rows_are_vetted_too(self, tmp_path: Path) -> None:
        """Minimal legacy-shaped rows (no source_function, no
        resolution, no context) go through the same resolve-keyed
        vet — the filter never depends on newer metadata."""
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        rl.write_text(json.dumps({"items": [
            {"id": "old-1",
             "question": "Explain this function",
             "source_command": "audit",
             "context": "Unresolved function: beta_ops_run"},
            {"id": "old-2",
             "question": "Explain this function",
             "source_command": "audit",
             "context": "Unresolved function: FUN_00404242"},
        ]}), encoding="utf-8")
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        assert f"1 {_DROP_LINE}" in result.stderr
        names = _item_names(out)
        assert "beta_ops_run" in names
        data = _study_list(out)
        assert data["reading_list_dropped_names"] == ["FUN_00404242"]

    def test_operator_identifier_never_vetted(
        self, tmp_path: Path,
    ) -> None:
        """--identifier keeps operator authority: a non-matching
        operator identifier is NOT dropped (and still focuses)."""
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["FUN_00401a2c"])
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--identifier", "zzz_not_in_tree",
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        assert f"1 {_DROP_LINE}" in result.stderr
        # Operator focus stands — no unfocused fallback.
        assert "proceeding with the unfocused default" not in result.stderr

    def test_type_suffix_identifier_keeps_focusing(
        self, tmp_path: Path,
    ) -> None:
        """The sg_table_t shape: the tree spells only ``sg_table``,
        but the downstream filter family still matches — the vet must
        NOT drop it. A literal-spelling vet lost the
        sg_table/sg_table_init items while the surviving focus stayed
        narrow: a study NARROWER than the unvetted one."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "sg.h").write_text(
            "struct sg_table {\n    int nents;\n};\n"
            "int sg_table_init(struct sg_table *t);\n",
            encoding="utf-8",
        )
        (repo / "delta.c").write_text(
            '#include "sg.h"\n'
            "int sg_table_init(struct sg_table *t) {\n"
            "    t->nents = 0;\n    return 0;\n}\n",
            encoding="utf-8",
        )
        (repo / "alpha.c").write_text(
            "int alpha_fn(void) { return 0; }\n", encoding="utf-8",
        )
        (repo / "gamma.c").write_text(
            "int gamma_ops_run(void) { return 2; }\n", encoding="utf-8",
        )
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["alpha_fn", "sg_table_t"])
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        assert _DROP_LINE not in result.stderr
        names = _item_names(out)
        assert {"alpha_fn", "sg_table", "sg_table_init"} <= names
        assert "gamma_ops_run" not in names  # focus still narrows
        assert _study_list(out)["reading_list_dropped"] == 0


# ------------------------------------------------------------------
# --correlate is a focus source
# ------------------------------------------------------------------


class TestCorrelateFocusSource:
    def test_all_dropped_with_correlate_stays_focused(
        self, tmp_path: Path,
    ) -> None:
        """An all-foreign reading list beside a live --correlate run
        must NOT announce the unfocused default — correlate names are
        operator focus, and the run builds the focused study."""
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["FUN_00401a2c"])
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
            "--correlate", "alpha_ctx,beta_ops_run",
        ])
        assert result.returncode == 0, result.stderr
        assert f"1 {_DROP_LINE}" in result.stderr
        assert "proceeding with the unfocused default" not in result.stderr
        names = _item_names(out)
        assert "alpha_ctx" in names
        assert "beta_ops_run" in names
        assert "gamma_ops_run" not in names  # focused, not default scope


# ------------------------------------------------------------------
# Empty study list is loud
# ------------------------------------------------------------------


class TestEmptyStudyListWarning:
    def test_empty_list_warns_with_generic_cause(
        self, tmp_path: Path,
    ) -> None:
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--identifier", "zzz_not_in_tree",
        ])
        assert result.returncode == 0, result.stderr
        assert "WARNING: study list is EMPTY (0 items)" in result.stderr
        assert ("no extractable items matched the requested focus"
                in result.stderr)

    def test_empty_list_with_drops_names_the_cause(
        self, tmp_path: Path,
    ) -> None:
        """A kept identifier witnessed only by a comment can still end
        at zero items — the warning must name the foreign drops."""
        repo = tmp_path / "repo"
        repo.mkdir()
        # Witness for `orphan_note` exists but nothing is extractable.
        (repo / "notes.c").write_text(
            "/* orphan_note lives here in prose only */\n",
            encoding="utf-8",
        )
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["orphan_note", "FUN_00401a2c"])
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        assert "WARNING: study list is EMPTY (0 items)" in result.stderr
        assert "resolved to no file in this tree" in result.stderr
        assert _study_list(out)["items"] == []


# ------------------------------------------------------------------
# redb merge: all-dropped fallback stays whole-binary
# ------------------------------------------------------------------


class TestRedbMergeFallback:
    def test_all_dropped_reading_list_keeps_unscoped_merge(
        self, tmp_path: Path,
    ) -> None:
        """When every reading-list identifier is foreign-dropped, the
        redb mechanical merge runs UNSCOPED (whole-binary default)
        instead of being skipped into an empty study."""
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        rl = tmp_path / "reading-list.json"
        _write_reading_list(rl, ["FUN_00401a2c"])
        redb = tmp_path / "re-database.json"
        redb.write_text(json.dumps({
            "source_tool": "test",
            "functions": [{
                "name": "redb_only_fn",
                "address": 4096,
                "size": 32,
                "signature": "int redb_only_fn(void)",
            }],
        }), encoding="utf-8")
        sidecar = tmp_path / "decomp-map.json"
        sidecar.write_text(json.dumps({
            "files": {
                "g000.c": [{"function": "redb_only_fn",
                            "start_line": 3}],
            },
        }), encoding="utf-8")
        result = _run(_PREP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
            "--redb", str(redb), "--redb-map", str(sidecar),
        ])
        assert result.returncode == 0, result.stderr
        assert "merge skipped" not in result.stderr
        assert "redb_only_fn" in _item_names(out)


# ------------------------------------------------------------------
# study-loop: zero-item outcome is a WARNING naming the cause
# ------------------------------------------------------------------


class TestStudyLoopZeroItemWarning:
    def test_zero_items_after_drops_is_a_warning(
        self, tmp_path: Path,
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "notes.c").write_text(
            "/* orphan_note lives here in prose only */\n",
            encoding="utf-8",
        )
        out = tmp_path / "out"
        out.mkdir()
        _write_reading_list(out / "reading-list.json",
                            ["orphan_note", "FUN_00401a2c"])
        result = _run(_LOOP_PATH, [
            str(repo), str(out), "--root", str(repo), "--skip-compile",
        ])
        assert result.returncode == 0, result.stderr
        assert "study-loop: WARNING: 0 study items" in result.stderr
        assert "different binary?" in result.stderr
        assert "no study items — done" not in result.stderr

    def test_zero_items_without_drops_stays_quiet(
        self, tmp_path: Path,
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "notes.c").write_text(
            "/* prose mentioning orphan_note only */\n",
            encoding="utf-8",
        )
        out = tmp_path / "out"
        out.mkdir()
        _write_reading_list(out / "reading-list.json", ["orphan_note"])
        result = _run(_LOOP_PATH, [
            str(repo), str(out), "--root", str(repo), "--skip-compile",
        ])
        assert result.returncode == 0, result.stderr
        assert "no study items — done" in result.stderr
        assert "study-loop: WARNING: 0 study items" not in result.stderr


# ------------------------------------------------------------------
# study-loop: explicit focus wins over the store-inherited list
# ------------------------------------------------------------------


def _make_project(tmp_path: Path) -> tuple[Path, Path]:
    """A project-shaped layout _detect_concepts_dir recognises:
    <proj>/concepts beside the run output dir."""
    proj = tmp_path / "proj"
    (proj / "concepts").mkdir(parents=True)
    out = proj / "run1"
    out.mkdir()
    return proj, out


class TestStoreInheritedReadingList:
    def test_explicit_focus_suppresses_store_inheritance(
        self, tmp_path: Path,
    ) -> None:
        """--identifier + absent run-local list + store with pending
        questions: the store list must NOT be copied in (it would
        re-scope the whole study to the store's backlog); the study
        follows the operator identifier and a counted line says the
        questions stay in the store."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "alpha.c").write_text(
            "int alpha_fn(void) { return 0; }\n", encoding="utf-8",
        )
        proj, out = _make_project(tmp_path)
        store_rl = proj / "concepts" / "reading-list.json"
        _write_reading_list(store_rl, ["FUN_00401a2c", "FUN_00403000"])
        store_before = store_rl.read_text(encoding="utf-8")
        result = _run(_LOOP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--identifier", "zzz_not_in_tree", "--skip-compile",
        ])
        assert result.returncode == 0, result.stderr
        assert ("explicit focus given — not inheriting the project "
                "reading list (2 pending question(s)" in result.stderr)
        # The store list never reached the run: no copy, no re-scope.
        assert not (out / "reading-list.json").is_file()
        assert "loaded prior reading-list.json" not in result.stderr
        assert "reading list added" not in result.stderr
        # The study followed the operator identifier, not the store.
        data = _study_list(out)
        assert data["identifiers"] == "zzz_not_in_tree"
        assert data["reading_list_dropped"] == 0
        # The store stays intact for a later unfocused resume.
        assert store_rl.read_text(encoding="utf-8") == store_before

    def test_no_focus_still_inherits_store_list(
        self, tmp_path: Path,
    ) -> None:
        """Without explicit focus the resume path is unchanged: the
        store list is copied into the run and drives prep."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "notes.c").write_text(
            "/* orphan_note lives here in prose only */\n",
            encoding="utf-8",
        )
        proj, out = _make_project(tmp_path)
        store_rl = proj / "concepts" / "reading-list.json"
        _write_reading_list(store_rl, ["orphan_note"])
        result = _run(_LOOP_PATH, [
            str(repo), str(out), "--root", str(repo), "--skip-compile",
        ])
        assert result.returncode == 0, result.stderr
        assert "loaded prior reading-list.json" in result.stderr
        assert "not inheriting the project reading list" not in result.stderr
        run_rl = out / "reading-list.json"
        assert run_rl.is_file()
        got = json.loads(run_rl.read_text(encoding="utf-8"))
        assert [i["id"] for i in got["items"]] == ["rl-0"]

    def test_run_local_list_is_honoured_untouched(
        self, tmp_path: Path,
    ) -> None:
        """A run-local reading-list.json already on disk is used
        as-is, focus or not — never overwritten, never suppressed."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "notes.c").write_text(
            "/* orphan_note lives here in prose only */\n",
            encoding="utf-8",
        )
        proj, out = _make_project(tmp_path)
        _write_reading_list(proj / "concepts" / "reading-list.json",
                            ["FUN_store_only"])
        run_rl = out / "reading-list.json"
        _write_reading_list(run_rl, ["orphan_note"])
        local_before = run_rl.read_text(encoding="utf-8")
        result = _run(_LOOP_PATH, [
            str(repo), str(out), "--root", str(repo),
            "--identifier", "zzz_not_in_tree", "--skip-compile",
        ])
        assert result.returncode == 0, result.stderr
        assert "not inheriting the project reading list" not in result.stderr
        assert "loaded prior reading-list.json" not in result.stderr
        # prep consumed the run-local list (orphan_note witnessed).
        assert "reading list added 1 identifiers" in result.stderr
        assert run_rl.read_text(encoding="utf-8") == local_before
