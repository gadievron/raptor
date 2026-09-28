"""find_redb identity validation — wrong-binary caches are skipped.

``find_redb`` probes RAPTOR-owned cache locations, one of which (the
run dir's PARENT) is shared by every run of a multi-binary project.
Pre-fix it accepted the first existing ``re-database.json`` with zero
binary-identity validation, so an audit of binary B inherited the
cache written for binary A and built its checklist from the wrong
function set. These tests pin the identity gate: recorded
``binary_path`` (and ``metadata.binary_sha256`` where stamped) must
agree with the run's target, mismatches skip toward rebuild — never
a hard error.

Hermetic: synthetic JSON documents + tmp_path files only.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from core.audit.binary_context import find_redb
from core.hash import sha256_file


def _stamp(doc: dict, binary: Path) -> None:
    # Imported lazily so the failing-first run of the identity tests
    # collects against the pre-fix module (no stamping helper yet).
    from core.audit.binary_context import stamp_binary_sha256
    stamp_binary_sha256(doc, binary)


def _redb_doc(binary_path: str | None, sha: str | None = None) -> dict:
    doc: dict = {
        "source_tool": "r2",
        "binary_path": binary_path,
        "functions": [],
        "metadata": {},
    }
    if sha:
        doc["metadata"]["binary_sha256"] = sha
    return doc


def _write_redb(
    dirpath: Path, binary: Path | None, sha: str | None = None,
) -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    p = dirpath / "re-database.json"
    p.write_text(json.dumps(
        _redb_doc(str(binary) if binary is not None else None, sha)))
    return p


def _write_raw(dirpath: Path, doc: dict) -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    p = dirpath / "re-database.json"
    p.write_text(json.dumps(doc))
    return p


def _make_binary(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


class TestWrongBinaryCaches:
    def test_project_cache_for_other_binary_not_accepted(self, tmp_path):
        """Two-binary fixture: a project dir carries the cache written
        for binary A; a run for binary B must NOT accept it."""
        bin_a = _make_binary(tmp_path / "bins" / "libalpha.so",
                             b"\x7fELF-alpha")
        bin_b = _make_binary(tmp_path / "bins" / "libbeta.so",
                             b"\x7fELF-beta")
        project = tmp_path / "project"
        run_b = project / "run-b"
        run_b.mkdir(parents=True)
        _write_redb(project, bin_a, sha256_file(bin_a))

        assert find_redb(run_b, bin_b) is None, (
            "the shared project dir's cache was recorded for a "
            "different binary — accepting it builds the checklist "
            "from the wrong function set"
        )

    def test_same_path_hash_mismatch_skipped_toward_rebuild(self, tmp_path):
        """Binary rebuilt in place: recorded path matches but the
        stamped content hash no longer does — stale, skip."""
        binf = _make_binary(tmp_path / "prog", b"\x7fELF-v1")
        run = tmp_path / "run"
        _write_redb(run, binf, sha256_file(binf))
        binf.write_bytes(b"\x7fELF-v2-rebuilt")

        assert find_redb(run, binf) is None

    def test_matching_path_and_hash_accepted(self, tmp_path):
        binf = _make_binary(tmp_path / "prog", b"\x7fELF-v1")
        run = tmp_path / "run"
        cand = _write_redb(run, binf, sha256_file(binf))

        assert find_redb(run, binf) == cand

    def test_hash_match_wins_over_moved_recorded_path(self, tmp_path):
        """The recorded path is gone but the stamp matches the target:
        content identity is the strongest evidence — accept."""
        binf = _make_binary(tmp_path / "new" / "prog", b"\x7fELF-v1")
        run = tmp_path / "run"
        cand = _write_redb(run, tmp_path / "old" / "prog",
                           sha256_file(binf))

        assert find_redb(run, binf) == cand

    def test_out_dir_local_right_binary_wins(self, tmp_path):
        """A run-local cache for the right binary is accepted even
        when the shared parent holds a wrong-binary one."""
        bin_a = _make_binary(tmp_path / "bins" / "libalpha.so",
                             b"\x7fELF-alpha")
        bin_b = _make_binary(tmp_path / "bins" / "libbeta.so",
                             b"\x7fELF-beta")
        project = tmp_path / "project"
        run_b = project / "run-b"
        _write_redb(project, bin_a, sha256_file(bin_a))
        local = _write_redb(run_b, bin_b, sha256_file(bin_b))

        assert find_redb(run_b, bin_b) == local

    def test_hardlinked_recorded_spelling_accepted(self, tmp_path):
        """The recorded path is a HARDLINK to the target under a
        different name: resolve() equality cannot see it, only the
        samefile step can — same inode is the same binary."""
        binf = _make_binary(tmp_path / "bins" / "target_bin",
                            b"\x7fELF-v1")
        alias = tmp_path / "other" / "alias_name"
        alias.parent.mkdir(parents=True)
        os.link(binf, alias)
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)
        cand = _write_redb(project, alias)

        assert find_redb(run, binf) == cand

    def test_wrong_local_falls_through_to_right_parent(self, tmp_path):
        """Skipping continues DOWN the candidate list: a wrong-binary
        run-local cache falls through to a matching parent cache."""
        bin_a = _make_binary(tmp_path / "bins" / "libalpha.so",
                             b"\x7fELF-alpha")
        bin_b = _make_binary(tmp_path / "bins" / "libbeta.so",
                             b"\x7fELF-beta")
        project = tmp_path / "project"
        run_b = project / "run-b"
        _write_redb(run_b, bin_a, sha256_file(bin_a))
        parent = _write_redb(project, bin_b, sha256_file(bin_b))

        assert find_redb(run_b, bin_b) == parent


class TestIdentityUnknown:
    def test_identity_unknown_run_local_accepted(self, tmp_path):
        """No recorded identity at all in the run's OWN dir: the run
        dir is single-target by construction — historical acceptance
        stands."""
        binf = _make_binary(tmp_path / "prog", b"\x7fELF")
        run = tmp_path / "run"
        cand = _write_redb(run, None)

        assert find_redb(run, binf) == cand

    def test_identity_unknown_shared_parent_skipped(self, tmp_path):
        """No recorded identity in the SHARED parent dir: exactly
        where a foreign binary's cache lives — never accepted
        silently."""
        binf = _make_binary(tmp_path / "bins" / "libbeta.so", b"\x7fELF")
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)
        _write_redb(project, None)

        assert find_redb(run, binf) is None

    def test_recorded_path_gone_same_stem_is_unknown_shared_refuses(
        self, tmp_path,
    ):
        """Recorded binary moved/deleted, no hash: an equal stem is
        NOT identity — a same-stem foreign binary's cache is
        indistinguishable from the moved-binary case, so the verdict
        is unknown and the SHARED slot refuses it."""
        binf = _make_binary(tmp_path / "bins" / "libbeta.so", b"\x7fELF")
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)
        _write_redb(project, tmp_path / "gone" / "libbeta.so")

        assert find_redb(run, binf) is None

    def test_recorded_path_gone_same_stem_run_local_accepted(
        self, tmp_path,
    ):
        """The documented moved-binary case is preserved where the
        slot itself vouches: unknown identity in the run's OWN dir
        keeps its acceptance."""
        binf = _make_binary(tmp_path / "bins" / "libbeta.so", b"\x7fELF")
        run = tmp_path / "run"
        cand = _write_redb(run, tmp_path / "gone" / "libbeta.so")

        assert find_redb(run, binf) == cand

    def test_recorded_path_gone_different_stem_skipped(self, tmp_path):
        binf = _make_binary(tmp_path / "bins" / "libbeta.so", b"\x7fELF")
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)
        _write_redb(project, tmp_path / "gone" / "libalpha.so")

        assert find_redb(run, binf) is None

    def test_directory_target_keeps_run_local_acceptance(self, tmp_path):
        """A non-file target (run dir spelling) is identity-
        undecidable: run-local caches keep their historical
        acceptance."""
        cand = _write_redb(tmp_path, Path("/x/target"))

        assert find_redb(tmp_path, tmp_path) == cand


class TestBaseParity:
    def test_target_none_first_existing_returned(self, tmp_path):
        """No target to validate against — first existing candidate
        wins, exactly as before."""
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)
        cand = _write_redb(project, tmp_path / "whatever" / "prog")

        assert find_redb(run, None) == cand

    def test_unreadable_candidate_returned_for_caller_error_path(
        self, tmp_path,
    ):
        """A candidate that cannot be parsed has unknowable identity;
        every consumer already owns a load-error path for this file —
        the path is handed back so that handling fires unchanged."""
        binf = _make_binary(tmp_path / "prog", b"\x7fELF")
        run = tmp_path / "run"
        run.mkdir()
        cand = run / "re-database.json"
        cand.write_text("{not json")

        assert find_redb(run, binf) == cand

    def test_validate_false_is_probe_only(self, tmp_path):
        """The checklist-timeout scaler's cheap path: existence probes
        only, no content reads, no identity decisions."""
        bin_a = _make_binary(tmp_path / "bins" / "libalpha.so",
                             b"\x7fELF-alpha")
        bin_b = _make_binary(tmp_path / "bins" / "libbeta.so",
                             b"\x7fELF-beta")
        project = tmp_path / "project"
        run_b = project / "run-b"
        run_b.mkdir(parents=True)
        cand = _write_redb(project, bin_a, sha256_file(bin_a))

        assert find_redb(run_b, bin_b, validate=False) == cand


class TestGhidraImportCache:
    def test_stem_keyed_cache_unknown_identity_accepted(
        self, tmp_path, monkeypatch,
    ):
        """The ghidra-import cache path is derived from THIS target's
        stem — identity-unknown there cannot be a different-stem
        foreign cache."""
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "raptor"))
        binf = _make_binary(tmp_path / "bins" / "libbeta.so", b"\x7fELF")
        cache = tmp_path / "raptor" / "out" / "ghidra-import-libbeta"
        cand = _write_redb(cache, None)

        assert find_redb(None, binf) == cand

    def test_stem_keyed_cache_wrong_binary_skipped(
        self, tmp_path, monkeypatch,
    ):
        """Even the stem-keyed location refuses a cache whose recorded
        identity resolves to a DIFFERENT existing binary."""
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "raptor"))
        bin_a = _make_binary(tmp_path / "bins" / "libalpha.so",
                             b"\x7fELF-alpha")
        binf = _make_binary(tmp_path / "bins" / "libbeta.so",
                            b"\x7fELF-beta")
        cache = tmp_path / "raptor" / "out" / "ghidra-import-libbeta"
        _write_redb(cache, bin_a, sha256_file(bin_a))

        assert find_redb(None, binf) is None


class TestGprTargets:
    def test_bundled_binary_is_unknown_run_accepts_shared_refuses(
        self, tmp_path,
    ):
        """A recorded path under the .gpr's parent is containment,
        not identity (executablePath records the import SOURCE, and
        one directory routinely holds several projects' bundles):
        unknown — the run-local slot accepts, the shared slot does
        not."""
        proj = tmp_path / "proj"
        proj.mkdir()
        gpr = proj / "analysis.gpr"
        gpr.write_text("")
        payload = _make_binary(proj / "payload" / "libbeta.so", b"\x7fELF")
        run = tmp_path / "project" / "run"
        run.mkdir(parents=True)

        cand = _write_redb(run, payload)
        assert find_redb(run, gpr) == cand

        cand.unlink()
        _write_redb(run.parent, payload)
        assert find_redb(run, gpr) is None

    def test_sibling_project_binary_refused_at_shared_slot(self, tmp_path):
        """Two .gpr projects sharing a parent dir: project B's lookup
        must not accept a shared-slot cache recorded for project A's
        binary just because that binary lives under the common
        parent."""
        ghidra_dir = tmp_path / "ghidra"
        ghidra_dir.mkdir()
        gpr_b = ghidra_dir / "projB.gpr"
        gpr_b.write_text("")
        bin_a = _make_binary(ghidra_dir / "binA", b"\x7fELF-alpha")
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)
        _write_redb(project, bin_a)

        assert find_redb(run, gpr_b) is None

    def test_same_stem_binary_elsewhere_accepted(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        gpr = proj / "libbeta.gpr"
        gpr.write_text("")
        binf = _make_binary(tmp_path / "bins" / "libbeta.so", b"\x7fELF")
        run = tmp_path / "run"
        cand = _write_redb(run, binf)

        assert find_redb(run, gpr) == cand

    def test_unrelated_binary_is_unknown_shared_skipped(self, tmp_path):
        """A .gpr target cannot be tied to an arbitrary foreign
        binary's name: identity is UNKNOWN — the run-local candidate
        keeps its acceptance, the shared parent does not."""
        proj = tmp_path / "proj"
        proj.mkdir()
        gpr = proj / "analysis.gpr"
        gpr.write_text("")
        other = _make_binary(tmp_path / "bins" / "libother.so", b"\x7fELF")
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)

        local = _write_redb(run, other)
        assert find_redb(run, gpr) == local

        local.unlink()
        _write_redb(project, other)
        assert find_redb(run, gpr) is None


class TestHashStamping:
    def test_stamp_writes_sha256(self, tmp_path):
        binf = _make_binary(tmp_path / "prog", b"\x7fELF-v1")
        doc: dict = {"source_tool": "r2", "binary_path": str(binf),
                     "functions": []}
        _stamp(doc, binf)
        assert doc["metadata"]["binary_sha256"] == sha256_file(binf)

    def test_stamp_missing_binary_no_raise_no_stamp(self, tmp_path):
        doc: dict = {"source_tool": "r2", "functions": []}
        _stamp(doc, tmp_path / "missing")
        assert "binary_sha256" not in (doc.get("metadata") or {})

    def test_stamp_tolerates_foreign_metadata_shape(self, tmp_path):
        binf = _make_binary(tmp_path / "prog", b"\x7fELF-v1")
        doc: dict = {"source_tool": "r2", "metadata": ["junk"]}
        _stamp(doc, binf)
        assert doc["metadata"] == ["junk"]

    def test_stamped_doc_round_trips_through_find_redb(self, tmp_path):
        """A write-time-stamped document makes future cache hits
        hash-validatable end to end."""
        binf = _make_binary(tmp_path / "prog", b"\x7fELF-v1")
        doc: dict = {"source_tool": "r2", "binary_path": str(binf),
                     "functions": []}
        _stamp(doc, binf)
        run = tmp_path / "run"
        run.mkdir()
        cand = run / "re-database.json"
        cand.write_text(json.dumps(doc))
        assert find_redb(run, binf) == cand

        binf.write_bytes(b"\x7fELF-v2-rebuilt")
        assert find_redb(run, binf) is None


class TestWrongTypedCacheFields:
    """Wrong-TYPED fields in a planted cache degrade per the series'
    own contract (skip or accept by the slot rule) — never a raise.

    Pre-fix, ``{"binary_path": 12345}`` escaped ``find_redb`` as a
    TypeError at ``Path(recorded)`` and wrong-typed ``functions``
    shapes escaped ``load_redb`` as TypeError/AttributeError, on
    every consumer path."""

    @pytest.mark.parametrize(
        "junk", [12345, ["a", "b"], {"x": 1}, True],
        ids=["int", "list", "dict", "bool"],
    )
    def test_wrong_typed_binary_path_shared_slot_refused(
        self, tmp_path, junk,
    ):
        binf = _make_binary(tmp_path / "bins" / "prog", b"\x7fELF")
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)
        _write_raw(project, {"source_tool": "r2", "binary_path": junk,
                             "functions": [], "metadata": {}})

        # Identity unknown, shared location: refused, never a raise.
        assert find_redb(run, binf) is None

    @pytest.mark.parametrize(
        "junk", [12345, ["a", "b"], {"x": 1}, True],
        ids=["int", "list", "dict", "bool"],
    )
    def test_wrong_typed_binary_path_run_slot_accepted(
        self, tmp_path, junk,
    ):
        binf = _make_binary(tmp_path / "bins" / "prog", b"\x7fELF")
        run = tmp_path / "run"
        cand = _write_raw(run, {"source_tool": "r2", "binary_path": junk,
                                "functions": [], "metadata": {}})

        # Identity unknown at the run's own slot: historical accept.
        assert find_redb(run, binf) == cand

    @pytest.mark.parametrize(
        "junk", [5, [3], "zzz", {"a": {}}, [["nested"]]],
        ids=["int", "list-of-int", "str", "dict", "nested-list"],
    )
    def test_wrong_typed_functions_candidate_returned(
        self, tmp_path, junk,
    ):
        """A functions field that cannot even load is the malformed-
        JSON class: identity unknowable, path handed back so every
        consumer's own load-error handling fires (BASE parity)."""
        binf = _make_binary(tmp_path / "bins" / "prog", b"\x7fELF")
        run = tmp_path / "run"
        cand = _write_raw(run, {"source_tool": "r2",
                                "binary_path": str(binf),
                                "functions": junk, "metadata": {}})

        assert find_redb(run, binf) == cand


class TestHazardConvergence:
    def test_wrong_typed_and_wrong_binary_converge_on_loud_skip(
        self, tmp_path, caplog,
    ):
        """FM-mandated convergence pin: the wrong-TYPED-field hazard
        and the cached-WRONG-BINARY hazard (stamp mismatch) must land
        in the same outcome class — a loud skip toward rebuild with
        the run proceeding — so the two classes cannot drift apart
        (one degrading, the other raising)."""
        binf = _make_binary(tmp_path / "bins" / "prog", b"\x7fELF-v1")
        other = _make_binary(tmp_path / "bins" / "other", b"\x7fELF-o")
        project = tmp_path / "project"
        run = project / "run"
        run.mkdir(parents=True)

        wrong_typed = {"source_tool": "r2", "binary_path": 12345,
                       "functions": [], "metadata": {}}
        wrong_binary = {"source_tool": "r2", "binary_path": str(other),
                        "functions": [],
                        "metadata": {"binary_sha256": sha256_file(other)}}

        for doc in (wrong_typed, wrong_binary):
            _write_raw(project, doc)
            caplog.clear()
            with caplog.at_level(
                logging.WARNING, logger="core.audit.binary_context",
            ):
                result = find_redb(run, binf)  # must not raise
            assert result is None, doc
            assert "binary-cache: SKIPPING" in caplog.text, doc


class TestSkipWarningEscaping:
    def test_candidate_path_control_bytes_escaped(
        self, tmp_path, monkeypatch, caplog,
    ):
        """The stem-keyed candidate path embeds the target-repo-chosen
        binary stem: a stem carrying ANSI bytes must be rendered
        inert in the SKIPPING warning, like the other operands."""
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "raptor"))
        evil = _make_binary(
            tmp_path / "bins" / "ev\x1b[31;1mPWNED\x1b[0mil",
            b"\x7fELF-evil",
        )
        other = _make_binary(tmp_path / "bins" / "other", b"\x7fELF-o")
        slot = (tmp_path / "raptor" / "out"
                / f"ghidra-import-{evil.stem}")
        _write_raw(slot, {"source_tool": "r2",
                          "binary_path": str(other), "functions": [],
                          "metadata": {"binary_sha256":
                                       sha256_file(other)}})

        with caplog.at_level(
            logging.WARNING, logger="core.audit.binary_context",
        ):
            assert find_redb(None, evil) is None
        skip_lines = [r.getMessage() for r in caplog.records
                      if "SKIPPING" in r.getMessage()]
        assert skip_lines
        assert all("\x1b" not in m for m in skip_lines)


class TestTargetHashMemo:
    def test_repeat_lookups_hash_target_once(self, tmp_path, monkeypatch):
        """find_redb runs per reviewed function; the accept path must
        not re-pay a full target read every call."""
        import core.hash as core_hash

        binf = _make_binary(tmp_path / "prog", b"\x7fELF-v1" * 8)
        run = tmp_path / "run"
        cand = _write_redb(run, binf, sha256_file(binf))

        calls = {"n": 0}
        real = core_hash.sha256_file

        def counting(path, *a, **kw):
            calls["n"] += 1
            return real(path, *a, **kw)

        monkeypatch.setattr(core_hash, "sha256_file", counting)
        assert find_redb(run, binf) == cand
        assert find_redb(run, binf) == cand
        assert calls["n"] == 1

    def test_swapped_binary_rehashes_fresh(self, tmp_path):
        """TOCTOU-at-find preserved across the memo: a swap that
        changes mtime/size misses the stat-stamped key and re-hashes
        (a same-mtime+same-size forgery is the documented residual)."""
        binf = _make_binary(tmp_path / "prog", b"\x7fELF-v1")
        run = tmp_path / "run"
        cand = _write_redb(run, binf, sha256_file(binf))

        assert find_redb(run, binf) == cand   # memoizes the v1 hash
        binf.write_bytes(b"\x7fELF-v2-rebuilt-and-longer")
        assert find_redb(run, binf) is None
