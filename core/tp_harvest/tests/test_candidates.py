"""Tests for core.tp_harvest.candidates."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.tp_harvest.candidates import (
    RUNBOOK_FILENAME,
    SKIP_LANGUAGE_UNKNOWN,
    SKIP_PATTERN_UNDERIVABLE,
    SKIP_SEED_OVERSIZED,
    SKIP_SEED_UNREADABLE,
    CandidateEmissionError,
    emit_candidate,
    generalise_line,
)
from core.tp_harvest.records import build_record

from .conftest import make_finding

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[3]


def _record(target_tree: Path, run_dir: Path, **overrides):
    return build_record(
        make_finding(**overrides), run_dir=run_dir,
        target_path=str(target_tree), command="validate",
    )


class TestGeneralise:
    def test_call_anchor_stays_metavars_replace_args(self):
        assert generalise_line("    strcpy(dst, src);") == "strcpy($A, $B)"

    def test_repeated_identifier_maps_to_one_metavar(self):
        assert generalise_line("memcpy(p, p, n)") == "memcpy($A, $A, $B)"

    def test_string_literals_collapse(self):
        out = generalise_line('sprintf(buf, "%s-%s", a, b)')
        assert out == 'sprintf($A, "...", $B, $C)'

    def test_keywords_never_metavariable_ized(self):
        out = generalise_line("if (check(user)) return run(cmd)")
        assert out is not None
        assert out.startswith("if (check($A)")
        assert "return" in out

    def test_no_call_anchor_underivable(self):
        assert generalise_line("char buf[16];") is None
        assert generalise_line("x = y + z") is None

    def test_comment_or_blank_underivable(self):
        assert generalise_line("   // strcpy(dst, src)") is None
        assert generalise_line("# os.system(cmd)") is None
        assert generalise_line("") is None

    def test_fully_concrete_call_underivable(self):
        # No metavariable produced -> pattern would just be the seed.
        assert generalise_line("exit(1)") is None

    def test_string_collapser_and_seed_cap_stay_bounded(self):
        # Two-direction guard on the churn-prone limits: the UNBOUNDED
        # string alternation is a scan-restart quadratic (a planted
        # '"' + '\"'*n line cost ~12 s at 64 KB), so the repeat bound
        # and the seed-line cap must both survive refactors.
        from core.tp_harvest.candidates import (
            _MAX_SEED_LINE_CHARS,
            _STRING_RE,
        )
        assert "{0,200}" in _STRING_RE.pattern
        assert "*" not in _STRING_RE.pattern.replace("\\*", "")
        # Cap small enough that even a pathological line is cheap,
        # generous enough for legitimate dense one-liners.
        assert 256 <= _MAX_SEED_LINE_CHARS <= 4096


class TestEmitCandidate:
    def test_emits_parseable_yaml(self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        out = tmp_path / "cands"
        path, reason = emit_candidate(rec, out)
        assert reason == ""
        assert path is not None and path.name.endswith(".candidate.yaml")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule = data["rules"][0]
        assert rule["id"].startswith("candidate.cwe-121.")
        assert rule["pattern"] == "strcpy($A, $B)"
        assert rule["languages"] == ["c"]
        assert rule["severity"] == "WARNING"
        assert rule["metadata"]["raptor_candidate"] is True
        assert rule["metadata"]["cwe"] == ["CWE-121"]
        assert rule["metadata"]["seed_span_sha"] == rec.span_sha
        assert "not enabled" in rule["message"].lower()

    def test_runbook_written_beside_candidates(
            self, run_dir, target_tree, tmp_path):
        out = tmp_path / "cands"
        emit_candidate(_record(target_tree, run_dir), out)
        runbook = (out / RUNBOOK_FILENAME).read_text(encoding="utf-8")
        assert "Nothing loads this directory" in runbook
        assert "negative" in runbook

    def test_unknown_language_skips(self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir, file="src/copy.weird")
        path, reason = emit_candidate(rec, tmp_path / "cands")
        assert (path, reason) == (None, SKIP_LANGUAGE_UNKNOWN)

    def test_unreadable_seed_skips(self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir, file="src/missing.c")
        path, reason = emit_candidate(rec, tmp_path / "cands")
        assert (path, reason) == (None, SKIP_SEED_UNREADABLE)

    def test_out_of_target_seed_paths_refused(
            self, run_dir, target_tree, tmp_path):
        # Containment: a finding-derived path must never read outside
        # the target tree — the seed line's call anchors land
        # CONCRETELY in the emitted pattern (content exfiltration into
        # a reviewable artifact).
        secret = tmp_path / "secret.c"
        secret.write_text("leak_me(token, region)\n", encoding="utf-8")
        for hostile in ("../secret.c", str(secret)):
            rec = _record(target_tree, run_dir, file=hostile, line=1)
            path, reason = emit_candidate(rec, tmp_path / "cands")
            assert (path, reason) == (None, SKIP_SEED_UNREADABLE), hostile
        assert not list((tmp_path / "cands").glob("*.yaml")) \
            if (tmp_path / "cands").exists() else True

    def test_symlink_escape_from_target_refused(
            self, run_dir, target_tree, tmp_path):
        secret = tmp_path / "secret.c"
        secret.write_text("leak_me(token, region)\n", encoding="utf-8")
        (target_tree / "src" / "link.c").symlink_to(secret)
        rec = _record(target_tree, run_dir, file="src/link.c", line=1)
        path, reason = emit_candidate(rec, tmp_path / "cands")
        assert (path, reason) == (None, SKIP_SEED_UNREADABLE)

    def test_oversized_seed_line_skips_by_name(
            self, run_dir, target_tree, tmp_path):
        # One planted multi-KB line is the quadratic-regex pump shape;
        # the hard input bound skips it before any regex runs.
        evil = "f(" + '"' + '\\"' * 32000 + "\n"
        (target_tree / "src" / "pump.c").write_text(evil, encoding="utf-8")
        rec = _record(target_tree, run_dir, file="src/pump.c", line=1)
        path, reason = emit_candidate(rec, tmp_path / "cands")
        assert (path, reason) == (None, SKIP_SEED_OVERSIZED)

    def test_candidate_write_replaces_planted_symlink(
            self, run_dir, target_tree, tmp_path):
        # Final-component write-through: a pre-planted symlink at the
        # exact candidate filename must be REPLACED by the atomic
        # rename, never followed (aimed at engine/ it would auto-
        # enable a generated rule).
        rec = _record(target_tree, run_dir)
        out = tmp_path / "cands"
        out.mkdir()
        victim = tmp_path / "victim.yaml"
        victim.write_text("untouched", encoding="utf-8")
        planted = out / f"{rec.harvest_id}.candidate.yaml"
        planted.symlink_to(victim)
        path, reason = emit_candidate(rec, out)
        assert reason == ""
        assert victim.read_text(encoding="utf-8") == "untouched"
        assert not path.is_symlink()
        assert "CANDIDATE" in path.read_text(encoding="utf-8")

    def test_runbook_write_replaces_planted_symlink(
            self, run_dir, target_tree, tmp_path):
        from core.tp_harvest.candidates import ensure_runbook
        out = tmp_path / "cands"
        out.mkdir()
        victim = tmp_path / "victim.md"
        # Dangling plant: exists() is False, so the write path runs —
        # and must replace the link, not create through it.
        (out / RUNBOOK_FILENAME).symlink_to(victim)
        path = ensure_runbook(out)
        assert not victim.exists()
        assert not path.is_symlink()
        assert "promotion" in path.read_text(encoding="utf-8").lower()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"),
                        reason="mkfifo unavailable")
    def test_planted_fifo_seed_does_not_block(
            self, run_dir, target_tree, tmp_path):
        # Untrusted target tree: a FIFO at the finding path must skip,
        # not hang the harvest (read_text_capped contract).
        os.mkfifo(target_tree / "src" / "fifo.c")
        rec = _record(target_tree, run_dir, file="src/fifo.c")
        path, reason = emit_candidate(rec, tmp_path / "cands")
        assert (path, reason) == (None, SKIP_SEED_UNREADABLE)

    def test_underivable_pattern_skips(self, run_dir, target_tree, tmp_path):
        # Line 1 of the fixture is an #include — no call skeleton.
        rec = _record(target_tree, run_dir, line=1)
        path, reason = emit_candidate(rec, tmp_path / "cands")
        assert (path, reason) == (None, SKIP_PATTERN_UNDERIVABLE)

    def test_hostile_message_cannot_inject_yaml(
            self, run_dir, target_tree, tmp_path):
        rec = _record(
            target_tree, run_dir,
            vuln_type='x"\nrules:\n  - id: injected\x1b',
        )
        path, reason = emit_candidate(rec, tmp_path / "cands")
        assert reason == ""
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert len(data["rules"]) == 1
        assert "injected" not in data["rules"][0]["id"]


class TestInTreeRefusal:
    """The NEVER-auto-enable backstop: emission under engine/ refuses."""

    def test_engine_dir_refused(self, run_dir, target_tree):
        rec = _record(target_tree, run_dir)
        with pytest.raises(CandidateEmissionError):
            emit_candidate(rec, REPO / "engine" / "semgrep" / "rules")
        with pytest.raises(CandidateEmissionError):
            emit_candidate(rec, REPO / "engine")

    def test_refusal_happens_before_any_write(self, run_dir, target_tree):
        rec = _record(target_tree, run_dir)
        probe = REPO / "engine" / "semgrep" / "rules" / "tp-harvest-probe"
        with pytest.raises(CandidateEmissionError):
            emit_candidate(rec, probe)
        assert not probe.exists()

    def test_dotted_path_into_engine_refused(
            self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        # Build a relative traversal that RESOLVES under engine/.
        rel = Path(str(tmp_path))
        depth = len(rel.parts) - 1
        sneaky = rel.joinpath(*([".."] * depth)).joinpath(
            *(REPO / "engine" / "semgrep").parts[1:])
        with pytest.raises(CandidateEmissionError):
            emit_candidate(rec, sneaky)

    def test_run_dirs_outside_engine_allowed(
            self, run_dir, target_tree, tmp_path):
        # The gate is scoped to the rules surface: ordinary run dirs
        # (including out/ under the repo root) stay writable.
        rec = _record(target_tree, run_dir)
        path, reason = emit_candidate(rec, tmp_path / "out" / "cands")
        assert reason == ""
        assert path is not None
