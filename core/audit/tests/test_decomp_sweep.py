"""Tests for the tree-wide decompiler Semgrep sweep
(core.audit.decomp_sweep).

Hermetic: semgrep is stubbed through the ``run_rule_fn`` injection
point (the pre_scan convention), the RE database is a synthetic
fixture, and decomp-tree conformance measurement — when the module
exists on this tree — is stubbed so no sandboxed children spawn from
a unit test.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from core.audit.decomp_sweep import (
    MAX_JOURNAL_ROWS,
    SWEEP_RECORD_NAME,
    build_finding_record,
    run_decomp_tree_sweep,
)
from core.concepts.model import (
    DECOMP_EVIDENCE_MAX_CONFIDENCE,
    DECOMP_EVIDENCE_TAG,
)
from core.json import load_json, save_json


@pytest.fixture(autouse=True)
def _no_conformance_children(monkeypatch):
    """Unit tests must not spawn sandboxed semgrep/tree-sitter
    children from the decomp-tree build seam (present only once the
    conformance module has landed)."""
    try:
        from packages.ghidra import decomp_conformance
    except ImportError:
        yield
        return
    monkeypatch.setattr(
        decomp_conformance, "measure_conformance",
        lambda *a, **k: {"stubbed": True},
    )
    yield


FID = "aabbccdd11223344:0x1000"


def _write_redb(out_dir: Path) -> None:
    save_json(out_dir / "re-database.json", {
        "source_tool": "test",
        "binary_path": "/opt/targets/demo",
        "functions": [
            {"name": "parse_input", "address": 0x1000, "size": 64,
             "fid": FID,
             "decompilation": "int parse_input(char *s)\n"
                              "{\n  strcpy(buf, s);\n  return 0;\n}"},
            {"name": "helper", "address": 0x2000, "size": 32,
             "decompilation": "void helper(void)\n{\n  return;\n}"},
        ],
        "xrefs": [],
    })


def _binary_gaps() -> list[dict]:
    return [
        {"file": "binary:demo", "name": "parse_input",
         "address": 0x1000},
        {"file": "binary:demo", "name": "helper", "address": 0x2000},
    ]


class _FakeFinding:
    def __init__(self, file: str, line: int, rule_id: str,
                 message: str = "match"):
        self.file = file
        self.line = line
        self.rule_id = rule_id
        self.message = message


class _FakeResult:
    def __init__(self, findings=(), errors=(), returncode=0):
        self.findings = list(findings)
        self.errors = list(errors)
        self.returncode = returncode


def _recording_runner(calls: list, findings_for_call=None):
    """A run_rule_fn stub that records the exact invocation shape."""

    def _run(target, config, **kwargs):
        calls.append({"target": Path(target), "config": config,
                      "kwargs": dict(kwargs)})
        if findings_for_call is None:
            return _FakeResult()
        return findings_for_call(Path(target), config)

    return _run


def _sidecar_span(tree_root: Path, function: str) -> tuple[str, int]:
    """(tree file name, a line inside *function*'s sidecar entry)."""
    data = load_json(tree_root / "decomp-map.json")
    for fname, entries in data["files"].items():
        for e in entries:
            if e["function"] == function:
                return fname, int(e["start_line"])
    raise AssertionError(f"{function} not in sidecar")


class TestRouting:
    def test_source_run_is_out_of_scope(self, tmp_path):
        out = run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=[{"file": "src/a.c", "name": "f"}],
            run_rule_fn=_recording_runner([]),
        )
        assert out is None
        assert not (tmp_path / SWEEP_RECORD_NAME).exists()

    def test_tree_built_from_redb_and_swept_tree_scope(self, tmp_path):
        _write_redb(tmp_path)
        calls: list = []
        out = run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner(calls),
        )
        assert out is not None and not out["skipped"]
        tree_root = tmp_path / "decomp-tree"
        assert (tree_root / "decomp-map.json").is_file()
        assert calls, "no semgrep invocations recorded"
        # Tree scope: every invocation targets the WHOLE tree root,
        # never a single function tmpfile.
        for call in calls:
            assert call["target"] == tree_root

    def test_rule_selection_is_decompiler_corpus_plus_decomp_safe(
            self, tmp_path, monkeypatch):
        from core.audit import decomp_sweep as ds
        _write_redb(tmp_path)
        safe_rule = tmp_path / "opted-in.yaml"
        safe_rule.write_text("# raptor: decomp-safe\nrules: []\n")
        monkeypatch.setattr(
            "core.audit.sweep.decomp_safe_curated_rules",
            lambda: [safe_rule],
        )
        calls: list = []
        out = ds.run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner(calls),
        )
        from core.audit.binary_verification import (
            decompiler_rules_for_tree,
        )
        expected = {str(p) for p in decompiler_rules_for_tree()}
        expected.add(str(safe_rule))
        assert {c["config"] for c in calls} == expected
        assert "opted-in.yaml" in out["rules_run"]

    def test_never_invoked_unsandboxed(self, tmp_path):
        """The invocation shape must rely on the runner's DEFAULT
        sandboxed path: no ``unsandboxed`` / ``subprocess_runner``
        overrides may be passed (decomp-trees are attacker-shaped
        pseudo-C; run-dir residency is not trust)."""
        _write_redb(tmp_path)
        calls: list = []
        run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner(calls),
        )
        assert calls
        for call in calls:
            assert "unsandboxed" not in call["kwargs"]
            assert "subprocess_runner" not in call["kwargs"]

    def test_source_never_greps_unsandboxed_true(self):
        """Belt-and-braces mutation pin: the module source must not
        spell an unsandboxed opt-out at all."""
        import core.audit.decomp_sweep as ds
        src = Path(ds.__file__).read_text(encoding="utf-8")
        assert "unsandboxed=True" not in src

    def test_sandbox_refusal_is_recorded_loudly(self, tmp_path):
        """A runner-level sandbox refusal (errors set) lands in
        rules_errored — never read as a clean zero-finding scan."""
        _write_redb(tmp_path)

        def _refusing(target, config, **kwargs):
            return _FakeResult(errors=["core.sandbox unavailable"],
                               returncode=-1)

        out = run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_refusing,
        )
        assert out["findings_total"] == 0
        assert out["rules_errored"]
        assert all("sandbox" in v for v in out["rules_errored"].values())


class TestIdentityGate:
    """Wrong-binary containment: a foreign binary's decompilation
    must never be swept into THIS target's journal — the existing
    tree, the re-database a rebuild consumes, and the rebuilt tree
    are each gated against the run's binary checklist keys."""

    def _sweep(self, out_dir, target, calls=None):
        return run_decomp_tree_sweep(
            target_path=target,
            out_dir=out_dir,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner(
                calls if calls is not None else []),
        )

    def _foreign_redb(self, path):
        save_json(path, {
            "source_tool": "test",
            "binary_path": "/opt/other-binary",
            "functions": [
                # Bare-address collision with the run's parse_input
                # gap — the proven cross-binary contamination probe.
                {"name": "parse_input", "address": 0x1000, "size": 64,
                 "decompilation": "int parse_input(char *s)\n"
                                  "{\n  strcpy(buf, s);\n  return 0;"
                                  "\n}"},
            ],
            "xrefs": [],
        })

    def test_foreign_redb_in_parent_is_refused(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        # find_redb searches the run dir's PARENT too — a foreign
        # binary's cached database there must not be built and swept.
        self._foreign_redb(tmp_path / "re-database.json")
        calls: list = []
        record = self._sweep(out, out / "demo", calls)
        assert record["skipped"] is True
        assert "foreign binary" in record["skip_reason"]
        assert calls == []
        from core.coverage.journal import load_entries
        assert load_entries(out) == []

    def test_foreign_redb_in_out_dir_is_refused(self, tmp_path):
        self._foreign_redb(tmp_path / "re-database.json")
        record = self._sweep(tmp_path, tmp_path / "demo")
        assert record["skipped"] is True
        assert "foreign binary" in record["skip_reason"]

    def test_empty_identity_sidecar_never_accepted(self, tmp_path):
        tree = tmp_path / "decomp-tree"
        tree.mkdir()
        save_json(tree / "decomp-map.json", {
            "binary_path": "",
            "files": {"g0.c": [{"function": "parse_input",
                                "address": 0x1000,
                                "start_line": 1, "end_line": 5}]},
        })
        calls: list = []
        record = self._sweep(tmp_path, tmp_path / "demo", calls)
        # No re-database to rebuild from — the identity-unknown tree
        # is refused, never swept.
        assert record["skipped"] is True
        assert calls == []

    def test_empty_identity_sidecar_rebuilds_from_redb(self, tmp_path):
        tree = tmp_path / "decomp-tree"
        tree.mkdir()
        save_json(tree / "decomp-map.json",
                  {"binary_path": "", "files": {}})
        _write_redb(tmp_path)
        record = self._sweep(tmp_path, tmp_path / "demo")
        assert record["skipped"] is False
        assert record["binary_file_key"] == "binary:demo"

    def test_rebuilt_tree_identity_rechecked(self, tmp_path,
                                             monkeypatch):
        _write_redb(tmp_path)
        import packages.ghidra.decomp_tree as dt

        def _evil_build(db, root, **kw):
            Path(root).mkdir(parents=True, exist_ok=True)
            save_json(Path(root) / "decomp-map.json", {
                "binary_path": "/opt/other-binary",
                "files": {"g0.c": [{"function": "parse_input",
                                    "address": 0x1000,
                                    "start_line": 1, "end_line": 5}]},
            })

        monkeypatch.setattr(dt, "write_decomp_tree", _evil_build)
        record = self._sweep(tmp_path, tmp_path / "demo")
        assert record["skipped"] is True
        assert "rebuilt decomp-tree" in record["skip_reason"]

    def test_gpr_target_accepts_matching_tree_without_rebuild(
            self, tmp_path, caplog):
        """A .gpr target whose stem differs from the binary stem must
        accept the run's matching tree (gap-key identity), not warn
        and rebuild every run."""
        _write_redb(tmp_path)
        # Build once with the real machinery via a first sweep.
        first = self._sweep(tmp_path, tmp_path / "demo")
        assert first["skipped"] is False
        # Remove the redb: a spurious rebuild would now fail loudly.
        (tmp_path / "re-database.json").unlink()
        with caplog.at_level(logging.WARNING):
            record = self._sweep(tmp_path, tmp_path / "someproj.gpr")
        assert record["skipped"] is False
        assert not any("rebuilding" in r.message for r in caplog.records)

    def test_sha_stamp_mismatch_refused(self, tmp_path):
        target = tmp_path / "demo"
        target.write_bytes(b"\x7fELF-not-really")
        _write_redb(tmp_path)
        data = load_json(tmp_path / "re-database.json")
        data["metadata"] = {"binary_sha256": "0" * 64}
        save_json(tmp_path / "re-database.json", data)
        record = self._sweep(tmp_path, target)
        assert record["skipped"] is True
        assert "sha256" in record["skip_reason"]

    def test_sha_stamp_match_passes(self, tmp_path):
        from core.hash import sha256_file
        target = tmp_path / "demo"
        target.write_bytes(b"\x7fELF-not-really")
        _write_redb(tmp_path)
        data = load_json(tmp_path / "re-database.json")
        data["metadata"] = {"binary_sha256": sha256_file(target)}
        save_json(tmp_path / "re-database.json", data)
        record = self._sweep(tmp_path, target)
        assert record["skipped"] is False


class TestOrchestratorWiring:
    """Source-level wiring pins for the post-loop hook inside
    ``_run_audit_body`` (the repo's convention for that function —
    see TestPostPassWiring in test_orchestrator.py: the heavy
    scaffolding is integration territory; these pins make hook
    deletion and counter-drift test-visible)."""

    @staticmethod
    def _body_src():
        src = (Path(__file__).resolve().parents[1]
               / "orchestrator.py").read_text()
        idx = src.find("def _run_audit_body")
        assert idx != -1
        end = src.find("\ndef ", idx)
        return src[idx:end if end != -1 else len(src)]

    def test_sweep_invoked_inside_post_loop_phase(self):
        window = self._body_src()
        start = window.find('start_phase("post_loop_checks")')
        end = window.find("# post_loop_checks", start)
        assert -1 not in (start, end) and start < end
        phase = window[start:end]
        assert "from .decomp_sweep import run_decomp_tree_sweep" in phase
        assert "run_decomp_tree_sweep(" in phase

    def test_journal_rows_counted_as_post_loop_mechanical(self):
        # The sweep's echo rows must increment the same counter the
        # sibling mechanical-row writers use, under the result lock —
        # else the console "(+N mechanical post-loop)" line
        # contradicts the journal.
        window = self._body_src()
        call = window.find("run_decomp_tree_sweep(")
        assert call != -1
        after = window[call:call + 1500]
        lock = after.find("with result._lock:")
        incr = after.find("result.post_loop_mechanical += _ds_rows")
        assert lock != -1 and incr != -1
        assert lock < incr


class TestLoudSkip:
    def test_no_redb_is_a_loud_skip(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            out = run_decomp_tree_sweep(
                target_path=tmp_path / "demo",
                out_dir=tmp_path,
                gaps=_binary_gaps(),
                run_rule_fn=_recording_runner([]),
            )
        assert out["skipped"] is True
        assert "re-database" in out["skip_reason"]
        record = load_json(tmp_path / SWEEP_RECORD_NAME)
        assert record["skipped"] is True
        assert any("decomp-sweep skipped" in r.message
                   for r in caplog.records)

    def test_wrong_binary_tree_is_not_swept(self, tmp_path):
        """An existing tree minted for a DIFFERENT binary stem must
        not feed this target's journal; without a re-database the
        result is a loud skip, not a wrong-binary sweep."""
        tree = tmp_path / "decomp-tree"
        tree.mkdir()
        save_json(tree / "decomp-map.json", {
            "binary_path": "/opt/other-binary",
            "files": {"g0.c": [{"function": "f", "address": 1,
                                "start_line": 1, "end_line": 5}]},
        })
        calls: list = []
        out = run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner(calls),
        )
        assert out["skipped"] is True
        assert calls == []


class TestMapping:
    def _sweep_with_matches(self, tmp_path, extra_unmapped=True):
        _write_redb(tmp_path)

        def _findings(target: Path, config: str):
            fname, line = _sidecar_span(target, "parse_input")
            found = [_FakeFinding(str(target / fname), line,
                                  "decompiler-strcpy",
                                  "strcpy with no bounds check")]
            if extra_unmapped:
                found.append(_FakeFinding(str(target / fname), 999999,
                                          "decompiler-strcpy", "stray"))
            return _FakeResult(findings=found)

        calls: list = []
        out = run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner(calls, _findings),
        )
        return out

    def test_finding_maps_through_sidecar_to_fid_and_address(
            self, tmp_path):
        out = self._sweep_with_matches(tmp_path)
        assert out["mapped"] == 1
        rec = out["records"][0]
        assert rec["file"] == "binary:demo"
        assert rec["function"] == "parse_input"
        assert rec["address"] == 0x1000
        assert rec["fid"] == FID
        assert rec["derived_from_target"] is True
        assert rec["checklist_match"] is True

    def test_unmapped_counted_never_dropped(self, tmp_path):
        out = self._sweep_with_matches(tmp_path)
        n_rules = len(out["rules_run"])
        assert out["unmapped"] == n_rules  # one stray per rule call
        assert out["unmapped_records"]
        assert out["unmapped_records"][0]["reason"]
        # Exact accounting: every finding is either mapped (counted
        # in a record's match_count) or unmapped — none vanish.
        assert out["findings_total"] == \
            sum(r["match_count"] for r in out["records"]) + out["unmapped"]

    def test_same_function_same_rule_aggregates(self, tmp_path):
        out = self._sweep_with_matches(tmp_path)
        # One rule id from several rule files still aggregates to one
        # record with an exact match count.
        assert out["records"][0]["match_count"] == len(out["rules_run"])

    def test_confidence_cap_and_tag_on_every_mapped_record(
            self, tmp_path):
        out = self._sweep_with_matches(tmp_path)
        for rec in out["records"]:
            assert rec["confidence"] == DECOMP_EVIDENCE_MAX_CONFIDENCE
            assert DECOMP_EVIDENCE_TAG in rec["tags"]

    def test_record_write_is_valid_json_on_disk(self, tmp_path):
        self._sweep_with_matches(tmp_path)
        data = json.loads(
            (tmp_path / SWEEP_RECORD_NAME).read_text(encoding="utf-8"))
        assert data["skipped"] is False

    def test_message_escaped_at_capture(self, tmp_path):
        _write_redb(tmp_path)

        def _findings(target: Path, config: str):
            fname, line = _sidecar_span(target, "parse_input")
            return _FakeResult(findings=[_FakeFinding(
                str(target / fname), line, "decompiler-strcpy",
                "evil \x1b]0;pwn\x07 text")])

        out = run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner([], _findings),
        )
        msg = out["records"][0]["message"]
        assert "\x1b" not in msg and "\x07" not in msg
        assert "\\x1b" in msg


class TestRuleSelection:
    def test_tree_selection_is_the_full_decompiler_corpus(self):
        """Completeness pin: tree scope means EVERY curated
        decompiler rule file — a narrowing regression in the
        delegated selection must fail here."""
        from core.audit.binary_verification import (
            _RULES_DIR,
            decompiler_rules_for_tree,
        )
        expected = set(_RULES_DIR.glob("*.yaml"))
        assert expected, "decompiler corpus missing"
        assert set(decompiler_rules_for_tree()) == expected


class TestDecompSafeMarker:
    def test_anchored_parse(self):
        from core.audit.sweep import _DECOMP_SAFE_MARKER, _parse_header_marker
        assert _parse_header_marker(
            "# raptor: decomp-safe\nrules: []\n", _DECOMP_SAFE_MARKER)
        # Leading comment block only — marker-shaped text after YAML
        # content never activates.
        assert not _parse_header_marker(
            "rules: []\n# raptor: decomp-safe\n", _DECOMP_SAFE_MARKER)
        # Near-miss spellings do not parse.
        assert not _parse_header_marker(
            "# raptor:  decomp-safe\nrules: []\n", _DECOMP_SAFE_MARKER)

    def test_uncurated_paths_never_opt_in(self, tmp_path):
        """An LLM-authored tempfile rule cannot opt itself onto the
        decomp-tree surface, marker or not."""
        from core.audit.sweep import is_decomp_safe_rule
        rule = tmp_path / "sneaky.yaml"
        rule.write_text("# raptor: decomp-safe\nrules: []\n")
        assert not is_decomp_safe_rule(str(rule))
        assert not is_decomp_safe_rule("")

    def test_real_enumeration_is_curated_and_marked(self):
        from core.audit.sweep import (
            _CURATED_SEMGREP_RULES_DIR,
            decomp_safe_curated_rules,
            is_decomp_safe_rule,
        )
        rules = decomp_safe_curated_rules()
        assert rules == sorted(rules)
        for r in rules:
            assert r.resolve().is_relative_to(_CURATED_SEMGREP_RULES_DIR)
            assert is_decomp_safe_rule(str(r))

    def test_marker_cache_is_per_marker(self, tmp_path, monkeypatch):
        import core.audit.sweep as sweep
        monkeypatch.setattr(sweep, "_CURATED_SEMGREP_RULES_DIR",
                            tmp_path.resolve())
        monkeypatch.setattr(sweep, "_RULE_MARKER_CACHE", {})
        rule = tmp_path / "r.yaml"
        rule.write_text("# raptor: decomp-safe\nrules: []\n")
        assert sweep.is_decomp_safe_rule(str(rule))
        # Per-(path, marker) keys: the decomp-safe hit must not leak
        # into the confirm-only role for the same file.
        assert not sweep.is_confirm_only_rule(str(rule))
        # Process-lifetime memo: a rewrite is not re-read (documented
        # staleness class shared with confirm-only).
        rule.write_text("rules: []\n")
        assert sweep.is_decomp_safe_rule(str(rule))


class TestConfidenceCapMechanism:
    """Mutation pin: removing the clamp from record building must
    fail here — a caller proposing a grade above the ceiling gets
    the ceiling back, through the ONE shared clamp."""

    ENTRY = {"function": "f", "address": 0x10, "fid": FID}

    def _rec(self, confidence: str) -> dict:
        return build_finding_record(
            binary_file_key="binary:demo", entry=self.ENTRY,
            rule_id="r", tree_file="g0.c", line=3, message="m",
            confidence=confidence,
        )

    def test_above_ceiling_is_clamped(self):
        for grade in ("corroborated", "documented", "tested"):
            assert self._rec(grade)["confidence"] == \
                DECOMP_EVIDENCE_MAX_CONFIDENCE

    def test_below_ceiling_not_inflated(self):
        assert self._rec("observed")["confidence"] == "observed"

    def test_unknown_grade_floors(self):
        assert self._rec("bogus")["confidence"] == "inferred"

    def test_tag_always_present(self):
        assert self._rec("traced")["tags"] == [DECOMP_EVIDENCE_TAG]

    def test_constants_are_the_shared_spelling(self):
        """No second spelling: the sweep's ceiling/tag ARE the
        concepts-model constants binary --study clamps with."""
        import core.audit.decomp_sweep as ds
        import core.concepts.model as m
        assert ds.DECOMP_EVIDENCE_MAX_CONFIDENCE \
            is m.DECOMP_EVIDENCE_MAX_CONFIDENCE
        assert ds.DECOMP_EVIDENCE_TAG is m.DECOMP_EVIDENCE_TAG
        assert ds.clamp_decomp_confidence is m.clamp_decomp_confidence


class TestJournal:
    def _run(self, tmp_path, n_functions=1):
        _write_redb(tmp_path)

        def _findings(target: Path, config: str):
            out = []
            for fn in ("parse_input", "helper")[:n_functions]:
                fname, line = _sidecar_span(target, fn)
                out.append(_FakeFinding(str(target / fname), line,
                                        "decompiler-strcpy", "match"))
            return _FakeResult(findings=out)

        return run_decomp_tree_sweep(
            target_path=tmp_path / "demo",
            out_dir=tmp_path,
            gaps=_binary_gaps(),
            run_rule_fn=_recording_runner([], _findings),
        )

    def test_mapped_findings_enter_journal_as_tool_evidence(
            self, tmp_path):
        out = self._run(tmp_path, n_functions=2)
        assert out["journal_rows"] == 2
        from core.coverage.journal import load_entries
        entries = load_entries(tmp_path)
        assert len(entries) == 2
        by_fn = {e.function: e for e in entries}
        assert set(by_fn) == {"parse_input", "helper"}
        e = by_fn["parse_input"]
        assert e.file == "binary:demo"
        assert e.verdict == "suspicious"
        assert e.evidence_tools == ["semgrep:decompiler-strcpy"]
        assert "decomp-sweep" in e.strategies
        assert DECOMP_EVIDENCE_TAG in e.body
        assert f"capped at {DECOMP_EVIDENCE_MAX_CONFIDENCE}" in e.body

    def test_rows_are_mechanical_echoes_not_reviews(self, tmp_path):
        self._run(tmp_path)
        from core.coverage.journal import is_mechanical_echo, load_entries
        for e in load_entries(tmp_path):
            assert is_mechanical_echo(e)
            assert e.body.startswith("[mechanical]")

    def test_journal_rows_capped_with_record(self, tmp_path,
                                             monkeypatch):
        """A hostile decompilation cannot flood the durable journal:
        rows cap, the artifact says so, and counts stay exact."""
        from core.audit import decomp_sweep as ds
        monkeypatch.setattr(ds, "MAX_JOURNAL_ROWS", 1)
        out = self._run(tmp_path, n_functions=2)
        assert out["journal_rows"] == 1
        assert out["journal_rows_capped"] is True
        assert out["mapped"] == 2  # artifact keeps every record
        assert MAX_JOURNAL_ROWS >= 1  # module default stays positive
