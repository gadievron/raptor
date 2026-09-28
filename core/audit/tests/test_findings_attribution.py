"""Function-name attribution at the findings row seam.

An exhaustive audit run of a large C codebase emitted findings whose
``function`` was the CALLEE at the finding line ("strcmp", "strlen"):
the regex C extractor minted phantom checklist items from multi-line
call continuations (``strcmp(a, b))) {`` matches the indented branch
of ``ANSI_PATTERN``), nested inside the real function's span. The
review loop reviewed the phantom under the callee name and every
findings emitter copied it unvalidated. These tests reconstruct that
shape with synthetic checklists and pin the row-seam contract:

- corrected rows carry the enclosing function + ``claimed_function``;
- valid names pass through untouched;
- unresolvable attribution keeps the finding (never a drop) and is
  disclosed on the row;
- the report's findings↔journal join keys on the AS-REVIEWED name;
- with several proper containers, the INNERMOST wins (a second, wider
  artifact span must not);
- the source fallback stays contained (finding-supplied paths cannot
  escape the target root) and capped (a claimed line beyond the read
  cap resolves unverified, never to a confident pre-cap name).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.audit.findings import emit_finding

# The resolution helpers are imported lazily inside the tests that
# need them so the emit/persist/bridge/report seam tests still RUN
# (and fail on the row shape, not on an ImportError) against a tree
# that predates the attribution seam.


def _resolve(*args: Any, **kwargs: Any) -> tuple[str, str]:
    from core.audit.findings import resolve_function_attribution
    return resolve_function_attribution(*args, **kwargs)


def _stamp(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from core.audit.findings import stamp_function_attribution
    return stamp_function_attribution(*args, **kwargs)


def _c_checklist() -> dict[str, Any]:
    """Synthetic checklist reproducing the observed phantom-item shape:
    a callee-named item nested inside the real function's span."""
    return {
        "files": [
            {
                "path": "modules/util.c",
                "items": [
                    {"name": "compare_certs", "kind": "function",
                     "line_start": 727, "line_end": 760},
                    # Phantom item minted from a call continuation.
                    {"name": "strcmp", "kind": "function",
                     "line_start": 752, "line_end": 754},
                    {"name": "init_config", "kind": "function",
                     "line_start": 100, "line_end": 180},
                ],
            },
        ],
    }


def _write_checklist(out_dir: Path, checklist: dict[str, Any]) -> None:
    (out_dir / "checklist.json").write_text(json.dumps(checklist))


class TestResolveFunctionAttribution:
    def test_observed_shape_nested_phantom_corrected(self):
        # The empirical defect: claimed name IS a checklist item, but
        # a phantom one strictly nested inside the real function.
        name, disposition = _resolve(
            _c_checklist(), "modules/util.c", "strcmp", 752,
        )
        assert (name, disposition) == ("compare_certs", "corrected")

    def test_valid_claim_passthrough(self):
        name, disposition = _resolve(
            _c_checklist(), "modules/util.c", "compare_certs", 752,
        )
        assert (name, disposition) == ("compare_certs", "validated")

    def test_unitemised_claim_rederived_from_line(self):
        name, disposition = _resolve(
            _c_checklist(), "modules/util.c", "ap_strfoo", 130,
        )
        assert (name, disposition) == ("init_config", "corrected")

    def test_line_outside_any_span_unverified(self):
        name, disposition = _resolve(
            _c_checklist(), "modules/util.c", "ap_strfoo", 999,
        )
        assert (name, disposition) == ("ap_strfoo", "unverified")

    def test_named_item_with_line_elsewhere_stays_validated(self):
        # The name is a real item for the file; only the line
        # disagrees (drift / related site) — never second-guess it.
        name, disposition = _resolve(
            _c_checklist(), "modules/util.c", "init_config", 999,
        )
        assert (name, disposition) == ("init_config", "validated")

    def test_file_absent_from_checklist_is_no_basis(self):
        name, disposition = _resolve(
            _c_checklist(), "other/file.c", "strcmp", 752,
        )
        assert (name, disposition) == ("strcmp", "no_basis")

    def test_no_checklist_is_no_basis(self):
        name, disposition = _resolve(
            None, "modules/util.c", "strcmp", 752,
        )
        assert (name, disposition) == ("strcmp", "no_basis")

    def test_two_proper_containers_innermost_wins(self):
        # Triple-nested shape (observed in the wild, names invented
        # here): an overrunning wide artifact span contains the real
        # function, which contains the claimed phantom. The INNERMOST
        # proper container is the true enclosing function — a wider
        # span must never win the correction.
        checklist = {
            "files": [
                {
                    "path": "support/tool.c",
                    "items": [
                        # Overrunning artifact span swallowing half
                        # the file.
                        {"name": "flush_output", "kind": "function",
                         "line_start": 100, "line_end": 600},
                        # The real enclosing function.
                        {"name": "scrub_args", "kind": "function",
                         "line_start": 200, "line_end": 300},
                        # Phantom item minted from a call continuation.
                        {"name": "strlen", "kind": "function",
                         "line_start": 250, "line_end": 254},
                    ],
                },
            ],
        }
        name, disposition = _resolve(
            checklist, "support/tool.c", "strlen", 251,
        )
        assert (name, disposition) == ("scrub_args", "corrected")

    def test_rederive_two_containers_innermost_wins(self):
        # Same property on the re-derive branch: an unplaced claim
        # inside two nested spans resolves to the more specific one.
        checklist = {
            "files": [
                {
                    "path": "pkg/mod.py",
                    "items": [
                        {"name": "outer", "kind": "function",
                         "line_start": 10, "line_end": 50},
                        {"name": "inner", "kind": "function",
                         "line_start": 20, "line_end": 30},
                    ],
                },
            ],
        }
        name, disposition = _resolve(
            checklist, "pkg/mod.py", "ghost_fn", 25,
        )
        assert (name, disposition) == ("inner", "corrected")

    def test_symlink_escape_refused_at_source_fallback(
        self, tmp_path: Path,
    ):
        # Fence: the source fallback must go through the contained
        # reader. A finding-supplied path that is a symlink escaping
        # the target root must refuse (-> unverified) and must NOT
        # read the symlink's target — a raw open() here would resolve
        # the outside file's def and stamp a "corrected" name.
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "loot.py").write_text(
            "def stolen_name():\n"
            "    a = 1\n"
            "    b = 2\n"
            "    return a\n"
        )
        target = tmp_path / "repo"
        target.mkdir()
        (target / "mod.py").symlink_to(outside / "loot.py")
        checklist = {
            "files": [{"path": "mod.py", "items": []}],
        }
        name, disposition = _resolve(
            checklist, "mod.py", "ghost_fn", 3, target_path=target,
        )
        assert (name, disposition) == ("ghost_fn", "unverified")

    def test_absolute_path_refused_at_source_fallback(
        self, tmp_path: Path,
    ):
        # Fence: an absolute finding path must never resolve outside
        # the target root, whatever it points at.
        outside = tmp_path / "outside2"
        outside.mkdir()
        loot = outside / "loot.py"
        loot.write_text(
            "def stolen_name():\n"
            "    a = 1\n"
            "    return a\n"
        )
        target = tmp_path / "repo2"
        target.mkdir()
        checklist = {
            "files": [{"path": str(loot), "items": []}],
        }
        name, disposition = _resolve(
            checklist, str(loot), "ghost_fn", 2, target_path=target,
        )
        assert (name, disposition) == ("ghost_fn", "unverified")

    def test_line_beyond_read_cap_is_unverified(self, tmp_path: Path):
        # Fence: the source fallback read is capped. A claimed line
        # BEYOND the cap has no readable basis — it must resolve
        # unverified, not to the last pre-cap def (early_helper) and
        # not via an uncapped read to the true past-cap def
        # (late_target).
        from core.audit.findings import _MAX_ATTRIBUTION_SOURCE_BYTES

        target = tmp_path / "repo"
        target.mkdir()
        pad = "# " + "p" * 65534  # 64 KiB per line, keeps line count low
        pad_count = _MAX_ATTRIBUTION_SOURCE_BYTES // len(pad) + 4
        source_lines = [
            "def early_helper():",
            "    return 1",
            *([pad] * pad_count),
            "def late_target():",
            "    marker = 1",
        ]
        (target / "big.py").write_text("\n".join(source_lines))
        claimed_line = len(source_lines)  # "    marker = 1", past the cap
        checklist = {
            "files": [{"path": "big.py", "items": []}],
        }
        name, disposition = _resolve(
            checklist, "big.py", "ghost_fn", claimed_line,
            target_path=target,
        )
        assert (name, disposition) == ("ghost_fn", "unverified")

    def test_python_nested_def_is_real_and_kept(self):
        # Nesting languages: a named inner def is a legitimate, more
        # specific attribution — the C-only phantom rule must not fire.
        checklist = {
            "files": [
                {
                    "path": "pkg/mod.py",
                    "items": [
                        {"name": "outer", "kind": "function",
                         "line_start": 10, "line_end": 50},
                        {"name": "inner", "kind": "function",
                         "line_start": 20, "line_end": 30},
                    ],
                },
            ],
        }
        name, disposition = _resolve(
            checklist, "pkg/mod.py", "inner", 25,
        )
        assert (name, disposition) == ("inner", "validated")

    def test_source_fallback_when_inventory_has_no_span(
        self, tmp_path: Path,
    ):
        # Inventory lookup fails (line outside every span, claim not
        # itemised) but the source file resolves the enclosing def.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "mod.py").write_text(
            "def helper():\n"
            "    pass\n"
            "\n"
            "def handler(req):\n"
            "    do_thing(req)\n"
            "    return req\n"
        )
        checklist = {
            "files": [
                {
                    "path": "mod.py",
                    "items": [
                        {"name": "helper", "kind": "function",
                         "line_start": 1, "line_end": 2},
                    ],
                },
            ],
        }
        name, disposition = _resolve(
            checklist, "mod.py", "do_thing", 5, target_path=target,
        )
        assert (name, disposition) == ("handler", "corrected")

    def test_macro_claim_validates_by_name(self):
        # Non-function kinds are never enclosing-candidates, but a
        # claim naming one is a legitimate attribution — no spurious
        # "unverified" stamp, no correction.
        checklist = {
            "files": [
                {
                    "path": "a.c",
                    "items": [
                        {"name": "MAXBUF", "kind": "constant_macro",
                         "line_start": 10, "line_end": 12},
                        {"name": "main", "kind": "function",
                         "line_start": 100, "line_end": 200},
                    ],
                },
            ],
        }
        name, disposition = _resolve(checklist, "a.c", "MAXBUF", 11)
        assert (name, disposition) == ("MAXBUF", "validated")

    def test_legacy_functions_key_supported(self):
        checklist = {
            "files": [
                {
                    "path": "a.c",
                    "functions": [
                        {"name": "real_fn",
                         "line_start": 5, "line_end": 40},
                        {"name": "strlen",
                         "line_start": 12, "line_end": 14},
                    ],
                },
            ],
        }
        name, disposition = _resolve(
            checklist, "a.c", "strlen", 12,
        )
        assert (name, disposition) == ("real_fn", "corrected")


class TestStampFunctionAttribution:
    def test_correction_preserves_claim(self):
        finding = {
            "file": "modules/util.c", "function": "strcmp", "line": 752,
        }
        _stamp(finding, _c_checklist())
        assert finding["function"] == "compare_certs"
        assert finding["claimed_function"] == "strcmp"

    def test_validated_row_untouched(self):
        finding = {
            "file": "modules/util.c", "function": "compare_certs",
            "line": 752,
        }
        _stamp(finding, _c_checklist())
        assert finding["function"] == "compare_certs"
        assert "claimed_function" not in finding
        assert "function_attribution" not in finding

    def test_unverified_disclosed_never_dropped(self):
        finding = {
            "file": "modules/util.c", "function": "ap_strfoo",
            "line": 999,
        }
        _stamp(finding, _c_checklist())
        assert finding["function"] == "ap_strfoo"
        assert finding["function_attribution"] == "unverified"

    def test_no_checklist_leaves_row_identical(self):
        finding = {"file": "a.c", "function": "fn", "line": 3}
        before = dict(finding)
        _stamp(finding, {})
        assert finding == before

    def test_hostile_shapes_never_raise(self):
        # Fail-safe direction: attribution failure must not cost the
        # finding (or the emit).
        finding = {"file": "a.c", "function": "fn", "line": "junk"}
        checklist: dict[str, Any] = {
            "files": [
                {"path": "a.c", "items": [
                    {"name": "fn", "line_start": "x", "line_end": None},
                    "not-a-dict",
                ]},
            ],
        }
        _stamp(finding, checklist)
        assert finding["function"] == "fn"


class TestEmitFindingAttribution:
    """The ``raptor-audit record`` seam (core.audit.findings)."""

    def test_observed_shape_corrected_at_emit(self, tmp_path: Path):
        _write_checklist(tmp_path, _c_checklist())
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="modules/util.c",
            function_name="strcmp",
            line=752,
            title="NULL deref",
            description="d",
        )
        assert finding["function"] == "compare_certs"
        assert finding["claimed_function"] == "strcmp"
        rows = json.loads((tmp_path / "findings.json").read_text())
        assert rows[0]["function"] == "compare_certs"
        assert rows[0]["claimed_function"] == "strcmp"

    def test_valid_name_untouched_at_emit(self, tmp_path: Path):
        _write_checklist(tmp_path, _c_checklist())
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="modules/util.c",
            function_name="compare_certs",
            line=752,
            title="t",
            description="d",
        )
        assert finding["function"] == "compare_certs"
        assert "claimed_function" not in finding

    def test_unresolved_attribution_never_drops_the_finding(
        self, tmp_path: Path,
    ):
        _write_checklist(tmp_path, _c_checklist())
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="modules/util.c",
            function_name="mystery_fn",
            line=9999,
            title="t",
            description="d",
        )
        assert finding["function"] == "mystery_fn"
        assert finding["function_attribution"] == "unverified"
        assert len(json.loads((tmp_path / "findings.json").read_text())) == 1

    def test_no_checklist_keeps_previous_row_shape(self, tmp_path: Path):
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="a.c",
            function_name="fn",
            line=3,
            title="t",
            description="d",
        )
        assert finding["function"] == "fn"
        assert "claimed_function" not in finding
        assert "function_attribution" not in finding


class TestPersistFindingsAttribution:
    """The in-session audit-loop findings.json writer."""

    def test_observed_shape_corrected_at_persist(self, tmp_path: Path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            ReviewOutcome,
            _persist_findings,
        )

        _write_checklist(tmp_path, _c_checklist())
        result = OrchestratorResult()
        outcome = ReviewOutcome(
            file="modules/util.c", function="strcmp",
            status="finding", body="b", hypothesis="h",
        )
        outcome.line = 752
        result.outcomes.append(outcome)
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        _persist_findings(result, config)

        rows = json.loads((tmp_path / "findings.json").read_text())
        assert rows[0]["function"] == "compare_certs"
        assert rows[0]["claimed_function"] == "strcmp"
        # Journal/coverage identity is out of scope for the row seam:
        # the outcome object keeps the as-reviewed name.
        assert outcome.function == "strcmp"


class TestValidateBridgeAttribution:
    """The /validate bridge findings.json writer."""

    def test_observed_shape_corrected_at_bridge_emit(
        self, tmp_path: Path,
    ):
        from core.audit.orchestrator import ReviewOutcome
        from core.audit.validate import _emit_findings_json

        _write_checklist(tmp_path, _c_checklist())
        outcome = ReviewOutcome(
            file="modules/util.c", function="strcmp",
            status="finding", body="b",
        )
        outcome.line = 752
        path = _emit_findings_json([(0, outcome)], tmp_path, tmp_path)

        payload = json.loads(Path(path).read_text())
        row = payload["findings"][0]
        assert row["function"] == "compare_certs"
        assert row["claimed_function"] == "strcmp"
        # Default title follows the corrected attribution.
        assert row["title"] == "Finding in compare_certs"


class TestReportJoinUsesAsReviewedName:
    """The findings↔journal verdict join must key on the AS-REVIEWED
    (checklist-item) name a corrected row keeps in claimed_function —
    the corrected name would orphan the row from its own review."""

    def test_benign_journal_verdict_still_drops_corrected_row(self):
        from core.audit.report import _apply_journal_verdict_overrides

        audit_data = {
            "functions_analysed": [
                {"file": "modules/util.c", "function": "strcmp",
                 "status": "clean", "line_start": 752},
            ],
        }
        findings = [
            {"id": "FIND-001", "file": "modules/util.c",
             "function": "compare_certs", "claimed_function": "strcmp",
             "line": 752, "status": "finding"},
        ]
        out = _apply_journal_verdict_overrides(findings, audit_data)
        assert out == []

    def test_uncorrected_rows_join_as_before(self):
        from core.audit.report import _apply_journal_verdict_overrides

        audit_data = {
            "functions_analysed": [
                {"file": "a.c", "function": "fn",
                 "status": "clean", "line_start": 10, "line_end": 30},
            ],
        }
        findings = [
            {"id": "FIND-001", "file": "a.c", "function": "fn",
             "line": 12, "status": "finding"},
        ]
        assert _apply_journal_verdict_overrides(findings, audit_data) == []
