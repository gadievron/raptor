"""Tests for ``packages/describe/report.py`` — top-level
report build + text/JSON renderers.

Scope guardrails: /describe is READ-ONLY by design. These
tests pin that no runnable operator-typed commands appear in
the output. See report.py module docstring for the security
rationale (Makefile can do anything; we don't recommend it)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.describe.report import (
    TargetTypeDefaults,
    DescribeReport,
    _short_int,
    build_describe_report,
    format_json,
    format_text,
)
from packages.describe.target_shape import TargetShape
from packages.describe.tool_readiness import ToolCheck


def _shape(**overrides) -> TargetShape:
    base = {
        "target_path": Path("/tmp/test"),
        "languages": {"cpp": 100},
        "language_breakdown": {"cpp": 100.0},
        "primary_language": "cpp",
        "build_systems": {"cpp": "autotools"},
        "target_type": "c.userspace-daemon",
        "total_files": 189,
        "total_lines": 52_000,
        "language_lines": {},
    }
    base.update(overrides)
    return TargetShape(**base)


def _report(
    shape=None, checks=None, preview=None, est=None,
) -> DescribeReport:
    return DescribeReport(
        target_shape=shape if shape is not None else _shape(),
        tool_checks=checks if checks is not None else [],
        target_type_defaults=preview,
        estimate_summary=est,
    )


class TestShortInt:
    def test_thousands(self):
        assert _short_int(52_000) == "52k"
        assert _short_int(1_500) == "1k"  # truncates

    def test_millions(self):
        assert _short_int(1_500_000) == "1.5M"

    def test_small(self):
        assert _short_int(42) == "42"


class TestFormatText:
    """Operator-facing text renderer."""

    def test_full_shape_renders_describe_block(self):
        shape = _shape()
        checks = [
            ToolCheck("CodeQL", "warn", "2.18.4",
                      "DB build needs autoreconf for autotools build system",
                      hint="sudo apt install autoconf"),
            ToolCheck("Binary oracle", "warn", None,
                      "no build artefacts found — will activate after build"),
        ]
        preview = TargetTypeDefaults(
            semgrep_packs=["security-audit", "command-injection"],
            high_priority_dirs=["src/http", "src/net"],
            pipeline_names=["understand-map", "scan", "agentic"],
        )
        out = format_text(_report(shape, checks, preview, "$25-$50, 40-75 min"))
        # Target analysis section
        assert "Target analysis:" in out
        assert "Languages: C++ (100%)" in out
        assert "Build system: autotools" in out
        assert "Size: ~52k LOC, 189 source files" in out
        assert "Detected type: c.userspace-daemon" in out
        # Target-type defaults preview
        assert "Defaults for this target type:" in out
        assert "security-audit, command-injection" in out
        assert "src/http, src/net" in out
        assert "understand-map → scan → agentic" in out
        # Target-specific checks section (header avoids "gaps"
        # because ✓ ok entries land here too — pre-fix "gaps"
        # misled operators into reading ok lines as problems).
        assert "Target-specific checks:" in out
        assert "Target-specific tool gaps:" not in out
        assert "⚠" in out and "CodeQL" in out
        assert "hint: sudo apt install autoconf" in out
        # Estimate
        assert "Cost estimate (when running /agentic): $25-$50, 40-75 min" in out
        # Doctor-deferral footer
        assert "raptor doctor" in out
        # Sandboxed-analysis pointer with resolved target path
        # (operator can copy the line; no <target> placeholder
        # forcing manual substitution).
        assert "raptor.py agentic" in out
        assert "<target>" not in out, (
            "footer should substitute the resolved target path; "
            "the <target> placeholder forces operators to hand-edit"
        )
        # The resolved path appears in the footer.
        assert str(shape.target_path) in out

    def test_no_runnable_build_commands_in_output(self):
        # SCOPE GUARDRAIL: /describe must NEVER recommend
        # operator-typed shell commands that execute target
        # code. ``./configure``, ``make``, ``apt install`` are
        # the markers — none should appear in the output's
        # main command list.
        shape = _shape()
        checks = [
            ToolCheck("CodeQL", "warn", "2.18.4",
                      "DB build needs autoreconf",
                      hint="sudo apt install autoconf"),
        ]
        out = format_text(_report(shape, checks, est="$25-$50"))
        # No numbered instruction list — would imply
        # "run these in order" and cross the sandbox boundary.
        assert "1. " not in out
        # No shell command sequences that execute target code.
        assert "./configure" not in out
        assert "./bootstrap" not in out
        assert "./autogen.sh" not in out
        assert "autoreconf -fi" not in out
        assert "&& make" not in out
        # Hint lines CAN say "apt install" (those are
        # operator-readable advice, not a numbered command
        # list to follow).

    def test_no_languages_renders_unknown(self):
        out = format_text(_report(_shape(
            languages={}, language_breakdown={},
            primary_language=None, build_systems={},
            target_type=None, total_files=0,
            total_lines=0,
        )))
        # "none detected" rather than "unknown" — we ran the
        # detectors and they reported no signal; honest about
        # what the run actually saw vs claiming we couldn't
        # tell.
        assert "Languages: none detected" in out
        assert "Build system: none detected" in out

    def test_no_target_type_defaults_omits_section(self):
        out = format_text(_report(preview=None))
        assert "Defaults for this target type" not in out

    def test_estimate_omitted_when_none(self):
        out = format_text(_report(est=None))
        assert "Cost estimate" not in out

    def test_multi_language_breakdown_sorted(self):
        out = format_text(_report(_shape(
            languages={"python": 5, "cpp": 95},
            language_breakdown={"python": 5.0, "cpp": 95.0},
            primary_language="cpp",
        )))
        c_idx = out.find("C++")
        py_idx = out.find("Python")
        assert c_idx < py_idx
        assert "C++ (95%)" in out
        assert "Python (5%)" in out

    def test_language_loc_rendered_when_present(self):
        # Per-language LOC surfaces alongside file-share %.
        # Pins the contrast with file-share alone, which over-
        # represents languages with many tiny files (Java's
        # one-class-per-file convention can dwarf a much larger
        # C++ kernel by file count alone).
        out = format_text(_report(_shape(
            languages={"java": 60, "cpp": 40},
            language_breakdown={"java": 60.0, "cpp": 40.0},
            primary_language="java",
            language_lines={"java": 5_000, "cpp": 47_000},
        )))
        assert "Java (60%, 5k LOC)" in out
        assert "C++ (40%, 47k LOC)" in out

    def test_language_loc_omitted_when_zero_or_absent(self):
        # Mixed: cpp has LOC, python doesn't (zero / missing).
        # Pins the omission contract per-language.
        out = format_text(_report(_shape(
            languages={"cpp": 95, "python": 5},
            language_breakdown={"cpp": 95.0, "python": 5.0},
            primary_language="cpp",
            language_lines={"cpp": 50_000, "python": 0},
        )))
        assert "C++ (95%, 50k LOC)" in out
        assert "Python (5%)" in out
        assert "Python (5%, 0" not in out


class TestFormatJson:
    """JSON renderer — machine consumers."""

    def test_round_trip_structure(self):
        preview = TargetTypeDefaults(
            semgrep_packs=["security-audit"],
            high_priority_dirs=["src/http"],
            pipeline_names=["scan", "agentic"],
        )
        report = _report(
            _shape(),
            checks=[ToolCheck("CodeQL", "warn", "2.18.4",
                              "needs libtool", "apt install libtool")],
            preview=preview,
            est="$25-$50, 40-75 min",
        )
        doc = json.loads(format_json(report))
        assert doc["primary_language"] == "cpp"
        assert doc["target_type"] == "c.userspace-daemon"
        assert doc["total_files"] == 189
        assert doc["build_systems"] == {"cpp": "autotools"}
        assert len(doc["tool_checks"]) == 1
        assert doc["tool_checks"][0]["status"] == "warn"
        assert doc["target_type_defaults"]["semgrep_packs"] == ["security-audit"]
        assert doc["target_type_defaults"]["pipeline_names"] == ["scan", "agentic"]
        assert doc["estimate_summary"] == "$25-$50, 40-75 min"
        # Per-language LOC surfaces as its own key (sums to
        # ``total_lines`` in real shapes; here it's the default
        # empty dict since _shape() doesn't override it).
        assert "language_lines" in doc
        # SCOPE GUARDRAIL: no runnable-command lists exported.
        forbidden_keys = {
            "pipeline", "setup_steps", "analysis_steps",
            "recommended_pipeline",
        }
        assert forbidden_keys.isdisjoint(doc.keys()), (
            f"JSON schema must not include runnable-command "
            f"lists; got intersection: "
            f"{doc.keys() & forbidden_keys}"
        )

    def test_no_target_type_defaults_serialises_null(self):
        report = _report(preview=None)
        doc = json.loads(format_json(report))
        assert doc["target_type_defaults"] is None

    def test_paths_serialised_as_strings(self):
        report = _report(_shape(target_path=Path("/home/raptor/targets/monit")))
        doc = json.loads(format_json(report))
        assert doc["target_path"] == "/home/raptor/targets/monit"


class TestBuildDescribeReport:
    """End-to-end — composes shape + checks + catalog preview
    + estimate against a real catalog-matching target tree."""

    def test_c_userspace_daemon_target_end_to_end(self, tmp_path):
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "Makefile.am").write_text("")
        src = tmp_path / "src"
        src.mkdir()
        for i in range(5):
            (src / f"f{i}.c").write_text("int main(){return 0;}")

        report = build_describe_report(tmp_path)
        assert report.target_shape.target_type == "c.userspace-daemon"
        assert report.target_shape.primary_language == "cpp"
        assert report.tool_checks
        # Catalog preview present + populated for a known entry.
        assert report.target_type_defaults is not None
        assert "security-audit" in report.target_type_defaults.semgrep_packs
        assert report.estimate_summary is not None

    def test_unmatched_target_surfaces_generic_defaults(self, tmp_path):
        # Empty tree → falls back to ``generic``. The generic
        # entry SHIPS with non-empty defaults today
        # (security-audit + owasp-top-ten packs + scan/agentic
        # pipeline) — operators get those defaults even on
        # unmatched targets. Pre-fix this was suppressed by a
        # hardcoded ``name == 'generic'`` check; the
        # field-emptiness gate correctly surfaces them now.
        report = build_describe_report(tmp_path)
        assert report.target_type_defaults is not None
        assert "security-audit" in report.target_type_defaults.semgrep_packs
        # Empty preferred-dirs is fine — generic doesn't
        # narrow attack surface by directory.
        assert report.target_type_defaults.high_priority_dirs == []

    def test_target_type_with_all_empty_fields_skips_preview(
        self, tmp_path, monkeypatch,
    ):
        # Counter-test: a target-type entry with ALL preview
        # fields empty still gets suppressed. Pins the
        # field-emptiness contract.
        import core.run.target_types as tt
        empty_entry = tt.CatalogEntry(name="hollow")
        monkeypatch.setattr(
            tt, "load_by_name", lambda _name: empty_entry,
        )
        from packages.describe.report import (
            _target_type_defaults as _ttd,
        )
        from packages.describe.target_shape import TargetShape
        from pathlib import Path as _Path
        shape = TargetShape(
            target_path=_Path("/tmp"),
            languages={"python": 10},
            language_breakdown={"python": 100.0},
            primary_language="python",
            build_systems={},
            target_type="hollow",
            total_files=10,
            total_lines=200,
        )
        assert _ttd(shape) is None

    def test_target_type_with_partial_defaults_renders(
        self, tmp_path, monkeypatch,
    ):
        # Pin the field-emptiness path: an entry with ANY
        # non-empty preview field surfaces (pre-fix the
        # suppression hardcoded ``name == 'generic'`` and would
        # have dropped this entry if it had been named generic).
        import core.run.target_types as tt
        synth_entry = tt.CatalogEntry(
            name="exotic",
            # Only semgrep_packs populated; dirs + pipeline empty.
            semgrep_packs_default=("security-audit",),
        )
        monkeypatch.setattr(
            tt, "load_by_name",
            lambda name: synth_entry if name == "exotic" else None,
        )
        from packages.describe.report import (
            _target_type_defaults as _ttd,
        )
        from packages.describe.target_shape import TargetShape
        from pathlib import Path as _Path
        shape = TargetShape(
            target_path=_Path("/tmp"),
            languages={"python": 10},
            language_breakdown={"python": 100.0},
            primary_language="python",
            build_systems={},
            target_type="exotic",
            total_files=10,
            total_lines=200,
        )
        preview = _ttd(shape)
        assert preview is not None
        assert preview.semgrep_packs == ["security-audit"]
        assert preview.high_priority_dirs == []
        assert preview.pipeline_names == []
