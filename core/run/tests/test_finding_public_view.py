"""Tests for finding_public_view — the publication-grade structural projector.

Pure-function tests; no spatch, no LLM, no lifecycle. The projector is
substrate for /cite, ZKPoX Tier 1.5+ attestation, and hall-of-fame
ingestion (none of which exist yet) — the contract is locked here so
those future consumers get a stable shape.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.run.findings import (
    FINDING_PUBLIC_SCHEMA_VERSION,
    PROVENANCE_REFS_FIELD,
    finding_public_view,
)


# --- allowlist enforcement -----------------------------------------------


def test_schema_version_always_present() -> None:
    out = finding_public_view({})
    assert out == {"schema": FINDING_PUBLIC_SCHEMA_VERSION}


def test_allowlist_keeps_known_structural_fields() -> None:
    # Every allowed field round-trips.
    finding = {
        "id": "F-001",
        "finding_id": "F-001",
        "file": "src/auth.py",
        "function": "login_user",
        "line": 142,
        "column": 8,
        "vuln_type": "sql_injection",
        "cwe_id": "CWE-89",
        "cwe_ids": ["CWE-89", "CWE-20"],
        "references": ["https://cwe.mitre.org/89.html"],
        "provenance_refs": [{"run_id": "r1", "ts": "2026-05-30T12:00:00Z"}],
    }
    out = finding_public_view(finding)
    # Schema added; everything else preserved.
    assert out["schema"] == FINDING_PUBLIC_SCHEMA_VERSION
    for key, value in finding.items():
        assert out[key] == value, f"{key}: {out[key]!r} != {value!r}"


def test_unknown_fields_dropped() -> None:
    # Arbitrary field not on allowlist → not in output.
    out = finding_public_view({
        "id": "F", "secret_data": "leak me", "internal_cache_key": "x:y:z",
    })
    assert "secret_data" not in out
    assert "internal_cache_key" not in out
    assert out.get("id") == "F"


def test_mutable_fields_dropped_even_when_present() -> None:
    # The whole point of the slim allowlist: status/severity/ruling/
    # reasoning are excluded because they're operator-claim territory.
    finding = {
        "id": "F",
        "severity": "High",
        "cvss_vector": "CVSS:3.1/AV:N/...",
        "cvss_score": 9.8,
        "status": "exploitable",
        "final_status": "exploitable",
        "title": "subject to operator refinement",
        "ruling": {"status": "exploitable", "reasoning": "LLM prose"},
        "reasoning": "long LLM-emitted prose that quotes source",
        "snippet": "char buf[8]; strcpy(buf, user);",
    }
    out = finding_public_view(finding)
    for dropped in (
        "severity", "cvss_vector", "cvss_score",
        "status", "final_status", "title",
        "ruling", "reasoning", "snippet",
    ):
        assert dropped not in out, f"{dropped} leaked: {out}"


def test_non_dict_input_returns_envelope_only() -> None:
    # Defensive — caller passed something other than a dict.
    assert finding_public_view(None) == {"schema": FINDING_PUBLIC_SCHEMA_VERSION}
    assert finding_public_view([]) == {"schema": FINDING_PUBLIC_SCHEMA_VERSION}
    assert finding_public_view("string") == {"schema": FINDING_PUBLIC_SCHEMA_VERSION}


def test_missing_optional_fields_omitted_not_nulled() -> None:
    # A field that's absent on input is absent on output (no None
    # placeholders). Distinguishes "not present" from "explicitly null".
    out = finding_public_view({"id": "F"})
    assert out == {"schema": FINDING_PUBLIC_SCHEMA_VERSION, "id": "F"}


# --- path relativization -------------------------------------------------


def test_file_relativized_against_target_path_arg() -> None:
    out = finding_public_view(
        {"file": "/abs/repo/src/a.c"}, target_path="/abs/repo",
    )
    assert out["file"] == "src/a.c"


def test_file_relativized_via_provenance_refs_when_no_arg(
    tmp_path: Path,
) -> None:
    # Manifest carrying target_path that the projector reads via the
    # absolute manifest_path on provenance_refs[0].
    target = tmp_path / "repo"
    target.mkdir()
    src = target / "src" / "a.c"
    src.parent.mkdir()
    src.write_text("// fixture")
    manifest = tmp_path / ".raptor-run.json"
    manifest.write_text(json.dumps({"target_path": str(target)}))
    out = finding_public_view({
        "file": str(src),
        PROVENANCE_REFS_FIELD: [
            {"run_id": "r1", "manifest_path": str(manifest)},
        ],
    })
    assert out["file"] == "src/a.c"


def test_file_falls_back_to_basename_when_no_anchor() -> None:
    # Absolute path + no target_path arg + no resolvable manifest →
    # basename only (never leak absolute deployment paths).
    out = finding_public_view({"file": "/abs/repo/src/a.c"})
    assert out["file"] == "a.c"


def test_file_outside_target_falls_back_to_basename() -> None:
    # Path doesn't sit under target_path — fall back to basename
    # rather than emit a leaky ``../`` traversal.
    out = finding_public_view(
        {"file": "/other/place/a.c"}, target_path="/abs/repo",
    )
    assert out["file"] == "a.c"


def test_file_relative_path_passes_through() -> None:
    # Already-relative path is publication-safe as-is.
    out = finding_public_view(
        {"file": "src/auth.py"}, target_path="/abs/repo",
    )
    assert out["file"] == "src/auth.py"


# --- L1-strict character validation --------------------------------------


def test_control_byte_drops_field_keeps_others() -> None:
    out = finding_public_view({
        "id": "F",
        "function": "login\x00user",         # NUL byte → drop
    })
    assert "function" not in out
    assert out["id"] == "F"


def test_ansi_escape_drops_field() -> None:
    # Terminal-injection vector: ANSI escape in a published view that
    # a CI log or markdown rendering could interpret.
    out = finding_public_view({
        "id": "F",
        "vuln_type": "sql_injection\x1b[31m red text",
    })
    assert "vuln_type" not in out


def test_rtl_override_drops_field() -> None:
    # Homograph / spoofing vector — U+202E reverses display direction.
    out = finding_public_view({
        "id": "F",
        "function": "safe_‮gnp.exe",
    })
    assert "function" not in out


def test_legitimate_unicode_preserved() -> None:
    # Non-Latin identifiers must survive — RAPTOR scans codebases with
    # all sorts of source language conventions.
    out = finding_public_view({
        "id": "F",
        "function": "Joséfile",
        "file": "src/李.c",
    })
    assert out["function"] == "Joséfile"
    assert out["file"] == "src/李.c"


def test_list_element_failing_validation_drops_whole_list() -> None:
    # A poisoned references list (e.g. an injected ANSI in one URL)
    # drops the whole field — partial publishing is risky.
    out = finding_public_view({
        "id": "F",
        "references": ["https://good.example/x", "bad\x1b[Aoops"],
    })
    assert "references" not in out
    assert out["id"] == "F"


# --- provenance_refs passthrough -----------------------------------------


def test_provenance_refs_structure_preserved() -> None:
    refs = [
        {"run_id": "scan-20260530", "ts": "2026-05-30T12:00:00+00:00",
         "manifest_path": ".raptor-run.json"},
        {"run_id": "scan-20260601", "ts": "2026-06-01T08:00:00+00:00",
         "manifest_path": ".raptor-run.json"},
    ]
    out = finding_public_view({"provenance_refs": refs})
    assert out["provenance_refs"] == refs


def test_provenance_refs_non_dict_entries_filtered() -> None:
    out = finding_public_view({
        "provenance_refs": [
            {"run_id": "good"}, "string-not-dict", None, 42,
        ],
    })
    # Only the dict survives.
    assert out["provenance_refs"] == [{"run_id": "good"}]


def test_provenance_refs_non_list_drops_field() -> None:
    out = finding_public_view({"id": "F", "provenance_refs": "not a list"})
    assert "provenance_refs" not in out
    assert out["id"] == "F"


def test_provenance_refs_empty_list_drops_field() -> None:
    out = finding_public_view({"id": "F", "provenance_refs": []})
    assert "provenance_refs" not in out


def test_provenance_refs_locked_to_known_keys() -> None:
    # Hand-edited or hostile findings.json can't smuggle extra nested
    # content out via the provenance_refs passthrough. Only the known
    # keys (run_id, ts, manifest_path) survive — anything else drops.
    out = finding_public_view({
        "provenance_refs": [{
            "run_id": "r1",
            "ts": "2026-05-30T...",
            "manifest_path": ".raptor-run.json",
            "exfil": "sensitive customer data",
            "nested": {"deep": {"junk": "should not leak"}},
        }],
    })
    assert out["provenance_refs"] == [{
        "run_id": "r1",
        "ts": "2026-05-30T...",
        "manifest_path": ".raptor-run.json",
    }]


# --- path-traversal defence ---------------------------------------------


def test_relative_path_with_double_dot_collapses_to_basename() -> None:
    # Could be misread as "bug is in /etc/passwd" in a published view.
    out = finding_public_view({"file": "../../etc/passwd"})
    assert out["file"] == "passwd"


def test_absolute_traversal_through_target_collapses_to_basename() -> None:
    # Absolute path that escapes the target via .. — collapse to basename
    # rather than relativise into a confusing path.
    out = finding_public_view(
        {"file": "/abs/repo/../../etc/passwd"}, target_path="/abs/repo",
    )
    assert out["file"] == "passwd"


# --- idempotence ---------------------------------------------------------


def test_idempotent_round_trip() -> None:
    finding = {
        "id": "F-001",
        "file": "src/auth.py",
        "function": "login_user",
        "line": 142,
        "vuln_type": "sql_injection",
        "cwe_id": "CWE-89",
        "cwe_ids": ["CWE-89"],
        "references": ["https://cwe.mitre.org/89.html"],
        "provenance_refs": [{"run_id": "r1", "ts": "2026-05-30T..."}],
        # mutable noise that should drop on first pass
        "severity": "High", "status": "exploitable",
    }
    once = finding_public_view(finding)
    twice = finding_public_view(once)
    assert once == twice


# --- type-coercion edge cases --------------------------------------------


def test_numeric_and_bool_fields_pass_through() -> None:
    # line / column are typically int; the projector accepts numeric
    # primitives without trying to stringify-then-validate.
    out = finding_public_view({"line": 142, "column": 8})
    assert out["line"] == 142
    assert out["column"] == 8


def test_unexpected_nested_dict_in_allowlist_field_dropped() -> None:
    # cwe_id arriving as a dict (caller-error / schema drift) is
    # dropped rather than passed through — safer than risking nested
    # sensitive content leaking via an allowlist field.
    out = finding_public_view({
        "id": "F",
        "cwe_id": {"weird": "shape"},
    })
    assert "cwe_id" not in out
    assert out["id"] == "F"


def test_file_non_string_drops_field() -> None:
    # file = list or dict or None → drop, don't crash.
    for bad in ([], {}, None, 42):
        out = finding_public_view({"file": bad})
        assert "file" not in out, f"file={bad!r} leaked"
