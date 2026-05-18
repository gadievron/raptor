"""Adversarial input tests for ``annotation_synth``.

The 24 baseline tests exercise the happy path + a handful of edge
cases. These cover the malicious-input dimension: what happens when
``context-map.json``, ``flow-trace-*.json``, or ``checklist.json``
contain values that could break the on-disk annotation format,
exhaust resources, or leak through the path-traversal defence.

Every input here is something a faulty / compromised / over-eager
LLM upstream could plausibly produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.annotations import iter_all_annotations, read_annotation
from packages.code_understanding.annotation_synth import (
    synthesise_from_understand_output,
)


@pytest.fixture
def fixture(tmp_path):
    """Tiny but realistic /understand output dir + repo + inventory."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text(
        "def login(req):\n    return req\n" * 5
    )
    out = tmp_path / "out"
    out.mkdir()
    checklist = {
        "target_path": str(repo),
        "files": [{
            "path": "src/app.py",
            "items": [{
                "name": "login", "line_start": 1, "line_end": 2,
            }],
        }],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))
    return repo, out


# ---------------------------------------------------------------------------
# Malicious JSON content — the LLM emits free-form prose into JSON
# fields that we then plumb into annotation metadata or body. None of
# these should corrupt the on-disk format or crash the synth.
# ---------------------------------------------------------------------------


class TestMaliciousJsonContent:
    def test_html_comment_close_in_entry_point_id(self, fixture):
        repo, out = fixture
        cmap = {"entry_points": [{
            "id": "EP-1-->INJECT", "type": "http_route",
            "method": "GET", "path": "/x",
            "file": "src/app.py", "line": 1,
        }]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        ann = read_annotation(out / "annotations", "src/app.py", "login")
        # Sanitiser converted ``-->`` to ``->`` so the comment
        # frontmatter stays valid.
        assert "-->" not in ann.metadata["entry_point_id"]
        # Round-trip read works.
        for a in iter_all_annotations(out / "annotations"):
            assert a.function == "login"

    def test_html_comment_open_in_sink_type(self, fixture):
        repo, out = fixture
        cmap = {
            "entry_points": [],
            "sink_details": [{
                "id": "S1", "type": "<!-- evil -->db_query",
                "operation": "execute", "file": "src/app.py", "line": 1,
            }],
        }
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        ann = read_annotation(out / "annotations", "src/app.py", "login")
        assert "<!--" not in ann.metadata["type"]
        assert "-->" not in ann.metadata["type"]

    def test_newline_in_id_field(self, fixture):
        """Newline + fake-heading payload in a JSON id field. Sanitiser
        must convert the newline to a space so the value stays on one
        physical line of the metadata HTML comment (preventing a fake
        section heading on a subsequent line)."""
        repo, out = fixture
        cmap = {"entry_points": [{
            "id": "EP-1\n## injected_section",
            "type": "http_route", "method": "GET", "path": "/x",
            "file": "src/app.py", "line": 1,
        }]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        # Pin: exactly one section in the rendered .md, no fake
        # ``## injected_section`` heading. The metadata VALUE may
        # still contain the substring "## injected_section" (it's
        # safely quoted inside the HTML comment) — that's OK because
        # the section-heading regex only matches at start-of-line.
        anns = list(iter_all_annotations(out / "annotations"))
        assert len(anns) == 1
        assert anns[0].function == "login"
        # Newline itself MUST be gone from the metadata value or
        # writing would have raised.
        assert "\n" not in anns[0].metadata.get("entry_point_id", "")

    def test_null_byte_in_id(self, fixture):
        repo, out = fixture
        cmap = {"entry_points": [{
            "id": "EP-1\x00evil", "type": "http_route",
            "method": "GET", "path": "/x",
            "file": "src/app.py", "line": 1,
        }]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        ann = read_annotation(out / "annotations", "src/app.py", "login")
        assert "\x00" not in ann.metadata.get("entry_point_id", "")

    def test_long_notes_in_body_does_not_crash(self, fixture):
        """Body is free-form prose — large content is fine, but make
        sure the synth doesn't choke."""
        repo, out = fixture
        big_notes = "x " * 50_000  # ~100KB
        cmap = {"entry_points": [{
            "id": "EP-1", "type": "http_route", "method": "GET",
            "path": "/x", "file": "src/app.py", "line": 1,
            "notes": big_notes,
        }]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.emitted == 1
        ann = read_annotation(out / "annotations", "src/app.py", "login")
        assert len(ann.body) >= 100_000

    def test_path_traversal_in_file_field_rejected(self, fixture):
        """A malicious context-map could try to land an annotation
        at ``../etc/passwd``. The substrate's path-traversal defence
        catches this — synth must record an error, not propagate."""
        repo, out = fixture
        # Add an inventory entry for the traversal target so resolve
        # would otherwise succeed.
        ck = json.loads((out / "checklist.json").read_text())
        ck["files"].append({
            "path": "../etc/passwd",
            "items": [{"name": "evil", "line_start": 1, "line_end": 2}],
        })
        (out / "checklist.json").write_text(json.dumps(ck))
        cmap = {"entry_points": [{
            "id": "EP-1", "type": "http_route", "method": "GET",
            "path": "/x", "file": "../etc/passwd", "line": 1,
        }]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        # Substrate's _validate_source_path rejects ``..``
        # ValueError → counted in errors, not emitted.
        assert counts.errors >= 1
        assert counts.emitted == 0
        # The annotation tree did not gain an ``../etc/passwd.md`` file
        # at the parent dir.
        assert not (out / "annotations" / ".." / "etc" / "passwd.md").exists()


# ---------------------------------------------------------------------------
# Trace step adversarial inputs.
# ---------------------------------------------------------------------------


class TestMaliciousTraceContent:
    def test_step_description_with_newlines_preserved_in_body(self, fixture):
        """Body is markdown — newlines in description are fine and
        preserved verbatim."""
        repo, out = fixture
        trace = {"steps": [{
            "step": 1, "type": "entry",
            "definition": "src/app.py:1",
            "description": "line one\nline two\nline three",
            "tainted_var": "x", "transform": "none",
            "confidence": "high",
        }]}
        (out / "flow-trace-EP-1.json").write_text(json.dumps(trace))
        counts = synthesise_from_understand_output(out)
        assert counts.emitted == 1
        ann = read_annotation(out / "annotations", "src/app.py", "login")
        assert "line two" in ann.body

    def test_huge_step_count(self, fixture):
        """LLM emits a 1000-step trace. Synth must complete and not
        explode the annotation file."""
        repo, out = fixture
        steps = [
            {
                "step": i, "type": "call",
                "definition": "src/app.py:1",
                "description": f"step {i}",
                "tainted_var": "x", "transform": "none",
                "confidence": "high",
            }
            for i in range(1, 1001)
        ]
        (out / "flow-trace-EP-1.json").write_text(json.dumps({"steps": steps}))
        counts = synthesise_from_understand_output(out)
        # All steps target the same function. Last writer wins, so
        # only one annotation on disk.
        assert counts.emitted == 1000
        anns = list(iter_all_annotations(out / "annotations"))
        assert len(anns) == 1

    def test_step_type_with_special_chars(self, fixture):
        repo, out = fixture
        trace = {"steps": [{
            "step": 1,
            "type": "call\x00<!-- evil -->",
            "definition": "src/app.py:1",
            "description": "x",
            "confidence": "high",
        }]}
        (out / "flow-trace-EP-1.json").write_text(json.dumps(trace))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        ann = read_annotation(out / "annotations", "src/app.py", "login")
        assert "\x00" not in ann.metadata.get("type", "")
        assert "-->" not in ann.metadata.get("type", "")

    def test_definition_with_relative_path_traversal(self, fixture):
        """Step definition pointing at ``../etc/passwd:1`` — synth's
        own ``_resolve`` calls ``lookup_function`` which treats the
        path as inventory-relative. With no matching inventory entry
        it returns None, so the step is skipped."""
        repo, out = fixture
        trace = {"steps": [{
            "step": 1, "type": "call",
            "definition": "../etc/passwd:1",
            "description": "x",
            "confidence": "high",
        }]}
        (out / "flow-trace-EP-1.json").write_text(json.dumps(trace))
        counts = synthesise_from_understand_output(out)
        assert counts.emitted == 0
        assert counts.skipped_no_function >= 1


# ---------------------------------------------------------------------------
# Inventory poisoning.
# ---------------------------------------------------------------------------


class TestInventoryPoisoning:
    def test_function_name_with_newline_rejected(self, fixture):
        """A poisoned checklist could carry a function name with
        embedded newlines. Substrate ``_validate_function_name``
        rejects with ValueError, synth records an error, no
        annotation lands."""
        repo, out = fixture
        ck = json.loads((out / "checklist.json").read_text())
        ck["files"][0]["items"][0]["name"] = "login\n## injected"
        (out / "checklist.json").write_text(json.dumps(ck))
        cmap = {"entry_points": [{
            "id": "EP-1", "type": "http_route", "method": "GET",
            "path": "/x", "file": "src/app.py", "line": 1,
        }]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        # Substrate raises → counted as error.
        assert counts.errors >= 1
        # Tree has no malformed annotation.
        anns = list(iter_all_annotations(out / "annotations"))
        # Either zero, or one without the injection.
        for a in anns:
            assert "##" not in a.function

    def test_corrupt_target_path_in_checklist(self, tmp_path):
        """``target_path`` resolves repo_root for hash computation.
        If it points at a non-existent directory, hash returns "" —
        annotation still lands, just without staleness metadata."""
        out = tmp_path / "out"
        out.mkdir()
        ck = {
            "target_path": "/nonexistent/path/that/does/not/exist",
            "files": [{
                "path": "src/app.py",
                "items": [{
                    "name": "f", "line_start": 1, "line_end": 2,
                }],
            }],
        }
        (out / "checklist.json").write_text(json.dumps(ck))
        cmap = {"entry_points": [{
            "id": "EP-1", "type": "http_route", "method": "GET",
            "path": "/x", "file": "src/app.py", "line": 1,
        }]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.emitted == 1
        ann = read_annotation(out / "annotations", "src/app.py", "f")
        # No hash key — source unreadable.
        assert "hash" not in ann.metadata


# ---------------------------------------------------------------------------
# Robustness: various JSON / structural surprises.
# ---------------------------------------------------------------------------


class TestStructuralSurprises:
    def test_entry_points_is_null_not_list(self, fixture):
        """LLM emits ``"entry_points": null`` instead of ``[]``."""
        repo, out = fixture
        cmap = {"entry_points": None, "sink_details": None}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.emitted == 0

    def test_entry_point_missing_required_fields(self, fixture):
        """Some entry points lack ``file`` or ``line``."""
        repo, out = fixture
        cmap = {"entry_points": [
            {"id": "EP-1"},  # no file, no line
            {"id": "EP-2", "file": "src/app.py"},  # no line
            {"id": "EP-3", "line": 1},  # no file
        ]}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        # All three skipped — none crashed.
        assert counts.skipped_no_function >= 3
        assert counts.errors == 0

    def test_flow_trace_with_no_steps_key(self, fixture):
        repo, out = fixture
        (out / "flow-trace-EP-X.json").write_text(json.dumps({}))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.emitted == 0

    def test_flow_trace_with_steps_not_a_list(self, fixture):
        """LLM emits a ``steps`` value that isn't a list (string,
        null, scalar). Synth must drop it silently — no crash, no
        annotations, no errors."""
        repo, out = fixture
        (out / "flow-trace-EP-X.json").write_text(
            json.dumps({"steps": "not a list"})
        )
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.emitted == 0

    def test_steps_list_with_non_dict_entries(self, fixture):
        """``steps: [{...valid...}, "garbage", null, 42]`` — the
        valid step lands, the others are silently dropped."""
        repo, out = fixture
        trace = {"steps": [
            {
                "step": 1, "type": "entry",
                "definition": "src/app.py:1",
                "description": "valid step",
                "tainted_var": "x", "transform": "none",
                "confidence": "high",
            },
            "garbage string",
            None,
            42,
            ["nested"],
        ]}
        (out / "flow-trace-EP-1.json").write_text(json.dumps(trace))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.emitted == 1

    def test_entry_points_is_string_not_list(self, fixture):
        """LLM emits ``"entry_points": "see notes"`` instead of a list."""
        repo, out = fixture
        cmap = {"entry_points": "see notes"}
        (out / "context-map.json").write_text(json.dumps(cmap))
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.emitted == 0


# ---------------------------------------------------------------------------
# Hunt variants — hostile / surprising input shapes
# ---------------------------------------------------------------------------


def _write_variants(out: Path, variants: list) -> None:
    (out / "variants.json").write_text(json.dumps({"variants": variants}))


class TestHuntVariantsHostile:
    """Hostile / surprising variant content. ``_emit_variants`` must
    not crash, must not corrupt on-disk annotation format, and must
    bound resource use."""

    def test_500_variant_stress(self, fixture):
        """Wide variant batch — picker / writer must scale linearly
        without blowing up. All 500 collide on the same (file,
        function), so last-writer-wins; pin counts.sources tracks
        all attempts."""
        repo, out = fixture
        _write_variants(out, [{
            "id": f"VAR-{i:03d}",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
        } for i in range(500)])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.sources.get("variant", 0) == 500

    def test_unicode_in_path_and_function_skipped_cleanly(self, fixture):
        """File path / function name with non-ASCII letters. The
        inventory has no matching entry → variant skipped to
        ``skipped_no_function``, no crash from non-ASCII handling."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-Ω",
            "file": "src/応用.py",
            "function": "處理",
            "line": 1,
            "taint_status": "confirmed_tainted",
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.skipped_no_function >= 1

    def test_control_bytes_in_body_fields(self, fixture):
        """NUL / bell / ESC inside body-bound fields (matched_code,
        notes, taint_source). Body is markdown — unlike metadata it
        isn't ``_safe_meta``-sanitised, but the underlying annotation
        substrate must not crash on these characters."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-CTRL",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
            "matched_code": "func(\x00x\x07y\x1bz)",
            "notes": "trailing\x00null",
            "taint_source": "src/x.py:1\x00with control",
        }])
        counts = synthesise_from_understand_output(out)
        # Either the annotation substrate accepts and round-trips
        # the body, OR rejects it with a counted error. Either is
        # acceptable; what's NOT acceptable is an uncaught exception.
        assert counts.errors + counts.sources.get("variant", 0) >= 1

    def test_proof_field_as_string_not_dict(self, fixture):
        """Producer emits ``proof`` as a plain string instead of the
        documented dict. ``_emit_variants`` falls back to taint_source
        as the body source — variant still annotated."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-PSTR",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
            "proof": "raw prose proof, not a dict",
            "taint_source": "src/router.py:5",
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.sources.get("variant", 0) == 1
        ann = read_annotation(
            out / "annotations", "src/app.py", "login",
        )
        assert ann is not None
        # Fallback to taint_source picked up.
        assert "Taint source: src/router.py:5" in ann.body

    def test_proof_field_as_list_not_dict(self, fixture):
        """``proof: ["item1", "item2"]`` — handler does
        ``isinstance(proof, dict)``, so a list silently falls
        through. Pin the contract."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-PLIST",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
            "proof": ["a", "b", "c"],
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.sources.get("variant", 0) == 1

    def test_deeply_nested_proof_dict(self, fixture):
        """20-level-deep ``proof`` dict — handler only reads three
        documented keys (vulnerable_code / source / sink) so depth
        is irrelevant; pin no recursion / no crash."""
        repo, out = fixture
        deep = {"vulnerable_code": "x"}
        for _ in range(20):
            deep = {"wrap": deep}
        _write_variants(out, [{
            "id": "VAR-DEEP",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
            "proof": deep,
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.sources.get("variant", 0) == 1

    def test_empty_body_variant_still_emits(self, fixture):
        """All body-building fields missing → empty body. Annotation
        substrate accepts empty bodies (status carried in metadata
        alone), so this should still emit one annotation."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-EMPTY",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
            # No matched_code / proof / taint_source / notes.
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.sources.get("variant", 0) == 1
        ann = read_annotation(
            out / "annotations", "src/app.py", "login",
        )
        assert ann is not None
        assert ann.body == ""
        assert ann.metadata["status"] == "finding"

    def test_path_traversal_in_variant_file_field(self, fixture):
        """``file: "../../etc/passwd"`` — would-be path traversal.
        Inventory lookup returns no match → variant skipped to
        ``skipped_no_function``. The annotation substrate's path-
        traversal defence is the second line; pin that we don't
        even reach it because the inventory miss filters first."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-TRAV",
            "file": "../../etc/passwd",
            "function": "anything",
            "line": 1,
            "taint_status": "confirmed_tainted",
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        assert counts.skipped_no_function >= 1
        # No annotation file written under the base dir.
        assert not any(
            (out / "annotations").rglob("*.md")
        )

    def test_html_comment_close_in_vuln_type_metadata(self, fixture):
        """``vuln_type`` lands in metadata; ``_safe_meta`` must
        defang ``-->`` so the on-disk frontmatter
        ``<!-- meta: vuln_type=... -->`` doesn't terminate early."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-HTML",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
            "vuln_type": "x-->y",
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        ann = read_annotation(
            out / "annotations", "src/app.py", "login",
        )
        assert ann is not None
        assert "-->" not in ann.metadata["vuln_type"]

    def test_newlines_in_metadata_field_sanitised(self, fixture):
        """``confidence`` / ``priority`` with newline → metadata
        substrate would reject; ``_safe_meta`` strips them so the
        write succeeds."""
        repo, out = fixture
        _write_variants(out, [{
            "id": "VAR-NL",
            "file": "src/app.py", "function": "login", "line": 1,
            "taint_status": "confirmed_tainted",
            "confidence": "high\nrating",
            "priority": "1\n2",
        }])
        counts = synthesise_from_understand_output(out)
        assert counts.errors == 0
        ann = read_annotation(
            out / "annotations", "src/app.py", "login",
        )
        assert ann is not None
        assert "\n" not in ann.metadata["confidence"]
        assert "\n" not in ann.metadata["priority"]
