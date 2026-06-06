from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.threat_model import (
    blank_for_project,
    diff_context_map,
    enrich_from_context_map,
    from_context_map,
    link_verified_outcomes,
    lint_model,
    load_for_target,
    load_model,
    project_threat_model_paths,
    prompt_context,
    render_report,
    save_model,
)
from core.verified_outcome.types import Oracle, OutcomeStatus, VerifiedOutcome


def _project(tmp_path: Path, *, name: str = "demo", target: str | None = None):
    return SimpleNamespace(
        name=name,
        target=target or str(tmp_path / "target"),
        output_dir=str(tmp_path / "out"),
    )


def test_blank_model_roundtrips_to_json_and_markdown(tmp_path):
    project = _project(tmp_path)
    model = blank_for_project(project)
    json_path, markdown_path = project_threat_model_paths(project)

    save_model(model, json_path, markdown_path)

    loaded = load_model(json_path)
    assert loaded is not None
    assert loaded.project_name == "demo"
    assert "Injection and command execution" in loaded.in_scope_vuln_classes
    assert markdown_path.read_text(encoding="utf-8").startswith("# Threat Model")


def test_context_map_seeds_focus_areas_and_bug_shapes(tmp_path):
    project = _project(tmp_path)
    model = from_context_map(project, {
        "entry_points": [{"name": "POST /login", "file": "routes.py"}],
        "trust_boundaries": [{"name": "browser to API", "trust": "external"}],
        "sinks": [{"name": "subprocess.run", "file": "worker.py"}],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No auth before shell execution",
            "severity": "critical",
        }],
        "hardcoded_secrets": [{
            "name": "MASTER_PASSWORD",
            "file": "auth.py",
            "line": 7,
        }],
    })

    assert "Entry point: POST /login (routes.py)" in model.focus_areas
    assert "Sensitive sink: subprocess.run (worker.py)" in model.focus_areas
    assert model.trust_boundaries == ["browser to API - external"]
    assert model.known_bug_shapes[0].endswith("No auth before shell execution (critical)")
    assert any("Hardcoded secret" in item for item in model.known_bug_shapes)
    assert model.version == 2
    assert model.data_flows[0]["id"] == "DF-001"
    assert model.threats[0]["status"] == "needs_evidence"
    assert model.threats[0]["risk_score"] >= 90
    assert any(c["id"] == "CTRL-004" for c in model.controls)


def test_prompt_context_escapes_control_characters(tmp_path):
    project = _project(tmp_path)
    model = blank_for_project(project)
    model.focus_areas = ["HTTP header\x1b[2J to sink"]

    rendered = prompt_context(model)

    assert "\x1b" not in rendered
    assert "\\x1b" in rendered


def test_lint_diff_and_report_surface_threat_model_health(tmp_path):
    project = _project(tmp_path)
    context_map = {
        "entry_points": [{"id": "EP-001", "name": "POST /login"}],
        "trust_boundaries": [{"id": "TB-001", "name": "browser to API"}],
        "sink_details": [{"id": "SINK-001", "type": "sql query", "file": "auth.py", "line": 12}],
        "unchecked_flows": [{
            "id": "UF-001",
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No parameter binding",
            "severity": "high",
        }],
    }
    model = from_context_map(project, context_map)

    issues = lint_model(model)
    drift = diff_context_map(model, {
        **context_map,
        "entry_points": context_map["entry_points"] + [{"id": "EP-002", "name": "GET /debug"}],
    })
    report = render_report(model, lint=issues, drift=drift)

    assert not any(i["severity"] == "error" for i in issues)
    assert drift["is_drifted"] is True
    assert "GET /debug" in "\n".join(drift["new_entry_points"])
    assert "Threat Model Report" in report
    assert "Top Threats" in report
    assert "██████" in report
    assert "__VERSION__" not in report


def test_verified_outcomes_update_matching_threat_status(tmp_path):
    project = _project(tmp_path)
    model = from_context_map(project, {
        "entry_points": [{"id": "EP-001", "name": "GET /hello"}],
        "sink_details": [{"id": "SINK-001", "type": "subprocess", "file": "hello.py"}],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "severity": "critical",
        }],
    })
    outcome = VerifiedOutcome(
        finding_id="SINK-001",
        oracle=Oracle.SANDBOX,
        status=OutcomeStatus.VERIFIED,
        reproducible=True,
        evidence={"signal": "SIGABRT"},
        cwe_id="CWE-78",
        file="hello.py",
    )

    link_verified_outcomes(model, [outcome])

    assert model.threats[0]["status"] == "confirmed"
    assert model.threats[0]["evidence_ids"]
    assert any(ev["oracle"] == "sandbox" for ev in model.evidence)


def test_enrich_from_context_map_preserves_operator_prose_but_adds_v2_ledger(tmp_path):
    project = _project(tmp_path)
    model = blank_for_project(project)
    model.version = 1
    model.summary = "operator wording stays"
    model.focus_areas = ["keep this"]
    model.threats = []
    model.controls = []

    enrich_from_context_map(model, {
        "entry_points": [{"id": "EP-001", "name": "GET /search"}],
        "sink_details": [{"id": "SINK-001", "type": "template render", "file": "posts.py"}],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No escaping before template render",
            "severity": "critical",
        }],
    })

    assert model.version == 2
    assert model.summary == "operator wording stays"
    assert model.focus_areas == ["keep this"]
    assert model.threats
    assert model.threats[0]["category"] == "server_side_template_injection"
    assert model.controls


def test_load_for_target_does_not_use_unrelated_active_project(tmp_path):
    target = tmp_path / "target-a"
    other = tmp_path / "target-b"
    target.mkdir()
    other.mkdir()
    project = _project(tmp_path, target=str(other))

    class FakeManager:
        def find_project_for_target(self, _target):
            return None

        def get_active(self):
            return "active"

        def load(self, _name):
            return project

    with patch("core.project.project.ProjectManager", return_value=FakeManager()):
        assert load_for_target(target) is None


# ---------------------------------------------------------------
# Security defences — added when PR #776 review surfaced the
# substrate issues (path traversal / silent-coerce / unbounded
# raw evidence / markdown+Mermaid injection / concurrent writes).
# ---------------------------------------------------------------


def test_from_dict_rejects_hostile_version_string():
    from core.threat_model import ThreatModel
    import pytest
    with pytest.raises(ValueError, match="version"):
        ThreatModel.from_dict({
            "project_name": "x", "target": "/x",
            "version": "evil",
        })


def test_from_dict_rejects_out_of_range_version():
    from core.threat_model import ThreatModel
    import pytest
    with pytest.raises(ValueError, match="schema version"):
        ThreatModel.from_dict({
            "project_name": "x", "target": "/x",
            "version": 999,
        })


def test_from_dict_caps_oversized_list_entries():
    # Pin both caps: the list-entry-count cap
    # (``_MAX_LIST_ENTRIES``) and the per-entry byte cap
    # (``_MAX_STRING_BYTES``). Fixture sizes are deliberately
    # tight — proving the cap doesn't require allocating a real
    # hostile-sized blob in the test; ``_clip_str`` now
    # pre-truncates before ``escape_nonprintable`` so the
    # substrate's behaviour on multi-MB inputs is bounded
    # regardless.
    from core.threat_model import (
        _MAX_LIST_ENTRIES,
        _MAX_STRING_BYTES,
        ThreatModel,
    )
    oversized = "A" * (_MAX_STRING_BYTES * 2)   # twice per-entry cap
    overlong_count = _MAX_LIST_ENTRIES * 2      # twice list cap
    model = ThreatModel.from_dict({
        "project_name": "x", "target": "/x",
        "focus_areas": [oversized] * overlong_count,
    })
    # List cap kicked in.
    assert len(model.focus_areas) == _MAX_LIST_ENTRIES
    # Per-entry byte cap kicked in.
    assert all(len(v) <= _MAX_STRING_BYTES for v in model.focus_areas)


def test_render_markdown_escapes_newline_injection(tmp_path):
    # Adversarial focus_area: opens a new ## section via embedded
    # newline. Pre-fix the renderer interpolated raw, forging
    # operator-readable section headings at line-start. Markdown
    # only treats ``## X`` as a heading at line-start, so the
    # security property is "the ## Forged Section text does NOT
    # appear at the start of any line." Inline (mid-bullet) is
    # just text.
    from core.threat_model import (
        ThreatModel, render_markdown,
    )
    model = ThreatModel(
        project_name="demo", target="/x",
        focus_areas=["benign\n## Forged Section\nexfil"],
    )
    md = render_markdown(model)
    # No line in the rendered markdown begins with "## Forged".
    assert not any(
        line.lstrip().startswith("## Forged") for line in md.splitlines()
    )
    assert "Forged Section" in md  # text preserved, structure not


def test_render_markdown_escapes_fenced_block_injection():
    from core.threat_model import (
        ThreatModel, render_markdown,
    )
    model = ThreatModel(
        project_name="demo", target="/x",
        focus_areas=["foo```\nfake fenced\n```bar"],
    )
    md = render_markdown(model)
    # Backticks should be replaced with the safe lookalike.
    assert "```" not in md.replace("```\n", "").replace("\n```", "")


def test_mermaid_label_strips_breakout_characters():
    from core.threat_model import _mermaid_label
    hostile = 'foo"]; flowchart LR; pwned -->|x|'
    label = _mermaid_label(hostile)
    # Mermaid statement terminator and pipe-bar both neutralised.
    assert "]; flowchart" not in label
    assert "|x|" not in label


def test_sanitise_raw_evidence_drops_unallowed_keys():
    from core.threat_model import _sanitise_raw_evidence
    hostile = {
        "summary": "ok",       # allowlisted
        "tool": "sandbox",     # allowlisted
        "secret_field": "x",   # NOT allowlisted — must drop
        "trusted_data": "y",   # NOT allowlisted — must drop
    }
    out = _sanitise_raw_evidence(hostile)
    assert "summary" in out and "tool" in out
    assert "secret_field" not in out
    assert "trusted_data" not in out


def test_sanitise_raw_evidence_caps_total_size():
    from core.threat_model import _sanitise_raw_evidence
    # All keys allowlisted but each value is huge — total size
    # cap kicks in via the _truncated marker.
    hostile = {
        "summary": "A" * 100_000,
        "tool": "B" * 100_000,
        "command": "C" * 100_000,
    }
    out = _sanitise_raw_evidence(hostile)
    # Either the truncation marker is set, OR the total is
    # bounded — both are valid outcomes of the cap.
    assert out.get("_truncated") or sum(
        len(str(v)) for v in out.values()
    ) <= 32 * 1024 + 100  # +slack for the truncated marker


def test_save_model_refuses_concurrent_overwrite(tmp_path):
    # Two writers race: writer 1 loads, writer 2 loads + saves,
    # writer 1 tries to save with the stale expected_mtime ->
    # should refuse.
    from core.threat_model import ThreatModel, save_model
    json_path = tmp_path / "tm.json"
    md_path = tmp_path / "tm.md"
    model = ThreatModel(project_name="demo", target="/x")
    save_model(model, json_path, md_path)
    stale_mtime = json_path.stat().st_mtime

    # Concurrent writer changes the file (simulate via touch +
    # rewrite).
    import time
    time.sleep(0.05)
    save_model(
        ThreatModel(project_name="demo", target="/x", notes="updated"),
        json_path, md_path,
    )

    # First writer tries to save with the stale mtime — refused.
    import pytest
    with pytest.raises(RuntimeError, match="modified by another"):
        save_model(
            ThreatModel(project_name="demo", target="/x", notes="lost"),
            json_path, md_path,
            expected_mtime=stale_mtime,
        )


def test_project_threat_model_json_path_refuses_traversal(tmp_path):
    # Operator-tamper-influenced project.json sets
    # threat_model_path to an absolute path outside output_dir.
    # Must be refused.
    from core.threat_model import _project_threat_model_json_path
    proj_out = tmp_path / "proj_out"
    proj_out.mkdir()
    proj = SimpleNamespace(
        name="demo",
        target=str(tmp_path / "target"),
        output_dir=str(proj_out),
        threat_model_path="/etc/shadow",
    )
    assert _project_threat_model_json_path(proj) is None


def test_project_threat_model_json_path_refuses_relative_escape(tmp_path):
    from core.threat_model import _project_threat_model_json_path
    proj_out = tmp_path / "proj_out"
    proj_out.mkdir()
    proj = SimpleNamespace(
        name="demo",
        target=str(tmp_path / "target"),
        output_dir=str(proj_out),
        threat_model_path="../../etc/passwd",
    )
    assert _project_threat_model_json_path(proj) is None


def test_project_threat_model_json_path_accepts_in_tree_relative(tmp_path):
    # Relative path that resolves INSIDE output_dir is fine.
    from core.threat_model import _project_threat_model_json_path
    proj_out = tmp_path / "proj_out"
    proj_out.mkdir()
    proj = SimpleNamespace(
        name="demo",
        target=str(tmp_path / "target"),
        output_dir=str(proj_out),
        threat_model_path="custom/tm.json",
    )
    result = _project_threat_model_json_path(proj)
    assert result is not None
    assert result.is_relative_to(proj_out.resolve())
