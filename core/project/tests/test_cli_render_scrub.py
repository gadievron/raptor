"""/project render surfaces print finding-derived text (LLM-authored,
or restored verbatim by /project import) — hostile bytes must be
escaped at the print sites."""

from __future__ import annotations

from core.project.cli import _print_code_findings, _print_correlate_counts

HOSTILE = "\x1b]0;pwned\x07\x9b2J‮evil"
RAW = ("\x1b", "\x07", "\x9b", "‮")


def _finding(**over) -> dict:
    base = {
        "id": "F-1",
        "file": f"src/{HOSTILE}.c",
        "function": "main",
        "line": 10,
        "vuln_type": f"overflow{HOSTILE}",
        "status": "confirmed",
        "reasoning": f"because {HOSTILE} of taint",
        "proof_source": f"argv{HOSTILE}",
        "proof_sink": f"strcpy{HOSTILE}",
    }
    base.update(over)
    return base


def test_code_findings_table_and_detail_escaped(capsys):
    _print_code_findings([_finding()], detailed=True)
    out = capsys.readouterr().out
    assert "verflow" in out  # title_case_type may capitalise
    for raw in RAW:
        assert raw not in out


def test_correlate_counts_are_int_only(capsys):
    # The header helper coerces every value — a foreign string in a
    # count slot raises rather than rendering.
    _print_correlate_counts({
        "runs": 2, "total_unique_findings": 5,
        "disagreements": 1, "new_findings": 0,
        "potentially_resolved": 0,
    })
    out = capsys.readouterr().out
    assert "Runs: 2" in out and "Disagreements: 1" in out

    import pytest
    with pytest.raises((ValueError, TypeError)):
        _print_correlate_counts({"runs": HOSTILE,
                                 "total_unique_findings": 1})


def test_emit_json_payload_ascii_encodes_c1(capfdbinary):
    """--json lanes: bare JSON escapes C0 but passes C1 terminal
    controls (single-byte CSI/OSC) raw — the funnel must ASCII-encode
    while staying valid, pipe-friendly JSON."""
    import json as _json

    from core.project.cli import _emit_json_payload

    _emit_json_payload({"threats": [{"title": f"t{HOSTILE}\x9d0;x"}]})
    out = capfdbinary.readouterr().out
    for raw in (b"\x1b", b"\x07", b"\x9b", b"\x9d"):
        assert raw not in out
    doc = _json.loads(out)
    assert doc["threats"][0]["title"].startswith("t\x1b")  # escaped, intact
    assert out.endswith(b"\n")


# ---------------------------------------------------------------------------
# Child-writable run metadata / imported project fields: the remaining
# render lanes (status rows, show-run detail, binary list, use/adopt
# echoes, merge prints, annotations diff, report annotation headings).
# ---------------------------------------------------------------------------


class _FakeProject:
    def __init__(self, tmp, runs=(), by_type=None):
        self.name = "proj"
        self.description = ""
        self.target = "/tmp/t"
        self.output_dir = str(tmp)
        self.output_path = tmp
        self.created = "2026-01-01T00:00:00+00:00"
        self.notes = ""
        self.trust = {}
        self.threat_model_path = None
        self._runs = list(runs)
        self._by_type = by_type or {}

    def settings_view(self):
        return {}

    def get_run_dirs(self, sweep=False):
        return self._runs

    def get_run_dirs_by_type(self):
        return self._by_type


def _hostile_run_dir(tmp_path, name="run_a", command="scan",
                     timestamp=None, manifest=None):
    import json as _json
    d = tmp_path / name
    d.mkdir()
    (d / ".raptor-run.json").write_text(_json.dumps({
        "version": 1,
        "command": command,
        "status": f"completed{HOSTILE}",
        "output_summary": f"5 findings{HOSTILE}",
        "output_summary_v": 2,
        "timestamp": (timestamp if timestamp is not None
                      else f"2026-01-01T00{HOSTILE}"),
        "manifest": (manifest if manifest is not None
                     else {"source_control": {
                         "base_sha": f"\x1b[2J{HOSTILE}beef"}}),
    }), encoding="utf-8")
    return d


def test_status_run_rows_escape_and_coerce_child_writable_cells(
        tmp_path, capsys):
    """One junk (non-string) marker cell previously raised TypeError in
    the :12s format spec and wedged /project status entirely; string
    cells (incl. the run-dir name and the manifest base_sha behind the
    provenance tag) rendered raw."""
    from core.project.cli import _print_status
    d = _hostile_run_dir(tmp_path, name=f"run_{HOSTILE}a",
                         command={"not": "a-string"})
    _print_status(_FakeProject(tmp_path, runs=[d]))
    out = capsys.readouterr().out
    assert "Runs: 1" in out
    for raw in RAW:
        assert raw not in out


def test_status_survives_junk_manifest_sha(tmp_path, capsys):
    """A non-string base_sha reaches the provenance tag through
    format_sha_short — it must not TypeError the row render."""
    from core.project.cli import _print_status
    d = _hostile_run_dir(
        tmp_path, manifest={"source_control": {"base_sha": 12345}})
    _print_status(_FakeProject(tmp_path, runs=[d]))
    out = capsys.readouterr().out
    assert "Runs: 1" in out
    for raw in RAW:
        assert raw not in out


def test_show_run_detail_escapes_command_status_timestamp_and_name(
        tmp_path, capsys):
    from core.project.cli import _print_run_provenance
    d = _hostile_run_dir(tmp_path, name=f"run_{HOSTILE}a",
                         command=f"scan{HOSTILE}")
    _print_run_provenance(_FakeProject(tmp_path, runs=[d]),
                          "run_")
    out = capsys.readouterr().out
    assert "Command:" in out and "Status:" in out and "When:" in out
    for raw in RAW:
        assert raw not in out


def test_show_run_detail_survives_non_string_timestamp(
        tmp_path, capsys):
    """A junk (non-string) timestamp cell must not TypeError the
    [:19] slice and wedge /project show."""
    from core.project.cli import _print_run_provenance
    d = _hostile_run_dir(tmp_path, timestamp=123456789)
    _print_run_provenance(_FakeProject(tmp_path, runs=[d]), "run_a")
    out = capsys.readouterr().out
    assert "Command:" in out
    for raw in RAW:
        assert raw not in out


def test_show_ambiguous_match_list_escapes_run_names(tmp_path, capsys):
    from core.project.cli import _print_run_provenance
    d1 = _hostile_run_dir(tmp_path, name=f"scan_{HOSTILE}1")
    d2 = _hostile_run_dir(tmp_path, name=f"scan_{HOSTILE}2")
    _print_run_provenance(_FakeProject(tmp_path, runs=[d1, d2]),
                          "scan_")
    out = capsys.readouterr().out
    assert "Ambiguous" in out
    for raw in RAW:
        assert raw not in out


def test_binary_list_escapes_persisted_paths(capsys):
    from unittest.mock import patch

    from core.project.cli import main
    fake_p = type("P", (), {"binaries": [f"/bins/x{HOSTILE}"]})()
    with patch("core.project.cli.ProjectManager") as MockMgr:
        MockMgr.return_value.load.return_value = fake_p
        with patch("sys.argv",
                   ["raptor-project", "binary", "list", "proj"]):
            main()
    out = capsys.readouterr().out
    assert "binaries (1)" in out
    for raw in RAW:
        assert raw not in out


def test_adopt_inferred_target_escaped(capsys):
    from unittest.mock import patch

    from core.project.cli import main
    with patch("core.project.cli.ProjectManager") as MockMgr:
        inst = MockMgr.return_value
        inst.load.return_value = None
        inst.adopt_target_for.return_value = f"/tgt{HOSTILE}"
        inst.add_directory.return_value = 0
        with patch("sys.argv",
                   ["raptor-project", "adopt", "proj", "run_x"]):
            main()
    out = capsys.readouterr().out
    assert "Target inferred from run metadata:" in out
    for raw in RAW:
        assert raw not in out


def test_merge_live_skip_and_failed_delete_lines_escaped(
        tmp_path, capsys, monkeypatch):
    """The merge containment fix sanitised cmd_type and the sibling
    {e} lanes but left d.name raw in the still-running skip line and
    relayed rmtree exception text through the failed_deletes list
    unescaped."""
    import shutil

    from core.project import cli as project_cli

    d1 = _hostile_run_dir(tmp_path, name=f"scan-a{HOSTILE}")
    d2 = _hostile_run_dir(tmp_path, name=f"scan-b{HOSTILE}")
    proj = _FakeProject(tmp_path, by_type={"scan": [d1, d2]})

    # Live-skip lane: both runs report still-running.
    monkeypatch.setattr("core.project.clean.split_live_runs",
                        lambda dirs: ([], list(dirs)))
    project_cli._do_merge(proj, "all", yes=True)
    out = capsys.readouterr().out
    assert "skipped (still running)" in out
    for raw in RAW:
        assert raw not in out

    # Failed-delete lane: merge succeeds, rmtree relays hostile text.
    monkeypatch.setattr("core.project.clean.split_live_runs",
                        lambda dirs: (list(dirs), []))
    monkeypatch.setattr(
        "core.project.merge.merge_runs",
        lambda dirs, merged: {"unique_findings": 1, "unique_vulns": 1,
                              "runs_merged": 2})
    monkeypatch.setattr("core.run.pin.freeze_run_pin",
                        lambda *a, **k: None)

    def _boom(path, *a, **k):
        raise OSError(f"unlink failed: {HOSTILE}")

    monkeypatch.setattr(shutil, "rmtree", _boom)
    project_cli._do_merge(proj, "all", yes=True)
    out = capsys.readouterr().out
    assert "failed to delete" in out
    for raw in RAW:
        assert raw not in out


def test_annotations_diff_render_escapes_agent_fields(capsys):
    from core.project.annotations_diff import format_diff
    rec = {
        "file": f"src/a{HOSTILE}.py",
        "function": f"fn{HOSTILE}",
        "metadata": {"status": f"finding{HOSTILE}",
                     "source": f"agent{HOSTILE}"},
    }
    changed = {
        "before": {**rec, "metadata": {"status": f"clean{HOSTILE}"}},
        "after": rec,
    }
    text = format_diff({
        "run_a": "a", "run_b": "b",
        "added": [rec], "removed": [rec],
        "changed": [changed], "unchanged": [],
    })
    for raw in RAW:
        assert raw not in text
    assert "status=" in text and "source=" in text


def test_report_annotation_headings_escaped():
    """The per-entry heading wraps file/function/status/source in
    backtick spans — spans stop neither ANSI bytes nor a backtick
    breakout, so the values must be sanitised like the bodies."""
    from core.project.report import render_annotations_markdown
    md = render_annotations_markdown([{
        "file": f"src/a{HOSTILE}`.py",
        "function": f"fn{HOSTILE}",
        "status": f"finding{HOSTILE}",
        "source": f"agent{HOSTILE}",
        "body": "ok",
    }], "proj")
    for raw in RAW:
        assert raw not in md
    # No raw backtick from the value survives inside the heading span.
    heading = next(ln for ln in md.splitlines() if ln.startswith("### "))
    assert heading.count("`") == 4  # exactly the two wrapping pairs
