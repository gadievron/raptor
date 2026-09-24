"""CLI surface for /binary hunt: flag validation, dispatch, lifecycle."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from packages.binary_analysis.cli import _build_parser, main
from packages.binary_analysis.hunt import HuntError
from packages.binary_analysis.manifest import BinaryManifest
from packages.binary_analysis.pipeline import BinaryAnalysisResult


def _make_result(binary: Path, out: Path) -> BinaryAnalysisResult:
    manifest = BinaryManifest(
        schema_version=1,
        binary_path=str(binary),
        binary_sha256="a" * 64,
        size_bytes=binary.stat().st_size,
        executable=True,
        target_kind="elf",
        arch="x86",
        bits=64,
        binary_format="elf",
    )
    return BinaryAnalysisResult(
        manifest=manifest,
        context_map={
            "entry_points": [],
            "sink_details": [],
            "surface_details": [],
            "candidate_flows": [],
            "framework_callback_candidates": [],
            "class_inventory": {"summary": {"class_count": 0}},
            "decompilations": {"coverage": {"decompiled_functions": 0}},
        },
        evidence=[],
        input_channels=[],
        graph_path=out / "graph" / "binary-graph.sqlite",
    )


def _anchor_payload(**overrides):
    payload = {
        "mode": "anchor",
        "families": [],
        "truncation_lines": [],
        "artifacts": {"json": "/x/binary-hunt-a.json",
                      "report": "/x/binary-hunt-a.md"},
    }
    payload.update(overrides)
    return payload


def test_parser_accepts_hunt_flags() -> None:
    args = _build_parser().parse_args([
        "hunt", "/tmp/run", "--anchor", "record blob",
        "--anchor", "recblob", "--anchor-re",
        "--calls", "parse", "--and-not-calls", "check",
        "--transitive", "--max-depth", "3", "--json",
    ])
    assert args.anchor == ["record blob", "recblob"]
    assert args.anchor_re is True
    assert args.calls == "parse"
    assert args.and_not_calls == "check"
    assert args.transitive is True
    assert args.max_depth == 3


def test_hunt_requires_a_mode(tmp_path: Path, capsys) -> None:
    rc = main(["hunt", str(tmp_path)])
    assert rc == 2
    assert "--anchor and/or --calls" in capsys.readouterr().err


def test_anchor_re_requires_anchor(tmp_path: Path, capsys) -> None:
    rc = main(["hunt", str(tmp_path), "--anchor-re", "--calls", "x"])
    assert rc == 2
    assert "--anchor-re requires --anchor" in capsys.readouterr().err


def test_calls_modifiers_require_calls(tmp_path: Path, capsys) -> None:
    for extra in (["--and-not-calls", "y"], ["--transitive"]):
        rc = main(["hunt", str(tmp_path), "--anchor", "z", *extra])
        assert rc == 2, extra
        assert "requires --calls" in capsys.readouterr().err


def test_max_depth_requires_transitive(tmp_path: Path, capsys) -> None:
    # Silently-inert flags lie about what ran: --max-depth without
    # --transitive refuses instead of being ignored.
    rc = main(["hunt", str(tmp_path), "--calls", "x", "--max-depth", "3"])
    assert rc == 2
    assert "--max-depth requires --transitive" in capsys.readouterr().err
    # And still refused when --calls is missing entirely.
    rc = main(["hunt", str(tmp_path), "--anchor", "z", "--max-depth", "3"])
    assert rc == 2
    assert "requires --calls" in capsys.readouterr().err


def test_bad_regex_refused_before_any_work(tmp_path: Path, capsys) -> None:
    with patch("packages.binary_analysis.cli.start_run") as start_run, \
            patch("packages.binary_analysis.hunt.run_anchor_hunt") as hunt:
        rc = main(["hunt", str(tmp_path), "--anchor", "(a+)+b",
                   "--anchor-re"])
    assert rc == 2
    assert "nested repetition" in capsys.readouterr().err
    start_run.assert_not_called()
    hunt.assert_not_called()


def test_run_dir_mode_dispatches_without_new_lifecycle(
    tmp_path: Path, capsys,
) -> None:
    with (
        patch("packages.binary_analysis.hunt.run_anchor_hunt",
              return_value=_anchor_payload()) as anchor,
        patch("packages.binary_analysis.hunt.run_calls_hunt",
              return_value={
                  "mode": "calls",
                  "query": {"resolved_calls": "parse"},
                  "caller_count": 2,
                  "callers": [],
                  "truncation_lines": [],
                  "artifacts": {"json": "/x/c.json", "report": "/x/c.md"},
              }) as calls,
        patch("packages.binary_analysis.cli.start_run") as start_run,
        patch("packages.binary_analysis.cli.complete_run") as complete_run,
    ):
        rc = main([
            "hunt", str(tmp_path), "--anchor", "record",
            "--calls", "parse", "--and-not-calls", "check",
            "--transitive",
        ])
    assert rc == 0
    # Existing run dir: hunts append to it; no new run lifecycle.
    start_run.assert_not_called()
    complete_run.assert_not_called()
    anchor.assert_called_once_with(
        tmp_path.resolve(), ["record"], regex=False,
    )
    calls.assert_called_once_with(
        tmp_path.resolve(), "parse", and_not_calls="check",
        transitive=True, max_depth=None,
    )
    out = capsys.readouterr().out
    assert "Callers of parse: 2" in out


def test_bare_binary_maps_first_with_lifecycle(tmp_path: Path) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    binary.chmod(0o755)
    out = tmp_path / "out"
    result = _make_result(binary, out)
    with (
        patch("packages.binary_analysis.cli.analyse_blackbox_binary",
              return_value=result) as analyse,
        patch("packages.binary_analysis.cli.start_run") as start_run,
        patch("packages.binary_analysis.cli.complete_run") as complete_run,
        patch("packages.binary_analysis.cli.get_output_dir",
              return_value=out),
        patch("packages.binary_analysis.hunt.run_anchor_hunt",
              return_value=_anchor_payload()) as anchor,
    ):
        rc = main(["hunt", str(binary), "--anchor", "record"])
    assert rc == 0
    analyse.assert_called_once()
    start_run.assert_called_once_with(
        out, "understand", target=str(binary.resolve()),
    )
    complete_run.assert_called_once_with(out)
    anchor.assert_called_once_with(out, ["record"], regex=False)
    payload = json.loads((out / "map-result.json").read_text())
    assert payload["mode"] == "map"


def test_bare_binary_analyse_failure_fails_run(tmp_path: Path, capsys) -> None:
    """An analyse crash in the bare-binary lane must fail the run
    (never strand it 'running'), print a scrubbed one-liner instead of
    a raw traceback, and exit 1 — the same shape as map."""
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    binary.chmod(0o755)
    out = tmp_path / "out"
    with (
        patch("packages.binary_analysis.cli.analyse_blackbox_binary",
              side_effect=RuntimeError("r2 exploded \x1bmid-analysis")),
        patch("packages.binary_analysis.cli.start_run") as start_run,
        patch("packages.binary_analysis.cli.complete_run") as complete_run,
        patch("packages.binary_analysis.cli.fail_run") as fail_run,
        patch("packages.binary_analysis.cli.get_output_dir",
              return_value=out),
        patch("packages.binary_analysis.hunt.run_anchor_hunt") as anchor,
    ):
        rc = main(["hunt", str(binary), "--anchor", "record"])
    assert rc == 1
    start_run.assert_called_once()
    fail_run.assert_called_once()
    assert fail_run.call_args.args[0] == out
    assert "binary hunt failed" in fail_run.call_args.args[1]
    complete_run.assert_not_called()
    anchor.assert_not_called()
    err = capsys.readouterr().err
    assert "hunt map phase failed" in err
    assert "\x1b" not in err


def test_hunt_refusal_exits_2_and_fails_run(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    binary.chmod(0o755)
    out = tmp_path / "out"
    result = _make_result(binary, out)
    with (
        patch("packages.binary_analysis.cli.analyse_blackbox_binary",
              return_value=result),
        patch("packages.binary_analysis.cli.start_run"),
        patch("packages.binary_analysis.cli.complete_run") as complete_run,
        patch("packages.binary_analysis.cli.fail_run") as fail_run,
        patch("packages.binary_analysis.cli.get_output_dir",
              return_value=out),
        patch("packages.binary_analysis.hunt.run_calls_hunt",
              side_effect=HuntError("no call-graph substrate available")),
    ):
        rc = main(["hunt", str(binary), "--calls", "parse"])
    assert rc == 2
    complete_run.assert_not_called()
    fail_run.assert_called_once()
    assert "hunt refused" in capsys.readouterr().err


def test_missing_target_exits_2(tmp_path: Path, capsys) -> None:
    rc = main(["hunt", str(tmp_path / "nope"), "--anchor", "x"])
    assert rc == 2
    assert "neither a run directory nor a file" in capsys.readouterr().err


def test_summary_scrubs_hostile_names(tmp_path: Path, capsys) -> None:
    payload = _anchor_payload(
        families=[{
            "id": "BHUNTFAM-abc",
            "members": [{"name": "fcn.\x1b[31mred"}],
        }],
        truncation_lines=["family capped at 1 of 2 \x1b[0m"],
    )
    with patch("packages.binary_analysis.hunt.run_anchor_hunt",
               return_value=payload):
        rc = main(["hunt", str(tmp_path), "--anchor", "record"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "capped at 1 of 2" in out


def test_json_lane_ascii_encodes(tmp_path: Path, capsys) -> None:
    payload = _anchor_payload(families=[{"id": "F", "members": []}])
    payload["c1"] = "\x85line"
    with patch("packages.binary_analysis.hunt.run_anchor_hunt",
               return_value=payload):
        rc = main(["hunt", str(tmp_path), "--anchor", "record", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "\x85" not in out
    assert "\\u0085" in out
