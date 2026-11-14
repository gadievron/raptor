import json
import subprocess
from pathlib import Path

import pytest

from core.dataflow.codeql_augmented_run import (
    CodeQLRunError, analyze, run_baseline_and_augmented,
)
from core.dataflow.finding_diff import diff_sarif_files


def _document(has_finding):
    def step(line):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "owned.py"}, "region": {"startLine": line},
        }}}

    results = [{"ruleId": "owned-rule", "codeFlows": [{"threadFlows": [{
        "locations": [step(1), step(2)],
    }]}]}] if has_finding else []
    return {"runs": [{"results": results}]}


def _pack(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "codeql-pack.yml").write_text("name: owned/models\nversion: 0.0.1\nlibrary: true\n")
    return pack


@pytest.mark.parametrize("missing_leg", ["baseline.sarif", "augmented.sarif"])
def test_missing_current_measurement_output_cannot_reuse_previous_metrics(tmp_path, missing_leg):
    out = tmp_path / "runs"
    out.mkdir()
    (out / "baseline.sarif").write_text(json.dumps(_document(True)))
    (out / "augmented.sarif").write_text(json.dumps(_document(False)))
    calls = []

    def runner(argv, **kwargs):
        path = Path(next(arg.removeprefix("--output=") for arg in argv if arg.startswith("--output=")))
        calls.append(path.name)
        if path.name != missing_leg:
            path.write_text(json.dumps(_document(path.name == "baseline.sarif")))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    baseline, augmented = run_baseline_and_augmented(
        tmp_path / "db", ["owned.ql"], _pack(tmp_path), out, runner=runner,
    )
    with pytest.raises(RuntimeError, match="SARIF stat failed"):
        diff_sarif_files(baseline.sarif_path, augmented.sarif_path)
    assert calls == ["baseline.sarif", "augmented.sarif"]


def test_current_measurement_outputs_replace_previous_metrics(tmp_path):
    out = tmp_path / "runs"
    out.mkdir()
    (out / "baseline.sarif").write_text(json.dumps(_document(True)))
    (out / "augmented.sarif").write_text(json.dumps(_document(False)))
    calls = []

    def runner(argv, **kwargs):
        path = Path(next(arg.removeprefix("--output=") for arg in argv if arg.startswith("--output=")))
        calls.append(path.name)
        assert not path.exists()
        path.write_text(json.dumps(_document(True)))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    baseline, augmented = run_baseline_and_augmented(
        tmp_path / "db", ["owned.ql"], _pack(tmp_path), out, runner=runner,
    )
    result = diff_sarif_files(baseline.sarif_path, augmented.sarif_path)
    assert result.baseline_count == result.augmented_count == 1
    assert result.suppression_rate == 0
    assert calls == ["baseline.sarif", "augmented.sarif"]


def test_invalid_pack_preserves_previous_output_before_dispatch(tmp_path):
    pack = _pack(tmp_path)
    (pack / "codeql-pack.yml").write_text("version: 0.0.1\n")
    output = tmp_path / "previous.sarif"
    original = json.dumps(_document(True))
    output.write_text(original)
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        pytest.fail("invalid pack reached analysis")

    with pytest.raises(CodeQLRunError, match="no parseable name"):
        analyze(tmp_path / "db", ["owned.ql"], output, extension_pack=pack, runner=runner)
    assert output.read_text() == original
    assert calls == []
