"""In-place fixes own fresh staging; review output remains persistent."""

from __future__ import annotations

import json
from contextlib import ExitStack
from pathlib import Path

import pytest

from core.testing.restricted_tree import restricted_tree
from packages.sca import optimise, pipeline
from packages.sca.pipeline import RunResult


@pytest.fixture
def fix_case(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "output"
    monkeypatch.setattr(optimise, "_resolve_out_dir", lambda explicit: output)

    def prepass(*, target, output_dir, options):
        assert not options.enable_llm_review and not options.enable_triage
        output_dir.mkdir(parents=True, exist_ok=True)
        findings = output_dir / "findings.json"
        name = target.name
        findings.write_text(json.dumps([{
            "vuln_type": "sca:vulnerable_dependency", "file": str(target / "requirements.txt"),
            "severity": "high", "sca": {
                "ecosystem": "PyPI", "name": name, "version": "1.0.0", "pin_style": "exact",
                "is_lockfile": False, "fixed_version": "1.1.0",
                "advisory": {"id": "TEST-1", "fixed_versions": ["1.1.0"]},
            },
        }]))
        return RunResult(target, output_dir, findings, output_dir / "report.md", output_dir / "sbom.json",
                         output_dir / "findings.sarif", 1, 1, 0, 0, 0, 0, 0, 0)

    monkeypatch.setattr(pipeline, "run_sca", prepass)
    target = tmp_path / "owned"
    target.mkdir()
    (target / "requirements.txt").write_text("owned==1.0.0\n")
    return target, output


def _apply(target):
    return optimise.main([str(target), "--apply", "--no-llm", "--no-hash-pin"])


def test_prior_staging_is_never_applied_or_deleted(fix_case):
    target, output = fix_case
    legacy = output / "_apply_staging"
    legacy.mkdir(parents=True)
    (legacy / "unrelated.txt").write_text("old staged data")
    (target / "unrelated.txt").write_text("current target data")

    assert _apply(target) == 0

    assert (target / "requirements.txt").read_text() == "owned==1.1.0\n"
    assert (target / "unrelated.txt").read_text() == "current target data"
    assert (legacy / "unrelated.txt").read_text() == "old staged data"
    assert list(output.glob("_apply_staging-*")) == []


@pytest.mark.parametrize("point", ["materialise", "apply"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit], ids=["io", "interrupt", "exit"])
def test_failed_apply_retires_its_restricted_stage(fix_case, monkeypatch, point, error):
    target, _output = fix_case
    before_cwd = Path.cwd()
    failure = error("stop this fix")
    stages = []
    original = optimise._materialise_changes
    with ExitStack() as stack:
        def stop(stage):
            stages.append(stage)
            assert (stage / "requirements.txt").read_text() == "owned==1.1.0\n"
            stack.enter_context(restricted_tree(stage / "tool-cache", mode=0o500))
            raise failure

        if point == "materialise":
            def fail(*args, **kwargs):
                original(*args, **kwargs)
                stop(args[2])
            monkeypatch.setattr(optimise, "_materialise_changes", fail)
        else:
            def fail(stage, target):
                stop(stage)
            monkeypatch.setattr(optimise, "_apply_in_place", fail)

        with pytest.raises(error) as caught:
            _apply(target)
        assert caught.value is failure
        assert stages and not stages[0].exists()
        assert (target / "requirements.txt").read_text() == "owned==1.0.0\n"
        assert Path.cwd() == before_cwd


def test_interleaved_fixes_use_distinct_stages(fix_case, monkeypatch):
    first, output = fix_case
    second = first.parent / "other"
    second.mkdir()
    (second / "requirements.txt").write_text("other==1.0.0\n")
    original = optimise._materialise_changes
    stages = []

    def materialise(*args, **kwargs):
        result = original(*args, **kwargs)
        stages.append(args[2])
        if len(stages) == 1:
            assert _apply(second) == 0
        return result

    monkeypatch.setattr(optimise, "_materialise_changes", materialise)
    assert _apply(first) == 0
    assert (first / "requirements.txt").read_text() == "owned==1.1.0\n"
    assert (second / "requirements.txt").read_text() == "other==1.1.0\n"
    assert len(stages) == len(set(stages)) == 2
    assert all(not stage.exists() for stage in stages)
    assert list(output.glob("_apply_staging-*")) == []


def test_review_output_persists_without_modifying_target(fix_case):
    target, output = fix_case
    assert optimise.main([str(target), "--out", str(output), "--no-llm", "--no-hash-pin"]) == 0
    assert (output / "proposed/requirements.txt").read_text() == "owned==1.1.0\n"
    assert (target / "requirements.txt").read_text() == "owned==1.0.0\n"


def test_no_rewrite_leaves_no_new_staging(fix_case, monkeypatch):
    target, output = fix_case
    (target / "requirements.txt").write_text("owned==1.1.0\n")
    original = optimise._materialise_changes
    stages = []

    def materialise(*args, **kwargs):
        stages.append(args[2])
        return original(*args, **kwargs)

    monkeypatch.setattr(optimise, "_materialise_changes", materialise)
    assert _apply(target) == 0
    assert (target / "requirements.txt").read_text() == "owned==1.1.0\n"
    assert stages and all(not stage.exists() for stage in stages)
    assert list(output.glob("_apply_staging-*")) == []
