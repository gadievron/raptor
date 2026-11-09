"""Default output anchoring must survive the remediation target cwd."""
import json

from packages.sca import optimise, pipeline
from packages.sca.pipeline import RunResult


def test_default_apply_stages_and_applies_from_one_output_root(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "project"
    target.mkdir()
    manifest = target / "requirements.txt"
    manifest.write_text("owned==1.0.0\n")
    calls = []

    def prepass(*, target, output_dir, **kwargs):
        calls.append(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        findings = output_dir / "findings.json"
        findings.write_text(json.dumps([{
            "vuln_type": "sca:vulnerable_dependency", "file": str(manifest), "severity": "high",
            "sca": {"ecosystem": "PyPI", "name": "owned", "version": "1.0.0", "pin_style": "exact",
                    "is_lockfile": False, "fixed_version": "1.1.0",
                    "advisory": {"id": "TEST-1", "fixed_versions": ["1.1.0"]}},
        }]))
        return RunResult(target, output_dir, findings, output_dir / "report.md", output_dir / "sbom.json",
                         output_dir / "findings.sarif", 1, 1, 0, 0, 0, 0, 0, 0)

    monkeypatch.setattr(pipeline, "run_sca", prepass)
    assert optimise.main([str(target), "--apply", "--no-llm", "--no-hash-pin"]) == 0
    assert manifest.read_text() == "owned==1.1.0\n"
    assert len(calls) == 1
    assert not (target / "out").exists()
    assert (calls[0] / "changes.json").is_file()
    assert not (calls[0] / "_apply_staging").exists()
    assert "applied in-place" in capsys.readouterr().out
