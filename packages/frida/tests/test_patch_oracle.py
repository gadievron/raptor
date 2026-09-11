"""Tests for the patch runtime regression oracle.

The frida sessions themselves are exercised by the live e2e suite;
here ``_run_side`` is monkeypatched to lay down synthetic run
directories so the verdict logic is tested hermetically.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from packages.frida import patch_oracle
from packages.frida.patch_oracle import _parse_location, main, verify_patch


def _sink_event(fn: str, caller_module: str) -> dict:
    return {"ts": 0.1, "type": "send", "payload": {
        "category": "sink", "fn": fn, "tid": 1,
        "caller_module": caller_module,
    }}


def _meta_event() -> dict:
    return {"ts": 0.0, "type": "send",
            "payload": {"_meta": "sink-watch attached"}}


def _write_run(side_dir: Path, binary: Path, events: list[dict]) -> None:
    side_dir.mkdir(parents=True, exist_ok=True)
    # A healthy session always carries at least the attach summary.
    lines = [json.dumps(e) for e in [_meta_event(), *events]]
    with (side_dir / "events.jsonl").open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    (side_dir / "metadata.json").write_text(json.dumps({
        "ok": True,
        "target": {"raw": str(binary), "kind": "binary", "pid": None,
                   "name": binary.name, "binary": str(binary)},
    }))


@pytest.fixture
def binaries(tmp_path: Path) -> tuple[Path, Path]:
    before = tmp_path / "vuln"
    after = tmp_path / "fixed"
    for b in (before, after):
        b.write_bytes(b"\x7fELF")
    return before, after


def _fake_run_side(events_by_side: dict[str, list[dict]]) -> object:
    """Build a _run_side stand-in that writes synthetic run dirs."""
    def fake(binary: Path, script_path: Path, side_dir: Path,
             poc: Path | None, duration: float) -> None:
        _write_run(side_dir, binary, events_by_side[side_dir.name])
    return fake


class TestVerdicts:
    def test_closed_when_sink_stops_firing(self, tmp_path, binaries,
                                           monkeypatch):
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [_sink_event("system", before.name)],
            "after": [],
        }))
        report = verify_patch(before, after, ["system"],
                              tmp_path / "out")
        assert report["verdict"] == "closed"
        assert report["confidence"] == "function"
        assert report["before"]["fired"]["system"]["call_count"] == 1
        assert not report["after"]["any_fired"]

    def test_still_fires_when_sink_survives(self, tmp_path, binaries,
                                            monkeypatch):
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [_sink_event("system", before.name)],
            "after": [_sink_event("system", after.name)],
        }))
        report = verify_patch(before, after, ["system"],
                              tmp_path / "out")
        assert report["verdict"] == "still_fires"
        assert report["confidence"] == "function"

    def test_inconclusive_when_poc_misses_sink(self, tmp_path, binaries,
                                               monkeypatch):
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [],
            "after": [],
        }))
        report = verify_patch(before, after, ["system"],
                              tmp_path / "out")
        assert report["verdict"] == "inconclusive"
        assert report["confidence"] is None

    def test_unattributed_sink_does_not_count(self, tmp_path, binaries,
                                              monkeypatch):
        """A sink firing from a foreign module is not evidence."""
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [_sink_event("system", "libother.so")],
            "after": [],
        }))
        report = verify_patch(before, after, ["system"],
                              tmp_path / "out")
        assert report["verdict"] == "inconclusive"

    def test_site_confidence_from_before_side(self, tmp_path, binaries,
                                              monkeypatch):
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [_sink_event("system", before.name)],
            "after": [],
        }))
        judged = patch_oracle._judge_side

        def judge_with_site(side_dir, binary, sinks, finding_location):
            result = judged(side_dir, binary, sinks, finding_location)
            if side_dir.name == "before":
                result["site_match"] = True
            return result

        monkeypatch.setattr(patch_oracle, "_judge_side", judge_with_site)
        report = verify_patch(before, after, ["system"],
                              tmp_path / "out",
                              finding_location=("vuln.c", 10))
        assert report["verdict"] == "closed"
        assert report["confidence"] == "site"

    def test_broken_after_session_is_inconclusive(self, tmp_path,
                                                  binaries, monkeypatch):
        """Silence from a session that observed NOTHING is not
        evidence the sink stopped firing."""
        before, after = binaries

        def fake(binary: Path, script_path: Path, side_dir: Path,
                 poc: Path | None, duration: float) -> None:
            if side_dir.name == "before":
                _write_run(side_dir, binary,
                           [_sink_event("system", binary.name)])
            else:
                side_dir.mkdir(parents=True, exist_ok=True)
                (side_dir / "events.jsonl").touch()
                (side_dir / "metadata.json").write_text(json.dumps({
                    "ok": True,
                    "target": {"raw": str(binary), "kind": "binary",
                               "pid": None, "name": binary.name,
                               "binary": str(binary)}}))

        monkeypatch.setattr(patch_oracle, "_run_side", fake)
        report = verify_patch(before, after, ["system"],
                              tmp_path / "out")
        assert report["verdict"] == "inconclusive"
        assert report["after"]["events_total"] == 0

    def test_out_dir_reuse_discards_stale_evidence(self, tmp_path,
                                                   binaries, monkeypatch):
        """The runner APPENDS to events.jsonl, so a second invocation
        into the same out dir must not judge the first run's events."""
        before, after = binaries
        out = tmp_path / "out"
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [_sink_event("system", before.name)],
            "after": [],
        }))
        assert verify_patch(before, after, ["system"],
                            out)["verdict"] == "closed"
        # Second PoC never reaches the sink: no new sink events.
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [],
            "after": [],
        }))
        report = verify_patch(before, after, ["system"], out)
        assert report["verdict"] == "inconclusive"


class TestReportArtifact:
    def test_report_written_with_run_dirs(self, tmp_path, binaries,
                                          monkeypatch):
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [_sink_event("system", before.name)],
            "after": [],
        }))
        out = tmp_path / "out"
        report = verify_patch(before, after, ["system"], out,
                              finding_location=("vuln.c", 10))
        on_disk = json.loads((out / "patch-verify.json").read_text())
        assert on_disk == report
        assert on_disk["finding_location"] == "vuln.c:10"
        assert Path(on_disk["before"]["run_dir"]).is_dir()
        assert (out / "sink-watch.js").is_file()


class TestInputValidation:
    def test_missing_binary_rejected(self, tmp_path, binaries):
        before, _ = binaries
        with pytest.raises(ValueError, match="after"):
            verify_patch(before, tmp_path / "nope", ["system"],
                         tmp_path / "out")

    def test_empty_sinks_rejected(self, tmp_path, binaries):
        before, after = binaries
        with pytest.raises(ValueError, match="sink"):
            verify_patch(before, after, [], tmp_path / "out")

    def test_missing_poc_rejected(self, tmp_path, binaries):
        before, after = binaries
        with pytest.raises(ValueError, match="poc"):
            verify_patch(before, after, ["system"], tmp_path / "out",
                         poc=tmp_path / "nope.txt")


class TestCli:
    def test_parse_location(self):
        assert _parse_location("src/a.c:42") == ("src/a.c", 42)
        for bad in ("noline", "a.c:", ":10", "a.c:x"):
            with pytest.raises(argparse.ArgumentTypeError):
                _parse_location(bad)

    def test_still_fires_exit_code(self, tmp_path, binaries,
                                   monkeypatch, capsys):
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [_sink_event("system", before.name)],
            "after": [_sink_event("system", after.name)],
        }))
        rc = main(["--before", str(before), "--after", str(after),
                   "--sink", "system", "--out", str(tmp_path / "out")])
        assert rc == 1
        assert "Still Fires" in capsys.readouterr().out

    def test_inconclusive_exit_code(self, tmp_path, binaries,
                                    monkeypatch, capsys):
        before, after = binaries
        monkeypatch.setattr(patch_oracle, "_run_side", _fake_run_side({
            "before": [],
            "after": [],
        }))
        rc = main(["--before", str(before), "--after", str(after),
                   "--sink", "system", "--out", str(tmp_path / "out")])
        assert rc == 3
        assert "Inconclusive" in capsys.readouterr().out

    def test_session_failure_maps_to_2(self, tmp_path, binaries,
                                       monkeypatch, capsys):
        before, after = binaries

        def boom(*args, **kwargs):
            raise RuntimeError("frida session against x failed")

        monkeypatch.setattr(patch_oracle, "_run_side", boom)
        rc = main(["--before", str(before), "--after", str(after),
                   "--sink", "system", "--out", str(tmp_path / "out")])
        assert rc == 2
        assert "failed" in capsys.readouterr().err

    def test_hung_session_maps_to_2_not_verdict(self, tmp_path, binaries,
                                                monkeypatch, capsys):
        """An infrastructure hang must never read as Still Fires."""
        import subprocess as sp

        before, after = binaries

        def hang(*args, **kwargs):
            raise sp.TimeoutExpired(cmd=["frida"], timeout=1)

        monkeypatch.setattr(patch_oracle.subprocess, "run", hang)
        rc = main(["--before", str(before), "--after", str(after),
                   "--sink", "system", "--out", str(tmp_path / "out")])
        assert rc == 2
        assert "hung" in capsys.readouterr().err

    def test_missing_raptor_dir_maps_to_2(self, tmp_path, binaries,
                                          monkeypatch, capsys):
        before, after = binaries
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        rc = main(["--before", str(before), "--after", str(after),
                   "--sink", "system", "--out", str(tmp_path / "out")])
        assert rc == 2
        assert "RAPTOR_DIR" in capsys.readouterr().err


class TestRunSideEnvHygiene:
    """The spawned target inherits _run_side's subprocess env and runs
    unsandboxed — operator credentials must never be readable via
    getenv from target code, 'built yourself' notwithstanding."""

    def _capture_env(self, tmp_path: Path, monkeypatch) -> dict:
        import subprocess as sp

        monkeypatch.setenv("RAPTOR_DIR", str(Path(__file__).resolve().parents[3]))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-test-not-real")
        monkeypatch.setenv("GH_TOKEN", "gh-test-not-real")
        seen: dict = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen.update(kwargs)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(patch_oracle.subprocess, "run", fake_run)
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        script = tmp_path / "watch.js"
        script.write_text("// noop")
        patch_oracle._run_side(binary, script, tmp_path / "side",
                               poc=None, duration=1.0)
        return seen

    def test_credentials_stripped_from_session_env(self, tmp_path,
                                                   monkeypatch):
        seen = self._capture_env(tmp_path, monkeypatch)
        env = seen["env"]
        for credential in ("ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY",
                           "GH_TOKEN"):
            assert credential not in env

    def test_cli_still_gets_import_path(self, tmp_path, monkeypatch):
        seen = self._capture_env(tmp_path, monkeypatch)
        env = seen["env"]
        assert env["RAPTOR_DIR"]
        assert env["PYTHONPATH"] == env["RAPTOR_DIR"]
