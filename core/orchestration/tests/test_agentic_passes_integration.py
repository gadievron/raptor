"""Semi-real integration tests for agentic_passes.

Mocks only the ``claude -p`` subprocess (which we can't run in CI). Lets
``libexec/raptor-run-lifecycle`` and ``libexec/raptor-build-checklist``
execute for real, then verifies that the resulting on-disk artefacts
satisfy the bridge's tier-2 sibling discovery — the actual claim the
lifecycle-proper rewrite makes.
"""

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from core.orchestration.agentic_passes import (
    run_understand_prepass,
    run_validate_postpass,
    _RAPTOR_DIR,
    _LIFECYCLE,
)
from core.orchestration.understand_bridge import find_understand_output, load_understand_context


def _make_target(tmp: Path) -> Path:
    """Create a minimal target repo with one Python file."""
    target = tmp / "target"
    target.mkdir()
    (target / "handler.py").write_text(
        "def handle_request(req):\n    return req.body\n"
    )
    return target


def _make_agentic_out(tmp: Path, target: Path) -> Path:
    """Create a fake agentic out_dir with a checklist that references target."""
    out_dir = tmp / "agentic_run"
    out_dir.mkdir()
    (out_dir / "checklist.json").write_text(json.dumps({
        "target_path": str(target),
        "files": [{
            "path": "handler.py",
            "items": [{"name": "handle_request", "line": 1}],
        }],
    }))
    # Mark this dir as command_type=agentic so infer_command_type works correctly.
    (out_dir / ".raptor-run.json").write_text(json.dumps({
        "command": "agentic",
        "target": str(target),
        "status": "running",
    }))
    return out_dir


def _selective_subprocess(real_run, claude_writes=None, claude_returncode=0):
    """Run lifecycle/build_checklist for real; mock only claude -p."""
    def dispatcher(cmd, *args, **kwargs):
        argv = cmd if isinstance(cmd, list) else [cmd]
        program = Path(argv[0]).name
        if program == "claude" or argv[0].endswith("/claude"):
            # Simulate claude writing the requested files into the
            # subprocess's --add-dir locations.
            if claude_writes and claude_returncode == 0:
                add_dirs = [argv[i + 1] for i, a in enumerate(argv) if a == "--add-dir"]
                # The pre-pass expects context-map.json in understand_dir;
                # the post-pass expects validation-report.md in validate_dir.
                # In both cases we drop into the LAST --add-dir (the run dir).
                target_dir = Path(add_dirs[-1]) if add_dirs else None
                if target_dir:
                    for name, content in claude_writes.items():
                        (target_dir / name).write_text(content)
            return MagicMock(returncode=claude_returncode, stdout="", stderr="")
        # Lifecycle / build_checklist run for real.
        return real_run(cmd, *args, **kwargs)
    return dispatcher


class PrepassIntegrationTests(unittest.TestCase):

    def test_creates_proper_understand_run_discoverable_by_bridge(self):
        # The whole point of going lifecycle-proper: the resulting understand
        # run dir must be discoverable by the bridge's tier-2 sibling search
        # from a sibling validate dir.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = _make_target(tmp)
            agentic_out = _make_agentic_out(tmp, target)

            # Point HOME at tmp so the lifecycle helpers don't write into
            # the real ~/.config or interact with the user's actual projects.
            ctx_map_payload = json.dumps({
                "entry_points": [{"file": "handler.py", "name": "handle_request"}],
                "sink_details": [],
                "sources": [], "sinks": [], "trust_boundaries": [],
            })
            from subprocess import run as real_subprocess_run
            dispatcher = _selective_subprocess(
                real_subprocess_run,
                claude_writes={"context-map.json": ctx_map_payload},
            )
            (tmp / "home").mkdir()
            (tmp / "out").mkdir()
            # Redirect RAPTOR_OUT_DIR so the real lifecycle helpers write
            # into our tmpdir, not the actual repo's out/.
            env_patch = patch.dict(os.environ, {
                "HOME": str(tmp / "home"),
                "RAPTOR_OUT_DIR": str(tmp / "out"),
            })
            with env_patch, patch(
                "core.orchestration.agentic_passes.subprocess.run",
                side_effect=dispatcher,
            ):
                result = run_understand_prepass(
                    target=target, agentic_out_dir=agentic_out,
                    claude_bin="/fake/claude",
                )

            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertIsNotNone(result.understand_dir)
            understand_dir = Path(result.understand_dir)
            self.assertTrue(understand_dir.exists())

            # Real lifecycle helpers should have created the standard files.
            self.assertTrue((understand_dir / ".raptor-run.json").exists())
            run_meta = json.loads((understand_dir / ".raptor-run.json").read_text())
            self.assertEqual(run_meta.get("command"), "understand")
            self.assertEqual(run_meta.get("status"), "completed")

            # checklist.json was reused from the agentic dir (no separate
            # raptor-build-checklist call needed).
            self.assertTrue((understand_dir / "checklist.json").exists())

            # context-map.json from the mocked claude.
            self.assertTrue((understand_dir / "context-map.json").exists())

            # The bridge tier-2 lookup must find this understand sibling
            # from a sibling validate-style dir.
            sibling_validate = understand_dir.parent / "validate-sibling"
            sibling_validate.mkdir()
            found, stale = find_understand_output(
                sibling_validate, target_path=str(target),
            )
            self.assertEqual(
                found.resolve() if found else None,
                understand_dir.resolve(),
                msg=f"bridge tier-2 didn't find understand sibling; got {found}",
            )

    def test_bridge_round_trip_populates_attack_surface_from_understand(self):
        # End-to-end: pre-pass writes context-map.json into a real understand
        # run dir, the bridge finds it from a sibling validate dir, AND
        # load_understand_context turns it into a usable attack-surface.json
        # in the validate dir. Goes one step beyond pure discovery.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = _make_target(tmp)
            agentic_out = _make_agentic_out(tmp, target)
            (tmp / "home").mkdir()
            (tmp / "out").mkdir()

            # Realistic context-map shape — sources/sinks/trust_boundaries are
            # the keys load_understand_context actually merges into attack-surface.
            ctx_map_payload = json.dumps({
                "sources": [{"file": "handler.py", "line": 1, "label": "HTTP request"}],
                "sinks": [{"file": "handler.py", "line": 2, "label": "echo response"}],
                "trust_boundaries": [],
                "entry_points": [{"file": "handler.py", "name": "handle_request"}],
                "sink_details": [],
            })
            from subprocess import run as real_subprocess_run
            env_patch = patch.dict(os.environ, {
                "HOME": str(tmp / "home"),
                "RAPTOR_OUT_DIR": str(tmp / "out"),
            })
            with env_patch, patch(
                "core.orchestration.agentic_passes.subprocess.run",
                side_effect=_selective_subprocess(
                    real_subprocess_run,
                    claude_writes={"context-map.json": ctx_map_payload},
                ),
            ):
                prepass = run_understand_prepass(
                    target=target, agentic_out_dir=agentic_out,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(prepass.ran, msg=prepass.skipped_reason)
            understand_dir = Path(prepass.understand_dir)

            # Stand up a fake validate dir as a sibling and let the bridge
            # find + load the understand artefact.
            validate_dir = understand_dir.parent / "validate-roundtrip"
            validate_dir.mkdir()
            found, stale = find_understand_output(validate_dir, target_path=str(target))
            self.assertEqual(
                found.resolve() if found else None,
                understand_dir.resolve(),
                msg="bridge tier-2 didn't find understand sibling",
            )

            summary = load_understand_context(found, validate_dir, stale)
            self.assertTrue(summary["context_map_loaded"],
                            msg=f"bridge claimed not to load context map: {summary}")

            # The bridge should have written attack-surface.json into validate_dir.
            attack_surface_path = validate_dir / "attack-surface.json"
            self.assertTrue(attack_surface_path.exists(),
                            msg="bridge didn't write attack-surface.json")
            attack_surface = json.loads(attack_surface_path.read_text())

            # Sources/sinks/trust_boundaries should match what we put in
            # context-map (they share the same schema by design).
            self.assertEqual(len(attack_surface.get("sources", [])), 1)
            self.assertEqual(len(attack_surface.get("sinks", [])), 1)
            self.assertEqual(attack_surface["sources"][0].get("file"), "handler.py")
            self.assertEqual(attack_surface["sinks"][0].get("file"), "handler.py")

    def test_2prime_enrichment_actually_marks_priority_in_real_checklist(self):
        # Verifies the path-convention claim: the checklist that build_inventory
        # would write uses relative paths, and /understand --map's templates
        # use the same — so enrich_checklist's strict-equality match works.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = _make_target(tmp)
            agentic_out = _make_agentic_out(tmp, target)

            ctx_map_payload = json.dumps({
                "entry_points": [{"file": "handler.py", "name": "handle_request"}],
                "sink_details": [],
            })
            from subprocess import run as real_subprocess_run
            dispatcher = _selective_subprocess(
                real_subprocess_run,
                claude_writes={"context-map.json": ctx_map_payload},
            )
            (tmp / "home").mkdir()
            (tmp / "out").mkdir()
            # Redirect RAPTOR_OUT_DIR so the real lifecycle helpers write
            # into our tmpdir, not the actual repo's out/.
            env_patch = patch.dict(os.environ, {
                "HOME": str(tmp / "home"),
                "RAPTOR_OUT_DIR": str(tmp / "out"),
            })
            with env_patch, patch(
                "core.orchestration.agentic_passes.subprocess.run",
                side_effect=dispatcher,
            ):
                result = run_understand_prepass(
                    target=target, agentic_out_dir=agentic_out,
                    claude_bin="/fake/claude",
                )

            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertTrue(result.checklist_enriched,
                            "expected enrichment to succeed against real checklist")

            # The function in the agentic checklist should now carry the
            # priority marker that agent.py copies into per-finding metadata.
            enriched = json.loads((agentic_out / "checklist.json").read_text())
            handler = enriched["files"][0]["items"][0]
            self.assertEqual(handler.get("priority"), "high")
            self.assertEqual(handler.get("priority_reason"), "entry_point")


class PostpassIntegrationTests(unittest.TestCase):

    def _make_report(self, dir_: Path, results: list) -> Path:
        path = dir_ / "autonomous_analysis_report.json"
        path.write_text(json.dumps({"results": results}))
        return path

    def test_creates_proper_validate_run_as_sibling_of_understand(self):
        # End-to-end: when both --understand and --validate run against the
        # same target, the bridge should be able to find the understand
        # sibling from the validate run via tier-2.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = _make_target(tmp)
            (tmp / "home").mkdir()
            (tmp / "out").mkdir()

            from subprocess import run as real_subprocess_run

            # Phase 1: simulate a previous --understand run that created a
            # proper sibling understand dir. We invoke the real lifecycle
            # helpers via the prepass.
            agentic_out = _make_agentic_out(tmp, target)
            ctx_map_payload = json.dumps({
                "entry_points": [{"file": "handler.py", "name": "handle_request"}],
                "sink_details": [],
                "sources": [], "sinks": [], "trust_boundaries": [],
            })
            env_patch = patch.dict(os.environ, {
                "HOME": str(tmp / "home"),
                "RAPTOR_OUT_DIR": str(tmp / "out"),
            })
            with env_patch, patch(
                "core.orchestration.agentic_passes.subprocess.run",
                side_effect=_selective_subprocess(
                    real_subprocess_run,
                    claude_writes={"context-map.json": ctx_map_payload},
                ),
            ):
                prepass = run_understand_prepass(
                    target=target, agentic_out_dir=agentic_out,
                    claude_bin="/fake/claude",
                )
            self.assertTrue(prepass.ran, msg=prepass.skipped_reason)

            # Phase 2: post-pass against a report with one qualifying finding.
            report = self._make_report(agentic_out, [
                {"finding_id": "vuln-1", "is_exploitable": True,
                 "file_path": "handler.py", "start_line": 1},
            ])
            with env_patch, patch(
                "core.orchestration.agentic_passes.subprocess.run",
                side_effect=_selective_subprocess(
                    real_subprocess_run,
                    claude_writes={"validation-report.md": "# Validation\n"},
                ),
            ):
                postpass = run_validate_postpass(
                    target=target, agentic_out_dir=agentic_out,
                    analysis_report=report, claude_bin="/fake/claude",
                )

            self.assertTrue(postpass.ran, msg=postpass.skipped_reason)
            self.assertEqual(postpass.selected_count, 1)
            validate_dir = Path(postpass.validate_dir)

            # Lifecycle artifacts exist and are correct command_type.
            run_meta = json.loads((validate_dir / ".raptor-run.json").read_text())
            self.assertEqual(run_meta.get("command"), "validate")
            self.assertEqual(run_meta.get("status"), "completed")

            # Selection file exists and contains the qualifying finding.
            selection = json.loads((validate_dir / "selected-findings.json").read_text())
            # After format conversion the file is in /validate
            # FindingsContainer shape — no "count" field; finding_id is
            # renamed to id.
            self.assertEqual(len(selection["findings"]), 1)
            self.assertEqual(selection["findings"][0]["id"], "vuln-1")
            self.assertIn("target_path", selection)

            # Bridge tier-2: from the validate sibling, we should find the
            # understand sibling. This proves --validate can pick up
            # --understand context without any --out alignment.
            found, _ = find_understand_output(validate_dir, target_path=str(target))
            self.assertEqual(
                found.resolve() if found else None,
                Path(prepass.understand_dir).resolve(),
                msg=f"bridge tier-2 didn't find understand sibling from validate; got {found}",
            )

    def test_postpass_skips_cleanly_when_no_qualifying_findings(self):
        # Post-pass over a report with zero qualifying findings should not
        # create a validate run dir — there's no work to lifecycle-manage.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = _make_target(tmp)
            (tmp / "home").mkdir()
            (tmp / "out").mkdir()
            agentic_out = _make_agentic_out(tmp, target)

            report = self._make_report(agentic_out, [
                {"finding_id": "noise-1", "is_exploitable": False, "confidence": "low"},
            ])
            env_patch = patch.dict(os.environ, {
                "HOME": str(tmp / "home"),
                "RAPTOR_OUT_DIR": str(tmp / "out"),
            })
            with env_patch:
                result = run_validate_postpass(
                    target=target, agentic_out_dir=agentic_out,
                    analysis_report=report, claude_bin="/fake/claude",
                )
            self.assertFalse(result.ran)
            self.assertIn("no findings matched", result.skipped_reason)
            # No validate_<ts>/ dir under out/.
            validate_dirs = [d for d in (tmp / "out").iterdir()
                             if d.is_dir() and d.name.startswith("validate_")]
            self.assertEqual(validate_dirs, [],
                             "no validate run dir should exist when no findings qualify")


if __name__ == "__main__":
    unittest.main()
