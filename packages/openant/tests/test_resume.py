"""Tests for /openant --resume: prior-run validation, seeding, and the
checkpoint identity rebase.

The refusal tests cover BOTH drift directions explicitly — the target
tree changing since the prior run, and the pinned core changing — as
these are load-bearing: the pinned upstream adopts path-keyed unit
checkpoints content-blind (its adopt gate covers backend identity, not
target or core version), so RAPTOR's validation is the only
target/core drift gate a resume has.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.config import OPENANT_PINNED_COMMIT
from packages.openant.resume import (
    SEED_MAX_DEPTH,
    OpenAntResumeError,
    assess_remaining,
    completed_unit_ids,
    rebase_gateway_fingerprints,
    seed_scan_dir,
    target_fingerprint,
    validate_prior_run,
)

_CORE_HEAD = "c" * 40


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _analyze_row(uid: str, verdict: str, finding: str) -> dict:
    return {"id": uid, "result": {"verdict": verdict, "finding": finding}}


def _mk_prior(
    base: Path,
    repo: Path,
    *,
    complete: bool = False,
    outcome: str | None = None,
    pin: str = OPENANT_PINNED_COMMIT,
    core_head: str | None = _CORE_HEAD,
    tfp: dict | None = None,
    model: str = "sonnet",
) -> Path:
    """A synthetic prior /openant run directory."""
    run = base / "prior"
    scan = run / "openant_scan"
    _write(scan / "dataset.json", {"units": [
        {"id": f"f.py:u{i}", "code": {"primary_code": "x" * 100}}
        for i in range(3)
    ]})
    ck = scan / "analyze_checkpoints"
    if complete:
        for i in range(3):
            _write(ck / f"u{i}.json",
                   _analyze_row(f"f.py:u{i}", "SAFE", "safe"))
        _write(ck / "_summary.json", {
            "phase": "done", "total_units": 3, "completed": 3,
            "incomplete": 0, "errors": 0})
        _write(scan / "pipeline_output.json", {"findings": []})
    else:
        _write(ck / "u0.json", _analyze_row("f.py:u0", "SAFE", "safe"))
        _write(ck / "u1.json",
               _analyze_row("f.py:u1", "VULNERABLE", "vulnerable"))
        _write(ck / "u2.json", _analyze_row("f.py:u2", "ERROR", "error"))
        _write(ck / "_summary.json", {
            "phase": "done", "total_units": 3, "completed": 2,
            "incomplete": 0, "errors": 1})
    report = {
        "repository": str(repo),
        "config": {
            "model": model, "level": "reachable", "enhance": True,
            "verify": False, "language": "auto",
            "core_provenance": {
                "pinned_commit": pin, "head": core_head,
                "matches": core_head == _CORE_HEAD,
            },
        },
        "phases": {"openant_scan": {"completed": True}},
        "cost": {"total_usd": 12.5},
    }
    if tfp is not None:
        report["target_fingerprint"] = tfp
    if outcome is not None:
        report["outcome"] = outcome
    _write(run / "raptor_openant_report.json", report)
    return run


def _validate(prior: Path, repo: Path, **kw):
    kw.setdefault("pinned_commit", OPENANT_PINNED_COMMIT)
    kw.setdefault("current_core_head", _CORE_HEAD)
    return validate_prior_run(prior, repo, **kw)


class TestTargetFingerprint(unittest.TestCase):
    def test_non_git_dir(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(target_fingerprint(Path(td)),
                             {"kind": "non-git"})

    @unittest.skipIf(shutil.which("git") is None, "git not available")
    def test_git_head_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q")
            (repo / "a.txt").write_text("a")
            _git(repo, "add", "a.txt")
            _git(repo, "commit", "-q", "-m", "one")
            fp = target_fingerprint(repo)
            self.assertEqual(fp["kind"], "git")
            self.assertEqual(len(fp["head"]), 40)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo),
         "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True, timeout=60,
    )


class TestValidatePriorRun(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.base = Path(self._td.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.addCleanup(self._td.cleanup)

    def test_missing_dir_refuses(self):
        with self.assertRaisesRegex(OpenAntResumeError, "not a directory"):
            _validate(self.base / "nope", self.repo)

    def test_missing_report_refuses(self):
        empty = self.base / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(OpenAntResumeError, "no readable"):
            _validate(empty, self.repo)

    def test_never_scanned_refuses(self):
        prior = _mk_prior(self.base, self.repo, outcome="not_configured")
        with self.assertRaisesRegex(OpenAntResumeError, "never scanned"):
            _validate(prior, self.repo)

    def test_forecast_run_refuses(self):
        prior = _mk_prior(self.base, self.repo, outcome="forecast_only")
        with self.assertRaisesRegex(OpenAntResumeError, "forecast"):
            _validate(prior, self.repo)

    def test_missing_dataset_refuses(self):
        prior = _mk_prior(self.base, self.repo)
        (prior / "openant_scan" / "dataset.json").unlink()
        with self.assertRaisesRegex(OpenAntResumeError, "dataset.json"):
            _validate(prior, self.repo)

    def test_target_path_mismatch_refuses(self):
        prior = _mk_prior(self.base, self.repo)
        other = self.base / "other"
        other.mkdir()
        with self.assertRaisesRegex(OpenAntResumeError, "target mismatch"):
            _validate(prior, other)

    def test_target_tree_drift_refuses(self):
        # Drift direction 1: the prior run recorded a git head, the
        # target tree has changed since (here: no longer that commit).
        prior = _mk_prior(self.base, self.repo,
                          tfp={"kind": "git", "head": "a" * 40})
        with self.assertRaisesRegex(OpenAntResumeError, "target drift"):
            _validate(prior, self.repo)

    @unittest.skipIf(shutil.which("git") is None, "git not available")
    def test_target_tree_drift_refuses_across_commits(self):
        _git(self.repo, "init", "-q")
        (self.repo / "a.txt").write_text("one")
        _git(self.repo, "add", "a.txt")
        _git(self.repo, "commit", "-q", "-m", "one")
        prior = _mk_prior(self.base, self.repo,
                          tfp=target_fingerprint(self.repo))
        # Unchanged tree resumes.
        _validate(prior, self.repo)
        # A new commit on the target refuses.
        (self.repo / "a.txt").write_text("two")
        _git(self.repo, "add", "a.txt")
        _git(self.repo, "commit", "-q", "-m", "two")
        with self.assertRaisesRegex(OpenAntResumeError, "target drift"):
            _validate(prior, self.repo)

    @unittest.skipIf(shutil.which("git") is None, "git not available")
    def test_validation_never_executes_repo_configured_filters(self):
        """Validating a git target must never run the repo-configured
        clean filter — git dirtiness queries (status; ls-files -m on
        RACILY-CLEAN index entries) re-hash worktree content through
        filter.<x>.clean, executing hostile repo config in the
        unsandboxed parent. The gate is HEAD-only and no dirtiness
        probe ships; uncommitted edits pass validation undetected (the
        documented limit) with the filter untouched."""
        canary = self.base / "filter-canary"

        def _g(*args: str) -> None:
            # The hostile filter is neutralised for OUR setup writes
            # only (-c wins over the repo config); validation gets the
            # repo as shipped, hostile filter armed.
            subprocess.run(
                ["git", "-C", str(self.repo),
                 "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                 "-c", "commit.gpgsign=false",
                 "-c", "filter.evil.clean=cat", *args],
                check=True, capture_output=True, timeout=60,
            )

        _g("init", "-q")
        _g("config", "filter.evil.clean",
           f"touch {canary}; cat")
        (self.repo / ".gitattributes").write_text("* filter=evil\n")
        (self.repo / "a.txt").write_text("one")
        _g("add", "-A")
        _g("commit", "-q", "-m", "one")
        # Entries are racily clean (just written, NOT backdated) — the
        # exact index state in which stat-shaped plumbing re-hashes.
        if canary.exists():
            canary.unlink()
        prior = _mk_prior(self.base, self.repo,
                          tfp=target_fingerprint(self.repo))
        _validate(prior, self.repo)
        self.assertFalse(canary.exists(),
                         "validation executed the repo-configured "
                         "clean filter")
        # Dirty worktree at the same HEAD: passes validation (the
        # documented HEAD-only limit) — still with no filter run.
        (self.repo / "a.txt").write_text("edited, not committed")
        result = _validate(prior, self.repo)
        self.assertFalse(canary.exists(),
                         "validation executed the repo-configured "
                         "clean filter on a dirty worktree")
        self.assertTrue(result.remaining["resumable"])

    def test_unverifiable_target_drift_warns_not_refuses(self):
        prior = _mk_prior(self.base, self.repo)  # no fingerprint recorded
        result = _validate(prior, self.repo)
        self.assertTrue(any("UNVERIFIABLE" in w for w in result.warnings))

    def test_pin_drift_refuses(self):
        # Drift direction 2a: the integration pin advanced since the
        # prior run — checkpoint schemas may differ across pins.
        prior = _mk_prior(self.base, self.repo, pin="d" * 40)
        with self.assertRaisesRegex(OpenAntResumeError, "pin"):
            _validate(prior, self.repo)

    def test_core_head_drift_refuses(self):
        # Drift direction 2b: same pin recorded, but the core checkout
        # executing THIS resume is at a different commit.
        prior = _mk_prior(self.base, self.repo)
        with self.assertRaisesRegex(OpenAntResumeError, "core drift"):
            _validate(prior, self.repo, current_core_head="e" * 40)

    def test_unknown_prior_core_head_warns(self):
        prior = _mk_prior(self.base, self.repo, core_head=None)
        result = _validate(prior, self.repo)
        self.assertTrue(any("core" in w for w in result.warnings))

    def test_complete_run_refuses_nothing_to_resume(self):
        prior = _mk_prior(self.base, self.repo, complete=True)
        with self.assertRaisesRegex(OpenAntResumeError,
                                    "nothing to resume"):
            _validate(prior, self.repo)

    def test_truncated_run_validates(self):
        prior = _mk_prior(self.base, self.repo)
        result = _validate(prior, self.repo)
        self.assertEqual(result.repository, self.repo.resolve())
        self.assertEqual(result.prior_cost_usd, 12.5)
        self.assertTrue(result.remaining["resumable"])
        self.assertTrue(
            any("errored" in r for r in result.remaining["reasons"]))

    def test_repo_none_adopts_prior_target(self):
        prior = _mk_prior(self.base, self.repo)
        result = _validate(prior, None)
        self.assertEqual(result.repository, self.repo.resolve())


@unittest.skipUnless(Path("/proc/self/stat").exists(),
                     "needs /proc starttime records")
class TestInFlightPriorRunRefuses(unittest.TestCase):
    """Both directions of the liveness gate: a prior run whose
    recorded worker is still alive refuses (resuming would seed from a
    scan dir mid-write and double-pay), while a dead/interrupted
    worker keeps the run eligible."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.base = Path(self._td.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.addCleanup(self._td.cleanup)

    @staticmethod
    def _own_starttime() -> str:
        stat = Path("/proc/self/stat").read_text()
        return stat.rsplit(")", 1)[1].split()[19]

    def _stamp_meta(self, prior: Path, *, status: str,
                    starttime: str) -> None:
        _write(prior / ".raptor-run.json", {
            "version": 2, "command": "openant", "status": status,
            "tool_pid": os.getpid(), "tool_pid_start": starttime,
        })

    def test_live_worker_refuses(self):
        prior = _mk_prior(self.base, self.repo)
        self._stamp_meta(prior, status="running",
                         starttime=self._own_starttime())
        with self.assertRaisesRegex(OpenAntResumeError, "in flight"):
            _validate(prior, self.repo)

    def test_dead_worker_validates(self):
        # Still status=running (a SIGKILL never gets a terminal
        # transition) but the starttime does not match: the identity
        # check reads the worker as dead (a recycled pid is not the
        # worker) — the run stays resumable.
        prior = _mk_prior(self.base, self.repo)
        self._stamp_meta(prior, status="running", starttime="1")
        result = _validate(prior, self.repo)
        self.assertTrue(result.remaining["resumable"])

    def test_interrupted_status_carries_no_inflight_claim(self):
        # A run marked interrupted is terminal even when the recorded
        # worker pid (the launching tool shell on session-bound runs)
        # is an alive process — no refusal.
        prior = _mk_prior(self.base, self.repo)
        self._stamp_meta(prior, status="interrupted",
                         starttime=self._own_starttime())
        result = _validate(prior, self.repo)
        self.assertTrue(result.remaining["resumable"])


class TestScanFailedReportResumesLikeSuccess(unittest.TestCase):
    """A hard-failed scan's report — written by the REAL scan_failed
    writer (``raptor_openant._write_skip_report``) — must feed the
    resume gates the same fields a successful run's report does: the
    drift gate REFUSES (never just warns) on a git target whose HEAD
    changed, the scan-shape adoption sees a config block, the core
    provenance verifies, and the prior spend books its real figure.
    Hard-failed runs are the primary --resume population."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.base = Path(self._td.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.addCleanup(self._td.cleanup)

    def _mk_scan_failed_prior(self, tfp: dict) -> Path:
        import raptor_openant
        from packages.openant.config import OpenAntConfig
        run = self.base / "prior"
        scan = run / "openant_scan"
        _write(scan / "dataset.json", {"units": [
            {"id": "f.py:u0", "code": {"primary_code": "x" * 100}}]})
        _write(scan / "analyze_checkpoints" / "u0.json",
               _analyze_row("f.py:u0", "ERROR", "error"))
        _write(scan / "analyze_checkpoints" / "_summary.json", {
            "phase": "done", "total_units": 1, "completed": 0,
            "incomplete": 0, "errors": 1})
        oa_config = OpenAntConfig(core_path=self.base / "core",
                                  model="opus", level="all",
                                  verify=True, language="python")
        raptor_openant._write_skip_report(
            run, self.repo, "OpenAnt timed out after 1800s",
            outcome="scan_failed",
            target_fp=tfp,
            config=raptor_openant._scan_shape_config(
                oa_config,
                {"pinned_commit": OPENANT_PINNED_COMMIT,
                 "head": _CORE_HEAD, "matches": True}),
            cost={"total_usd": 3.75, "openant_reported_usd": 0.0,
                  "gateway_ledger_usd": 3.75},
        )
        return run

    def test_git_drift_refuses_not_warns(self):
        prior = self._mk_scan_failed_prior({"kind": "git", "head": "a" * 40})
        with self.assertRaisesRegex(OpenAntResumeError, "target drift"):
            _validate(prior, self.repo)

    def test_shape_cost_and_provenance_adopted(self):
        import raptor_openant
        prior = self._mk_scan_failed_prior({"kind": "non-git"})
        result = _validate(prior, self.repo)
        # The failed run's real spend books, not $0.
        self.assertEqual(result.prior_cost_usd, 3.75)
        # Core provenance is recorded: no unverifiable-core warning.
        self.assertFalse(any("core" in w for w in result.warnings),
                         result.warnings)
        # The scan-shape adoption sees the config block and adopts it.
        args = argparse.Namespace(model="sonnet", level="reachable",
                                  language="auto", no_enhance=False,
                                  verify=False)
        notes = raptor_openant._adopt_prior_scan_config(args, result.report)
        self.assertTrue(notes)
        self.assertEqual(args.model, "opus")
        self.assertEqual(args.level, "all")
        self.assertEqual(args.language, "python")
        self.assertTrue(args.verify)

    def test_fieldless_skip_report_still_warns_not_crashes(self):
        # A report without the fields (older runs, other outcomes)
        # keeps the warn-and-proceed lane.
        import raptor_openant
        run = self.base / "prior"
        scan = run / "openant_scan"
        _write(scan / "dataset.json", {"units": []})
        _write(scan / "analyze_checkpoints" / "u0.json",
               _analyze_row("f.py:u0", "ERROR", "error"))
        raptor_openant._write_skip_report(
            run, self.repo, "boom", outcome="scan_failed")
        result = _validate(run, self.repo)
        self.assertTrue(any("UNVERIFIABLE" in w for w in result.warnings))
        self.assertEqual(result.prior_cost_usd, 0.0)


class TestAssessRemaining(unittest.TestCase):
    def _scan(self) -> Path:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return Path(td.name)

    def test_errors_resumable(self):
        scan = self._scan()
        _write(scan / "analyze_checkpoints" / "u.json",
               _analyze_row("a", "ERROR", "error"))
        _write(scan / "analyze_checkpoints" / "_summary.json",
               {"phase": "done", "total_units": 1, "completed": 0,
                "incomplete": 0, "errors": 1})
        _write(scan / "pipeline_output.json", {})
        out = assess_remaining(scan)
        self.assertTrue(out["resumable"])

    def test_under_total_resumable(self):
        scan = self._scan()
        _write(scan / "enhance_checkpoints" / "u.json",
               {"id": "a", "agent_context": {"security_classification": "neutral"}})
        _write(scan / "enhance_checkpoints" / "_summary.json",
               {"phase": "in_progress", "total_units": 5, "completed": 1,
                "incomplete": 0, "errors": 0})
        _write(scan / "pipeline_output.json", {})
        self.assertTrue(assess_remaining(scan)["resumable"])

    def test_files_without_summary_resumable(self):
        scan = self._scan()
        _write(scan / "analyze_checkpoints" / "u.json",
               _analyze_row("a", "SAFE", "safe"))
        _write(scan / "pipeline_output.json", {})
        out = assess_remaining(scan)
        self.assertTrue(out["resumable"])
        self.assertTrue(any("no summary" in r for r in out["reasons"]))

    def test_missing_pipeline_output_resumable(self):
        scan = self._scan()
        _write(scan / "analyze_checkpoints" / "u.json",
               _analyze_row("a", "SAFE", "safe"))
        _write(scan / "analyze_checkpoints" / "_summary.json",
               {"phase": "done", "total_units": 1, "completed": 1,
                "incomplete": 0, "errors": 0})
        self.assertTrue(assess_remaining(scan)["resumable"])

    def test_complete_not_resumable(self):
        scan = self._scan()
        _write(scan / "analyze_checkpoints" / "u.json",
               _analyze_row("a", "SAFE", "safe"))
        _write(scan / "analyze_checkpoints" / "_summary.json",
               {"phase": "done", "total_units": 1, "completed": 1,
                "incomplete": 0, "errors": 0})
        _write(scan / "pipeline_output.json", {})
        self.assertFalse(assess_remaining(scan)["resumable"])


class TestCompletedUnitIds(unittest.TestCase):
    def _dir(self) -> Path:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return Path(td.name)

    def test_analyze_classification(self):
        d = self._dir()
        _write(d / "a.json", _analyze_row("a", "SAFE", "safe"))
        _write(d / "b.json", _analyze_row("b", "ERROR", "error"))
        _write(d / "c.json", {"id": "c", "result": {"verdict": None}})
        _write(d / "e.json", {"id": "e", "result": "not-a-dict"})
        _write(d / "_summary.json", {"total_units": 4})
        _write(d / "_fingerprint.json", {"scheme_version": 2})
        self.assertEqual(completed_unit_ids(d, "analyze"), {"a"})

    def test_enhance_classification(self):
        d = self._dir()
        _write(d / "a.json",
               {"id": "a", "agent_context": {"security_classification": "neutral"}})
        _write(d / "b.json",
               {"id": "b", "agent_context": {"error": {"type": "api"}}})
        _write(d / "c.json",
               {"id": "c", "agent_context": {"security_classification": "incomplete"}})
        _write(d / "e.json", {"id": "e", "context_key": "llm_context",
                              "llm_context": {"security_classification": "dangerous"}})
        self.assertEqual(completed_unit_ids(d, "enhance"), {"a", "e"})

    def test_verify_classification(self):
        d = self._dir()
        _write(d / "a.json",
               {"id": "a", "verification": {"correct_finding": "vulnerable"}})
        _write(d / "b.json",
               {"id": "b", "verification": {"correct_finding": "error"}})
        _write(d / "c.json", {"id": "c", "verification": {}})
        _write(d / "e.json", {"id": "e", "error": "adapter raise",
                              "verification": {"incomplete": True}})
        self.assertEqual(completed_unit_ids(d, "verify"), {"a"})


class TestSeedScanDir(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.base = Path(self._td.name)
        self.addCleanup(self._td.cleanup)
        self.prior = self.base / "prior_scan"
        _write(self.prior / "dataset.json", {"units": []})
        _write(self.prior / "analyzer_output.json", {})
        _write(self.prior / "application_context.json", {})
        _write(self.prior / "analyze_checkpoints" / "u.json",
               _analyze_row("a", "SAFE", "safe"))
        _write(self.prior / "analyze_checkpoints" / "_fingerprint.json",
               {"scheme_version": 2})
        # Artifacts that must NOT travel into the new run:
        _write(self.prior / "pipeline_output.json", {"findings": []})
        _write(self.prior / "results.json", {})
        _write(self.prior / "results_verified.json", {})
        _write(self.prior / "openant-gateway-spend.json", {"token_id": "x"})
        (self.prior / "openant.stderr.log").write_text("noise")
        _write(self.prior / "openant-xdg" / "openant" / "config.json",
               {"secret": True})
        _write(self.prior / "analyze_checkpoints.superseded-abcd" / "u.json",
               {"id": "old"})

    def _tree(self, root: Path) -> dict:
        out = {}
        for p in sorted(root.rglob("*")):
            if p.is_file():
                out[str(p.relative_to(root))] = p.read_bytes()
        return out

    def test_seed_copies_state_and_drops_excluded(self):
        before = self._tree(self.prior)
        new = self.base / "new_scan"
        seed_scan_dir(self.prior, new)
        seeded = self._tree(new)
        self.assertIn("dataset.json", seeded)
        self.assertIn("analyzer_output.json", seeded)
        self.assertIn("application_context.json", seeded)
        self.assertIn(os.path.join("analyze_checkpoints", "u.json"), seeded)
        for dropped in ("pipeline_output.json", "results.json",
                        "results_verified.json",
                        "openant-gateway-spend.json", "openant.stderr.log"):
            self.assertNotIn(dropped, seeded, dropped)
        self.assertFalse(any(p.startswith("openant-xdg") for p in seeded))
        self.assertFalse(any(".superseded-" in p for p in seeded))
        # The prior run directory is byte-identical afterwards.
        self.assertEqual(before, self._tree(self.prior))

    def test_seed_refuses_non_empty_target(self):
        new = self.base / "new_scan"
        _write(new / "dataset.json", {})
        with self.assertRaisesRegex(OpenAntResumeError, "non-empty"):
            seed_scan_dir(self.prior, new)

    # -- lstat discipline: the prior scan dir was child-writable, so a
    # -- planted non-regular entry REFUSES the whole seed (never
    # -- dereferenced, never skipped) and leaves no partial residue.

    def _assert_refuses_and_leaves_nothing(self, pattern: str):
        new = self.base / "new_scan"
        before = self._tree(self.prior)
        with self.assertRaisesRegex(OpenAntResumeError, pattern):
            seed_scan_dir(self.prior, new)
        self.assertFalse(
            new.exists() and any(new.iterdir()),
            "a refused seed must leave the new run dir absent/empty")
        # ... and the prior dir is still untouched.
        self.assertEqual(before, self._tree(self.prior))

    def test_seed_refuses_file_symlink_without_ingesting(self):
        secret = self.base / "host-secret.txt"
        secret.write_text("host-secret-content")
        os.symlink(secret, self.prior / "evil-file-link.json")
        self._assert_refuses_and_leaves_nothing("symlink")

    def test_seed_refuses_dir_symlink_without_ingesting(self):
        outside = self.base / "host-tree" / "sub"
        outside.mkdir(parents=True)
        (outside / "host-data.txt").write_text("host-tree-data")
        os.symlink(self.base / "host-tree",
                   self.prior / "analyze_checkpoints" / "evil-dir-link")
        self._assert_refuses_and_leaves_nothing("symlink")

    def test_seed_refuses_dangling_symlink(self):
        os.symlink(self.base / "does-not-exist",
                   self.prior / "dangling-link")
        self._assert_refuses_and_leaves_nothing("symlink")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no mkfifo on platform")
    def test_seed_refuses_fifo_without_hanging(self):
        os.mkfifo(self.prior / "evil-fifo.json")
        self._assert_refuses_and_leaves_nothing("special file")

    def test_seed_failure_removes_already_copied_files(self):
        # The plant sorts LAST at the top level, so regular entries
        # have already been copied when the refusal fires — the
        # partial seed must still be removed wholesale.
        os.symlink(self.base / "nope", self.prior / "zzz-last-link")
        self._assert_refuses_and_leaves_nothing("symlink")

    # -- nesting depth is child-authored too: beyond the cap refuses
    # -- residue-free, while legitimately deep state still seeds.

    def _nest(self, levels: int) -> Path:
        d = self.prior
        for _ in range(levels):
            d = d / "d"
        d.mkdir(parents=True)
        return d

    def test_seed_refuses_pathological_nesting_without_residue(self):
        # Exact boundary: SEED_MAX_DEPTH nested levels is one past the
        # admitted maximum — refuse, and say so accurately.
        self._nest(SEED_MAX_DEPTH)
        self._assert_refuses_and_leaves_nothing(
            f"more than {SEED_MAX_DEPTH - 1} levels")

    def test_seed_copies_deep_but_legal_nesting(self):
        # Exact boundary: SEED_MAX_DEPTH - 1 nested levels is the
        # admitted maximum — seeds.
        leaf_dir = self._nest(SEED_MAX_DEPTH - 1)
        (leaf_dir / "leaf.json").write_text("{}")
        new = self.base / "new_scan"
        seed_scan_dir(self.prior, new)
        rel = Path(*(["d"] * (SEED_MAX_DEPTH - 1))) / "leaf.json"
        self.assertTrue((new / rel).is_file())

    def test_walk_never_consumes_a_stack_frame_per_level(self):
        # A nesting depth well under the cap must seed even when the
        # interpreter's recursion headroom is smaller than the depth —
        # the walk may not recurse per directory level.
        import inspect
        leaf_dir = self._nest(40)
        (leaf_dir / "leaf.json").write_text("{}")
        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(len(inspect.stack()) + 30)
        try:
            new = self.base / "new_scan"
            seed_scan_dir(self.prior, new)
        finally:
            sys.setrecursionlimit(limit)
        rel = Path(*(["d"] * 40)) / "leaf.json"
        self.assertTrue((new / rel).is_file())


def _canonical_digest(key: dict) -> str:
    canonical = json.dumps(key, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sidecar_key(base_url: str) -> dict:
    return {
        "scheme_version": 2,
        "phase": "analyze",
        "model": "test-model-a",
        "provider_name": "raptor-gateway",
        "adapter_type": "anthropic",
        "config_base_url": base_url,
        "templates_sha": "sha256:" + "0" * 64,
        "extra": {"ctx_sources_sha256": "1" * 64},
    }


class TestRebaseGatewayFingerprints(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.scan = Path(self._td.name)
        self.addCleanup(self._td.cleanup)

    def _put_sidecar(self, key: dict, digest: str | None = None) -> Path:
        sidecar = dict(key)
        sidecar["key_digest"] = digest or _canonical_digest(key)
        sidecar["written_at"] = "2026-01-01T00:00:00Z"
        path = self.scan / "analyze_checkpoints" / "_fingerprint.json"
        _write(path, sidecar)
        return path

    def test_port_only_difference_rebases(self):
        key = _sidecar_key("http://127.0.0.1:34001/anthropic")
        path = self._put_sidecar(key)
        n = rebase_gateway_fingerprints(
            self.scan, "http://127.0.0.1:40001/anthropic")
        self.assertEqual(n, 1)
        data = json.loads(path.read_text())
        self.assertEqual(data["config_base_url"],
                         "http://127.0.0.1:40001/anthropic")
        # The digest is recomputed correctly (independent recompute)
        # and every other key member is unchanged.
        rekey = {k: v for k, v in data.items()
                 if k not in ("key_digest", "written_at")}
        self.assertEqual(data["key_digest"], _canonical_digest(rekey))
        self.assertEqual(data["written_at"], "2026-01-01T00:00:00Z")
        for field in ("phase", "model", "provider_name", "adapter_type",
                      "templates_sha", "extra"):
            self.assertEqual(data[field], key[field], field)

    def _assert_untouched(self, path: Path, new_url: str, expect_n=0):
        before = path.read_bytes()
        n = rebase_gateway_fingerprints(self.scan, new_url)
        self.assertEqual(n, expect_n)
        self.assertEqual(path.read_bytes(), before)

    def test_same_port_untouched(self):
        path = self._put_sidecar(
            _sidecar_key("http://127.0.0.1:34001/anthropic"))
        self._assert_untouched(path, "http://127.0.0.1:34001/anthropic")

    def test_route_path_change_keeps_honest_reset(self):
        # A different provider front is a REAL identity change — the
        # rebase must not paper over it.
        path = self._put_sidecar(
            _sidecar_key("http://127.0.0.1:34001/anthropic"))
        self._assert_untouched(path,
                               "http://127.0.0.1:40001/bedrock/mantle")

    def test_non_loopback_prior_untouched(self):
        path = self._put_sidecar(
            _sidecar_key("https://gw.example.invalid/anthropic"))
        self._assert_untouched(path, "http://127.0.0.1:40001/anthropic")

    def test_non_loopback_new_url_untouched(self):
        path = self._put_sidecar(
            _sidecar_key("http://127.0.0.1:34001/anthropic"))
        self._assert_untouched(path, "https://gw.example.invalid/x")

    def test_digest_mismatch_untouched(self):
        # An unknown writer's sidecar is left to fail closed upstream.
        path = self._put_sidecar(
            _sidecar_key("http://127.0.0.1:34001/anthropic"),
            digest="sha256:" + "f" * 64)
        self._assert_untouched(path, "http://127.0.0.1:40001/anthropic")

    def test_foreign_scheme_version_untouched(self):
        key = _sidecar_key("http://127.0.0.1:34001/anthropic")
        key["scheme_version"] = 3
        path = self._put_sidecar(key)
        self._assert_untouched(path, "http://127.0.0.1:40001/anthropic")


# ---------------------------------------------------------------------------
# Pinned-checkout cross-checks: only run when a clean pinned core with a
# venv is discoverable (same hermeticity posture as the CLI contract test).
# ---------------------------------------------------------------------------
from packages.openant.tests.test_pinned_cli_contract import (  # noqa: E402
    _PINNED_CORE,
)
from packages.openant.scanner import _find_venv_python  # noqa: E402

_DIGEST_DRIVER = """\
import json, sys
from core.backend_identity import build_fingerprint
fp = build_fingerprint(
    phase="analyze", model="test-model-a",
    provider_name="raptor-gateway", adapter_type="anthropic",
    config_base_url="http://127.0.0.1:40001/anthropic",
    template_texts=["T1", "T2"],
    extra_key={"ctx_sources_sha256": "1" * 64},
)
print(json.dumps(fp))
"""

_RESTORE_DRIVER = """\
import json, sys
from core.checkpoint import StepCheckpoint
cp = StepCheckpoint("Analyze", sys.argv[1])
cp.dir = sys.argv[2]
print(json.dumps(sorted(cp.load_ids(skip_errors=True))))
"""


@unittest.skipIf(_PINNED_CORE is None,
                 "no pinned openant-core checkout with a venv on this host")
class TestPinnedCoreCrossChecks(unittest.TestCase):
    def _run_pinned(self, driver: str, *argv: str) -> str:
        core = _PINNED_CORE
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "driver.py"
            script.write_text(driver)
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", td),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "PYTHONPATH": str(core),
            }
            proc = subprocess.run(
                [_find_venv_python(core), str(script), *argv],
                capture_output=True, text=True, timeout=300,
                cwd=str(core), env=env, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            return proc.stdout

    def test_digest_replica_matches_pinned_algorithm(self):
        """The rebase's digest recompute must be byte-identical to the
        pinned core's — otherwise a rebased sidecar would fail its
        adopt gate and silently re-pay the whole analyze phase."""
        fp = json.loads(self._run_pinned(_DIGEST_DRIVER))
        key = {k: v for k, v in fp.items() if k != "key_digest"}
        self.assertEqual(fp["key_digest"], _canonical_digest(key))

    def test_seeded_checkpoints_suppress_redispatch(self):
        """Requirement (d): completed units in a SEEDED checkpoint dir
        are restored (never re-dispatched, never re-billed) by the
        pinned core's own resume logic, while errored units are NOT
        counted completed (they retry). Exercised end-to-end: build a
        prior checkpoint dir, seed it the way --resume does, and ask
        the pinned core which units it considers done."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prior = base / "prior_scan"
            ck = prior / "analyze_checkpoints"
            _write(ck / "u0.json", _analyze_row("f.py:u0", "SAFE", "safe"))
            _write(ck / "u1.json",
                   _analyze_row("f.py:u1", "VULNERABLE", "vulnerable"))
            _write(ck / "u2.json",
                   _analyze_row("f.py:u2", "ERROR", "error"))
            _write(ck / "_summary.json", {
                "phase": "done", "total_units": 3, "completed": 2,
                "incomplete": 0, "errors": 1})
            new = base / "new_scan"
            seed_scan_dir(prior, new)
            done = json.loads(self._run_pinned(
                _RESTORE_DRIVER, str(new),
                str(new / "analyze_checkpoints")))
            self.assertEqual(done, ["f.py:u0", "f.py:u1"])


if __name__ == "__main__":
    unittest.main()
