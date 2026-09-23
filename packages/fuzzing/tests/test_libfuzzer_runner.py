"""Tests for the libFuzzer runner process contract."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.libfuzzer_runner import LibFuzzerRunner


class TestLibFuzzerRunner(unittest.TestCase):

    def test_run_uses_sandbox_and_sanitised_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            out_dir = tmp / "out"

            captured = {}

            def fake_sandbox_run(cmd, **kwargs):
                captured["cmd"] = cmd
                captured["kwargs"] = kwargs
                # Streams are file-backed (bounded-memory capture of
                # untrusted harness output) — write where the harness
                # would.
                kwargs["stderr"].write(
                    b"#1 DONE cov: 1 ft: 1 corp: 1/1b exec/s: 1\n")

                class Result:
                    returncode = 0

                return Result()

            with patch.dict(os.environ, {"LD_PRELOAD": "evil.dylib"}, clear=False), \
                 patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                       side_effect=fake_sandbox_run):
                runner = LibFuzzerRunner(
                    harness_path=harness,
                    output_dir=out_dir,
                    max_total_time=1,
                )
                result = runner.run()

            self.assertEqual(result.stats.total_executions, 1)
            self.assertEqual(captured["cmd"][0], str(harness.resolve()))
            self.assertTrue(captured["kwargs"]["block_network"])
            self.assertTrue(captured["kwargs"]["restrict_reads"])
            self.assertNotIn("LD_PRELOAD", captured["kwargs"]["env"])
            # identity scrub: the harness is untrusted target code
            env = captured["kwargs"]["env"]
            for ident in ("USER", "LOGNAME", "HOSTNAME", "PWD"):
                self.assertNotIn(ident, env)
            self.assertEqual(env.get("HOME"), "/tmp")
            self.assertEqual(captured["kwargs"]["output"], str(out_dir.resolve()))

    def test_corpus_is_copied_into_output_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            seed_dir = tmp / "seeds"
            seed_dir.mkdir()
            (seed_dir / "seed0").write_bytes(b"seed")

            runner = LibFuzzerRunner(
                harness_path=harness,
                corpus_dir=seed_dir,
                output_dir=tmp / "out",
                max_total_time=1,
            )

            self.assertEqual((runner.corpus_dir / "seed0").read_bytes(), b"seed")
            self.assertTrue(str(runner.corpus_dir).startswith(str((tmp / "out").resolve())))

    def test_default_output_dir_anchored_to_configured_out_dir(self):
        # Regression: the default output dir was a literal
        # `out/libfuzzer_*` relative to the CWD at construction time,
        # planting run dirs inside whatever directory the operator
        # launched from instead of the configured run base.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            configured = tmp / "configured-out"

            with patch(
                "core.config.RaptorConfig.get_out_dir",
                return_value=configured,
            ):
                runner = LibFuzzerRunner(harness_path=harness)

            self.assertTrue(
                str(runner.output_dir).startswith(str(configured.resolve())),
                f"default output dir {runner.output_dir} not under the "
                f"configured out dir {configured}",
            )


class TestCampaignVerdictAndArtifacts(unittest.TestCase):
    """Failure verdict + artifact globs.

    A harness dying at startup (missing shared lib, rc=127) must not
    surface as a clean zero-findings campaign, and LSAN leak-<hash>
    artifacts (detect_leaks=1 is set on the campaign env) count as
    findings."""

    def _run(self, tmp: Path, returncode: int, artifacts: list[str]):
        harness = tmp / "fuzz_target"
        harness.write_text("#!/bin/sh\nexit 0\n")
        harness.chmod(0o755)
        out_dir = tmp / "out"

        def fake_sandbox_run(cmd, **kwargs):
            for name in artifacts:
                (out_dir / "crashes" / name).write_bytes(b"input")

            class Result:
                pass

            Result.returncode = returncode
            return Result()

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake_sandbox_run):
            runner = LibFuzzerRunner(
                harness_path=harness, output_dir=out_dir,
                max_total_time=1,
            )
            return runner.run()

    def test_startup_death_is_campaign_failed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self._run(Path(tmpdir), returncode=127, artifacts=[])
            self.assertTrue(result.campaign_failed)
            self.assertEqual(result.returncode, 127)

    def test_clean_exit_is_not_failed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self._run(Path(tmpdir), returncode=0, artifacts=[])
            self.assertFalse(result.campaign_failed)

    def test_dirty_exit_with_crash_is_a_finding_not_failure(self):
        # libFuzzer exits non-zero ON the crash it found — that is a
        # successful campaign.
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self._run(
                Path(tmpdir), returncode=77, artifacts=["crash-deadbeef"])
            self.assertFalse(result.campaign_failed)
            self.assertEqual(len(result.crashes), 1)

    def test_leak_artifacts_are_collected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self._run(
                Path(tmpdir), returncode=1, artifacts=["leak-cafef00d"])
            self.assertEqual(len(result.leak_inputs), 1)
            self.assertEqual(result.stats.leaks, 1)
            self.assertEqual(result.total_findings(), 1)
            # A leak ended the campaign — it is a finding, not a
            # failed run.
            self.assertFalse(result.campaign_failed)

    def test_streams_are_file_backed_not_captured(self):
        # The harness's output must never be buffered unbounded in
        # this process — file-backed streams only, then a bounded
        # read-back for parsing.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            captured = {}

            def fake_sandbox_run(cmd, **kwargs):
                captured.update(kwargs)

                class Result:
                    returncode = 0

                return Result()

            with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                       side_effect=fake_sandbox_run):
                LibFuzzerRunner(
                    harness_path=harness, output_dir=tmp / "out",
                    max_total_time=1,
                ).run()

            self.assertNotIn("capture_output", captured)
            self.assertTrue(hasattr(captured["stdout"], "write"))
            self.assertTrue(hasattr(captured["stderr"], "write"))

    def test_log_tail_read_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            big = Path(tmpdir) / "stderr.log"
            cap = LibFuzzerRunner._MAX_PARSE_BYTES
            with open(big, "wb") as fh:
                fh.write(b"x" * (cap + 1024))
                fh.write(b"TAIL-MARKER")
            text = LibFuzzerRunner._read_log_tail(big)
            self.assertLessEqual(len(text), cap)
            self.assertTrue(text.endswith("TAIL-MARKER"))


class TestSeedWorkingCorpusSymlinks(unittest.TestCase):
    """Corpus seeding must never dereference symlinks: a hostile
    in-repo corpus can plant ``seed -> <host secret>`` and the copied
    bytes would be handed to the untrusted harness and persisted in
    run artifacts. Mirrors the AFL corpus stager's contract."""

    def test_file_symlink_rejected_regular_files_copied(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            secret = tmp / "secret"
            secret.write_bytes(b"PRIVATE-KEY-MATERIAL")
            source = tmp / "corpus"
            (source / "nested").mkdir(parents=True)
            (source / "seed-real").write_bytes(b"A")
            (source / "nested" / "seed-deep").write_bytes(b"B")
            (source / "seed-link").symlink_to(secret)
            dest = tmp / "dest"
            dest.mkdir()

            LibFuzzerRunner._seed_working_corpus(source, dest)

            self.assertEqual((dest / "seed-real").read_bytes(), b"A")
            self.assertEqual(
                (dest / "nested" / "seed-deep").read_bytes(), b"B")
            self.assertFalse((dest / "seed-link").exists())
            copied = {p.read_bytes() for p in dest.rglob("*") if p.is_file()}
            self.assertNotIn(b"PRIVATE-KEY-MATERIAL", copied)

    def test_directory_symlink_not_traversed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            outside = tmp / "outside"
            outside.mkdir()
            (outside / "leak").write_bytes(b"OUTSIDE")
            source = tmp / "corpus"
            source.mkdir()
            (source / "seed0").write_bytes(b"A")
            (source / "dirlink").symlink_to(outside)
            dest = tmp / "dest"
            dest.mkdir()

            LibFuzzerRunner._seed_working_corpus(source, dest)

            self.assertEqual((dest / "seed0").read_bytes(), b"A")
            self.assertFalse((dest / "dirlink").exists())


if __name__ == "__main__":
    unittest.main()


class TestSeedCopyBounded:
    def test_oversized_seed_skipped_with_warning(self, tmp_path, monkeypatch, caplog):
        """A hostile in-repo corpus can plant a huge \"seed\" — the
        stager must skip it (recorded, like symlinks), not copy
        gigabytes into the run dir (corpus_manager's bounded-copy
        idiom)."""
        import packages.fuzzing.libfuzzer_runner as lf

        monkeypatch.setattr(lf.LibFuzzerRunner, "_MAX_SEED_BYTES", 1024)
        source = tmp_path / "src"
        source.mkdir()
        (source / "ok").write_bytes(b"A" * 100)
        (source / "huge").write_bytes(b"B" * 4096)
        dest = tmp_path / "work"
        dest.mkdir()
        with caplog.at_level("WARNING"):
            lf.LibFuzzerRunner._seed_working_corpus(source, dest)
        assert (dest / "ok").read_bytes() == b"A" * 100
        assert not (dest / "huge").exists()
        assert any("skipped" in r.getMessage() for r in caplog.records)

    def test_seed_growing_past_cap_between_stat_and_read_truncated_out(
        self, tmp_path, monkeypatch,
    ):
        """The copy itself is a bounded read, so a file growing after
        the stat can never land oversize in the working corpus."""
        import packages.fuzzing.libfuzzer_runner as lf

        monkeypatch.setattr(lf.LibFuzzerRunner, "_MAX_SEED_BYTES", 1024)
        source = tmp_path / "src"
        source.mkdir()
        seed = source / "grower"
        seed.write_bytes(b"A" * 100)

        real_stat = type(seed).stat

        def lying_stat(self, **kw):
            st = real_stat(self, **kw)
            if self.name == "grower" and st.st_size == 4096:
                # pretend the pre-growth size was still visible
                import os
                vals = list(st)
                vals[6] = 100
                return os.stat_result(vals)
            return st

        seed.write_bytes(b"A" * 4096)  # "grew" after the stat
        monkeypatch.setattr(type(seed), "stat", lying_stat)
        dest = tmp_path / "work"
        dest.mkdir()
        lf.LibFuzzerRunner._seed_working_corpus(source, dest)
        copied = dest / "grower"
        assert not copied.exists() or copied.stat().st_size <= 1024
