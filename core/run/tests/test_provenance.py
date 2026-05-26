"""Tests for run provenance manifest capture (core/run/provenance.py)."""

import json
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core.run.provenance import (
    UNAVAILABLE_MANIFEST,
    aggregate_provenance,
    build_start_manifest,
    detect_engines,
    environment_snapshot,
    format_manifest_block,
    format_provenance_rollup,
    format_repro_short,
    format_sha_short,
    harness_model_entry,
    public_view,
    run_deterministically_reproducible,
    run_engines,
    run_framework_sha,
    run_manifest,
    run_models,
    run_target,
    run_timestamp,
    run_who,
    source_control_snapshot,
    target_snapshot,
    tool_version,
)


def _full_run_metadata() -> dict:
    """A realistic .raptor-run.json with both safe and sensitive fields."""
    return {
        "version": 2,
        "command": "agentic",
        "timestamp": "2026-05-24T16:00:00+00:00",
        "end_timestamp": "2026-05-24T16:05:00+00:00",
        "duration_seconds": 300.0,
        "status": "completed",
        # --- sensitive — must never be published ---
        "target_path": "/home/jcartwright/clients/acme/secret-product/src",
        "session_pid": 1434317,
        "tool_pid": 1794072,
        "extra": {"error": "FileNotFoundError: /home/jcartwright/.ssh/id_rsa", "packs": ["x"]},
        # --- manifest ---
        "manifest": {
            "schema": 1,
            "source_control": {"base_sha": "9668aa8c", "dirty": True, "diff_sha256": "deadbeef"},
            # Target block: captured locally, but its commit/branch may be a
            # private engagement — opt-in for publication, so public_view drops it.
            "target": {"vcs": "git", "commit": "4f2a9b1c", "dirty": False, "branch": "release/2.3"},
            "environment": {"python": "3.14.4", "os": "Linux", "arch": "x86_64"},
            "engines": {"semgrep": "1.79.0"},
            "models": [{"alias": "gemini-2.5-pro", "resolved": "gemini-2.5-pro",
                        "role": "primary", "calls": 3}],
            "deterministically_reproducible": False,
        },
    }


def _have_git() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


_GIT = _have_git()


def _init_repo(path: Path) -> None:
    """Init a git repo at ``path`` with one commit.

    Config is set inline (``-c``-style via ``git config`` on the repo) so the
    test never depends on the operator's global gitconfig — CI runners often
    have none.
    """
    def g(*args):
        subprocess.run(
            ["git", "-C", str(path), *args],
            capture_output=True, text=True, check=True,
        )
    g("init", "-q")
    g("config", "user.email", "t@example.com")
    g("config", "user.name", "Test")
    (path / "a.txt").write_text("hello\n")
    g("add", "a.txt")
    g("commit", "-q", "-m", "init")


class TestSourceControlSnapshot(unittest.TestCase):

    def test_non_git_dir_reports_all_none(self):
        # A directory that is not a git checkout: provenance is unknowable,
        # so every field is None — never a fabricated/current value.
        with TemporaryDirectory() as d:
            snap = source_control_snapshot(Path(d))
            self.assertIsNone(snap["base_sha"])
            self.assertIsNone(snap["dirty"])
            self.assertIsNone(snap["diff_sha256"])

    @unittest.skipUnless(_GIT, "git not available")
    def test_clean_repo(self):
        with TemporaryDirectory() as d:
            repo = Path(d)
            _init_repo(repo)
            snap = source_control_snapshot(repo)
            self.assertRegex(snap["base_sha"], r"^[0-9a-f]{40}$")
            self.assertFalse(snap["dirty"])
            self.assertIsNone(snap["diff_sha256"])

    @unittest.skipUnless(_GIT, "git not available")
    def test_dirty_tracked_change_sets_diff_hash(self):
        with TemporaryDirectory() as d:
            repo = Path(d)
            _init_repo(repo)
            (repo / "a.txt").write_text("hello\nworld\n")  # modify tracked file
            snap = source_control_snapshot(repo)
            self.assertTrue(snap["dirty"])
            self.assertRegex(snap["diff_sha256"], r"^[0-9a-f]{64}$")

    @unittest.skipUnless(_GIT, "git not available")
    def test_untracked_only_is_dirty_without_diff_hash(self):
        # An untracked-only modification still flags dirty=True (a "modified
        # variant"), but `git diff HEAD` omits untracked files, so the diff
        # hash stays None. Documents the known v1 boundary.
        with TemporaryDirectory() as d:
            repo = Path(d)
            _init_repo(repo)
            (repo / "new.txt").write_text("x\n")
            snap = source_control_snapshot(repo)
            self.assertTrue(snap["dirty"])
            self.assertIsNone(snap["diff_sha256"])


class TestTargetSnapshot(unittest.TestCase):

    def test_none_path(self):
        self.assertIsNone(target_snapshot(None))

    def test_non_git_dir(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(target_snapshot(Path(d)))

    @unittest.skipUnless(_GIT, "git not available")
    def test_git_target(self):
        with TemporaryDirectory() as d:
            repo = Path(d)
            _init_repo(repo)
            snap = target_snapshot(repo)
            self.assertEqual(snap["vcs"], "git")
            self.assertRegex(snap["commit"], r"^[0-9a-f]{40}$")
            self.assertFalse(snap["dirty"])
            self.assertTrue(snap["branch"])

    def test_target_git_uses_untrusted_safe_overrides(self):
        # SECURITY REGRESSION: the target is attacker-controlled — every git
        # invocation must carry the safe overrides that neutralise config-based
        # RCE (core.fsmonitor / core.hooksPath / credential.helper, CVE-2024-32002
        # family). Spy on the argv git is actually invoked with. Works even on a
        # non-git dir — the first (rev-parse) call already carries the overrides.
        import core.run.provenance as prov
        seen = []
        real_run = prov.subprocess.run

        def spy(cmd, *a, **k):
            seen.append(cmd)
            return real_run(cmd, *a, **k)

        with TemporaryDirectory() as d:
            with mock.patch.object(prov.subprocess, "run", side_effect=spy):
                prov.target_snapshot(Path(d))
        joined = " ".join(" ".join(map(str, c)) for c in seen)
        self.assertTrue(seen, "no git invocation captured")
        self.assertIn("core.fsmonitor=", joined)
        self.assertIn("core.hooksPath=/dev/null", joined)

    def test_source_control_uses_bare_git(self):
        # RAPTOR's own checkout is trusted — no per-invocation overrides needed
        # (and adding them everywhere would be noise). Confirm the framework
        # snapshot does NOT route through the untrusted-safe path.
        import core.run.provenance as prov
        seen = []
        real_run = prov.subprocess.run

        def spy(cmd, *a, **k):
            seen.append(cmd)
            return real_run(cmd, *a, **k)

        with TemporaryDirectory() as d:
            with mock.patch.object(prov.subprocess, "run", side_effect=spy):
                prov.source_control_snapshot(Path(d))
        joined = " ".join(" ".join(map(str, c)) for c in seen)
        self.assertNotIn("core.fsmonitor=", joined)


class TestDetectEngines(unittest.TestCase):

    def test_empty_dir(self):
        with TemporaryDirectory() as d:
            self.assertEqual(detect_engines(Path(d)), {})

    def test_detects_from_canonical_output_files(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            (out / "semgrep_owasp.sarif").write_text("{}")
            (out / "cocci.sarif").write_text("{}")
            eng = detect_engines(out)
            self.assertIn("semgrep", eng)
            self.assertIn("coccinelle", eng)
            self.assertNotIn("codeql", eng)


class TestBuildStartManifestTarget(unittest.TestCase):

    def test_directory_target_gets_acquisition_marker(self):
        # A non-git directory now gets the {source:"directory"} acquisition
        # stamp (no git block, no content hash — the equivalence id is the
        # coverage store's, derived from the inventory).
        with TemporaryDirectory() as d:
            m = build_start_manifest(target=Path(d))
            self.assertEqual(m["target"], {"source": "directory"})

    @unittest.skipUnless(_GIT, "git not available")
    def test_target_block_when_git(self):
        with TemporaryDirectory() as d:
            repo = Path(d)
            _init_repo(repo)
            m = build_start_manifest(target=repo)
            self.assertIn("target", m)
            self.assertEqual(m["target"]["vcs"], "git")


class TestEnvironmentSnapshot(unittest.TestCase):

    def test_has_python_os_arch(self):
        env = environment_snapshot()
        self.assertIn("python", env)
        self.assertTrue(env["python"])
        # Coarse os/arch only — not the fingerprinting platform.platform()
        # string. See environment_snapshot docstring.
        self.assertIn("os", env)
        self.assertIn("arch", env)
        self.assertNotIn("platform", env)


class TestBuildStartManifest(unittest.TestCase):

    def test_shape(self):
        with TemporaryDirectory() as d:
            m = build_start_manifest(Path(d))
            self.assertEqual(m["schema"], 1)
            self.assertIn("source_control", m)
            self.assertIn("environment", m)


class TestToolVersion(unittest.TestCase):

    def test_unknown_tool_returns_none(self):
        self.assertIsNone(tool_version("not-a-real-engine"))

    @unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
    def test_semgrep_returns_version_string(self):
        v = tool_version("semgrep")
        self.assertIsInstance(v, str)
        self.assertTrue(v)

    def test_absent_tool_returns_none(self):
        # 'coccinelle' probes `spatch`; if it isn't installed the probe must
        # degrade to None rather than raise.
        if shutil.which("spatch"):
            self.skipTest("spatch installed — can't exercise the absent path")
        self.assertIsNone(tool_version("coccinelle"))


class TestStandardCompletionProvenance(unittest.TestCase):
    """standard_completion_provenance — the end-of-run facts the lifecycle
    derives itself: engines detected from output files for EVERY command, with
    deterministically_reproducible True only for the deterministic static-rule
    commands (scan/codeql)."""

    def test_deterministic_only_for_static_rule_commands(self):
        from core.run.provenance import is_deterministically_reproducible
        self.assertTrue(is_deterministically_reproducible("scan"))
        self.assertTrue(is_deterministically_reproducible("codeql"))
        # LLM-mediated (agentic/validate/understand) and stochastic/runtime
        # (fuzz/web) commands are not — nor is an unknown command.
        for cmd in ("agentic", "validate", "understand", "fuzz", "web", None):
            self.assertFalse(is_deterministically_reproducible(cmd))

    def test_engines_detected_for_any_command(self):
        from core.run.provenance import standard_completion_provenance
        with TemporaryDirectory() as d:
            out = Path(d)
            # Real output filenames: semgrep_*.sarif, codeql_*.sarif, cocci.sarif.
            (out / "semgrep_semgrep_injection.sarif").write_text("{}")
            (out / "codeql_java.sarif").write_text("{}")
            (out / "cocci.sarif").write_text("{}")
            # Even a non-scan command captures engines now (uniform coverage);
            # only the reproducibility verdict differs by command.
            m = standard_completion_provenance(out, "validate")
            self.assertIn("semgrep", m["engines"])
            self.assertIn("codeql", m["engines"])
            self.assertIn("coccinelle", m["engines"])
            self.assertFalse(m["deterministically_reproducible"])

    def test_scan_reproducible_with_no_output(self):
        from core.run.provenance import standard_completion_provenance
        with TemporaryDirectory() as d:
            m = standard_completion_provenance(Path(d), "scan")
            self.assertEqual(m["engines"], {})
            self.assertTrue(m["deterministically_reproducible"])


class TestFormatShaShort(unittest.TestCase):

    def test_clean_tree(self):
        m = {"source_control": {"base_sha": "9668aa8c3b0f", "dirty": False}}
        self.assertEqual(format_sha_short(m), "9668aa8")

    def test_dirty_tree_gets_star(self):
        m = {"source_control": {"base_sha": "9668aa8c3b0f", "dirty": True}}
        self.assertEqual(format_sha_short(m), "9668aa8*")

    def test_no_sha_or_no_manifest_is_empty(self):
        self.assertEqual(format_sha_short(None), "")
        self.assertEqual(format_sha_short({}), "")
        self.assertEqual(format_sha_short({"source_control": {"base_sha": None}}), "")


class TestFormatManifestBlock(unittest.TestCase):

    def test_empty_for_no_manifest(self):
        self.assertEqual(format_manifest_block(None), "")

    def test_unavailable_is_honest(self):
        block = format_manifest_block(UNAVAILABLE_MANIFEST)
        self.assertIn("unavailable", block)

    def test_full_block_renders_all_sections(self):
        m = {
            "schema": 1,
            "source_control": {"base_sha": "9668aa8c3b0f54b9", "dirty": True},
            "environment": {"python": "3.14.4", "os": "Linux", "arch": "x86_64"},
            "engines": {"semgrep": "1.79.0"},
            "models": [{"alias": "gemini-2.5-pro", "resolved": "gemini-2.5-pro-002",
                        "role": "primary", "calls": 3}],
            "deterministically_reproducible": False,
        }
        block = format_manifest_block(m)
        self.assertIn("9668aa8c3b0f", block)
        self.assertIn("(modified)", block)
        self.assertIn("Python 3.14.4", block)
        self.assertIn("semgrep 1.79.0", block)
        self.assertIn("gemini-2.5-pro-002", block)
        self.assertIn("no (LLM-mediated)", block)


class TestPublicView(unittest.TestCase):

    def test_drops_sensitive_fields(self):
        pub = public_view(_full_run_metadata())
        # The leak vectors must be gone entirely.
        self.assertNotIn("target_path", pub)
        self.assertNotIn("extra", pub)
        self.assertNotIn("session_pid", pub)
        self.assertNotIn("tool_pid", pub)
        # And nothing nested should echo the operator's home path.
        self.assertNotIn("jcartwright", json.dumps(pub))

    def test_target_block_dropped_by_default(self):
        # The target's commit/branch may be a private engagement — not in the
        # publish allowlist; an opt-in label belongs to the cite UX.
        pub = public_view(_full_run_metadata())
        self.assertNotIn("target", pub.get("manifest", {}))
        self.assertNotIn("4f2a9b1c", json.dumps(pub))

    def test_keeps_safe_run_and_manifest_fields(self):
        pub = public_view(_full_run_metadata())
        self.assertEqual(pub["command"], "agentic")
        self.assertEqual(pub["status"], "completed")
        m = pub["manifest"]
        self.assertEqual(m["source_control"]["base_sha"], "9668aa8c")
        self.assertTrue(m["source_control"]["dirty"])
        self.assertEqual(m["source_control"]["diff_sha256"], "deadbeef")  # hash, content-safe
        self.assertEqual(m["environment"]["os"], "Linux")
        self.assertEqual(m["engines"]["semgrep"], "1.79.0")
        self.assertEqual(m["models"][0]["resolved"], "gemini-2.5-pro")
        self.assertIs(m["deterministically_reproducible"], False)

    def test_allowlist_drops_unknown_future_fields(self):
        md = _full_run_metadata()
        md["some_future_secret"] = "leak-me"
        md["manifest"]["some_future_manifest_secret"] = "leak-me-too"
        pub = public_view(md)
        self.assertNotIn("some_future_secret", pub)
        self.assertNotIn("some_future_manifest_secret", pub["manifest"])

    def test_subdict_fields_allowlisted(self):
        # Allowlist must apply INSIDE environment/engines/models too — a crafted
        # manifest can't smuggle a secret/path under an extra sub-dict key.
        md = {"command": "scan", "manifest": {
            "environment": {"python": "3.14", "os": "Linux", "arch": "x86_64", "SECRET": "leak"},
            "engines": {"semgrep": "1.79.0", "evil": {"cmd": "/leak"}},
            "models": [{"provider": "g", "alias": "a", "resolved": "r",
                        "role": "primary", "calls": 1, "api_key": "LEAK"}],
        }}
        pub = public_view(md)
        self.assertEqual(set(pub["manifest"]["environment"]), {"python", "os", "arch"})
        # non-string engine value (a dict) dropped
        self.assertEqual(pub["manifest"]["engines"], {"semgrep": "1.79.0"})
        self.assertEqual(set(pub["manifest"]["models"][0]),
                         {"provider", "alias", "resolved", "role", "calls"})
        self.assertNotIn("LEAK", json.dumps(pub))

    def test_unavailable_manifest_passthrough(self):
        md = {"command": "scan", "manifest": dict(UNAVAILABLE_MANIFEST)}
        pub = public_view(md)
        self.assertEqual(pub["manifest"], {"provenance": "unavailable"})

    def test_none_and_empty(self):
        self.assertEqual(public_view(None), {})
        self.assertEqual(public_view({}), {})


class TestFormatReproShort(unittest.TestCase):

    def test_values(self):
        self.assertEqual(format_repro_short({"deterministically_reproducible": True}), "repro")
        self.assertEqual(format_repro_short({"deterministically_reproducible": False}), "llm")
        self.assertEqual(format_repro_short({}), "")
        self.assertEqual(format_repro_short(None), "")


class TestAggregateProvenance(unittest.TestCase):

    def _metas(self):
        return [
            {"manifest": {
                "source_control": {"base_sha": "aaa", "dirty": False},
                "engines": {"semgrep": "1.79.0"},
                "models": [{"alias": "gemini-2.5-pro", "resolved": "gemini-2.5-pro"}],
                "deterministically_reproducible": True}},
            {"manifest": {
                "source_control": {"base_sha": "aaa", "dirty": True},
                "engines": {"codeql": "2.23.8"},
                "models": [{"alias": "claude-haiku-4-5", "resolved": "claude-haiku-4-5-20251001"}],
                "deterministically_reproducible": False}},
            {"manifest": {"provenance": "unavailable"}},
            None,  # skipped entirely
        ]

    def test_rollup_counts(self):
        s = aggregate_provenance(self._metas())
        self.assertEqual(s["runs"], 3)             # None skipped
        self.assertEqual(s["shas"]["aaa"], 2)      # same SHA across two runs
        self.assertEqual(s["dirty_runs"], 1)
        self.assertIn("semgrep", s["engines"])
        self.assertIn("codeql", s["engines"])
        self.assertEqual(s["models"]["gemini-2.5-pro"], 1)
        self.assertEqual(s["models"]["claude-haiku-4-5-20251001"], 1)  # by resolved snapshot
        self.assertEqual(s["reproducible"], {"yes": 1, "no": 1, "unknown": 1})
        self.assertEqual(s["unavailable"], 1)

    def test_empty(self):
        self.assertEqual(aggregate_provenance([])["runs"], 0)

    def test_tolerates_non_dict_engines(self):
        # Malformed/imported manifest with engines as a list must not crash.
        s = aggregate_provenance([{"manifest": {
            "engines": ["semgrep"],
            "source_control": {"base_sha": "x", "dirty": False},
            "deterministically_reproducible": True,
        }}])
        self.assertEqual(s["runs"], 1)
        self.assertEqual(s["engines"], {})


class TestFormatProvenanceRollup(unittest.TestCase):

    def test_no_runs(self):
        self.assertEqual(format_provenance_rollup({"runs": 0}), "No runs with provenance.")

    def test_render(self):
        s = aggregate_provenance([
            {"manifest": {
                "source_control": {"base_sha": "abc123def456", "dirty": True},
                "engines": {"semgrep": "1.79.0"},
                "models": [{"resolved": "gemini-2.5-pro"}],
                "deterministically_reproducible": False}},
        ])
        out = format_provenance_rollup(s)
        self.assertIn("Provenance across 1 run", out)
        self.assertIn("abc123def456", out)
        self.assertIn("Modified-tree runs: 1/1", out)
        self.assertIn("semgrep 1.79.0", out)
        self.assertIn("LLM-mediated", out)


class TestLifecycleE2E(unittest.TestCase):
    """End-to-end: start_run seals framework+target+env, a scan drops engine
    output, complete_run fills engines+reproducibility — the full manifest a
    real /scan run produces, exercised through the real lifecycle (no mocks)."""

    @unittest.skipUnless(_GIT, "git not available")
    def test_scan_run_seals_and_enriches_full_manifest(self):
        from core.run import complete_run, load_run_metadata, start_run
        with TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            _init_repo(target)
            out = Path(d) / "scan-run"

            start_run(out, "scan", target=str(target))
            # The manifest is sealed at START: framework + target + env present
            # before any analysis runs.
            sealed = load_run_metadata(out)["manifest"]
            self.assertIn("source_control", sealed)       # RAPTOR's own repo
            self.assertEqual(sealed["target"]["vcs"], "git")
            self.assertRegex(sealed["target"]["commit"], r"^[0-9a-f]{40}$")
            self.assertIn("environment", sealed)
            self.assertNotIn("engines", sealed)            # not known yet

            # Scanner drops its SARIF output, then the run completes. No
            # per-command manifest wiring — the lifecycle fills engines +
            # deterministically_reproducible itself, uniformly.
            (out / "semgrep_owasp.sarif").write_text("{}")
            complete_run(out)

            final = load_run_metadata(out)
            m = final["manifest"]
            self.assertEqual(final["status"], "completed")
            # Start-sealed facts survive the merge…
            self.assertIn("source_control", m)
            self.assertEqual(m["target"]["vcs"], "git")
            # …and end-of-run facts are filled by the lifecycle.
            self.assertIn("semgrep", m["engines"])
            self.assertTrue(m["deterministically_reproducible"])


class TestUniformCompletionEnrichment(unittest.TestCase):
    """complete_run fills standard provenance for EVERY completion path —
    including the Claude-driven commands that finish through the lifecycle
    stubs without passing a manifest — and never clobbers a caller-supplied
    fact."""

    def test_non_scan_command_enriched_without_caller_manifest(self):
        # /validate and /understand finish via the lifecycle stubs with no
        # manifest=. They must still get engines + reproducibility — this is
        # the uneven-coverage gap closed.
        from core.run import complete_run, load_run_metadata, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "validate-run"
            start_run(out, "validate", target=str(Path(d)))
            (out / "semgrep_x.sarif").write_text("{}")
            complete_run(out)  # no manifest — the stub path
            m = load_run_metadata(out)["manifest"]
            self.assertIn("semgrep", m["engines"])
            self.assertFalse(m["deterministically_reproducible"])

    def test_caller_supplied_key_is_not_clobbered(self):
        # setdefault precedence: an explicit caller value wins over the
        # lifecycle's derived default.
        from core.run import complete_run, load_run_metadata, start_run
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "validate", target=str(Path(d)))
            complete_run(out, manifest={"deterministically_reproducible": True})
            m = load_run_metadata(out)["manifest"]
            self.assertTrue(m["deterministically_reproducible"])

    def test_unavailable_manifest_not_enriched(self):
        # A run carrying the 'unavailable' stamp (predates manifest capture) is
        # left untouched — no engines/reproducibility grafted on.
        import json
        from core.run import complete_run, load_run_metadata, start_run
        from core.run.metadata import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan", target=str(Path(d)))
            meta_path = out / RUN_METADATA_FILE
            meta = json.loads(meta_path.read_text())
            meta["manifest"] = dict(UNAVAILABLE_MANIFEST)
            meta_path.write_text(json.dumps(meta))
            (out / "semgrep_x.sarif").write_text("{}")
            complete_run(out)
            m = load_run_metadata(out)["manifest"]
            self.assertEqual(m.get("provenance"), "unavailable")
            self.assertNotIn("engines", m)


class TestUnavailableManifest(unittest.TestCase):

    def test_marked_unavailable(self):
        self.assertEqual(UNAVAILABLE_MANIFEST["provenance"], "unavailable")
        self.assertIn("reason", UNAVAILABLE_MANIFEST)


class TestManifestReadAccessors(unittest.TestCase):
    """The stable read contract consumers (CoverageStore import, /project rollup,
    future citation) go through instead of indexing the raw manifest dict."""

    def test_reads_each_field_from_a_real_manifest(self):
        md = _full_run_metadata()
        self.assertEqual(run_engines(md), {"semgrep": "1.79.0"})
        self.assertEqual(run_models(md)[0]["resolved"], "gemini-2.5-pro")
        self.assertEqual(run_target(md)["commit"], "4f2a9b1c")
        self.assertEqual(run_framework_sha(md), "9668aa8c")
        self.assertEqual(run_timestamp(md), "2026-05-24T16:00:00+00:00")
        self.assertIs(run_deterministically_reproducible(md), False)

    def test_degrades_gracefully_on_none_and_unavailable(self):
        # None input and the 'unavailable' stamp both yield empty/None — never
        # raise — so the same call works on legacy/adopted runs.
        for md in (None, {}, {"manifest": dict(UNAVAILABLE_MANIFEST)}):
            self.assertEqual(run_manifest(md), {})
            self.assertEqual(run_engines(md), {})
            self.assertEqual(run_models(md), [])
            self.assertIsNone(run_target(md))
            self.assertIsNone(run_framework_sha(md))
            self.assertIsNone(run_deterministically_reproducible(md))

    def test_missing_fields_return_empty_not_raise(self):
        # A manifest that predates a field (e.g. no det_repro / no target yet)
        # reads as None/empty, distinguishable from a present value.
        md = {"timestamp": "2026-05-25T00:00:00+00:00",
              "manifest": {"source_control": {"base_sha": "abc"}}}
        self.assertEqual(run_engines(md), {})
        self.assertEqual(run_models(md), [])
        self.assertIsNone(run_target(md))
        self.assertIsNone(run_deterministically_reproducible(md))
        self.assertEqual(run_framework_sha(md), "abc")
        self.assertEqual(run_timestamp(md), "2026-05-25T00:00:00+00:00")

    def test_malformed_shapes_tolerated(self):
        # Imported/corrupt manifest with wrong types must not crash accessors.
        md = {"manifest": {"engines": ["not", "a", "dict"],
                           "models": {"not": "a list"},
                           "target": "not a dict"}}
        self.assertEqual(run_engines(md), {})
        self.assertEqual(run_models(md), [])
        self.assertIsNone(run_target(md))


class TestWhoAndHarnessModel(unittest.TestCase):
    """#1 — the WHO (finder identity) sealed at start, and the agent-supplied
    ambient harness model recorded at completion."""

    def test_build_start_manifest_seals_who_when_set(self):
        from unittest import mock
        with mock.patch("core.run.identity.load_finder_identity",
                        return_value={"name": "Jane Doe", "handle": "@jane"}):
            m = build_start_manifest(target=None)
            self.assertEqual(m["who"], {"name": "Jane Doe", "handle": "@jane"})

    def test_build_start_manifest_omits_who_when_unset(self):
        from unittest import mock
        with mock.patch("core.run.identity.load_finder_identity", return_value=None):
            self.assertNotIn("who", build_start_manifest(target=None))

    def test_run_who_accessor(self):
        self.assertEqual(run_who({"manifest": {"who": {"name": "Jane"}}}),
                         {"name": "Jane"})
        self.assertIsNone(run_who({"manifest": {}}))
        self.assertIsNone(run_who(None))
        self.assertIsNone(run_who({"manifest": {"who": "not-a-dict"}}))

    def test_harness_model_entry_valid(self):
        self.assertEqual(
            harness_model_entry("claude-opus-4-7[1m]"),
            {"role": "harness", "alias": "claude-opus-4-7[1m]",
             "resolved": "claude-opus-4-7[1m]"})

    def test_harness_model_entry_tolerates_agent_mistakes(self):
        # The agent WILL fumble it — every bad shape must omit, never record junk.
        for bad in (
            None, "", "   ",
            "<your-model-id>",            # unsubstituted placeholder
            "claude-opus<x>",             # stray angle bracket
            "--model",                    # a flag captured as the value
            "-opus",                      # leading dash
            "the model is opus",          # prose (whitespace)
            "claude opus 4.7",            # whitespace
            "x" * 200,                    # implausibly long
            123,                          # non-string
            # adversarial: manifest is publish-bound, so no injection/spoof
            "claude\x00evil",             # null byte
            "claude\x1b[31mRED",          # ANSI terminal-injection escape
            "claude‮RTL",                 # unicode RTL-override spoof
            "café-model",                 # non-ASCII (model ids are ASCII)
        ):
            self.assertIsNone(harness_model_entry(bad), f"should omit: {bad!r}")


if __name__ == "__main__":
    unittest.main()
