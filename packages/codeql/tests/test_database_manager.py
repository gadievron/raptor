"""Tests for CodeQL database manager build command handling."""

import json
import os
import stat
import subprocess as sp
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.build.build_detector import BuildSystem
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture
def db_manager(tmp_path):
    """Create a DatabaseManager with a fake codeql binary."""
    with patch.object(DatabaseManager, '__init__', lambda self: None):
        mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.cache_dir = tmp_path / "cache"
        mgr.cache_dir.mkdir()
        # db_root mirrors what real __init__ sets (RaptorConfig.CODEQL_DB_DIR);
        # needed by load_metadata / get_metadata_path which don't go through
        # the get_database_dir seam that other tests patch.
        mgr.db_root = mgr.cache_dir
        return mgr


def _run_create(db_manager, tmp_path, command, language="javascript"):
    """Run create_database and capture the subprocess command and script state."""
    bs = BuildSystem(type="npm", command=command, working_dir=tmp_path,
                     env_vars={}, confidence=1.0, detected_files=[])
    captured = {"cmd": [], "script_content": None, "script_mode": None}

    def fake_run(cmd, **kwargs):
        # Return-shape-aware fake: pre-fix every invocation returned
        # ``returncode=0, stdout="2.16.0"`` regardless of which codeql
        # subcommand was being run. That meant ``codeql database
        # create`` would "succeed" without producing any database
        # files, and the test only passed because the surrounding
        # mocks (``_count_database_files``, ``get_database_dir``)
        # papered over the missing artefacts. A regression where
        # ``database create`` started returning a CompletedProcess
        # with empty stderr but non-zero rc would slip past the
        # test silently. Differentiate by subcommand so each branch
        # of the create_database control flow gets a realistic
        # response shape and a future shape change surfaces as a
        # test failure rather than a downstream production bug.
        # Only capture the database create call, not codeql version etc.
        is_version_probe = "--version" in cmd
        is_database_create = (
            "database" in cmd and "create" in cmd
        )
        if is_database_create:
            captured["cmd"] = list(cmd)
            for arg in cmd:
                p = Path(str(arg))
                if p.name.startswith(".raptor_codeql_build_") and p.exists():
                    captured["script_content"] = p.read_text()
                    captured["script_mode"] = p.stat().st_mode
        r = MagicMock()
        r.returncode = 0
        if is_version_probe:
            # ``codeql --version`` legitimately prints the version
            # string and nothing else.
            r.stdout = "2.16.0\n"
            r.stderr = ""
        elif is_database_create:
            # ``codeql database create`` prints progress to stderr
            # and a JSON-ish summary to stdout on success; empty
            # stdout/stderr would be the bug shape we want to
            # surface as a test failure if it ever appeared.
            r.stdout = ""
            r.stderr = "Initializing database at ...\nFinalizing database.\n"
        else:
            r.stdout = ""
            r.stderr = ""
        return r

    db_path = tmp_path / "db"
    with patch('core.sandbox.run', side_effect=fake_run), \
         patch.object(db_manager, '_count_database_files', return_value=0), \
         patch.object(db_manager, 'save_metadata'), \
         patch.object(db_manager, 'get_cached_database', return_value=None), \
         patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
         patch.object(db_manager, 'get_database_dir', return_value=db_path):
        db_manager.create_database(tmp_path, language, bs)

    return captured


class TestBuildScript:
    """CodeQL --command is always wrapped in a build script."""

    def test_simple_command_passed_directly(self, db_manager, tmp_path):
        """Single-word commands like 'make' pass through without a script."""
        c = _run_create(db_manager, tmp_path, "make")
        assert c["script_content"] is None
        idx = c["cmd"].index("--command")
        assert c["cmd"][idx + 1] == "make"

    def test_shell_operators_wrapped(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert "npm install && npm run build" in c["script_content"]

    def test_or_operator_wrapped(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "pip install -e . || pip install -r requirements.txt")
        assert "||" in c["script_content"]

    def test_script_has_shebang(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "cmake . && make")
        assert c["script_content"].startswith("#!/bin/bash\n")

    def test_script_is_executable(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert c["script_mode"] & stat.S_IEXEC

    def test_script_passed_as_command_arg(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "cmake . && make")
        assert "--command" in c["cmd"]
        idx = c["cmd"].index("--command")
        assert ".raptor_codeql_build_" in c["cmd"][idx + 1]

    def test_no_command_equals_format(self, db_manager, tmp_path):
        """Never uses --command=value (the old broken format)."""
        c = _run_create(db_manager, tmp_path, "make")
        assert not any(arg.startswith("--command=") for arg in c["cmd"])

    def test_script_cleaned_up_after_success(self, db_manager, tmp_path):
        _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_script_cleaned_up_on_failure(self, db_manager, tmp_path):
        bs = BuildSystem(type="npm", command="npm install", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 1
            r.stderr = "fail"
            return r

        db_path = tmp_path / "db"
        with patch('core.sandbox.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "javascript", bs,
                                       traced_build=True)

        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_script_cleaned_up_on_timeout(self, db_manager, tmp_path):
        bs = BuildSystem(type="npm", command="npm install", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        db_path = tmp_path / "db"
        with patch('core.sandbox.run', side_effect=sp.TimeoutExpired("cmd", 60)), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "javascript", bs,
                                       traced_build=True)

        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_empty_command_no_script(self, db_manager, tmp_path):
        bs = BuildSystem(type="no-build", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        captured_cmd = []

        def fake_run(cmd, **kwargs):
            nonlocal captured_cmd
            captured_cmd = list(cmd)
            r = MagicMock()
            r.returncode = 0
            return r

        db_path = tmp_path / "db"
        with patch('core.sandbox.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "python", bs)

        assert "--command" not in captured_cmd
        assert not list(tmp_path.glob(".raptor_codeql_build_*"))


# ---------------------------------------------------------------------------
# Concurrent-write safety: build-in-staging + atomic-promote
# ---------------------------------------------------------------------------


class TestBuildEnvFilter:
    """A build system that declares env_vars reaches the blocklist
    filter — the branch every empty-env fixture skips. Pre-fix the
    frozenset + list concat raised TypeError there, crashing every
    traced ``database create`` whose build system carried env_vars
    (maven/gradle/ant/npm/go all do)."""

    def test_env_vars_declared_does_not_crash_create(self, db_manager,
                                                     tmp_path):
        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stdout = "2.16.0\n"
            r.stderr = "Finalizing database.\n"
            return r

        bs = BuildSystem(type="npm", command="npm run build",
                         working_dir=tmp_path,
                         env_vars={"LD_PRELOAD": "/tmp/evil.so",
                                   "NODE_OPTIONS": "--max-old-space-size=1"},
                         confidence=1.0, detected_files=[])
        with patch('core.sandbox.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files',
                          return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database',
                          return_value=None), \
             patch.object(db_manager, 'compute_repo_hash',
                          return_value='abc'), \
             patch.object(db_manager, 'get_database_dir',
                          return_value=tmp_path / "db"):
            result = db_manager.create_database(tmp_path, "javascript", bs,
                                                traced_build=True)
        assert result is not None
        assert not any("TypeError" in e for e in (result.errors or []))

    def test_create_path_actually_filters_declared_env(self, db_manager,
                                                       tmp_path):
        """Call-site consumption pin: the spawned build env must show
        the FILTER'S effect, not just the helper's. Dropping the
        _filter_build_env_vars call (env.update(build_system.env_vars)
        raw) puts the hostile members below into the captured env;
        dropping the update entirely loses the benign knob — either
        mutation fails here."""
        captured = {}

        def fake_run(cmd, **kwargs):
            if "database" in cmd and "create" in cmd:
                captured["env"] = dict(kwargs.get("env") or {})
            r = MagicMock()
            r.returncode = 0
            r.stdout = "2.16.0\n"
            r.stderr = "Finalizing database.\n"
            return r

        bs = BuildSystem(type="npm", command="npm run build",
                         working_dir=tmp_path,
                         env_vars={"LD_PRELOAD": "/tmp/evil.so",
                                   "GIT_ASKPASS": "./steal-creds.sh",
                                   "GOFLAGS": "-toolexec=./evil",
                                   "CGO_ENABLED": "0"},
                         confidence=1.0, detected_files=[])
        with patch('core.sandbox.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files',
                          return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database',
                          return_value=None), \
             patch.object(db_manager, 'compute_repo_hash',
                          return_value='abc'), \
             patch.object(db_manager, 'get_database_dir',
                          return_value=tmp_path / "db"):
            db_manager.create_database(tmp_path, "javascript", bs,
                                       traced_build=True)

        env = captured["env"]
        # Refused members never override the safe baseline: LD_PRELOAD
        # and GOFLAGS are absent from get_safe_env's output entirely;
        # GIT_ASKPASS stays at its inert pin, never the repo's script.
        assert env.get("LD_PRELOAD") != "/tmp/evil.so"
        assert "LD_PRELOAD" not in env
        assert env.get("GOFLAGS") != "-toolexec=./evil"
        assert env.get("GIT_ASKPASS") != "./steal-creds.sh"
        # ...while the benign declared knob flows through the filter.
        assert env.get("CGO_ENABLED") == "0"


class TestFilterBuildEnvVars:
    """Direct tests for the hostile-input gate on repo-declared build
    env vars (attacker-authored metadata layered over get_safe_env —
    an admitted name OVERRIDES the baseline, including GIT_ENV_VARS
    pins)."""

    def _filter(self, env_vars):
        from packages.codeql.database_manager import _filter_build_env_vars
        return _filter_build_env_vars(env_vars)

    def test_refuses_credential_family(self):
        admitted = self._filter({
            "AWS_CONFIG_FILE": ".cfg",       # credential_process exec
            "GIT_ASKPASS": "./steal.sh",     # would override the pin
            "GOOGLE_APPLICATION_CREDENTIALS": ".sa.json",
            "CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-ATTACKER",
            "KUBECONFIG": ".kube-evil",
            "RUSTC_WRAPPER": "./evil-rustc",
        })
        assert admitted == {}

    def test_refuses_ecosystem_surface_members(self):
        """Build metadata is repo-authored: the per-ecosystem exec/
        config-redirect members must never override the safe
        baseline (one representative per surface; the vocabulary
        unit tests pin every member)."""
        admitted = self._filter({
            "NPM_CONFIG_GLOBALCONFIG": ".npmrc-global",
            "NPM_CONFIG_SCRIPT_SHELL": "./evil-shell",
            "CARGO_BUILD_RUSTC": "./evil-rustc",
            "RUSTFLAGS": "-C linker=./evil-linker",
            "GOENV": ".go-env",
            "GOFLAGS": "-toolexec=./evil",
            "COMPOSER_HOME": ".composer",
            "MAVEN_ARGS": "-s ./evil-settings.xml",
            "ANT_OPTS": "-javaagent:./evil.jar",
            "DOTNET_STARTUP_HOOKS": "./evil.dll",
            "NUGET_PLUGIN_PATHS": "./evil-plugin",
            "MSBuildSDKsPath": "./evil-sdks",
            "msbuildsdkspath": "./evil-sdks",  # case-folded membership
            "OBJC": "./evil-objc",
            "M2FLAGS": "-x ./evil-dir",
            "BUNDLE_APP_CONFIG": ".bundle",
            "CMAKE_TOOLCHAIN_FILE": "./evil.cmake",
            "CC": "./evil-cc",
            # Pattern members ride the redirect shape rule.
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "./evil",
            "BUNDLE_BUILD__NOKOGIRI": "--with-cflags=-fplugin=./e.so",
            # make dot-named recipe variables: env origin beats the
            # default database, so each value REPLACES the whole
            # recipe of the matching built-in rule — a stronger
            # primitive than CC, which the gate already refused while
            # admitting these.
            "COMPILE.c": "echo pwned #",
            "LINK.o": "echo pwned #",
            "LEX.l": "echo pwned #",
            # make's env-consumed option carriers: GNUMAKEFLAGS is
            # appended to MAKEFLAGS before parsing, so it carries the
            # exact primitives above through an otherwise-unfiltered
            # wrapper — `--eval=$(shell …)` execs at parse time (even
            # under -n), and a `CC=`/`COMPILE.c=` word resurrects the
            # program/recipe overrides. MFLAGS is the historical
            # spelling of the option word.
            "GNUMAKEFLAGS": "--eval=$(shell touch /tmp/pwned)",
            "gnumakeflags": "CC=./evil-cc",  # case-folded membership
            "MFLAGS": "COMPILE.c=./evil-cc",
        })
        assert admitted == {}

    def test_admits_detector_benign_knobs(self):
        # The detector's own benign build knobs keep flowing (the
        # refusal above must not widen into these).
        admitted = self._filter({
            "CGO_ENABLED": "0",
            "NODE_ENV": "development",
        })
        assert admitted == {
            "CGO_ENABLED": "0",
            "NODE_ENV": "development",
        }

    def test_refuses_credential_shaped_names(self):
        admitted = self._filter({
            "MYTOOL_API_TOKEN": "attacker",
            "BUILD_SIGNING_KEY": "attacker",
            "VENDOR_CONFIG_FILE": "evil.conf",
        })
        assert admitted == {}

    def test_refuses_dangerous_and_raptor_names(self):
        admitted = self._filter({
            "LD_PRELOAD": "/tmp/evil.so",
            "BASH_ENV": "/tmp/evil.sh",
            "HTTPS_PROXY": "http://attacker:3128",
            "RAPTOR_OUT_DIR": "/tmp/steer",
            "_RAPTOR_TRUSTED": "1",
        })
        assert admitted == {}

    def test_refuses_lowercase_aliases_case_folded(self):
        """The gate compares case-folded: npm honours the lowercase
        canonical npm_config_userconfig, and lowercase proxy vars are
        honoured by most tooling — an exact-case check would admit
        the working alias of a blocked name."""
        admitted = self._filter({
            "npm_config_userconfig": ".npmrc-evil",
            "https_proxy": "http://attacker:3128",
            "raptor_out_dir": "/tmp/steer",
            "kubeconfig": ".kube-evil",
        })
        assert admitted == {}

    def test_admits_benign_build_vars(self):
        # CFLAGS and GOFLAGS are NOT in this set: both are flags-
        # injection members of the ecosystem env family (GOFLAGS can
        # carry -toolexec=<cmd>, CFLAGS -fplugin=<so>), and repo build
        # metadata is attacker-authored — the gate fails closed on
        # them even though most repos use them benignly. The cost is
        # a default-flags build; the alternative is exec on the
        # traced-build lane.
        env_vars = {
            "NODE_ENV": "production",
            # JAVA_HOME admission is sound HERE because the traced
            # build runs inside the sandbox (repo-code exec is already
            # assumed on that lane, and env_detect injects toolchain
            # homes deliberately). The settings-scan lane blocks the
            # same name via TOOLCHAIN_HOME_ENV_VARS — a future
            # consumer of this filter OUTSIDE the sandbox must not
            # inherit this admission silently.
            "JAVA_HOME": "/usr/lib/jvm/java-17",
            # Case-folding must not widen the refusal into benign
            # lookalike build knobs (CFLAGS_EXTRA is not CFLAGS).
            "cflags_extra": "-fno-omit-frame-pointer",
        }
        assert self._filter(env_vars) == env_vars

    def test_refuses_flag_injection_spellings(self):
        # The flags-injection members, in the exact spellings the
        # admit-direction pin above used to carry.
        assert self._filter({
            "CFLAGS": "-O2",
            "GOFLAGS": "-mod=vendor",
        }) == {}


class TestStagingPromote:
    """create_database builds in staging, atomic-promotes to canonical;
    concurrent writers don't corrupt; readers never see partial state."""

    def test_staging_path_is_same_parent_as_canonical(self, db_manager, tmp_path):
        # Same-fs requirement for atomic rename — staging and canonical
        # must share a parent directory.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            staging = db_manager._staging_path("abc", "python")
        assert staging.parent == canonical.parent

    def test_staging_path_includes_pid(self, db_manager, tmp_path):
        # Per-process staging means concurrent writers don't collide on
        # the staging dir itself.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            staging = db_manager._staging_path("abc", "python")
        assert f"-{os.getpid()}" in staging.name
        assert staging.name.startswith(".staging-")

    def test_successful_build_renames_staging_to_canonical(self, db_manager, tmp_path):
        # On success, staging dir disappears (was renamed) and canonical
        # exists with the build's content.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            # Simulate codeql writing the DB to the staging path it was
            # given on the command line. cmd[3] is the staging path
            # (codeql, database, create, <staging>, ...).
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "db-info.json").write_text("{}")
            r = MagicMock()
            r.returncode = 0
            r.stdout = "2.16.0"
            r.stderr = ""
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=1), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        assert result.success is True
        assert canonical.exists(), "canonical should exist after promote"
        assert (canonical / "db-info.json").exists(), "canonical content present"
        # No staging dirs left behind (the rename ate ours; no orphans).
        assert not list(canonical.parent.glob(".staging-*"))

    def test_lost_promotion_race_uses_winner_canonical(self, db_manager, tmp_path):
        # Simulate: another writer populated canonical between our cache-miss
        # check and our promote attempt. We should cleanup our staging and
        # return the winner's canonical path.
        # Canonical must pass validate_database for the lost-race branch
        # to accept it: batch 399 requires not just `codeql-database.yml`
        # but also a `db-<lang>/` subdir holding > 100KB of trie content
        # (real CodeQL DB shape). The fixture mimics that shape so the
        # test exercises the "winner is valid → use their canonical"
        # path rather than the "winner looks broken → evict + retry"
        # path which has its own dedicated tests.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        # Pre-populate canonical (simulating sibling who finished first)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: python\n")
        (canonical / "winner-marker").write_text("winner")
        winner_db = canonical / "db-python"
        winner_db.mkdir()
        # > 100KB to clear validate_database's minimum-substance check.
        (winner_db / "trie.bin").write_bytes(b"w" * 150_000)

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "loser-marker").write_text("loser")
            r = MagicMock()
            r.returncode = 0
            r.stdout = "2.16.0"
            r.stderr = ""
            return r

        # Patch _evict_stale_canonical to no-op so the test stays focused on
        # the lost-race-with-valid-canonical scenario rather than the
        # pre-build eviction logic (which has its own dedicated tests).
        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=1), \
             patch.object(db_manager, 'save_metadata') as save_meta_mock, \
             patch.object(db_manager, '_evict_stale_canonical'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        assert result.success is True
        assert result.database_path == canonical
        # Winner's content survived (loser's didn't overwrite)
        assert (canonical / "winner-marker").exists()
        assert not (canonical / "loser-marker").exists()
        # Loser's staging dir is gone (cleanup)
        assert not list(canonical.parent.glob(".staging-*"))
        # used_cached=True correctly reflects that we're using sibling's cache
        assert result.cached is True
        # Loser must NOT overwrite winner's metadata (winner already saved
        # consistent metadata; saving again would just be churn)
        save_meta_mock.assert_not_called()

    def test_lost_promotion_race_with_invalid_canonical_evicts_and_promotes_ours(
            self, db_manager, tmp_path):
        """Sibling promoted broken content (e.g., missing codeql-database.yml)
        between our cache check and our promote attempt. We must:
        (a) validate canonical before trusting it — without this check,
            a sibling who promoted broken content would propagate to us
            as success=True pointing at garbage,
        (b) evict the broken canonical and retry-promote our valid
            staging into the now-empty slot — without retry, the next
            run would redundantly rebuild because the cache slot stays
            empty.

        We patch _evict_stale_canonical to no-op so this test focuses on
        the post-build lost-race branch. The pre-build eviction logic
        has its own dedicated tests in TestEvictStaleCanonicalGracePeriod.
        """
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        # Pre-populate canonical with INVALID content (no codeql-database.yml).
        canonical.mkdir()
        (canonical / "marker").write_text("broken sibling promote")

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "codeql-database.yml").write_text("language: python\n")
            (staging_arg / "valid-content").write_text("our build")
            r = MagicMock()
            r.returncode = 0
            r.stdout = "2.16.0"
            r.stderr = ""
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=2), \
             patch.object(db_manager, 'save_metadata') as save_meta_mock, \
             patch.object(db_manager, '_evict_stale_canonical'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        # We succeeded (didn't propagate sibling's broken canonical as success)
        assert result.success is True
        assert result.cached is False  # we used our own build, not cache
        # Result points at canonical because we retry-promoted our valid
        # staging into the empty slot (after evicting broken sibling copy).
        # Pre-R2 behaviour was final_path=staging; R2 now retries the
        # promote so future runs hit cache instead of redundantly rebuilding.
        assert result.database_path == canonical, \
            f"expected canonical (promoted via retry), got: {result.database_path}"
        assert (canonical / "codeql-database.yml").exists()
        assert (canonical / "valid-content").exists()
        # Broken canonical was evicted (renamed to .stale.*) — exactly one
        # marker since this is a single eviction.
        stale_markers = list(canonical.parent.glob("*.stale.*"))
        assert len(stale_markers) == 1, \
            f"expected 1 stale marker from eviction, got: {len(stale_markers)}"
        # We DID save metadata because we retry-promoted (did_promote=True)
        save_meta_mock.assert_called_once()
        # Our staging dir is gone — got renamed to canonical
        assert not list(canonical.parent.glob(".staging-*"))

    def test_build_failure_cleans_up_staging(self, db_manager, tmp_path):
        # Failed builds must not leave staging dirs lying around (would
        # confuse cache lookups and pollute the cache dir).
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)

        bs = BuildSystem(type="pip", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "partial").write_text("garbage")
            r = MagicMock()
            r.returncode = 1
            r.stdout = ""
            r.stderr = "build failed"
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", bs)

        assert result.success is False
        assert not canonical.exists(), "failed build must not promote"
        # Failure preserves ONE inspectable dir under a GC-reaped
        # name; live (per-pid) staging dirs must all be gone.
        leftovers = list(canonical.parent.glob(".staging-*"))
        assert leftovers == [canonical.parent / ".staging-failed-python"], (
            f"staging cleanup: {leftovers}"
        )


class TestStaleMarkerGC:
    """_gc_stale_markers reaps abandoned .staging-*/.stale.* dirs after TTL."""

    def test_gc_removes_old_staging_dirs(self, db_manager, tmp_path):
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        old = repo_dir / ".staging-python-99999"
        old.mkdir()
        # Make it look 2 hours old (well past 1-hour TTL)
        old_mtime = time.time() - 7200
        os.utime(old, (old_mtime, old_mtime))

        db_manager._gc_stale_markers(repo_dir)

        assert not old.exists()

    def test_gc_preserves_recent_staging(self, db_manager, tmp_path):
        # Active concurrent writer's staging dir is fresh; must not be GC'd
        # while the writer might still need it.
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        recent = repo_dir / ".staging-python-12345"
        recent.mkdir()  # mtime = now

        db_manager._gc_stale_markers(repo_dir)

        assert recent.exists()

    def test_gc_removes_old_stale_markers(self, db_manager, tmp_path):
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        # Evicted-stale marker name pattern from _evict_stale_canonical
        old_stale = repo_dir / "python-db.stale.1234567890.99999"
        old_stale.mkdir()
        old_mtime = time.time() - 7200
        os.utime(old_stale, (old_mtime, old_mtime))

        db_manager._gc_stale_markers(repo_dir)

        assert not old_stale.exists()

    def test_gc_leaves_unrelated_files(self, db_manager, tmp_path):
        # Real DBs and metadata files in the cache dir must not be touched.
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        real_db = repo_dir / "python-db"
        real_db.mkdir()
        real_meta = repo_dir / "python-metadata.json"
        real_meta.write_text("{}")

        db_manager._gc_stale_markers(repo_dir)

        assert real_db.exists()
        assert real_meta.exists()


class TestStaleMarkerName:
    """`_stale_marker_name` must produce nanosecond-unique names so two
    same-second evictions from the same process don't collide on the
    rename target (which would silently leave the canonical in place)."""

    def test_marker_includes_nanosecond_timestamp(self, db_manager, tmp_path):
        canonical = tmp_path / "python-db"
        marker = db_manager._stale_marker_name(canonical)
        # Format: <name>.stale.<time_ns>.<pid>
        # Nanosecond timestamps are 19 digits as of 2026 (approx).
        parts = marker.split(".stale.")
        assert parts[0] == "python-db"
        ts_pid = parts[1].split(".")
        assert len(ts_pid) == 2
        ts, pid = ts_pid
        assert ts.isdigit() and len(ts) >= 18, \
            f"expected ns-precision timestamp, got {ts!r}"
        assert pid.startswith("") and pid.isdigit()

    def test_two_calls_in_same_second_produce_distinct_names(
            self, db_manager, tmp_path):
        # The whole point of using time_ns: two calls in quick succession
        # (likely same second) get distinct names so consecutive evictions
        # don't collide on the rename target.
        canonical = tmp_path / "python-db"
        a = db_manager._stale_marker_name(canonical)
        b = db_manager._stale_marker_name(canonical)
        assert a != b, f"same-second marker collision: {a} == {b}"


class TestEvictStaleCanonicalGracePeriod:
    """Regression for the R1 race: in-flight writers (just promoted
    canonical, haven't called save_metadata yet) must NOT have their
    canonical evicted by a sibling. Before the grace period was added,
    _evict_stale_canonical aggressively evicted any canonical with no
    metadata — racing the writer's hundreds-of-ms post-promote/pre-save
    window."""

    def test_fresh_canonical_with_no_metadata_is_not_evicted(
            self, db_manager, tmp_path):
        # Simulate: writer just renamed staging→canonical but hasn't
        # called save_metadata yet. canonical's mtime is fresh.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: python\n")
        # NOTE: deliberately no <lang>-metadata.json file — simulating
        # the gap between os.rename and save_metadata.

        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            db_manager._evict_stale_canonical("abc", "python", max_age_days=7)

        # Fresh canonical without metadata must NOT be evicted (grace
        # period protects in-flight writers).
        assert canonical.exists(), \
            "in-flight writer's fresh canonical was wrongly evicted"
        assert not list(canonical.parent.glob("*.stale.*")), \
            "no stale markers should be created"

    def test_old_canonical_with_no_metadata_IS_evicted(
            self, db_manager, tmp_path):
        # Simulate: previous writer crashed between rename and
        # save_metadata, leaving canonical orphaned. It's been there
        # for longer than the grace period — must be evicted so the
        # next run can rebuild and save consistent metadata.
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: python\n")
        # Backdate canonical's mtime well past the grace period.
        from core.config import RaptorConfig
        old_mtime = time.time() - (RaptorConfig.CODEQL_DB_MISSING_METADATA_GRACE + 60)
        os.utime(canonical, (old_mtime, old_mtime))

        with patch.object(db_manager, 'get_database_dir', return_value=canonical):
            db_manager._evict_stale_canonical("abc", "python", max_age_days=7)

        # Orphan must be evicted to break the rebuild loop.
        assert not canonical.exists(), \
            "orphaned canonical past grace period should be evicted"
        assert len(list(canonical.parent.glob("*.stale.*"))) == 1, \
            "exactly one stale marker should be created from eviction"


class TestEvictedMarkerMtimeGrace:
    """The GC's documented 1-hour reader grace must actually hold for
    stale-evicted canonicals: os.rename preserves the evicted DB's
    own (stale-by-definition) mtime, so pre-fix the marker was
    GC-eligible the moment it was created — the very next sibling
    run's cache-miss GC could rmtree it out from under an active
    reader."""

    def _aged_canonical(self, tmp_path, age_seconds):
        canonical = tmp_path / "cache" / "abc" / "cpp-db"
        canonical.parent.mkdir(parents=True)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: cpp\n")
        old = time.time() - age_seconds
        os.utime(canonical, (old, old))
        return canonical

    def test_stale_eviction_marker_gets_fresh_mtime(
            self, db_manager, tmp_path):
        # Aged 8 days — evicted because stale (missing-metadata leg,
        # same rename site as the stale-by-age leg).
        canonical = self._aged_canonical(tmp_path, 8 * 24 * 3600)
        with patch.object(db_manager, 'get_database_dir',
                          return_value=canonical):
            db_manager._evict_stale_canonical("abc", "cpp", max_age_days=7)
        markers = list(canonical.parent.glob("*.stale.*"))
        assert len(markers) == 1
        age = time.time() - markers[0].stat().st_mtime
        assert age < 60, (
            f"marker inherited the evicted DB's mtime "
            f"(age {age / 3600:.1f}h) — the 1h reader grace is vacuous"
        )

    def test_freshly_evicted_marker_survives_immediate_gc(
            self, db_manager, tmp_path):
        canonical = self._aged_canonical(tmp_path, 8 * 24 * 3600)
        with patch.object(db_manager, 'get_database_dir',
                          return_value=canonical):
            db_manager._evict_stale_canonical("abc", "cpp", max_age_days=7)
        db_manager._gc_stale_markers(canonical.parent)
        assert list(canonical.parent.glob("*.stale.*")), (
            "freshly-evicted marker reaped by an immediate GC pass — "
            "an active reader's DB was deleted inside the grace window"
        )

    def test_force_eviction_marker_gets_fresh_mtime(
            self, db_manager, tmp_path):
        """The force=True eviction path shares the fix."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_text("x = 1\n")
        canonical = self._aged_canonical(tmp_path, 8 * 24 * 3600)

        def fake_run(cmd, **kwargs):
            staging = Path(cmd[3])
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "db-info.json").write_text("{}")
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch('core.sandbox.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files',
                          return_value=1), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'compute_repo_hash',
                          return_value='abc'), \
             patch.object(db_manager, 'get_database_dir',
                          return_value=canonical):
            db_manager.create_database(repo, "python", None, force=True)
        markers = list(canonical.parent.glob("*.stale.*"))
        assert markers, "force eviction should leave a stale marker"
        age = time.time() - markers[0].stat().st_mtime
        assert age < 60


class TestAutoCleanupWiring:
    """CODEQL_DB_AUTO_CLEANUP was dead config: nothing ever invoked
    cleanup_old_databases outside the manual --cleanup CLI flag, so the
    default db_root accumulated stale databases the read side (7-day
    staleness gate in get_cached_database) would never serve again."""

    @pytest.fixture
    def _fresh_flag(self):
        """Reset the once-per-process guard around each test."""
        old = DatabaseManager._auto_cleanup_done
        DatabaseManager._auto_cleanup_done = False
        yield
        DatabaseManager._auto_cleanup_done = old

    def _mgr(self, tmp_path, monkeypatch, *, auto, db_root=None):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_DIR", tmp_path / "dbs")
        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_AUTO_CLEANUP", auto)
        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_CACHE_DAYS", 7)
        with patch.object(DatabaseManager, "_detect_codeql_cli",
                          return_value="/usr/bin/codeql"), \
             patch.object(DatabaseManager, "cleanup_old_databases",
                          return_value=[]) as cleanup:
            DatabaseManager(db_root=db_root)
        return cleanup

    def test_default_root_triggers_cleanup(self, tmp_path, monkeypatch,
                                           _fresh_flag):
        cleanup = self._mgr(tmp_path, monkeypatch, auto=True)
        cleanup.assert_called_once_with(days=7)

    def test_flag_off_skips_cleanup(self, tmp_path, monkeypatch,
                                    _fresh_flag):
        cleanup = self._mgr(tmp_path, monkeypatch, auto=False)
        cleanup.assert_not_called()

    def test_custom_db_root_skips_cleanup(self, tmp_path, monkeypatch,
                                          _fresh_flag):
        custom = tmp_path / "custom"
        cleanup = self._mgr(tmp_path, monkeypatch, auto=True, db_root=custom)
        cleanup.assert_not_called()

    def test_runs_once_per_process(self, tmp_path, monkeypatch, _fresh_flag):
        first = self._mgr(tmp_path, monkeypatch, auto=True)
        second = self._mgr(tmp_path, monkeypatch, auto=True)
        first.assert_called_once()
        second.assert_not_called()

    def test_cleanup_failure_does_not_break_init(self, tmp_path, monkeypatch,
                                                 _fresh_flag):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_DIR", tmp_path / "dbs")
        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_AUTO_CLEANUP", True)
        with patch.object(DatabaseManager, "_detect_codeql_cli",
                          return_value="/usr/bin/codeql"), \
             patch.object(DatabaseManager, "cleanup_old_databases",
                          side_effect=OSError("disk went away")):
            mgr = DatabaseManager()
        assert mgr.codeql_cli == "/usr/bin/codeql"


class TestDetectCodeqlCli:
    """CODEQL_CLI env validation in ``_detect_codeql_cli``."""

    def _detect(self, db_manager, monkeypatch, env_value, which=None):
        if env_value is None:
            monkeypatch.delenv("CODEQL_CLI", raising=False)
        else:
            monkeypatch.setenv("CODEQL_CLI", env_value)
        with patch("packages.codeql.database_manager.shutil.which",
                   return_value=which):
            return db_manager._detect_codeql_cli()

    def test_executable_file_accepted(self, db_manager, tmp_path, monkeypatch):
        cli = tmp_path / "codeql"
        cli.write_text("#!/bin/sh\n")
        cli.chmod(0o755)
        assert self._detect(db_manager, monkeypatch, str(cli)) == str(cli)

    def test_directory_rejected_with_warning(
        self, db_manager, tmp_path, monkeypatch, caplog,
    ):
        """A directory carries the x bit, so the pre-fix X_OK-only
        check accepted CODEQL_CLI=/some/dir and later exploded at
        subprocess.run."""
        import logging
        with caplog.at_level(logging.WARNING):
            got = self._detect(db_manager, monkeypatch, str(tmp_path),
                               which="/opt/codeql/codeql")
        assert got == "/opt/codeql/codeql"
        assert any("CODEQL_CLI" in r.getMessage()
                   and "not an executable file" in r.getMessage()
                   for r in caplog.records)

    def test_non_executable_file_rejected_with_warning(
        self, db_manager, tmp_path, monkeypatch, caplog,
    ):
        import logging
        plain = tmp_path / "notes.txt"
        plain.write_text("not a binary")
        plain.chmod(0o644)
        with caplog.at_level(logging.WARNING):
            got = self._detect(db_manager, monkeypatch, str(plain), which=None)
        assert got is None
        assert any("CODEQL_CLI" in r.getMessage() for r in caplog.records)

    def test_unset_env_uses_path_lookup_silently(
        self, db_manager, monkeypatch, caplog,
    ):
        import logging
        with caplog.at_level(logging.WARNING):
            got = self._detect(db_manager, monkeypatch, None,
                               which="/usr/local/bin/codeql")
        assert got == "/usr/local/bin/codeql"
        assert not [r for r in caplog.records
                    if "CODEQL_CLI" in r.getMessage()]


class TestRepoHashDirtyTree:
    """compute_repo_hash must invalidate on uncommitted edits — HEAD
    alone kept serving the stale database for the whole cache TTL."""

    @staticmethod
    def _git(repo, *args):
        sp.run(
            ["git", "-c", "user.email=t@example.invalid",
             "-c", "user.name=t", *args],
            cwd=repo, check=True, capture_output=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null",
                 "GIT_CONFIG_SYSTEM": "/dev/null"},
        )

    def _git_repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_text("x = 1\n")
        self._git(repo, "init", "-q")
        self._git(repo, "add", ".")
        self._git(repo, "commit", "-q", "-m", "init")
        return repo

    def test_clean_tree_hash_is_stable(self, db_manager, tmp_path):
        repo = self._git_repo(tmp_path)
        h1 = db_manager.compute_repo_hash(repo)
        h2 = db_manager.compute_repo_hash(repo)
        assert h1 == h2

    def test_uncommitted_edit_changes_hash(self, db_manager, tmp_path):
        repo = self._git_repo(tmp_path)
        clean = db_manager.compute_repo_hash(repo)
        (repo / "a.py").write_text("x = 2\n")
        dirty = db_manager.compute_repo_hash(repo)
        assert clean != dirty

    def test_edit_to_already_dirty_file_changes_hash(
        self, db_manager, tmp_path,
    ):
        repo = self._git_repo(tmp_path)
        (repo / "a.py").write_text("x = 2\n")
        first = db_manager.compute_repo_hash(repo)
        (repo / "a.py").write_text("x = 3\n")
        # Deterministic mtime bump: a sleep-based "ensure mtime_ns
        # moves" fails on filesystems with 1s timestamp granularity.
        st = (repo / "a.py").stat()
        os.utime(repo / "a.py",
                 ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        second = db_manager.compute_repo_hash(repo)
        assert first != second

    def test_untracked_file_changes_hash(self, db_manager, tmp_path):
        repo = self._git_repo(tmp_path)
        clean = db_manager.compute_repo_hash(repo)
        (repo / "new.py").write_text("y = 1\n")
        assert db_manager.compute_repo_hash(repo) != clean

    def test_non_git_fallback_detects_size_preserving_edit(
        self, db_manager, tmp_path,
    ):
        repo = tmp_path / "plain"
        repo.mkdir()
        (repo / "a.py").write_text("x = 1\n")
        h1 = db_manager.compute_repo_hash(repo)
        (repo / "a.py").write_text("x = 2\n")  # same size, new content
        h2 = db_manager.compute_repo_hash(repo)
        assert h1 != h2


class TestKeptFallbackDbGC:
    """Promote-failure fallback DBs must survive the 1h staging GC.

    Pre-fix the fallback handed the caller a `.staging-*` path, and a
    sibling run's cache-miss GC could rmtree the in-use DB mid-analysis
    (analyses routinely run past the 1h TTL)."""

    def test_detach_renames_out_of_staging_namespace(
        self, db_manager, tmp_path,
    ):
        staging = tmp_path / ".staging-cpp-1234-abcd"
        staging.mkdir()
        (staging / "codeql-database.yml").write_text("x")

        kept = db_manager._detach_staging_from_gc(staging, "cpp")

        assert kept != staging
        assert kept.name.startswith(".kept-cpp-")
        assert kept.is_dir()
        assert not staging.exists()
        assert (kept / "codeql-database.yml").exists()

    def test_gc_spares_kept_dir_past_staging_ttl(self, db_manager, tmp_path):
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        kept = repo_dir / ".kept-cpp-1234-abcd"
        kept.mkdir()
        # 2 hours old: past the 1h staging TTL but within the 24h kept TTL.
        old_mtime = time.time() - 7200
        os.utime(kept, (old_mtime, old_mtime))

        db_manager._gc_stale_markers(repo_dir)

        assert kept.exists()

    def test_gc_reaps_kept_dir_past_24h(self, db_manager, tmp_path):
        # Two-direction: abandoned fallbacks must not accumulate forever.
        repo_dir = tmp_path / "cache" / "abc"
        repo_dir.mkdir(parents=True)
        kept = repo_dir / ".kept-cpp-1234-abcd"
        kept.mkdir()
        old_mtime = time.time() - 25 * 3600
        os.utime(kept, (old_mtime, old_mtime))

        db_manager._gc_stale_markers(repo_dir)

        assert not kept.exists()


class TestValidateDatabaseSizeFloor:
    """Size-floor trade-off (see validate_database): small-but-complete
    DBs must validate; empty/byte-sized aborted builds must not."""

    def _make_db(self, tmp_path, payload_bytes: int):
        db = tmp_path / "cpp-db"
        (db / "db-cpp").mkdir(parents=True)
        (db / "codeql-database.yml").write_text("primaryLanguage: cpp\n")
        (db / "db-cpp" / "data.trie").write_bytes(b"x" * payload_bytes)
        return db

    def test_small_but_complete_db_validates(self, db_manager, tmp_path):
        # ~20KB: a legitimately tiny one-file target DB. The previous
        # 100KB floor made this a permanent cache miss and drove
        # evict/rebuild churn in the lost-race branch.
        db = self._make_db(tmp_path, 20 * 1024)
        assert db_manager.validate_database(db) is True

    def test_aborted_build_still_rejected(self, db_manager, tmp_path):
        # Two-direction: yml + near-empty db-* dir is the aborted-build
        # signature and must keep failing validation.
        db = self._make_db(tmp_path, 512)
        assert db_manager.validate_database(db) is False


class TestCacheTtlKnob:
    """Every TTL consumer derives from CODEQL_DB_CACHE_DAYS — the read
    path must honour the same knob the auto-cleanup enforces."""

    def test_ttl_helper_reads_config(self, monkeypatch):
        from core.config import RaptorConfig
        from packages.codeql.database_manager import DatabaseManager

        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_CACHE_DAYS", 21,
                            raising=False)
        assert DatabaseManager._cache_ttl_days() == 21

    def _mgr_with_cached_db(self, tmp_path, monkeypatch, age_days):
        from datetime import datetime, timedelta, timezone

        from packages.codeql import database_manager as dm

        # Constructing without a detectable CodeQL CLI raises — stub
        # detection (same seam TestAutoCleanupWiring stubs) so the TTL
        # logic under test is exercised on hosts and CI images that
        # do not ship the CLI. The value is never invoked: the cached
        # DB, its metadata, and validation are all synthesized below.
        with patch.object(dm.DatabaseManager, "_detect_codeql_cli",
                          return_value="/usr/bin/codeql"):
            mgr = dm.DatabaseManager(db_root=tmp_path / "dbs")
        repo = tmp_path / "repo"
        repo.mkdir(exist_ok=True)
        (repo / "a.c").write_text("int x;\n")
        repo_hash = mgr.compute_repo_hash(repo)
        db_dir = mgr.get_database_dir(repo_hash, "cpp")
        db_dir.mkdir(parents=True, exist_ok=True)
        created = (datetime.now(timezone.utc)
                   - timedelta(days=age_days)).isoformat()
        meta = dm.DatabaseMetadata(
            repo_hash=repo_hash, repo_path=str(repo), language="cpp",
            created_at=created, codeql_version="v", build_command="",
            build_system="none", file_count=1, success=True,
            duration_seconds=0.1, errors=[],
            database_path=str(db_dir),
        )
        monkeypatch.setattr(mgr, "load_metadata", lambda *a, **k: meta)
        monkeypatch.setattr(
            mgr, "validate_database", lambda *a, **k: True)
        return mgr, repo

    def test_get_cached_database_honours_raised_knob(
            self, tmp_path, monkeypatch):
        """A DB older than the old hardcoded 7 days but inside the
        operator's raised TTL is served; past a lowered TTL it is
        not (both directions)."""
        from core.config import RaptorConfig

        mgr, repo = self._mgr_with_cached_db(
            tmp_path, monkeypatch, age_days=10)
        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_CACHE_DAYS", 30,
                            raising=False)
        assert mgr.get_cached_database(repo, "cpp") is not None
        monkeypatch.setattr(RaptorConfig, "CODEQL_DB_CACHE_DAYS", 3,
                            raising=False)
        assert mgr.get_cached_database(repo, "cpp") is None


class TestCleanupOrphanMetadata:
    """cleanup_old_databases must unlink metadata whose DB dir is
    already gone — pre-fix orphan *-metadata.json files were
    re-parsed by every future cleanup pass forever."""

    def _plant_old_metadata(self, db_manager, db_exists: bool):
        slot = db_manager.db_root / "abc"
        slot.mkdir(parents=True)
        db_path = slot / "python-db"
        if db_exists:
            db_path.mkdir()
        meta = slot / "python-metadata.json"
        meta.write_text(json.dumps({
            "created_at": "2020-01-01T00:00:00+00:00",
            "database_path": str(db_path),
        }))
        return meta, db_path

    def test_orphan_metadata_unlinked(self, db_manager, tmp_path):
        meta, _ = self._plant_old_metadata(db_manager, db_exists=False)
        db_manager.cleanup_old_databases(days=7)
        assert not meta.exists(), "orphan metadata must be unlinked"

    def test_orphan_metadata_kept_on_dry_run(self, db_manager, tmp_path):
        meta, _ = self._plant_old_metadata(db_manager, db_exists=False)
        db_manager.cleanup_old_databases(days=7, dry_run=True)
        assert meta.exists()

    def test_live_pair_still_deleted_together(self, db_manager, tmp_path):
        meta, db_path = self._plant_old_metadata(db_manager, db_exists=True)
        db_manager.cleanup_old_databases(days=7)
        assert not db_path.exists()
        assert not meta.exists()


class TestRepoHashComputedOnce:
    def test_create_database_computes_repo_hash_once(
            self, db_manager, tmp_path):
        """Each compute is a `git status --porcelain` + per-path
        stats; create_database used to recompute up to 4x."""
        calls = {"n": 0}

        def counting_hash(repo_path):
            calls["n"] += 1
            return "abc"

        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "db-info.json").write_text("{}")
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files',
                          return_value=1), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'compute_repo_hash',
                          side_effect=counting_hash), \
             patch.object(db_manager, 'get_database_dir',
                          return_value=canonical):
            result = db_manager.create_database(tmp_path, "python", None)
        assert result.success is True
        assert calls["n"] == 1, (
            f"compute_repo_hash ran {calls['n']}x in one create — "
            f"memoise it once at the top"
        )


class TestForceEvictionFailure:
    def test_failed_force_eviction_does_not_serve_the_forced_away_db(
            self, db_manager, tmp_path):
        """force=True whose eviction rename FAILS (canonical still
        present) must not hand the surviving old canonical back as
        cached=True via the lost-promote-race branch — the operator
        asked for fresh."""
        canonical = tmp_path / "cache" / "abc" / "python-db"
        canonical.parent.mkdir(parents=True)
        canonical.mkdir()
        (canonical / "codeql-database.yml").write_text("language: python\n")
        (canonical / "stale-marker").write_text("old")
        old_db = canonical / "db-python"
        old_db.mkdir()
        (old_db / "trie.bin").write_bytes(b"o" * 150_000)

        real_rename = os.rename
        state = {"evict_blocked": False}

        def flaky_rename(src, dst):
            # Fail ONLY the force-eviction rename (canonical -> .stale.*);
            # allow the promote-time eviction and the staging promote.
            if (str(src) == str(canonical) and ".stale." in str(dst)
                    and not state["evict_blocked"]):
                state["evict_blocked"] = True
                raise OSError("EACCES: eviction rename denied")
            return real_rename(src, dst)

        def fake_sandbox_run(cmd, **kwargs):
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "codeql-database.yml").write_text(
                "language: python\n",
            )
            fresh = staging_arg / "db-python"
            fresh.mkdir()
            (fresh / "trie.bin").write_bytes(b"n" * 150_000)
            (staging_arg / "fresh-marker").write_text("new")
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch('core.sandbox.run', side_effect=fake_sandbox_run), \
             patch.object(db_manager, '_count_database_files',
                          return_value=1), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'compute_repo_hash',
                          return_value='abc'), \
             patch.object(db_manager, 'get_database_dir',
                          return_value=canonical), \
             patch('packages.codeql.database_manager.os.rename',
                   side_effect=flaky_rename):
            result = db_manager.create_database(
                tmp_path, "python", None, force=True,
            )

        assert result.success is True
        assert result.cached is False, (
            "the DB the operator forced away was served back as cached"
        )
        final = Path(result.database_path)
        assert (final / "fresh-marker").exists(), (
            "final DB must be OUR fresh build, not the stale survivor"
        )
