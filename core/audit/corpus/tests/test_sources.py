"""Tests for the corpus source registry and clone bootstrap."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from core.audit.corpus.sources import (
    SOURCES_PATH,
    SourceEntry,
    SourceFetchError,
    clone_source,
    fetch_files,
    load_sources,
    looks_like_connectivity_error,
)

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="git not available",
)


@pytest.fixture()
def origin_repo(tmp_path):
    """A local git origin with one tagged commit."""
    origin = tmp_path / "origin"
    origin.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"}

    def git(*args):
        subprocess.run(
            ["git", "-C", str(origin), *args],
            check=True, capture_output=True, env=env,
        )

    subprocess.run(
        ["git", "init", "-q", str(origin)],
        check=True, capture_output=True, env=env,
    )
    (origin / "src").mkdir()
    (origin / "src" / "a.c").write_text("int f(void) { return 0; }\n")
    git("add", "-A")
    git("commit", "-q", "-m", "pinned")
    git("tag", "v1.0.0")
    sha = subprocess.run(
        ["git", "-C", str(origin), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, env=env,
    ).stdout.strip()
    return origin, sha


def _entry(origin, **overrides):
    defaults = {
        "repo_key": "test-repo",
        "url": f"file://{origin}",
        "mirror_urls": (),
        "ref_kind": "tag",
    }
    defaults.update(overrides)
    return SourceEntry(**defaults)


class TestLoadSources:
    def test_registry_parses(self, tmp_path):
        p = tmp_path / "sources.json"
        p.write_text(json.dumps({"repos": {
            "demo-repo": {
                "url": "https://example.org/demo/demo-repo.git",
                "mirror_urls": ["https://mirror.example.org/demo.git"],
                "ref_kind": "tag",
                "notes": "mirror carries the release tags",
            },
            "src-rooted-repo": {
                "url": "https://example.org/demo/src-rooted-repo.git",
                "symlinks": {"lib": "src/lib"},
            },
        }}))
        entries = load_sources(p)
        assert set(entries) == {"demo-repo", "src-rooted-repo"}
        demo = entries["demo-repo"]
        assert demo.url.startswith("https://")
        assert demo.mirror_urls == (
            "https://mirror.example.org/demo.git",
        )
        assert demo.ref_kind == "tag"
        assert entries["src-rooted-repo"].symlinks.get("lib") == "src/lib"

    def test_committed_registry_parses_when_present(self):
        if not SOURCES_PATH.is_file():
            pytest.skip("no local sources.json")
        entries = load_sources()
        for key, entry in entries.items():
            assert entry.url.startswith("https://"), key

    def test_malformed_registry_rejected(self, tmp_path):
        p = tmp_path / "sources.json"
        p.write_text(json.dumps({"repos": {"x": {"mirror_urls": []}}}))
        with pytest.raises(ValueError, match="needs a 'url'"):
            load_sources(p)

    def test_missing_repos_key_rejected(self, tmp_path):
        p = tmp_path / "sources.json"
        p.write_text("{}")
        with pytest.raises(ValueError, match="repos"):
            load_sources(p)


class TestCloneSource:
    def test_clone_at_tag(self, tmp_path, origin_repo):
        origin, _ = origin_repo
        dest = tmp_path / "fixtures" / "test-repo"
        result = clone_source(
            "test-repo", "v1.0.0", dest, entry=_entry(origin),
        )
        assert result == dest
        assert (dest / "src" / "a.c").is_file()

    def test_clone_at_sha(self, tmp_path, origin_repo):
        origin, sha = origin_repo
        dest = tmp_path / "fixtures" / "test-repo"
        clone_source("test-repo", sha, dest, entry=_entry(origin))
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        assert head == sha

    def test_mirror_fallback(self, tmp_path, origin_repo):
        origin, _ = origin_repo
        dest = tmp_path / "fixtures" / "test-repo"
        entry = _entry(
            origin,
            url=f"file://{tmp_path}/no-such-origin",
            mirror_urls=(f"file://{origin}",),
        )
        clone_source("test-repo", "v1.0.0", dest, entry=entry)
        assert (dest / "src" / "a.c").is_file()

    def test_all_urls_fail_raises_with_stderr(self, tmp_path):
        dest = tmp_path / "fixtures" / "test-repo"
        entry = _entry(
            tmp_path / "gone",
            url=f"file://{tmp_path}/gone",
            mirror_urls=(f"file://{tmp_path}/also-gone",),
        )
        with pytest.raises(SourceFetchError, match="also-gone"):
            clone_source("test-repo", "v1.0.0", dest, entry=entry)
        # no partial clone left behind
        assert not dest.exists()

    def test_symlinks_applied(self, tmp_path, origin_repo):
        origin, _ = origin_repo
        dest = tmp_path / "fixtures" / "test-repo"
        entry = _entry(origin, symlinks={"go": "src"})
        clone_source("test-repo", "v1.0.0", dest, entry=entry)
        assert (dest / "go" / "a.c").is_file()
        # idempotent on re-application
        clone_source(
            "test-repo", "v1.0.0", tmp_path / "fixtures" / "again",
            entry=entry,
        )

    def test_escaping_symlink_target_rejected(self, tmp_path, origin_repo):
        origin, _ = origin_repo
        dest = tmp_path / "fixtures" / "test-repo"
        entry = _entry(origin, symlinks={"go": "../outside"})
        with pytest.raises(ValueError, match="repo-relative"):
            clone_source("test-repo", "v1.0.0", dest, entry=entry)

    def test_unknown_repo_key(self, tmp_path):
        with pytest.raises(SourceFetchError, match="no sources.json entry"):
            clone_source("nope-repo", "v1", tmp_path / "d")


class TestRunGitEnv:
    """Fetch subprocesses must keep the operator's proxy route.

    ``get_safe_env()`` strips HTTP(S)_PROXY by default; a corpus
    ``--fetch`` on a mandatory-egress-proxy host then has no route to
    the upstream remote and every clone fails with a connect error.
    """

    def test_proxy_vars_preserved(self, monkeypatch):
        import core.audit.corpus.sources as sources_mod

        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
        captured = {}

        def fake_run(cmd, **kw):
            captured["env"] = kw["env"]
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(sources_mod.subprocess, "run", fake_run)
        sources_mod._run_git(["version"], timeout_s=5)
        assert captured["env"].get("HTTPS_PROXY") == (
            "http://proxy.invalid:3128"
        )


class TestFetchFiles:
    """Sparse per-file fetch: only the labelled files, at the pinned
    ref, into a repo@ref-keyed cache dir."""

    def test_fetches_only_requested_files(self, tmp_path, origin_repo):
        origin, _ = origin_repo
        (origin / "src" / "b.c").write_text("int g(void) { return 1; }\n")
        subprocess.run(
            ["git", "-C", str(origin), "add", "-A"],
            check=True, capture_output=True,
            env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        )
        # b.c is committed but NOT tagged v1.0.0 — the sparse fetch at
        # the tag must not see it even if it asked for it.
        dest = tmp_path / "cache" / "test-repo@v1.0.0"
        fetch_files(
            "test-repo", "v1.0.0", ["src/a.c"], dest,
            entry=_entry(origin),
        )
        assert (dest / "src" / "a.c").is_file()
        assert not (dest / "src" / "b.c").exists()

    def test_fetch_at_bare_sha(self, tmp_path, origin_repo):
        origin, sha = origin_repo
        dest = tmp_path / "cache" / f"test-repo@{sha}"
        fetch_files(
            "test-repo", sha, ["src/a.c"], dest, entry=_entry(origin),
        )
        assert (dest / "src" / "a.c").is_file()
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
            env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        ).stdout.strip()
        assert head == sha

    def test_reuse_widens_sparse_set(self, tmp_path, origin_repo):
        origin, _ = origin_repo
        (origin / "src" / "b.c").write_text("int g(void) { return 1; }\n")
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
               "HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
        subprocess.run(
            ["git", "-C", str(origin), "add", "-A"],
            check=True, capture_output=True, env=env,
        )
        subprocess.run(
            ["git", "-C", str(origin), "commit", "-q", "-m", "b"],
            check=True, capture_output=True, env=env,
        )
        subprocess.run(
            ["git", "-C", str(origin), "tag", "v2.0.0"],
            check=True, capture_output=True, env=env,
        )
        dest = tmp_path / "cache" / "test-repo@v2.0.0"
        fetch_files(
            "test-repo", "v2.0.0", ["src/a.c"], dest,
            entry=_entry(origin),
        )
        assert not (dest / "src" / "b.c").exists()
        fetch_files(
            "test-repo", "v2.0.0", ["src/a.c", "src/b.c"], dest,
            entry=_entry(origin),
        )
        assert (dest / "src" / "a.c").is_file()
        assert (dest / "src" / "b.c").is_file()

    def test_symlinks_applied(self, tmp_path, origin_repo):
        origin, _ = origin_repo
        dest = tmp_path / "cache" / "test-repo@v1.0.0"
        fetch_files(
            "test-repo", "v1.0.0", ["src/a.c"], dest,
            entry=_entry(origin, symlinks={"go": "src"}),
        )
        assert (dest / "go" / "a.c").is_file()

    def test_missing_ref_raises_non_connectivity(
        self, tmp_path, origin_repo,
    ):
        origin, _ = origin_repo
        dest = tmp_path / "cache" / "test-repo@v9.9.9"
        with pytest.raises(SourceFetchError) as exc:
            fetch_files(
                "test-repo", "v9.9.9", ["src/a.c"], dest,
                entry=_entry(origin),
            )
        assert exc.value.connectivity is False
        assert not dest.exists()


class TestConnectivityClassification:
    def test_network_route_failures_flagged(self):
        for stderr in (
            "fatal: unable to access 'https://x/': "
            "Could not resolve host: x",
            "fatal: unable to access 'https://x/': Failed to connect "
            "to proxy port 3128: Connection refused",
            "fatal: unable to access 'https://x/': Connection timed out",
        ):
            assert looks_like_connectivity_error(stderr) is True

    def test_missing_ref_not_flagged(self):
        for stderr in (
            "fatal: Remote branch v9.9.9 not found in upstream origin",
            "fatal: couldn't find remote ref v9.9.9",
            "fatal: remote error: upload-pack: not our ref deadbeef",
        ):
            assert looks_like_connectivity_error(stderr) is False


class TestFixturesGitIgnored:
    """The fixture clones are licensed third-party source and must
    never become committable.

    ``FIXTURES_DIR`` holds pinned clones of upstream repos, some
    under copyleft licences; if that path ever stopped being
    git-ignored, ``git add`` at the RAPTOR repo root could commit
    third-party licensed source into this repository.
    """

    def _check_ignore(self, repo_root, rel_path):
        return subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", "-q",
             "--", str(rel_path)],
            capture_output=True, text=True, timeout=30,
        )

    def test_fixtures_dir_is_git_ignored(self):
        from pathlib import Path

        from core.audit.corpus.run_corpus import FIXTURES_DIR

        assert not FIXTURES_DIR.is_absolute(), (
            "FIXTURES_DIR is expected to be repo-root-relative"
        )
        repo_root = Path(__file__).resolve().parents[4]
        probe = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse",
             "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=30,
        )
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            pytest.skip("RAPTOR source tree is not a git checkout")

        # Representative licensed file under a pinned clone.  On dev
        # trees where the fixtures dir is a symlink, git refuses deep
        # pathspecs ("beyond a symbolic link", rc=128) — fall back to
        # the directory itself, which covers everything beneath it.
        deep = FIXTURES_DIR / "demo-repo" / "COPYING"
        result = self._check_ignore(repo_root, deep)
        if result.returncode == 128:
            result = self._check_ignore(repo_root, FIXTURES_DIR)
        assert result.returncode == 0, (
            f"{FIXTURES_DIR} is not git-ignored at the repo root — "
            f"pinned fixture clones are licensed third-party source "
            f"and must never be committable"
        )
