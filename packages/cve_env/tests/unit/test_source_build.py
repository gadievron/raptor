"""Unit tests for the ported source_build tool.

Strategy: pure helpers tested directly; `SourceBuilder` tested with
subprocess.run / urllib.request.urlopen mocked, never hitting real git or
GitHub. Integration tests use tempfile scaffolds for Dockerfile /
build-config discovery.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from cve_env.tools import source_build as sb
from cve_env.tools.source_build import (
    SourceBuildConfig,
    SourceBuilder,
    SourceBuildResult,
    _is_commit_sha,
    _pick_deepen_steps,
    find_version_tag,
    normalize_github_url,
    source_build_payload,
)

# -- normalize_github_url --------------------------------------------------


def test_normalize_github_url_passthrough() -> None:
    assert (
        normalize_github_url("https://github.com/vulhub/vulhub")
        == "https://github.com/vulhub/vulhub"
    )


def test_normalize_github_url_strips_dot_git() -> None:
    assert (
        normalize_github_url("https://github.com/foo/bar.git")
        == "https://github.com/foo/bar"
    )


def test_normalize_github_url_git_protocol() -> None:
    assert (
        normalize_github_url("git://github.com/foo/bar.git")
        == "https://github.com/foo/bar"
    )


def test_normalize_github_url_git_plus_https() -> None:
    assert (
        normalize_github_url("git+https://github.com/foo/bar")
        == "https://github.com/foo/bar"
    )


def test_normalize_github_url_git_plus_ssh() -> None:
    assert (
        normalize_github_url("git+ssh://git@github.com/foo/bar.git")
        == "https://github.com/foo/bar"
    )


def test_normalize_github_url_scp_form() -> None:
    assert (
        normalize_github_url("git@github.com:foo/bar.git")
        == "https://github.com/foo/bar"
    )


def test_normalize_github_url_rejects_non_github() -> None:
    assert normalize_github_url("https://gitlab.com/foo/bar") is None
    assert normalize_github_url("https://bitbucket.org/foo/bar") is None


def test_normalize_github_url_rejects_empty() -> None:
    assert normalize_github_url(None) is None
    assert normalize_github_url("") is None


def test_normalize_github_url_rejects_malformed_github() -> None:
    # Missing owner/repo segment.
    assert normalize_github_url("https://github.com/") is None


def test_normalize_github_url_rejects_attacker_host_with_github_in_path() -> None:
    """An attacker-controlled host with `github.com/<owner>/<repo>` in
    the PATH must NOT normalize to a valid github URL. The previous
    implementation used an unanchored regex `_GITHUB_OWNER_REPO_RE.search(url)`
    that matched the path substring and returned `https://github.com/evil/repo`,
    which would cause cve-env to clone an attacker-chosen repo.
    Caught by raptor CodeQL `py/incomplete-url-substring-sanitization` (2026-05-02).
    """
    assert normalize_github_url("https://attacker.com/github.com/evil/repo") is None
    assert normalize_github_url("http://attacker.example/path/github.com/foo/bar") is None


def test_normalize_github_url_rejects_subdomain_lookalikes() -> None:
    """Hosts that contain `github.com` as a substring or are confusable
    with github.com must be rejected. urlparse + exact-netloc match
    closes these bypasses; the substring `"github.com" in url` filter
    accepted them."""
    assert normalize_github_url("https://gist.github.com/foo/bar") is None
    assert normalize_github_url("https://github.com.evil.com/foo/bar") is None
    assert normalize_github_url("https://github.io/foo/bar") is None
    assert normalize_github_url("https://raw.githubusercontent.com/foo/bar/main") is None


def test_normalize_github_url_rejects_userinfo_smuggling() -> None:
    """A URL with userinfo of `github.com` followed by an attacker host
    (`https://github.com@evil.com/foo/bar`) parses as netloc=`github.com@evil.com`,
    which the substring filter would have accepted but exact-host equality
    rejects."""
    assert normalize_github_url("https://github.com@evil.com/foo/bar") is None


def test_normalize_github_url_rejects_metachar_in_owner_repo() -> None:
    """Even though all subprocess calls in cve_env are list-form (no shell=True),
    defense in depth: owner/repo charset matches GitHub's actual identifier
    rules `[A-Za-z0-9._-]+` so future refactors that interpolate owner/repo
    into shell strings or log messages don't surface metachars."""
    assert normalize_github_url("https://github.com/foo;bar/baz") is None
    assert normalize_github_url("https://github.com/foo/bar$baz") is None
    assert normalize_github_url("https://github.com/foo bar/baz") is None
    assert normalize_github_url("https://github.com/foo/bar`baz") is None


# -- find_version_tag ------------------------------------------------------


def test_find_version_tag_exact_v_prefix() -> None:
    assert find_version_tag(["v1.2.3", "v1.2.4"], "1.2.3") == "v1.2.3"


def test_find_version_tag_exact_no_v_prefix() -> None:
    assert find_version_tag(["1.2.3"], "v1.2.3") == "1.2.3"


def test_find_version_tag_prefix_dot_separator() -> None:
    # version=1.5 should match tag 1.5.0
    assert find_version_tag(["1.5.0", "1.6.0"], "1.5") == "1.5.0"


def test_find_version_tag_prefix_dash_separator() -> None:
    assert find_version_tag(["1.5-final"], "1.5") == "1.5-final"


def test_find_version_tag_version_prefixes_tag() -> None:
    # version=1.5.0.1 and tag=1.5 -> tag is a proper prefix of version (stripped)
    assert find_version_tag(["1.5"], "1.5.0.1") == "1.5"


def test_find_version_tag_fuzzy_contains() -> None:
    assert find_version_tag(["some-1.5-tag"], "1.5") == "some-1.5-tag"


def test_find_version_tag_no_match() -> None:
    assert find_version_tag(["2.0.0", "3.0.0"], "1.0") is None


def test_find_version_tag_empty_tags() -> None:
    assert find_version_tag([], "1.5") is None


def test_find_version_tag_priority_order() -> None:
    # Exact wins over prefix; prefix wins over fuzzy.
    tags = ["1.5-fuzzy", "1.5.0", "1.5"]
    assert find_version_tag(tags, "1.5") == "1.5"  # exact
    assert find_version_tag(tags, "1.5.0") == "1.5.0"  # exact (over fuzzy)


# -- _pick_deepen_steps ----------------------------------------------------


def test_pick_deepen_steps_none_falls_back_to_fixed() -> None:
    # When API is unreachable, use the default cascade.
    steps = _pick_deepen_steps(None)
    assert 0 in steps  # Full-depth fetch is in the cascade somewhere.


def test_pick_deepen_steps_tiny_repo() -> None:
    # <5 MB → single full-depth fetch.
    assert _pick_deepen_steps(1_000) == (0,)


def test_pick_deepen_steps_medium_repo() -> None:
    assert _pick_deepen_steps(20_000) == (100, 0)


def test_pick_deepen_steps_large_repo() -> None:
    assert _pick_deepen_steps(100_000) == (500, 5000, 0)


# -- SourceBuildResult.ok --------------------------------------------------


def test_result_ok_true_when_dockerfile_path_and_tag(tmp_path: Path) -> None:
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine")
    r = SourceBuildResult(
        repo_dir=tmp_path,
        checked_out_tag="v1.0",
        dockerfile_path=df,
        dockerfile_text="FROM alpine",
        build_config=None,
    )
    assert r.ok is True


def test_result_ok_true_when_build_config_alone(tmp_path: Path) -> None:
    # No Dockerfile but has a build_config hint -> still OK
    # (agent will dockerfile_gen + docker_build).
    r = SourceBuildResult(
        repo_dir=tmp_path,
        checked_out_tag="v1.0",
        dockerfile_path=None,
        dockerfile_text=None,
        build_config="maven",
    )
    assert r.ok is True


def test_result_ok_false_when_no_tag() -> None:
    r = SourceBuildResult(
        repo_dir=Path("/tmp/x"),
        checked_out_tag=None,
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
    )
    assert r.ok is False


def test_result_ok_false_when_no_dockerfile_and_no_config(tmp_path: Path) -> None:
    r = SourceBuildResult(
        repo_dir=tmp_path,
        checked_out_tag="v1.0",
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
    )
    assert r.ok is False


# -- Dockerfile discovery (integration with tempfile) ---------------------


def _make_repo(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def test_find_dockerfile_at_root(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"Dockerfile": "FROM alpine"})
    builder = SourceBuilder()
    assert builder._find_dockerfile(repo) == repo / "Dockerfile"


def test_find_dockerfile_in_docker_subdir(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"docker/Dockerfile": "FROM alpine"})
    builder = SourceBuilder()
    assert builder._find_dockerfile(repo) == repo / "docker" / "Dockerfile"


def test_find_dockerfile_skips_test_paths(tmp_path: Path) -> None:
    # Root Dockerfile wins even if a test/ variant also exists.
    repo = _make_repo(
        tmp_path / "repo",
        {
            "Dockerfile": "FROM alpine",
            "test/Dockerfile": "FROM alpine",
        },
    )
    builder = SourceBuilder()
    assert builder._find_dockerfile(repo) == repo / "Dockerfile"


def test_find_dockerfile_rglob_when_no_common_location(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"nested/deep/Dockerfile": "FROM alpine"})
    builder = SourceBuilder()
    result = builder._find_dockerfile(repo)
    assert result is not None
    assert result.name == "Dockerfile"


def test_find_dockerfile_rglob_avoids_test_dir(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path / "repo",
        {
            "tests/Dockerfile": "FROM alpine",
            "examples/Dockerfile": "FROM alpine",
            "src/Dockerfile": "FROM alpine",
        },
    )
    builder = SourceBuilder()
    result = builder._find_dockerfile(repo)
    assert result is not None
    # Relative to the repo, it should pick src/ over tests/ or examples/.
    rel = str(result.relative_to(repo)).lower()
    assert "test" not in rel
    assert "example" not in rel


def test_find_dockerfile_none_when_absent(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"README.md": "no dockerfile here"})
    builder = SourceBuilder()
    assert builder._find_dockerfile(repo) is None


def test_find_build_config_pom_xml(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"pom.xml": "<project/>"})
    builder = SourceBuilder()
    assert builder._find_build_config(repo) == "maven"


def test_find_build_config_package_json(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"package.json": "{}"})
    builder = SourceBuilder()
    assert builder._find_build_config(repo) == "npm"


def test_find_build_config_go_mod(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"go.mod": "module foo"})
    builder = SourceBuilder()
    assert builder._find_build_config(repo) == "go"


def test_find_build_config_none_when_no_marker(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"README.md": ""})
    builder = SourceBuilder()
    assert builder._find_build_config(repo) is None


def test_read_dockerfile_caps_at_64kib(tmp_path: Path) -> None:
    huge = tmp_path / "Dockerfile"
    huge.write_text("X" * (128 * 1024))
    builder = SourceBuilder()
    text = builder._read_dockerfile(huge)
    assert text is not None
    assert len(text) == 64 * 1024


def test_read_dockerfile_none_when_path_none() -> None:
    builder = SourceBuilder()
    assert builder._read_dockerfile(None) is None


def test_find_devcontainer_image_jsonc_tolerant(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".devcontainer").mkdir(parents=True)
    (repo / ".devcontainer" / "devcontainer.json").write_text(
        '{\n'
        '  // line comment\n'
        '  /* block\n'
        '     comment */\n'
        '  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",\n'
        '  "trailing": 1,\n'  # trailing comma inside is stripped by the normalizer
        '}\n'
    )
    builder = SourceBuilder()
    assert (
        builder._find_devcontainer_image(repo)
        == "mcr.microsoft.com/devcontainers/base:ubuntu"
    )


def test_find_devcontainer_image_none_when_absent(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "repo", {"README.md": ""})
    builder = SourceBuilder()
    assert builder._find_devcontainer_image(repo) is None


# -- SourceBuilder.build() with subprocess mocks ---------------------------


def _fake_completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["git"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_build_rejects_non_github_url(tmp_path: Path) -> None:
    builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
    result = builder.build(
        source_url="https://gitlab.com/foo/bar", product="foo", version="1.0"
    )
    assert not result.ok
    assert result.error is not None
    assert "not a GitHub URL" in result.error


def test_payload_for_gitlab_url_includes_git_clone_hint() -> None:
    """Phase 15: source_build_payload returns next_step_hint pointing to
    `Bash + git clone` for GitLab/Bitbucket/Codeberg URLs."""
    payload = source_build_payload(
        source_url="https://gitlab.com/foo/bar", product="foo", version="1.0"
    )
    assert payload["ok"] is False
    assert payload["reason"] == "not_github_url"
    hint = payload.get("next_step_hint", "")
    assert "Bash" in hint
    assert "git clone" in hint
    assert "GitLab" in hint or "Bitbucket" in hint or "Codeberg" in hint


def test_payload_for_osdn_url_includes_curl_tar_hint() -> None:
    """Phase 15: source_build_payload returns next_step_hint pointing to
    `Bash + curl + tar` for OSDN/SourceForge release-tarball forges."""
    payload = source_build_payload(
        source_url="https://osdn.net/projects/xoonips/", product="xoonips", version="3.49"
    )
    assert payload["ok"] is False
    assert payload["reason"] == "not_github_url"
    hint = payload.get("next_step_hint", "")
    assert "curl" in hint
    assert "tar" in hint
    assert "OSDN" in hint or "SourceForge" in hint or "tarball" in hint


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", True),
        ("A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", True),  # case-insensitive
        ("1.2.3", False),
        ("v1.2.3", False),
        ("a1b2c3d", False),  # too short (7 chars)
        ("a1b2c3d4e5f60718293a4b5c6d7e8f901234567g", False),  # 'g' not hex
        ("", False),
        ("a1b2c3d4e5f60718293a4b5c6d7e8f90123456789", False),  # 41 chars
    ],
)
def test_is_commit_sha(version: str, expected: bool) -> None:  # noqa: FBT001
    assert _is_commit_sha(version) is expected


def test_build_with_commit_sha_clone_failure_returns_clean_error(tmp_path: Path) -> None:
    """Phase 11.2: when full-clone fails on a SHA path, error message is clean."""
    sha = "a" * 40

    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            return _fake_completed(128, stderr="fatal: Repository not found")
        msg = f"unexpected git args: {args}"
        raise AssertionError(msg)

    with patch("cve_env.utils.run.subprocess.run", side_effect=fake_run):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/foo/bar", product="bar", version=sha
        )
    assert not result.ok
    assert result.error is not None
    assert "no tag matched" in result.error  # Falls through to standard error path
    assert any("git clone failed" in w.lower() for w in result.warnings)


def test_build_with_commit_sha_checkout_failure(tmp_path: Path) -> None:
    """Phase 11.2: clone succeeds but checkout SHA fails (e.g., SHA not in repo)."""
    sha = "b" * 40

    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            target = Path(args[-1])
            target.mkdir(parents=True, exist_ok=True)
            return _fake_completed(0)
        if args[:2] == ["git", "checkout"]:
            return _fake_completed(128, stderr="fatal: reference is not a tree")
        msg = f"unexpected git args: {args}"
        raise AssertionError(msg)

    with patch("cve_env.utils.run.subprocess.run", side_effect=fake_run):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/foo/bar", product="bar", version=sha
        )
    assert not result.ok
    assert result.error is not None
    assert any("checkout" in w.lower() and "failed" in w.lower() for w in result.warnings)


def test_build_with_commit_sha_clone_timeout(tmp_path: Path) -> None:
    """Phase 11.2: clone subprocess timeout is reported in warnings."""
    sha = "c" * 40

    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            raise subprocess.TimeoutExpired(cmd="git clone", timeout=60)
        msg = f"unexpected git args after timeout: {args}"
        raise AssertionError(msg)

    with patch("cve_env.utils.run.subprocess.run", side_effect=fake_run):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/foo/bar", product="bar", version=sha
        )
    assert not result.ok
    assert any("timed out" in w.lower() for w in result.warnings)


def test_build_with_commit_sha_skips_tag_listing(tmp_path: Path) -> None:
    """Phase 11.2: a 40-hex SHA `version` triggers full-clone + checkout SHA.

    Asserts that ``git tag --list`` and ``git fetch --tags`` are NEVER
    called — the tag-matching path is bypassed entirely.
    """
    sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    seen_args: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen_args.append(args)
        if args[:2] == ["git", "clone"]:
            target = Path(args[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "package.json").write_text('{"name": "vuln-plugin"}')
            return _fake_completed(0)
        if args[:2] == ["git", "checkout"]:
            return _fake_completed(0)
        # If anything else fires (tag list, fetch --tags), the SHA path is broken.
        msg = f"unexpected git args during SHA path: {args}"
        raise AssertionError(msg)

    with patch("cve_env.utils.run.subprocess.run", side_effect=fake_run):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/wp-plugins/foo",
            product="foo",
            version=sha,
        )

    assert result.ok, result.error
    assert result.checked_out_tag == sha
    assert result.build_config == "npm"
    # Verify the checkout used the SHA verbatim.
    checkout_calls = [a for a in seen_args if a[:2] == ["git", "checkout"]]
    assert len(checkout_calls) == 1
    assert checkout_calls[0][2] == sha
    # Verify NO tag operations.
    assert not any(a[:3] == ["git", "tag", "--list"] for a in seen_args)
    assert not any("--tags" in a for a in seen_args)


def test_build_shallow_clone_succeeds_tag_matches(tmp_path: Path) -> None:
    """Happy path: shallow clone finds the tag on first try."""

    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            # Simulate `git clone` by creating the target dir + pom.xml +
            # Dockerfile so downstream discovery has something to find.
            target = Path(args[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "Dockerfile").write_text("FROM alpine")
            (target / "pom.xml").write_text("<project/>")
            return _fake_completed(0)
        if args[:3] == ["git", "fetch", "--tags"]:
            return _fake_completed(0)
        if args[:2] == ["git", "tag"]:
            return _fake_completed(0, stdout="v1.0\nv1.5\nv2.0\n")
        if args[:2] == ["git", "checkout"]:
            return _fake_completed(0)
        msg = f"unexpected git args: {args}"
        raise AssertionError(msg)

    with patch("cve_env.utils.run.subprocess.run", side_effect=fake_run):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/foo/bar",
            product="bar",
            version="1.5",
        )

    assert result.ok, result.error
    assert result.checked_out_tag == "v1.5"
    assert result.dockerfile_text == "FROM alpine"
    assert result.build_config == "maven"


def test_build_no_tag_matches_returns_error(tmp_path: Path) -> None:
    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            target = Path(args[-1])
            target.mkdir(parents=True, exist_ok=True)
            return _fake_completed(0)
        if args[:3] == ["git", "fetch", "--tags"]:
            return _fake_completed(0)
        if args[:3] == ["git", "tag", "--list"]:
            return _fake_completed(0, stdout="v3.0\nv4.0\n")
        if len(args) >= 2 and args[1] == "fetch":
            # Any deepen operation succeeds but still no matching tag.
            return _fake_completed(0)
        msg = f"unexpected: {args}"
        raise AssertionError(msg)

    with (
        patch("cve_env.utils.run.subprocess.run", side_effect=fake_run),
        # Disable archive fallback for this test to isolate the clone path.
        patch.object(
            SourceBuilder, "_archive_fallback", lambda *a, **k: None
        ),
        # Disable adaptive depth probe so we don't hit urllib.
        patch.object(SourceBuilder, "_deepen_steps", lambda *a, **k: (0,)),
    ):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/foo/bar",
            product="bar",
            version="1.5",
        )

    assert not result.ok
    assert result.error is not None
    assert "no tag matched" in result.error


def test_build_clone_failure_triggers_archive_fallback(tmp_path: Path) -> None:
    """When shallow clone fails, the codeload tarball rescue must fire."""
    call_log: list[str] = []

    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            call_log.append("clone_failed")
            return _fake_completed(128, stderr="rate limited")
        if args[:3] == ["gh", "auth", "token"]:
            return _fake_completed(1, stderr="not authenticated")
        msg = f"unexpected: {args}"
        raise AssertionError(msg)

    tarball = _make_fake_tarball({"Dockerfile": "FROM alpine", "go.mod": "module x"})

    def fake_urlopen(req: Any, **_: Any) -> Any:
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "api.github.com/repos/foo/bar/tags" in url:
            return _FakeResp(json.dumps([{"name": "v1.5"}]).encode())
        if urllib.parse.urlparse(url).hostname == "codeload.github.com":
            return _FakeResp(tarball)
        msg = f"unexpected url: {url}"
        raise AssertionError(msg)

    with (
        patch("cve_env.utils.run.subprocess.run", side_effect=fake_run),
        patch(
            "cve_env.tools.source_build._urlopen",
            side_effect=fake_urlopen,
        ),
    ):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/foo/bar",
            product="bar",
            version="1.5",
        )

    assert call_log == ["clone_failed"]
    assert result.ok, (result.error, result.warnings)
    assert result.checked_out_tag == "v1.5"
    assert result.dockerfile_text == "FROM alpine"
    assert result.build_config == "go"


# -- source_build_payload --------------------------------------------------


def test_payload_not_a_github_url() -> None:
    out = source_build_payload(
        source_url="https://example.com/foo/bar", product="foo", version="1"
    )
    assert out["ok"] is False
    assert out["reason"] == "not_github_url"


def test_payload_failure_path_repo_dir_is_none(tmp_path: Path) -> None:
    """B9 fix (2026-05-02): on not-ok results, source_build_payload calls
    builder.cleanup() which deletes the temp tree, but historically the
    response still echoed the now-deleted ``repo_dir`` path back to the
    agent. CVE-2020-15308 in bench50-20260502-180209 hit this: agent read
    repo_dir from the failed response, tried ``cd`` into it via Bash, got
    ENOENT. Failure responses must report ``repo_dir: None`` to match
    on-disk reality after cleanup."""
    fake_result = SourceBuildResult(
        repo_dir=tmp_path / "sitracker",  # would normally exist
        checked_out_tag=None,
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
        warnings=["no tag matched at current depth; deepening to 100"],
        error="no tag matched '3.67'",
    )
    with patch.object(SourceBuilder, "build", return_value=fake_result), \
         patch.object(SourceBuilder, "cleanup") as mock_cleanup:  # don't actually rmtree in test
        out = source_build_payload(
            source_url="https://github.com/sitracker/sitracker",
            product="sitracker",
            version="3.67",
        )
    assert out["ok"] is False
    assert out["reason"] == "no_tag_matched"
    # The fix: repo_dir must be None on failure (cleaned up; not safe to expose)
    assert out["repo_dir"] is None, (
        f"failure response echoed repo_dir={out['repo_dir']!r} but builder.cleanup() "
        "would have deleted it; the agent must not be told a stale path"
    )
    # B9 followup (persona review): the contract is "cleanup MUST run before
    # the failure response is returned". Without this assertion, a regression
    # that sets repo_dir=None but skips the cleanup() call would still pass —
    # the agent gets the right shape but a temp tree leaks on disk.
    mock_cleanup.assert_called_once()


def test_next_step_hint_cloned_no_dockerfile_points_to_clone(tmp_path: Path) -> None:
    """R2 (2026-05-23): when a tag matched + tree cloned but the repo has no
    Dockerfile/build-config, the hint must point the agent at dockerfile_gen
    against the clone — NOT the misleading 'no tag matched' (forensic
    CVE-2022-23383: v6.3 checked out, no Dockerfile, agent quit)."""
    from cve_env.tools.source_build import _next_step_hint

    r = SourceBuildResult(
        repo_dir=tmp_path / "repo",
        checked_out_tag="v6.3",
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
    )
    hint = _next_step_hint(r)
    assert "no tag matched" not in hint, "tag WAS matched; hint must not say otherwise"
    assert "dockerfile_gen" in hint
    assert "clone" in hint or "repo_dir" in hint
    # b1 interaction: must tell the agent to pass context_dir=repo_dir so the
    # fused auto-build targets the clone, not an empty temp context.
    assert "context_dir=repo_dir" in hint


def test_next_step_hint_genuine_no_tag_unchanged(tmp_path: Path) -> None:
    """R2 guard: a genuine no-tag (no checkout) keeps the existing hint."""
    from cve_env.tools.source_build import _next_step_hint

    r = SourceBuildResult(
        repo_dir=None,
        checked_out_tag=None,
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
    )
    assert "no tag matched" in _next_step_hint(r)


def test_payload_cloned_no_dockerfile_retains_repo_dir(tmp_path: Path) -> None:
    """R2: tag matched + tree cloned but no Dockerfile is RECOVERABLE — retain
    the clone + echo the live repo_dir so the agent can dockerfile_gen against
    it. Distinct from the genuine-no-tag failure (which still cleans up + nulls
    repo_dir per B9/CVE-2020-15308)."""
    repo = tmp_path / "yzmcms"
    repo.mkdir()
    fake_result = SourceBuildResult(
        repo_dir=repo,
        checked_out_tag="v6.3",
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
    )
    with patch.object(SourceBuilder, "build", return_value=fake_result), \
         patch.object(SourceBuilder, "retain") as mock_retain, \
         patch.object(SourceBuilder, "cleanup") as mock_cleanup:
        out = source_build_payload(
            source_url="https://github.com/yzmcms/yzmcms",
            product="yzmcms",
            version="6.3",
        )
    assert out["ok"] is False
    assert out["repo_dir"] == str(repo), "live clone must be echoed for dockerfile_gen"
    assert out["checked_out_tag"] == "v6.3"
    assert "no tag matched" not in out["next_step_hint"]
    mock_retain.assert_called_once()
    mock_cleanup.assert_not_called()


def test_source_build_handler_fuses_docker_build_when_dockerfile_present(tmp_path: Path) -> None:
    """Fix (2026-05-24): the source_build HANDLER fuses docker_build when the
    payload is ok + has a Dockerfile + clone — closing the source_build→
    docker_build seam (sibling of b1's dockerfile_gen fuse). CVE-2022-1813 quit
    one-call-short here: source_build returned ok=true w/ a Dockerfile + repo_dir
    + 'call docker_build' hint, but the agent did image_resolve+Bash then end_turn
    without building. After the fix the build runs in the same call (under `build`)."""
    import asyncio
    import json
    from unittest.mock import MagicMock

    from cve_env.agent import tools

    repo = tmp_path / "rengine"
    repo.mkdir()
    fake_payload = {
        "ok": True,
        "repo_dir": str(repo),
        "checked_out_tag": "v1.1.0",
        "dockerfile_path": str(repo / "Dockerfile"),
        "dockerfile_text": "FROM debian@sha256:" + "a" * 64 + "\nRUN true\n",
        "build_config": None,
        "warnings": [],
        "next_step_hint": "call docker_build(context_dir=repo_dir, dockerfile_text=...)",
    }
    with patch("cve_env.tools.source_build.source_build_payload", return_value=fake_payload), \
         patch(
             "cve_env.utils.run.subprocess.run",
             return_value=MagicMock(returncode=0, stdout="Successfully built abc123\n", stderr=""),
         ):
        env = asyncio.run(
            tools.source_build.handler(
                {
                    "source_url": "https://github.com/yogeshojha/rengine",
                    "product": "rengine",
                    "version": "1.1.0",
                }
            )
        )
    out = json.loads(env["content"][0]["text"])
    assert "build" in out, "source_build with a Dockerfile must fuse docker_build (close the seam)"
    assert out["build"]["ok"] is True, f"fused build should succeed; got {out.get('build')!r}"


def test_source_build_handler_no_fuse_when_no_dockerfile(tmp_path: Path) -> None:
    """Guard: a build_config-only payload (no dockerfile_text) must NOT fuse —
    the agent dockerfile_gen's against the clone (then b1 fuses that)."""
    import asyncio
    import json
    from unittest.mock import MagicMock

    from cve_env.agent import tools

    repo = tmp_path / "app"
    repo.mkdir()
    fake_payload = {
        "ok": True,
        "repo_dir": str(repo),
        "checked_out_tag": "v1.0",
        "dockerfile_path": None,
        "dockerfile_text": None,
        "build_config": "maven",
        "warnings": [],
        "next_step_hint": "no Dockerfile in repo; call dockerfile_gen with build_config=...",
    }
    with (
        patch("cve_env.tools.source_build.source_build_payload", return_value=fake_payload),
        patch("cve_env.utils.run.subprocess.run", return_value=MagicMock(returncode=0)) as mock_run,
    ):
        env = asyncio.run(
            tools.source_build.handler(
                {"source_url": "https://github.com/o/r", "product": "r", "version": "1.0"}
            )
        )
    out = json.loads(env["content"][0]["text"])
    assert "build" not in out, "build_config-only payload must not auto-build (no Dockerfile)"
    mock_run.assert_not_called()


def test_payload_success_path_has_next_step_hint(tmp_path: Path) -> None:
    """Integration: mocked build() success path produces a complete payload."""

    fake_result = SourceBuildResult(
        repo_dir=tmp_path / "bar",
        checked_out_tag="v1.5",
        dockerfile_path=tmp_path / "bar" / "Dockerfile",
        dockerfile_text="FROM alpine",
        build_config="maven",
        warnings=["shallow worked"],
    )

    with patch.object(SourceBuilder, "build", return_value=fake_result):
        out = source_build_payload(
            source_url="https://github.com/foo/bar",
            product="bar",
            version="1.5",
        )
    assert out["ok"] is True
    assert out["checked_out_tag"] == "v1.5"
    assert out["dockerfile_text"] == "FROM alpine"
    assert "docker_build" in out["next_step_hint"]


def test_payload_no_dockerfile_points_at_dockerfile_gen(tmp_path: Path) -> None:
    fake_result = SourceBuildResult(
        repo_dir=tmp_path / "bar",
        checked_out_tag="v1.5",
        dockerfile_path=None,
        dockerfile_text=None,
        build_config="maven",
    )
    with patch.object(SourceBuilder, "build", return_value=fake_result):
        out = source_build_payload(
            source_url="https://github.com/foo/bar",
            product="bar",
            version="1.5",
        )
    assert out["ok"] is True
    assert out["dockerfile_text"] is None
    assert "dockerfile_gen" in out["next_step_hint"]
    assert "maven" in out["next_step_hint"]


def test_payload_catches_unexpected_exception(tmp_path: Path) -> None:
    with patch.object(SourceBuilder, "build", side_effect=RuntimeError("boom")):
        out = source_build_payload(
            source_url="https://github.com/foo/bar", product="bar", version="1.5"
        )
    assert out["ok"] is False
    assert out["reason"] == "unexpected_error"
    assert "boom" in out["error"]


def test_payload_unexpected_exception_explicit_repo_dir_none(tmp_path: Path) -> None:
    """B9 followup (2026-05-02 persona review): the unexpected_error branch
    at source_build_payload was missing repo_dir entirely, while the
    not-result.ok branch sets repo_dir=None explicitly. Asymmetric shape:
    consumers calling tr.get('repo_dir') get None either way, but a future
    refactor that switches to ``tr['repo_dir']`` (KeyError on missing) would
    break only on this branch. Make every failure response carry an
    explicit repo_dir field, even if always None on crash."""
    with patch.object(SourceBuilder, "build", side_effect=RuntimeError("boom")):
        out = source_build_payload(
            source_url="https://github.com/foo/bar", product="bar", version="1.5"
        )
    assert "repo_dir" in out, "every failure response must carry an explicit repo_dir key"
    assert out["repo_dir"] is None, "crash path: no clone exists; cannot offer a path"


# -- HTTP helpers / archive helpers ---------------------------------------


def _make_fake_tarball(files: dict[str, str]) -> bytes:
    """Build an in-memory tar.gz with a top-level dir like GitHub's codeload."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        top = tarfile.TarInfo(name="bar-1.5")
        top.type = tarfile.DIRTYPE
        tf.addfile(top)
        for rel, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"bar-1.5/{rel}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_malicious_tarball_with_symlink(symlink_target: str) -> bytes:
    """Build a tarball with a SYMTYPE member pointing at ``symlink_target``.

    Used by Phase 61.2 tests to confirm tarfile data-filter rejects
    symlinks pointing outside the extraction destination.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        top = tarfile.TarInfo(name="bar-1.5")
        top.type = tarfile.DIRTYPE
        tf.addfile(top)
        # A regular file so the extraction has at least one valid member.
        data = b"FROM alpine"
        f = tarfile.TarInfo(name="bar-1.5/Dockerfile")
        f.size = len(data)
        tf.addfile(f, io.BytesIO(data))
        # The malicious symlink: bar-1.5/escape -> <symlink_target>
        link = tarfile.TarInfo(name="bar-1.5/escape")
        link.type = tarfile.SYMTYPE
        link.linkname = symlink_target
        tf.addfile(link)
    return buf.getvalue()


# Phase 61.2 — tarball symlink/traversal guard ----------------------------


def test_phase61_tarball_filter_blocks_absolute_symlink(tmp_path: Path) -> None:
    """A tarball whose member is a symlink to /etc/passwd must not extract.

    Pre-fix: tf.extract was called without filter="data"; legacy behavior
    honors symlinks → attacker writes through symlink to host filesystem.
    Post-fix: filter="data" rejects symlinks pointing outside destination,
    raising tarfile.AbsoluteLinkError (a TarError subclass), which is
    caught and returns False — extraction is refused.
    """
    malicious = _make_malicious_tarball_with_symlink("/etc/passwd")

    def fake_run(args: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            return _fake_completed(128, stderr="rate limited")
        if args[:3] == ["gh", "auth", "token"]:
            return _fake_completed(1, stderr="not authenticated")
        msg = f"unexpected: {args}"
        raise AssertionError(msg)

    def fake_urlopen(req: Any, **_: Any) -> Any:
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "api.github.com/repos/foo/bar/tags" in url:
            return _FakeResp(json.dumps([{"name": "v1.5"}]).encode())
        if urllib.parse.urlparse(url).hostname == "codeload.github.com":
            return _FakeResp(malicious)
        msg = f"unexpected url: {url}"
        raise AssertionError(msg)

    with (
        patch("cve_env.utils.run.subprocess.run", side_effect=fake_run),
        patch(
            "cve_env.tools.source_build._urlopen",
            side_effect=fake_urlopen,
        ),
    ):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        result = builder.build(
            source_url="https://github.com/foo/bar",
            product="bar",
            version="1.5",
        )

    # Either: extraction was refused → build failed,
    # OR: the symlink was filtered but other members extracted → build may
    # succeed only if Dockerfile is present and symlink is absent. Either
    # way, the symlink must NOT exist on disk anywhere under tmp_path.
    for p in tmp_path.rglob("escape"):
        assert not p.is_symlink(), f"symlink leaked to disk at {p}"
    # Confirm the symlink was actually filtered (not silently extracted).
    if result.repo_dir is not None:
        assert not (result.repo_dir / "escape").exists()


def test_phase61_tarball_filter_blocks_relative_escape_symlink(
    tmp_path: Path,
) -> None:
    """A symlink with linkname='../../../etc/passwd' is also blocked."""
    malicious = _make_malicious_tarball_with_symlink("../../../etc/passwd")

    def fake_run(args: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["git", "clone"]:
            return _fake_completed(128, stderr="rate limited")
        if args[:3] == ["gh", "auth", "token"]:
            return _fake_completed(1, stderr="not authenticated")
        msg = f"unexpected: {args}"
        raise AssertionError(msg)

    def fake_urlopen(req: Any, **_: Any) -> Any:
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "api.github.com/repos/foo/bar/tags" in url:
            return _FakeResp(json.dumps([{"name": "v1.5"}]).encode())
        if urllib.parse.urlparse(url).hostname == "codeload.github.com":
            return _FakeResp(malicious)
        msg = f"unexpected url: {url}"
        raise AssertionError(msg)

    with (
        patch("cve_env.utils.run.subprocess.run", side_effect=fake_run),
        patch(
            "cve_env.tools.source_build._urlopen",
            side_effect=fake_urlopen,
        ),
    ):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        builder.build(
            source_url="https://github.com/foo/bar",
            product="bar",
            version="1.5",
        )

    for p in tmp_path.rglob("escape"):
        assert not p.is_symlink(), f"symlink leaked to disk at {p}"


class _FakeResp:
    """Tiny stand-in for urllib.request's context-manager response."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def __enter__(self) -> _FakeResp:  # noqa: PYI034 -- matches urllib shape
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def read(self, _size: int = -1) -> bytes:
        # Matches urllib's response.read(size=-1) shape. The fake bodies are
        # tiny (well under any cap), so the size hint is ignored.
        return self._body


# -- Security hardening: PT-1 product path-traversal + DOS-1 tarball caps ------


def test_build_rejects_dotdot_product() -> None:
    """``product`` is LLM tool input → a ``..`` value must be rejected, never
    used to name the on-disk checkout dir."""
    builder = SourceBuilder()
    result = builder.build(
        source_url="https://github.com/foo/bar", product="..", version="1.0"
    )
    assert result.repo_dir is None
    assert result.error is not None and "unsafe product" in result.error


def test_build_product_cannot_rmtree_outside_workdir(tmp_path: Path) -> None:
    """A traversal ``product`` must not let the pre-clone rmtree escape work_dir.

    Pre-fix ``work / "../victim"`` resolved to the real sibling dir and
    ``shutil.rmtree(target)`` deleted it. Post-fix ``Path(product).name`` keeps
    the target inside work_dir, so the sibling survives.
    """
    work = tmp_path / "work"
    work.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("important")

    def boom(req: Any, **_: Any) -> Any:
        raise urllib.error.URLError("no network in test")

    with (
        patch("cve_env.tools.source_build._urlopen", side_effect=boom),
        patch(
            "cve_env.utils.run.subprocess.run",
            side_effect=lambda *a, **k: _fake_completed(128, stderr="clone disabled"),
        ),
    ):
        builder = SourceBuilder(SourceBuildConfig(work_dir=work))
        builder.build(
            source_url="https://github.com/foo/bar",
            product="../victim",
            version="1.0",
        )

    assert victim.exists() and (victim / "keep.txt").exists(), (
        "rmtree must not escape work_dir via a traversal product"
    )


def test_download_tarball_refuses_oversized_extraction(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """DOS-1: a tarball whose uncompressed size exceeds the cap is refused
    (decompression-bomb guard) — nothing is extracted."""
    monkeypatch.setattr(sb, "_MAX_EXTRACT_BYTES", 1)
    tarball = _make_fake_tarball({"Dockerfile": "FROM alpine", "go.mod": "module x"})

    with patch(
        "cve_env.tools.source_build._urlopen",
        side_effect=lambda req, **_: _FakeResp(tarball),
    ):
        builder = SourceBuilder(SourceBuildConfig(work_dir=tmp_path))
        target = tmp_path / "out"
        ok = builder._download_tarball("foo", "bar", "v1.5", target)

    assert ok is False, "over-cap extraction must be refused"
    assert not (target / "Dockerfile").exists(), "nothing should be extracted"


def test_http_get_json_on_404_returns_none() -> None:
    def raise_404(req: Any, **_: Any) -> Any:
        raise urllib.error.HTTPError(
            url=req.full_url, code=404, msg="Not Found", hdrs=None, fp=None  # type: ignore[arg-type]
        )

    with patch(
        "cve_env.tools.source_build._urlopen", side_effect=raise_404
    ):
        assert sb._http_get_json("https://api.github.com/repos/x/y", timeout=5) is None


def test_http_get_bytes_on_404_returns_none() -> None:
    def raise_404(req: Any, **_: Any) -> Any:
        raise urllib.error.HTTPError(
            url=req.full_url, code=404, msg="Not Found", hdrs=None, fp=None  # type: ignore[arg-type]
        )

    with patch(
        "cve_env.tools.source_build._urlopen", side_effect=raise_404
    ):
        assert (
            sb._http_get_bytes(
                "https://codeload.github.com/x/y/tar.gz/refs/tags/v1", timeout=5
            )
            is None
        )


# -- context manager + cleanup -------------------------------------------


def test_context_manager_cleans_up_on_exit(tmp_path: Path) -> None:
    # Builder-created temp dir should get removed on __exit__ when not retained.
    created: list[Path] = []

    with SourceBuilder() as b:
        # Force a tempdir creation by calling build() on a URL that fails early.
        b.build(source_url="https://example.com/foo/bar", product="x", version="1")
        created = list(b._temp_dirs)
    # After context manager exits, temp dirs should be gone.
    for d in created:
        assert not d.exists()


def test_atexit_cleanup_removes_retained_dirs(tmp_path: Path) -> None:
    """The atexit hook must remove retained clones registered by
    source_build_payload, otherwise multiple successful CVE builds
    accumulate clones until the disk fills (the failure mode that
    crashed bench50-20260425-003221)."""
    # Simulate a successful payload retaining a temp dir.
    fake_dir = tmp_path / "fake-clone-dir"
    fake_dir.mkdir()
    (fake_dir / "Dockerfile").write_text("FROM alpine")

    # Register it like source_build_payload would.
    sb._RETAINED_DIRS.append(fake_dir)
    assert fake_dir.exists()

    # Run the cleanup directly (simulating process exit).
    sb._cleanup_retained_dirs()
    assert not fake_dir.exists()
    assert sb._RETAINED_DIRS == []


def test_payload_registers_retained_dir_for_atexit(tmp_path: Path) -> None:
    """source_build_payload must add the builder's temp_dirs to _RETAINED_DIRS
    on success, so atexit can clean them later."""
    initial = list(sb._RETAINED_DIRS)
    fake_clone = tmp_path / "clone-dir"
    fake_clone.mkdir()
    fake_result = SourceBuildResult(
        repo_dir=fake_clone,
        checked_out_tag="v1.0",
        dockerfile_path=fake_clone / "Dockerfile",
        dockerfile_text="FROM alpine",
        build_config="maven",
    )

    def fake_build(self, **_: Any) -> SourceBuildResult:
        # Mimic SourceBuilder.build registering a temp dir on the builder.
        self._temp_dirs.append(fake_clone)
        return fake_result

    try:
        with patch.object(SourceBuilder, "build", fake_build):
            out = source_build_payload(
                source_url="https://github.com/foo/bar",
                product="bar",
                version="1.0",
            )
        assert out["ok"] is True
        assert fake_clone in sb._RETAINED_DIRS
    finally:
        # Reset module-level registry so this test doesn't pollute later tests.
        sb._RETAINED_DIRS[:] = initial


def test_retain_prevents_cleanup() -> None:
    with SourceBuilder() as b:
        # Simulate a tempdir that build() would have registered.
        import tempfile as _tf

        d = Path(_tf.mkdtemp(prefix="cve-env-test-retain-"))
        b._temp_dirs.append(d)
        b.retain()
    assert d.exists()
    # Manual cleanup.
    import shutil as _sh

    _sh.rmtree(d, ignore_errors=True)


# A2: _next_step_hint no_tag_matched fallback (CVE-2020-15014 forensic)


def test_no_tag_matched_hint_suggests_dockerfile_gen() -> None:
    """A2 fix: when no tag matched, hint must mention dockerfile_gen so the
    agent tries git-clone-into-dockerfile_gen rather than giving up.
    CVE-2020-15014: _next_step_hint returned 'no next step; give_up';
    agent followed it; CVE succeeds in bench when dockerfile_gen is tried.
    """
    result = SourceBuildResult(
        repo_dir=None,
        checked_out_tag=None,
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
        error="no tag matched '9.5.1'",
        warnings=["no tag matched at current depth; deepening to 100"],
    )
    hint = sb._next_step_hint(result)
    assert "dockerfile_gen" in hint or "git clone" in hint, (
        f"Expected hint to mention dockerfile_gen or git clone, got: {hint!r}"
    )
    assert "give_up" not in hint, (
        f"Hint must not say give_up when only no_tag_matched: {hint!r}"
    )


# ─── B-1: urllib env-based proxy injection defense ─────────────────────────


def test_BUG004b_urllib_disables_env_proxy() -> None:
    """B-1 (companion to BUG-004b for requests): source_build's _urlopen
    helper MUST install a ProxyHandler({}) on its opener to defeat env-based
    proxy injection. Unlike `requests`'s proxies={} (a no-op — env vars
    still merge), urllib's ProxyHandler({}) IS sufficient to disable
    proxy lookup.

    bafb's bugs937.md::BUG-004b claimed urllib hardening was added but
    diff vs cve-env-working showed source_build.py was untouched (revert
    wiped it). This test ports the protection.
    """
    import urllib.request
    from unittest.mock import MagicMock

    captured_handlers: list = []

    def fake_build_opener(*handlers: object) -> MagicMock:
        captured_handlers.extend(handlers)
        opener = MagicMock()
        opener.open.return_value = MagicMock(status=200, read=lambda: b"")
        return opener

    with patch(
        "cve_env.tools.source_build.urllib.request.build_opener",
        side_effect=fake_build_opener,
    ):
        req = urllib.request.Request("https://api.github.com/repos/x/y")
        sb._urlopen(req, timeout=5)

    proxy_handlers = [
        h for h in captured_handlers if isinstance(h, urllib.request.ProxyHandler)
    ]
    assert proxy_handlers, (
        "B-1: _urlopen must install a ProxyHandler on its opener; "
        f"got handlers: {[type(h).__name__ for h in captured_handlers]}"
    )
    # ProxyHandler({}) disables env-based proxy lookup; any populated dict
    # would re-enable some proxy. Empty dict is the documented disable.
    assert proxy_handlers[0].proxies == {}, (
        f"B-1: ProxyHandler must have empty proxies={{}}; "
        f"got {proxy_handlers[0].proxies}"
    )


# ─── Pure-logic coverage gaps (no network / git / docker) ──────────────────
#
# Every test below exercises a pure-logic branch by calling the helper method
# directly with `_urlopen` / `_http_get_*` / archive sub-steps mocked, or by
# building a small in-memory archive. None hit real git/docker/network. The
# subprocess shell-out branches (clone/deepen/checkout timeouts, etc.) are left
# to the existing integration-style tests above; over-mocking them here would
# be brittle.


# -- _env_int --------------------------------------------------------------


def test_env_int_uses_default_when_unset(monkeypatch: Any) -> None:
    monkeypatch.delenv("CVE_ENV_TEST_INT", raising=False)
    assert sb._env_int("CVE_ENV_TEST_INT", 42) == 42


def test_env_int_parses_valid_value(monkeypatch: Any) -> None:
    monkeypatch.setenv("CVE_ENV_TEST_INT", "123")
    assert sb._env_int("CVE_ENV_TEST_INT", 42) == 123


def test_env_int_falls_back_on_malformed_value(monkeypatch: Any) -> None:
    """Lines 73-74: a non-int env value must NOT raise; falls back to default."""
    monkeypatch.setenv("CVE_ENV_TEST_INT", "not-a-number")
    assert sb._env_int("CVE_ENV_TEST_INT", 42) == 42


def test_env_int_empty_string_uses_default(monkeypatch: Any) -> None:
    """An empty env value is falsy → `os.environ.get(...) or default` yields the
    default int, never an empty-string int() crash."""
    monkeypatch.setenv("CVE_ENV_TEST_INT", "")
    assert sb._env_int("CVE_ENV_TEST_INT", 7) == 7


# -- normalize_github_url: non-http(s) scheme ------------------------------


def test_normalize_github_url_rejects_non_http_scheme() -> None:
    """Line 146: a URL whose scheme survives the rewrites but isn't http/https
    (e.g. ftp://github.com/...) is rejected before host matching."""
    assert normalize_github_url("ftp://github.com/foo/bar") is None
    assert normalize_github_url("file:///github.com/foo/bar") is None


# -- _fetch_repo_size_kb (436-452) -----------------------------------------


def test_fetch_repo_size_kb_no_owner_repo_match() -> None:
    """Line 463-equivalent guard (437-438): a URL with no owner/repo returns None
    without any HTTP call."""
    builder = SourceBuilder()
    assert builder._fetch_repo_size_kb("https://github.com/") is None


def test_fetch_repo_size_kb_parses_size() -> None:
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", return_value={"size": 1234}):
        assert builder._fetch_repo_size_kb("https://github.com/foo/bar") == 1234


def test_fetch_repo_size_kb_float_size_coerced_to_int() -> None:
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", return_value={"size": 99.7}):
        assert builder._fetch_repo_size_kb("https://github.com/foo/bar") == 99


def test_fetch_repo_size_kb_non_dict_response() -> None:
    """Lines 445-446: a non-dict JSON body (e.g. a list) returns None."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", return_value=["not", "a", "dict"]):
        assert builder._fetch_repo_size_kb("https://github.com/foo/bar") is None


def test_fetch_repo_size_kb_bool_size_rejected() -> None:
    """Lines 448-449: a JSON ``size`` of bool True/False must NOT be treated as
    an int (bool is an int subclass) — returns None."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", return_value={"size": True}):
        assert builder._fetch_repo_size_kb("https://github.com/foo/bar") is None


def test_fetch_repo_size_kb_missing_size_key() -> None:
    """Line 452: ``size`` absent (or non-numeric) → None."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", return_value={"other": 1}):
        assert builder._fetch_repo_size_kb("https://github.com/foo/bar") is None
    with patch.object(sb, "_http_get_json", return_value={"size": "big"}):
        assert builder._fetch_repo_size_kb("https://github.com/foo/bar") is None


def test_fetch_repo_size_kb_oserror_returns_none() -> None:
    """Lines 443-444: an OSError from the HTTP helper is swallowed → None."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", side_effect=OSError("boom")):
        assert builder._fetch_repo_size_kb("https://github.com/foo/bar") is None


# -- _archive_fallback (463, 471-474) --------------------------------------


def test_archive_fallback_no_owner_repo_match() -> None:
    """Line 463: a URL with no owner/repo group returns None immediately."""
    builder = SourceBuilder()
    warnings: list[str] = []
    out = builder._archive_fallback(
        "https://github.com/", "1.0", Path("/nonexistent"), warnings
    )
    assert out is None


def test_archive_fallback_no_tags_available() -> None:
    """Lines 466-468: empty tag list from the API → warning + None."""
    builder = SourceBuilder()
    warnings: list[str] = []
    with patch.object(SourceBuilder, "_list_tags_via_api", return_value=[]):
        out = builder._archive_fallback(
            "https://github.com/foo/bar", "1.0", Path("/nonexistent"), warnings
        )
    assert out is None
    assert any("no tags available" in w for w in warnings)


def test_archive_fallback_no_matching_tag(tmp_path: Path) -> None:
    """Lines 469-472: tags exist but none match ``version`` → warning + None."""
    builder = SourceBuilder()
    warnings: list[str] = []
    with patch.object(
        SourceBuilder, "_list_tags_via_api", return_value=["v9.9.9"]
    ):
        out = builder._archive_fallback(
            "https://github.com/foo/bar", "1.0", tmp_path / "t", warnings
        )
    assert out is None
    assert any("no tag matched" in w for w in warnings)


def test_archive_fallback_rmtrees_existing_target_then_downloads(
    tmp_path: Path,
) -> None:
    """Lines 473-481: a pre-existing target dir is rmtree'd before download, and
    a successful download returns the matched tag with a 'codeload' warning."""
    builder = SourceBuilder()
    warnings: list[str] = []
    target = tmp_path / "bar"
    target.mkdir()
    (target / "stale.txt").write_text("old")
    captured: dict[str, Any] = {}

    def fake_download(owner: str, repo: str, tag: str, tgt: Path) -> bool:
        # Target must already be gone when download runs (rmtree fired).
        captured["existed_at_download"] = tgt.exists()
        tgt.mkdir(parents=True, exist_ok=True)
        return True

    with (
        patch.object(SourceBuilder, "_list_tags_via_api", return_value=["v1.0"]),
        patch.object(SourceBuilder, "_download_tarball", side_effect=fake_download),
    ):
        out = builder._archive_fallback(
            "https://github.com/foo/bar", "1.0", target, warnings
        )
    assert out == "v1.0"
    assert captured["existed_at_download"] is False, "stale target not removed"
    assert any("codeload" in w for w in warnings)


def test_archive_fallback_download_failure_warns(tmp_path: Path) -> None:
    """A matched tag but a failed download → warning + None."""
    builder = SourceBuilder()
    warnings: list[str] = []
    with (
        patch.object(SourceBuilder, "_list_tags_via_api", return_value=["v1.0"]),
        patch.object(SourceBuilder, "_download_tarball", return_value=False),
    ):
        out = builder._archive_fallback(
            "https://github.com/foo/bar", "1.0", tmp_path / "bar", warnings
        )
    assert out is None
    assert any("download or extract failed" in w for w in warnings)


# -- _list_tags_via_api (489-490, 496) -------------------------------------


def test_list_tags_via_api_oserror_returns_empty() -> None:
    """Lines 489-490: an OSError from the HTTP helper → empty list."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", side_effect=OSError("boom")):
        assert builder._list_tags_via_api("foo", "bar") == []


def test_list_tags_via_api_non_list_response() -> None:
    """Lines 491-492: a non-list JSON body → empty list."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_json", return_value={"message": "rate limited"}):
        assert builder._list_tags_via_api("foo", "bar") == []


def test_list_tags_via_api_skips_non_dict_and_nameless_entries() -> None:
    """Line 496 + 498->494: non-dict entries and entries without a usable
    ``name`` are skipped; only valid string names survive."""
    builder = SourceBuilder()
    payload = [
        "not-a-dict",
        {"no_name": 1},
        {"name": ""},  # empty name skipped
        {"name": 123},  # non-string name skipped
        {"name": "v1.0"},
        {"name": "v1.1"},
    ]
    with patch.object(sb, "_http_get_json", return_value=payload):
        assert builder._list_tags_via_api("foo", "bar") == ["v1.0", "v1.1"]


# -- _download_tarball pure branches (512-515, 520, 525-530, 541, 548, 551) -


def test_download_tarball_payload_none_returns_false(tmp_path: Path) -> None:
    """Lines 514-515: when the HTTP helper returns None (no bytes), refuse."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_bytes", return_value=None):
        assert (
            builder._download_tarball("foo", "bar", "v1.0", tmp_path / "out") is False
        )


def test_download_tarball_http_oserror_returns_false(tmp_path: Path) -> None:
    """Lines 512-513: an OSError fetching the tarball → refuse (False)."""
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_bytes", side_effect=OSError("conn reset")):
        assert (
            builder._download_tarball("foo", "bar", "v1.0", tmp_path / "out") is False
        )


def _make_many_member_tarball(n_members: int) -> bytes:
    """A tar.gz with a top dir + ``n_members`` tiny regular files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        top = tarfile.TarInfo(name="bar-1.5")
        top.type = tarfile.DIRTYPE
        tf.addfile(top)
        for i in range(n_members):
            data = b"x"
            info = tarfile.TarInfo(name=f"bar-1.5/f{i}.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_download_tarball_refuses_over_member_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Lines 524-530 (DOS-1): a tarball with more members than the cap is
    refused — nothing is extracted."""
    monkeypatch.setattr(sb, "_MAX_EXTRACT_MEMBERS", 2)
    tarball = _make_many_member_tarball(5)  # top + 5 files > cap of 2
    target = tmp_path / "out"
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_bytes", return_value=tarball):
        ok = builder._download_tarball("foo", "bar", "v1.5", target)
    assert ok is False
    assert not target.exists() or not any(target.iterdir())


def test_download_tarball_empty_member_list_returns_false(
    tmp_path: Path,
) -> None:
    """Lines 518-520: a valid gzip whose tar has zero members → refuse."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass  # no members
    empty_tar = buf.getvalue()
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_bytes", return_value=empty_tar):
        assert (
            builder._download_tarball("foo", "bar", "v1.5", tmp_path / "out") is False
        )


def test_download_tarball_blank_top_segment_returns_false(
    tmp_path: Path,
) -> None:
    """Lines 539-541: when the first member's name has an empty top segment
    (starts with '/'), extraction is refused."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # Leading-slash name → split('/', 1)[0] == "" → blank top segment.
        info = tarfile.TarInfo(name="/oops")
        info.size = 0
        tf.addfile(info, io.BytesIO(b""))
    tarball = buf.getvalue()
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_bytes", return_value=tarball):
        assert (
            builder._download_tarball("foo", "bar", "v1.5", tmp_path / "out") is False
        )


def test_download_tarball_skips_topdir_dotdot_and_foreign_members(
    tmp_path: Path,
) -> None:
    """Lines 545-551: the extraction loop skips (a) the bare top-dir member,
    (b) members not under the prefix, and (c) members whose stripped path
    contains '..'. Only the clean Dockerfile lands on disk."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        top = tarfile.TarInfo(name="bar-1.5")
        top.type = tarfile.DIRTYPE
        tf.addfile(top)
        # Clean file under prefix → extracted.
        good = b"FROM alpine"
        gi = tarfile.TarInfo(name="bar-1.5/Dockerfile")
        gi.size = len(good)
        tf.addfile(gi, io.BytesIO(good))
        # Member NOT under the prefix → skipped (line 547-548).
        foreign = b"nope"
        fi = tarfile.TarInfo(name="other-top/evil.txt")
        fi.size = len(foreign)
        tf.addfile(fi, io.BytesIO(foreign))
        # Member under prefix but with '..' in the relative path → skipped (550-551).
        dd = b"escape"
        di = tarfile.TarInfo(name="bar-1.5/../escape.txt")
        di.size = len(dd)
        tf.addfile(di, io.BytesIO(dd))
    tarball = buf.getvalue()
    target = tmp_path / "out"
    builder = SourceBuilder()
    with patch.object(sb, "_http_get_bytes", return_value=tarball):
        ok = builder._download_tarball("foo", "bar", "v1.5", target)
    assert ok is True
    assert (target / "Dockerfile").read_text() == "FROM alpine"
    assert not (target / "evil.txt").exists()
    assert not list(target.rglob("escape.txt"))


# -- _read_dockerfile OSError (665-666) ------------------------------------


def test_read_dockerfile_oserror_returns_none(tmp_path: Path) -> None:
    """Lines 665-666: a read that raises OSError (e.g. a directory, or perms) →
    None rather than propagating."""
    builder = SourceBuilder()
    a_dir = tmp_path / "Dockerfile"
    a_dir.mkdir()  # reading a directory as text raises OSError
    assert builder._read_dockerfile(a_dir) is None


# -- _find_devcontainer_image branches (687-688, 694-695, 699) -------------


def test_find_devcontainer_image_read_oserror_continues(tmp_path: Path) -> None:
    """Lines 687-688: an OSError reading the first devcontainer location is
    swallowed (``continue``); a readable second location still wins."""
    repo = tmp_path / "repo"
    (repo / ".devcontainer").mkdir(parents=True)
    # First candidate (.devcontainer/devcontainer.json) is a DIRECTORY → is_file()
    # is False, so it's skipped at the is_file gate. To force the read-OSError
    # branch we instead make the root .devcontainer.json a directory after the
    # first is_file passes — simplest: stub read_text to raise once.
    df = repo / ".devcontainer" / "devcontainer.json"
    df.write_text('{"image": "img:tag"}')
    real_read = Path.read_text
    calls = {"n": 0}

    def flaky_read(self: Path, *a: Any, **k: Any) -> str:
        if self == df and calls["n"] == 0:
            calls["n"] += 1
            raise OSError("transient")
        return real_read(self, *a, **k)

    with patch.object(Path, "read_text", flaky_read):
        builder = SourceBuilder()
        # Only one candidate is readable-but-raises → loop continues → returns None.
        assert builder._find_devcontainer_image(repo) is None


def test_find_devcontainer_image_invalid_json_returns_none(tmp_path: Path) -> None:
    """Lines 694-695: malformed JSON (even after JSONC stripping) → None."""
    repo = tmp_path / "repo"
    (repo / ".devcontainer").mkdir(parents=True)
    (repo / ".devcontainer" / "devcontainer.json").write_text("{ not valid json ]")
    builder = SourceBuilder()
    assert builder._find_devcontainer_image(repo) is None


def test_find_devcontainer_image_no_image_key_returns_none(tmp_path: Path) -> None:
    """Line 699: valid JSON with no usable ``image`` → None."""
    repo = tmp_path / "repo"
    (repo / ".devcontainer").mkdir(parents=True)
    (repo / ".devcontainer" / "devcontainer.json").write_text(
        '{"name": "x", "image": "   "}'  # whitespace-only image is not usable
    )
    builder = SourceBuilder()
    assert builder._find_devcontainer_image(repo) is None


# -- _http_get_json branches (747, 750-755, 760, 764-765) ------------------


def test_http_get_json_non_200_status_returns_none() -> None:
    """Line 746-747: a non-200 status (e.g. 500) → None."""
    with patch.object(sb, "_urlopen", return_value=_FakeResp(b"{}", status=500)):
        assert sb._http_get_json("https://api.github.com/x", timeout=5) is None


def test_http_get_json_over_cap_returns_none(monkeypatch: Any) -> None:
    """Lines 748-755 (DOS-1): a JSON body over the cap is ignored → None."""
    monkeypatch.setattr(sb, "_MAX_JSON_BYTES", 4)
    big = b'{"size": 1234567}'  # well over 4 bytes
    with patch.object(sb, "_urlopen", return_value=_FakeResp(big)):
        assert sb._http_get_json("https://api.github.com/x", timeout=5) is None


def test_http_get_json_urlerror_with_oserror_reason_reraises() -> None:
    """Lines 758-760: a URLError whose ``reason`` is an OSError is re-raised as
    that OSError (callers convert it to a benign None/[] up the stack)."""
    err = urllib.error.URLError(OSError("network down"))
    with patch.object(sb, "_urlopen", side_effect=err):
        with pytest.raises(OSError, match="network down"):
            sb._http_get_json("https://api.github.com/x", timeout=5)


def test_http_get_json_urlerror_non_oserror_reason_returns_none() -> None:
    """Line 761: a URLError with a non-OSError reason (a bare string) → None."""
    err = urllib.error.URLError("dns weirdness")
    with patch.object(sb, "_urlopen", side_effect=err):
        assert sb._http_get_json("https://api.github.com/x", timeout=5) is None


def test_http_get_json_undecodable_body_returns_none() -> None:
    """Lines 764-765: a body that isn't valid UTF-8 JSON → None (no raise)."""
    with patch.object(sb, "_urlopen", return_value=_FakeResp(b"\xff\xfe not json")):
        assert sb._http_get_json("https://api.github.com/x", timeout=5) is None


# -- _http_get_bytes branches (774, 777-782, 785-788) ----------------------


def test_http_get_bytes_non_200_status_returns_none() -> None:
    """Lines 773-774: a non-200 status → None."""
    with patch.object(sb, "_urlopen", return_value=_FakeResp(b"data", status=403)):
        assert (
            sb._http_get_bytes("https://codeload.github.com/x", timeout=5) is None
        )


def test_http_get_bytes_over_cap_returns_none(monkeypatch: Any) -> None:
    """Lines 775-782 (DOS-1): a tarball body over the cap → None (cascade falls
    back to git clone)."""
    monkeypatch.setattr(sb, "_MAX_TARBALL_BYTES", 4)
    big = b"a much larger than four byte body"
    with patch.object(sb, "_urlopen", return_value=_FakeResp(big)):
        assert (
            sb._http_get_bytes("https://codeload.github.com/x", timeout=5) is None
        )


def test_http_get_bytes_under_cap_returns_body() -> None:
    """Happy path: a small body is returned verbatim as bytes."""
    with patch.object(sb, "_urlopen", return_value=_FakeResp(b"tarbytes")):
        assert (
            sb._http_get_bytes("https://codeload.github.com/x", timeout=5)
            == b"tarbytes"
        )


def test_http_get_bytes_urlerror_with_oserror_reason_reraises() -> None:
    """Lines 785-787: URLError wrapping an OSError → re-raised as that OSError."""
    err = urllib.error.URLError(OSError("reset"))
    with patch.object(sb, "_urlopen", side_effect=err):
        with pytest.raises(OSError, match="reset"):
            sb._http_get_bytes("https://codeload.github.com/x", timeout=5)


def test_http_get_bytes_urlerror_non_oserror_reason_returns_none() -> None:
    """Line 788: URLError with a non-OSError reason → None."""
    err = urllib.error.URLError("weird")
    with patch.object(sb, "_urlopen", side_effect=err):
        assert (
            sb._http_get_bytes("https://codeload.github.com/x", timeout=5) is None
        )


# -- _classify_failure branches (918-922) ----------------------------------


def test_classify_failure_unknown_when_no_error() -> None:
    r = SourceBuildResult(
        repo_dir=None,
        checked_out_tag=None,
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
        error=None,
    )
    assert sb._classify_failure(r) == "unknown"


def test_classify_failure_checkout_failed() -> None:
    """Lines 918-919: an error mentioning 'checkout' → 'checkout_failed'."""
    r = SourceBuildResult(
        repo_dir=Path("/tmp/x"),
        checked_out_tag=None,
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
        error="checkout 'v1.0' failed",
    )
    assert sb._classify_failure(r) == "checkout_failed"


def test_classify_failure_clone_failed_when_repo_dir_none() -> None:
    """Lines 920-921: a generic error with repo_dir=None → 'clone_failed'."""
    r = SourceBuildResult(
        repo_dir=None,
        checked_out_tag=None,
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
        error="some unexpected git failure",
    )
    assert sb._classify_failure(r) == "clone_failed"


def test_classify_failure_no_dockerfile_when_repo_dir_present(tmp_path: Path) -> None:
    """Line 922: a generic error WITH a repo_dir → 'no_dockerfile_or_build_config'."""
    r = SourceBuildResult(
        repo_dir=tmp_path,
        checked_out_tag="v1.0",
        dockerfile_path=None,
        dockerfile_text=None,
        build_config=None,
        error="repo cloned but nothing to build",
    )
    assert sb._classify_failure(r) == "no_dockerfile_or_build_config"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
