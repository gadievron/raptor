"""Tests for :mod:`cve_env.tools.github_fetch`."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import MagicMock, patch

from cve_env.tools.github_fetch import github_fetch
from cve_env.tools.web_fetch import FetchResult


def _fetch_ok(body: str) -> FetchResult:
    return FetchResult(ok=True, url="https://gh/x", status=200, body=body, body_bytes=len(body))


def _fetch_fail(reason: str) -> FetchResult:
    return FetchResult(ok=False, url="https://gh/x", status=404, body="", reason=reason)


def test_github_fetch_requires_owner_and_repo() -> None:
    r = github_fetch(owner="", repo="vulhub", path="x")
    assert r.ok is False
    assert "required" in r.reason


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_file_returns_decoded_content(mock_fetch: Any) -> None:
    content = "services:\n  web:\n    image: vulhub/drupal:8.5.0\n"
    payload = {
        "type": "file",
        "name": "docker-compose.yml",
        "path": "drupal/CVE-2018-7600/docker-compose.yml",
        "size": len(content),
        "encoding": "base64",
        "content": base64.b64encode(content.encode()).decode(),
    }
    mock_fetch.return_value = _fetch_ok(json.dumps(payload))
    r = github_fetch(
        owner="vulhub",
        repo="vulhub",
        path="drupal/CVE-2018-7600/docker-compose.yml",
    )
    assert r.ok is True
    assert r.kind == "file"
    assert "vulhub/drupal:8.5.0" in r.content
    assert r.size == len(content)


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_directory_listing(mock_fetch: Any) -> None:
    payload = [
        {"name": "CVE-2018-7600", "type": "dir", "path": "drupal/CVE-2018-7600", "size": 0},
        {"name": "README.md", "type": "file", "path": "drupal/README.md", "size": 1024},
    ]
    mock_fetch.return_value = _fetch_ok(json.dumps(payload))
    r = github_fetch(owner="vulhub", repo="vulhub", path="drupal")
    assert r.ok is True
    assert r.kind == "dir"
    assert len(r.entries) == 2
    names = [e["name"] for e in r.entries]
    assert "CVE-2018-7600" in names


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_propagates_http_failure(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_fail("HTTP 404")
    r = github_fetch(owner="vulhub", repo="vulhub", path="nope")
    assert r.ok is False
    assert "github fetch failed" in r.reason


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_handles_malformed_json(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok("{not json")
    r = github_fetch(owner="vulhub", repo="vulhub", path="x")
    assert r.ok is False
    assert "json decode" in r.reason


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_ref_passed_to_url(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok(json.dumps([]))
    github_fetch(owner="vulhub", repo="vulhub", path="drupal", ref="master")
    called_url = mock_fetch.call_args.kwargs["url"]
    assert "?ref=master" in called_url


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_auth_header_when_token_set(mock_fetch: Any, monkeypatch: Any) -> None:
    from cve_env.tools.github_fetch import reset_token_cache

    reset_token_cache()
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token_abc")
    mock_fetch.return_value = _fetch_ok(json.dumps([]))
    github_fetch(owner="vulhub", repo="vulhub", path="drupal")
    headers = mock_fetch.call_args.kwargs["headers"]
    assert "Authorization" in headers
    assert "Bearer ghp_test_token_abc" in headers["Authorization"]


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_no_auth_header_when_no_token_anywhere(
    mock_fetch: Any, mock_run: Any, monkeypatch: Any
) -> None:
    """Phase 17.1: with no GITHUB_TOKEN env AND `gh auth token` failing,
    the request goes out anonymously."""
    from cve_env.tools.github_fetch import reset_token_cache

    reset_token_cache()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    # Simulate `gh` not installed / not logged in.
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not logged in")
    mock_fetch.return_value = _fetch_ok(json.dumps([]))
    github_fetch(owner="vulhub", repo="vulhub", path="drupal")
    headers = mock_fetch.call_args.kwargs["headers"]
    assert "Authorization" not in headers


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_uses_gh_cli_token_when_env_unset(
    mock_fetch: Any, mock_run: Any, monkeypatch: Any
) -> None:
    """Phase 17.1: when GITHUB_TOKEN is unset, fall back to `gh auth token`."""
    from cve_env.tools.github_fetch import reset_token_cache

    reset_token_cache()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    mock_run.return_value = MagicMock(
        returncode=0, stdout="gho_from_gh_cli_xyz\n", stderr=""
    )
    mock_fetch.return_value = _fetch_ok(json.dumps([]))
    github_fetch(owner="vulhub", repo="vulhub", path="drupal")
    headers = mock_fetch.call_args.kwargs["headers"]
    assert "Authorization" in headers
    assert "Bearer gho_from_gh_cli_xyz" in headers["Authorization"]


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_env_token_takes_precedence_over_gh_cli(
    mock_fetch: Any, mock_run: Any, monkeypatch: Any
) -> None:
    """Phase 17.1: explicit GITHUB_TOKEN env var beats gh CLI token."""
    from cve_env.tools.github_fetch import reset_token_cache

    reset_token_cache()
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_explicit_env_var")
    mock_run.return_value = MagicMock(returncode=0, stdout="gho_should_not_be_used\n")
    mock_fetch.return_value = _fetch_ok(json.dumps([]))
    github_fetch(owner="vulhub", repo="vulhub", path="drupal")
    headers = mock_fetch.call_args.kwargs["headers"]
    assert "Bearer ghp_explicit_env_var" in headers["Authorization"]
    # `gh auth token` should NOT have been invoked when env var is set.
    mock_run.assert_not_called()


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_strips_leading_trailing_slashes(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok(json.dumps([]))
    github_fetch(owner="vulhub", repo="vulhub", path="/drupal/CVE-2018-7600/")
    called_url = mock_fetch.call_args.kwargs["url"]
    # Should have no double slash and no trailing slash.
    assert "/contents/drupal/CVE-2018-7600" in called_url
    assert "//drupal" not in called_url.replace("https://", "")


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_unknown_shape_fails(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok(json.dumps("a string"))
    r = github_fetch(owner="vulhub", repo="vulhub", path="x")
    assert r.ok is False
    assert "unexpected response shape" in r.reason


@patch("cve_env.tools.github_fetch.web_fetch")
def test_github_fetch_file_without_base64_encoding(mock_fetch: Any) -> None:
    # Non-base64 file content (rare, but possible).
    payload = {
        "type": "file",
        "name": "x.txt",
        "path": "x.txt",
        "size": 5,
        "encoding": "utf-8",
        "content": "hello",
    }
    mock_fetch.return_value = _fetch_ok(json.dumps(payload))
    r = github_fetch(owner="o", repo="r", path="x.txt")
    assert r.ok is True
    assert r.content == "hello"


# ─── B-17 (2026-05-06): source-file sanitization ────────────────────


def _file_payload(path: str, content: str) -> dict[str, Any]:
    return {
        "type": "file",
        "name": path.rsplit("/", 1)[-1],
        "path": path,
        "size": len(content),
        "encoding": "base64",
        "content": base64.b64encode(content.encode()).decode(),
    }


@patch("cve_env.tools.github_fetch.web_fetch")
def test_b17_dockerfile_returned_raw(mock_fetch: Any) -> None:
    """Dockerfiles must NOT be sanitized — they're build artifacts."""
    content = "FROM apache:2.4.49\nRUN apt-get install -y libapache2-mod-php\n"
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("Dockerfile", content)))
    r = github_fetch(owner="o", repo="r", path="Dockerfile")
    assert r.content == content, "Dockerfile content must pass through unchanged"


@patch("cve_env.tools.github_fetch.web_fetch")
def test_b17_docker_compose_yml_returned_raw(mock_fetch: Any) -> None:
    content = "services:\n  web:\n    image: vulhub/leadshop:1.4.20\n"
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("docker-compose.yml", content)))
    r = github_fetch(owner="o", repo="r", path="docker-compose.yml")
    assert r.content == content


@patch("cve_env.tools.github_fetch.web_fetch")
def test_b17_package_json_returned_raw(mock_fetch: Any) -> None:
    content = '{"name": "h5vp", "version": "1.0.6"}'
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("package.json", content)))
    r = github_fetch(owner="o", repo="r", path="package.json")
    assert r.content == content


@patch("cve_env.tools.github_fetch.web_fetch")
def test_b17_php_source_truncated_and_sanitized(mock_fetch: Any) -> None:
    """PHP source files (likely vulnerable code) must be truncated to
    2 KiB AND run through exploit_text_sanitizer."""
    content = (
        "<?php\nclass VideoController {\n"
        "    public function get_item($request) {\n"
        "        // SQL injection sink — this is exploitable by unauthenticated users\n"
        "        $video = $wpdb->get_row(\"SELECT * FROM table WHERE id='$id'\");\n"
        "    }\n}\n"
    ) + ("// padding\n" * 500)  # >2 KiB padding to force truncation
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("inc/Rest/VideoController.php", content)))
    r = github_fetch(owner="o", repo="r", path="inc/Rest/VideoController.php")
    assert r.ok is True
    assert len(r.content) <= 2048 + 1, "source file must be truncated to ~2 KiB"
    assert "exploitable by" not in r.content.lower(), (
        "exploit-disclosure phrase must be sanitized out"
    )
    assert "sql injection" not in r.content.lower(), (
        "class-verb 'SQL injection' must be replaced"
    )
    # Build-relevant signal must survive
    assert "VideoController" in r.content, "class name must survive sanitization"


@patch("cve_env.tools.github_fetch.web_fetch")
def test_b17_python_source_sanitized(mock_fetch: Any) -> None:
    content = (
        "# Module exploits buffer overflow in input parsing\n"
        "def parse_input(data):\n"
        "    # An attacker can use this to escalate privileges\n"
        "    return eval(data)\n"
    )
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("src/parser.py", content)))
    r = github_fetch(owner="o", repo="r", path="src/parser.py")
    assert r.ok is True
    assert "buffer overflow" not in r.content.lower()
    assert "attacker can" not in r.content.lower()
    assert "parse_input" in r.content


@patch("cve_env.tools.github_fetch.web_fetch")
def test_readme_prose_sanitized_preserves_build_info(mock_fetch: Any) -> None:
    """Phase 1b (2026-05-23): README/doc prose is now SANITIZED for
    exploit-disclosure language (forensic: CVE-2024-44902's README
    returned a raw deserialization PoC gadget chain that tripped the AUP
    filter) while build-relevant literals survive. Supersedes the
    pre-2026-05-23 raw-README behavior (was test_b17_readme_returned_raw)."""
    content = (
        "# h5vp\n\n"
        "This plugin has a deserialization vulnerability. "
        "An attacker can execute arbitrary code via crafted input.\n\n"
        "Install: composer require h5vp/h5vp:1.0.6\n"
    )
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("README.md", content)))
    r = github_fetch(owner="o", repo="r", path="README.md")
    assert r.ok is True
    # Exploit-disclosure language neutralized
    assert "deserialization" not in r.content.lower(), "class-verb must be rewritten"
    assert "an attacker can" not in r.content.lower(), "attacker sentence must be removed"
    # Build-relevant literals preserved
    assert "h5vp/h5vp:1.0.6" in r.content, "package coordinate must survive"
    assert "composer require" in r.content, "install command must survive"


@patch("cve_env.tools.github_fetch.web_fetch")
def test_changelog_prose_sanitized(mock_fetch: Any) -> None:
    """Phase 1b: CHANGELOG (prose) is sanitized; version literals survive."""
    content = "v1.2 — fixed SQL injection in login. An attacker could bypass auth."
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("CHANGELOG.md", content)))
    r = github_fetch(owner="o", repo="r", path="CHANGELOG.md")
    assert "sql injection" not in r.content.lower()
    assert "an attacker could" not in r.content.lower()
    assert "v1.2" in r.content, "version literal must survive"


@patch("cve_env.tools.github_fetch.web_fetch")
def test_b17_pom_xml_returned_raw(mock_fetch: Any) -> None:
    content = "<project><artifactId>jeewms</artifactId><version>3.7</version></project>"
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("pom.xml", content)))
    r = github_fetch(owner="o", repo="r", path="pom.xml")
    assert r.content == content


@patch("cve_env.tools.github_fetch.web_fetch")
def test_b17_go_source_truncated(mock_fetch: Any) -> None:
    content = (
        "package main\n// CVE-2024-X — command injection in processFile\n"
        "import \"os/exec\"\n\nfunc processFile(name string) {\n"
        "    exec.Command(\"sh\", \"-c\", \"cat \" + name).Run()\n}\n"
    ) + ("// pad\n" * 500)
    mock_fetch.return_value = _fetch_ok(json.dumps(_file_payload("internal/unpack/unpack.go", content)))
    r = github_fetch(owner="o", repo="r", path="internal/unpack/unpack.go")
    assert len(r.content) <= 2048 + 1
    assert "command injection" not in r.content.lower()
    assert "processFile" in r.content


def test_build_artifact_and_prose_doc_classification() -> None:
    """Phase 1b (2026-05-23): lock both allowlists. Structured build files
    stay raw-exempt (`_is_build_artifact`); prose docs (README/CHANGELOG/
    .md/.txt/.rst) move to the sanitized class (`_is_prose_doc`).
    Supersedes test_b17_is_build_artifact_helper."""
    from cve_env.tools.github_fetch import _is_build_artifact, _is_prose_doc

    # Structured build artifacts → raw (build artifact, NOT prose)
    for path in [
        "Dockerfile", "drupal/CVE-2018-7600/Dockerfile",
        "docker-compose.yml", "compose.yaml",
        "package.json", "package-lock.json",
        "composer.json", "pom.xml", "go.mod", "Cargo.toml",
        "requirements.txt", "Gemfile", "LICENSE",
        "CMakeLists.txt", "Makefile",
        "config.yml", "settings.toml",
    ]:
        assert _is_build_artifact(path), f"{path!r} should be a build artifact"
        assert not _is_prose_doc(path), f"{path!r} should not be prose"

    # Prose docs → sanitized (prose, NOT raw build artifact)
    for path in [
        "README.md", "readme.rst", "CHANGELOG", "CHANGELOG.md",
        "docs/guide.txt", "intro.asciidoc", "notes.rst",
    ]:
        assert _is_prose_doc(path), f"{path!r} should be a prose doc"
        assert not _is_build_artifact(path), f"{path!r} should NOT be a raw build artifact"

    # Source files (must be neither)
    for path in [
        "src/main.py", "lib/app.go", "inc/Rest/VideoController.php",
        "internal/unpack/unpack.go", "src/main.c", "include/foo.h",
        "App.java", "main.rb", "index.js", "app.ts",
    ]:
        assert not _is_build_artifact(path), f"{path!r} should NOT be a build artifact"
        assert not _is_prose_doc(path), f"{path!r} should NOT be prose"


# --- D1 (2026-05-25): PoC-fetch guard -------------------------------------
# cve-env builds vulnerable ENVIRONMENTS, not exploits → it must not pull
# dedicated exploit-PoC repos into context (trips cyber safeguards + not needed).


def test_is_exploit_poc_repo_blocks_dedicated_poc() -> None:
    from cve_env.tools.github_fetch import _is_exploit_poc_repo

    # Verified live refusal triggers + the bench-024444 investigation set:
    assert _is_exploit_poc_repo("0xf4n9x", "CVE-2022-24990")
    assert _is_exploit_poc_repo("fru1ts", "CVE-2024-44902")
    assert _is_exploit_poc_repo("airbus-cert", "CVE-2024-4040")
    assert _is_exploit_poc_repo("offensive-security", "exploitdb")
    assert _is_exploit_poc_repo("codeb0ss", "CVE-2022-30518-PoC")


def test_is_exploit_poc_repo_allows_env_and_source_repos() -> None:
    from cve_env.tools.github_fetch import _is_exploit_poc_repo

    assert not _is_exploit_poc_repo("vulhub", "vulhub")        # env source (allowlist)
    assert not _is_exploit_poc_repo("apache", "tomcat")        # upstream product
    assert not _is_exploit_poc_repo("zkoss", "zk")             # upstream product
    assert not _is_exploit_poc_repo("someone", "apocalypse")   # no 'poc' substring FP
    assert not _is_exploit_poc_repo("", "")                    # missing → other guard handles


def test_github_fetch_blocks_poc_repo_before_network() -> None:
    # Guard must short-circuit BEFORE the HTTP fetch (offline/registry-independent,
    # never pulls the exploit code).
    from cve_env.tools.github_fetch import github_fetch

    r = github_fetch(owner="0xf4n9x", repo="CVE-2022-24990", path=".")
    assert not r.ok
    assert r.reason_class == "poc_repo_blocked"
    assert "environments, not exploits" in r.reason.lower()
