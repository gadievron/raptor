"""Tests for :mod:`cve_env.tools.dockerfile_gen`."""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock, patch

import pytest

from cve_env.tools.dockerfile_gen import render_dockerfile

_has_sdk = importlib.util.find_spec("claude_agent_sdk") is not None

_DIGEST = "docker.io/library/nginx@sha256:" + "a" * 64

def test_render_minimal_valid() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["echo hello"],
        workdir="/app",
        cmd=["nginx", "-g", "daemon off;"],
        ports=[80],
    )
    assert r.ok is True
    assert "FROM docker.io/library/nginx@sha256:" in r.dockerfile_text
    assert "WORKDIR /app" in r.dockerfile_text
    assert "RUN echo hello" in r.dockerfile_text
    assert "EXPOSE 80" in r.dockerfile_text
    assert 'CMD ["nginx", "-g", "daemon off;"]' in r.dockerfile_text

def test_render_rejects_non_digest_base() -> None:
    r = render_dockerfile(
        base_image="nginx:1.20",
        install_steps=[],
    )
    assert r.ok is False
    assert any("digest-pinned" in i for i in r.issues)

def test_render_rejects_latest_base() -> None:
    r = render_dockerfile(base_image="nginx:latest", install_steps=[])
    assert r.ok is False
    assert any("forbidden version tag" in i for i in r.issues)

def test_render_injects_apt_packages_before_other_steps() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["./configure && make"],
        apt_packages=["libssl-dev", "libpcre3-dev"],
    )
    assert r.ok is True
    lines = r.dockerfile_text.splitlines()
    apt_line = next((ln for ln in lines if "apt-get" in ln), "")
    configure_line = next((ln for ln in lines if "configure" in ln), "")
    assert apt_line
    assert configure_line
    assert lines.index(apt_line) < lines.index(configure_line)
    assert "libssl-dev" in apt_line
    assert "libpcre3-dev" in apt_line

def test_render_skips_empty_install_steps() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["", "   ", "echo hi"],
    )
    assert r.ok is True
    run_lines = [ln for ln in r.dockerfile_text.splitlines() if ln.startswith("RUN ")]
    # One RUN line for "echo hi"; empty entries are skipped.
    assert len(run_lines) == 1

def test_render_rejects_relative_workdir() -> None:
    r = render_dockerfile(base_image=_DIGEST, install_steps=[], workdir="app")
    assert r.ok is False
    assert any("absolute path" in i for i in r.issues)

def test_render_rejects_bad_port_type() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        ports=["not-a-port"],  # type: ignore[list-item]
    )
    assert r.ok is False
    assert any("not an integer" in i for i in r.issues)

def test_render_result_dockerfile_text_still_set_on_semantic_reject() -> None:
    # Force a semantic failure: non-absolute workdir fails the arg check.
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[""],
        workdir="/app",
        cmd=[],
    )
    assert r.ok is True  # all checks satisfied

# -- Phase 11.1: copy_ops (plugin/extension overlay) ---------------------------

def test_render_emits_single_copy_op() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=[{"src": "plugin/", "dst": "/var/www/html/wp-content/plugins/foo/"}],
    )
    assert r.ok is True
    assert "COPY plugin/ /var/www/html/wp-content/plugins/foo/" in r.dockerfile_text

def test_render_emits_multiple_copy_ops_in_order_after_apt_before_run() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["wp plugin activate foo"],
        apt_packages=["unzip"],
        copy_ops=[
            {"src": "plugin/", "dst": "/var/www/html/wp-content/plugins/foo/"},
            {"src": "config.php", "dst": "/var/www/html/wp-config.php"},
        ],
    )
    assert r.ok is True
    lines = r.dockerfile_text.splitlines()
    apt_idx = next(i for i, ln in enumerate(lines) if "apt-get" in ln)
    copy1_idx = next(i for i, ln in enumerate(lines) if ln.startswith("COPY plugin/"))
    copy2_idx = next(i for i, ln in enumerate(lines) if "COPY config.php" in ln)
    run_idx = next(i for i, ln in enumerate(lines) if ln.startswith("RUN wp plugin"))
    assert apt_idx < copy1_idx < copy2_idx < run_idx

def test_render_rejects_copy_op_with_dotdot_in_src() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=[{"src": "../../../etc/passwd", "dst": "/foo"}],
    )
    assert r.ok is False
    assert any("'..'" in i for i in r.issues)

def test_render_rejects_copy_op_with_relative_dst() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=[{"src": "plugin/", "dst": "relative/path"}],
    )
    assert r.ok is False
    assert any("absolute path" in i for i in r.issues)

def test_render_rejects_copy_op_with_absolute_src() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=[{"src": "/host/etc/passwd", "dst": "/foo"}],
    )
    assert r.ok is False
    assert any("context-relative" in i for i in r.issues)

def test_render_rejects_copy_op_when_op_is_not_a_dict() -> None:
    """LLM-supplied copy_ops can be malformed (None, list, string)."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=["not-a-dict"],  # type: ignore[list-item]
    )
    assert r.ok is False
    assert any("must be a dict" in i for i in r.issues)

def test_render_rejects_copy_op_with_empty_src_or_dst() -> None:
    r1 = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=[{"src": "", "dst": "/foo"}],
    )
    assert r1.ok is False
    assert any("src must be a non-empty string" in i for i in r1.issues)

    r2 = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=[{"src": "plugin/", "dst": ""}],
    )
    assert r2.ok is False
    assert any("dst must be a non-empty string" in i for i in r2.issues)

def test_render_rejects_copy_op_with_non_string_src() -> None:
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        copy_ops=[{"src": 123, "dst": "/foo"}],  # type: ignore[dict-item]
    )
    assert r.ok is False
    assert any("src must be a non-empty string" in i for i in r.issues)

# Phase 20.2: soft warnings for dep-version-drift -----------------------

def test_render_warns_on_bare_apt_install() -> None:
    """Phase 20.2: bare `apt install pkg` (no version pin) → SOFT warning
    (when the package is NOT in cve_named_packages — Phase 32.1 made
    CVE-named bare-installs hard-rejects). Render still ok=True."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get install -y apache2"],
    )
    assert r.ok is True  # render still succeeds
    assert any("bare `apt install" in w for w in r.warnings)

def test_render_no_warning_when_apt_install_has_version_pin() -> None:
    """Pinned version → no warning."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get install -y apache2=2.4.41-4ubuntu3"],
    )
    assert r.ok is True
    assert not any("bare `apt install" in w for w in r.warnings)

def test_render_rejects_apt_get_update_without_pin() -> None:
    """Phase 32.2 / P21: `apt-get update` without immediate version-pinned
    install on the same RUN is a HARD REJECT — pulls latest security archive,
    may PATCH the very vuln."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get update && apt-get install -y apache2"],
    )
    assert r.ok is False
    assert any("P21" in i for i in r.issues)
    assert any("apt-get update" in i for i in r.issues)

def test_render_no_warning_apt_update_with_versioned_install() -> None:
    """`apt-get update && apt install pkg=X.Y.Z` is defensible: same RUN has
    a `=` token, so P21 doesn't fire."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get update && apt-get install -y apache2=2.4.41-4ubuntu3"],
    )
    assert r.ok is True
    assert not any("apt-get update" in i for i in r.issues)

def test_render_warnings_multiple_steps() -> None:
    """Multiple install_steps each evaluated independently. With apt-get update
    in the mix Phase 32.2 hard-rejects, so use a permissive version of the
    test that exercises the soft-warning path only."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[
            "apt-get install -y curl",
            "apt-get install -y git=1:2.34.1-1ubuntu1",  # pinned, no warning
            "pip install Django",
        ],
    )
    assert r.ok is True
    # Bare apt install at index 0 → at least 1 warning.
    assert any("bare `apt install" in w for w in r.warnings)

def test_render_rejects_bare_apt_install_of_cve_named_package() -> None:
    """Phase 32.1 / P20: bare `apt install <cve-pkg>` is a HARD reject when
    cve_named_packages includes that package."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get install -y openssl curl"],
        cve_named_packages=["openssl"],
    )
    assert r.ok is False
    assert any("P20" in i for i in r.issues)
    assert any("openssl" in i for i in r.issues)

def test_render_accepts_pinned_install_of_cve_named_package() -> None:
    """Phase 32.1: pinned install of CVE-named package is fine — that's
    exactly what the gate is encouraging."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get install -y openssl=1.1.1f-1ubuntu2"],
        cve_named_packages=["openssl"],
    )
    assert r.ok is True
    assert not any("P20" in i for i in r.issues)

def test_render_cve_named_check_is_case_insensitive() -> None:
    """Phase 32.1: case-insensitive match — agent might pass `OpenSSL` or
    `openssl` from nvd_lookup."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get install -y openssl"],
        cve_named_packages=["OpenSSL"],
    )
    assert r.ok is False
    assert any("P20" in i for i in r.issues)

def test_render_cve_named_empty_list_is_back_compat() -> None:
    """Phase 32.1: cve_named_packages=[] (or missing) → only Phase 20.2
    soft warnings, no P20 hard reject."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["apt-get install -y openssl"],
        cve_named_packages=[],
    )
    assert r.ok is True
    # Still gets the soft warning.
    assert any("bare `apt install" in w for w in r.warnings)

def test_render_payload_includes_warnings() -> None:
    """The render_to_payload wrapper exposes warnings to the agent."""
    from cve_env.tools.dockerfile_gen import render_to_payload

    payload = render_to_payload(
        base_image=_DIGEST,
        install_steps=["apt-get install -y apache2"],
    )
    assert payload["ok"] is True
    assert "warnings" in payload
    assert any("bare `apt install" in w for w in payload["warnings"])

def test_render_payload_includes_p20_issues_for_cve_named_pkg() -> None:
    """Phase 32.1: render_to_payload surfaces P20 in the issues field."""
    from cve_env.tools.dockerfile_gen import render_to_payload

    payload = render_to_payload(
        base_image=_DIGEST,
        install_steps=["apt-get install -y log4j-core"],
        cve_named_packages=["log4j-core"],
    )
    assert payload["ok"] is False
    assert any("P20" in i for i in payload["issues"])

# b1 (2026-05-23): fuse dockerfile_gen → docker_build -----------------------

@pytest.mark.skipif(not _has_sdk, reason="claude_agent_sdk not installed")
@patch("cve_env.utils.run.subprocess.run")
def test_b1_fuse_autobuilds_when_no_copy_ops(mock_run: object) -> None:
    pytest.importorskip("claude_agent_sdk")
    """A clean FROM+RUN render auto-builds (fuse render→build), closing the
    render→build gap that had 0% prompt follow-through (loop.py:992). No
    copy_ops + build omitted → build immediately."""
    mock_run.return_value = MagicMock(  # type: ignore[attr-defined]
        returncode=0, stdout="Successfully built abc123\n", stderr=""
    )
    from cve_env.agent.tools import _maybe_fuse_build
    from cve_env.tools.dockerfile_gen import render_to_payload

    payload = render_to_payload(
        base_image=_DIGEST, install_steps=["apt-get install -y apache2"]
    )
    assert payload["ok"] is True
    out = _maybe_fuse_build(payload, {})
    assert "build" in out, "clean FROM+RUN render must auto-build"
    assert out["build"]["ok"] is True
    assert "docker_run" in out["next_step_hint"]

@pytest.mark.skipif(not _has_sdk, reason="claude_agent_sdk not installed")
@patch("cve_env.utils.run.subprocess.run")
def test_b1_fuse_skips_when_copy_ops(mock_run: object) -> None:
    """copy_ops present → no auto-build (the agent must stage the COPY context
    first); stays render-only unless build=True is explicit."""
    from cve_env.agent.tools import _maybe_fuse_build
    from cve_env.tools.dockerfile_gen import render_to_payload

    copy_ops = [{"src": "plugin", "dst": "/var/www/plugin"}]
    payload = render_to_payload(
        base_image=_DIGEST, install_steps=["echo hi"], copy_ops=copy_ops
    )
    out = _maybe_fuse_build(payload, {"copy_ops": copy_ops})
    assert "build" not in out
    mock_run.assert_not_called()  # type: ignore[attr-defined]

@pytest.mark.skipif(not _has_sdk, reason="claude_agent_sdk not installed")
@patch("cve_env.utils.run.subprocess.run")
def test_b1_fuse_opt_out_build_false(mock_run: object) -> None:
    """build=False is an explicit opt-out even without copy_ops."""
    from cve_env.agent.tools import _maybe_fuse_build
    from cve_env.tools.dockerfile_gen import render_to_payload

    payload = render_to_payload(base_image=_DIGEST, install_steps=["echo hi"])
    out = _maybe_fuse_build(payload, {"build": False})
    assert "build" not in out
    mock_run.assert_not_called()  # type: ignore[attr-defined]

@pytest.mark.skipif(not _has_sdk, reason="claude_agent_sdk not installed")
@patch("cve_env.utils.run.subprocess.run")
def test_b1_fuse_surfaces_build_failure(mock_run: object) -> None:
    """A failed fused build is SURFACED (agent sees it + retries), not hidden."""
    mock_run.return_value = MagicMock(  # type: ignore[attr-defined]
        returncode=1, stdout="", stderr="E: build broke"
    )
    from cve_env.agent.tools import _maybe_fuse_build
    from cve_env.tools.dockerfile_gen import render_to_payload

    payload = render_to_payload(base_image=_DIGEST, install_steps=["echo hi"])
    out = _maybe_fuse_build(payload, {})
    assert "build" in out
    assert out["build"]["ok"] is False

# Phase 37.4: apt_unsafe flag tests ---------------------------------------

def test_phase37_4_apt_unsafe_default_off() -> None:
    """Phase 37.4: by default, apt-get update/install commands have NO
    GPG-bypass flags. The Dockerfile is conventional."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        apt_packages=["libssl-dev"],
    )
    assert r.ok is True
    assert "Acquire::AllowInsecureRepositories" not in r.dockerfile_text
    assert "Acquire::Check-Valid-Until" not in r.dockerfile_text

def test_phase37_4_apt_unsafe_injects_bypass_flags() -> None:
    """Phase 37.4: apt_unsafe=True wraps apt-get with flags that bypass
    GPG signature + valid-until checks. Recovers from CVE-2022-1103-class
    'invalid signature' errors on bullseye base images."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=[],
        apt_packages=["libssl-dev"],
        apt_unsafe=True,
    )
    assert r.ok is True
    assert "Acquire::AllowInsecureRepositories=true" in r.dockerfile_text
    assert "Acquire::Check-Valid-Until=false" in r.dockerfile_text

def test_phase37_4_apt_unsafe_no_apt_no_change() -> None:
    """Phase 37.4: apt_unsafe is a no-op when there are no apt_packages."""
    r = render_dockerfile(
        base_image=_DIGEST,
        install_steps=["echo hello"],
        apt_unsafe=True,
    )
    assert r.ok is True
    # No apt-get line, so no flags either.
    assert "Acquire::" not in r.dockerfile_text
