"""Tests for the inline-install parser (Dockerfile / devcontainer / sh / GHA)."""

from __future__ import annotations

from pathlib import Path


from packages.sca.parsers.inline_installs import (
    parse_devcontainer_json,
    parse_dockerfile,
    parse_gha_workflow,
    parse_shell_script,
)


def _write(tmp_path: Path, body: str, name: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------

def test_dockerfile_pip_pin(tmp_path: Path) -> None:
    p = _write(tmp_path, "FROM python:3.12\nRUN pip install django==4.2.7\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "PyPI"
    assert d.name == "django"
    assert d.version == "4.2.7"
    assert d.purl == "pkg:pypi/django@4.2.7"
    assert d.source_kind == "dockerfile"


def test_dockerfile_apt_pin(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "FROM debian:11\nRUN apt-get install -y nginx=1.18.0-6.1\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "Debian"
    assert d.name == "nginx"
    assert d.version == "1.18.0-6.1"
    assert d.purl == "pkg:deb/debian/nginx@1.18.0-6.1"


def test_dockerfile_yum_pin(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN yum install -y nginx-1.18.0\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "Red Hat"
    assert deps[0].name == "nginx"
    assert deps[0].version == "1.18.0"


def test_dockerfile_dnf_pin(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN dnf install -y httpd-2.4.51\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "Red Hat"
    assert deps[0].name == "httpd"
    assert deps[0].version == "2.4.51"


def test_dockerfile_apk_pin(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN apk add nginx=1.18.0-r0\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "Alpine"
    assert deps[0].name == "nginx"
    assert deps[0].version == "1.18.0-r0"


def test_dockerfile_continuation(tmp_path: Path) -> None:
    """Backslash-continued ``RUN`` lines join into one logical line."""
    body = (
        "RUN pip install \\\n"
        "    django==4.2.7 \\\n"
        "    requests==2.31.0\n"
    )
    p = _write(tmp_path, body, "Dockerfile")
    deps = parse_dockerfile(p)
    names = sorted(d.name for d in deps)
    assert names == ["django", "requests"]


def test_dockerfile_chained_commands(tmp_path: Path) -> None:
    """``apt update && apt install foo`` — split on ``&&``."""
    p = _write(tmp_path,
               "RUN apt-get update && apt-get install -y curl=7.88.1-1\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "curl"
    assert deps[0].version == "7.88.1-1"


def test_dockerfile_unpinned_emits_wildcard(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN pip install requests\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].version is None


def test_dockerfile_skips_dash_r(tmp_path: Path) -> None:
    """``-r requirements.txt`` is not a package — discovery picks that up."""
    p = _write(tmp_path,
               "RUN pip install --no-cache-dir -r /tmp/requirements.txt\n",
               "Dockerfile")
    assert parse_dockerfile(p) == []


def test_dockerfile_python_m_pip(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN python3 -m pip install pytest==8.1.1\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "pytest"


def test_dockerfile_commented_run(tmp_path: Path) -> None:
    """``# RUN pip install foo==1.2.3`` — surfaced with commented_out=True."""
    p = _write(tmp_path, "# RUN pip install django==4.2.7\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "django"
    assert deps[0].commented_out is True


def test_dockerfile_inline_comment_stripped(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN pip install django==4.2.7  # pin for compat\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "django"


def test_dockerfile_apt_target_release_skipped(tmp_path: Path) -> None:
    """``apt install -t bullseye-backports nginx`` — ``bullseye-backports``
    is the value of ``-t``, not a package."""
    p = _write(tmp_path,
               "RUN apt-get install -t bullseye-backports nginx=1.18.0\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    names = sorted(d.name for d in deps)
    assert names == ["nginx"]


def test_dockerfile_yum_enablerepo_skipped(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN yum install --enablerepo=epel nginx-1.18.0\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    # ``--enablerepo=epel`` has the value in-token, no skip; nginx is the dep.
    names = sorted(d.name for d in deps)
    assert names == ["nginx"]


def test_dockerfile_apt_multiple(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN apt install -y curl=7.88.1-1 wget=1.21-1 nginx\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"curl", "wget", "nginx"}
    assert by_name["nginx"].version is None  # unpinned still surfaces


# ---------------------------------------------------------------------------
# Dockerfile — improvements inherited from core.dockerfile.apt
# (sudo, pipe, subshell parens, bash -c, multi-stage attribution,
# comment-in-continuation). These shapes were previously missed or
# mis-parsed by the legacy regex scanner.
# ---------------------------------------------------------------------------

def test_dockerfile_sudo_prefix_via_core(tmp_path: Path) -> None:
    """``sudo apt-get install -y curl`` — the sudo prefix is now
    stripped (was missed by the regex scanner)."""
    p = _write(tmp_path, "FROM ubuntu\nRUN sudo apt-get install -y curl\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    debian = [d for d in deps if d.ecosystem == "Debian"]
    assert [d.name for d in debian] == ["curl"]


def test_dockerfile_bash_c_recursion_via_core(tmp_path: Path) -> None:
    """``bash -c "apt-get install -y curl"`` — shlex unquotes the
    body and the apt extractor recurses into it."""
    p = _write(tmp_path,
               'FROM debian\nRUN bash -c "apt-get install -y curl"\n',
               "Dockerfile")
    deps = parse_dockerfile(p)
    debian = [d for d in deps if d.ecosystem == "Debian"]
    assert [d.name for d in debian] == ["curl"]


def test_dockerfile_pipe_separator_via_core(tmp_path: Path) -> None:
    """``yes | apt-get install -y curl`` — pipes split commands."""
    p = _write(tmp_path,
               "FROM debian\nRUN yes | apt-get install -y curl\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    debian = [d for d in deps if d.ecosystem == "Debian"]
    assert [d.name for d in debian] == ["curl"]


def test_dockerfile_multi_stage_scope_attribution(tmp_path: Path) -> None:
    """Multi-stage builds: each apt dep carries the AS-stage in
    its ``scope`` field so SCA can build per-stage SBOMs."""
    p = _write(tmp_path,
               "FROM debian AS builder\nRUN apt-get install -y gcc\n"
               "FROM debian AS runtime\nRUN apt-get install -y libc6\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    by_name = {d.name: d for d in deps if d.ecosystem == "Debian"}
    assert by_name["gcc"].scope == "builder"
    assert by_name["libc6"].scope == "runtime"


def test_dockerfile_comment_in_continuation_via_core(tmp_path: Path) -> None:
    """``# comment`` lines inside a multi-line RUN no longer
    terminate the continuation — packages on lines after a comment
    are picked up. (Fixed in core.dockerfile.parser.)"""
    p = _write(
        tmp_path,
        "FROM debian\n"
        "RUN apt-get install -y \\\n"
        "    curl \\\n"
        "    # explainer\n"
        "    wget\n",
        "Dockerfile",
    )
    deps = parse_dockerfile(p)
    debian = sorted(d.name for d in deps if d.ecosystem == "Debian")
    assert debian == ["curl", "wget"]


def test_dockerfile_apt_skipped_in_legacy_scanner(tmp_path: Path) -> None:
    """The legacy regex shell scanner now skips apt entirely so
    Debian deps aren't double-counted between the two passes."""
    p = _write(tmp_path,
               "FROM debian\nRUN apt-get install -y curl\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    # Exactly one Debian dep — would be 2 if both passes emitted.
    assert sum(1 for d in deps if d.ecosystem == "Debian") == 1


def test_dockerfile_pip_still_via_legacy_scanner(tmp_path: Path) -> None:
    """Non-apt managers still go through the legacy scanner — the
    refactor only short-circuits Debian."""
    p = _write(tmp_path,
               "FROM python:3.12\n"
               "RUN apt-get install -y curl\n"
               "RUN pip install django==4.2.7\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    by_eco = {d.ecosystem: d.name for d in deps}
    assert by_eco == {"Debian": "curl", "PyPI": "django"}


# ---------------------------------------------------------------------------
# devcontainer.json
# ---------------------------------------------------------------------------

def test_devcontainer_post_create_string(tmp_path: Path) -> None:
    body = """\
{
  "image": "python:3.12",
  "postCreateCommand": "pip install django==4.2.7"
}
"""
    p = _write(tmp_path, body, "devcontainer.json")
    deps = parse_devcontainer_json(p)
    assert len(deps) == 1
    assert deps[0].name == "django"
    assert deps[0].source_kind == "devcontainer"


def test_devcontainer_post_create_array(tmp_path: Path) -> None:
    body = """\
{
  "postCreateCommand": [
    "pip install django==4.2.7",
    "pip install requests==2.31.0"
  ]
}
"""
    p = _write(tmp_path, body, "devcontainer.json")
    deps = parse_devcontainer_json(p)
    names = sorted(d.name for d in deps)
    assert names == ["django", "requests"]


def test_devcontainer_with_jsonc_comments(tmp_path: Path) -> None:
    """devcontainer.json allows ``//`` line comments — tolerate them."""
    body = """\
{
  // image must match CI
  "image": "python:3.12",
  "postCreateCommand": "pip install requests==2.31.0",
}
"""
    p = _write(tmp_path, body, "devcontainer.json")
    deps = parse_devcontainer_json(p)
    assert len(deps) == 1
    assert deps[0].name == "requests"


def test_devcontainer_chained_command(tmp_path: Path) -> None:
    body = """\
{
  "postCreateCommand": "pip install -r req.txt && pip install black==24.1.0"
}
"""
    p = _write(tmp_path, body, "devcontainer.json")
    deps = parse_devcontainer_json(p)
    # The `-r req.txt` invocation has no pkg arg; black is the real install.
    assert len(deps) == 1
    assert deps[0].name == "black"


# ---------------------------------------------------------------------------
# Shell script
# ---------------------------------------------------------------------------

def test_shell_script_basic(tmp_path: Path) -> None:
    body = """\
#!/usr/bin/env bash
set -e
pip install django==4.2.7
apt-get install -y nginx=1.18.0-6
"""
    p = _write(tmp_path, body, "install.sh")
    deps = parse_shell_script(p)
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"django", "nginx"}
    assert by_name["django"].source_kind == "shell_script"
    assert by_name["django"].ecosystem == "PyPI"
    assert by_name["nginx"].ecosystem == "Debian"


def test_shell_script_continuation(tmp_path: Path) -> None:
    body = (
        "pip install \\\n"
        "    django==4.2.7 \\\n"
        "    requests==2.31.0\n"
    )
    p = _write(tmp_path, body, "install.sh")
    deps = parse_shell_script(p)
    assert sorted(d.name for d in deps) == ["django", "requests"]


# ---------------------------------------------------------------------------
# GHA workflows
# ---------------------------------------------------------------------------

def test_gha_block_run(tmp_path: Path) -> None:
    body = """\
name: tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: install
        run: |
          python -m pip install --upgrade pip
          pip install pytest==8.1.1
"""
    p = _write(tmp_path, body, "tests.yml")
    deps = parse_gha_workflow(p)
    by_name = {d.name: d for d in deps}
    assert "pytest" in by_name
    assert by_name["pytest"].version == "8.1.1"
    assert by_name["pytest"].source_kind == "gha_workflow"


def test_gha_inline_run(tmp_path: Path) -> None:
    body = """\
jobs:
  test:
    steps:
      - run: pip install black==24.1.0
"""
    p = _write(tmp_path, body, "lint.yml")
    deps = parse_gha_workflow(p)
    assert len(deps) == 1
    assert deps[0].name == "black"


# ---------------------------------------------------------------------------
# Discovery → parser dispatch (predicate registration)
# ---------------------------------------------------------------------------

def test_dispatch_dockerfile_via_predicate(tmp_path: Path) -> None:
    """Discovery + parser-registry round-trip: a Dockerfile gets routed."""
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest

    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install django==4.2.7\n", encoding="utf-8")

    manifests = find_manifests(repo)
    assert any(m.path.name == "Dockerfile" and m.ecosystem == "Inline"
               for m in manifests)

    df_manifest = next(m for m in manifests if m.path.name == "Dockerfile")
    deps = parse_manifest(df_manifest)
    assert len(deps) == 1
    assert deps[0].name == "django"


def test_dispatch_gha_workflow_via_path(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest

    wf_dir = tmp_path / "proj" / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - run: pip install pytest==8.1.1\n",
        encoding="utf-8",
    )

    manifests = find_manifests(tmp_path / "proj")
    wf_manifests = [m for m in manifests if m.path.suffix == ".yml"]
    assert wf_manifests
    deps = parse_manifest(wf_manifests[0])
    assert deps and deps[0].name == "pytest"


def test_pipeline_toggle_filters_inline(tmp_path: Path) -> None:
    """``enable_inline_installs=False`` drops the inline manifests."""
    from packages.sca.discovery import find_manifests

    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "Dockerfile").write_text("RUN pip install x==1.0\n",
                                      encoding="utf-8")
    (repo / "requirements.txt").write_text("django==4.2.7\n",
                                             encoding="utf-8")

    manifests = find_manifests(repo)
    inline = [m for m in manifests if m.ecosystem == "Inline"]
    others = [m for m in manifests if m.ecosystem != "Inline"]
    assert inline and others


def test_dockerfile_with_extension(tmp_path: Path) -> None:
    """Variants like ``Dockerfile.dev`` are recognised."""
    p = _write(tmp_path, "RUN pip install django==4.2.7\n", "Dockerfile.dev")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "django"


# ---------------------------------------------------------------------------
# npm / yarn / pnpm
# ---------------------------------------------------------------------------

def test_dockerfile_npm_install_pinned(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN npm install -g lodash@4.17.21\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    d = deps[0]
    assert d.ecosystem == "npm"
    assert d.name == "lodash"
    assert d.version == "4.17.21"
    assert d.purl == "pkg:npm/lodash@4.17.21"


def test_dockerfile_npm_scoped(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN npm install -g @anthropic-ai/claude-code@1.0.0\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "@anthropic-ai/claude-code"
    assert deps[0].version == "1.0.0"


def test_dockerfile_npm_scoped_unpinned(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN npm install -g @anthropic-ai/claude-code\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "@anthropic-ai/claude-code"
    assert deps[0].version is None


def test_dockerfile_yarn_add(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN yarn add react@18.2.0\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "react"
    assert deps[0].version == "18.2.0"
    assert deps[0].ecosystem == "npm"


def test_dockerfile_pnpm_add(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN pnpm add typescript@5.3.3 prettier\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    by_name = {d.name: d for d in deps}
    assert by_name["typescript"].version == "5.3.3"
    assert by_name["prettier"].version is None


def test_dockerfile_npm_caret_range(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN npm install lodash@^4.17.0\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "lodash"
    assert deps[0].version == "4.17.0"
    assert deps[0].pin_style.value == "caret"


# ---------------------------------------------------------------------------
# pipx / uv pip
# ---------------------------------------------------------------------------

def test_pipx_install(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN pipx install black==24.1.0\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "PyPI"
    assert deps[0].name == "black"
    assert deps[0].version == "24.1.0"


def test_uv_pip_install(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN uv pip install pytest==8.1.1\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "PyPI"
    assert deps[0].name == "pytest"


# ---------------------------------------------------------------------------
# cargo / gem / brew / go
# ---------------------------------------------------------------------------

def test_cargo_install_with_version(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN cargo install ripgrep --version 14.1.0\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "Cargo"
    assert deps[0].name == "ripgrep"
    assert deps[0].version == "14.1.0"
    assert deps[0].purl == "pkg:cargo/ripgrep@14.1.0"


def test_cargo_install_unpinned(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN cargo install ripgrep\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "ripgrep"
    assert deps[0].version is None


def test_gem_install_with_version(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN gem install rake -v 13.0.6\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "RubyGems"
    assert deps[0].name == "rake"
    assert deps[0].version == "13.0.6"


def test_gem_install_long_version_flag(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN gem install bundler --version 2.5.10\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "bundler"
    assert deps[0].version == "2.5.10"


def test_brew_install_versioned(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN brew install python@3.12 nginx\n", "Dockerfile")
    deps = parse_dockerfile(p)
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"python", "nginx"}
    assert by_name["python"].version == "3.12"
    assert by_name["nginx"].version is None
    assert by_name["python"].ecosystem == "Homebrew"


def test_go_install(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN go install github.com/foo/bar@v1.2.3\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "Go"
    assert deps[0].name == "github.com/foo/bar"
    assert deps[0].version == "v1.2.3"


def test_go_install_latest_unpinned(tmp_path: Path) -> None:
    """``@latest`` pins to whatever's current — treat as unpinned."""
    p = _write(tmp_path,
               "RUN go install github.com/foo/bar@latest\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].version is None


def test_npx_inline(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN npx prettier@3.0.0 --write .\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "npm"
    assert deps[0].name == "prettier"
    assert deps[0].version == "3.0.0"


def test_npx_first_positional_only(tmp_path: Path) -> None:
    """``npx create-react-app my-app`` — ``my-app`` is the cmd arg, not a pkg."""
    p = _write(tmp_path,
               "RUN npx create-react-app my-app --typescript\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "create-react-app"
    assert deps[0].version is None


def test_npx_package_flag(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN npx -p typescript@5.3.3 tsc --version\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "typescript"
    assert deps[0].version == "5.3.3"


def test_npx_multiple_packages(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN npx --package=foo@1.0 --package=bar@2.0 cmd\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {"foo", "bar"}
    assert by_name["foo"].version == "1.0"


def test_bunx_inline(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN bunx esbuild@0.20.0 build.ts\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "esbuild"
    assert deps[0].version == "0.20.0"


def test_pnpm_dlx(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN pnpm dlx vite@5.0.0\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "vite"
    assert deps[0].version == "5.0.0"


def test_yarn_dlx(tmp_path: Path) -> None:
    p = _write(tmp_path, "RUN yarn dlx tsx@4.0.0 script.ts\n", "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "tsx"
    assert deps[0].version == "4.0.0"


def test_npx_scoped_package(tmp_path: Path) -> None:
    p = _write(tmp_path,
               "RUN npx @anthropic-ai/claude-code@1.0.0 --help\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "@anthropic-ai/claude-code"
    assert deps[0].version == "1.0.0"


def test_dockerfile_npm_skips_url(tmp_path: Path) -> None:
    """``npm install git+https://...`` — URL form, skip."""
    p = _write(tmp_path,
               "RUN npm install git+https://github.com/foo/bar.git\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert deps == []


# ---------------------------------------------------------------------------
# PEP 508 multi-specifier shapes — REGRESSION for the dogfood bug
# ---------------------------------------------------------------------------
#
# `pip install 'urllib3>=2.0,<3.0'` was producing
# ``version="2.0,<3.0"`` (whole post-operator string, regex bug),
# which OSV-matched against every old urllib3 1.x advisory because
# the version comparator couldn't parse the nonsense string.
#
# Now the inline-install parser consumes the same
# ``packaging.specifiers.SpecifierSet`` engine the requirements.txt
# parser uses, so multi-spec pins emit RANGE with version=None —
# matching what requirements.txt already does for the same syntax.

def test_pip_range_multi_spec_yields_no_exact_version(tmp_path: Path):
    """``urllib3>=2.0,<3.0`` is RANGE with no exact version — does
    not produce a phantom version='2.0,<3.0' that OSV-matches against
    1.x advisories."""
    p = _write(tmp_path,
               "RUN pip install 'urllib3>=2.0,<3.0'\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "urllib3"
    assert deps[0].version is None, (
        f"got version={deps[0].version!r}; range pins must NOT emit "
        f"a fake version that OSV will match against"
    )
    assert deps[0].pin_style.value == "range"


def test_pip_range_with_exclusion_is_also_range_no_version(tmp_path: Path):
    """``foo>=1.0,!=1.5`` — multi-spec with exclusion is RANGE."""
    p = _write(tmp_path,
               "RUN pip install 'requests>=2.31,!=2.32.0'\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].version is None
    assert deps[0].pin_style.value == "range"


def test_pip_single_lower_bound_keeps_version(tmp_path: Path):
    """``foo>=1.2.3`` — single bound IS a RANGE, but the lower
    bound is meaningful enough to OSV-query against. Keep it."""
    p = _write(tmp_path,
               "RUN pip install 'requests>=2.31.0'\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"
    assert deps[0].pin_style.value == "range"


def test_pip_exact_pin_unchanged(tmp_path: Path):
    """Sanity: ``foo==1.2.3`` still produces EXACT with the right version."""
    p = _write(tmp_path,
               "RUN pip install 'numpy==1.26.4'\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].name == "numpy"
    assert deps[0].version == "1.26.4"
    assert deps[0].pin_style.value == "exact"


def test_pip_compatible_release_unchanged(tmp_path: Path):
    """``foo~=1.2.3`` still produces TILDE with the right version."""
    p = _write(tmp_path,
               "RUN pip install 'pyyaml~=6.0'\n",
               "Dockerfile")
    deps = parse_dockerfile(p)
    assert len(deps) == 1
    assert deps[0].pin_style.value == "tilde"
    assert deps[0].version == "6.0"


# ---------------------------------------------------------------------------
# Comment-only-at-start rule (parser-FP defence)
# ---------------------------------------------------------------------------

def test_gha_workflow_prose_mentioning_pip_install_does_not_extract(
    tmp_path: Path,
) -> None:
    """Free-form comments that happen to contain ``pip install``
    mid-sentence must NOT emit deps. Discovered 2026-05-20 against
    ``.github/workflows/lint.yml`` which had::

        # grep + uv pip install keeps a single source of truth.

    The parser was stripping the leading ``#`` and treating the
    remainder as shell code, then taking the tokens after
    ``pip install`` as package names (``keeps``, ``a``, ``single``,
    ``source``, ``of``, ``truth.``). Several of those (``a``,
    ``single``, ``source``, ``of``) are real squatted PyPI packages
    that ``harden`` then proposed promoting — operationally
    serious.

    Fix: when a line was commented, only accept matches whose
    install verb starts at position 0 of the (post-``#``-strip)
    body.
    """
    wf = """name: lint
on: [push]
jobs:
  ruff:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # grep + uv pip install keeps a single source of truth.
          uv pip install "$(grep -E '^ruff==' requirements-dev.txt)"
"""
    p = _write(tmp_path, wf, "lint.yml")
    deps = parse_gha_workflow(p)
    # The real ``uv pip install "..."`` line uses ``$(grep ...)`` so
    # the resolved arg isn't a literal pkg name — the parser declines
    # to emit anything actionable from it. That's expected.
    # The KEY assertion: no bogus ``a`` / ``single`` / ``source`` /
    # ``of`` / ``keeps`` / ``truth`` deps from the comment line.
    bogus_names = {"a", "single", "source", "of", "keeps", "truth"}
    extracted_names = {d.name for d in deps}
    assert not (bogus_names & extracted_names), (
        f"parser extracted bogus packages from prose comment: "
        f"{bogus_names & extracted_names}"
    )


def test_shell_commented_pip_install_at_start_still_extracts(
    tmp_path: Path,
) -> None:
    """The deliberate ``# pip install foo==1.0`` hint convention
    must still work — the verb is at the start of the comment
    body, so ``m.start() == 0`` and extraction proceeds."""
    p = _write(tmp_path,
               "#!/bin/sh\n# pip install django==4.2.7\n",
               "install.sh")
    deps = parse_shell_script(p)
    assert len(deps) == 1
    assert deps[0].name == "django"
    assert deps[0].version == "4.2.7"
    assert deps[0].commented_out is True


def test_shell_prose_with_embedded_pip_install_does_not_extract(
    tmp_path: Path,
) -> None:
    """Shell-script equivalent of the lint.yml regression. Prose
    that mentions ``pip install`` partway through a sentence is not
    an install hint."""
    p = _write(tmp_path,
               "#!/bin/sh\n"
               "# don't forget to pip install requests before running\n",
               "setup.sh")
    deps = parse_shell_script(p)
    extracted_names = {d.name for d in deps}
    # ``requests``, ``before``, ``running`` would all be bogus.
    assert not extracted_names, (
        f"parser extracted from prose comment: {extracted_names}"
    )
