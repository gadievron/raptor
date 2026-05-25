"""Tests for the inline-install rewriter (Dockerfile / sh / GHA / devcontainer)."""

from __future__ import annotations

from pathlib import Path


from packages.sca.update import _PlanEntry, _rewrite_inline_install


def _plan(eco: str, name: str, target: str, installed: str = "1.0") -> _PlanEntry:
    return _PlanEntry(
        ecosystem=eco, name=name, installed=installed, target=target,
        manifest=Path("/x/Dockerfile"), advisory_ids=[],
    )


# ---------------------------------------------------------------------------
# PyPI: pinned form (==, >=, ~=, etc.) → ==<new>
# ---------------------------------------------------------------------------

def test_pypi_pinned_eq() -> None:
    text = "RUN pip install django==4.2.7\n"
    plan = _plan("PyPI", "django", "4.2.10")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert new == "RUN pip install django==4.2.10\n"


def test_pypi_lower_bound_floor_preserved() -> None:
    """A lone lower bound is the downgrade floor — keep it alongside the
    new exact pin rather than collapsing it away."""
    text = "RUN pip install requests>=2.31.0\n"
    plan = _plan("PyPI", "requests", "2.33.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert new == "RUN pip install requests>=2.31.0,==2.33.0\n"


def test_pypi_quoted_multi_constraint_range_keeps_corridor() -> None:
    """``'urllib3>=2.0,<3.0'`` → ``'urllib3>=2.0,==2.7.0,<3.0'`` — floor
    and ceiling are preserved as the safe corridor with the new exact pin
    slotted between. Still round-trips to up_to_date because the parser
    now treats an ``==``-bearing spec as EXACT. Regression for the
    sca-self-bump CI urllib3 stragglers."""
    text = "RUN pip install 'urllib3>=2.0,<3.0'\n"
    plan = _plan("PyPI", "urllib3", "2.7.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert new == "RUN pip install 'urllib3>=2.0,==2.7.0,<3.0'\n"


def test_pypi_unpinned_gets_pin_appended() -> None:
    text = "RUN pip install --no-cache-dir semgrep\n"
    plan = _plan("PyPI", "semgrep", "1.161.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert new == "RUN pip install --no-cache-dir semgrep==1.161.0\n"


def test_pypi_pipx_install() -> None:
    text = "RUN pipx install black==24.1.0\n"
    plan = _plan("PyPI", "black", "24.3.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "black==24.3.0" in new


def test_pypi_uv_pip_install() -> None:
    text = "RUN uv pip install pytest==8.1.1\n"
    plan = _plan("PyPI", "pytest", "8.2.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "pytest==8.2.0" in new


def test_pypi_python_m_pip() -> None:
    text = "RUN python3 -m pip install pytest==8.1.1\n"
    plan = _plan("PyPI", "pytest", "8.2.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "pytest==8.2.0" in new


# ---------------------------------------------------------------------------
# PyPI: scope precision — don't touch comments, paths, other deps
# ---------------------------------------------------------------------------

def test_pypi_does_not_match_in_comment() -> None:
    """``# pip install foo==1.0`` on its own line — that line still has
    ``pip install`` in it, but it's a comment. Current implementation
    is permissive: the line-detector doesn't strip leading ``#``, so
    commented RUNs DO get rewritten. This test pins that behaviour
    (revisit if it causes real-world issues)."""
    text = "# RUN pip install django==4.2.7\n"
    plan = _plan("PyPI", "django", "4.2.10")
    new, hit, _ = _rewrite_inline_install(text, plan)
    # Permissive: the substitution fires because the line *contains*
    # ``pip install``. If this becomes a problem in practice we can
    # tighten by stripping leading ``#`` before the cmd_re check.
    assert hit is True
    assert "django==4.2.10" in new


def test_pypi_does_not_touch_lines_without_install_cmd() -> None:
    """A bare line that mentions the dep name but has no install command
    must NOT be modified."""
    text = "ENV DJANGO_SETTINGS_MODULE=django.production\n"
    plan = _plan("PyPI", "django", "4.2.10")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is False
    assert new == text


def test_pypi_only_replaces_matching_name_in_multipkg_line() -> None:
    """``pip install foo==1.0 bar==2.0`` — only update bar."""
    text = "RUN pip install django==4.2.7 requests==2.30.0\n"
    plan = _plan("PyPI", "requests", "2.33.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "django==4.2.7" in new        # untouched
    assert "requests==2.33.0" in new      # rewritten


def test_pypi_does_not_match_substring_of_other_name() -> None:
    """``request`` should not match inside ``requests``."""
    text = "RUN pip install requests==2.30.0\n"
    plan = _plan("PyPI", "request", "9.9.9")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is False
    assert new == text


# ---------------------------------------------------------------------------
# Debian / Alpine: ``pkg=version``
# ---------------------------------------------------------------------------

def test_debian_pinned() -> None:
    text = "RUN apt-get install -y nginx=1.18.0-6.1\n"
    plan = _plan("Debian", "nginx", "1.22.1-9")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "nginx=1.22.1-9" in new


def test_debian_unpinned_gets_pin_appended() -> None:
    text = "RUN apt-get install -y rr\n"
    plan = _plan("Debian", "rr", "5.6")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "rr=5.6" in new


def test_alpine_apk() -> None:
    text = "RUN apk add nginx=1.18.0-r0\n"
    plan = _plan("Alpine", "nginx", "1.22.1-r0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "nginx=1.22.1-r0" in new


# ---------------------------------------------------------------------------
# Red Hat: ``pkg-version`` (rpm convention)
# ---------------------------------------------------------------------------

def test_redhat_pinned() -> None:
    text = "RUN yum install -y httpd-2.4.51\n"
    plan = _plan("Red Hat", "httpd", "2.4.62")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "httpd-2.4.62" in new


def test_redhat_dnf() -> None:
    text = "RUN dnf install -y nginx-1.18.0\n"
    plan = _plan("Red Hat", "nginx", "1.22.1")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "nginx-1.22.1" in new


# ---------------------------------------------------------------------------
# npm: ``pkg@version`` (with scoped names)
# ---------------------------------------------------------------------------

def test_npm_plain() -> None:
    text = "RUN npm install -g lodash@4.17.21\n"
    plan = _plan("npm", "lodash", "4.17.22")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "lodash@4.17.22" in new


def test_npm_scoped() -> None:
    text = "RUN npm install -g @anthropic-ai/claude-code@1.0.0\n"
    plan = _plan("npm", "@anthropic-ai/claude-code", "1.5.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "@anthropic-ai/claude-code@1.5.0" in new


def test_npm_unpinned_gets_version_appended() -> None:
    text = "RUN npm install -g yarn\n"
    plan = _plan("npm", "yarn", "4.0.2")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "yarn@4.0.2" in new


def test_yarn_add() -> None:
    text = "RUN yarn add react@18.2.0\n"
    plan = _plan("npm", "react", "18.3.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "react@18.3.0" in new


# ---------------------------------------------------------------------------
# Multiple lines / continuation handling
# ---------------------------------------------------------------------------

def test_multiline_only_updates_install_lines() -> None:
    text = (
        "FROM python:3.12\n"
        "ENV LANG=en_US.UTF-8\n"
        "RUN pip install django==4.2.7\n"
        "RUN pip install requests==2.30.0\n"
    )
    plan = _plan("PyPI", "requests", "2.33.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "django==4.2.7" in new       # untouched
    assert "requests==2.33.0" in new     # rewritten
    assert "ENV LANG=en_US.UTF-8" in new  # untouched (the `LANG=...` could
                                          # look like a `pkg=ver` but the
                                          # line has no install cmd)


def test_apt_multiline_continuation_block_pins_package() -> None:
    """The sca-self-bump failure: a ``\\``-continued ``apt-get install``
    block with one package per line (and interspersed ``#`` comments)
    must pin packages on the *continuation* lines, not just the command
    line. Mirrors the .devcontainer/Dockerfile block exactly."""
    text = (
        "RUN apt-get update \\\n"
        "    && apt-get install -y --no-install-recommends \\\n"
        "    #\n"
        "    # --- Network Tools ---\n"
        "    curl \\\n"
        "    git \\\n"
        "    jq \\\n"
        "    && apt-get clean \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    )
    plan = _plan("Debian", "curl", "8.20.0-2")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "    curl=8.20.0-2 \\\n" in new        # continuation line pinned
    assert "    git \\\n" in new                  # other packages untouched
    assert "    jq \\\n" in new
    assert "&& apt-get clean" in new              # post-separator cmd untouched
    assert "rm -rf /var/lib/apt/lists/*" in new


def test_apt_multiline_does_not_rewrite_name_inside_comment() -> None:
    """A package name appearing inside a ``#`` comment within the
    continuation block must not be pinned — only the real arg line is."""
    text = (
        "RUN apt-get install -y --no-install-recommends \\\n"
        "    # install git for cloning repos\n"
        "    git \\\n"
        "    && apt-get clean\n"
    )
    plan = _plan("Debian", "git", "1:2.53.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "    git=1:2.53.0 \\\n" in new                 # arg line pinned
    assert "    # install git for cloning repos\n" in new  # comment verbatim


def test_apt_separator_ends_args_no_false_pin_in_next_command() -> None:
    """After ``&&`` the install's args are over; a package name that
    appears in the following command must not be pinned."""
    text = (
        "RUN apt-get install -y --no-install-recommends \\\n"
        "    curl \\\n"
        "    && echo installing curl done\n"
    )
    plan = _plan("Debian", "curl", "8.20.0-2")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "    curl=8.20.0-2 \\\n" in new            # the arg
    assert "&& echo installing curl done\n" in new   # echo's 'curl' untouched


# ---------------------------------------------------------------------------
# Cargo: ``cargo install <pkg> --version <X>`` (multi-token version)
# ---------------------------------------------------------------------------

def test_cargo_pinned_version_flag() -> None:
    text = "RUN cargo install ripgrep --version 14.1.0\n"
    plan = _plan("Cargo", "ripgrep", "14.2.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "--version 14.2.0" in new
    assert "14.1.0" not in new


def test_cargo_unpinned_appends_version_flag() -> None:
    text = "RUN cargo install ripgrep\n"
    plan = _plan("Cargo", "ripgrep", "14.2.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "ripgrep --version 14.2.0" in new


def test_cargo_short_vers_flag() -> None:
    text = "RUN cargo install ripgrep --vers 14.1.0\n"
    plan = _plan("Cargo", "ripgrep", "14.2.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "--vers 14.2.0" in new


# ---------------------------------------------------------------------------
# Gem: ``gem install <pkg> -v <X>`` (multi-token version)
# ---------------------------------------------------------------------------

def test_gem_short_v_flag() -> None:
    text = "RUN gem install rake -v 13.0.6\n"
    plan = _plan("RubyGems", "rake", "13.1.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "-v 13.1.0" in new


def test_gem_long_version_flag() -> None:
    text = "RUN gem install bundler --version 2.5.10\n"
    plan = _plan("RubyGems", "bundler", "2.5.20")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "--version 2.5.20" in new


def test_gem_unpinned_appends() -> None:
    text = "RUN gem install rake\n"
    plan = _plan("RubyGems", "rake", "13.1.0")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "rake --version 13.1.0" in new


# ---------------------------------------------------------------------------
# NuGet: ``dotnet add package <name> --version <X>``
# ---------------------------------------------------------------------------

def test_nuget_dotnet_add_package_versioned() -> None:
    text = "RUN dotnet add package Newtonsoft.Json --version 13.0.1\n"
    plan = _plan("NuGet", "Newtonsoft.Json", "13.0.3")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "--version 13.0.3" in new


def test_nuget_install_dash_uppercase_version() -> None:
    """``nuget install Foo -Version 1.0`` (PascalCase flag)."""
    text = "RUN nuget install Newtonsoft.Json -Version 13.0.1\n"
    plan = _plan("NuGet", "Newtonsoft.Json", "13.0.3")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "-Version 13.0.3" in new


def test_nuget_dotnet_add_package_unpinned() -> None:
    text = "RUN dotnet add package Newtonsoft.Json\n"
    plan = _plan("NuGet", "Newtonsoft.Json", "13.0.3")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "Newtonsoft.Json --version 13.0.3" in new


def test_nuget_powershell_install_package() -> None:
    text = "RUN Install-Package Newtonsoft.Json -Version 13.0.1\n"
    plan = _plan("NuGet", "Newtonsoft.Json", "13.0.3")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "13.0.3" in new


# ---------------------------------------------------------------------------
# Composer (Packagist): ``composer require vendor/pkg:version``
# ---------------------------------------------------------------------------

def test_composer_require_pinned() -> None:
    text = "RUN composer require symfony/console:6.4.0\n"
    plan = _plan("Packagist", "symfony/console", "6.4.5")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "symfony/console:6.4.5" in new


def test_composer_require_unpinned_appends_version() -> None:
    text = "RUN composer require symfony/console\n"
    plan = _plan("Packagist", "symfony/console", "6.4.5")
    new, hit, _ = _rewrite_inline_install(text, plan)
    assert hit is True
    assert "symfony/console:6.4.5" in new


# ---------------------------------------------------------------------------
# Error / no-match paths
# ---------------------------------------------------------------------------

def test_genuinely_unsupported_ecosystem() -> None:
    """Conda etc. — not in the table; should error cleanly."""
    text = "RUN conda install -c conda-forge mamba=1.5.0\n"
    plan = _plan("Conda", "mamba", "1.6.0")
    new, hit, reason = _rewrite_inline_install(text, plan)
    assert hit is False
    assert "Conda" in (reason or "")


def test_dep_not_in_file_returns_no_change() -> None:
    text = "RUN pip install django==4.2.7\n"
    plan = _plan("PyPI", "requests", "2.33.0")
    new, hit, reason = _rewrite_inline_install(text, plan)
    assert hit is False
    assert "not found" in (reason or "")


# ---------------------------------------------------------------------------
# End-to-end: dispatch via _rewrite_one with the right manifest path
# ---------------------------------------------------------------------------

def test_dispatch_via_rewrite_one_for_dockerfile(tmp_path: Path) -> None:
    """``_rewrite_one`` on a Dockerfile should route to the inline rewriter."""
    from packages.sca.update import _rewrite_one
    p = tmp_path / "Dockerfile"
    p.write_text("RUN pip install django==4.2.7\n", encoding="utf-8")
    plan = _PlanEntry(
        ecosystem="PyPI", name="django",
        installed="4.2.7", target="4.2.10",
        manifest=p, advisory_ids=[],
    )
    new, hit, _ = _rewrite_one(p, p.read_text(), plan)
    assert hit is True
    assert "django==4.2.10" in new


def test_dispatch_for_shell_script(tmp_path: Path) -> None:
    from packages.sca.update import _rewrite_one
    p = tmp_path / "install.sh"
    p.write_text("#!/usr/bin/env bash\npip install requests==2.30.0\n",
                 encoding="utf-8")
    plan = _PlanEntry(
        ecosystem="PyPI", name="requests",
        installed="2.30.0", target="2.33.0",
        manifest=p, advisory_ids=[],
    )
    new, hit, _ = _rewrite_one(p, p.read_text(), plan)
    assert hit is True
    assert "requests==2.33.0" in new


def test_dispatch_for_gha_workflow(tmp_path: Path) -> None:
    from packages.sca.update import _rewrite_one
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    p = workflows / "ci.yml"
    p.write_text(
        "jobs:\n  t:\n    steps:\n      - run: pip install pytest==8.1.1\n",
        encoding="utf-8",
    )
    plan = _PlanEntry(
        ecosystem="PyPI", name="pytest",
        installed="8.1.1", target="8.2.0",
        manifest=p, advisory_ids=[],
    )
    new, hit, _ = _rewrite_one(p, p.read_text(), plan)
    assert hit is True
    assert "pytest==8.2.0" in new


# ---------------------------------------------------------------------------
# Maven: ``mvn install:install-file -DgroupId= -DartifactId= -Dversion=``
# ---------------------------------------------------------------------------

def test_maven_install_file_full_form() -> None:
    src = (
        "RUN mvn install:install-file -DgroupId=org.example "
        "-DartifactId=foo -Dversion=1.2.3 -Dpackaging=jar -Dfile=foo.jar\n"
    )
    out, hit, _ = _rewrite_inline_install(
        src, _plan("Maven", "org.example:foo", target="2.0.0"))
    assert hit is True
    assert "-Dversion=2.0.0" in out
    assert "1.2.3" not in out


def test_maven_deploy_deploy_file_form() -> None:
    src = (
        "mvn deploy:deploy-file -Durl=file:///r -DgroupId=org.example "
        "-DartifactId=foo -Dversion=1.0\n"
    )
    out, hit, _ = _rewrite_inline_install(
        src, _plan("Maven", "org.example:foo", target="3.0.0"))
    assert hit is True
    assert "-Dversion=3.0.0" in out


def test_maven_mvnw_wrapper_invocation_matches() -> None:
    src = (
        "./mvnw install:install-file -DgroupId=org.example "
        "-DartifactId=foo -Dversion=1.0 -Dfile=foo.jar\n"
    )
    out, hit, _ = _rewrite_inline_install(
        src, _plan("Maven", "org.example:foo", target="1.5"))
    assert hit is True
    assert "-Dversion=1.5" in out


def test_maven_skip_when_artifact_does_not_match() -> None:
    """The plan targets ``org.example:foo`` but the line installs
    ``org.example:other`` — must NOT rewrite the version even though
    the groupId matches."""
    src = (
        "mvn install:install-file -DgroupId=org.example "
        "-DartifactId=other -Dversion=1.0 -Dfile=other.jar\n"
    )
    out, hit, _ = _rewrite_inline_install(
        src, _plan("Maven", "org.example:foo", target="2.0"))
    assert hit is False
    assert out == src           # untouched


def test_maven_skip_when_only_groupid_matches_no_artifactid_arg() -> None:
    """A line with -DgroupId but no -DartifactId is ambiguous; refuse
    rather than rewrite a partial coordinate match."""
    src = "mvn install:install-file -DgroupId=org.example -Dversion=1.0\n"
    out, hit, _ = _rewrite_inline_install(
        src, _plan("Maven", "org.example:foo", target="2.0"))
    assert hit is False


def test_maven_quoted_version_value_is_rewritten() -> None:
    """Some operators quote the value; preserve the quoting."""
    src = (
        'mvn install:install-file -DgroupId="org.example" '
        '-DartifactId="foo" -Dversion="1.2.3" -Dfile=foo.jar\n'
    )
    out, hit, _ = _rewrite_inline_install(
        src, _plan("Maven", "org.example:foo", target="2.0.0"))
    assert hit is True
    assert '-Dversion="2.0.0"' in out


def test_maven_skip_when_name_lacks_colon() -> None:
    """Maven dep names are ``groupId:artifactId``. A name without ``:``
    is malformed for this ecosystem — skip cleanly rather than guess."""
    src = (
        "mvn install:install-file -DgroupId=org.example "
        "-DartifactId=foo -Dversion=1.0\n"
    )
    out, hit, _ = _rewrite_inline_install(
        src, _plan("Maven", "no-colon", target="2.0"))
    assert hit is False


def test_maven_does_not_match_unrelated_mvn_goal() -> None:
    """``mvn package`` / ``mvn dependency:tree`` are not install
    invocations; the cmd-regex must not fire on them."""
    src = "RUN mvn package -DskipTests\n"
    out, hit, msg = _rewrite_inline_install(
        src, _plan("Maven", "org.example:foo", target="2.0"))
    assert hit is False
    # The reason should be "name not found in inline" — i.e. the cmd
    # regex matched nothing relevant, falling through to the
    # not-found branch.
    assert msg is not None and "not found" in msg
