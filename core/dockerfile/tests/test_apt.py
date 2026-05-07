"""Tests for ``core.dockerfile.apt`` — extract apt-get install
package lists from parsed Dockerfile instruction streams."""

from __future__ import annotations

from core.dockerfile.apt import (
    AptPackage,
    extract_apt_packages,
)
from core.dockerfile.parser import parse_dockerfile


def _names(pkgs):
    return [p.name for p in pkgs]


# ---------------------------------------------------------------------------
# Basic forms
# ---------------------------------------------------------------------------


def test_simple_install():
    src = "FROM debian\nRUN apt-get install -y curl\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]
    assert pkgs[0].version is None
    assert pkgs[0].arch is None
    assert pkgs[0].line == 2


def test_multiple_packages():
    src = "FROM debian\nRUN apt-get install -y curl wget git\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl", "wget", "git"]


def test_apt_alias():
    """``apt`` (deprecated alias) is handled too — used in some
    minimal images."""
    src = "FROM debian\nRUN apt install -y curl\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_no_install_no_op():
    """``apt-get update`` alone returns no packages."""
    src = "FROM debian\nRUN apt-get update\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_no_apt_no_op():
    """RUN that doesn't invoke apt is ignored entirely."""
    src = "FROM python:3.11\nRUN pip install requests\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_empty_dockerfile():
    pkgs = extract_apt_packages(parse_dockerfile(""))
    assert pkgs == []


# ---------------------------------------------------------------------------
# Chaining
# ---------------------------------------------------------------------------


def test_update_then_install_chained_with_and():
    """The standard ``apt-get update && apt-get install -y ...``
    idiom — second command's packages are extracted."""
    src = (
        "FROM debian\n"
        "RUN apt-get update && apt-get install -y curl wget\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl", "wget"]


def test_install_chained_with_semicolon():
    src = (
        "FROM debian\n"
        "RUN apt-get update; apt-get install -y curl\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_install_chained_with_or():
    src = (
        "FROM debian\n"
        "RUN apt-get install -y maybe-this || apt-get install -y fallback\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["maybe-this", "fallback"]


def test_install_then_cleanup():
    """The classic install + cleanup idiom — only the install
    packages are extracted; ``rm -rf /var/lib/apt/lists/*`` is
    irrelevant."""
    src = (
        "FROM debian\n"
        "RUN apt-get update \\\n"
        "    && apt-get install -y curl wget \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl", "wget"]


# ---------------------------------------------------------------------------
# Line continuations
# ---------------------------------------------------------------------------


def test_line_continuation_packages():
    src = (
        "FROM debian\n"
        "RUN apt-get install -y \\\n"
        "    curl \\\n"
        "    wget \\\n"
        "    git\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl", "wget", "git"]


def test_real_world_devcontainer_shape():
    """The shape used by RAPTOR's own devcontainer Dockerfile —
    ``RUN apt-get update && apt-get install -y --no-install-recommends \\``
    with packages on continuation lines, comments interleaved."""
    src = (
        "FROM debian\n"
        "# install build tools\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        "    gcc \\\n"
        "    clang-format \\\n"
        "    gdb \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["gcc", "clang-format", "gdb"]


# ---------------------------------------------------------------------------
# Flag handling
# ---------------------------------------------------------------------------


def test_short_flags_skipped():
    src = "FROM debian\nRUN apt-get install -y -q curl\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_long_flags_skipped():
    src = (
        "FROM debian\n"
        "RUN apt-get install -y --no-install-recommends curl\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_global_flags_before_install_skipped():
    """``apt-get -o Foo=Bar install -y pkg`` — flags between the
    binary and the ``install`` subcommand are skipped, packages
    still extracted."""
    src = (
        "FROM debian\n"
        "RUN apt-get -q -o Dpkg::Options::=--force-confnew install -y curl\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_assume_yes_flag_variants():
    for flag in ("-y", "--yes", "--assume-yes"):
        src = f"FROM debian\nRUN apt-get install {flag} curl\n"
        pkgs = extract_apt_packages(parse_dockerfile(src))
        assert _names(pkgs) == ["curl"], flag


# ---------------------------------------------------------------------------
# Env prefixes
# ---------------------------------------------------------------------------


def test_debian_frontend_env_prefix():
    src = (
        "FROM debian\n"
        "RUN DEBIAN_FRONTEND=noninteractive apt-get install -y curl\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_multiple_env_prefixes():
    src = (
        "FROM debian\n"
        "RUN DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none "
        "apt-get install -y curl\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


# ---------------------------------------------------------------------------
# Version pins + architecture qualifiers
# ---------------------------------------------------------------------------


def test_version_pin():
    src = "FROM debian\nRUN apt-get install -y curl=7.74.0-1\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs[0].name == "curl"
    assert pkgs[0].version == "7.74.0-1"
    assert pkgs[0].arch is None


def test_version_pin_with_ubuntu_suffix():
    src = (
        "FROM debian\n"
        "RUN apt-get install -y curl=7.74.0-1.3+deb11u7\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs[0].name == "curl"
    assert pkgs[0].version == "7.74.0-1.3+deb11u7"


def test_arch_qualifier():
    src = "FROM debian\nRUN apt-get install -y libc6:arm64\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs[0].name == "libc6"
    assert pkgs[0].arch == "arm64"
    assert pkgs[0].version is None


def test_arch_qualifier_and_version():
    src = (
        "FROM debian\n"
        "RUN apt-get install -y libc6:arm64=2.31-13+deb11u5\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs[0].name == "libc6"
    assert pkgs[0].arch == "arm64"
    assert pkgs[0].version == "2.31-13+deb11u5"


# ---------------------------------------------------------------------------
# Multiple RUN instructions
# ---------------------------------------------------------------------------


def test_multiple_runs():
    src = (
        "FROM debian\n"
        "RUN apt-get install -y curl\n"
        "RUN apt-get install -y wget\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl", "wget"]
    assert pkgs[0].line == 2
    assert pkgs[1].line == 3


def test_no_dedup_across_runs():
    """Same package mentioned in two RUN lines surfaces twice —
    the consumer (e.g. SCA) decides what to do with duplicates.
    Useful for the multi-stage case where the same install runs
    in different stages."""
    src = (
        "FROM debian\n"
        "RUN apt-get install -y curl\n"
        "RUN apt-get install -y curl\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl", "curl"]


# ---------------------------------------------------------------------------
# Edge cases / out of scope
# ---------------------------------------------------------------------------


def test_heredoc_skipped():
    """RUN heredoc-form (``<<EOF`` body) is intentionally out of
    scope — practically never used for apt installs in real
    Dockerfiles. Skipping prevents mis-parsing the heredoc body."""
    src = (
        "FROM debian\n"
        "RUN <<EOF\n"
        "apt-get install -y curl\n"
        "EOF\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_var_substitution_passes_through():
    """``${VERSION}`` in a version pin is passed through verbatim —
    consumers that need substitution do their own ARG tracking."""
    src = (
        "FROM debian\n"
        "ARG CURL_VERSION=7.74.0-1\n"
        "RUN apt-get install -y curl=${CURL_VERSION}\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs[0].name == "curl"
    assert pkgs[0].version == "${CURL_VERSION}"


def test_pkg_starting_with_dash_skipped():
    """Defensive: token like ``-curl`` is treated as a flag, not a
    package. (Real apt would reject this.)"""
    src = "FROM debian\nRUN apt-get install -y -curl wget\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["wget"]


def test_empty_install_args():
    """``apt-get install -y`` with no packages."""
    src = "FROM debian\nRUN apt-get install -y\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_return_value_is_dataclass():
    src = "FROM debian\nRUN apt-get install -y curl\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert isinstance(pkgs[0], AptPackage)


def test_apt_get_other_subcommand():
    """``apt-get remove`` / ``apt-get purge`` aren't installs and
    yield nothing. Only ``install`` matters for SCA."""
    for sub in ("remove", "purge", "autoremove", "upgrade"):
        src = f"FROM debian\nRUN apt-get {sub} -y curl\n"
        pkgs = extract_apt_packages(parse_dockerfile(src))
        assert pkgs == [], sub


def test_install_word_alone_no_apt():
    """The word ``install`` outside an apt invocation is ignored."""
    src = "FROM debian\nRUN install -m 0755 binary /usr/local/bin/\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


# ---------------------------------------------------------------------------
# Adversarial-input handling (fixed in adversarial-review pass)
# ---------------------------------------------------------------------------


def test_sudo_prefix_handled():
    """``sudo`` prefix is rare in Dockerfiles but real on bases that
    demote root. Strip it like an env prefix."""
    src = "FROM ubuntu\nRUN sudo apt-get install -y curl\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_pipe_separates_commands():
    """``yes | apt-get install`` (auto-confirm pipe) — pipe acts as
    a command separator."""
    src = "FROM ubuntu\nRUN yes | apt-get install -y curl\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_subshell_parens_stripped():
    """``( apt-get install -y pkg )`` and ``(apt-get install -y pkg)``
    both parse — the subshell parens are stripped."""
    for src in (
        'FROM ubuntu\nRUN ( apt-get install -y curl )\n',
        'FROM ubuntu\nRUN (apt-get install -y curl)\n',
    ):
        pkgs = extract_apt_packages(parse_dockerfile(src))
        assert _names(pkgs) == ["curl"]


def test_quoted_package_unquoted():
    '''``apt-get install -y "curl"`` — surrounding quotes stripped.'''
    src = 'FROM ubuntu\nRUN apt-get install -y "curl"\n'
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_local_deb_file_path_skipped():
    """``apt-get install -y ./local.deb`` — the file path isn't a
    package name an OSV advisory would match against."""
    src = "FROM ubuntu\nRUN apt-get install -y ./local-pkg.deb\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_absolute_path_skipped():
    src = "FROM ubuntu\nRUN apt-get install -y /tmp/local.deb\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_command_substitution_dollar_paren_skipped():
    """``$(cmd ...)`` produces token fragments (``$(cat`` and ``)``)
    that aren't valid package names — skip both."""
    src = "FROM ubuntu\nRUN apt-get install -y $(cat /tmp/pkglist)\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_command_substitution_backtick_skipped():
    """``\\`cmd ...\\``` produces ``\\`cat`` and ``\\`...`` tokens —
    skip both."""
    src = "FROM ubuntu\nRUN apt-get install -y `cat /tmp/pkglist`\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_clean_var_substitution_passes_through():
    """``${PKG_NAME}`` (clean braces) is NOT a substitution fragment
    — pass through verbatim. Consumers can ARG-resolve."""
    src = "FROM ubuntu\nRUN apt-get install -y ${PKG_NAME}\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs[0].name == "${PKG_NAME}"


def test_truncated_var_substitution_skipped():
    """``${PKG`` (mismatched brace) is not a clean variable form."""
    src = "FROM ubuntu\nRUN apt-get install -y ${PKG\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


# ---------------------------------------------------------------------------
# Multi-stage stage attribution
# ---------------------------------------------------------------------------


def test_stage_attribution_multi_stage():
    """``FROM x AS builder`` then install gcc, ``FROM y AS runtime``
    then install libc6 — each AptPackage carries its stage so SCA
    can build per-stage SBOMs distinguishing build-only deps from
    runtime deps."""
    src = (
        "FROM ubuntu AS builder\n"
        "RUN apt-get install -y gcc\n"
        "FROM ubuntu AS runtime\n"
        "RUN apt-get install -y libc6\n"
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    by_name = {p.name: p for p in pkgs}
    assert by_name["gcc"].stage == "builder"
    assert by_name["libc6"].stage == "runtime"


def test_stage_attribution_no_as_clause():
    """``FROM ubuntu`` (no AS) — stage is None."""
    src = "FROM ubuntu\nRUN apt-get install -y curl\n"
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs[0].stage is None


# ---------------------------------------------------------------------------
# Shell ``-c`` recursion (shlex enables this)
# ---------------------------------------------------------------------------


def test_bash_c_recursion():
    """``bash -c "apt-get install -y pkg"`` — the shell body is a
    shlex-unquoted single token; recurse into it."""
    src = (
        'FROM debian\n'
        'RUN bash -c "apt-get install -y curl"\n'
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_sh_c_recursion():
    src = (
        'FROM debian\n'
        'RUN sh -c "apt-get install -y curl"\n'
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_bash_lc_recursion():
    """``bash -lc "..."`` (login + command) — same recursion path."""
    src = (
        'FROM debian\n'
        'RUN bash -lc "apt-get install -y curl wget"\n'
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl", "wget"]


def test_bash_c_with_env_inside_body():
    """The recursive parse handles env prefixes inside the shell
    body the same way."""
    src = (
        'FROM debian\n'
        'RUN bash -c '
        '"DEBIAN_FRONTEND=noninteractive apt-get install -y curl"\n'
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_bash_c_with_chain_inside_body():
    """Chained installs inside ``bash -c`` body all recurse."""
    src = (
        'FROM debian\n'
        'RUN bash -c '
        '"apt-get update && apt-get install -y curl"\n'
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert _names(pkgs) == ["curl"]


def test_bash_script_invocation_no_c_skipped():
    """``bash /path/to/install.sh`` (no -c) — script execution is
    out of scope; can't read foreign scripts at parse time."""
    src = (
        'FROM debian\n'
        'RUN bash /opt/install-deps.sh\n'
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    assert pkgs == []


def test_unbalanced_quotes_falls_back_gracefully():
    """``apt-get install -y "unclosed`` — shlex would raise; we
    fall back to whitespace splitting so the parse doesn't abort.
    The unclosed-quote token may emit oddly but doesn't crash."""
    src = (
        'FROM debian\n'
        'RUN apt-get install -y curl "unclosed wget\n'
    )
    pkgs = extract_apt_packages(parse_dockerfile(src))
    # The fallback splitter still recovers ``curl`` even though the
    # rest of the line is malformed.
    assert "curl" in _names(pkgs)
