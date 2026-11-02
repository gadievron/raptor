"""Tests for ``packages.sca.rewriters.dockerfile_inline_install``.

Covers in-place rewriting of ``RUN pip install <name>==<version>``
tokens inside Dockerfiles: applied happy path, idempotency,
mismatch refusal, not-found skip, multi-package RUN lines,
multi-line ``\\``-continuation RUNs, and the dispatcher route
through ``dockerfile_from`` keyed on ``extra["kind"] ==
"inline_install_pip"``."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.dockerfile_inline_install import (
    rewrite_dockerfile_inline_install,
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_inline_install_rewrite_applies_when_old_value_matches(
    tmp_path: Path,
) -> None:
    """The canonical case: ``RUN pip install foo==X`` rewritten
    to ``RUN pip install foo==Y`` in place."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install --no-cache-dir semgrep==1.161.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied
    assert "semgrep==1.163.0" in dockerfile.read_text()
    assert "semgrep==1.161.0" not in dockerfile.read_text()


def test_inline_install_no_change_when_already_at_target(
    tmp_path: Path,
) -> None:
    """Idempotency: re-running with the same plan after the file
    is already at target → no-change skip, not a value_mismatch."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.163.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"


def test_inline_install_value_mismatch_refuses_overwrite(
    tmp_path: Path,
) -> None:
    """If the file's current pin differs from the plan's expected
    old_value, refuse the rewrite — operator may have already
    bumped manually."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.999.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason
    # File untouched.
    assert "semgrep==1.999.0" in dockerfile.read_text()


def test_inline_install_not_found_when_pkg_absent(
    tmp_path: Path,
) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install requests==2.31.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"
    assert "requests==2.31.0" in dockerfile.read_text()  # untouched


# ---------------------------------------------------------------------------
# Multi-package RUN lines
# ---------------------------------------------------------------------------

def test_inline_install_multi_package_single_run(
    tmp_path: Path,
) -> None:
    """``RUN pip install foo==1 bar==2`` — only the targeted
    package is rewritten; the rest is left alone."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install semgrep==1.161.0 black==24.0.0 ruff==0.5.0\n",
    )
    edits = [RewriteEdit(
        locator="black", old_value="24.0.0", new_value="25.0.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    txt = dockerfile.read_text()
    assert "semgrep==1.161.0" in txt
    assert "black==25.0.0" in txt
    assert "ruff==0.5.0" in txt


def test_inline_install_multi_line_continuation(
    tmp_path: Path,
) -> None:
    """RUN bodies that span multiple physical lines via ``\\``
    continuation are common in real Dockerfiles. The rewriter
    matches across lines because it operates on the file's full
    text rather than line-by-line."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install --no-cache-dir \\\n"
        "        semgrep==1.161.0 \\\n"
        "        black==24.0.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    assert "semgrep==1.163.0" in dockerfile.read_text()


def test_inline_install_name_collision_word_boundary(
    tmp_path: Path,
) -> None:
    """``foo`` and ``foobar`` share a prefix. The word-boundary
    in the regex must NOT match ``foobar==1.0`` when bumping ``foo``."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install foo==1.0.0 foobar==2.0.0\n",
    )
    edits = [RewriteEdit(
        locator="foo", old_value="1.0.0", new_value="1.1.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    txt = dockerfile.read_text()
    assert "foo==1.1.0" in txt
    assert "foobar==2.0.0" in txt  # untouched


# ---------------------------------------------------------------------------
# Dispatcher integration through ``rewrite()``
# ---------------------------------------------------------------------------

def test_dispatcher_routes_via_extra_kind(tmp_path: Path) -> None:
    """An edit with ``extra["kind"] == "inline_install_pip"`` is
    routed to the inline-install rewriter by the dockerfile_from
    dispatcher, not to dockerfile_arg or the FROM-image path."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\nRUN pip install semgrep==1.161.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep",
        old_value="1.161.0",
        new_value="1.163.0",
        extra={"kind": "inline_install_pip"},
    )]
    results = rewrite(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied
    assert "semgrep==1.163.0" in dockerfile.read_text()


def test_dispatcher_mixed_arg_and_inline_install(
    tmp_path: Path,
) -> None:
    """A single ``rewrite()`` call can carry both an ARG edit
    and an inline_install edit; both should land."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "ARG CODEQL_VERSION=2.15.5\n"
        "RUN pip install semgrep==1.161.0\n",
    )
    edits = [
        RewriteEdit(
            locator="CODEQL_VERSION",
            old_value="2.15.5", new_value="2.25.4",
            extra={"kind": "arg"},
        ),
        RewriteEdit(
            locator="semgrep",
            old_value="1.161.0", new_value="1.163.0",
            extra={"kind": "inline_install_pip"},
        ),
    ]
    results = rewrite(dockerfile, edits)
    assert all(r.applied for r in results)
    txt = dockerfile.read_text()
    assert "ARG CODEQL_VERSION=2.25.4" in txt
    assert "semgrep==1.163.0" in txt


def test_inline_install_two_stage_twins_both_bumped(
    tmp_path: Path,
) -> None:
    """A two-stage Dockerfile installing the same pin in builder AND
    runtime: both occurrences must be bumped — a first-match count=1
    substitution bumped one stage and left the other vulnerable while
    the run reported applied."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13 AS builder\n"
        "RUN pip install semgrep==1.161.0\n"
        "FROM python:3.13-slim\n"
        "RUN pip install --no-cache-dir semgrep==1.161.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    text = dockerfile.read_text()
    assert text.count("semgrep==1.163.0") == 2
    assert "semgrep==1.161.0" not in text
    assert results[0].reason == "applied"


def test_inline_install_mixed_versions_partial_reported(
    tmp_path: Path,
) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13\n"
        "RUN pip install semgrep==1.161.0\n"
        "RUN pip install semgrep==1.150.0\n",
    )
    edits = [RewriteEdit(
        locator="semgrep", old_value="1.161.0", new_value="1.163.0",
    )]
    results = rewrite_dockerfile_inline_install(dockerfile, edits)
    assert results[0].applied
    assert results[0].reason.startswith("partial:")
    text = dockerfile.read_text()
    assert "semgrep==1.163.0" in text
    assert "semgrep==1.150.0" in text


def test_npm_rewrite_only_literal_install_arguments(tmp_path):
    from packages.sca.rewriters.dockerfile_inline_install import npm_install_pins
    df = tmp_path / 'Dockerfile'
    source = '''# npm install foo@1.0.0
FROM node:24
ENV EXAMPLE=foo@1.0.0
RUN echo "npm install foo@1.0.0" && npm install -g --prefix /usr 'foo@1.0.0' "@scope/tool@2.0.0" \\
    --ignore-scripts # foo@1.0.0
RUN npm install foo@^1.0.0
RUN ["npm", "install", "foo@1.0.0"]
RUN cat <<EOF
npm install foo@1.0.0
EOF
'''
    df.write_text(source)
    pins = npm_install_pins(source)
    assert [(n,v) for n,v,_,_ in pins] == [('foo','1.0.0'),('@scope/tool','2.0.0')]
    assert all(source[a:b] == v for _,v,a,b in pins)
    edits = [RewriteEdit(locator='foo',old_value='1.0.0',new_value='1.1.0',extra={'kind':'inline_install_npm'}),
             RewriteEdit(locator='@scope/tool',old_value='2.0.0',new_value='2.1.0',extra={'kind':'inline_install_npm'})]
    assert all(r.applied for r in rewrite(df,edits))
    assert df.read_text() == source.replace("'foo@1.0.0'", "'foo@1.1.0'").replace('"@scope/tool@2.0.0"','"@scope/tool@2.1.0"')
    assert all(r.reason=='no_change' for r in rewrite(df,edits))


@pytest.mark.parametrize('body', [
    'echo npm install foo@1.0.0',
    'npm install --registry https://other.example foo@1.0.0',
    'npm install --registry=https://other.example foo@1.0.0',
    'npm install --userconfig /tmp/npmrc foo@1.0.0',
    'npm install --unknown foo@1.0.0',
    'npm install foo@1.0.0 "$ARGS"',
    'npm install foo@1.0.0 > output',
    'npm install foo@1.0.0 | cat',
    'npm install "foo@${VERSION}"',
    'npm install foo@1.0.0-rc.1',
    'npm install npm:foo@1.0.0',
    'npm install foo@https://example.org/1.0.0',
])
def test_npm_unsupported_commands_are_not_discovered_or_rewritten(tmp_path, body):
    from packages.sca.rewriters.dockerfile_inline_install import npm_install_pins
    source = 'FROM node:24\nRUN '+body+'\n';df=tmp_path/'Dockerfile';df.write_text(source)
    assert npm_install_pins(source)==[]
    edit=RewriteEdit(locator='foo',old_value='1.0.0',new_value='2.0.0',extra={'kind':'inline_install_npm'})
    assert rewrite(df,[edit])[0].reason=='not_found'
    assert df.read_text()==source


def test_npm_rewrite_handles_crlf_and_multistage_and_rejects_stale_plans(tmp_path):
    df=tmp_path/'Dockerfile'
    source='FROM node:24 AS build\r\nRUN npm install \\\r\n  foo@1.0.0\r\nFROM node:24\r\nRUN npm i foo@1.0.0\r\n'
    df.write_bytes(source.encode())
    edit=RewriteEdit(locator='foo',old_value='1.0.0',new_value='2.0.0',extra={'kind':'inline_install_npm'})
    assert rewrite(df,[edit])[0].applied
    # The shared atomic writer may normalize CRLF; verify version spans independently.
    from packages.sca.rewriters.dockerfile_inline_install import npm_install_pins
    assert [(n,v) for n,v,_,_ in npm_install_pins(df.read_text())]==[('foo','2.0.0'),('foo','2.0.0')]
    df.write_text('FROM node:24\nRUN npm i foo@1.0.0\nRUN npm install foo@1.5.0\n')
    before=df.read_bytes()
    assert rewrite(df,[edit])[0].reason=='value_mismatch'
    assert df.read_bytes()==before
    bad=RewriteEdit(locator='foo',old_value='1.0.0',new_value='2.0.0; curl evil',extra={'kind':'inline_install_npm'})
    assert rewrite(df,[bad])[0].reason.startswith('invalid_')


@pytest.mark.parametrize('prefix', ['ENV NPM_CONFIG_REGISTRY=https://other.example\n',
                                   'ENV npm_config_userconfig=/tmp/npmrc\n',
                                   'COPY .npmrc /root/.npmrc\n',
                                   'RUN npm config set @scope:registry https://other.example\n',
                                   'SHELL ["powershell", "-Command"]\n'])
def test_npm_dockerfile_registry_or_shell_overrides_are_not_rewrite_surfaces(prefix):
    from packages.sca.rewriters.dockerfile_inline_install import npm_install_pins
    assert npm_install_pins('FROM node:24\n'+prefix+'RUN npm install foo@1.0.0\n')==[]


def test_npm_version_spans_preserve_raw_crlf_when_applied_to_source():
    from packages.sca.rewriters.dockerfile_inline_install import _apply_npm
    source='FROM scratch\r\nRUN npm install \\\r\n  foo@1.0.0\r\n'
    edit=RewriteEdit(locator='foo',old_value='1.0.0',new_value='1.1.0')
    text,result=_apply_npm(source,edit)
    assert result.applied and text==source.replace('foo@1.0.0','foo@1.1.0')
