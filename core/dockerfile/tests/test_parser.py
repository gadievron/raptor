"""Tests for ``core.dockerfile.parser``.

The parser is shared substrate so its behaviour is locked down
here rather than re-tested in every consumer. Cover the load-
bearing shapes (FROM with AS stage, RUN with line continuation,
comments, unknown directives) plus a few real-world fixtures."""

from __future__ import annotations

from core.dockerfile.parser import (
    parse_dockerfile,
)


# ---------------------------------------------------------------------------
# Basic shape
# ---------------------------------------------------------------------------


def test_simple_dockerfile():
    src = """\
FROM python:3.11
RUN apt-get update && apt-get install -y curl
COPY . /app
WORKDIR /app
CMD ["python", "main.py"]
"""
    insts = parse_dockerfile(src)
    directives = [i.directive for i in insts]
    assert directives == ["FROM", "RUN", "COPY", "WORKDIR", "CMD"]


def test_directives_uppercased():
    """The keyword may be lower-case in source (rare but valid);
    the parser uppercases for downstream consumers so they don't
    have to."""
    src = "from python:3.11\nrun echo hi\n"
    insts = parse_dockerfile(src)
    assert [i.directive for i in insts] == ["FROM", "RUN"]


def test_args_preserved_verbatim():
    """Args carry the exact text after the directive — consumers
    parse further as they need."""
    src = "FROM python:3.11-slim\n"
    insts = parse_dockerfile(src)
    assert insts[0].args == "python:3.11-slim"


# ---------------------------------------------------------------------------
# Comments + blank lines
# ---------------------------------------------------------------------------


def test_comments_skipped():
    src = """\
# This is a comment
FROM python:3.11
# Another comment
RUN echo hi
"""
    insts = parse_dockerfile(src)
    assert [i.directive for i in insts] == ["FROM", "RUN"]


def test_blank_lines_skipped():
    src = """\

FROM python:3.11

RUN echo hi

"""
    insts = parse_dockerfile(src)
    assert [i.directive for i in insts] == ["FROM", "RUN"]


def test_indented_comment_skipped():
    """Comments with leading whitespace are still comments per
    the Dockerfile spec."""
    src = "    # leading whitespace ok\nFROM python:3.11\n"
    insts = parse_dockerfile(src)
    assert insts[0].directive == "FROM"


# ---------------------------------------------------------------------------
# Line continuations
# ---------------------------------------------------------------------------


def test_line_continuation_collapsed():
    """``RUN`` with backslash-continuation is one logical
    instruction. Args carry the collapsed shell-fragment."""
    src = """\
RUN apt-get update \\
 && apt-get install -y \\
    curl \\
    git
"""
    insts = parse_dockerfile(src)
    assert len(insts) == 1
    assert insts[0].directive == "RUN"
    # The collapsed args should be one logical shell-line.
    assert "apt-get update" in insts[0].args
    assert "apt-get install" in insts[0].args
    assert "curl" in insts[0].args
    assert "git" in insts[0].args


def test_comment_lines_inside_continuation_dont_terminate():
    """Real Dockerfiles often interleave ``# explainer`` lines
    between continued args. Docker treats those as transparent —
    the prior line's trailing ``\\`` continuation still applies.
    """
    src = """\
RUN apt-get install -y \\
    curl \\
    # explainer line
    wget \\
    # another explainer
    git
"""
    insts = parse_dockerfile(src)
    assert len(insts) == 1
    assert insts[0].directive == "RUN"
    args = insts[0].args
    # All three packages survived the continuation across
    # comment-only intermediate lines.
    assert "curl" in args
    assert "wget" in args
    assert "git" in args


def test_continuation_line_numbers_use_first_line():
    """``Instruction.line`` points at the FIRST line of the
    instruction, not the continuation lines. Consumers emitting
    findings against this line want the directive's line."""
    src = """\
FROM python:3.11
RUN apt-get update \\
 && apt-get install -y curl
"""
    insts = parse_dockerfile(src)
    assert insts[0].line == 1
    assert insts[1].line == 2


def test_raw_preserves_continuation():
    """``Instruction.raw`` keeps the original source span
    including the backslashes — for consumers that re-emit /
    patch."""
    src = "RUN echo \\\n  hi\n"
    insts = parse_dockerfile(src)
    assert "\\" in insts[0].raw
    assert "\n" in insts[0].raw


# ---------------------------------------------------------------------------
# Multi-stage builds
# ---------------------------------------------------------------------------


def test_from_as_extracts_stage_name():
    src = """\
FROM python:3.11 AS builder
RUN pip install build
FROM python:3.11-slim
COPY --from=builder /app /app
"""
    insts = parse_dockerfile(src)
    assert insts[0].directive == "FROM"
    assert insts[0].stage_name == "builder"
    assert insts[0].args == "python:3.11"

    # Subsequent instructions inherit the active stage.
    assert insts[1].stage_name == "builder"

    # Second FROM (no AS) clears the stage name.
    assert insts[2].stage_name is None
    assert insts[2].args == "python:3.11-slim"


def test_from_as_lowercase():
    src = "FROM python:3.11 as build-stage\n"
    insts = parse_dockerfile(src)
    assert insts[0].stage_name == "build-stage"


def test_from_without_as():
    """No ``AS <name>`` clause → stage_name is None."""
    src = "FROM python:3.11\n"
    insts = parse_dockerfile(src)
    assert insts[0].stage_name is None
    assert insts[0].args == "python:3.11"


# ---------------------------------------------------------------------------
# Unknown directives
# ---------------------------------------------------------------------------


def test_unknown_directive_skipped():
    """Frontend extensions or operator typos shouldn't crash —
    debug-log + skip."""
    src = """\
FROM python:3.11
WAT thisisnotvalid
RUN echo hi
"""
    insts = parse_dockerfile(src)
    assert [i.directive for i in insts] == ["FROM", "RUN"]


# ---------------------------------------------------------------------------
# Real-world fixtures
# ---------------------------------------------------------------------------


def test_realistic_python_dockerfile():
    """A typical Python Dockerfile with multi-stage build."""
    src = """\
# Build stage
FROM python:3.11 AS build
WORKDIR /app
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim
WORKDIR /app
COPY --from=build /app /app
COPY src/ /app/src/
RUN apt-get update \\
 && apt-get install -y --no-install-recommends \\
    curl \\
 && rm -rf /var/lib/apt/lists/*
USER nobody
EXPOSE 8000
CMD ["python", "src/server.py"]
"""
    insts = parse_dockerfile(src)
    # Two FROMs, both correctly tagged with their stage names.
    froms = [i for i in insts if i.directive == "FROM"]
    assert len(froms) == 2
    assert froms[0].stage_name == "build"
    assert froms[1].stage_name is None

    # The RUN's continued lines should be collapsed.
    runs = [i for i in insts if i.directive == "RUN"]
    apt_run = [r for r in runs if "apt-get update" in r.args]
    assert len(apt_run) == 1
    assert "rm -rf" in apt_run[0].args


# ── heredoc bodies are consumed, never parsed as instructions ──────────


def test_heredoc_body_never_yields_phantom_instructions():
    text = (
        "FROM debian:11 AS build\n"
        "RUN <<SCRIPT\n"
        "FROM evil/image\n"
        "RUN echo phantom\n"
        "SCRIPT\n"
        "RUN echo real\n"
    )
    insts = parse_dockerfile(text)
    directives = [i.directive for i in insts]
    assert directives == ["FROM", "RUN", "RUN"]
    # Stage tracking survives — the heredoc'd FROM must not reset it.
    assert all(i.stage_name == "build" for i in insts)
    # The body is preserved in raw for round-trip consumers.
    heredoc_run = insts[1]
    assert "FROM evil/image" in heredoc_run.raw
    assert heredoc_run.args.startswith("<<SCRIPT")


def test_heredoc_dash_form_indented_terminator():
    text = (
        "FROM alpine\n"
        "RUN <<-EOT\n"
        "  echo body\n"
        "\tEOT\n"
        "RUN echo after\n"
    )
    insts = parse_dockerfile(text)
    assert [i.directive for i in insts] == ["FROM", "RUN", "RUN"]
    assert insts[2].args == "echo after"


def test_unterminated_heredoc_consumes_to_eof_without_phantoms():
    text = "FROM alpine\nRUN <<EOT\nFROM evil/image\n"
    insts = parse_dockerfile(text)
    assert [i.directive for i in insts] == ["FROM", "RUN"]


def test_shell_shapes_do_not_false_trigger_heredoc():
    # ``<<<`` here-strings and arithmetic ``1<<2`` are not heredocs.
    text = (
        "FROM alpine\n"
        "RUN cat <<< hello\n"
        "RUN echo $((1<<2))\n"
        "RUN echo done\n"
    )
    insts = parse_dockerfile(text)
    assert [i.directive for i in insts] == ["FROM", "RUN", "RUN", "RUN"]


# ── comment-only continuation chunks are transparent in args ───────────


def test_comment_continuation_lines_excluded_from_args():
    text = (
        "RUN apt-get install -y \\\n"
        "    # explainer comment\n"
        "    zlib1g-dev\n"
    )
    insts = parse_dockerfile(text)
    assert len(insts) == 1
    assert "#" not in insts[0].args
    assert "explainer" not in insts[0].args
    assert "zlib1g-dev" in insts[0].args
    # raw keeps the comment for round-trip.
    assert "# explainer comment" in insts[0].raw


# ── heredoc markers are TOKENS: quoted / mid-word << never triggers ────


def test_quoted_heredoc_lookalike_does_not_swallow_instructions():
    # BuildKit builds all of these normally; a phantom heredoc here
    # both regresses legitimate files and hands an attacker a
    # one-token way to hide later RUN/FROM lines from extraction.
    text = (
        "FROM debian:11\n"
        'RUN echo "placeholder <<VERSION"\n'
        "RUN apt-get install -y curl\n"
        "RUN pip install requests\n"
    )
    insts = parse_dockerfile(text)
    assert [i.directive for i in insts] == ["FROM", "RUN", "RUN", "RUN"]


def test_single_quoted_sed_template_not_a_heredoc():
    text = (
        "FROM debian:11\n"
        "RUN sed -i 's/<<PLACEHOLDER>>/prod/' /etc/app.conf\n"
        "RUN apt-get install -y curl\n"
    )
    insts = parse_dockerfile(text)
    assert [i.directive for i in insts] == ["FROM", "RUN", "RUN"]


def test_mid_token_shift_with_identifier_not_a_heredoc():
    text = (
        "FROM debian:11\n"
        "RUN echo $((1<<bits))\n"
        "FROM alpine AS second\n"
    )
    insts = parse_dockerfile(text)
    assert [i.directive for i in insts] == ["FROM", "RUN", "FROM"]
    assert insts[2].stage_name == "second"


def test_true_heredoc_mid_line_still_consumes_body():
    # Control: a genuine token-initial marker after a connector still
    # opens the heredoc and its body never becomes instructions.
    text = (
        "FROM debian:11\n"
        "RUN apt-get update && tee /etc/motd <<BANNER\n"
        "FROM inside/body\n"
        "BANNER\n"
        "RUN echo after\n"
    )
    insts = parse_dockerfile(text)
    assert [i.directive for i in insts] == ["FROM", "RUN", "RUN"]
    assert "FROM inside/body" in insts[1].raw
    assert insts[2].args == "echo after"
