r"""Tokenise a Dockerfile into an ordered list of :class:`Instruction`.

Each instruction carries:
  * ``directive`` — the keyword (``FROM``, ``RUN``, ``COPY``, …),
    upper-cased so consumers don't repeat the case-folding.
  * ``args`` — the raw argument string (with line-continuation
    backslashes collapsed). Consumers parse this further as
    needed; we don't pre-tokenise into a structured form because
    the right shape depends on the directive (``RUN`` is a shell
    fragment, ``FROM`` is an image reference, ``COPY`` is a
    flag-and-paths list, etc.).
  * ``stage_name`` — when the instruction belongs to a multi-stage
    build, the ``AS <name>`` clause from the active ``FROM`` line.
    ``None`` means "default stage" (no ``AS`` declared).
  * ``line`` — 1-based line number of the directive's first line,
    so consumers emitting findings can point at the right source.
  * ``raw`` — the original source span (with line continuations
    preserved). Used by consumers that re-emit / patch the file.

Behaviours:
  * Line continuations (`` \ \n ``) are collapsed into one
    logical line.
  * Comments (``#`` at start of a line, ignoring leading
    whitespace) are skipped, except the parser-directive comments
    (``# syntax=...``, ``# escape=\\``) which we currently
    ignore — their behaviour is dockerfile-frontend-specific and
    not relevant to the consumers we serve.
  * Heredoc bodies (``<<EOF`` / ``<<-EOF``) are consumed up to their
    terminator and NEVER parsed as instructions — a heredoc'd
    ``FROM evil/image`` line must not reset stage tracking or plant
    phantom instructions in the stream. Bodies are preserved in the
    instruction's ``raw`` span; ``args`` carries the marker line.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# All Dockerfile directives we recognise (https://docs.docker.com/
# reference/dockerfile/). Anything outside this set is logged at
# debug and skipped — modern Dockerfiles use frontend extensions
# (``# syntax=`` directive) that legitimately introduce new
# directives, so we don't error.
_KNOWN_DIRECTIVES = frozenset({
    "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV",
    "EXPOSE", "FROM", "HEALTHCHECK", "LABEL", "MAINTAINER",
    "ONBUILD", "RUN", "SHELL", "STOPSIGNAL", "USER",
    "VOLUME", "WORKDIR",
})


# ``FROM <image> [AS <stage>]`` — extract the stage name when
# present. We tolerate both ``AS`` and ``as`` since either shows
# up in practice.
_FROM_AS_RE = re.compile(
    r"\s+AS\s+(?P<name>[A-Za-z0-9_-]+)\s*$",
    re.IGNORECASE,
)


# One heredoc marker TOKEN: ``<<EOF``, ``<<-EOF``, ``<<"EOF"`` — no
# whitespace between ``<<`` and the tag (BuildKit's lexer rule), tag
# identifier-shaped so arithmetic ``1<<2`` never matches. Matched only
# at positions _heredoc_tags has verified to be token-initial and
# unquoted.
_HEREDOC_TOKEN_RE = re.compile(
    r"<<-?(?P<q>[\"']?)(?P<tag>[A-Za-z_][A-Za-z0-9_]*)(?P=q)"
)

# Directives whose args may open heredocs (per the Dockerfile
# reference); scoping the scan avoids false marker hits elsewhere.
_HEREDOC_DIRECTIVES = frozenset({"RUN", "COPY", "ADD"})


def _heredoc_tags(args: str) -> list[str]:
    """Heredoc tags opened by an instruction's args, in order.

    BuildKit's lexer opens a heredoc only for an UNQUOTED token that
    BEGINS with ``<<`` — a bare regex sweep over the whole args string
    instead treated ANY ``<<identifier`` as a marker, so
    ``echo "placeholder <<VERSION"``, ``sed 's/<<X>>/y/'`` and
    ``$((1<<bits))`` each opened a phantom heredoc that swallowed
    every later instruction to EOF (a regression for legitimate
    Dockerfiles AND a one-token evasion primitive hiding later
    RUN/FROM lines from apt/SBOM extraction). This quote-state scan
    enforces the token rule: markers count only at token start,
    outside single/double quotes and backslash escapes; ``<<<``
    here-strings stay excluded.
    """
    tags: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    token_start = True
    i = 0
    n = len(args)
    while i < n:
        c = args[i]
        if escaped:
            escaped = False
            token_start = False
            i += 1
            continue
        if in_single:
            in_single = c != "'"
            token_start = False
            i += 1
            continue
        if c == "\\":
            escaped = True
            i += 1
            continue
        if in_double:
            in_double = c != '"'
            token_start = False
            i += 1
            continue
        if c == "'":
            in_single = True
            token_start = False
            i += 1
            continue
        if c == '"':
            in_double = True
            token_start = False
            i += 1
            continue
        if c.isspace():
            token_start = True
            i += 1
            continue
        if (
            token_start
            and args.startswith("<<", i)
            and not args.startswith("<<<", i)
        ):
            m = _HEREDOC_TOKEN_RE.match(args, i)
            if m:
                tags.append(m.group("tag"))
                i = m.end()
                token_start = False
                continue
        token_start = False
        i += 1
    return tags


class DockerfileSyntaxError(ValueError):
    """Raised on input we genuinely cannot parse — e.g. an
    instruction with no directive name. Most malformed input is
    handled gracefully (skipped, logged); this error is for
    operators with invalid Dockerfiles that wouldn't build either."""


@dataclass(frozen=True)
class Instruction:
    directive: str
    args: str
    stage_name: str | None
    line: int
    raw: str


def parse_dockerfile(text: str) -> list[Instruction]:
    """Parse the Dockerfile source into an ordered list of
    instructions.

    Returns instructions in source order. The list is suitable for
    iterating multiple times (consumers walking ``FROM`` lines vs
    ``RUN`` lines independently).
    """
    out: list[Instruction] = []
    current_stage: str | None = None
    raw_lines = text.splitlines()
    i = 0
    while i < len(raw_lines):
        # Skip blank + comment-only lines. Track i for line numbers.
        line = raw_lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Collapse line continuations: gather lines while the
        # current one ends with `` \``. Comment-only continuation
        # lines (a frequent shape inside multi-line ``RUN`` blocks)
        # don't terminate the continuation — Docker treats them as
        # transparent. They're preserved in ``raw`` for round-trip
        # but the continuation-test still uses the prior non-comment
        # line.
        first_line_no = i + 1
        chunks = [line]
        while line.rstrip().endswith("\\"):
            i += 1
            if i >= len(raw_lines):
                break
            next_line = raw_lines[i]
            chunks.append(next_line)
            if next_line.strip().startswith("#"):
                # Skip — keep ``line`` as-is so the while-test
                # continues using the prior continuation status.
                continue
            line = next_line
        i += 1

        # Strip the trailing backslashes for the LOGICAL line, but
        # keep them in ``raw`` so consumers can round-trip. Comment-
        # only continuation chunks are transparent to Docker and are
        # excluded here too — joining them in left a bare ``#`` plus
        # comment prose embedded mid-args for downstream tokenisers.
        logical = " ".join(
            (c.rstrip()[:-1] if c.rstrip().endswith("\\") else c)
            .strip()
            for c in chunks
            if not c.strip().startswith("#")
        )

        # Split directive from args.
        parts = logical.split(None, 1)
        if not parts:
            continue
        directive = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

        # Consume heredoc bodies (see module docstring): every marker
        # token on the logical line (token-initial, unquoted — see
        # _heredoc_tags) opens a body that runs to a line whose
        # stripped content equals the tag (``<<-`` allows indented
        # terminators; stripping accepts both forms). Body lines join
        # ``raw`` but are never re-entered as instructions. An
        # unterminated heredoc consumes to EOF — matching the build
        # frontend, which would refuse such a file anyway.
        if directive in _HEREDOC_DIRECTIVES:
            for tag in _heredoc_tags(args):
                while i < len(raw_lines):
                    body_line = raw_lines[i]
                    chunks.append(body_line)
                    i += 1
                    if body_line.strip() == tag:
                        break

        raw = "\n".join(chunks)

        if directive not in _KNOWN_DIRECTIVES:
            # Unknown directive — surface but don't crash. Could be
            # a frontend-specific extension or operator typo.
            logger.debug(
                "core.dockerfile: unknown directive %r at line %d "
                "— skipping", directive, first_line_no,
            )
            continue

        # Track stage on FROM directives (multi-stage builds).
        if directive == "FROM":
            match = _FROM_AS_RE.search(args)
            if match:
                current_stage = match.group("name")
                args = args[:match.start()].rstrip()
            else:
                current_stage = None

        out.append(Instruction(
            directive=directive,
            args=args,
            stage_name=current_stage,
            line=first_line_no,
            raw=raw,
        ))
    return out


__all__ = [
    "DockerfileSyntaxError",
    "Instruction",
    "parse_dockerfile",
]
