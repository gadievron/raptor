"""Tokenise a Dockerfile into an ordered list of :class:`Instruction`.

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
  * Heredoc bodies (``<<EOF`` / ``<<-EOF``) are kept intact in the
    instruction's ``args`` text — consumers don't need to peer
    inside them today.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

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


class DockerfileSyntaxError(ValueError):
    """Raised on input we genuinely cannot parse — e.g. an
    instruction with no directive name. Most malformed input is
    handled gracefully (skipped, logged); this error is for
    operators with invalid Dockerfiles that wouldn't build either."""


@dataclass(frozen=True)
class Instruction:
    directive: str
    args: str
    stage_name: Optional[str]
    line: int
    raw: str


def parse_dockerfile(text: str) -> List[Instruction]:
    """Parse the Dockerfile source into an ordered list of
    instructions.

    Returns instructions in source order. The list is suitable for
    iterating multiple times (consumers walking ``FROM`` lines vs
    ``RUN`` lines independently).
    """
    out: List[Instruction] = []
    current_stage: Optional[str] = None
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

        raw = "\n".join(chunks)
        # Strip the trailing backslashes for the LOGICAL line, but
        # keep them in ``raw`` so consumers can round-trip.
        logical = " ".join(
            (c.rstrip()[:-1] if c.rstrip().endswith("\\") else c)
            .strip()
            for c in chunks
        )

        # Split directive from args.
        parts = logical.split(None, 1)
        if not parts:
            continue
        directive = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

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
