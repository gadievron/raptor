"""Dockerfile parsing — generic, consumer-agnostic.

Dockerfile is a small instruction-language. Several raptor
consumers care about different subsets:

  * SCA wants ``FROM`` (base image → SBOM) and ``RUN`` (inline
    package installs)
  * ``/scan`` wants ``FROM`` for context display
  * ``/audit`` wants the full instruction stream for review
  * ``/codeql`` wants ``COPY`` + ``ADD`` to track build inputs
  * agentic enrichment wants ``ENV`` to know what configuration
    is baked in

Until now, the only Dockerfile parsing in raptor lived in
``packages/sca/parsers/inline_installs.py`` — SCA-specific because
it returned ``Dependency`` directly. This module provides the
generic instruction stream; SCA wraps the relevant parts into
``Dependency``, other consumers wrap into their own shapes.

Module layout:

  * :mod:`core.dockerfile.parser` — tokenise the file into an
    ordered list of :class:`Instruction` objects.
  * :mod:`core.dockerfile.apt` — walk the instruction stream and
    extract ``apt-get install`` package declarations (name,
    optional version pin, optional architecture qualifier, source
    line). Substrate for SCA's Debian deps tier.

Limitations (also captured in :doc:`README`):
  * No ``ARG`` / ``ENV`` substitution — instructions carry the
    raw text. Consumers needing substitution (``FROM ${BASE}``)
    do their own ARG-tracking.
  * Multi-stage builds are surfaced via the ``stage_name`` field
    on each instruction; we don't compute reachability between
    stages (which COPY-from-stage chains affect the final image).
  * Heredoc syntax (``<<EOF``) is parsed as raw text; we don't
    interpret the contained shell.
"""

from .apt import (
    AptPackage,
    extract_apt_packages,
)
from .parser import (
    DockerfileSyntaxError,
    Instruction,
    parse_dockerfile,
)

__all__ = [
    "AptPackage",
    "DockerfileSyntaxError",
    "Instruction",
    "extract_apt_packages",
    "parse_dockerfile",
]
