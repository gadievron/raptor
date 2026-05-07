"""Extract apt-get install package lists from Dockerfile RUN instructions.

Pure mechanical parser — given a parsed instruction stream, walks the
``RUN`` instructions, finds ``apt-get install`` / ``apt install``
invocations, and returns the package args (name, optional version pin,
optional architecture qualifier).

Designed primarily for an SCA Debian-deps consumer (mapping RUN-line
``apt-get install`` declarations to OSV Debian advisories) but
consumer-agnostic — anything wanting the full apt install graph of a
Dockerfile uses this.

## Recognised forms

  * ``RUN apt-get install -y pkg1 pkg2``
  * ``RUN apt install -y pkg`` (deprecated alias, same syntax)
  * ``RUN apt-get update && apt-get install -y pkg`` (chained)
  * ``RUN apt-get install -y \\\n    pkg1 \\\n    pkg2`` (line-continued)
  * ``RUN DEBIAN_FRONTEND=noninteractive apt-get install -y pkg``
    (env-prefixed)
  * ``RUN apt-get -o Dpkg::Options::=--force-confnew install -y pkg``
    (global flags between the binary and ``install``)
  * Version pins: ``pkg=1.2.3``, ``pkg=1.2.3-1ubuntu0.1``
  * Architecture suffix: ``pkg:arm64``, ``pkg:arm64=1.2.3``

## What this does not do

  * **ARG / ENV substitution.** ``${VAR}`` appears in the output
    verbatim. Consumers that need substitution do their own ARG
    tracking via the existing instruction stream.
  * **Quote-aware shell splitting.** Standard whitespace splitting,
    which is correct for the unquoted, simple-flag-only forms
    ``apt-get install`` actually takes in real Dockerfiles.
    ``RUN bash -c "apt-get install -y foo"`` (subshell-quoted) is
    rare and intentionally out of scope.
  * **Heredoc bodies.** ``RUN <<EOF`` is skipped — practically
    never used for apt installs.
  * **Globs / wildcards.** ``pkg*`` is returned verbatim as the
    name; the consumer (SCA tier) decides whether to resolve.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .parser import Instruction


@dataclass(frozen=True)
class AptPackage:
    """A single package declared by a Dockerfile ``apt-get install``.

    ``name`` is the unqualified package name. ``version`` carries the
    explicit pin from ``pkg=VERSION`` form when present (else None).
    ``arch`` carries the architecture qualifier from ``pkg:ARCH``
    (else None — implicit native arch).
    ``stage`` is the multi-stage build stage name (from the active
    ``FROM x AS <stage>``) the install belongs to (None when the
    enclosing FROM had no AS clause). Lets SCA build per-stage
    SBOMs distinguishing build-only deps (e.g. ``gcc`` in a builder
    stage) from runtime deps (e.g. ``libc6`` in the runtime stage).
    ``line`` is the 1-based source line of the ``RUN`` instruction
    that declared the package, for finding-emitting consumers.
    """

    name: str
    version: Optional[str]
    arch: Optional[str]
    stage: Optional[str]
    line: int


def extract_apt_packages(
    instructions: List[Instruction],
) -> List[AptPackage]:
    """Walk a parsed Dockerfile's instructions, return apt packages.

    Returns the deduplicated list of packages declared across every
    ``RUN apt-get install`` / ``apt install`` invocation. Order is
    preserved (source order, then within-RUN argument order).

    Empty when no RUN instructions install via apt.
    """
    out: List[AptPackage] = []
    for inst in instructions:
        if inst.directive != "RUN":
            continue
        out.extend(_extract_from_run(inst))
    return out


def _extract_from_run(inst: Instruction) -> List[AptPackage]:
    if inst.args.lstrip().startswith("<<"):
        # Heredoc body — out of scope.
        return []
    flat = _flatten_run(inst.raw)
    out: List[AptPackage] = []
    for tokens in _split_commands(flat):
        out.extend(_packages_from_command(tokens, inst.line, inst.stage_name))
    return out


def _flatten_run(raw: str) -> str:
    """Collapse a multi-line RUN's raw source into one shell command
    line, stripping shell ``#``-comments along the way.

    ``Instruction.args`` already collapses line continuations, but
    treats comment-only lines between continued args as plain text
    (so ``pkg \\\n  # explainer\n  pkg2`` becomes ``pkg # explainer
    pkg2``, leaving ``#`` as a token that downstream tokenisation
    can't tell from a real argument). Re-walking the raw lets us
    drop comment-only physical lines and inline ``# ...`` tails
    before tokenisation, matching real shell semantics.
    """
    physical = raw.splitlines()
    if physical and physical[0].split(None, 1)[0].upper() == "RUN":
        # Drop the leading ``RUN`` directive on the first line.
        head = physical[0].split(None, 1)
        physical[0] = head[1] if len(head) > 1 else ""
    chunks: List[str] = []
    for ln in physical:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            # Comment-only line — skip entirely.
            continue
        if s.endswith("\\"):
            s = s[:-1].rstrip()
        # Strip inline ``# ...`` tail at a word boundary.
        idx = _inline_comment_start(s)
        if idx is not None:
            s = s[:idx].rstrip()
        if s:
            chunks.append(s)
    return " ".join(chunks)


def _inline_comment_start(s: str) -> Optional[int]:
    """Return the index where an inline shell comment starts in ``s``.

    Shell semantics: ``#`` starts a comment only at the beginning of
    a word (preceded by whitespace or at position 0). ``pkg#tag``
    is NOT a comment (rare for apt but defensive). Quote-awareness
    is intentionally minimal — apt-get install lines almost never
    quote.
    """
    i = 0
    while i < len(s):
        if s[i] == "#" and (i == 0 or s[i - 1].isspace()):
            return i
        i += 1
    return None


def _split_commands(args: str) -> List[List[str]]:
    """Split a shell command line into per-command token lists.

    Tokenisation goes through ``shlex.split`` (POSIX mode) so quoted
    arguments are unquoted (``"curl"`` -> ``curl``) and backslash
    escapes are honoured. ``&&`` / ``||`` / ``;`` / ``|`` split
    commands whether they're standalone (``a && b``) or fused
    (``update;install``, ``yes|apt-get``) — the connectors are
    pre-padded so shlex sees them as their own tokens.

    On unbalanced quotes (``shlex.ValueError``) we fall back to
    plain whitespace splitting so a broken Dockerfile doesn't
    abort the scan; consumers get whatever packages we can recognise.
    """
    # Pre-process so connectors are always standalone tokens. Order
    # matters: pad ``&&`` / ``||`` first so the ``;`` / ``|`` pads
    # don't turn ``&&`` into ``& &``. The final ``|  |`` reverse
    # repairs ``||`` that the bare-``|`` pad would otherwise split.
    padded = (
        args.replace("&&", " && ")
        .replace("||", " || ")
        .replace(";", " ; ")
        .replace("|", " | ")
        .replace("|  |", "||")
    )
    try:
        tokens = shlex.split(padded, comments=False, posix=True)
    except ValueError:
        tokens = padded.split()
    out: List[List[str]] = []
    current: List[str] = []
    for tok in tokens:
        if tok in ("&&", "||", ";", "|"):
            if current:
                out.append(current)
                current = []
            continue
        current.append(tok)
    if current:
        out.append(current)
    return out


def _packages_from_command(
    tokens: List[str],
    line: int,
    stage: Optional[str],
) -> List[AptPackage]:
    """For one shell command's token list, extract apt-installed
    packages. Returns empty unless the command is
    ``[(sudo|env=val) ...] (apt-get|apt) [flags] install [flags] pkg ...``.

    Subshell parens are unwrapped: tokens with a leading ``(`` or
    trailing ``)`` are stripped. ``( apt-get install -y pkg )`` and
    ``(apt-get install -y pkg)`` both parse the same as the bare
    form.
    """
    tokens = [_strip_subshell_paren(t) for t in tokens if t]
    tokens = [t for t in tokens if t]
    i = 0
    # Skip ``KEY=VALUE`` env-var prefixes (e.g. DEBIAN_FRONTEND) and
    # ``sudo`` prefixes (rare in Dockerfiles but real, e.g. on
    # bases that demote root before subsequent layers).
    while i < len(tokens) and (
        _is_env_prefix(tokens[i]) or tokens[i] == "sudo"
    ):
        i += 1
    if i >= len(tokens):
        return []
    # ``bash -c "apt-get install -y curl"`` / ``sh -c "..."`` — the
    # shell body is a single shlex-unquoted string in tokens[i+N].
    # Recurse into it so the contained installs are extracted.
    if tokens[i] in _SHELL_PROGS:
        return _recurse_shell_c(tokens, i + 1, line, stage)
    if tokens[i] not in ("apt-get", "apt"):
        return []
    i += 1
    # Skip global flags between the binary name and ``install``.
    # Some flags take a separate-token arg (``-o KEY=VAL``,
    # ``-c FILE``, ``-t TARGET``) — consume both. The arg-bearing
    # flags below cover everything apt(-get) defines as global.
    while i < len(tokens) and tokens[i].startswith("-"):
        flag = tokens[i]
        i += 1
        if flag in _ARG_BEARING_FLAGS and i < len(tokens):
            i += 1
    if i >= len(tokens) or tokens[i] != "install":
        return []
    i += 1
    out: List[AptPackage] = []
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if tok.startswith("-"):
            # Install-time flags follow the same arg-bearing rule.
            if tok in _ARG_BEARING_FLAGS and i < len(tokens):
                i += 1
            continue
        parsed = _parse_pkg(tok)
        if parsed is None:
            continue
        name, version, arch = parsed
        out.append(AptPackage(
            name=name, version=version, arch=arch,
            stage=stage, line=line,
        ))
    return out


_SHELL_PROGS = frozenset({"bash", "sh", "dash", "ash", "zsh"})
# Flag values that mean "next token is the shell-command body".
# ``-c`` is canonical; ``-lc`` / ``-Lc`` / ``-cl`` collapse a login
# / interactive flag with ``-c``. Other flag combos are out of scope.
_SHELL_C_FLAGS = frozenset({"-c", "-lc", "-Lc", "-cl"})


def _recurse_shell_c(
    tokens: List[str],
    start: int,
    line: int,
    stage: Optional[str],
) -> List[AptPackage]:
    """For a ``bash``/``sh`` invocation starting at ``start``, find
    ``-c <body>`` and recursively extract from the body string.

    Returns ``[]`` for invocations without ``-c`` (script execution
    or interactive — out of scope).
    """
    j = start
    while j < len(tokens):
        tok = tokens[j]
        if tok in _SHELL_C_FLAGS:
            j += 1
            if j >= len(tokens):
                return []
            body = tokens[j]
            out: List[AptPackage] = []
            for sub in _split_commands(body):
                out.extend(_packages_from_command(sub, line, stage))
            return out
        if tok.startswith("-"):
            j += 1
            continue
        # Non-flag before any ``-c`` — script invocation, out of scope.
        return []
    return []


def _strip_subshell_paren(tok: str) -> str:
    """Strip leading ``(`` and trailing ``)`` from a token.

    Handles the ``(apt-get install -y pkg)`` shape — both parens
    fused to the adjacent token. Tokens with embedded parens (``foo(bar)``,
    rare in apt) get stripped too — false-positive risk is low
    given apt token shapes.
    """
    while tok.startswith("("):
        tok = tok[1:]
    while tok.endswith(")"):
        tok = tok[:-1]
    return tok


# Flags that take a separate-token argument. apt-get(8) defines
# these as global / install-time options. Any other ``-`` flag is
# treated as bare (no following arg consumed).
_ARG_BEARING_FLAGS = frozenset({
    "-o", "--option",
    "-c", "--config-file",
    "-t", "--target-release",
    "--default-release",
})


def _is_env_prefix(tok: str) -> bool:
    """``KEY=VALUE`` shell env prefix.

    Distinct from ``pkg=version`` package args because env prefixes
    appear BEFORE the command name; we only call this scanning the
    leading tokens, never inside the install argument list, so the
    syntactic ambiguity is resolved by position.
    """
    if "=" not in tok or tok.startswith("-") or tok.startswith("="):
        return False
    name = tok.split("=", 1)[0]
    if not name or name[0].isdigit():
        return False
    # Identifier-ish: letters, digits, underscores.
    return all(c.isalnum() or c == "_" for c in name)


def _parse_pkg(
    token: str,
) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
    """Parse ``pkg``, ``pkg=ver``, ``pkg:arch``, or ``pkg:arch=ver``.

    Returns ``(name, version | None, arch | None)`` or ``None`` for
    tokens that aren't recognisable as packages — empty, leading
    ``=``, leading ``:``, file paths (``./local.deb``, ``/abs/path``),
    or shell-substitution / quote-fragment tokens (``$(...``, ```...``,
    ``"..."``).
    """
    if not token or token.startswith("=") or token.startswith(":"):
        return None
    # File paths to local .deb files: real apt syntax, but the file
    # name is the install target — not a package name an OSV
    # advisory would match against. Skip; consumers can scan the
    # file separately if they care.
    if token.startswith("/") or token.startswith("./") or token.startswith("../"):
        return None
    # Shell command substitution / variable expansion produces
    # token fragments that aren't packages (``$(cat`` or ``)`` from
    # ``$(cat list)``). Reject any token containing unbalanced
    # backticks or paren-substitution markers.
    if any(m in token for m in ("$(", ")", "`", "${", "}")):
        # ``${VAR}`` and ``$VAR`` substitution: pass through (the
        # whole token is the variable). But ``${VAR`` (truncated)
        # or ``$(...)`` fragments are noise.
        if not _is_clean_var_substitution(token):
            return None
    # Quote stripping is handled upstream by ``shlex.split`` in
    # ``_split_commands`` — by the time we see the token here it
    # is already unquoted.
    name = token
    version: Optional[str] = None
    arch: Optional[str] = None
    if "=" in name:
        name, version = name.split("=", 1)
        if not version:
            version = None
    if ":" in name:
        name, arch = name.split(":", 1)
        if not arch:
            arch = None
    if not name:
        return None
    return (name, version, arch)


def _is_clean_var_substitution(token: str) -> bool:
    """A token is a clean ``$VAR`` or ``pkg=${VAR}`` substitution
    (acceptable to pass through verbatim) when its only ``$`` /
    ``{`` / ``}`` characters form well-balanced ``${...}`` or a
    leading ``$identifier``. Anything fancier (``$(cmd ...)``,
    backticks) is rejected.
    """
    if "`" in token or "$(" in token:
        return False
    # Count braces. ``${A}`` is fine; ``${A`` or ``A}`` is not.
    if token.count("{") != token.count("}"):
        return False
    return True


__all__ = [
    "AptPackage",
    "extract_apt_packages",
]
