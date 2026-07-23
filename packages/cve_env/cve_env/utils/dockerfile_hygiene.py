"""LLM-output sanitization for Dockerfiles and JSON.

These MUST wrap every piece of LLM-produced Dockerfile or JSON before
it touches disk:

  * :func:`robust_json_parse` -- recover JSON from markdown fences,
    trailing commas, control chars, surrounding prose.
  * :func:`sanitize_dockerfile` -- collapse over-escaped backslashes,
    comment-out malformed LABEL lines.
  * :func:`validate_dockerfile_semantics` -- lightweight static check;
    also enforces our no-``:latest`` invariant.

All three are pure (no I/O, no logging mutation) so callers can wire
them into fault-injection tests. ``validate_dockerfile_semantics``
returns the list of issues; an empty list means the Dockerfile is
acceptable.
"""

from __future__ import annotations

import contextlib
import json
import re
from typing import Any

from cve_env.policy import FORBIDDEN_VERSION_TAGS, SHA256_DIGEST_SUFFIX_RE

_EMPTY_LABEL_MARKER = "# INVALID LABEL (malformed): "
# Strip ``@sha256:<64-hex>`` BEFORE parsing the tag so that
# ``nginx:latest@sha256:<digest>`` correctly surfaces ``latest``.
# Re-export of the canonical name in cve_env.policy.
_SHA256_DIGEST_SUFFIX_RE = SHA256_DIGEST_SUFFIX_RE


def robust_json_parse(text: str) -> dict[str, Any] | None:
    """Parse ``text`` as JSON; return ``None`` if unrecoverable.

    Recovers from: markdown code fences, trailing commas, leading/trailing
    prose, stray control characters. Does *not* invent fields -- if the
    JSON is semantically wrong the caller still has to reject it.
    """
    if not text or not isinstance(text, str):
        return None

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    stripped = text.strip()

    if "```json" in stripped:
        with contextlib.suppress(IndexError):
            stripped = stripped.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in stripped:
        with contextlib.suppress(IndexError):
            stripped = stripped.split("```", 1)[1].split("```", 1)[0].strip()

    # Takes outermost { }. Nested JSON in prose may extract wrong object.
    # Callers should prefer structured tool output.
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end <= start:
        return None
    stripped = stripped[start : end + 1]

    stripped = re.sub(r",\s*}", "}", stripped)
    stripped = re.sub(r",\s*]", "]", stripped)

    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    stripped = re.sub(r"[\x00-\x1f\x7f]", "", stripped)
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def sanitize_dockerfile(text: str) -> str:
    """Clean up a Dockerfile produced by an LLM.

    Fixes:
      * excessive backslash escaping (``\\\\\\\\`` -> ``\\``),
      * malformed ``LABEL`` lines lacking ``key=value`` (commented out
        with a marker so the semantic validator can still report them).
    """
    if not text:
        return text

    text = re.sub(r"\\{4,}", r"\\\\", text)  # collapse 4+ backslashes to 2

    out_lines: list[str] = []
    for raw in text.split("\n"):
        line = raw
        stripped = line.strip()
        if stripped.upper().startswith("LABEL "):
            body = stripped[6:].strip()
            if "=" not in body:
                line = f"{_EMPTY_LABEL_MARKER}{line}"
            elif "\\\\" in line:
                line = re.sub(r"\\{2,}", "\\\\", line)
        out_lines.append(line)
    return "\n".join(out_lines)


def _check_from_line(stripped: str, from_images: list[str]) -> list[str]:
    """Validate a FROM line; append discovered image to ``from_images``."""
    issues: list[str] = []
    parts = stripped.split()
    idx = 1
    while idx < len(parts) and parts[idx].startswith("--"):
        if "=" not in parts[idx]:
            idx += 1  # skip the flag's value too
        idx += 1
    if idx >= len(parts):
        return ["FROM line missing image name"]
    image = parts[idx]
    from_images.append(image)
    if image.startswith(("/", "./")):
        issues.append(f"FROM: not a docker image (looks like a path): {image}")
    else:
        # Strip the ``@sha256:<digest>`` suffix BEFORE parsing the tag.
        # Otherwise ``nginx:latest@sha256:<digest>`` has ``@`` so a
        # condition like ``"@" not in image`` would be False and no tag
        # would be checked at all — defense bypassable.
        ref_for_tag = _SHA256_DIGEST_SUFFIX_RE.sub("", image)
        tag = ref_for_tag.rsplit(":", 1)[1] if ":" in ref_for_tag else ""
        if tag.lower() in FORBIDDEN_VERSION_TAGS:
            issues.append(f"P14: FROM forbidden tag ({tag!r}) in {image}")
    return issues


def _check_run_line(stripped: str) -> list[str]:
    body = stripped[3:].strip()
    if not body or body == "\\":
        return ["empty RUN command"]
    return []


def _check_copy_line(stripped: str) -> list[str]:
    parts = stripped.split()
    if len(parts) < 3:
        return [f"{parts[0]} needs source and destination: {stripped!r}"]
    issues: list[str] = []
    # Flag ADD from remote URLs — prefer COPY + explicit download for
    # auditability and layer-cache control.
    if stripped.startswith("ADD "):
        for src in parts[1:-1]:  # all but directive and last (dst)
            if src.startswith(("http://", "https://", "ftp://")):
                issues.append(
                    f"ADD fetches a remote URL ({src}); prefer COPY + "
                    "explicit download (curl/wget) for auditability"
                )
    return issues


def _merge_continuation_lines(text: str) -> list[str]:
    """Collapse backslash-continuation lines into single logical lines
    BEFORE per-line classification.

    Without this, ``RUN \\\n    apt-get update`` is seen as:
      line 1: ``RUN \\``  → flagged as empty RUN (false positive)
      line 2: ``    apt-get update``  → not classified as RUN

    With merging, the two physical lines become one logical line:
      ``RUN apt-get update``  → correctly classified.
    """
    out: list[str] = []
    buf = ""
    for raw in text.split("\n"):
        # If the previous line ended in `\`, this physical line continues
        # the prior logical one. Strip the trailing `\` (and any
        # whitespace before/after) before joining.
        buf = buf + " " + raw.lstrip() if buf else raw
        # If buf still ends in a backslash, we're mid-continuation; do
        # NOT flush yet. Strip trailing whitespace before checking.
        # Count trailing backslashes — only merge on odd count (real
        # continuation). Even count = escaped literal backslashes.
        rstripped = buf.rstrip()
        stripped_bs = rstripped.rstrip("\\")
        num_backslashes = len(rstripped) - len(stripped_bs)
        if num_backslashes % 2 == 1:  # odd = real continuation
            # Drop the trailing `\` and keep accumulating.
            buf = rstripped[:-1]
            continue
        # even (including 0) = not a continuation, flush.
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def validate_dockerfile_semantics(text: str) -> list[str]:
    """Return the list of issues. Empty list = Dockerfile is acceptable.

    Checks:
      * at least one ``FROM`` line (multi-stage builds with several FROMs are
        intentionally allowed — only zero FROMs is rejected),
      * ``FROM`` image refs are parseable, have no spaces, no path prefix,
        no forbidden tag (``:latest``, ``:stable``, etc.),
      * no empty ``RUN`` commands,
      * ``COPY``/``ADD`` have both source and destination,
      * no ``# INVALID LABEL`` markers left from :func:`sanitize_dockerfile`.

    Backslash-continuation lines are merged into single logical lines
    first so multi-line RUN/COPY are not falsely flagged as empty.
    """
    issues: list[str] = []
    from_images: list[str] = []

    for raw in _merge_continuation_lines(text):
        stripped = raw.strip()
        up = stripped.upper()
        if up.startswith("FROM "):
            issues.extend(_check_from_line(stripped, from_images))
        elif up == "RUN" or up.startswith("RUN "):
            issues.extend(_check_run_line(stripped))
        elif up.startswith(("COPY ", "ADD ")):
            issues.extend(_check_copy_line(stripped))
        if stripped.startswith(_EMPTY_LABEL_MARKER):
            issues.append(f"unresolved malformed LABEL: {stripped}")

    if not from_images:
        issues.append("no FROM statement found")
    return issues
