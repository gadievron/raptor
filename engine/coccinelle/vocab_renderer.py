r"""Render Coccinelle rules with DomainVocabulary extensions.

Reads ``// @vocab: <bucket>`` markers from ``.cocci`` files and extends
the SmPL construct that follows with study-discovered names from the
audit DomainVocabulary.

Supported constructs (auto-detected from the line after the marker):

* **Inline alternation** ``\(a\|b\)`` — appends ``\|name`` entries.
* **Identifier list** ``identifier fn = {a, b, ...};`` — appends names.
* **Python set literal** ``{"a", "b", ...}`` — appends ``"name"`` entries.
* **when-clause block** ``when != func(`` — inserts extra ``when !=`` lines.
* **Multi-line disjunction** ``(`` block with ``// @vocab-tmpl:`` —
  inserts new ``|`` entries from the template (``%s`` = name).
"""

from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Markers may sit inside an indented construct (e.g. a when-clause
# block nested in an if body), so allow leading whitespace.
_MARKER_RE = re.compile(r"^\s*//\s*@vocab:\s*(\w+)\s*$")
_TMPL_RE = re.compile(r"^\s*//\s*@vocab-tmpl:\s*(.+)$")

_BUCKET_MAP = {
    "deallocators": "deallocators",
    "allocators": "allocators",
    "lock_acquires": "lock_acquires",
    "lock_releases": "lock_releases",
    "refcount_gets": "refcount_gets",
    "refcount_puts": "refcount_puts",
    "callback_cancels": "callback_cancels",
    # teardown_lifetime.cocci also marks ``callback_cancels_async``
    # slots; DomainVocabulary carries no async/sync split, so those
    # markers stay seed-only — _get_bucket warns instead of silently
    # yielding the empty set (U12-F265).
}

# Strict identifier grammar for spliced names — same expression as
# api_pack_renderer._IDENT_RE and condition_smt._VOCAB_IDENT_RE.
# Vocabulary originates from LLM study output over the untrusted
# scanned repo; the rendered rule runs under allow_scripting=True, so
# any name that could carry SmPL/Python syntax (quotes, braces, ``@``,
# newlines) must be rejected here even if an upstream gate already
# validated it (defense in depth for U12-F260).
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

# Scripting-block header matcher — keep in sync with the canonical
# copy in packages.coccinelle.runner._SCRIPT_BLOCK_RE (engine/ does
# not import packages/).
_SCRIPT_BLOCK_RE = re.compile(
    r"^[ \t]*@[ \t]*(?:script|initialize|finalize)[ \t]*:",
    re.MULTILINE | re.IGNORECASE,
)


def _get_bucket(vocab: Any, bucket_name: str) -> frozenset[str]:
    bucket_attr = _BUCKET_MAP.get(bucket_name)
    if bucket_attr is None:
        logger.warning(
            "unknown @vocab bucket %r — no vocabulary spliced for "
            "this marker", bucket_name,
        )
        return frozenset()
    names = getattr(vocab, bucket_attr, frozenset())
    safe = frozenset(
        n for n in names if isinstance(n, str) and _IDENT_RE.match(n)
    )
    rejected = set(names) - set(safe)
    if rejected:
        logger.warning(
            "rejected %d vocabulary name(s) for bucket %s that fail "
            "the identifier grammar (splice refused): %s",
            len(rejected), bucket_name,
            ", ".join(repr(str(r))[:60] for r in sorted(
                rejected, key=str,
            )[:3]),
        )
    return safe


def _extend_alternation(line: str, names: frozenset[str]) -> str:
    r"""Extend ``\(a\|b\)`` with extra names."""
    if not names:
        return line
    suffix = "".join(rf"\|{n}" for n in sorted(names))
    return line.replace(r"\)", suffix + r"\)", 1)


def _extend_identifier_list(line: str, names: frozenset[str]) -> str:
    """Extend ``identifier fn = {a, b, ...};`` with extra names."""
    if not names:
        return line
    extra = ", ".join(sorted(names))
    return line.replace("};", f", {extra}}};", 1)


def _extend_python_set(line: str, names: frozenset[str]) -> str:
    """Extend ``{"a", "b", ...}`` with extra quoted names."""
    if not names:
        return line
    extra = ", ".join(f'"{n}"' for n in sorted(names))
    idx = line.rfind("}")
    if idx < 0:
        return line
    return line[:idx] + ", " + extra + line[idx:]


def _extend_when_block(
    lines: list[str], start: int, names: frozenset[str],
) -> tuple[list[str], int]:
    """Extend a ``when !=`` clause block with extra ``when != name(...)`` lines.

    Returns ``(replacement lines for the block, source lines consumed)``
    so the caller can keep scanning for further ``@vocab`` markers after
    the block instead of swallowing the rest of the file.
    """
    # The start line is the block opener by contract (the caller only
    # dispatches here when it contains ``when !=`` — possibly prefixed
    # by ``...``), so it always belongs to the block; scanning it with
    # the ``startswith`` test below would end the block at zero lines.
    last_when = start
    end = len(lines)
    for i in range(start + 1, len(lines)):
        stripped = lines[i].lstrip()
        if _MARKER_RE.match(lines[i]) or _TMPL_RE.match(lines[i]):
            # A following @vocab marker belongs to the NEXT construct,
            # not to this block — swallowing it as a plain comment
            # would leave that construct unspliced.
            end = i
            break
        if stripped.startswith("when !="):
            last_when = i
        elif stripped and not stripped.startswith("//"):
            end = i
            break
    consumed = end - start
    if not names:
        return list(lines[start:end]), consumed

    indent = "      "
    m = re.match(r"^(\s*)when", lines[last_when].lstrip() and lines[last_when])
    if m:
        indent = " " * (len(lines[last_when]) - len(lines[last_when].lstrip()))

    extra = [f"{indent}when != {n}(...)\n" for n in sorted(names)]
    return (
        lines[start : last_when + 1] + extra + lines[last_when + 1 : end],
        consumed,
    )


def _extend_disjunction(
    lines: list[str], start: int, tmpl: str, names: frozenset[str],
) -> tuple[list[str], int]:
    """Extend a ``( ... | ... )`` disjunction block with new ``|`` entries.

    Returns ``(replacement lines for the block, source lines consumed)``
    — the block ends at its closing ``)`` line, and the caller resumes
    marker scanning right after it.
    """
    close_idx = None
    for i in range(start, len(lines)):
        if lines[i].strip() == ")":
            close_idx = i
            break
    if close_idx is None:
        # Unterminated block: pass the tail through untouched.
        return list(lines[start:]), len(lines) - start
    consumed = close_idx - start + 1
    if not names:
        return list(lines[start : start + consumed]), consumed

    extra = []
    for n in sorted(names):
        rendered = tmpl.replace("%s", n)
        extra.append("|\n")
        extra.append(f"  {rendered}\n")

    return (
        lines[start:close_idx] + extra + [lines[close_idx]],
        consumed,
    )


def render(rule_path: Path, vocab: Any) -> Path | None:
    """Render a ``.cocci`` rule with vocab extensions.

    Returns a Path to a tempfile with the rendered rule, or None if the
    rule has no ``@vocab`` markers or vocab is empty/None.
    """
    if vocab is None:
        return None

    text = rule_path.read_text()
    if "// @vocab:" not in text:
        return None

    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    modified = False

    while i < len(lines):
        marker = _MARKER_RE.match(lines[i].rstrip())
        if not marker:
            out.append(lines[i])
            i += 1
            continue

        bucket_name = marker.group(1)
        names = _get_bucket(vocab, bucket_name)
        out.append(lines[i])
        i += 1

        tmpl_match = _TMPL_RE.match(lines[i].rstrip()) if i < len(lines) else None
        if tmpl_match:
            tmpl = tmpl_match.group(1)
            out.append(lines[i])
            i += 1
            if i < len(lines) and lines[i].strip() == "(":
                # Splice only the disjunction block itself and keep
                # scanning: a rule file routinely carries further
                # @vocab markers after the first construct (e.g. an
                # allocator trigger followed by a deallocator
                # suppression), and consuming the whole tail here left
                # those later markers silently unprocessed — an
                # asymmetric splice that minted findings on
                # project-vocabulary code.
                block, consumed = _extend_disjunction(lines, i, tmpl, names)
                if len(block) != consumed:
                    modified = True
                out.extend(block)
                i += consumed
                continue

        if i >= len(lines):
            break

        line = lines[i]
        stripped = line.strip()

        if r"\(" in stripped and r"\)" in stripped:
            out.append(_extend_alternation(line, names))
            modified = modified or bool(names)
            i += 1
        elif stripped.startswith("identifier") and "= {" in stripped:
            out.append(_extend_identifier_list(line, names))
            modified = modified or bool(names)
            i += 1
        elif '= {"' in stripped or ('= {' in stripped and '"' in stripped):
            out.append(_extend_python_set(line, names))
            modified = modified or bool(names)
            i += 1
        elif "when !=" in stripped:
            # Same scanning rule as the disjunction branch: extend only
            # the when-clause block and resume after it, so later
            # markers in the file still get processed.
            block, consumed = _extend_when_block(lines, i, names)
            if len(block) != consumed:
                modified = True
            out.extend(block)
            i += consumed
        else:
            out.append(line)
            i += 1

    if not modified:
        return None

    rendered = "".join(out)

    # Belt-and-braces on top of the per-name identifier gate: the
    # rendered rule must not have grown any scripting block relative
    # to the source rule. The identifier grammar makes this
    # unreachable via vocabulary content by construction; if it ever
    # fires, splicing is refused for the whole rule (seed rule runs
    # unextended) and the event is loud.
    if len(_SCRIPT_BLOCK_RE.findall(rendered)) != len(
        _SCRIPT_BLOCK_RE.findall(text)
    ):
        logger.error(
            "vocab rendering of %s introduced a scripting block — "
            "splice refused, running the un-extended rule",
            rule_path.name,
        )
        return None

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".cocci", prefix=rule_path.stem + "_vocab_",
        delete=False,
    )
    tmp.write(rendered)
    tmp.close()
    return Path(tmp.name)
