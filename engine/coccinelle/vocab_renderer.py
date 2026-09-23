r"""Render Coccinelle rules with DomainVocabulary extensions.

Reads ``// @vocab: <bucket>`` markers from ``.cocci`` files and extends
the SmPL construct that follows with study-discovered names from the
audit DomainVocabulary.

Supported constructs (auto-detected from the line after the marker):

* **Inline alternation** ``\(a\|b\)`` — appends ``\|name`` entries.
* **Identifier list** ``identifier fn = {a, b, ...};`` — appends names.
* **Python set literal** ``{"a", "b", ...}`` — appends ``"name"``
  entries; the literal may span multiple lines.
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
    # DomainVocabulary carries no async/sync split for callback
    # cancels, so async-only splice slots (teardown_lifetime.cocci's
    # trigger alternations) carry plain seed-only comments instead of
    # @vocab markers. An unmapped bucket name is an authoring error:
    # _get_bucket warns instead of silently yielding the empty set,
    # and the render-validity oracle turns that warning into a
    # failure.
}

# Strict identifier grammar for spliced names — same expression as
# api_pack_renderer._IDENT_RE and condition_smt._VOCAB_IDENT_RE.
# Vocabulary originates from LLM study output over the untrusted
# scanned repo; the rendered rule runs under allow_scripting=True, so
# any name that could carry SmPL/Python syntax (quotes, braces, ``@``,
# newlines) must be rejected here even if an upstream gate already
# validated it (defense in depth for U12-F260). Matched with
# fullmatch(): re.match + '$' accepts a trailing newline
# (``"kfree\n"``), which splices a literal line break into the
# rendered alternation and turns the whole sweep into an spatch parse
# error — api_pack_renderer documents the same trap.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")

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
        n for n in names if isinstance(n, str) and _IDENT_RE.fullmatch(n)
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


def _extend_python_set(
    lines: list[str], start: int, names: frozenset[str],
) -> tuple[list[str], int, bool]:
    """Extend a ``{"a", "b", ...}`` set literal with extra quoted names.

    The literal may span multiple lines (the stock rules' report-script
    suppression sets do) — scan forward to the line carrying the
    closing ``}`` like ``_extend_when_block`` scans its block, and
    insert the new entries before it.  Returns ``(replacement lines,
    source lines consumed, changed)``.
    """
    close_idx = None
    for i in range(start, len(lines)):
        if i > start and (
            _MARKER_RE.match(lines[i]) or _TMPL_RE.match(lines[i])
        ):
            # Ran into the next marker before any closing brace: the
            # literal is malformed — refuse the splice, keep the next
            # marker scannable, and let the dead-splice witness make
            # the refusal loud.
            break
        if "}" in lines[i]:
            close_idx = i
            break
    if close_idx is None:
        return [lines[start]], 1, False
    consumed = close_idx - start + 1
    if not names:
        return list(lines[start : start + consumed]), consumed, False
    extra = ", ".join(f'"{n}"' for n in sorted(names))
    closing = lines[close_idx]
    idx = closing.rfind("}")
    block = list(lines[start:close_idx])
    block.append(closing[:idx] + ", " + extra + closing[idx:])
    return block, consumed, True


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

    # Reuse the last when-line's indentation when that line itself
    # starts with ``when``; a block opener like ``... when != f(``
    # keeps the six-space default instead of inheriting the dots'
    # indent.
    indent = "      "
    last_line = lines[last_when]
    if last_line.lstrip().startswith("when"):
        indent = " " * (len(last_line) - len(last_line.lstrip()))

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
        if rendered.startswith("*"):
            # Context-mode ``*`` annotations only match at column 0:
            # an indented star line parses clean but silently never
            # matches anything, so star templates must be emitted
            # unindented.
            extra.append(f"{rendered}\n")
        else:
            extra.append(f"  {rendered}\n")

    return (
        lines[start:close_idx] + extra + [lines[close_idx]],
        consumed,
    )


def _warn_if_dead(
    rule_path: Path, bucket_name: str, names: frozenset[str],
    changed: bool,
) -> None:
    """Witness a dead splice slot.

    A ``@vocab`` marker with a non-empty vocabulary that produced no
    textual change means the construct after the marker was not
    recognised or never grew — the learned lane is seed-only with
    zero diagnostics otherwise (the unknown-bucket warning only covers
    bucket-name typos, not effect-free splices).
    """
    if names and not changed:
        logger.warning(
            "@vocab marker for bucket %r in %s produced no extension "
            "— the construct after the marker was not recognised or "
            "never grew; this splice slot is DEAD (seed names only) "
            "on every vocabulary-bearing audit",
            bucket_name, rule_path.name,
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
        # Per-marker witness: a marker with non-empty names whose
        # construct never changed is a dead splice slot — the learned
        # lane is silently seed-only forever. The warning is the only
        # runtime witness (rendering must keep degrading gracefully);
        # the render-validity oracle promotes it to a CI failure.
        changed = False

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
                changed = len(block) != consumed
                if changed:
                    modified = True
                out.extend(block)
                i += consumed
                _warn_if_dead(rule_path, bucket_name, names, changed)
                continue

        if i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if r"\(" in stripped and r"\)" in stripped:
                new_line = _extend_alternation(line, names)
                changed = new_line != line
                out.append(new_line)
                i += 1
            elif stripped.startswith("identifier") and "= {" in stripped:
                new_line = _extend_identifier_list(line, names)
                changed = new_line != line
                out.append(new_line)
                i += 1
            elif '= {"' in stripped or ('= {' in stripped and '"' in stripped):
                block, consumed, changed = _extend_python_set(
                    lines, i, names,
                )
                out.extend(block)
                i += consumed
            elif "when !=" in stripped:
                # Same scanning rule as the disjunction branch: extend
                # only the when-clause block and resume after it, so
                # later markers in the file still get processed.
                block, consumed = _extend_when_block(lines, i, names)
                changed = len(block) != consumed
                out.extend(block)
                i += consumed
            else:
                out.append(line)
                i += 1

        if changed:
            modified = True
        _warn_if_dead(rule_path, bucket_name, names, changed)

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
