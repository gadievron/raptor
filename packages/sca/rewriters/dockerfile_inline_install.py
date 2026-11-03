"""Dockerfile ``RUN pip install <name>==<version>`` rewriter.

The inline-install bumper walker emits :class:`RewriteEdit`
records whose ``locator`` is the PyPI package name and
``extra["kind"] == "inline_install_pip"``. This module finds the
matching ``<name>==<version>`` token inside any ``RUN`` line in
the Dockerfile and rewrites the version.

The pip entry point covers PyPI exact-pinned installs —
``pip install <name>==<version>``. Other ecosystems
(``apt-get install foo=1.0``,
``gem install foo -v 1.0``) have parsers in
``packages.sca.parsers.inline_installs`` but no bumper walker
yet; npm pins use the separate conservative entry point below. Add when
triggers fire.

Like ``dockerfile_arg``, this module is NOT ``@register``'d
directly — the Dockerfile predicate is owned by
``dockerfile_from`` which routes inline-install edits here based
on ``extra["kind"]``.
"""

from __future__ import annotations

import logging
import re

from . import RewriteEdit, RewriteResult, rewrite_file_with
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def rewrite_dockerfile_inline_install(
    path: Path, edits: list[RewriteEdit],
) -> list[RewriteResult]:
    r"""Apply inline-pip install version-pin edits to a Dockerfile.

    Each edit's ``locator`` is the PyPI package name; the regex
    matches ``<name>==<version>`` with optional surrounding
    quoting / whitespace inside any line that looks like part of
    a ``RUN`` instruction. We don't try to parse RUN bodies —
    they can span multiple physical lines via ``\`` continuation
    — instead we rewrite the first matching ``<name>==<value>``
    token anywhere in the file, refusing to touch any other line
    that happens to contain ``<name>==``.
    """
    return rewrite_file_with(path, edits, _apply_one)


def _apply_one(
    text: str, edit: RewriteEdit,
) -> tuple[str, RewriteResult]:
    """Apply a single inline-install edit. Refuses on value
    mismatch (the file's value differs from what the plan
    expected) so a stale plan never silently corrupts an
    already-bumped pin.
    """
    name = re.escape(edit.locator)
    # Match ``<name>==<version>`` as a whole-word token.
    # Word-boundary before; version captured up to next
    # whitespace / quote / EOL / shell metachar. Tolerates
    # extras / markers like ``<name>[extra]==1.0`` only
    # implicitly (the ``[extra]`` portion isn't between name and
    # ``==`` so the regex sees ``<name>`` + ``[extra]==1.0``
    # which doesn't match — those are skipped).
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_.\-])({name}==)([A-Za-z0-9.+\-]+)",
    )
    # Multi-stage Dockerfiles repeat the same install line per stage
    # (``pip install foo==1.0`` in builder AND runtime). Verdicts are
    # computed across ALL occurrences and every one still at the old
    # value is bumped — a first-match ``count=1`` substitution bumped
    # one stage and left its twin on the vulnerable version while the
    # run reported applied.
    matches = list(pattern.finditer(text))
    if not matches:
        return text, RewriteResult(
            edit=edit, applied=False, reason="not_found",
        )
    values = [m.group(2) for m in matches]
    needs_bump = [
        m for m in matches
        if m.group(2) == edit.old_value and m.group(2) != edit.new_value
    ]
    if not needs_bump:
        if all(v == edit.new_value for v in values):
            return text, RewriteResult(
                edit=edit, applied=False, reason="no_change",
            )
        stray = next(v for v in values if v != edit.new_value)
        return text, RewriteResult(
            edit=edit, applied=False,
            reason=(
                f"value_mismatch: file has {stray!r}, "
                f"plan expected {edit.old_value!r}"
            ),
        )
    # Splice the value span directly, back-to-front so earlier
    # offsets stay valid (also removes the re.sub template
    # interpolation of new_value entirely).
    new_text = text
    for m in sorted(needs_bump, key=lambda m: m.start(2), reverse=True):
        new_text = new_text[:m.start(2)] + edit.new_value + new_text[m.end(2):]
    stray_values = sorted(set(values) - {edit.old_value, edit.new_value})
    reason = "applied"
    if stray_values:
        reason = (
            f"partial: {len(needs_bump)} occurrence(s) bumped; other "
            f"value(s) left in place: {stray_values!r}"
        )
    return new_text, RewriteResult(
        edit=edit, applied=True, reason=reason,
    )




# npm discovery and rewriting deliberately share this conservative grammar.
_NPM_PIN = re.compile(r'(?P<name>(?:@[A-Za-z0-9-~][A-Za-z0-9._~-]*/)?[A-Za-z0-9-~][A-Za-z0-9._~-]*)@(?P<version>(?:0|[1-9][0-9]{0,15})\.(?:0|[1-9][0-9]{0,15})\.(?:0|[1-9][0-9]{0,15}))\Z')
_NPM_VALUE_FLAGS = frozenset({'--prefix', '--cache', '--workspace', '-w', '--userconfig'})
_NPM_BOOL_FLAGS = frozenset({'-g', '--global', '--ignore-scripts', '--no-audit', '--no-fund',
                            '--save', '--save-dev', '--save-exact', '-S', '-D', '-E', '--no-save'})


def _npm_commands(raw: str):
    """Yield literal shell words and offsets; never evaluate shell syntax.

    Unsupported substitutions, redirects, pipelines and compound commands are
    not rewrite surfaces. Quotes around a whole word are preserved, while mixed
    quoting/escapes in a word are deliberately outside this narrow grammar.
    """
    # Docker comment-only continuation lines are transparent. Keep offsets.
    raw = re.sub(r'(?m)^[ \t]*#[^\n]*', lambda m: ' ' * len(m[0]), raw)
    raw = re.sub(r'\\\r?\n', lambda m: ' ' * len(m[0]), raw)
    commands: list[list[tuple[str | None, int]]] = []
    words: list[tuple[str | None, int]] = []
    i = 0
    while i < len(raw):
        if raw[i].isspace():
            i += 1
            continue
        if raw[i] == '#':
            break
        if raw[i] in ';|&':
            op = raw[i:i + 2] if raw[i:i + 2] in {'&&', '||'} else raw[i]
            if op not in {';', '&&', '||'}:
                return []
            commands.append(words); words = []; i += len(op)
            continue
        if raw[i] in '<>()':
            return []
        start, quote = i, None
        while i < len(raw):
            c = raw[i]
            if quote:
                if c == quote:
                    quote = None
            elif c in "'\"":
                quote = c
            elif c.isspace() or c in ';|&<>()':
                break
            if c == '\\':
                i += 1
            i += 1
        if quote:
            return []
        word = raw[start:i]
        offset = start
        if len(word) >= 2 and word[0] in "'\"" and word[-1] == word[0]:
            word = word[1:-1]; offset += 1
        literal_word = None if any(c in word for c in "'\"\\$`") else word
        words.append((literal_word, offset))
    commands.append(words)
    return commands


def npm_install_pins(text: str) -> list[tuple[str, str, int, int]]:
    """Return (name, version, version-start, version-end) for safe RUN pins.

    Only direct shell-form npm install/i/add commands with known flags qualify.
    JSON RUNs, heredocs, custom shells and explicit registry overrides are skipped.
    """
    from core.dockerfile.parser import parse_dockerfile, _heredoc_tags
    if re.search(r'(?im)^[ \t]*#[ \t]*escape[ \t]*=[ \t]*`', text):
        return []
    offsets = [0] + [m.end() for m in re.finditer('\n', text)]
    pins = []
    custom_shell = False
    instructions = parse_dockerfile(text)
    for inst in instructions:
        if inst.directive == 'ENV' and re.search(r'(?i)\bnpm_config_(?:registry|userconfig)\b', inst.args):
            return []
        if inst.directive in {'COPY', 'ADD'} and '.npmrc' in inst.args:
            return []
        if inst.directive == 'RUN':
            for words in _npm_commands(inst.args):
                values = [word for word, _ in words]
                if values[:2] == ['npm', 'config'] and any(
                        value and 'registry' in value.lower() for value in values[2:]):
                    return []
    for inst in instructions:
        if inst.directive == 'SHELL':
            custom_shell = True
        if (inst.directive != 'RUN' or custom_shell or inst.args.lstrip().startswith('[')
                or _heredoc_tags(inst.args)):
            continue
        first = offsets[inst.line - 1]
        last_line = inst.line + inst.raw.count('\n')
        last = offsets[last_line] if last_line < len(offsets) else len(text)
        raw = text[first:last]
        head = re.match(r'[ \t]*RUN\b', raw, re.I)
        if head is None:
            continue
        for words in _npm_commands(' ' * head.end() + raw[head.end():]):
            if len(words) < 3 or words[0][0] != 'npm' or words[1][0] not in {'install', 'i', 'add'}:
                continue
            if any(word is None for word, _ in words):
                continue
            candidates = []
            skip_value = False
            valid = True
            for word, pos in words[2:]:
                if skip_value:
                    skip_value = False
                    continue
                flag = word.split('=', 1)[0]
                # Never query the configured client for a command using a
                # different registry or per-command npm configuration.
                if flag in {'--registry', '--userconfig'}:
                    valid = False; break
                if flag in _NPM_VALUE_FLAGS:
                    skip_value = '=' not in word
                    continue
                if word in _NPM_BOOL_FLAGS:
                    continue
                if word.startswith('-'):
                    valid = False; break
                pin = _NPM_PIN.fullmatch(word)
                if pin is not None and len(pin['name']) <= 214:
                    start = first + pos + pin.start('version')
                    candidates.append((pin['name'], pin['version'], start, start + len(pin['version'])))
            if valid and not skip_value:
                pins.extend(candidates)
    return pins


def rewrite_dockerfile_npm_install(path: Path, edits: list[RewriteEdit]) -> list[RewriteResult]:
    """Rewrite only exact npm RUN pins, preserving surrounding shell text."""
    return rewrite_file_with(path, edits, _apply_npm)


def _apply_npm(text: str, edit: RewriteEdit) -> tuple[str, RewriteResult]:
    if _NPM_PIN.fullmatch(edit.locator + '@' + edit.new_value) is None:
        return text, RewriteResult(edit=edit, applied=False, reason='invalid_target_version')
    matches = [(version, start, end) for name, version, start, end in npm_install_pins(text) if name == edit.locator]
    if not matches:
        return text, RewriteResult(edit=edit, applied=False, reason='not_found')
    # A stale mixed-version plan must not partially change a multi-stage file.
    if any(v not in {edit.old_value, edit.new_value} for v, _, _ in matches):
        return text, RewriteResult(edit=edit, applied=False, reason='value_mismatch')
    changes = [(start, end) for v, start, end in matches if v == edit.old_value and v != edit.new_value]
    if not changes:
        return text, RewriteResult(edit=edit, applied=False, reason='no_change')
    for start, end in reversed(changes):
        text = text[:start] + edit.new_value + text[end:]
    return text, RewriteResult(edit=edit, applied=True)
