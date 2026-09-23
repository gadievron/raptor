"""Console-chokepoint closure detector.

The logging-sink exclusion of the report-writer audit's
exception-relay arm is sound only while every runtime console config
routes through ``configure_cli_logging`` (or the run-logging setup in
core/logging itself). This module enumerates console-handler
acquisition sites mechanically — bare ``basicConfig``, same-line
``addHandler(StreamHandler())``, and the ``logging.config`` loaders —
over the tracked runtime tree.

The closure's regression surface is tree-wide (any new file can add a
bare console sink), so ONE detector serves two consumers and neither
can drift from the other:

* ``.github/scripts/check_console_chokepoint.py`` — per-PR lint gate
  over the same walk;
* ``core/logging/tests/test_console_escaping.py`` — the test-tier
  closure sweep plus the predicate pins.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


def bare_console_config_offences(text: str) -> list[int]:
    """Line numbers of console-handler acquisition outside the
    chokepoint in ``text``.

    basicConfig spellings: an attribute call on any module alias
    (``logging.basicConfig(`` / ``_logging.basicConfig(``) and the
    imported-name form (``from logging import basicConfig [as x]`` —
    the import itself is the marker; importing it has no purpose but
    calling it, and flagging at the import keeps the scan alias-proof).

    Beyond-basicConfig spellings (a plain-formatter console handler
    needs none of the basicConfig vocabulary): same-line
    ``.addHandler(...StreamHandler(...)`` and the
    ``logging.config`` loaders (``dictConfig`` / ``fileConfig`` as
    attribute calls or imports — a config-dict console handler gets
    whatever formatter the dict names, never the escaping one).

    Documented residuals (all evasions of a LINE regex, adversarially
    probed): a VARIABLE-mediated StreamHandler
    (``h = StreamHandler(); root.addHandler(h)``) — deliberately,
    because the FileHandler variant of that idiom is the legitimate
    audit-file pattern (e.g. sca's debug.log handler); the same call
    SPLIT across lines (``root.addHandler(\\n    StreamHandler())``);
    a StreamHandler SUBCLASS; a getattr-mediated loader call; and
    ``logging.config.listen()``. Folding those needs the AST tier,
    not a line regex — the chokepoint doctrine (all console config
    through configure_cli_logging) plus review remain the control for
    deliberate evasion, same as the writer audit's aliased-sink
    residual.
    """
    offences = []
    for m in re.finditer(r"^[^\n#]*?\b\w+\.basicConfig\(", text, re.M):
        offences.append(text.count("\n", 0, m.start()) + 1)
    # Anchor whitespace is horizontal-only ([^\S\n]): with MULTILINE,
    # ^\s* re-scans whole blank-line runs from every line start —
    # quadratic on planted whitespace; leading indent never spans
    # lines, so the match set is unchanged.
    # (?=\S) pins each whitespace run to end where the import body
    # begins (same language — the line class absorbed any remainder):
    # unpinned, the runs split against the line class from every
    # anchor — quadratic on import-shaped lines followed by
    # whitespace runs.
    for m in re.finditer(
            r"^[^\S\n]*from\s+logging\s+import\s+(?=\S)[^\n]*\bbasicConfig\b",
            text, re.M):
        offences.append(text.count("\n", 0, m.start()) + 1)
    for m in re.finditer(
            r"^[^\n#]*?\.addHandler\([^\n]*\bStreamHandler\(",
            text, re.M):
        offences.append(text.count("\n", 0, m.start()) + 1)
    for m in re.finditer(
            r"^[^\n#]*?\b(?:dictConfig|fileConfig)\(", text, re.M):
        offences.append(text.count("\n", 0, m.start()) + 1)
    for m in re.finditer(
            r"^[^\S\n]*from\s+logging\.config\s+import\s+(?=\S)[^\n]*"
            r"\b(?:dictConfig|fileConfig)\b",
            text, re.M):
        offences.append(text.count("\n", 0, m.start()) + 1)
    return sorted(set(offences))


def _candidates(repo: Path) -> list[str]:
    """Tracked runtime files that could host a console sink.

    Exempt: test files, subsystem ``scripts/`` dirs (outside the
    launcher), core/logging itself (the chokepoint's home), and the
    buffer-capture harness (raptor-self-test's child harness logs into
    an in-memory buffer, never a TTY).
    """
    # Universe = every tracked tree that hosts runtime Python: core/,
    # packages/, engine/, plugins/ (in-session hook launchers included),
    # libexec/ launchers, and the root raptor*.py modules — the same
    # runtime universe the repo's other tree-wide gates walk. The
    # closure claim is tree-wide, so a new runtime tree must be added
    # HERE (and a fixture row in the candidate-universe test) or the
    # gate silently never sees it.
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files",
         "core", "packages", "engine", "plugins", "libexec",
         "raptor*.py"],
        capture_output=True, text=True, check=True,
    )
    rels = []
    for rel in proc.stdout.splitlines():
        parts = rel.split("/")
        if ("tests" in parts or "scripts" in parts
                or parts[-1].startswith("test_")
                or parts[-1] == "conftest.py"):
            continue
        if rel.startswith("core/logging/"):
            continue
        if rel == "libexec/raptor-self-test":
            # basicConfig(stream=<StringIO buffer>) inside a child
            # harness heredoc — captured, never a TTY.
            continue
        if not (rel.endswith(".py") or rel.startswith("libexec/")):
            continue
        rels.append(rel)
    return rels


def runtime_console_offences(repo: Path) -> list[str]:
    """``<rel>:<line>`` console-config offences across the tracked
    runtime tree.

    Raises ``OSError`` / ``subprocess.CalledProcessError`` when git or
    the checkout is unavailable — callers choose skip (test tier) vs
    fail (lint gate).
    """
    offenders: list[str] = []
    for rel in _candidates(repo):
        try:
            text = (repo / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # Skip-on-undecodable is the sibling-scan convention; a
            # non-UTF-8 tracked candidate must not kill the sweep.
            continue
        offenders.extend(
            f"{rel}:{line}" for line in bare_console_config_offences(text)
        )
    return offenders
