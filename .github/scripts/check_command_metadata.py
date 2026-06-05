#!/usr/bin/env python3
"""Lint slash-command metadata: every ``.claude/commands/*.md`` must
carry a parseable ``dispatch:`` frontmatter field, and any
``exclude_from_listing: true`` flag must match the hardcoded exclusion
list in ``commands.md``.

Failing modes:

* missing ``dispatch:`` — Claude would have to infer the dispatch
  from the .md body, defeating the "literal dispatch" rule.
* unknown dispatch shape — only ``skill`` and command-lines beginning
  with ``libexec/``, ``bin/``, ``python3 raptor.py``, or ``bash`` are
  accepted today; new shapes need explicit allowlisting here.
* missing dispatch target — for executable-form dispatches, the
  first-token path must exist on disk (catches typo'd or renamed
  libexec paths at PR time, not at operator-call time).
* exclusion drift — anything with ``exclude_from_listing: true``
  must also appear in commands.md's hardcoded "Exclude internal/
  duplicate commands" list; and vice-versa. Single source of truth.

Run::

    python3 .github/scripts/check_command_metadata.py

Exits 0 on clean, non-zero with a per-violation report otherwise.
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
COMMANDS_DIR = REPO / ".claude" / "commands"
COMMANDS_INDEX = COMMANDS_DIR / "commands.md"

# Dispatch tokens we accept. ``skill`` means "no single libexec — see
# the body of the .md for multi-step workflow." Everything else must
# resolve to a file on disk that the operator's machine can run.
_ACCEPTED_DISPATCH_PREFIXES = (
    "libexec/",
    "bin/",
    "python3 raptor.py",
    "bash ",
)


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Return the YAML-ish frontmatter as a flat dict. The repo uses
    a tiny subset (string scalars only, one key per line) so a real
    YAML parser would be overkill — and would add a CI dependency
    we don't have today."""
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}
    body = text[4:end]
    out: dict[str, str] = {}
    for line in body.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        out[key.strip()] = val.strip()
    return out


def _check_dispatch(name: str, dispatch: str) -> list[str]:
    errs: list[str] = []
    if dispatch == "skill":
        return errs
    if not any(dispatch.startswith(p) for p in _ACCEPTED_DISPATCH_PREFIXES):
        errs.append(
            f"/{name}: dispatch starts with an unrecognised prefix "
            f"({dispatch!r}); allowlist new shapes in "
            f"check_command_metadata.py if intentional"
        )
        return errs
    # First token of the dispatch is the binary / script — must exist.
    # ``python3 raptor.py <mode>`` is special: raptor.py must exist.
    # ``bash <path>`` similarly.
    tokens = shlex.split(dispatch)
    if not tokens:
        errs.append(f"/{name}: empty dispatch after split")
        return errs
    if tokens[0] in ("python3", "bash"):
        if len(tokens) < 2:
            errs.append(f"/{name}: dispatch {dispatch!r} missing script path")
            return errs
        target = REPO / tokens[1]
    else:
        target = REPO / tokens[0]
    if not target.exists():
        errs.append(
            f"/{name}: dispatch target {target.relative_to(REPO)} "
            f"does not exist (renamed or typo'd?)"
        )
    return errs


def main() -> int:
    if not COMMANDS_DIR.is_dir():
        print(f"FATAL: {COMMANDS_DIR} not a directory", file=sys.stderr)
        return 2
    md_files = sorted(COMMANDS_DIR.glob("*.md"))
    if not md_files:
        print(f"FATAL: no .md files under {COMMANDS_DIR}", file=sys.stderr)
        return 2

    errs: list[str] = []
    excluded_via_frontmatter: set[str] = set()
    for md in md_files:
        name = md.stem
        fm = _parse_frontmatter(md.read_text())
        dispatch = fm.get("dispatch")
        if not dispatch:
            errs.append(
                f"/{name}: missing ``dispatch:`` frontmatter field. Add either "
                f"a command-line (libexec/... | bin/... | python3 raptor.py "
                f"<mode> | bash ...) or the literal ``skill`` for multi-step "
                f"workflows the body owns."
            )
            continue
        errs.extend(_check_dispatch(name, dispatch))
        if fm.get("exclude_from_listing", "").lower() == "true":
            excluded_via_frontmatter.add(name)

    # Parity: commands.md's hardcoded exclusion list must match the
    # frontmatter-flagged set. Pull the names out of the documented
    # text by looking for the pattern "raptor-X" / "/X" in the
    # exclusion sentence.
    commands_md = COMMANDS_INDEX.read_text()
    excl_pattern = re.compile(
        r"internal/duplicate commands.*?(?=\.\s|\n\n)",
        re.IGNORECASE | re.DOTALL,
    )
    m = excl_pattern.search(commands_md)
    if not m:
        errs.append(
            "commands.md: could not locate the 'Exclude internal/duplicate "
            "commands' sentence — has the wording changed? Update this "
            "lint or restore the sentence."
        )
    else:
        excluded_in_index = set(re.findall(r"raptor-[\w-]+|\b\w[\w-]+\b", m.group(0)))
        # Drop noise tokens; only keep names that correspond to .md files.
        md_names = {p.stem for p in md_files}
        excluded_in_index = excluded_in_index & md_names

        missing_in_md = excluded_in_index - excluded_via_frontmatter
        missing_in_index = excluded_via_frontmatter - excluded_in_index
        for n in sorted(missing_in_md):
            errs.append(
                f"/{n}: listed as excluded in commands.md but missing "
                f"``exclude_from_listing: true`` frontmatter"
            )
        for n in sorted(missing_in_index):
            errs.append(
                f"/{n}: has ``exclude_from_listing: true`` frontmatter but "
                f"not listed in commands.md's exclude sentence"
            )

    if errs:
        print("Command-metadata lint failed:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"OK: {len(md_files)} command .md files lint-clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
