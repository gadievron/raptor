"""Fingerprint-driven ffuf tuning: extensions and wordlist selection.

No wordlists are bundled (size, licensing). The operator provisions a
wordlist directory once; selection resolves conventionally-named lists
(SecLists layout) under it per the target's fingerprint. Both helpers
are pure, table-driven functions — the scanner logs what was chosen
and why, so runs stay reproducible.
"""

from __future__ import annotations

from pathlib import Path

# fingerprint-signal substring -> file extensions worth appending.
_EXTENSION_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("php", "laravel", "wordpress", "drupal", "codeigniter"),
     (".php", ".inc")),
    (("java", "tomcat", "jboss", "jetty", "servlet", "jsp"),
     (".jsp", ".do", ".action")),
    (("asp.net", "iis", "microsoft"),
     (".aspx", ".ashx", ".asmx")),
    (("rails", "ruby"), (".rb",)),
)

# Always-on conservative backup pair when a server product is known.
_BACKUP_EXTENSIONS: tuple[str, ...] = (".bak", ".old")

# Conventional wordlist filenames per fingerprint family, checked in
# order under the operator-provided directory. The generic fallbacks
# match the SecLists Discovery/Web-Content layout.
_WORDLIST_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("php", "laravel", "wordpress", "drupal"),
     ("Common-PHP-Filenames.txt", "PHP.fuzz.txt")),
    (("java", "tomcat", "jboss", "servlet"),
     ("ApacheTomcat.fuzz.txt", "JavaServlets-Common.fuzz.txt")),
    (("asp.net", "iis"),
     ("IIS.fuzz.txt", "SharePoint.fuzz.txt")),
)
_GENERIC_WORDLISTS: tuple[str, ...] = (
    "common.txt",
    "raft-small-words.txt",
    "directory-list-2.3-small.txt",
)


def _signals(fingerprint: dict) -> str:
    return " ".join(str(v) for v in (fingerprint or {}).values()).lower()


def recommend_extensions(fingerprint: dict) -> tuple[str, ...]:
    """ffuf ``-e`` extensions suggested by the target's fingerprint."""
    blob = _signals(fingerprint)
    extensions: list[str] = []
    for needles, exts in _EXTENSION_RULES:
        if any(needle in blob for needle in needles):
            extensions.extend(e for e in exts if e not in extensions)
    if fingerprint and (fingerprint.get("server") or fingerprint.get("server_product")):
        extensions.extend(e for e in _BACKUP_EXTENSIONS if e not in extensions)
    return tuple(extensions)


def preferred_from_recall(rows: list[dict]) -> str | None:
    """The best-performing wordlist NAME from SAGE recall rows, or None.

    Parses the wordlist-effectiveness observations this scanner stores
    at report time ("Wordlist effectiveness on host: name.txt: 12
    hit(s)"). Hint tier only: the caller merely tries this name first —
    a missing file or a better fingerprint match still wins, and
    nothing is ever suppressed on recall.
    """
    import re

    best_name: str | None = None
    best_hits = 0
    # The lookbehind pins each attempt to the start of a name run: a
    # bare [\w.\-]+ head re-scans a hostile run from every offset —
    # quadratic. Dropped starts are mid-name false tokens only.
    pair_re = re.compile(r"(?<![\w.\-])([\w.\-]+\.txt):\s*(\d+)\s*hit")
    for row in rows or []:
        content = str(row.get("content") or "")
        if "Wordlist effectiveness" not in content:
            continue
        for name, hits_text in pair_re.findall(content):
            hits = int(hits_text)
            if hits > best_hits:
                best_hits = hits
                best_name = name
    return best_name


def select_wordlist(
    fingerprint: dict,
    wordlist_dir: Path | str,
    preferred: str | None = None,
) -> Path | None:
    """A conventionally-named wordlist under *wordlist_dir*, or None.

    Fingerprint-specific names are preferred; the generic discovery
    lists are the fallback. Search is recursive so a SecLists checkout
    works as-is. ``preferred`` (a prior from SAGE recall) is tried
    first when given — a hint, not an override: if the file is absent
    the normal ordering applies untouched.
    """
    root = Path(wordlist_dir)
    if not root.is_dir():
        return None
    blob = _signals(fingerprint)
    names: list[str] = []
    if preferred:
        names.append(preferred)
    for needles, candidates in _WORDLIST_RULES:
        if any(needle in blob for needle in needles):
            names.extend(candidates)
    names.extend(_GENERIC_WORDLISTS)
    for name in names:
        direct = root / name
        if direct.is_file():
            return direct
        found = next(iter(sorted(root.rglob(name))), None)
        if found is not None and found.is_file():
            return found
    return None
