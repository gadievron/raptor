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


def select_wordlist(fingerprint: dict, wordlist_dir: Path | str) -> Path | None:
    """A conventionally-named wordlist under *wordlist_dir*, or None.

    Fingerprint-specific names are preferred; the generic discovery
    lists are the fallback. Search is recursive so a SecLists checkout
    works as-is.
    """
    root = Path(wordlist_dir)
    if not root.is_dir():
        return None
    blob = _signals(fingerprint)
    names: list[str] = []
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
