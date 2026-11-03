"""Restricted metadata for Debian common-license aliases; never traverse links."""
from pathlib import PurePosixPath
import re

COMMON_DIRECTORY = "/usr/share/common-licenses/"
COMMON_ALIASES = ("GPL", "LGPL", "GFDL")


def common_alias_target(path: str, link: str) -> str:
    """Accept only a direct, relative, versioned target in the same family."""
    family = PurePosixPath(path).name
    if path != COMMON_DIRECTORY + family or family not in COMMON_ALIASES:
        raise ValueError("unexpected common-license alias")
    if not isinstance(link, str) or not re.fullmatch(re.escape(family) + r"-[0-9]+(?:\.[0-9]+)*", link):
        raise ValueError("unsafe or unexpected common-license alias target")
    return COMMON_DIRECTORY + link


def corrected_common_reference(name: str, copyright_text: str) -> str | None:
    """Resolve known Debian reference spelling errors, retaining the original.

    GPL's version 2.0 names the version installed as GPL-2. Gzip's GFDL-3
    reference is accepted only inside an explicit GFDL 1.3 grant stanza.
    No generic family alias or missing version is inferred.
    """
    if name == "GPL-2.0":
        return "GPL-2"
    if name != "GFDL-3":
        return None
    for stanza in re.split(r"(?m)(?=^License:)", copyright_text):
        if not stanza.startswith("License: GFDL-1.3+-no-invariant\n"):
            continue
        body = stanza.split("\n\n", 1)[0]
        if (COMMON_DIRECTORY + name in body
                and "GNU Free Documentation License, Version 1.3 or" in " ".join(body.split())):
            return "GFDL-1.3"
    return None
