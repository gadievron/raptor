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
