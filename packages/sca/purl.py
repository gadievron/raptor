"""``raptor-sca purl`` — tiny utility that prints a canonical purl.

Useful as glue for shell scripts: build cache keys, construct
CycloneDX ``bom-ref`` values, or hand the string to other tooling.

    raptor-sca purl npm   lodash                                  4.17.21
    raptor-sca purl PyPI  django                                  4.2.10
    raptor-sca purl Maven org.apache.logging.log4j:log4j-core     2.17.1
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from .ecosystems import canonicalise, known_list


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    eco_canonical = canonicalise(args.ecosystem)
    if eco_canonical is None:
        print(
            f"raptor-sca purl: unknown ecosystem {args.ecosystem!r}; "
            f"expected one of {known_list()}",
            file=sys.stderr,
        )
        return 2
    if not _valid_name(args.name):
        print(
            f"raptor-sca purl: invalid package name {args.name!r}",
            file=sys.stderr,
        )
        return 2
    if not _valid_version(args.version):
        print(
            f"raptor-sca purl: invalid version {args.version!r}",
            file=sys.stderr,
        )
        return 2
    print(f"pkg:{eco_canonical.lower()}/{args.name}@{args.version}")
    return 0


def _valid_name(name: str) -> bool:
    """Reject path-traversal / shell-metachar / whitespace shapes.

    Allowed shapes:
      ``lodash``                    bare package name
      ``@types/node``               npm scoped (one leading @, one /)
      ``org.apache.foo:bar``        Maven groupId:artifactId
    """
    if not name or name in (".", ".."):
        return False
    if "\\" in name or ".." in name:
        return False
    if any(c in name for c in (" ", "\t", "\n", "\r")):
        return False
    if "/" in name:
        # Only npm-scoped (@scope/name) is allowed to contain a slash.
        if not (name.startswith("@") and name.count("/") == 1):
            return False
    return True


def _valid_version(version: str) -> bool:
    """Reject path-traversal / whitespace / slash shapes in version."""
    if not version or version in (".", ".."):
        return False
    if "\\" in version or ".." in version or "/" in version:
        return False
    if any(c in version for c in (" ", "\t", "\n", "\r")):
        return False
    return True


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca purl",
        description="Print a canonical purl for the given dependency coords.",
    )
    p.add_argument("ecosystem",
                   help='ecosystem name (e.g., "npm", "PyPI", "Maven")')
    p.add_argument("name",
                   help='package name (Maven uses "groupId:artifactId")')
    p.add_argument("version", help="exact version")
    return p.parse_args(argv)


if __name__ == "__main__":               # pragma: no cover
    sys.exit(main(sys.argv[1:]))


__all__ = ["main"]
