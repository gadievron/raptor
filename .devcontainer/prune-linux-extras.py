#!/usr/bin/env python3
"""Remove unused platform bundles and upstream test fixtures from Linux images."""
import argparse
from pathlib import Path
import re
import shutil
import sys


_GUARD = re.compile(
    r'if \(process\.platform === "darwin" \|\| process\.platform === "win32"\) \{\s*'
    r'const \{ reflinkFileSync \} = __require\("@reflink/reflink"\);'
)


def checked_path(root, relative):
    path = root
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("symlink in cleanup target")
    return path


def prune_pnpm(root):
    """Delete the scope only while both shipped entrypoints guard its sole use."""
    scope = checked_path(root, "dist/node_modules/@reflink")
    if not scope.exists():
        return
    for relative in ("dist/pnpm.mjs", "dist/worker.js"):
        path = checked_path(root, relative)
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            print("WARNING: pnpm layout changed; retaining reflink packages")
            return
        text = path.read_text(encoding="utf-8")
        if text.count("@reflink/") != 1 or len(_GUARD.findall(text)) != 1:
            print("WARNING: pnpm platform guard changed; retaining reflink packages")
            return
    # Do not miss a newly introduced consumer outside the two checked bundles.
    for path in root.rglob("*"):
        if scope in path.parents or path.suffix not in {".js", ".mjs", ".cjs"}:
            continue
        relative = path.relative_to(root).as_posix()
        checked_path(root, relative)
        if relative in {"dist/pnpm.mjs", "dist/worker.js"}:
            continue
        if path.stat().st_size > 64 * 1024 * 1024 or "@reflink/" in path.read_text(encoding="utf-8"):
            print("WARNING: additional pnpm consumer; retaining reflink packages")
            return
    shutil.rmtree(scope)
    print("Removed pnpm's macOS/Windows-only reflink dependency scope")


def prune_nvm_tests(root):
    """Keep NVM's runtime and license; omit its development test suite."""
    if not checked_path(root, "nvm.sh").is_file() or not checked_path(root, "LICENSE.md").is_file():
        print("WARNING: NVM layout changed; retaining test fixtures")
        return
    tests = checked_path(root, "test")
    if tests.is_dir():
        shutil.rmtree(tests)
        print("Removed NVM's development test fixtures")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pnpm-root", type=Path)
    parser.add_argument("--nvm-root", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        return
    for root, action in ((args.pnpm_root, prune_pnpm), (args.nvm_root, prune_nvm_tests)):
        if root is not None:
            if root.is_symlink():
                raise ValueError("cleanup root must not be a symlink")
            action(root)


if __name__ == "__main__":
    main()
