#!/usr/bin/env python3
"""Use the container's system Node for Playwright and remove its duplicate runtime."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
from importlib.metadata import distribution
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def configure(dist, *, check: bool = False) -> None:
    """Validate the supported override before removing a recorded bundled binary."""
    if sys.platform != "linux":
        raise ValueError("system Node cleanup is for Linux containers only")
    if os.environ.get("PLAYWRIGHT_NODEJS_PATH") != "/usr/bin/node":
        raise ValueError("PLAYWRIGHT_NODEJS_PATH must select /usr/bin/node")
    driver = Path(dist.locate_file("playwright/driver"))
    bundled = driver / "node"
    records = [entry for entry in dist.files or ()
               if str(entry).endswith(".dist-info/RECORD") and len(entry.parts) == 2]
    if len(records) != 1:
        raise ValueError("Playwright must have one installed RECORD")
    record = Path(dist.locate_file(records[0]))
    if record.is_symlink() or driver.is_symlink() or bundled.is_symlink():
        raise ValueError("refusing symlinked Playwright installation")
    rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
    names = [row[0] for row in rows if len(row) == 3]
    if len(names) != len(rows) or len(set(names)) != len(names):
        raise ValueError("invalid or duplicate Playwright RECORD rows")
    selected = [row for row in rows if row[0] == "playwright/driver/node"]
    if bundled.exists():
        info = bundled.stat()
        if not stat.S_ISREG(info.st_mode) or not 4 <= info.st_size <= 256 * 1024 * 1024:
            raise ValueError("unexpected bundled Node file type or size")
        with bundled.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ValueError("bundled Node must be an ELF executable")
            stream.seek(0)
            digest = base64.urlsafe_b64encode(hashlib.file_digest(stream, "sha256").digest()).rstrip(b"=").decode()
        if selected != [["playwright/driver/node", "sha256=" + digest, str(info.st_size)]]:
            raise ValueError("bundled Node does not match its installed RECORD")
        if check:
            raise ValueError("bundled Node remains installed")
    elif selected:
        raise ValueError("RECORD references a missing bundled Node")
    # Exercise the exact driver that will run after cleanup, using the supported override.
    subprocess.run(["/usr/bin/node", str(driver / "package/cli.js"), "--version"],
                   check=True, timeout=30)
    if not bundled.exists():
        return
    out = io.StringIO(newline="")
    csv.writer(out, lineterminator="\n").writerows(
        row for row in rows if row[0] != "playwright/driver/node")
    info = record.stat()
    descriptor, temporary = tempfile.mkstemp(prefix=".playwright-record-", dir=record.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(out.getvalue())
            stream.flush()
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fsync(stream.fileno())
        bundled.unlink()
        os.replace(temporary, record)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    configure(distribution("playwright"), check=args.check)


if __name__ == "__main__":
    main()
