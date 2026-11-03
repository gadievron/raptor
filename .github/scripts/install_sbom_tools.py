#!/usr/bin/env python3
"""Install the pinned Linux/amd64 Syft binary after checking its archive hash."""
from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path
import re
import tarfile
import tomllib
from urllib.parse import urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 128 * 1024 * 1024


def install(pins: dict, out: Path) -> None:
    if type(pins.get("schema_version")) is not int or pins["schema_version"] != 1:
        raise ValueError("unsupported tool pins")
    entry = pins["syft"]
    if (urlparse(entry["url"]).scheme != "https"
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or entry["member"] != "syft"):
        raise ValueError("invalid Syft source, checksum or member")
    if out.exists() or out.is_symlink():
        raise ValueError("tool output must be a new directory")
    with urlopen(entry["url"], timeout=60) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("Syft archive checksum or size mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        matches = [member for member in archive.getmembers() if member.name == entry["member"]]
        if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= MAX_BYTES:
            raise ValueError("invalid Syft archive member")
        payload = archive.extractfile(matches[0]).read(MAX_BYTES + 1)
        if len(payload) != matches[0].size:
            raise ValueError("truncated Syft binary")
    out.mkdir(parents=True, exist_ok=False)
    target = out / "syft"
    target.write_bytes(payload)
    target.chmod(0o755)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", type=Path, default=ROOT / ".github/sbom-tools.toml")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.pins.open("rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError("tool pin file exceeds size budget")
        install(tomllib.loads(raw.decode("utf-8")), args.out)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        parser.exit(1, f"SBOM tool installation failed: {exc}\n")


if __name__ == "__main__":
    main()
