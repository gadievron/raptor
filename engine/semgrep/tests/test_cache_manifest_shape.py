"""Malformed pack identities are rejected before hashing or cache writes."""

import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

import pytest


@pytest.mark.parametrize("pack", [{}, []], ids=["object", "array"])
def test_verified_import_rejects_unhashable_pack_ids(tmp_path, monkeypatch, pack):
    path = Path(__file__).resolve().parents[1] / "tools" / "cache-packs.py"
    spec = importlib.util.spec_from_file_location("owned_cache_manifest_tool", path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    cache = tmp_path / "cache"
    cache.mkdir()
    previous = cache / "previous.json"
    previous.write_bytes(b"unchanged")
    monkeypatch.setattr(tool, "CACHE_DIR", cache)
    bundle = tmp_path / "owned.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("manifest.json", json.dumps({"schema": 1, "packs": [pack]}))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()

    with pytest.raises(SystemExit, match="Invalid manifest pack list"):
        tool._verified_import(bundle, digest)

    assert list(cache.iterdir()) == [previous]
    assert previous.read_bytes() == b"unchanged"
