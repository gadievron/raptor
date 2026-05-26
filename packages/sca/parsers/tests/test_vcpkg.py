"""Tests for the vcpkg.json parser."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.vcpkg import parse


def _write(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "vcpkg.json"
    p.write_text(json.dumps(data))
    return p


def test_simple_string_dependencies(tmp_path):
    p = _write(tmp_path, {"dependencies": ["zlib", "openssl"]})
    deps = parse(p)
    names = sorted(d.name for d in deps)
    assert names == ["openssl", "zlib"]
    assert all(d.ecosystem == "vcpkg" for d in deps)
    assert all(d.pin_style == PinStyle.WILDCARD for d in deps)


def test_object_dependency_with_version(tmp_path):
    p = _write(tmp_path, {
        "dependencies": [{"name": "fmt", "version-string": "9.1.0"}],
    })
    [d] = parse(p)
    assert d.name == "fmt"
    assert d.version == "9.1.0"
    assert d.pin_style == PinStyle.EXACT


def test_object_dependency_with_min_version(tmp_path):
    p = _write(tmp_path, {
        "dependencies": [{"name": "fmt", "version>=": "9.0.0"}],
    })
    [d] = parse(p)
    assert d.version == "9.0.0"
    assert d.pin_style == PinStyle.RANGE


def test_version_field_precedence(tmp_path):
    """``version`` wins over ``version-string`` when both present."""
    p = _write(tmp_path, {
        "dependencies": [{
            "name": "fmt",
            "version": "9.1.0",
            "version-string": "ignored",
        }],
    })
    [d] = parse(p)
    assert d.version == "9.1.0"


def test_purl_format(tmp_path):
    p = _write(tmp_path, {
        "dependencies": [{"name": "openssl", "version-string": "3.0.11"}],
    })
    [d] = parse(p)
    assert d.purl == "pkg:vcpkg/openssl@3.0.11"


def test_purl_without_version(tmp_path):
    p = _write(tmp_path, {"dependencies": ["zlib"]})
    [d] = parse(p)
    assert d.purl == "pkg:vcpkg/zlib"


def test_features_block_extracted(tmp_path):
    """Optional features' deps are emitted alongside the main set —
    over-report rather than under-report."""
    p = _write(tmp_path, {
        "dependencies": ["zlib"],
        "features": {
            "ssl": {"dependencies": ["openssl"]},
            "compression": {"dependencies": ["bzip2", "xz-utils"]},
        },
    })
    deps = parse(p)
    names = sorted(d.name for d in deps)
    assert names == ["bzip2", "openssl", "xz-utils", "zlib"]


def test_invalid_port_name_skipped(tmp_path):
    """Vcpkg port names are lowercase + dashes only. ``OpenSSL`` (with
    capitals) doesn't match — skipped silently."""
    p = _write(tmp_path, {"dependencies": ["OpenSSL", "zlib"]})
    deps = parse(p)
    assert {d.name for d in deps} == {"zlib"}


def test_malformed_json(tmp_path):
    p = tmp_path / "vcpkg.json"
    p.write_text("{not json")
    assert parse(p) == []


def test_top_level_array(tmp_path):
    """Top-level array, not dict — parser must not crash."""
    p = tmp_path / "vcpkg.json"
    p.write_text(json.dumps(["zlib"]))
    assert parse(p) == []


def test_missing_file(tmp_path):
    assert parse(tmp_path / "vcpkg.json") == []


def test_empty_dependencies(tmp_path):
    p = _write(tmp_path, {"name": "myproj", "version": "0.1.0"})
    assert parse(p) == []
