"""Descriptor conversion failures retain unknown-size semantics."""
from __future__ import annotations

import pytest

from core.oci.manifest import parse_image_index, parse_image_manifest


class _RefusedSize(str):
    def __int__(self):
        raise OverflowError("controlled size conversion refusal")


def _parse_size(kind, size):
    descriptor = {"digest": "sha256:" + "a" * 64, "size": size}
    if kind == "manifest":
        parsed = parse_image_manifest({
            "config": {"digest": "sha256:" + "b" * 64},
            "layers": [descriptor],
        })
        entries = parsed.layers
    else:
        entries = parse_image_index({"manifests": [descriptor]})
    assert len(entries) == 1
    assert entries[0].digest == descriptor["digest"]
    return entries[0].size


@pytest.mark.parametrize("kind", ["manifest", "index"])
def test_size_conversion_overflow_remains_unknown(kind):
    assert _parse_size(kind, _RefusedSize("123")) == 0


@pytest.mark.parametrize("kind", ["manifest", "index"])
@pytest.mark.parametrize("size, expected", [(123, 123), (123.75, 123), ("123", 123), (None, 0)])
def test_admitted_sizes_keep_existing_conversion(kind, size, expected):
    assert _parse_size(kind, size) == expected
