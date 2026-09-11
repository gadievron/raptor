"""Decompression-budget regression tests — BOTH directions.

This limit has flip-flopped (unbounded → flat 256 MiB → ratio
budget); these tests are the enforcement for the rationale block on
the constants in ``core/oci/blob.py``. The legit-direction pins use
the MEASURED sizes of real layers a stress sweep wrongly refused
under the flat cap; the bomb-direction pins prove ratio-shaped
inputs still die.
"""

from __future__ import annotations

import gzip
import io
import tarfile

import pytest

from core.oci import blob as blob_mod
from core.oci.blob import (
    DECOMPRESSION_BUDGET_CEILING,
    DECOMPRESSION_BUDGET_FLOOR,
    DECOMPRESSION_RATIO_BOUND,
    extract_files_from_layer,
    layer_decompression_budget,
)
from core.tar import TarTotalBytesExceeded


# ---------------------------------------------------------------------------
# Budget function — legit direction (would FAIL under the flat cap)
# ---------------------------------------------------------------------------

# (compressed, decompressed) measured on the exact layer digests the
# sweep refused: python:3.8, mysql:8, rust:alpine3.16.
_MEASURED_LEGIT_LAYERS = [
    (211_300_000, 597_200_000),
    (132_400_000, 548_200_000),
    (216_000_000, 667_200_000),
]


@pytest.mark.parametrize(("compressed", "decompressed"),
                         _MEASURED_LEGIT_LAYERS)
def test_budget_admits_measured_legitimate_layers(
    compressed: int, decompressed: int,
) -> None:
    """Real base-image layers (ratios 2.8-4.1x) fit the budget. Under
    the old flat 256 MiB cap every one of these was refused."""
    assert layer_decompression_budget(compressed) > decompressed


def test_budget_regions() -> None:
    floor = DECOMPRESSION_BUDGET_FLOOR
    # Floor region: tiny/absent/lying compressed sizes never scale
    # the budget down (or up) — hostile manifests can't pick a bound.
    assert layer_decompression_budget(None) == floor
    assert layer_decompression_budget(0) == floor
    assert layer_decompression_budget(-5) == floor
    assert layer_decompression_budget(1024) == floor
    # Ratio region.
    mid = 100 * 1024 * 1024
    assert layer_decompression_budget(mid) == DECOMPRESSION_RATIO_BOUND * mid
    # Ceiling region: absolute work bound holds however large the
    # compressed input claims to be.
    assert (layer_decompression_budget(10 * 1024 ** 3)
            == DECOMPRESSION_BUDGET_CEILING)


# ---------------------------------------------------------------------------
# Extraction — bomb direction (must keep failing)
# ---------------------------------------------------------------------------

def _gzip_layer_with_member(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue())


def _gzip_layer_declaring_huge_member(declared: int) -> bytes:
    """A syntactically valid tar whose first member DECLARES a huge
    size — the budget charges header-declared sizes before reading
    data, which is exactly how a decompression bomb's cost is
    bounded, so no huge body is needed to exercise the refusal."""
    info = tarfile.TarInfo("var/lib/dpkg/status")
    info.size = declared
    header = info.tobuf(format=tarfile.GNU_FORMAT)
    return gzip.compress(header)


def test_true_bomb_shape_refused_with_production_constants() -> None:
    """A member claiming more than the ceiling dies whatever the
    claimed compressed size — the absolute work bound holds."""
    layer = _gzip_layer_declaring_huge_member(
        DECOMPRESSION_BUDGET_CEILING + 1,
    )
    with pytest.raises(TarTotalBytesExceeded, match="bomb-shape"):
        extract_files_from_layer(
            iter([layer]), {"var/lib/dpkg/status"},
            compressed_size=len(layer),
        )


def test_high_ratio_bomb_refused_at_scaled_budget(monkeypatch) -> None:
    """Ratio-shaped bomb: tiny fetched blob, huge declared expansion.
    Floor shrunk so the test stays byte-cheap; the production floor
    only changes WHERE the refusal lands, not whether it does."""
    monkeypatch.setattr(blob_mod, "DECOMPRESSION_BUDGET_FLOOR", 4096)
    layer = _gzip_layer_declaring_huge_member(5 * 1024 * 1024)
    # compressed_size = actual tiny transfer → budget = max(4096,
    # 12 * len(layer)) ≪ 5 MiB declared.
    with pytest.raises(TarTotalBytesExceeded, match="bomb-shape"):
        extract_files_from_layer(
            iter([layer]), {"var/lib/dpkg/status"},
            compressed_size=len(layer),
        )


def test_legit_shape_layer_extracts_under_scaled_budget(
    monkeypatch,
) -> None:
    """Legit-shape (low-ratio) layer larger than a shrunken floor is
    ACCEPTED because the ratio term scales the budget with the real
    transfer size — the flat-cap regression this file exists for."""
    monkeypatch.setattr(blob_mod, "DECOMPRESSION_BUDGET_FLOOR", 4096)
    import random
    data = random.Random(42).randbytes(100_000)   # incompressible → ratio ~1
    layer = _gzip_layer_with_member("var/lib/dpkg/status", data)
    # Old flat behaviour == floor-only budget: 100 KB > 4096 → would
    # refuse. Ratio budget: 12 * len(layer) ≈ 1.2 MB → accepted.
    got = extract_files_from_layer(
        iter([layer]), {"var/lib/dpkg/status"},
        compressed_size=len(layer),
    )
    assert got["var/lib/dpkg/status"] == data


def test_lying_descriptor_cannot_buy_cpu_beyond_fetched_bytes(
    monkeypatch,
) -> None:
    """The amplification the fetched-bytes guard closes: a manifest
    DECLARING a huge compressed size raised the declared-size budget
    toward the ceiling while serving a kilobytes-sized bomb — up to
    ~1600:1 of decompression CPU per fetched byte. The budget must
    follow the bytes actually served, whatever the descriptor claims."""
    monkeypatch.setattr(blob_mod, "DECOMPRESSION_BUDGET_FLOOR", 4096)
    # A REAL expansion: 5 MiB of zeros gzip to a few KiB, so the
    # fetched-bytes budget (max(4096, 12 * ~5 KiB)) is exceeded by the
    # actual decompressed output long before 5 MiB.
    bomb = _gzip_layer_with_member(
        "var/lib/dpkg/status", b"\0" * (5 * 1024 * 1024))
    with pytest.raises(blob_mod.DecompressionBudgetExceeded):
        extract_files_from_layer(
            iter([bomb]), {"var/lib/dpkg/status"},
            # The lie: declared compressed size far above the actual
            # transfer — the OLD budget scaled off this and admitted
            # the whole 5 MiB expansion.
            compressed_size=512 * 1024 * 1024,
        )


def test_gunzip_guard_roundtrips_ordinary_layers() -> None:
    import random
    data = random.Random(7).randbytes(50_000)
    layer = _gzip_layer_with_member("lib/apk/db/installed", data)
    got = extract_files_from_layer(
        iter([layer]), {"lib/apk/db/installed"},
        compressed_size=len(layer),
    )
    assert got["lib/apk/db/installed"] == data


def test_gunzip_guard_translates_corrupt_stream() -> None:
    from core.tar import TarOpenError
    with pytest.raises(TarOpenError):
        list(blob_mod._gunzip_ratio_guarded(iter([b"not gzip at all"])))
