"""Source-coverage floor vs the multi-binary ``absent`` contract.

The floor exists to drop WRONG binaries (planted / stale ELFs whose
DWARF matches almost no project source names). Two contract points are
pinned here:

* An operator-DECLARED binary (``--binary`` / project binary store) is
  exempt from the floor — the drop warning's "pass --binary explicitly
  to override" remedy must actually exist.
* When the floor drops one of several non-declared binaries that
  produced evidence, the run's ``absent`` verdicts lose suppression
  authority: "absent only when EVERY declared binary lacks it" cannot
  be quantified over a set the floor silently narrowed.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.analysis.binary_oracle import (
    absent_earns_suppression,
    enrich_inventory_with_binary_oracle,
)

_needs_cc = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("gcc", "nm", "objdump", "readelf")),
    reason="gcc toolchain (gcc/nm/objdump/readelf) not available",
)

_LIB_SRC = """
#include <stdio.h>
void g1(void){puts("1");} void g2(void){puts("2");}
void g3(void){puts("3");} void g4(void){puts("4");}
void g5(void){puts("5");}
int main(void){g1();g2();g3();g4();g5();return 0;}
"""

_APP_SRC = """
#include <stdio.h>
void g6(void){puts("6");} void g7(void){puts("7");}
int main(void){g6();g7();return 0;}
"""

_WRONG_SRC = """
#include <stdio.h>
void h1(void){puts("1");} void h2(void){puts("2");}
void h3(void){puts("3");} void h4(void){puts("4");}
int main(void){h1();h2();h3();h4();return 0;}
"""

_NAMES = [f"g{i}" for i in range(1, 11)]


def _build(tmp: Path, stem: str, src: str) -> Path:
    c = tmp / f"{stem}.c"
    c.write_text(src, encoding="utf-8")
    out = tmp / stem
    subprocess.run(
        ["gcc", "-g", "-O0", "-o", str(out), str(c)],
        check=True, capture_output=True, timeout=60,
    )
    return out


def _inventory() -> dict:
    return {
        "files": [{
            "path": "src/app.c",
            "language": "c",
            "items": [
                {"kind": "function", "name": n, "metadata": {}}
                for n in _NAMES
            ],
        }],
    }


@pytest.fixture(scope="module")
def binaries(tmp_path_factory) -> dict[str, Path]:
    if not all(shutil.which(t) for t in ("gcc", "nm", "objdump", "readelf")):
        pytest.skip("gcc toolchain not available")
    tmp = tmp_path_factory.mktemp("oracle_floor")
    return {
        "lib": _build(tmp, "hybrid_lib", _LIB_SRC),
        "app": _build(tmp, "hybrid_app", _APP_SRC),
        "wrong": _build(tmp, "wrongbin", _WRONG_SRC),
    }


def _item_meta(inv: dict, name: str) -> dict | None:
    for it in inv["files"][0]["items"]:
        if it["name"] == name:
            return (it.get("metadata") or {}).get("binary_oracle")
    return None


@_needs_cc
@pytest.mark.slow
def test_floor_drop_of_one_binary_downgrades_absent_authority(
        binaries: dict[str, Path]) -> None:
    """Hybrid pair, neither declared: the app matches 2 of 10 project
    names and gets floor-dropped. Its unique functions then combine to
    ``absent`` from the surviving lib alone — that verdict must NOT
    carry suppression authority (the every-binary quantifier was
    narrowed to every-SURVIVING-binary)."""
    inv = _inventory()
    counts = enrich_inventory_with_binary_oracle(
        inv, [binaries["lib"], binaries["app"]])
    assert counts["classified"] > 0
    summary = inv["binary_oracle"]
    assert summary["any_floor_dropped"] is True
    assert summary["earns_suppression"] is False
    g6 = _item_meta(inv, "g6")
    assert g6 is not None and g6["classification"] == "absent"
    assert absent_earns_suppression(g6["binaries"]) is False


@_needs_cc
@pytest.mark.slow
def test_declared_binaries_are_exempt_from_the_floor(
        binaries: dict[str, Path]) -> None:
    """Operator-declared hybrid pair: the floor never drops a declared
    binary, so a function alive in ANY declared binary is never
    ``absent`` and suppression authority is preserved."""
    inv = _inventory()
    enrich_inventory_with_binary_oracle(
        inv, [binaries["lib"], binaries["app"]],
        declared_paths=[binaries["lib"], binaries["app"]])
    summary = inv["binary_oracle"]
    assert summary.get("any_floor_dropped") is not True
    assert summary["earns_suppression"] is True
    g6 = _item_meta(inv, "g6")
    assert g6 is not None and g6["classification"] != "absent"
    g1 = _item_meta(inv, "g1")
    assert g1 is not None and g1["classification"] != "absent"


@_needs_cc
@pytest.mark.slow
def test_declared_wrong_binary_is_kept_as_operator_assertion(
        binaries: dict[str, Path]) -> None:
    """The floor warning's remedy — pass the binary explicitly — must
    exist: a declared binary matching zero project names still
    enriches (operator asserts trust; the floor only warns)."""
    inv = _inventory()
    counts = enrich_inventory_with_binary_oracle(
        inv, [binaries["wrong"]],
        declared_paths=[binaries["wrong"]])
    assert counts["classified"] > 0
    assert "binary_oracle" in inv


@_needs_cc
@pytest.mark.slow
def test_undeclared_wrong_binary_still_floor_dropped(
        binaries: dict[str, Path]) -> None:
    """Control (two directions): the planted-ELF defense stays — an
    auto-detected unrelated binary is dropped and, being the only
    binary, enrichment skips entirely."""
    inv = _inventory()
    counts = enrich_inventory_with_binary_oracle(inv, [binaries["wrong"]])
    assert counts["classified"] == 0
    assert "binary_oracle" not in inv
