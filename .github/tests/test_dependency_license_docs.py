"""Keep dependency licence summaries aligned with the pinned distributions."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DOC = (REPO / "docs" / "dependencies.md").read_text(encoding="utf-8")


def _license_cell(package: str) -> str:
    prefix = f"| {package} |"
    row = next((line for line in DOC.splitlines() if line.startswith(prefix)), None)
    assert row is not None, f"missing dependency row for {package}"
    return row.split("|")[2].strip()


def test_pinned_optional_distribution_licences() -> None:
    assert _license_cell("orjson") == "MPL-2.0 AND (Apache-2.0 OR MIT)"
    assert (
        _license_cell("pwntools")
        == "Mostly MIT; some bundled GPL/BSD-2-Clause components"
    )
    assert _license_cell("r2pipe") == "MIT"


def test_mixed_licences_are_not_flattened_to_mit_or_apache() -> None:
    assert "All core dependencies are MIT or Apache 2.0." not in DOC
    assert "summarises upstream package metadata and bundled notices" in DOC
    assert (
        "[AGPL-3.0-or-later]"
        "(https://github.com/AFLplusplus/AFLplusplus/blob/stable/LICENSING.md)"
        in DOC
    )
    assert "many source files are individually Apache-2.0" in DOC
