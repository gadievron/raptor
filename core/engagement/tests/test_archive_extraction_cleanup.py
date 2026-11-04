"""Ledger extraction failures retire partial trees and keep explicit cap tails."""

import zipfile
from contextlib import ExitStack
from pathlib import Path

import pytest

from core.archive.errors import ArchiveError, DecompressionLimitExceeded
from core.engagement.ledger import CLASS_ARCHIVE, build_ledger
from core.testing.restricted_tree import restricted_tree


@pytest.mark.parametrize(
    "error", [OSError, ArchiveError, KeyboardInterrupt, SystemExit]
)
@pytest.mark.parametrize("mode", [0, 0o555])
def test_failed_archive_expansion_reclaims_partial_output(
    tmp_path, monkeypatch, error, mode
):
    target = tmp_path / "target"
    target.mkdir()
    with zipfile.ZipFile(target / "source.zip", "w") as z:
        z.writestr("source.c", "data")
    failure = error("expansion failed")
    created = []
    with ExitStack() as stack:

        def fail(source, dest, **kwargs):
            created.append(Path(dest))
            stack.enter_context(restricted_tree(Path(dest) / "objects", mode))
            raise failure

        monkeypatch.setattr("core.archive.extract.extract_to_dir", fail)
        if error in (OSError, ArchiveError):
            doc = build_ledger(target, tmp_path / "output")
            rows = [row for row in doc["rows"] if row["class"] == CLASS_ARCHIVE]
            assert len(rows) == 1
            assert rows[0]["expanded"] is False
            assert any(r["kind"] == "archive_extract_failed" for r in doc["residuals"])
        else:
            with pytest.raises(error) as caught:
                build_ledger(target, tmp_path / "output")
            assert caught.value is failure
        assert created and all(not p.exists() for p in created)


def test_capped_expansion_preserves_completed_children_and_remainder(
    tmp_path, monkeypatch
):
    target = tmp_path / "target"
    target.mkdir()
    with zipfile.ZipFile(target / "source.zip", "w") as z:
        z.writestr("source.c", "data")
    created = []

    def capped(source, dest, **kwargs):
        created.append(Path(dest))
        Path(dest).mkdir(parents=True)
        (Path(dest) / "child.dat").write_bytes(b"CHILD")
        raise DecompressionLimitExceeded("entry cap", cap="entry_count")

    monkeypatch.setattr("core.archive.extract.extract_to_dir", capped)
    doc = build_ledger(target, tmp_path / "output")
    assert created and (created[0] / "child.dat").read_bytes() == b"CHILD"
    assert any(r["kind"] == "archive_truncated" for r in doc["residuals"])
