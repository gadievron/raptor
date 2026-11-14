"""Bundle readers stop at the logical pack budget plus one refusal byte."""

from contextlib import contextmanager
import importlib.util
import io
from pathlib import Path
import zipfile


def test_member_reads_only_remaining_budget_and_preserves_exact_limit(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "tools" / "cache-packs.py"
    spec = importlib.util.spec_from_file_location("owned_cache_budget_tool", path)
    assert spec is not None and spec.loader is not None
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    monkeypatch.setattr(tool, "MAX_PACK_BYTES", 1024)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("oversize", b"x" * 60000)
        archive.writestr("exact", b"y" * 1024)
    buffer.seek(0)
    reads = []
    with zipfile.ZipFile(buffer) as archive:
        original = archive.open

        @contextmanager
        def observed(name):
            with original(name) as member:
                class Reader:
                    def read(self, amount):
                        data = member.read(amount)
                        reads.append((amount, len(data)))
                        return data
                yield Reader()

        monkeypatch.setattr(archive, "open", observed)
        assert tool._read_member_bounded(archive, "oversize") is None
        assert sum(received for _, received in reads) == 1025
        assert max(requested for requested, _ in reads) == 1025
        reads.clear()
        assert tool._read_member_bounded(archive, "exact") == b"y" * 1024
        assert sum(received for _, received in reads) == 1024
