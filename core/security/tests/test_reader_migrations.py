"""Real FIFO refusal and preserved prefixes at migrated reader boundaries."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group


@pytest.mark.integration
@pytest.mark.parametrize("reader", ["key", "source", "inventory"])
def test_migrated_reader_refuses_fifo_without_writer(tmp_path, reader):
    fifo = tmp_path / "source.c"
    os.mkfifo(fifo, 0o600)
    result = run_in_process_group([
        sys.executable, "-c", """
from pathlib import Path
import sys
path = Path(sys.argv[1])
if sys.argv[2] == 'key':
    from core.security.mac_key import read_existing_key, REFUSED
    assert read_existing_key(path, key_len=32, warn=lambda *args: None) is REFUSED
elif sys.argv[2] == 'source':
    from core.analysis.sanitizer_cut_postpass import _read_source_capped
    assert _read_source_capped(path) is None
else:
    from core.inventory.builder import _process_single_file
    result = _process_single_file(path, path.parent, [])
    assert result['_excluded'] is True, result
    assert result['_reason'] == 'open_failed_or_symlink', result
print('refused')
""", str(fifo), reader], cwd=Path(__file__).resolve().parents[3], timeout=8,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
    )
    assert result.stdout.strip() == "refused"


def test_document_context_keeps_oversize_prefix(tmp_path):
    from core.concepts.study import _DOC_MAX_BYTES, _load_doc_context
    path = tmp_path / "README.md"
    path.write_bytes(b"kept\n" + b"x" * _DOC_MAX_BYTES + b"NOT_READ")
    content = _load_doc_context([{"file": path.name}], tmp_path)
    assert "kept" in content
    assert "NOT_READ" not in content
    assert len(content) > _DOC_MAX_BYTES

