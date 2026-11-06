"""Caller-contract windows use scanner coordinates and bounded source storage."""

import pytest

from core.audit import caller_contract as contract
from core.audit import context


@pytest.mark.parametrize("separator", ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\r"],
                         ids=["VT", "FF", "FS", "GS", "RS", "NEL", "LS", "PS", "CR"])
def test_scanner_coordinates_survive_embedded_separators(tmp_path, separator):
    text = f"// comment {separator}more comment\nvoid f() {{\n    work();\n}}\ncall_here();\n"
    (tmp_path / "source.c").write_bytes(text.encode())
    assert contract._infer_def_end(tmp_path, "source.c", 2) == 4
    excerpt = contract._site_excerpt(tmp_path, "source.c", 5, {})
    assert "    5> call_here();" in excerpt


def test_definition_window_preserves_scan_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(contract, "_MAX_DEF_SCAN_LINES", 3)
    path = tmp_path / "source.c"
    path.write_text("// before\nvoid f() {\nwork();\n}\n")
    assert contract._infer_def_end(tmp_path, path.name, 2) == 4
    monkeypatch.setattr(contract, "_MAX_DEF_SCAN_LINES", 2)
    assert contract._infer_def_end(tmp_path, path.name, 2) == 2


def test_definition_window_uses_streamed_reader(tmp_path, monkeypatch):
    (tmp_path / "source.c").write_text("// before\nvoid f() {}\n" + "// tail\n" * 2000)
    def full_read_forbidden(*args, **kwargs):
        pytest.fail("definition inference buffered the full source")
    monkeypatch.setattr(context, "_read_target_text", full_read_forbidden)
    assert contract._infer_def_end(tmp_path, "source.c", 2) == 2


def test_late_oversize_still_rejects_completed_definition(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(context, "_MAX_SOURCE_FILE_BYTES", 64)
    (tmp_path / "source.c").write_text("void f() {\n}\n" + "x" * 128)
    assert contract._infer_def_end(tmp_path, "source.c", 1) == 1
    assert "over" in caplog.text and "cap" in caplog.text


@pytest.mark.parametrize("start", [0, -1, 100], ids=["zero", "negative", "past-eof"])
def test_empty_definition_windows_keep_fallback(tmp_path, start):
    (tmp_path / "source.c").write_text("ordinary text\n")
    assert contract._infer_def_end(tmp_path, "source.c", start) == start
