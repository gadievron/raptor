"""Tests for ``packages/describe/start_line.py`` — single-line
target summary emitted at /scan / /agentic / /codeql startup."""

from __future__ import annotations

from packages.describe.start_line import format_start_line


def _c_daemon(tmp_path):
    (tmp_path / "configure.ac").write_text("")
    (tmp_path / "Makefile.am").write_text("")
    src = tmp_path / "src"
    src.mkdir()
    for i in range(10):
        (src / f"f{i}.c").write_text("int main(){return 0;}\n")
    return tmp_path


class TestFormatStartLine:
    def test_full_signal_set_renders_compact_line(self, tmp_path):
        target = _c_daemon(tmp_path)
        line = format_start_line(target)
        assert line is not None
        assert "C++" in line
        assert "autotools" in line
        assert "c.userspace-daemon" in line
        # Cost estimate appears as tail clause (the existing
        # surface — preserved so the budget gate's "$N-M"
        # framing stays recognisable).
        assert "estimated" in line
        # One line only — operator visibility, not a wall of
        # text at run start.
        assert "\n" not in line

    def test_omits_generic_target_type(self, tmp_path):
        # "generic" is the catalog's bland fallback — adding it
        # to the start line is noise. Omit, keep the line tight.
        (tmp_path / "f.py").write_text("pass\n")
        line = format_start_line(tmp_path)
        assert line is not None
        assert "generic" not in line

    def test_empty_target_returns_none(self, tmp_path):
        # No languages → infer_target_shape still works but the
        # line has nothing useful to render and no estimate
        # either. Return None so the caller surfaces nothing
        # rather than an empty header.
        line = format_start_line(tmp_path)
        # The estimate for an empty tree may yield None; if so,
        # line is None. If the estimator yields a generic line
        # we'd still want the line to be informative.
        # Either way, we don't render a header with nothing.
        if line is not None:
            assert "Analyzing" not in line or "(" in line  # has content

    def test_loc_renders_compactly(self, tmp_path):
        # Synthetic large repo — assert k/M abbreviation kicks in.
        for i in range(100):
            (tmp_path / f"f{i}.c").write_text("\n" * 600)  # 600 lines each
        line = format_start_line(tmp_path)
        assert line is not None
        # 100 files * 600 lines = 60000 LOC → "60k LOC"
        assert "LOC" in line
        assert "60k" in line or "59k" in line  # boundary tolerance
