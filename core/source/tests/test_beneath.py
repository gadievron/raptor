"""Tests for core.source.beneath — the anchored (dir-fd) open.

Every containment/regularity case runs TWICE: once on the default
route (openat2 fast path where the kernel has it) and once with the
fast path disabled, so the component-walk fallback is pinned to the
identical contract — the module's no-platform-skew promise.
"""

import os

import pytest

from core.source import beneath
from core.source.beneath import open_regular_beneath


@pytest.fixture(params=["default", "walk-only"])
def route(request, monkeypatch):
    """Run the test body on both open routes."""
    if request.param == "walk-only":
        monkeypatch.setattr(beneath, "_OPENAT2_ARCH_OK", False)
    return request.param


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "top.txt").write_text("top")
    (root / "sub" / "leaf.txt").write_text("leaf")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("SECRET")
    return root


class TestAccepts:
    def test_top_level_file(self, tree, route):
        f = open_regular_beneath(tree, "top.txt")
        assert f is not None
        with f:
            assert f.read() == "top"

    def test_nested_file(self, tree, route):
        f = open_regular_beneath(tree, "sub/leaf.txt")
        assert f is not None
        with f:
            assert f.read() == "leaf"

    def test_binary_mode(self, tree, route):
        f = open_regular_beneath(tree, "top.txt", "rb")
        assert f is not None
        with f:
            assert f.read() == b"top"

    def test_fdopen_kwargs_pass_through(self, tree, route):
        (tree / "latin.txt").write_bytes(b"caf\xe9")
        f = open_regular_beneath(tree, "latin.txt", "r",
                                 encoding="utf-8", errors="replace")
        assert f is not None
        with f:
            assert f.read() == "caf�"

    def test_dot_segments_normalised(self, tree, route):
        f = open_regular_beneath(tree, "./sub/leaf.txt")
        assert f is not None
        with f:
            assert f.read() == "leaf"


class TestRefusals:
    def test_absolute_rel(self, tree, route):
        assert open_regular_beneath(tree, "/etc/hostname") is None

    def test_dotdot_rel(self, tree, route):
        assert open_regular_beneath(
            tree, "../outside/secret.txt") is None

    def test_empty_rel(self, tree, route):
        assert open_regular_beneath(tree, ".") is None

    def test_missing_file(self, tree, route):
        assert open_regular_beneath(tree, "absent.txt") is None

    def test_missing_root(self, tree, route):
        assert open_regular_beneath(tree / "nope", "top.txt") is None

    def test_root_not_a_directory(self, tree, route):
        assert open_regular_beneath(tree / "top.txt", "x") is None

    def test_final_symlink_refused(self, tree, route):
        (tree / "link.txt").symlink_to(tree / "top.txt")
        assert open_regular_beneath(tree, "link.txt") is None

    def test_escaping_symlink_refused(self, tree, tmp_path, route):
        (tree / "esc.txt").symlink_to(
            tmp_path / "outside" / "secret.txt")
        assert open_regular_beneath(tree, "esc.txt") is None

    def test_intermediate_symlink_refused(self, tree, tmp_path, route):
        """The swap shape: an in-tree directory component that is a
        symlink — even to an IN-ROOT directory — refuses. At open
        time a link component is either a post-containment swap or
        an unvetted redirect; callers resolve first."""
        (tree / "swapped").symlink_to(tree / "sub")
        assert open_regular_beneath(tree, "swapped/leaf.txt") is None

    def test_intermediate_symlink_out_of_root_refused(
            self, tree, tmp_path, route):
        (tree / "swapped").symlink_to(tmp_path / "outside")
        assert open_regular_beneath(tree, "swapped/secret.txt") is None

    def test_non_utf8_filename_reads_on_both_routes(self, tree, route):
        """Surrogate-escaped (non-UTF-8) filenames from hostile trees
        must open identically on both routes — os.fsencode, never a
        strict str.encode (which raised through every consumer)."""
        import os

        name = os.fsdecode(b"\xff\xfebad.txt")
        raw = os.path.join(os.fsencode(str(tree)), b"\xff\xfebad.txt")
        with open(raw, "wb") as fh:  # raw-open: test fixture writes its own tmp plant
            fh.write(b"weird")
        f = open_regular_beneath(tree, name, "rb")
        assert f is not None
        with f:
            assert f.read() == b"weird"

    def test_embedded_nul_refused_both_routes(self, tree, route):
        """A NUL in rel would truncate the openat2 C string (opening
        a different name than requested) and raise ValueError from
        the walk's os.open — both routes must refuse instead."""
        assert open_regular_beneath(tree, "top.txt\x00x") is None
        assert open_regular_beneath(tree, "sub\x00/leaf.txt") is None

    def test_fifo_refused(self, tree, route):
        os.mkfifo(tree / "wedge.txt")
        assert open_regular_beneath(tree, "wedge.txt") is None

    def test_directory_final_refused(self, tree, route):
        assert open_regular_beneath(tree, "sub") is None

    def test_write_mode_is_a_caller_bug(self, tree, route):
        with pytest.raises(ValueError, match="reader"):
            open_regular_beneath(tree, "top.txt", "w")


class TestFallbackPlumbing:
    def test_openat2_unusable_degrades_to_walk(self, tree, monkeypatch):
        """A NotImplementedError from the fast path must land on the
        walk, not surface — pin the degrade seam itself."""
        monkeypatch.setattr(beneath, "_OPENAT2_ARCH_OK", True)

        def boom(root_fd, rel):
            raise NotImplementedError

        monkeypatch.setattr(beneath, "_openat2_beneath", boom)
        f = open_regular_beneath(tree, "sub/leaf.txt")
        assert f is not None
        with f:
            assert f.read() == "leaf"

    def test_usable_cache_never_flipped_by_refusal(self, tree,
                                                   monkeypatch):
        """A path refusal (None) must not disable the fast path for
        later calls — only syscall-unusable shapes may."""
        monkeypatch.setattr(beneath, "_openat2_usable", None)
        if not beneath._OPENAT2_ARCH_OK:
            pytest.skip("no openat2 on this arch")
        got = open_regular_beneath(tree, "absent.txt")
        assert got is None
        assert beneath._openat2_usable is not False
