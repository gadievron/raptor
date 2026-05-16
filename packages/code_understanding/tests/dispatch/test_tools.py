"""Tests for SandboxedTools — the security-critical Read/Grep/Glob handlers.

Path traversal, symlink escape, output capping, and basic correctness.
The tools are JSON-string in/out; tests parse the JSON to inspect.
"""

import json
from pathlib import Path

import pytest

from packages.code_understanding.dispatch.tools import (
    SandboxedTools,
    _MAX_FILE_BYTES,
    _MAX_GLOB_MATCHES,
    _MAX_GREP_FILE_BYTES,
    _MAX_GREP_MATCHES,
    _MAX_LINE_BYTES,
    _is_inside,
)


@pytest.fixture
def repo(tmp_path):
    """A small fixture repo: src/x.c, src/util.h, README.md, .git/HEAD."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.c").write_text(
        "void f(char* p) {\n    strcpy(buf, p);\n    return;\n}\n"
    )
    (tmp_path / "src" / "util.h").write_text("#define MAX 256\n")
    (tmp_path / "README.md").write_text("# Test\nstrcpy mention here.\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    return tmp_path


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestForRepo:
    def test_constructs_for_existing_dir(self, tmp_path):
        tools = SandboxedTools.for_repo(tmp_path)
        assert tools.repo_root == tmp_path.resolve()

    def test_rejects_missing_path(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            SandboxedTools.for_repo(tmp_path / "does-not-exist")

    def test_rejects_file_path(self, tmp_path):
        f = tmp_path / "a.txt"
        f.write_text("hi")
        with pytest.raises(ValueError, match="not a directory"):
            SandboxedTools.for_repo(f)

    def test_resolves_symlinks_at_construction(self, tmp_path):
        # If repo_path is a symlink to a real dir, store the real dir.
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        tools = SandboxedTools.for_repo(link)
        assert tools.repo_root == real.resolve()

    def test_rejects_nul_byte_in_repo_path(self):
        # Symmetric with read_file's NUL guard — clean error rather than
        # bare ValueError from Path.resolve().
        with pytest.raises(ValueError, match="NUL byte"):
            SandboxedTools.for_repo("/tmp/x\x00y")


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


class TestReadFile:
    def test_reads_file_content(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src/x.c"))
        assert "strcpy" in result["content"]
        assert result["truncated"] is False
        assert result["path"] == "src/x.c"

    def test_max_lines_truncates(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src/x.c", max_lines=2))
        assert result["truncated"] is True
        assert result["content"].count("\n") == 2

    def test_byte_cap_enforced(self, tmp_path):
        # Write a file larger than _MAX_FILE_BYTES
        f = tmp_path / "big.txt"
        f.write_bytes(b"x" * (_MAX_FILE_BYTES + 100))
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.read_file("big.txt"))
        assert result["truncated"] is True
        assert len(result["content"]) <= _MAX_FILE_BYTES

    def test_decodes_with_replacement_for_binary(self, tmp_path):
        f = tmp_path / "bin.dat"
        f.write_bytes(b"\xff\xfe\x00\x01\xff")
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.read_file("bin.dat"))
        # No exception; content readable via replacement
        assert "content" in result

    def test_returns_error_for_directory(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src"))
        assert "error" in result

    def test_returns_error_for_missing_file(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("nonexistent.c"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_repo_root_disappeared_returns_error(self, tmp_path):
        # Mirror of grep + glob fixes — pattern audit for read_file.
        # Without this, _resolve_inside surfaces "not found" for every
        # call, misleading the model into trying alternate paths.
        d = tmp_path / "repo"
        d.mkdir()
        (d / "x.c").write_text("hello")
        tools = SandboxedTools.for_repo(d)
        import shutil
        shutil.rmtree(d)
        result = json.loads(tools.read_file("x.c"))
        assert "error" in result
        assert "no longer exists" in result["error"]


class TestReadFileMaxLinesValidation:
    """Regression: max_lines was not type-validated. A non-int value
    (string, list) crashed at ``max_lines > 0`` rather than surfacing
    a clean error."""

    def test_string_max_lines_rejected(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src/x.c", max_lines="5"))  # type: ignore[arg-type]
        assert "error" in result
        assert "max_lines" in result["error"]

    def test_bool_max_lines_rejected(self, repo):
        # bool is subclass of int — schema error if it shows up here.
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src/x.c", max_lines=True))  # type: ignore[arg-type]
        assert "error" in result

    def test_none_max_lines_works(self, repo):
        # None is the documented default; should NOT raise.
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src/x.c", max_lines=None))
        assert "error" not in result


class TestReadFileMemoryBound:
    """Regression: previously read_bytes() allocated the whole file
    before slicing to _MAX_FILE_BYTES. Defended by reading with a cap."""

    def test_does_not_allocate_full_giant_file(self, tmp_path):
        # Simulate a giant file by writing _MAX_FILE_BYTES + 1MB.
        # The read should produce _MAX_FILE_BYTES, never more.
        f = tmp_path / "giant.bin"
        # 1MB above the cap is enough to verify capping; we don't need
        # to actually allocate gigabytes in the test.
        f.write_bytes(b"x" * (_MAX_FILE_BYTES + 1024 * 1024))
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.read_file("giant.bin"))
        assert result["truncated"] is True
        # If we'd read the full file then sliced, content would be exactly
        # _MAX_FILE_BYTES (4-char chars or 1-char). Either way, len bounded.
        assert len(result["content"]) <= _MAX_FILE_BYTES


# ---------------------------------------------------------------------------
# Path traversal — the security-critical bit
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_rejects_absolute_path(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("/etc/passwd"))
        assert "error" in result
        assert "absolute" in result["error"].lower()

    def test_rejects_dotdot_traversal(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("../../etc/passwd"))
        assert "error" in result
        # Either escapes-repo or not-found, both are safe outcomes
        msg = result["error"].lower()
        assert "escapes" in msg or "not found" in msg

    def test_rejects_complex_traversal(self, repo):
        # Mix of legit-looking dirs with .. that ultimately escapes
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src/../../etc/passwd"))
        assert "error" in result

    def test_rejects_empty_path(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file(""))
        assert "error" in result
        assert "non-empty" in result["error"].lower()

    def test_rejects_non_string_path(self, repo):
        tools = SandboxedTools.for_repo(repo)
        # The protocol is JSON-out-on-error, so non-string paths get
        # rejected like any other invalid input.
        result = json.loads(tools.read_file(None))  # type: ignore[arg-type]
        assert "error" in result

    def test_rejects_nul_byte_in_path(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("src/x\x00.c"))
        assert "error" in result
        assert "nul" in result["error"].lower()

    def test_rejects_symlink_pointing_outside(self, tmp_path_factory):
        # Need TWO separate temp dirs to test true symlink escape — if
        # both repo and target sit under one tmp_path, the "outside"
        # file is technically inside the (parent) repo.
        repo = tmp_path_factory.mktemp("repo_x")
        outside_dir = tmp_path_factory.mktemp("outside_y")
        secret = outside_dir / "secret.txt"
        secret.write_text("EXFILTRATE_ME")
        (repo / "evil_link").symlink_to(secret)

        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.read_file("evil_link"))
        # MUST be an error (path escapes repo_root)
        assert "error" in result, (
            f"Symlink escape NOT caught — leaked: {result.get('content')!r}"
        )
        assert "escapes" in result["error"].lower()

    def test_skips_external_symlinks_during_grep_walk(self, tmp_path_factory):
        # If a symlink points outside repo_root, the file walker shouldn't
        # follow it (otherwise grep would scan unrelated files).
        repo = tmp_path_factory.mktemp("repo_z")
        outside_dir = tmp_path_factory.mktemp("outside_w")
        (outside_dir / "external.txt").write_text("FINDME_OUTSIDE")
        (repo / "internal.txt").write_text("FINDME_INSIDE")
        (repo / "external_link.txt").symlink_to(outside_dir / "external.txt")

        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("FINDME"))
        files = {m["file"] for m in result["matches"]}
        # internal.txt found, external_link.txt skipped (or its content not leaked)
        assert "internal.txt" in files
        assert "external_link.txt" not in files


# ---------------------------------------------------------------------------
# grep
# ---------------------------------------------------------------------------


class TestGrep:
    def test_finds_literal_substring(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("strcpy"))
        files = {m["file"] for m in result["matches"]}
        assert "src/x.c" in files
        assert "README.md" in files

    def test_regex_mode(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep(r"str(cpy|cat)", regex=True))
        assert len(result["matches"]) >= 1

    def test_invalid_regex_returns_error(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("[unbalanced", regex=True))
        assert "error" in result
        assert "regex" in result["error"].lower()

    def test_empty_pattern_rejected(self, repo):
        # Regression: previously allowed; "" matches every line of every
        # file → exhausts iteration cap with useless results.
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep(""))
        assert "error" in result
        assert "non-empty" in result["error"].lower()

    def test_non_string_pattern_rejected(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep(None))  # type: ignore[arg-type]
        assert "error" in result

    def test_repo_root_disappeared_returns_error(self, tmp_path):
        # Construct tools, then delete the repo dir before grep.
        # Without explicit detection, os.walk silently yields nothing
        # and operator gets {matches: []} indistinguishable from a real
        # empty result. We surface the error instead.
        d = tmp_path / "repo"
        d.mkdir()
        (d / "x.c").write_text("FINDME\n")
        tools = SandboxedTools.for_repo(d)
        # Delete the repo dir
        import shutil
        shutil.rmtree(d)
        result = json.loads(tools.grep("FINDME"))
        assert "error" in result
        assert "no longer exists" in result["error"]

    def test_match_order_is_deterministic(self, tmp_path):
        # Create files in non-alphabetic order. Output should be sorted.
        for name in ["zeta.c", "alpha.c", "middle.c"]:
            (tmp_path / name).write_text("FINDME\n")
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.grep("FINDME"))
        files = [m["file"] for m in result["matches"]]
        assert files == sorted(files)
        assert files == ["alpha.c", "middle.c", "zeta.c"]

    def test_match_order_within_file_is_by_line(self, tmp_path):
        # Multiple matches in one file should appear in line order.
        (tmp_path / "x.c").write_text("FINDME\nFOO\nFINDME\nBAR\nFINDME\n")
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.grep("FINDME"))
        lines = [m["line"] for m in result["matches"]]
        assert lines == [1, 3, 5]

    def test_cap_truncated_set_is_deterministic_and_alphabetic(self, tmp_path):
        # Regression: previously walk-order was filesystem-dependent.
        # When cap-truncation kicked in, two runs on the same repo could
        # return DIFFERENT match SETS, not just different orders. Now
        # walk is sorted, so cap-truncation returns the alphabetically
        # earliest N matches deterministically.
        from packages.code_understanding.dispatch.tools import _MAX_GREP_MATCHES

        # Create more matching files than the match cap.
        n = _MAX_GREP_MATCHES + 50
        # Use zero-padded names so alphabetic sort matches numeric.
        for i in range(n):
            (tmp_path / f"f{i:04d}.c").write_text("HIT\n")

        tools = SandboxedTools.for_repo(tmp_path)
        result1 = json.loads(tools.grep("HIT"))
        result2 = json.loads(tools.grep("HIT"))

        # Truncation occurred
        assert result1["truncated"] is True
        # Same set across runs
        files1 = [m["file"] for m in result1["matches"]]
        files2 = [m["file"] for m in result2["matches"]]
        assert files1 == files2
        # Alphabetic prefix of all files (proves cap took the earliest)
        assert files1[0] == "f0000.c"
        assert files1[-1] == f"f{_MAX_GREP_MATCHES - 1:04d}.c"
        # Files past the cap are NOT in the result
        for f in files1:
            assert f < f"f{_MAX_GREP_MATCHES:04d}.c"

    def test_case_sensitive_by_default(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("STRCPY"))
        assert len(result["matches"]) == 0

    def test_case_insensitive_when_requested(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("STRCPY", case_sensitive=False))
        assert len(result["matches"]) >= 1

    def test_path_scoping(self, repo):
        tools = SandboxedTools.for_repo(repo)
        # Limit to src/ — README.md mention should be excluded
        result = json.loads(tools.grep("strcpy", path="src"))
        files = {m["file"] for m in result["matches"]}
        assert "README.md" not in files
        assert "src/x.c" in files

    def test_path_scoping_with_traversal_rejected(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("anything", path="../../etc"))
        assert "error" in result

    def test_path_scoping_to_file_returns_error_not_silent_empty(self, repo):
        # Regression: passing a file path to ``path=`` would walk
        # nothing and silently return empty matches, indistinguishable
        # from a real "no matches" result. Now surfaces as an error
        # pointing the model at read_file().
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("strcpy", path="src/x.c"))
        assert "error" in result
        assert "not a directory" in result["error"]
        assert "read_file" in result["error"]

    def test_skips_dot_git(self, repo):
        # .git/HEAD contains "ref: refs/heads/main" — a grep for "ref"
        # should not return it.
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.grep("refs/heads"))
        files = {m["file"] for m in result["matches"]}
        assert ".git/HEAD" not in files

    def test_skips_node_modules_pycache(self, tmp_path):
        # Create node_modules and __pycache__; verify they're skipped
        for noisy in ("node_modules", "__pycache__"):
            d = tmp_path / noisy
            d.mkdir()
            (d / "f.txt").write_text("FINDME")
        (tmp_path / "real.txt").write_text("FINDME")

        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.grep("FINDME"))
        files = {m["file"] for m in result["matches"]}
        assert files == {"real.txt"}

    def test_match_cap_truncates(self, tmp_path):
        # Write a file with more matches than _MAX_GREP_MATCHES
        big = tmp_path / "big.txt"
        big.write_text("\n".join(["FOO"] * (_MAX_GREP_MATCHES + 50)))
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.grep("FOO"))
        assert result["truncated"] is True
        assert len(result["matches"]) <= _MAX_GREP_MATCHES

    def test_long_lines_snippet_truncated(self, tmp_path):
        f = tmp_path / "long.c"
        f.write_text("FOO" + "x" * 1000)
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.grep("FOO"))
        assert len(result["matches"]) == 1
        assert len(result["matches"][0]["snippet"]) <= 300

    def test_per_line_read_is_bounded(self, tmp_path):
        # Regression: previously `for raw in fh:` could allocate
        # arbitrary memory if a file has no newlines (one giant line).
        # Now readline() is capped at _MAX_LINE_BYTES.
        f = tmp_path / "no_newlines.txt"
        # File has no newlines and is ~_MAX_LINE_BYTES * 3 in size.
        # Pattern lives at the start, so we'll find it on the first chunk.
        content = "FINDME" + ("x" * (_MAX_LINE_BYTES * 3))
        f.write_text(content)
        tools = SandboxedTools.for_repo(tmp_path)
        # No exception, no OOM
        result = json.loads(tools.grep("FINDME"))
        assert len(result["matches"]) >= 1

    def test_skips_files_above_size_threshold(self, tmp_path):
        # Files larger than _MAX_GREP_FILE_BYTES are skipped (would
        # dominate wall-clock). The skip is reported in the result.
        big = tmp_path / "huge.log"
        big.write_bytes(b"FINDME\n" * (_MAX_GREP_FILE_BYTES // 7 + 1))
        small = tmp_path / "small.log"
        small.write_text("FINDME\n")
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.grep("FINDME"))
        files_with_match = {m["file"] for m in result["matches"]}
        assert "small.log" in files_with_match
        assert "huge.log" not in files_with_match
        assert "huge.log" in result["skipped_large_files"]


# ---------------------------------------------------------------------------
# glob_files
# ---------------------------------------------------------------------------


class TestGlobFiles:
    def test_basic_glob(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.glob_files("src/*.c"))
        assert result["matches"] == ["src/x.c"]

    def test_double_star_glob_via_simple_pattern(self, repo):
        tools = SandboxedTools.for_repo(repo)
        # fnmatch doesn't do recursive **; we expose simple patterns only
        result = json.loads(tools.glob_files("src/*.h"))
        assert result["matches"] == ["src/util.h"]

    def test_strips_leading_dot_slash(self, repo):
        tools = SandboxedTools.for_repo(repo)
        a = json.loads(tools.glob_files("./src/*.c"))
        b = json.loads(tools.glob_files("src/*.c"))
        assert a["matches"] == b["matches"]

    def test_skips_dot_git_results(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.glob_files("*"))
        for m in result["matches"]:
            assert not m.startswith(".git/")

    def test_match_cap_truncates(self, tmp_path):
        # Generate a lot of files
        for i in range(_MAX_GLOB_MATCHES + 50):
            (tmp_path / f"f{i}.txt").write_text("x")
        tools = SandboxedTools.for_repo(tmp_path)
        result = json.loads(tools.glob_files("*.txt"))
        assert result["truncated"] is True
        assert len(result["matches"]) == _MAX_GLOB_MATCHES

    def test_empty_pattern_rejected(self, repo):
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.glob_files(""))
        assert "error" in result

    def test_non_string_pattern_rejected(self, repo):
        # Regression: previously truthy non-string (e.g. 42) reached
        # pattern.lstrip() and crashed with AttributeError.
        tools = SandboxedTools.for_repo(repo)
        result = json.loads(tools.glob_files(42))  # type: ignore[arg-type]
        assert "error" in result
        assert "non-empty string" in result["error"].lower()

    def test_repo_root_disappeared_returns_error(self, tmp_path):
        # Mirror of grep's behaviour — silent empty result is misleading.
        d = tmp_path / "repo"
        d.mkdir()
        (d / "x.c").write_text("placeholder")
        tools = SandboxedTools.for_repo(d)
        import shutil
        shutil.rmtree(d)
        result = json.loads(tools.glob_files("*.c"))
        assert "error" in result
        assert "no longer exists" in result["error"]


# ---------------------------------------------------------------------------
# _is_inside helper
# ---------------------------------------------------------------------------


class TestIsInside:
    def test_path_inside_root(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        assert _is_inside(sub, tmp_path) is True

    def test_path_outside_root(self, tmp_path):
        # /tmp vs tmp_path/sub — disjoint
        other = Path("/tmp")
        sub = tmp_path / "sub"
        sub.mkdir()
        # Even though both might share a /tmp prefix, sub.is_relative_to(/tmp)
        # depends on tmp_path being under /tmp. We're checking the inverse
        # direction here: /tmp is NOT inside tmp_path.
        assert _is_inside(other, sub) is False

    def test_root_is_inside_itself(self, tmp_path):
        assert _is_inside(tmp_path, tmp_path) is True
