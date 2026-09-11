"""Tests for packages.ghidra.detect — project detection and validation."""

from __future__ import annotations


from packages.ghidra.detect import (
    check_ghidra_version,
    get_programs,
    get_project_dir,
    get_project_name,
    get_project_version,
    is_ghidra_project,
    validate_project,
)

MINIMAL_GPR = """\
<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="OWNER" TYPE="string" VALUE="testuser" />
    </BASIC_INFO>
</FILE_INFO>
"""


def _make_project(tmp_path, name="test_project", gpr_content=None):
    """Create a minimal Ghidra project structure."""
    gpr = tmp_path / f"{name}.gpr"
    gpr.write_text(gpr_content or MINIMAL_GPR, encoding="utf-8")
    rep = tmp_path / f"{name}.rep"
    rep.mkdir()
    return gpr


# --- is_ghidra_project -----------------------------------------------------

class TestIsGhidraProject:
    def test_valid_gpr(self, tmp_path):
        gpr = _make_project(tmp_path)
        assert is_ghidra_project(gpr) is True

    def test_wrong_extension(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("not a project", encoding="utf-8")
        assert is_ghidra_project(f) is False

    def test_directory(self, tmp_path):
        d = tmp_path / "test.gpr"
        d.mkdir()
        assert is_ghidra_project(d) is False

    def test_nonexistent(self, tmp_path):
        assert is_ghidra_project(tmp_path / "nope.gpr") is False

    def test_gpr_without_rep(self, tmp_path):
        gpr = tmp_path / "orphan.gpr"
        gpr.write_text(MINIMAL_GPR, encoding="utf-8")
        assert is_ghidra_project(gpr) is True


# --- validate_project -------------------------------------------------------

class TestValidateProject:
    def test_valid(self, tmp_path):
        gpr = _make_project(tmp_path)
        assert validate_project(gpr) is None

    def test_missing_path(self, tmp_path):
        err = validate_project(tmp_path / "nope.gpr")
        assert "does not exist" in err

    def test_not_a_file(self, tmp_path):
        d = tmp_path / "dir.gpr"
        d.mkdir()
        err = validate_project(d)
        assert "not a file" in err

    def test_wrong_extension(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello", encoding="utf-8")
        err = validate_project(f)
        assert "not a .gpr" in err

    def test_missing_rep(self, tmp_path):
        gpr = tmp_path / "orphan.gpr"
        gpr.write_text(MINIMAL_GPR, encoding="utf-8")
        err = validate_project(gpr)
        assert "missing .rep" in err

    def test_malformed_xml(self, tmp_path):
        gpr = tmp_path / "bad.gpr"
        gpr.write_text("not xml at all {{{", encoding="utf-8")
        (tmp_path / "bad.rep").mkdir()
        err = validate_project(gpr)
        assert "malformed" in err

    def test_wrong_root_element(self, tmp_path):
        gpr = tmp_path / "wrong.gpr"
        gpr.write_text('<?xml version="1.0"?>\n<PROJECT/>', encoding="utf-8")
        (tmp_path / "wrong.rep").mkdir()
        err = validate_project(gpr)
        assert "unexpected root" in err

    def test_empty_gpr_with_prp(self, tmp_path):
        """Ghidra 11.x: empty .gpr + valid project.prp → OK."""
        gpr = tmp_path / "saprouter.gpr"
        gpr.write_text("", encoding="utf-8")
        rep = tmp_path / "saprouter.rep"
        rep.mkdir()
        (rep / "project.prp").write_text(MINIMAL_GPR, encoding="utf-8")
        assert validate_project(gpr) is None

    def test_empty_gpr_no_prp(self, tmp_path):
        """Empty .gpr without project.prp → corrupt."""
        gpr = tmp_path / "broken.gpr"
        gpr.write_text("", encoding="utf-8")
        (tmp_path / "broken.rep").mkdir()
        err = validate_project(gpr)
        assert "corrupt" in err

    def test_empty_gpr_malformed_prp(self, tmp_path):
        """Empty .gpr + bad project.prp XML → error."""
        gpr = tmp_path / "bad.gpr"
        gpr.write_text("", encoding="utf-8")
        rep = tmp_path / "bad.rep"
        rep.mkdir()
        (rep / "project.prp").write_text("not xml {{", encoding="utf-8")
        err = validate_project(gpr)
        assert "malformed" in err


# --- get_project_name / get_project_dir ------------------------------------

class TestProjectHelpers:
    def test_name(self, tmp_path):
        gpr = _make_project(tmp_path, name="saprouter")
        assert get_project_name(gpr) == "saprouter"

    def test_dir(self, tmp_path):
        gpr = _make_project(tmp_path, name="proj")
        assert get_project_dir(gpr) == tmp_path


# --- get_programs -----------------------------------------------------------

class TestGetPrograms:
    def test_empty_project(self, tmp_path):
        gpr = _make_project(tmp_path)
        assert get_programs(gpr) == []

    def test_single_program(self, tmp_path):
        gpr = _make_project(tmp_path)
        idata = tmp_path / "test_project.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / "saprouter").mkdir()
        assert get_programs(gpr) == ["saprouter"]

    def test_multiple_programs(self, tmp_path):
        gpr = _make_project(tmp_path)
        idata = tmp_path / "test_project.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / "main_binary").mkdir()
        (idata / "libcrypto.so").mkdir()
        programs = get_programs(gpr)
        assert programs == ["libcrypto.so", "main_binary"]

    def test_ignores_hidden(self, tmp_path):
        gpr = _make_project(tmp_path)
        idata = tmp_path / "test_project.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / ".DS_Store").mkdir()
        (idata / "real_prog").mkdir()
        assert get_programs(gpr) == ["real_prog"]


# --- check_ghidra_version --------------------------------------------------

class TestCheckGhidraVersion:
    def test_good_version(self):
        assert check_ghidra_version("11.1.2") is None

    def test_minimum_version(self):
        assert check_ghidra_version("10.0") is None

    def test_too_old(self):
        err = check_ghidra_version("9.2.4")
        assert "below minimum" in err

    def test_none(self):
        err = check_ghidra_version(None)
        assert "could not determine" in err

    def test_unparseable(self):
        err = check_ghidra_version("notaversion")
        assert "could not parse" in err


# --- get_project_version (empty .gpr fallback) ----------------------------

class TestGetProjectVersion:
    def test_version_from_prp(self, tmp_path):
        """Empty .gpr falls back to .rep/project.prp for version."""
        gpr = tmp_path / "proj.gpr"
        gpr.write_text("", encoding="utf-8")
        rep = tmp_path / "proj.rep"
        rep.mkdir()
        (rep / "project.prp").write_text(
            '<?xml version="1.0"?>\n<FILE_INFO>\n'
            '  <STATE NAME="GHIDRA_VERSION" TYPE="string" VALUE="11.1.2" />\n'
            "</FILE_INFO>\n",
            encoding="utf-8",
        )
        assert get_project_version(gpr) == "11.1.2"

    def test_version_from_gpr(self, tmp_path):
        """Non-empty .gpr with version-like value."""
        gpr = tmp_path / "proj.gpr"
        gpr.write_text(
            '<?xml version="1.0"?>\n<FILE_INFO>\n'
            '  <STATE NAME="GHIDRA_VERSION" TYPE="string" VALUE="10.4" />\n'
            "</FILE_INFO>\n",
            encoding="utf-8",
        )
        (tmp_path / "proj.rep").mkdir()
        assert get_project_version(gpr) == "10.4"

    def test_no_version(self, tmp_path):
        gpr = tmp_path / "proj.gpr"
        gpr.write_text("", encoding="utf-8")
        rep = tmp_path / "proj.rep"
        rep.mkdir()
        (rep / "project.prp").write_text(MINIMAL_GPR, encoding="utf-8")
        assert get_project_version(gpr) is None


class TestGetProgramsIndex:
    def test_real_names_from_index(self, tmp_path):
        from packages.ghidra.detect import get_programs
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        idata = tmp_path / "p.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / "00").mkdir()
        (idata / "~index.dat").write_text(
            "VERSION=1\n/\n  00000000:target:645079\nNEXT-ID:1\n"
            "MD5:d41d8cd98f00b204e9800998ecf8427e\n"
        )
        assert get_programs(gpr) == ["target"]

    def test_folder_scan_fallback_without_index(self, tmp_path):
        from packages.ghidra.detect import get_programs
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        idata = tmp_path / "p.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / "00").mkdir()
        assert get_programs(gpr) == ["00"]

    def test_symlinked_index_refused(self, tmp_path):
        from packages.ghidra.detect import get_programs
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        idata = tmp_path / "p.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / "00").mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("aaaa:leaked:bbbb\n")
        (idata / "~index.dat").symlink_to(outside)
        # falls back to the folder scan instead of following the link
        assert get_programs(gpr) == ["00"]

    def test_oversized_index_refused(self, tmp_path):
        from packages.ghidra.detect import get_programs
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        idata = tmp_path / "p.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / "00").mkdir()
        (idata / "~index.dat").write_bytes(b"x" * (1024 * 1024 + 1))
        assert get_programs(gpr) == ["00"]

    def test_two_field_entries_parsed(self, tmp_path):
        # V0 indexes and V1 entries with a null fileId are 2-field —
        # legal, and must yield real names (not the folder-id
        # fallback). Header/trailer lines are excluded by the hex
        # guard on the storage-id field.
        from packages.ghidra.detect import get_programs
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        idata = tmp_path / "p.rep" / "idata"
        idata.mkdir(parents=True)
        (idata / "00").mkdir()
        (idata / "~index.dat").write_text(
            "VERSION=1\n/\n"
            "  00000000:target:645079\n"
            "  00000001:nofileid\n"
            "NEXT-ID:2\nMD5:d41d8cd98f00b204e9800998ecf8427e\n"
        )
        assert get_programs(gpr) == ["target", "nofileid"]
