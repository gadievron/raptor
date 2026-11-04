"""Installed declarations and version signatures stay bounded and explicit."""
import importlib.util
from pathlib import Path
import struct

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native_inventory", ROOT / ".devcontainer/native_build_inventory.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def python_tree(tmp_path):
    prefix = tmp_path / "python"
    makefile = prefix / "lib/python3.14/config/Makefile"
    include = prefix / "include/python3.14"
    shared = prefix / "lib/python3.14/lib-dynload"
    for path in (makefile.parent, include, shared):
        path.mkdir(parents=True)
    makefile.write_text(f"VERSION=3.14\nprefix={prefix}\nexec_prefix=${{prefix}}\nLIBDIR=${{exec_prefix}}/lib\nBINLIBDEST=$(LIBDIR)/python$(VERSION)\nDESTSHARED=$(BINLIBDEST)/lib-dynload\nMODSHARED_NAMES=_example\nEXT_SUFFIX=.cpython-314-test.so\nPY3LIBRARY=libpython3.so\n")
    (include / "patchlevel.h").write_text('#define PY_VERSION "3.14.10"\n')
    (shared / "_example.cpython-314-test.so").write_bytes(b"compiled extension")
    (shared / "unclaimed.cpython-314-test.so").write_bytes(b"unrelated plugin")
    (prefix / "lib/libpython3.so").write_bytes(b"ABI shim")
    values = tool.assignments(makefile.read_text())
    runtime = {"version": "3.14.10", "makefile": str(makefile), "include": str(include),
               "variables": {name: tool.expanded(values, name) for name in
                             ("MODSHARED_NAMES", "EXT_SUFFIX", "DESTSHARED", "LIBDIR", "PY3LIBRARY", "prefix")}}
    return prefix, runtime


def test_python_inventory_uses_declared_modules_and_abi_shim(tmp_path):
    prefix, runtime = python_tree(tmp_path)
    inventory = tool.Inventory()
    tool.python_inventory(inventory, prefix / "bin/python3", "3.14.10", runtime)
    assert {Path(row["path"]).name for row in inventory.claims} == {"_example.cpython-314-test.so", "libpython3.so"}
    assert all(len(row["metadata_sha256"]) == 2 for row in inventory.claims)
    assert len(inventory.records) == 2


@pytest.mark.parametrize("change", ["version", "header", "runtime", "path_escape", "module_name"])
def test_python_conflicting_metadata_never_becomes_ownership(tmp_path, change):
    prefix, runtime = python_tree(tmp_path)
    if change == "version":
        runtime["version"] = "3.14.9"
    elif change == "header":
        (Path(runtime["include"]) / "patchlevel.h").write_text('#define PY_VERSION "3.14.9"\n')
    elif change == "runtime":
        runtime["variables"]["EXT_SUFFIX"] = ".different.so"
    elif change == "path_escape":
        runtime["makefile"] = str(prefix / "../other/Makefile")
    else:
        path = Path(runtime["makefile"])
        path.write_text(path.read_text().replace("MODSHARED_NAMES=_example", "MODSHARED_NAMES=../../foreign"))
        runtime["variables"]["MODSHARED_NAMES"] = "../../foreign"
    with pytest.raises((ValueError, FileNotFoundError)):
        tool.python_inventory(tool.Inventory(), prefix / "bin/python3", "3.14.10", runtime)


def test_make_variables_are_data_and_never_execute_shell():
    assert tool.expanded({"prefix": "/usr", "libdir": "${prefix}/lib"}, "libdir") == "/usr/lib"
    with pytest.raises(ValueError):
        tool.expanded({"prefix": "$(shell touch /tmp/should-not-exist)"}, "prefix")


def elf_fixture(version=b"2.56.0\0"):
    # A small ELF64 object with a real object-symbol table and string table.
    data = bytearray(512)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 40, 64)
    struct.pack_into("<HH", data, 58, 64, 4)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (0, 2, 0, 0, 320, 24, 2, 0, 8, 24),
                (0, 3, 0, 0, 350, 20, 0, 0, 1, 0),
                (0, 1, 0, 4096, 400, len(version), 0, 0, 1, 0)]
    for i, row in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", data, 64 + i * 64, *row)
    struct.pack_into("<IBBHQQ", data, 320, 0, 1, 0, 3, 4096, len(version))
    data[350:369] = b"git_version_string\0"
    data[400:400 + len(version)] = version
    return bytes(data)


def test_git_version_is_read_from_elf_object_not_filename_or_random_string():
    assert tool.elf_object_string(elf_fixture(), "git_version_string") == "2.56.0"
    assert tool.elf_object_string(elf_fixture(), "different_symbol") is None
    assert tool.elf_object_string(b"not ELF but git version 2.56.0", "git_version_string") is None
    assert tool.elf_object_string(elf_fixture()[:90], "git_version_string") is None


def test_git_programs_ignore_shell_expressions_and_unlisted_files():
    source = "PROGRAM_OBJS += daemon.o\nOTHER_PROGRAMS += scalar$X\nREMOTE_CURL_ALIASES = git-remote-https$X\nOTHER_PROGRAMS += $(shell echo arbitrary)\n"
    assert tool.git_programs(source) == {"git-daemon", "scalar", "git-remote-https"}


def test_svn_install_metadata_binds_libraries_to_matching_release(tmp_path):
    prefix = tmp_path / "usr"
    binary = prefix / "bin/svn"
    binary.parent.mkdir(parents=True)
    (binary.parent / "svnadmin").write_bytes(b"program")
    pkg = prefix / "share/pkgconfig"
    pkg.mkdir(parents=True)
    lib = prefix / "lib"
    lib.mkdir()
    (pkg / "libsvn_client.pc").write_text(f"prefix={prefix}\nlibdir=${{prefix}}/lib\nName: libsvn_client\nVersion: 1.14.5\nLibs: -L${{libdir}} -lsvn_client-1\n")
    (lib / "libsvn_client-1.la").write_text(f"library_names='libsvn_client-1.so.0.0.0 libsvn_client-1.so.0'\ninstalled=yes\nlibdir='{lib}'\n")
    (lib / "libsvn_client-1.so.0.0.0").write_bytes(b"library")
    (lib / "libsvn_client-1.so.0").symlink_to("libsvn_client-1.so.0.0.0")
    source = "[svnadmin]\ntype=exe\ninstall=bin\n[libsvn_client]\ntype=lib\ninstall=lib\n"
    inventory = tool.Inventory()
    tool.svn_inventory(inventory, binary, "1.14.5", source, lambda argv: "1.14.5\n")
    assert {Path(row["path"]).name for row in inventory.claims} == {"svnadmin", "libsvn_client-1.so.0.0.0"}
    (pkg / "libsvn_client.pc").write_text((pkg / "libsvn_client.pc").read_text().replace("1.14.5", "1.14.4"))
    with pytest.raises(ValueError, match="identity mismatch"):
        tool.svn_inventory(tool.Inventory(), binary, "1.14.5", source, lambda argv: "1.14.5")


def test_svn_version_falls_back_when_program_does_not_support_quiet(tmp_path):
    import subprocess
    binary = tmp_path / "usr/bin/svn"
    binary.parent.mkdir(parents=True)
    (binary.parent / "svnmucc").write_bytes(b"native")
    calls = []

    def runner(argv):
        calls.append(argv)
        if "--quiet" in argv:
            raise subprocess.CalledProcessError(1, argv)
        return "svnmucc, version 1.14.5 (r1917199)\nadditional information\n"

    inventory = tool.Inventory()
    tool.svn_inventory(inventory, binary, "1.14.5", "[svnmucc]\ntype=exe\ninstall=bin\n", runner)
    assert len(inventory.claims) == 1 and len(calls) == 2


def test_image_ships_collectors_and_their_project_license():
    dockerfile = (ROOT / ".devcontainer/Dockerfile").read_text()
    assert "COPY LICENSE /usr/share/doc/raptor/LICENSE" in dockerfile
    helper = "COPY .devcontainer/native_build_inventory.py /usr/local/libexec/native_build_inventory.py"
    invoke = "RUN python3 /usr/local/libexec/collect-native-notices.py"
    assert dockerfile.index(helper) < dockerfile.index(invoke)
    assert "RUN python3 /usr/local/libexec/collect-npm-native-notices.py" in dockerfile
