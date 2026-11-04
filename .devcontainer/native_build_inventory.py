"""Bounded, explicit native build inventories; no directory-wide ownership guesses."""
from __future__ import annotations

import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import subprocess

MAX_METADATA = 512 * 1024
MAX_BINARY = 64 * 1024 * 1024


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("not a bounded regular inventory file")
        data = stream.read(limit + 1)
    if len(data) != info.st_size:
        raise ValueError("inventory file changed or exceeded its budget")
    return data


def assignments(text):
    result = {}
    text = text.replace("\\\n", " ")
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:)\s*(.*?)\s*", line)
        if match:
            value = match[2]
            result[match[1]] = value[1:-1] if len(value) >= 2 and value[0] == value[-1] == "'" else value
    return result


def expanded(values, name):
    value = values.get(name, "")
    for _ in range(16):
        updated = re.sub(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
                         lambda match: values.get(match[1] or match[2], match[0]), value)
        if updated == value:
            break
        value = updated
    if "$" in value or "`" in value or "\x00" in value:
        raise ValueError("unsupported build variable expression")
    return value


def elf_object_string(data, symbol):
    """Read a bounded ELF object symbol, without running the binary."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] not in {1, 2} or data[5] not in {1, 2}:
        return None
    endian = "<" if data[5] == 1 else ">"
    wide = data[4] == 2
    offset = struct.unpack_from(endian + ("Q" if wide else "I"), data, 40 if wide else 32)[0]
    size, count = struct.unpack_from(endian + "HH", data, 58 if wide else 46)
    expected = 64 if wide else 40
    if size != expected or not 0 < count <= 4096 or offset + size * count > len(data):
        return None
    sections = [struct.unpack_from(endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII"), data, offset + i * size)
                for i in range(count)]
    needle = symbol.encode("ascii") + b"\x00"
    for section in sections:
        if section[1] not in {2, 11}:
            continue
        step = 24 if wide else 16
        if (section[9] != step or section[5] % step or section[5] // step > 500000
                or section[4] + section[5] > len(data) or section[6] >= count):
            continue
        strings = sections[section[6]]
        if strings[1] != 3 or strings[4] + strings[5] > len(data):
            continue
        for at in range(section[4], section[4] + section[5], step):
            fields = struct.unpack_from(endian + ("IBBHQQ" if wide else "IIIBBH"), data, at)
            name, info, index, value, length = ((fields[0], fields[1], fields[3], fields[4], fields[5]) if wide else
                                               (fields[0], fields[3], fields[5], fields[1], fields[2]))
            if (info & 15 != 1 or index >= count or name + len(needle) > strings[5]
                    or not data.startswith(needle, strings[4] + name) or not 1 <= length <= 128):
                continue
            owner = sections[index]
            if value < owner[3] or value - owner[3] + length > owner[5]:
                continue
            start = owner[4] + value - owner[3]
            if start + length > len(data):
                continue
            try:
                return data[start:start + length].split(b"\x00", 1)[0].decode("ascii")
            except UnicodeDecodeError:
                return None
    return None


def inside(path, prefix):
    return path.is_absolute() and prefix.is_absolute() and ".." not in path.parts and ".." not in prefix.parts and path.is_relative_to(prefix)


class Inventory:
    def __init__(self):
        self.claims = []
        self.records = []
        self.contents = {}
        self.gaps = []

    def metadata(self, path):
        data = read_regular(path, MAX_METADATA)
        sha = hashlib.sha256(data).hexdigest()
        filename = "NOTICE-INSTALLED-METADATA-" + sha + ".txt"
        self.records.append({"file": filename, "sha256": sha, "image_path": str(path),
                             "content_kind": "installed_build_metadata"})
        self.contents[filename] = data
        return data, sha

    def regular(self, path):
        try:
            return stat.S_ISREG(path.lstat().st_mode)
        except FileNotFoundError:
            return False

    def claim(self, path, basis, evidence, data=None):
        if data is None:
            data = read_regular(path, MAX_BINARY)
        self.claims.append({"path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                            "basis": basis, "metadata_sha256": evidence})


def python_inventory(inventory, binary, version, runtime):
    prefix = Path(runtime["variables"]["prefix"])
    makefile = Path(runtime["makefile"])
    header = Path(runtime["include"]) / "patchlevel.h"
    if runtime["version"] != version or not inside(makefile, prefix) or not inside(header, prefix):
        raise ValueError("Python build metadata identity differs from interpreter")
    make, make_sha = inventory.metadata(makefile)
    patch, patch_sha = inventory.metadata(header)
    patch_version = re.search(rb'^#define\s+PY_VERSION\s+"([^"]+)"', patch, re.M)
    if not patch_version or patch_version[1].decode() != version:
        raise ValueError("Python patchlevel header differs from interpreter")
    values = assignments(make.decode("utf-8"))
    if values.get("VERSION") != ".".join(version.split(".")[:2]):
        raise ValueError("Python Makefile version mismatch")
    for name in ("MODSHARED_NAMES", "EXT_SUFFIX", "DESTSHARED", "LIBDIR", "PY3LIBRARY", "prefix"):
        if expanded(values, name) != runtime["variables"].get(name):
            raise ValueError("Python runtime and installed Makefile disagree")
    suffix = expanded(values, "EXT_SUFFIX")
    shared = Path(expanded(values, "DESTSHARED"))
    if not inside(shared, prefix) or not re.fullmatch(r"\.[A-Za-z0-9_.-]+\.so", suffix):
        raise ValueError("unsupported Python extension layout")
    names = expanded(values, "MODSHARED_NAMES").split()
    if not names or len(names) > 512 or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
        raise ValueError("invalid Python shared module inventory")
    for name in names:
        path = shared / (name + suffix)
        if inventory.regular(path):
            inventory.claim(path, "cpython_installed_module_build_inventory", [make_sha, patch_sha])
            inventory.claims[-1]["declaration"] = {"variable": "MODSHARED_NAMES", "module": name, "extension_suffix": suffix}
    library = expanded(values, "PY3LIBRARY")
    libdir = Path(expanded(values, "LIBDIR"))
    if not inside(libdir, prefix) or not re.fullmatch(r"libpython[0-9.]+\.so", library):
        raise ValueError("unsupported Python ABI shim inventory")
    if inventory.regular(libdir / library):
        inventory.claim(libdir / library, "cpython_installed_abi_build_inventory", [make_sha, patch_sha])
        inventory.claims[-1]["declaration"] = {"variable": "PY3LIBRARY", "library": library}


def git_programs(source):
    programs = set()
    for line in source.splitlines():
        match = re.fullmatch(r"\s*PROGRAM_OBJS\s*\+=\s*([A-Za-z0-9_-]+)\.o\s*", line)
        if match:
            programs.add("git-" + match[1])
        match = re.fullmatch(r"\s*(?:OTHER_PROGRAMS|REMOTE_CURL_PRIMARY|REMOTE_CURL_ALIASES)\s*(?:\+=|=)\s*(.*?)\s*", line)
        if match:
            tokens = [token.removesuffix("$X") for token in match[1].split()]
            if tokens and all(re.fullmatch(r"[A-Za-z0-9_-]+", token) for token in tokens):
                programs.update(tokens)
    return programs


def git_inventory(inventory, binary, version, source, exec_path):
    prefix = binary.parent.parent
    directory = Path(exec_path.strip())
    if not directory.is_absolute() or not inside(directory, prefix):
        raise ValueError("Git exec path lies outside its installation")
    for name in sorted(git_programs(source)):
        for path in (directory / name, binary.parent / name):
            if not inventory.regular(path):
                continue
            data = read_regular(path, MAX_BINARY)
            if elf_object_string(data, "git_version_string") == version:
                inventory.claim(path, "git_release_target_and_elf_version", [], data)
                inventory.claims[-1]["version_signature"] = {"symbol": "git_version_string", "value": version}
            else:
                inventory.gaps.append(str(path) + ": Git version symbol unavailable or mismatched")


def svn_inventory(inventory, binary, version, source, runner):
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(source)
    prefix = binary.parent.parent
    for name in config.sections():
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            continue
        section = config[name]
        if section.get("type") == "exe" and section.get("install") == "bin":
            path = binary.parent / name
            if inventory.regular(path):
                try:
                    argv = [str(path), "--version", "--quiet"]
                    try:
                        output = runner(argv).strip()
                    except subprocess.CalledProcessError:
                        argv = [str(path), "--version"]
                        output = runner(argv).strip()
                    identified = re.search(r"^" + re.escape(name) + r", version ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)", output, re.M)
                    found = identified[1] if identified else output
                    if found == version:
                        inventory.claim(path, "subversion_release_target_and_runtime_version", [])
                        inventory.claims[-1]["version_signature"] = {"argv": argv, "value": found, "locale": "C"}
                    else:
                        inventory.gaps.append(str(path) + ": Subversion version mismatch")
                except (OSError, subprocess.SubprocessError):
                    inventory.gaps.append(str(path) + ": Subversion version query unavailable")
        if section.get("type") not in {"lib", "fs-module", "ra-module"} or not section.get("install", "").endswith("lib"):
            continue
        pc = prefix / "share/pkgconfig" / (name + ".pc")
        if not inventory.regular(pc):
            continue
        data, pc_sha = inventory.metadata(pc)
        values = assignments(data.decode("utf-8"))
        if values.get("Version") != version or values.get("Name") != name:
            raise ValueError("Subversion pkg-config identity mismatch")
        libdir = Path(expanded(values, "libdir"))
        if not libdir.is_absolute() or not inside(libdir, prefix):
            raise ValueError("Subversion library directory lies outside its installation")
        for token in shlex.split(values.get("Libs", "")):
            match = re.fullmatch(r"-l(svn_[A-Za-z0-9_]+-[0-9]+)", token)
            if not match or "lib" + match[1].rsplit("-", 1)[0] != name:
                continue
            archive, la_sha = inventory.metadata(libdir / ("lib" + match[1] + ".la"))
            installed = assignments(archive.decode("utf-8"))
            if installed.get("installed") != "yes" or installed.get("libdir") != str(libdir):
                raise ValueError("Subversion libtool installation mismatch")
            for target in installed.get("library_names", "").split():
                if not re.fullmatch(re.escape("lib" + match[1]) + r"\.so(?:\.[0-9]+)*", target):
                    raise ValueError("unsafe Subversion library inventory name")
                path = libdir / target
                if inventory.regular(path):
                    inventory.claim(path, "subversion_pkgconfig_and_libtool_inventory", [pc_sha, la_sha])
                    inventory.claims[-1]["declaration"] = {"project_section": name, "pkgconfig_version": version, "libtool_library": target}


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15, env={**os.environ, "LC_ALL": "C"}).stdout


def collect_build_inventory(name, binary, version, definitions):
    inventory = Inventory()
    if name == "cpython":
        code = ("import json,sys,sysconfig; print(json.dumps({'version':sys.version.split()[0],"
                "'makefile':sysconfig.get_makefile_filename(),'include':sysconfig.get_path('include'),"
                "'variables':{k:sysconfig.get_config_var(k) for k in "
                "('MODSHARED_NAMES','EXT_SUFFIX','DESTSHARED','LIBDIR','PY3LIBRARY','prefix')}}))")
        python_inventory(inventory, binary, version, json.loads(run([str(binary), "-I", "-c", code])))
    elif name == "git":
        git_inventory(inventory, binary, version, definitions["Makefile"], run([str(binary), "--exec-path"]))
    elif name == "subversion":
        svn_inventory(inventory, binary, version, definitions["build.conf"], run)
    return inventory
