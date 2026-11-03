"""Linux packaging still works after Windows-only resource removal."""
import ast
import base64
import json
import csv
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import re
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prune_windows_helpers", ROOT / ".devcontainer/prune-windows-helpers.py")
PRUNE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRUNE)


@pytest.fixture(autouse=True)
def linux_image_policy(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(PRUNE, "sys", SimpleNamespace(platform="linux"))


def pe(machine=0x8664):
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, machine)
    return bytes(data)


def put(root, path, data=None):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(pe() if data is None else data)
    return target


@pytest.mark.parametrize("relative", [
    "usr/local/lib/python3.14/site-packages/pip/_vendor/distlib/t32.exe",
    "usr/local/py-utils/shared/lib/python3.14/site-packages/pip/_vendor/distlib/w64-arm.exe",
    "usr/local/py-utils/venvs/virtualenv/lib/python3.14/site-packages/distlib/t64.exe",
    "usr/local/py-utils/venvs/pipenv/lib/python3.14/site-packages/pipenv/patched/pip/_vendor/distlib/w32.exe",
    "usr/local/lib/python3.14/site-packages/setuptools/cli-arm64.exe",
    "root/.local/share/uv/tools/example/lib/python3.15/site-packages/setuptools/gui.exe",
    "usr/lib/node_modules/pnpm/dist/vendor/fastlist-0.4.0-x86.exe",
    "usr/local/lib/node_modules/pnpm/dist/vendor/fastlist-1.0.0-beta.1-arm64.exe",
])
def test_known_helpers_are_removed_across_environment_and_version_changes(tmp_path, relative):
    path = put(tmp_path, relative)
    result = PRUNE.prune(tmp_path)
    assert not path.exists()
    assert result[0]["path"] == "/" + relative
    assert result[0]["sha256"] == hashlib.sha256(pe()).hexdigest()
    assert PRUNE.prune(tmp_path) == []
    assert PRUNE.prune(tmp_path, check=True) == []


def test_other_executables_notices_and_sources_are_preserved(tmp_path):
    files = [put(tmp_path, path, b"preserved") for path in (
        "usr/local/bin/python3.14", "usr/local/share/target.exe",
        "usr/local/lib/python3.14/site-packages/other/t32.exe",
        "usr/local/lib/python3.14/site-packages/distlib/LICENSE.txt",
        "usr/local/lib/python3.14/site-packages/distlib/scripts.py",
    )]
    assert PRUNE.prune(tmp_path) == []
    assert all(path.read_bytes() == b"preserved" for path in files)


@pytest.mark.parametrize("data", [b"not executable", pe()[:70], pe(0), b"MZ" + b"\0" * 126], ids=[
    "non-executable", "truncated-pe", "wrong-machine",
    "missing-pe-signature",
])
def test_unexpected_resource_content_aborts_without_removing_any_file(tmp_path, data):
    good = put(tmp_path, "usr/local/lib/python3.14/site-packages/distlib/t32.exe")
    bad = put(tmp_path, "usr/local/lib/python3.14/site-packages/distlib/w32.exe", data)
    with pytest.raises(ValueError):
        PRUNE.prune(tmp_path)
    assert good.exists() and bad.exists()


def test_new_helper_names_require_review(tmp_path):
    path = put(tmp_path, "usr/local/lib/python3.14/site-packages/distlib/new-helper.exe")
    with pytest.raises(ValueError, match="unreviewed"):
        PRUNE.prune(tmp_path)
    assert path.exists()


def test_check_does_not_remove_helpers(tmp_path):
    path = put(tmp_path, "usr/local/lib/python3.14/site-packages/setuptools/cli.exe")
    with pytest.raises(ValueError, match="remain"):
        PRUNE.prune(tmp_path, check=True)
    assert path.exists()


def test_helper_file_and_search_root_symlinks_are_refused(tmp_path):
    target = put(tmp_path, "outside.exe")
    helper = tmp_path / "usr/local/lib/python3.14/site-packages/distlib/t32.exe"
    helper.parent.mkdir(parents=True)
    helper.symlink_to(target)
    with pytest.raises(OSError):
        PRUNE.prune(tmp_path)
    assert target.exists()
    other = tmp_path / "other-root"
    other.mkdir()
    (other / "usr").symlink_to(tmp_path / "usr", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        PRUNE.prune(other)


def test_hard_linked_helpers_can_both_be_removed(tmp_path):
    path = put(tmp_path, "usr/local/lib/python3.14/site-packages/distlib/t32.exe")
    path.with_name("w32.exe").hardlink_to(path)
    assert len(PRUNE.prune(tmp_path)) == 2


def wheel(root, *, signed=False, duplicate=False):
    path = root / "usr/share/python-wheels/example-2.0-py3-none-any.whl"
    path.parent.mkdir(parents=True, exist_ok=True)
    files = {"pip/_vendor/distlib/t32.exe": pe(), "pip/entry.py": b"print('linux')\n",
             "example-2.0.dist-info/METADATA": b"Name: example\nLicense-Expression: MIT\n",
             "example-2.0.dist-info/LICENSE": b"full license notice",
             "pip/_vendor/other-1.dist-info/RECORD": b"vendored record must remain unchanged"}
    if signed:
        files["example-2.0.dist-info/RECORD.jws"] = b"signature"
    record = "example-2.0.dist-info/RECORD"
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(data))])
    writer.writerow([record, "", ""])
    files[record] = out.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.comment = b"retain archive notice"
        for name, data in files.items():
            archive.writestr(name, data)
        if duplicate:
            archive.writestr("pip/entry.py", b"duplicate")
    return path, files


def test_bundled_wheel_preserves_linux_files_notices_and_record_hashes(tmp_path):
    path, files = wheel(tmp_path)
    rows = PRUNE.prune(tmp_path)
    assert rows[0]["archive"].endswith(".whl")
    with zipfile.ZipFile(path) as archive:
        assert archive.comment == b"retain archive notice"
        assert "pip/_vendor/distlib/t32.exe" not in archive.namelist()
        for name, data in files.items():
            if not name.endswith((".exe", "/RECORD")):
                assert archive.read(name) == data
        record = list(csv.reader(io.StringIO(archive.read("example-2.0.dist-info/RECORD").decode())))
        assert {row[0] for row in record} == set(archive.namelist())
        digest = base64.urlsafe_b64encode(hashlib.sha256(files["pip/entry.py"]).digest()).rstrip(b"=").decode()
        assert next(row for row in record if row[0] == "pip/entry.py")[1] == "sha256=" + digest
    assert PRUNE.prune(tmp_path, check=True) == []


@pytest.mark.parametrize("change", ["signed", "duplicate", "missing-record"])
def test_unsafe_wheels_remain_unchanged(tmp_path, change):
    path, _ = wheel(tmp_path, signed=change == "signed", duplicate=change == "duplicate")
    if change == "missing-record":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("pip/_vendor/distlib/t32.exe", pe())
    before = path.read_bytes()
    with pytest.raises(ValueError):
        PRUNE.prune(tmp_path)
    assert path.read_bytes() == before


def test_wheel_check_is_read_only(tmp_path):
    path, _ = wheel(tmp_path)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="remain"):
        PRUNE.prune(tmp_path, check=True)
    assert path.read_bytes() == before


def test_publication_verifies_flattened_candidate_before_tagging_and_push():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    # Check the literal shell blocks without requiring a YAML runtime dependency.
    blocks = re.findall(r"^        run: \|\n((?:          .*\n|\n)+)", workflow, re.MULTILINE)
    verified = next(i for i, block in enumerate(blocks) if "buildah build" in block)
    published = next(i for i, block in enumerate(blocks) if "docker://${tag}" in block)
    assert verified < published
    block = blocks[verified]
    assert "--squash" in block and "len .OCIv1.RootFS.DiffIDs" in block
    assert "prune-windows-helpers.py --check" in block
    assert "skopeo copy --preserve-digests" in blocks[published]
    dockerfile = (ROOT / ".devcontainer/Dockerfile").read_text()
    assert dockerfile.index("RUN python3 /usr/local/libexec/prune-windows-helpers.py") < dockerfile.index("USER vscode")


def virtualenv_bundle(root, *, bad=False):
    old_path, _ = wheel(root)
    path = root / "usr/local/lib/python3.14/site-packages/virtualenv/seed/wheels/embed" / old_path.name
    path.parent.mkdir(parents=True)
    old_path.rename(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = path.parent / "__init__.py"
    source = "BUNDLE_SHA256 = " + json.dumps({path.name: "0" * 64 if bad else digest}) + "\n# verification stays enabled\n"
    manifest.write_text(source)
    cache = path.parent / "__pycache__/__init__.cpython-314.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"stale compiled checksum table")
    record = root / "usr/local/lib/python3.14/site-packages/virtualenv-1.dist-info/RECORD"
    record.parent.mkdir()
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    for target in (path, manifest, cache):
        writer.writerow([target.relative_to(record.parent.parent).as_posix(),
            "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(target.read_bytes()).digest()).rstrip(b"=").decode(),
            str(target.stat().st_size)])
    writer.writerow(["virtualenv-1.dist-info/RECORD", "", ""])
    record.write_text(out.getvalue())
    return path, manifest, cache, record, source


def test_virtualenv_hash_verification_and_installed_record_are_retained(tmp_path):
    path, manifest, cache, record, before = virtualenv_bundle(tmp_path)
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    PRUNE.prune(tmp_path)
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert old_sha != new_sha
    table = ast.literal_eval(ast.parse(manifest.read_text()).body[0].value)
    assert table[path.name] == new_sha
    assert manifest.read_text() == before.replace(old_sha, new_sha)
    assert not cache.exists()
    rows = list(csv.reader(io.StringIO(record.read_text())))
    assert not any(row[0].endswith(".pyc") for row in rows)
    for row in rows:
        if row[0].endswith("/RECORD"):
            continue
        payload = (record.parent.parent / row[0]).read_bytes()
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        assert row[1:] == ["sha256=" + expected, str(len(payload))]


def test_corrupt_original_virtualenv_seed_is_not_relabelled(tmp_path):
    path, manifest, _, _, _ = virtualenv_bundle(tmp_path, bad=True)
    before = path.read_bytes(), manifest.read_bytes()
    with pytest.raises(ValueError, match="checksum mismatch"):
        PRUNE.prune(tmp_path)
    assert before == (path.read_bytes(), manifest.read_bytes())


def test_native_windows_cleanup_is_refused_before_any_mutation(tmp_path, monkeypatch):
    path = put(tmp_path, "usr/local/lib/python3.14/site-packages/distlib/t32.exe")
    with monkeypatch.context() as context:
        context.setattr(PRUNE.sys, "platform", "win32")
        with pytest.raises(ValueError, match="Linux images only"):
            PRUNE.prune(tmp_path)
    assert path.read_bytes() == pe()


def test_wheel_inspection_scratch_is_contained_and_cleaned(tmp_path, monkeypatch):
    path, _ = wheel(tmp_path)
    original = PRUNE.tempfile.TemporaryDirectory
    parents = []

    def contained(*args, **kwargs):
        parents.append(kwargs.get("dir"))
        assert kwargs.get("dir") == path.parent
        return original(*args, **kwargs)

    monkeypatch.setattr(PRUNE.tempfile, "TemporaryDirectory", contained)
    PRUNE.wheel_helpers(path)
    assert parents
    assert not list(path.parent.glob("wheel-pe-*"))
