"""Distinct logical pack names must not replace each other's emitted files."""

from pathlib import Path

import pytest

from core.dataflow.extension_pack import ModelRow, write_extension_pack


def _emit(root: Path, name: str | None = None, function: str = "first"):
    options = {} if name is None else {"pack_name": name}
    return write_extension_pack(
        [ModelRow(role="sink", name=function, access_input="Argument[*0]",
                  model_kind="command-injection", provenance="operator")],
        language="cpp", out_dir=root, **options,
    )


def _snapshot(root: Path):
    return {str(p.relative_to(root)): p.read_bytes()
            for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "first,second", [("a-b/c", "a/b-c"), ("a/b-c", "a-b/c")],
    ids=["scope-hyphen-first", "name-hyphen-first"],
)
def test_colliding_pack_names_preserve_first_result(tmp_path, first, second):
    result = _emit(tmp_path, first)
    before = _snapshot(tmp_path)
    result_before = result.to_dict()
    with pytest.raises(ValueError, match="pack destination"):
        _emit(tmp_path, second, "second")
    assert _snapshot(tmp_path) == before
    assert result.to_dict() == result_before
    assert result.pack_name == first
    assert result.model_file.read_bytes() == before[str(result.model_file.relative_to(tmp_path))]


def test_same_name_update_and_default_layout_remain_supported(tmp_path):
    first = _emit(tmp_path)
    model_before = first.model_file.read_bytes()
    second = _emit(tmp_path, function="second")
    assert second.pack_dir == first.pack_dir == tmp_path / "raptor-learned-models-cpp"
    assert second.model_file == first.model_file
    assert second.model_file.read_bytes() != model_before
    assert second.rows_written == 1


def test_existing_empty_destination_remains_supported(tmp_path):
    destination = tmp_path / "a-b"
    destination.mkdir()
    assert _emit(tmp_path, "a/b").pack_dir == destination


def test_populated_destination_without_manifest_is_preserved(tmp_path):
    destination = tmp_path / "a-b"
    destination.mkdir()
    (destination / "owned.txt").write_text("retain")
    before = _snapshot(tmp_path)
    with pytest.raises(ValueError, match="populated without a manifest"):
        _emit(tmp_path, "a/b")
    assert _snapshot(tmp_path) == before
    assert not (destination / "models").exists()


@pytest.mark.parametrize("manifest", [
    "name: [",
    "",
    "- a/b",
    "version: 0.0.0",
    "name: 42",
    "name: no-scope",
    "name: a/b\nname: a/b",
    "name: a/b\nname: other/pack",
    "name: !unknown a/b",
    "name: a/b\n<<: {name: other/pack}",
])
def test_unsupported_manifest_refuses_before_model_directory(tmp_path, manifest):
    destination = tmp_path / "a-b"
    destination.mkdir()
    (destination / "codeql-pack.yml").write_text(manifest)
    before = _snapshot(tmp_path)
    with pytest.raises(ValueError, match="pack destination"):
        _emit(tmp_path, "a/b")
    assert _snapshot(tmp_path) == before
    assert not (destination / "models").exists()


def test_same_name_quoted_mapping_is_supported(tmp_path):
    destination = tmp_path / "a-b"
    destination.mkdir()
    (destination / "codeql-pack.yml").write_text('version: 0.0.0\nname: "a/b"\n')
    assert _emit(tmp_path, "a/b").pack_dir == destination


def test_unreadable_manifest_preserves_existing_output(tmp_path, monkeypatch):
    result = _emit(tmp_path, "a/b")
    before = _snapshot(tmp_path)
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        if path == result.pack_dir / "codeql-pack.yml":
            raise PermissionError("owned refusal")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    with pytest.raises(ValueError, match="manifest unreadable"):
        _emit(tmp_path, "a/b", "second")
    assert _snapshot(tmp_path) == before


def test_non_directory_destination_is_preserved(tmp_path):
    destination = tmp_path / "a-b"
    destination.write_text("retain")
    with pytest.raises(ValueError, match="not a directory"):
        _emit(tmp_path, "a/b")
    assert destination.read_text() == "retain"


@pytest.mark.parametrize("manifest", [
    "name: &pack a/b\ncopy: *pack\n",
    "declared: &pack a/b\nname: *pack\n",
    "source: &pack {name: a/b}\n<<: *pack\n",
    "&root {name: a/b, self: *root}",
])
def test_manifest_aliases_are_refused_without_writes(tmp_path, manifest):
    destination = tmp_path / "a-b"
    destination.mkdir()
    (destination / "codeql-pack.yml").write_text(manifest)
    before = _snapshot(tmp_path)
    with pytest.raises(ValueError, match="malformed manifest"):
        _emit(tmp_path, "a/b")
    assert _snapshot(tmp_path) == before
    assert not (destination / "models").exists()


def test_unused_name_anchor_is_unambiguous(tmp_path):
    destination = tmp_path / "a-b"
    destination.mkdir()
    (destination / "codeql-pack.yml").write_text("name: &pack a/b\n")
    assert _emit(tmp_path, "a/b").pack_dir == destination


def test_linked_destination_is_not_adopted(tmp_path):
    root = tmp_path / "output"
    root.mkdir()
    target = tmp_path / "owned-target"
    target.mkdir()
    (target / "retain.txt").write_text("retain")
    (root / "a-b").symlink_to(target, target_is_directory=True)
    before = _snapshot(target)
    with pytest.raises(ValueError, match="linked destination"):
        _emit(root, "a/b")
    assert _snapshot(target) == before
    assert (root / "a-b").is_symlink()


def test_linked_manifest_is_not_adopted(tmp_path):
    root = tmp_path / "output"
    result = _emit(root, "a/b")
    manifest = result.pack_dir / "codeql-pack.yml"
    target = tmp_path / "owned-manifest.yml"
    target.write_bytes(manifest.read_bytes())
    manifest.unlink()
    manifest.symlink_to(target)
    before = _snapshot(root)
    target_before = target.read_bytes()
    with pytest.raises(ValueError, match="linked manifest"):
        _emit(root, "a/b", "second")
    assert _snapshot(root) == before
    assert target.read_bytes() == target_before
    assert manifest.is_symlink()


def test_directory_manifest_is_refused_before_model_creation(tmp_path):
    destination = tmp_path / "a-b"
    (destination / "codeql-pack.yml").mkdir(parents=True)
    with pytest.raises(ValueError, match="manifest is not a file"):
        _emit(tmp_path, "a/b")
    assert not (destination / "models").exists()


def test_operator_output_root_alias_preserves_identity_checks(tmp_path):
    real_root = tmp_path / "real"
    real_root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_root, target_is_directory=True)
    first = _emit(alias, "a-b/c")
    updated = _emit(real_root, "a-b/c", "second")
    assert first.pack_dir.resolve() == updated.pack_dir.resolve()
    before = _snapshot(real_root)
    with pytest.raises(ValueError, match="manifest names"):
        _emit(alias, "a/b-c", "third")
    assert _snapshot(real_root) == before


def test_dangling_named_destination_is_refused(tmp_path):
    destination = tmp_path / "a-b"
    target = tmp_path / "absent-target"
    destination.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="linked destination"):
        _emit(tmp_path, "a/b")
    assert destination.is_symlink()
    assert not target.exists()


def test_dangling_manifest_is_refused(tmp_path):
    destination = tmp_path / "a-b"
    destination.mkdir()
    manifest = destination / "codeql-pack.yml"
    target = tmp_path / "absent-manifest"
    manifest.symlink_to(target)
    with pytest.raises(ValueError, match="linked manifest"):
        _emit(tmp_path, "a/b")
    assert manifest.is_symlink()
    assert not target.exists()
    assert not (destination / "models").exists()


@pytest.mark.parametrize("dangling", [False, True])
def test_models_directory_links_are_refused(tmp_path, dangling):
    root = tmp_path / "output"
    result = _emit(root, "a/b")
    models = result.pack_dir / "models"
    target = tmp_path / "owned-models"
    if dangling:
        result.model_file.unlink()
        models.rmdir()
    else:
        models.rename(target)
    models.symlink_to(target, target_is_directory=True)
    before = _snapshot(root)
    target_before = _snapshot(target) if target.exists() else None
    with pytest.raises(ValueError, match="linked models directory"):
        _emit(root, "a/b", "second")
    assert _snapshot(root) == before
    assert models.is_symlink()
    if target_before is None:
        assert not target.exists()
    else:
        assert _snapshot(target) == target_before


@pytest.mark.parametrize("dangling", [False, True])
def test_model_file_links_are_refused(tmp_path, dangling):
    root = tmp_path / "output"
    result = _emit(root, "a/b")
    model = result.model_file
    target = tmp_path / "owned-model.yml"
    if dangling:
        model.unlink()
    else:
        model.rename(target)
    model.symlink_to(target)
    before = _snapshot(root)
    target_before = target.read_bytes() if target.exists() else None
    with pytest.raises(ValueError, match="linked model file"):
        _emit(root, "a/b", "second")
    assert _snapshot(root) == before
    assert model.is_symlink()
    if target_before is None:
        assert not target.exists()
    else:
        assert target.read_bytes() == target_before


def test_models_non_directory_is_preserved(tmp_path):
    destination = tmp_path / "a-b"
    destination.mkdir()
    (destination / "models").write_text("retain")
    before = _snapshot(tmp_path)
    with pytest.raises(ValueError, match="models is not a directory"):
        _emit(tmp_path, "a/b")
    assert _snapshot(tmp_path) == before


def test_model_non_regular_file_is_preserved(tmp_path):
    root = tmp_path / "output"
    result = _emit(root, "a/b")
    result.model_file.unlink()
    result.model_file.mkdir()
    before = _snapshot(root)
    with pytest.raises(ValueError, match="model is not a file"):
        _emit(root, "a/b", "second")
    assert _snapshot(root) == before
    assert result.model_file.is_dir()
