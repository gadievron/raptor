"""Tests for deterministic fuzzing seed corpus preparation."""

from pathlib import Path

import pytest

from packages.fuzzing.seed_corpus import (
    SeedCorpusOptions,
    prepare_builtin_seed_corpus,
    prepare_seed_corpus,
)


def test_prepare_seed_corpus_groups_supported_inputs_and_writes_manifest(tmp_path):
    source = tmp_path / "project"
    out = tmp_path / "seeds"
    (source / "tests" / "fixtures").mkdir(parents=True)
    (source / "examples").mkdir()
    (source / "tests" / "fixtures" / "case.json").write_text(
        '{"ok": true}\n', encoding="utf-8"
    )
    (source / "tests" / "fixtures" / "case.yaml").write_text(
        "ok: true\n", encoding="utf-8"
    )
    (source / "examples" / "case.xml").write_text("<root />\n", encoding="utf-8")
    (source / "examples" / "case.txt").write_text("hello\n", encoding="utf-8")
    (source / "examples" / "image.png").write_bytes(b"\x89PNG\r\n")

    manifest = prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=out))

    assert manifest["seed_count"] == 5
    destinations = [seed["destination"] for seed in manifest["seeds"]]
    assert destinations == [
        "text/seed-0001.txt",
        "xml/seed-0001.xml",
        "binary/seed-0001.png",
        "json/seed-0001.json",
        "yaml/seed-0001.yaml",
    ]
    assert (out / "manifest.json").is_file()
    assert (out / "json" / "seed-0001.json").read_text(
        encoding="utf-8"
    ) == '{"ok": true}\n'
    assert manifest["seeds"][0]["sha256"]


def test_prepare_seed_corpus_skips_sensitive_and_uninteresting_files(tmp_path):
    source = tmp_path / "project"
    out = tmp_path / "seeds"
    source.mkdir()
    (source / ".env").write_text("API_KEY=not-copied\n", encoding="utf-8")
    (source / "id_rsa").write_text("private key\n", encoding="utf-8")
    (source / "client_secret.json").write_text("{}\n", encoding="utf-8")
    (source / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (source / "main.py").write_text("print('not a seed')\n", encoding="utf-8")
    (source / "tests").mkdir()
    (source / "tests" / "valid.json").write_text("{}\n", encoding="utf-8")

    manifest = prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=out))

    assert [seed["source"] for seed in manifest["seeds"]] == ["tests/valid.json"]
    skipped = {item["path"]: item["reason"] for item in manifest["skipped"]}
    assert skipped[".env"] == "sensitive filename"
    assert skipped["id_rsa"] == "sensitive filename"
    assert skipped["client_secret.json"] == "sensitive filename"
    assert skipped["package-lock.json"] == "lockfile"
    assert skipped["main.py"] == "unsupported file type"


def test_prepare_seed_corpus_skips_large_files_and_symlinks(tmp_path):
    source = tmp_path / "project"
    out = tmp_path / "seeds"
    source.mkdir()
    (source / "small.json").write_text("{}\n", encoding="utf-8")
    (source / "large.json").write_text("x" * 20, encoding="utf-8")
    target = source / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    (source / "linked.json").symlink_to(target)

    manifest = prepare_seed_corpus(
        SeedCorpusOptions(source_dir=source, out_dir=out, max_file_size=10)
    )

    assert [seed["source"] for seed in manifest["seeds"]] == [
        "small.json",
        "target.json",
    ]
    skipped = {item["path"]: item["reason"] for item in manifest["skipped"]}
    assert skipped["large.json"] == "too large"
    assert "linked.json" not in skipped
    assert not (out / "json" / "seed-0003.json").exists()


def test_prepare_seed_corpus_can_include_lockfiles_when_requested(tmp_path):
    source = tmp_path / "project"
    out = tmp_path / "seeds"
    source.mkdir()
    (source / "package-lock.json").write_text("{}\n", encoding="utf-8")

    manifest = prepare_seed_corpus(
        SeedCorpusOptions(source_dir=source, out_dir=out, include_lockfiles=True)
    )

    assert [seed["source"] for seed in manifest["seeds"]] == ["package-lock.json"]


def test_prepare_seed_corpus_refuses_source_directory_as_output_without_deleting(tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "seed.json").write_text("{}\n", encoding="utf-8")
    (source / "json").mkdir()
    operator_data = source / "json" / "operator-data.json"
    operator_data.write_text("do not delete\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must not be the source directory"):
        prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=source))

    assert operator_data.read_text(encoding="utf-8") == "do not delete\n"


def test_prepare_seed_corpus_refuses_output_ancestor_without_deleting(tmp_path):
    source = tmp_path / "workspace" / "project"
    out = tmp_path / "workspace"
    source.mkdir(parents=True)
    (source / "seed.json").write_text("{}\n", encoding="utf-8")
    (out / "json").mkdir()
    operator_data = out / "json" / "operator-data.json"
    operator_data.write_text("do not delete\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must not be an ancestor"):
        prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=out))

    assert operator_data.read_text(encoding="utf-8") == "do not delete\n"


def test_prepare_seed_corpus_refuses_dangerous_output_paths(tmp_path, monkeypatch):
    source = tmp_path / "project"
    source.mkdir()
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    with pytest.raises(ValueError, match="too broad or dangerous"):
        prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=fake_home))

    with pytest.raises(ValueError, match="too broad or dangerous"):
        prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=Path(source.anchor)))


def test_prepare_seed_corpus_refuses_repository_root_output(tmp_path):
    source = tmp_path / "project"
    out = tmp_path / "repo"
    source.mkdir()
    out.mkdir()
    (out / ".git").mkdir()

    with pytest.raises(ValueError, match="repository root"):
        prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=out))


def test_prepare_seed_corpus_ignores_output_directory_inside_source(tmp_path):
    source = tmp_path / "project"
    out = source / ".raptor" / "fuzz" / "seeds"
    source.mkdir()
    (source / "seed.json").write_text("{}\n", encoding="utf-8")

    first = prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=out))
    (source / "seed.json").unlink()
    (source / "other.yaml").write_text("ok: true\n", encoding="utf-8")
    (out / "notes.txt").write_text("operator note\n", encoding="utf-8")
    second = prepare_seed_corpus(SeedCorpusOptions(source_dir=source, out_dir=out))

    assert [seed["source"] for seed in first["seeds"]] == ["seed.json"]
    assert [seed["source"] for seed in second["seeds"]] == ["other.yaml"]
    assert not (out / "json" / "seed-0001.json").exists()
    assert (out / "yaml" / "seed-0001.yaml").is_file()
    assert (out / "notes.txt").read_text(encoding="utf-8") == "operator note\n"


def test_prepare_builtin_seed_corpus_materialises_flat_manifest(tmp_path):
    out = tmp_path / "builtin"

    manifest = prepare_builtin_seed_corpus(out)

    assert manifest["source"] == "raptor_builtin_seed_corpus"
    assert manifest["profile"] == "default"
    assert manifest["seed_count"] >= 10
    assert (out / "manifest.json").is_file()
    destinations = [seed["destination"] for seed in manifest["seeds"]]
    assert "seed-0003-json-object" in destinations
    assert "seed-0006-http-get" in destinations
    assert "seed-0014-command-prefixes" in destinations
    assert all("/" not in destination for destination in destinations)
    assert (out / "seed-0003-json-object").read_text(encoding="utf-8").startswith("{")
    assert manifest["seeds"][0]["sha256"]


def test_prepare_builtin_seed_corpus_resets_only_raptor_generated_files(tmp_path):
    out = tmp_path / "builtin"
    out.mkdir()
    operator_note = out / "operator-note.txt"
    operator_note.write_text("keep me\n", encoding="utf-8")

    first = prepare_builtin_seed_corpus(out)
    generated = out / first["seeds"][0]["destination"]
    generated.write_text("stale\n", encoding="utf-8")
    second = prepare_builtin_seed_corpus(out)

    assert operator_note.read_text(encoding="utf-8") == "keep me\n"
    assert generated.read_text(encoding="utf-8") != "stale\n"
    assert first["seed_count"] == second["seed_count"]


def test_prepare_builtin_seed_corpus_refuses_dangerous_outputs(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    with pytest.raises(ValueError, match="too broad or dangerous"):
        prepare_builtin_seed_corpus(fake_home)

    with pytest.raises(ValueError, match="too broad or dangerous"):
        prepare_builtin_seed_corpus(Path(fake_home.anchor))
