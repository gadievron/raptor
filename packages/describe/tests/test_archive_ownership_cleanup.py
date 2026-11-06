"""Describe transfers extraction ownership only after resolution succeeds."""

import io
import zipfile
from contextlib import ExitStack
from pathlib import Path

import pytest

from packages.describe import cli
from core.testing.restricted_tree import restricted_tree


@pytest.fixture
def archive(tmp_path, monkeypatch):
    path = tmp_path / "source.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("source/main.c", "data")
    monkeypatch.setattr(cli, "_find_cached_extraction", lambda *args: None)
    return path


@pytest.mark.parametrize("stage", ["extract", "descend"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_resolution_failure_cleans_before_ownership_transfer(
    archive, monkeypatch, stage, error
):
    failure = error("resolution failed")
    created = []
    mkdir = cli.tempfile.mkdtemp

    def track(*args, **kwargs):
        result = mkdir(*args, **kwargs)
        created.append(Path(result))
        return result

    monkeypatch.setattr(cli.tempfile, "mkdtemp", track)

    def fail(*args):
        raise failure

    monkeypatch.setattr(
        "core.archive.extract_to_dir"
        if stage == "extract"
        else cli.__name__ + "._descend_single_subdir",
        fail,
    )
    if error is OSError:
        assert cli.resolve_archive_target(archive, io.StringIO()) is None
    else:
        with pytest.raises(error) as caught:
            cli.resolve_archive_target(archive, io.StringIO())
        assert caught.value is failure
    assert created and all(not p.exists() for p in created)


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
def test_failed_describe_extraction_reclaims_restricted_tree(
    archive, monkeypatch, mode
):
    created = []
    with ExitStack() as stack:

        def fail(source, dest):
            created.append(Path(dest))
            stack.enter_context(restricted_tree(Path(dest) / "objects", mode))
            raise OSError("disk full")

        monkeypatch.setattr("core.archive.extract_to_dir", fail)
        assert cli.resolve_archive_target(archive, io.StringIO()) is None
        assert created and all(not p.exists() for p in created)


@pytest.mark.parametrize("kind", ["file", "symlink", "dangling"])
def test_cache_probe_only_reuses_real_directories(tmp_path, monkeypatch, kind):
    from core.archive import safe_cache_name
    from core.run.provenance import archive_snapshot

    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("source/main.c", "data")
    snap = archive_snapshot(source)
    root = tmp_path / "project"
    cache = (
        root
        / "_sources"
        / safe_cache_name(snap["archive_name"], snap["archive_sha256"])
    )
    cache.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    if kind == "file":
        cache.write_text("keep")
    else:
        cache.symlink_to(
            outside if kind == "symlink" else tmp_path / "absent",
            target_is_directory=True,
        )
    monkeypatch.setattr(
        "core.run.output._resolve_active_project",
        lambda: (str(root), "p", str(tmp_path)),
    )
    monkeypatch.setenv("RAPTOR_OUT_DIR", str(tmp_path / "empty"))
    assert cli._find_cached_extraction(source, safe_cache_name) is None


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_describe_report_failure_reclaims_owned_restricted_extraction(
    archive, monkeypatch, error
):
    created = []
    failure = error("report failed")
    monkeypatch.setattr(cli, "_describe_binary", lambda *args, report_options=None: None)
    with ExitStack() as stack:

        def extract(source, dest):
            created.append(Path(dest))
            stack.enter_context(restricted_tree(Path(dest) / "objects", 0o555))

        def fail(*args, **kwargs):
            raise failure

        monkeypatch.setattr("core.archive.extract_to_dir", extract)
        monkeypatch.setattr("packages.describe.report.build_describe_report", fail)
        with pytest.raises(error) as caught:
            cli.describe_main(
                str(archive), False, stderr=io.StringIO(), stdout=io.StringIO()
            )
        assert caught.value is failure
        assert created and all(not p.exists() for p in created)


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_project_classification_failure_cleans_archive_scratch(
    archive, tmp_path, monkeypatch, error
):
    from core.project.cli import _detect_archive_target_type

    owned = tmp_path / "owned"
    failure = error("classification failed")
    with restricted_tree(owned, 0o555):
        monkeypatch.setattr(
            cli, "resolve_archive_target", lambda *args: (owned, owned, archive.name)
        )

        def fail(*args, **kwargs):
            raise failure

        monkeypatch.setattr("core.run.target_types.binary_dominant", fail)
        if error is RuntimeError:
            assert _detect_archive_target_type(archive) is None
        else:
            with pytest.raises(error) as caught:
                _detect_archive_target_type(archive)
            assert caught.value is failure
        assert not owned.exists()
