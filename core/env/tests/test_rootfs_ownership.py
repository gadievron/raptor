"""A requested kept rootfs is published only after the build succeeds."""

from pathlib import Path

import pytest

from core.env import build


@pytest.mark.parametrize("existing", ["directory", "file", "symlink"])
def test_preexisting_keep_destination_is_refused_without_touching_it(
    tmp_path, monkeypatch, existing
):
    keep = tmp_path / "rootfs"
    real = tmp_path / "operator-data"
    real.mkdir()
    (real / "payload").write_text("keep")
    if existing == "directory":
        real.rename(keep)
        real = keep
    elif existing == "symlink":
        keep.symlink_to(real, target_is_directory=True)
    else:
        keep.write_text("keep")
    calls = []

    def inner(*args, **kwargs):
        calls.append(kwargs)
        return build.BuildProduct(ok=False, reason="build_failed")

    monkeypatch.setattr(build, "_containerized_build", inner)
    product = build.containerized_build(
        tmp_path, "make", out_dir=tmp_path / "out", keep_rootfs=keep
    )
    assert not product.ok
    assert calls == []
    assert (real / "payload").read_text() == "keep"
    assert keep.exists()


@pytest.mark.parametrize("outcome", ["success", "failure", "interrupt"])
def test_kept_rootfs_is_staged_until_success_and_reclaimed_on_failure(
    tmp_path, monkeypatch, outcome
):
    keep = tmp_path / "rootfs"
    staging = []

    def inner(*args, **kwargs):
        path = Path(kwargs["keep_rootfs"])
        staging.append(path)
        assert path != keep
        path.mkdir(parents=True)
        (path / "payload").write_text("built")
        if outcome == "interrupt":
            raise KeyboardInterrupt
        return build.BuildProduct(
            ok=outcome == "success",
            reason="" if outcome == "success" else "no_artifacts",
        )

    monkeypatch.setattr(build, "_containerized_build", inner)
    if outcome == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            build.containerized_build(
                tmp_path, "make", out_dir=tmp_path / "out", keep_rootfs=keep
            )
    else:
        product = build.containerized_build(
            tmp_path, "make", out_dir=tmp_path / "out", keep_rootfs=keep
        )
        assert product.ok is (outcome == "success")
        assert product.rootfs == (keep if product.ok else None)
    assert keep.exists() is (outcome == "success")
    assert staging and all(not path.exists() for path in staging)
    assert list(tmp_path.glob("raptor-rootfs-build-*")) == []


@pytest.mark.parametrize("change", ["populated", "replaced"])
def test_destination_changed_during_build_survives_failed_publication(
    tmp_path, monkeypatch, change
):
    keep = tmp_path / "rootfs"

    def inner(*args, **kwargs):
        root = Path(kwargs["keep_rootfs"])
        root.mkdir()
        (root / "built").write_text("image")
        if change == "replaced":
            keep.rename(tmp_path / "old-reservation")
            keep.mkdir()
        (keep / "operator-data").write_text("keep")
        return build.BuildProduct(ok=True)

    monkeypatch.setattr(build, "_containerized_build", inner)
    result = build.containerized_build(
        tmp_path, "make", out_dir=tmp_path / "out", keep_rootfs=keep
    )
    assert not result.ok
    assert result.rootfs is None
    assert (keep / "operator-data").read_text() == "keep"
    assert not (keep / "built").exists()
    assert list(tmp_path.glob("raptor-rootfs-build-*")) == []


def test_build_cannot_publish_symlink_as_rootfs(tmp_path, monkeypatch):
    keep = tmp_path / "rootfs"
    real = tmp_path / "operator-data"
    real.mkdir()
    (real / "payload").write_text("keep")

    def inner(*args, **kwargs):
        Path(kwargs["keep_rootfs"]).symlink_to(real, target_is_directory=True)
        return build.BuildProduct(ok=True)

    monkeypatch.setattr(build, "_containerized_build", inner)
    result = build.containerized_build(
        tmp_path, "make", out_dir=tmp_path / "out", keep_rootfs=keep
    )
    assert not result.ok
    assert not keep.exists()
    assert (real / "payload").read_text() == "keep"
    assert list(tmp_path.glob("raptor-rootfs-build-*")) == []
