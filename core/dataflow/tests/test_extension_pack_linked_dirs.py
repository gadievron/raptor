import subprocess

import pytest

from core.dataflow.codeql_augmented_run import analyze


@pytest.mark.parametrize("external", [True, False])
def test_linked_pack_directory_refuses_before_analysis(tmp_path, external):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "codeql-pack.yml").write_text("name: owned/models\n")
    target = (tmp_path if external else pack) / "owned-lib"
    target.mkdir()
    (target / "owned.qll").write_text("/* owned inert query marker */")
    (pack / "lib").symlink_to(target, target_is_directory=True)
    output = tmp_path / "previous.sarif"
    output.write_text("owned previous report")
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    with pytest.raises(ValueError):
        analyze(tmp_path / "db", ["owned.ql"], output, extension_pack=pack, runner=runner)
    assert calls == []
    assert output.read_text() == "owned previous report"


def test_plain_data_subdirectory_remains_admitted(tmp_path):
    pack = tmp_path / "pack"
    models = pack / "models"
    models.mkdir(parents=True)
    (pack / "codeql-pack.yml").write_text("name: owned/models\n")
    (models / "owned.yml").write_text("extensions: []\n")
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    result = analyze(tmp_path / "db", ["owned.ql"], tmp_path / "out.sarif",
                     extension_pack=pack, runner=runner)
    assert len(calls) == 1
    assert result.extension_pack == pack
