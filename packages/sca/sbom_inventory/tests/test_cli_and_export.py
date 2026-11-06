import hashlib
import io
import json
import csv

import pytest
from core.testing.logging_state import isolated_cli_logging

from packages.sca import cli as sca_cli
from packages.sca.sbom_inventory.cli import main
from packages.sca.sbom_inventory.inventory import read_inventory
from packages.sca.sbom_inventory.model import Record
from packages.sca.sbom_inventory.output import csv_inventory, export_notices
from packages.sca.sbom_inventory.source import Source


@isolated_cli_logging()
def test_public_cli_dispatch_and_portable_filtered_outputs(cdx, write_json, tmp_path, capsys):
    path = write_json(cdx)
    out = tmp_path / "out"
    assert sca_cli.main(["sbom", "inspect", str(path), "--license", "MIT", "--format", "json", "--out", str(out)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["format"] == "raptor-sbom-inventory"
    assert printed["summary"]["packages"] == 1
    assert len(printed["selection"]) == 1
    assert (out / "inventory.csv").exists() and (out / "summary.md").exists()
    assert not (out / "report.html").exists()
    assert main(["diff", str(out / "inventory.json"), str(out / "inventory.json")]) == 0
    assert json.loads(capsys.readouterr().out)["counts"] == {}


@isolated_cli_logging()
def test_text_output_preserves_layout_and_is_not_truncated(cdx, write_json, capsys):
    assert main(["inspect", str(write_json(cdx))]) == 0
    text = capsys.readouterr().out
    assert "\n## Selected inventory\n" in text
    assert "example" in text
    assert "notice_gap_packages" not in text
    assert "not assessed" in text


@isolated_cli_logging()
def test_invalid_input_creates_no_success_artifacts(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"bomFormat":"SPDX","components":[]}')
    out = tmp_path / "out"
    assert main(["inspect", str(path), "--out", str(out)]) == 2
    assert not out.exists()
    assert "raptor-sca sbom:" in capsys.readouterr().err


def test_csv_defangs_formulas_controls_and_retains_occurrence_ids():
    row = Record("one", " =HYPERLINK(\"bad\")\x1b[2J", "1", "library", declarations=["MIT OR Apache-2.0"])
    text = csv_inventory([row])
    cells = list(csv.reader(io.StringIO(text)))
    assert cells[1][0] == "one"
    assert cells[1][2].startswith("' ")
    assert "\x1b" not in text
    assert cells[1][6] == "MIT OR Apache-2.0"


def test_notice_export_preserves_bytes_associations_and_can_be_reopened(bundle, tmp_path):
    out = tmp_path / "notices"
    with Source(bundle) as source:
        inventory, embedded = read_inventory(source)
        sha = inventory.records[0].notices[0].sha256
        original = source.blob(sha)
        result = export_notices(out, inventory, inventory.records, source, embedded, include_unassociated=True)
    assert result == {"notice_records": 1, "unique_texts": 1}
    assert (out / "prepared/notices/sha256" / sha).read_bytes() == original
    with Source(out) as source:
        reread, _ = read_inventory(source)
    assert reread.records[0].notices[0].sha256 == hashlib.sha256(original).hexdigest()
    assert reread.records[0].notice_status == "captured"
    assert reread.coverage is None


def test_late_notice_failure_leaves_no_partial_export(bundle, tmp_path):
    out = tmp_path / "notices"
    with Source(bundle) as source:
        inventory, embedded = read_inventory(source)
        sha = inventory.records[0].notices[0].sha256
        (bundle / "prepared/notices/sha256" / sha).write_bytes(b"changed after inspection")
        with pytest.raises(ValueError, match="checksum"):
            export_notices(out, inventory, inventory.records, source, embedded, include_unassociated=True)
    assert not out.exists()
    assert not list(tmp_path.glob("raptor-sca-notices-*"))


def test_export_refuses_to_overwrite_existing_path(bundle, tmp_path):
    out = tmp_path / "notices"
    out.mkdir()
    (out / "important.txt").write_text("keep")
    with Source(bundle) as source:
        inventory, embedded = read_inventory(source)
        with pytest.raises(ValueError, match="already exists"):
            export_notices(out, inventory, inventory.records, source, embedded, include_unassociated=True)
    assert (out / "important.txt").read_text() == "keep"


@isolated_cli_logging()
def test_machine_json_output_escapes_terminal_controls_and_bidi(cdx, write_json, capsys):
    cdx["components"][0]["name"] = "foreign\x1b[2J\u202eevil"
    assert main(["inspect", str(write_json(cdx)), "--format", "json"]) == 0
    text = capsys.readouterr().out
    assert "\x1b" not in text and "\u202e" not in text
    assert json.loads(text)["records"][0]["name"].endswith("evil")


@pytest.mark.parametrize("command", [[], ["inspect"], ["diff"], ["notices"]])
@isolated_cli_logging()
def test_help_has_examples_for_every_entrypoint(command, capsys):
    with pytest.raises(SystemExit) as error:
        main(command + ["--help"])
    assert error.value.code == 0
    help_text = capsys.readouterr().out
    assert help_text.count("raptor-sca sbom") >= 3


@isolated_cli_logging()
def test_inspection_output_directory_is_a_readable_snapshot(cdx, write_json, tmp_path, capsys):
    path = write_json(cdx)
    out = tmp_path / "inventory"
    assert main(["inspect", str(path), "--out", str(out), "--format", "json"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(["inspect", str(out), "--format", "json"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["records"] == second["records"]
    assert any("not re-verified" in note for note in second["diagnostics"])
