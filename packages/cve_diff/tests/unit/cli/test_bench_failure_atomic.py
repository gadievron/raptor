"""Native benchmark failure reports replace the output entry atomically."""

from cve_diff.cli.bench import _write_failure_md
from cve_diff.report.markdown import render_failure


def test_failure_report_replaces_symlink_without_overwriting_target(tmp_path):
    retained = tmp_path / "retained.txt"
    retained.write_text("operator data")
    output = tmp_path / "run"
    output.mkdir()
    report = output / "CVE-2025-12345.md"
    report.symlink_to(retained)

    _write_failure_md(output, "CVE-2025-12345", "DiscoveryError", "No public fix captured")

    assert retained.read_text() == "operator data"
    assert not report.is_symlink()
    assert report.read_text() == render_failure("CVE-2025-12345", "DiscoveryError", "No public fix captured")
