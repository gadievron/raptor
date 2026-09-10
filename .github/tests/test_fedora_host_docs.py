"""Regression tests for the checksum-pinned Fedora host recipes."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DOC = (REPO / "docs" / "fedora-copilot.md").read_text(encoding="utf-8")
CONSTRAINTS = (
    REPO / "packaging" / "fedora" / "constraints-host-tools.txt"
).read_text(encoding="utf-8")


def test_manual_python_installs_use_host_constraints() -> None:
    constraint = "-c packaging/fedora/constraints-host-tools.txt"

    assert DOC.count(constraint) == 3
    assert "google-api-core==2.34.0" in CONSTRAINTS
    assert "opentelemetry-api==1.37.0" in CONSTRAINTS
    assert "protobuf==6.33.6" in CONSTRAINTS


def test_joern_recipe_uses_distribution_version_probe() -> None:
    assert "joern --version" not in DOC
    assert "io.joern.joern-cli-" in DOC
    assert 'assert version == sys.argv[2]' in DOC


def test_google_cloud_arm_checksum_matches_validated_archive() -> None:
    assert (
        "GCLOUD_SHA256="
        "8ce6287e01e54b53d2e9618d124b62ac85efe5a093904ae027b17f2057030662"
        in DOC
    )

