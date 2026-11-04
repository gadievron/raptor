"""Publication cannot bypass verification or switch images after the audit."""
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_publication_reports_gaps_without_gating_the_exact_image():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    steps = re.findall(r"^      - name: ([^\n]+)\n(.*?)(?=^      - name: |\Z)", workflow, re.MULTILINE | re.DOTALL)
    by_name = {name: (i, body) for i, (name, body) in enumerate(steps)}
    build = by_name["Build and verify cleaned image"][0]
    export, exported = by_name["Export immutable image"]
    inventory, scanned = by_name["Generate container inventories"]
    ownership, owned = by_name["Prepare audit output permissions"]
    audit, audited = by_name["Collect and prepare container notice evidence"]
    report, reported = by_name["Report container license and notice coverage"]
    publish, published = by_name["Publish verified image"]
    assert build < export < inventory < ownership < audit < report < publish
    assert "chown -R 0:0" in owned
    assert "chmod -R a+rX" in exported
    assert "--format v2s2 --compression-format gzip" in exported
    assert "continue-on-error" not in exported
    assert "--scope squashed" in scanned
    for step in (scanned, audited, reported):
        assert "continue-on-error: true" in step
    assert "--require-license-declarations" not in workflow
    assert "license_declaration_gate" not in published
    assert "--owner-oci-layout /image" in audited and "--network none" in audited
    assert "--emit-annotations" in reported
    assert "--preserve-digests" in published
    assert 'source="oci:${RUNNER_TEMP}/container-oci:verified"' in published
    assert published.index("sha256sum") < published.index("skopeo copy")
    assert "if: always()" not in published
    artifact = by_name["Retain container SBOM and notice evidence"][1]
    assert "if: always()" in artifact and "name: container-sbom" in artifact
    assert "${{ runner.temp }}/container-sbom/" in artifact
    assert "coverage is unknown" in by_name["Summarize container license coverage"][1]
    assert "SYFT_PARALLELISM: \"4\"" in workflow


def test_workflow_shell_blocks_parse_without_executing_them():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    blocks = re.findall(r"^        run: \|\n((?:          .*\n|\n)+)", workflow, re.MULTILINE)
    assert len(blocks) >= 8
    for block in blocks:
        body = "\n".join(line[10:] if line.startswith("          ") else line for line in block.splitlines())
        subprocess.run(["bash", "-n"], input=body, text=True, check=True)


def publication_script():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    body = workflow.split("      - name: Publish verified image\n", 1)[1]
    block = re.search(r"^        run: \|\n((?:          .*\n|\n)+)", body, re.MULTILINE).group(1)
    return "\n".join(line[10:] if line.startswith("          ") else line for line in block.splitlines())


@pytest.mark.parametrize("input_tag,scope_status", [("", 0), ("v1.2.3", 2), ("", 1), ("", 2)])
def test_publication_allows_gap_reports_but_rejects_changed_image_bytes(tmp_path, input_tag, scope_status):
    import hashlib
    import json
    import os

    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    skopeo = binary_dir / "skopeo"
    skopeo.write_text("#!/bin/sh\nset -eu\ncase \"$1\" in\ninspect) cat \"$TEST_MANIFEST\" ;;\ncopy) printf '%s\\n' \"$*\" >> \"$TEST_COPIES\" ;;\n*) exit 42 ;;\nesac\n")
    skopeo.chmod(0o755)
    # Stub the freshness boundary, preserving the workflow's own branching.
    python = binary_dir / "python3"
    python.write_text("#!/bin/sh\nset -eu\ntest \"$#\" -eq 2\ntest \"$1\" = .github/scripts/dockerhub_scope.py\ntest \"$2\" = --check-main\ntest \"$IMAGE_INPUTS\" = \"$TEST_FINGERPRINT\"\nprintf '%s\\n' \"$*\" >> \"$TEST_SCOPE_CALLS\"\nexit \"$TEST_SCOPE_STATUS\"\n")
    python.chmod(0o755)
    runtime = tmp_path / "runner"
    evidence = runtime / "container-sbom"
    evidence.mkdir(parents=True)
    raw = b'{"schemaVersion":2}'
    (evidence / "image-digest.txt").write_text("sha256:" + hashlib.sha256(raw).hexdigest() + "\n")
    manifest = tmp_path / "manifest.json"
    copied = tmp_path / "copied.txt"
    scope_calls = tmp_path / "scope-calls.txt"
    env = dict(os.environ, PATH=str(binary_dir) + os.pathsep + os.environ["PATH"],
               RUNNER_TEMP=str(runtime), TAGS="example.invalid/image:a,example.invalid/image:b",
               DOCKER_CONFIG=str(tmp_path / "docker-auth"), INPUT_TAG=input_tag,
               IMAGE_INPUTS="a" * 64, TEST_FINGERPRINT="a" * 64,
               TEST_SCOPE_CALLS=str(scope_calls), TEST_SCOPE_STATUS=str(scope_status),
               TEST_MANIFEST=str(manifest), TEST_COPIES=str(copied))
    for status in ("gaps", "unavailable", "changed-image"):
        copied.unlink(missing_ok=True)
        scope_calls.unlink(missing_ok=True)
        (evidence / "license-report.json").write_text(json.dumps({"status": status}))
        manifest.write_bytes(raw + b"\n" if status == "changed-image" else raw)
        result = subprocess.run(["bash", "-c", publication_script()], env=env, text=True, capture_output=True)
        assert scope_calls.exists() is (not bool(input_tag))
        if not input_tag:
            assert scope_calls.read_text().splitlines() == [".github/scripts/dockerhub_scope.py --check-main"]
        if not input_tag and scope_status:
            assert result.returncode == (0 if scope_status == 1 else scope_status), result.stderr
            assert not copied.exists()
            continue
        if status == "changed-image":
            assert result.returncode != 0
            assert not copied.exists()
        else:
            assert result.returncode == 0, result.stderr
            calls = copied.read_text().splitlines()
            assert len(calls) == 2
            assert all("--preserve-digests" in call and "container-oci:verified" in call for call in calls)
