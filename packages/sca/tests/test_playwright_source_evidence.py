"""Source evidence must bind the complete installed payload, not its version label."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest


from core.testing.module_bindings import patch_module_attribute

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("check_playwright_source", ROOT / ".github/scripts/check_playwright_source.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def archive(path, contents):
    with tarfile.open(path, "w:gz") as target:
        for name, raw in contents.items():
            member = tarfile.TarInfo("package/" + name)
            member.size = len(raw)
            target.addfile(member, io.BytesIO(raw))


def attestation(digest):
    return {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "pkg:npm/playwright-core@1.60.0", "digest": {"sha512": digest}}],
            "predicate": {"runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}}, "buildDefinition": {
                "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"ref": "refs/tags/v1.60.0", "repository": mod.REPO,
                                                     "path": ".github/workflows/publish_release.yml"}},
                "resolvedDependencies": [{"uri": "git+" + mod.REPO + "@refs/tags/v1.60.0",
                                          "digest": {"gitCommit": "b" * 40}}]}}}


@pytest.fixture
def source_case(tmp_path, monkeypatch):
    version, commit = "1.60.0", "a" * 40
    sdk = {"playwright/__init__.py": b"", "playwright/_impl/_driver.py": b"pass\n", "playwright/py.typed": b""}
    driver = {"package.json": b'{"version":"1.60.0"}', "cli.js": b"// driver\n"}
    archive(tmp_path / "sdk.tar.gz", sdk)
    archive(tmp_path / "driver.tgz", driver)
    generator = b'process.stdout.write("{}\\n");\n'
    sources = {name: generator if name.endswith("generateApiJson.js") else b"" for name in mod.GENERATORS}
    sources["packages/protocol/spec/a.yml"] = b"Example: {}"
    archive(tmp_path / "driver-source.tar.gz", sources)
    template = b'TEMPLATES = {".py": "version = {version!r}\\ncommit = {scm_version.short_node!r}\\n"}\n'
    (tmp_path / "version-template.py").write_bytes(template)
    (tmp_path / "version-template-LICENSE.txt").write_text("license fixture")
    digest = hashlib.sha512((tmp_path / "driver.tgz").read_bytes()).hexdigest()
    bundle = {"dsseEnvelope": {"payload": base64.b64encode(json.dumps(attestation(digest)).encode()).decode()}}
    (tmp_path / "driver.sigstore.json").write_text(json.dumps(bundle))
    names = ["sdk.tar.gz", "driver.tgz", "driver-source.tar.gz", "version-template.py", "driver.sigstore.json", "version-template-LICENSE.txt"]
    manifest = {"version": version, "sdk_revision": commit, "driver_revision": "b" * 40,
                "sha256": {name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in names}}
    (tmp_path / "inputs.json").write_text(json.dumps(manifest))
    expected = {name.removeprefix("playwright/"): raw for name, raw in sdk.items()}
    expected.update({"driver/package/" + name: raw for name, raw in driver.items()})
    expected.update({"_repo_version.py": mod.sdk_version_file(template, version, commit),
                     "driver/package/api.json": b"{}\n", "driver/package/protocol.yml": b"Example: {}\n"})
    root = "/site/playwright/"
    files = [{"location": {"path": root + name}, "digests": [{"algorithm": "sha256", "value": hashlib.sha256(raw).hexdigest()}]}
             for name, raw in expected.items()]
    artifact = {"version": version, "locations": [{"path": "/site/playwright-1.60.0.dist-info/METADATA"}]}
    calls = []
    monkeypatch.setattr(mod, "verify_signature", lambda *args, **kwargs: calls.append(kwargs))
    patch_module_attribute(monkeypatch, mod, "subprocess", "run", lambda command, **kwargs: kwargs["stdout"].write(b"{}\n"))
    return artifact, files, tmp_path, calls


def test_complete_source_payload_and_generated_files_match(source_case):
    artifact, files, evidence, calls = source_case
    result = mod.verify(artifact, files, evidence, Path("sigstore"))
    assert result["status"] == "verified_source_payload"
    assert len(result["files"]) == len(files)
    assert calls == [{"offline": True}]
    assert "not a wheel build attestation" in result["limitations"]


@pytest.mark.parametrize("fault", ["changed", "missing", "extra", "duplicate", "stale"])
def test_changed_or_incomplete_installed_payload_is_refused(source_case, fault):
    artifact, files, evidence, _ = source_case
    if fault == "changed":
        files[0]["digests"][0]["value"] = "0" * 64
    elif fault == "missing":
        files.pop(0)
    elif fault == "extra":
        files.append({"location": {"path": "/site/playwright/unknown.so"}, "digests": [{"algorithm": "sha256", "value": "0" * 64}]})
    elif fault == "duplicate":
        files.append(files[0])
    else:
        artifact["version"] = "1.60.1"
    with pytest.raises(ValueError):
        mod.verify(artifact, files, evidence, Path("sigstore"))


def test_tampered_source_archive_is_refused_before_signature_check(source_case):
    artifact, files, evidence, calls = source_case
    (evidence / "sdk.tar.gz").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="changed"):
        mod.verify(artifact, files, evidence, Path("sigstore"))
    assert not calls


@pytest.mark.parametrize("fault", ["digest", "repository", "ref", "workflow", "commit"])
def test_attestation_must_bind_release_workflow_commit_and_digest(fault):
    document = attestation("d" * 128)
    definition = document["predicate"]["buildDefinition"]
    if fault == "digest":
        document["subject"][0]["digest"]["sha512"] = "e" * 128
    elif fault == "repository":
        definition["externalParameters"]["workflow"]["repository"] = "https://example.invalid/repo"
    elif fault == "ref":
        definition["externalParameters"]["workflow"]["ref"] = "refs/heads/main"
    elif fault == "workflow":
        definition["externalParameters"]["workflow"]["path"] = "other.yml"
    else:
        definition["resolvedDependencies"][0]["digest"]["gitCommit"] = "main"
    with pytest.raises(ValueError):
        mod.driver_revision(document, "1.60.0", "d" * 128)


def test_signature_verification_requires_identity_issuer_and_offline_cache(tmp_path, monkeypatch):
    commands = []
    patch_module_attribute(monkeypatch, mod, "subprocess", "run", lambda command, **kwargs: commands.append((command, kwargs)))
    mod.verify_signature(tmp_path, "1.60.0", Path("/tools/sigstore"), offline=True)
    command, options = commands[0]
    assert "--tuf-force-cache" in command
    assert command[command.index("--certificate-issuer") + 1] == "https://token.actions.githubusercontent.com"
    assert command[command.index("--certificate-identity-uri") + 1].endswith("1\\.60\\.0$")
    assert command[command.index("--tlog-threshold") + 1] == "1"
    assert command[command.index("--ctlog-threshold") + 1] == "1"
    assert options["check"] and options["timeout"] == 60


def test_archive_path_escape_is_refused(tmp_path):
    path = tmp_path / "source.tgz"
    archive(path, {"../escape": b"payload"})
    with pytest.raises(ValueError, match="unsafe"):
        list(mod.members(path))


def test_directory_entries_do_not_inflate_verified_file_count(source_case):
    artifact, files, evidence, _ = source_case
    count = len(files)
    files.append({"location": {"path": "/site/playwright/_impl"}, "metadata": {"type": "Directory"}})
    proof = mod.verify(artifact, files, evidence, Path("sigstore"))
    assert len(proof["files"]) == count
    assert {file["basis"] for file in proof["files"]} == {
        "immutable_sdk_source", "reproduced_sdk_version_metadata", "reproduced_driver_metadata", "sigstore_attested_driver_archive"}


def test_regular_file_without_hash_does_not_count_as_verified(source_case):
    artifact, files, evidence, _ = source_case
    files.append({"location": {"path": "/site/playwright/unhashed.py"}, "metadata": {"type": "RegularFile"}})
    with pytest.raises(ValueError, match="no scanner content hash"):
        mod.verify(artifact, files, evidence, Path("sigstore"))
