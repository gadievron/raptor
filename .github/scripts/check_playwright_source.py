#!/usr/bin/env python3
"""Collect and replay source-content evidence for the shipped Playwright SDK.

Source content and a signed driver release are distinct from a wheel build
attestation. No claims about installed bytecode or the wheel builder are made.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
from types import SimpleNamespace
import urllib.request

MAX_ARCHIVE = 40 * 1024 * 1024
REPO = "https://github.com/microsoft/playwright"
GENERATORS = ("utils/doclint/generateApiJson.js", "utils/doclint/api_parser.js",
              "utils/doclint/documentation.js", "utils/markdown.js")


def fetch(url: str, limit: int = MAX_ARCHIVE) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "raptor-sbom-source-check"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("upstream evidence redirect must remain HTTPS")
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("upstream evidence exceeds its byte budget")
    return raw


def read(path: Path, limit: int = MAX_ARCHIVE) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("retained evidence exceeds its byte budget")
    return raw


def revision(repo: str, tag: str) -> str:
    document = json.loads(fetch(f"https://api.github.com/repos/{repo}/commits/{tag}", 1024 * 1024))
    result = document.get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", result):
        raise ValueError("upstream revision is unavailable")
    return result


def members(path: Path):
    """Yield bounded regular members without invoking archive extraction."""
    with tarfile.open(path, mode="r|gz") as archive:
        total = 0
        seen = set()
        for index, member in enumerate(archive):
            total += member.size
            if index >= 30000 or total > 512 * 1024 * 1024:
                raise ValueError("source archive exceeds expanded budget")
            name = member.name.partition("/")[2]
            normalized = PurePosixPath(name)
            if normalized.is_absolute() or ".." in normalized.parts or "\\" in name:
                raise ValueError("unsafe source archive member")
            if not member.isfile():
                continue
            if name in seen or member.size > 8 * 1024 * 1024:
                raise ValueError("duplicate or oversized source archive member")
            seen.add(name)
            stream = archive.extractfile(member)
            assert stream is not None
            yield name, stream.read(member.size + 1)


def statement(bundle: dict) -> dict:
    return json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True))


def driver_revision(document: dict, version: str, digest: str) -> str:
    if (document.get("_type"), document.get("predicateType")) != (
            "https://in-toto.io/Statement/v1", "https://slsa.dev/provenance/v1"):
        raise ValueError("unsupported driver attestation")
    if document.get("subject") != [{"name": "pkg:npm/playwright-core@" + version,
                                    "digest": {"sha512": digest}}]:
        raise ValueError("attestation does not bind the driver archive")
    definition = document["predicate"]["buildDefinition"]
    if definition.get("buildType") != "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1":
        raise ValueError("unsupported driver build type")
    if document["predicate"]["runDetails"]["builder"]["id"] != "https://github.com/actions/runner/github-hosted":
        raise ValueError("driver builder is not GitHub hosted")
    workflow = definition["externalParameters"]["workflow"]
    if workflow != {"ref": "refs/tags/v" + version, "repository": REPO,
                    "path": ".github/workflows/publish_release.yml"}:
        raise ValueError("unexpected driver publisher workflow")
    dependencies = definition["resolvedDependencies"]
    expected_uri = "git+" + REPO + "@refs/tags/v" + version
    revisions = [d.get("digest", {}).get("gitCommit", "") for d in dependencies if d.get("uri") == expected_uri]
    if len(revisions) != 1 or not re.fullmatch(r"[0-9a-f]{40}", revisions[0]):
        raise ValueError("driver source commit is ambiguous")
    return revisions[0]


def sdk_version_file(template_source: bytes, version: str, commit: str) -> bytes:
    """Read the pinned build tool's literal template without executing it."""
    tree = ast.parse(template_source)
    templates = [ast.literal_eval(node.value) for node in tree.body
                 if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TEMPLATES" for t in node.targets)]
    if len(templates) != 1:
        raise ValueError("unsupported SDK version generator")
    return templates[0][".py"].format(
        version=version, version_tuple=tuple(int(part) for part in version.split(".")),
        scm_version=SimpleNamespace(short_node="g" + commit[:9])).encode()


def collect(version: str, destination: Path) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("unsupported SDK version")
    destination.mkdir(parents=True, exist_ok=False)
    sdk = revision("microsoft/playwright-python", "v" + version)
    sdk_url = f"https://codeload.github.com/microsoft/playwright-python/tar.gz/{sdk}"
    (destination / "sdk.tar.gz").write_bytes(fetch(sdk_url))
    source = dict((name, raw) for name, raw in members(destination / "sdk.tar.gz")
                  if name in {"setup.py", "pyproject.toml"})
    import tomllib
    config = tomllib.loads(source["pyproject.toml"].decode())
    versions = [requirement.split("==", 1)[1] for requirement in config["build-system"]["requires"]
                if requirement.startswith("setuptools-scm==")]
    if len(versions) != 1 or not re.fullmatch(r"[0-9.]+", versions[0]):
        raise ValueError("SDK has no supported pinned version generator")
    if config["tool"]["setuptools_scm"]["version_file"] != "playwright/_repo_version.py":
        raise ValueError("SDK version-file location changed")
    setup = ast.parse(source["setup.py"])
    drivers = [ast.literal_eval(node.value) for node in setup.body if isinstance(node, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "driver_version" for t in node.targets)]
    if drivers != [version]:
        raise ValueError("SDK and driver versions differ")
    scm = revision("pypa/setuptools-scm", "v" + versions[0])
    template_url = f"https://raw.githubusercontent.com/pypa/setuptools-scm/{scm}/src/setuptools_scm/_integration/dump_version.py"
    (destination / "version-template.py").write_bytes(fetch(template_url, 1024 * 1024))
    (destination / "version-template-LICENSE.txt").write_bytes(fetch(
        f"https://raw.githubusercontent.com/pypa/setuptools-scm/{scm}/LICENSE", 1024 * 1024))
    url = f"https://registry.npmjs.org/-/npm/v1/attestations/playwright-core@{version}"
    attestations = json.loads(fetch(url, 2 * 1024 * 1024))["attestations"]
    bundles = [a["bundle"] for a in attestations if a["predicateType"] == "https://slsa.dev/provenance/v1"]
    if len(bundles) != 1:
        raise ValueError("driver build attestation unavailable or ambiguous")
    (destination / "driver.sigstore.json").write_text(json.dumps(bundles[0]))
    tarball = f"https://registry.npmjs.org/playwright-core/-/playwright-core-{version}.tgz"
    driver = fetch(tarball)
    (destination / "driver.tgz").write_bytes(driver)
    commit = driver_revision(statement(bundles[0]), version, hashlib.sha512(driver).hexdigest())
    driver_source = f"https://codeload.github.com/microsoft/playwright/tar.gz/{commit}"
    (destination / "driver-source.tar.gz").write_bytes(fetch(driver_source))
    files = ["sdk.tar.gz", "version-template.py", "driver.sigstore.json", "driver.tgz", "driver-source.tar.gz", "version-template-LICENSE.txt"]
    manifest = {"version": version, "sdk_revision": sdk, "driver_revision": commit,
                "sdk_url": sdk_url, "driver_url": tarball, "driver_source_url": driver_source,
                "template_url": template_url,
                "sha256": {name: hashlib.sha256(read(destination / name)).hexdigest() for name in files}}
    (destination / "inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")


def verify_signature(evidence: Path, version: str, verifier: Path, *, offline: bool) -> None:
    identity = r"^https://github\.com/microsoft/playwright/\.github/workflows/publish_release\.yml@refs/tags/v" + re.escape(version) + "$"
    command = [str(verifier), "verify", str(evidence / "driver.sigstore.json"),
               "--certificate-identity-uri", identity,
               "--certificate-issuer", "https://token.actions.githubusercontent.com",
               "--tlog-threshold", "1", "--ctlog-threshold", "1",
               "--tuf-cache-path", str((evidence / "sigstore-trust").resolve())]
    if offline:
        command.append("--tuf-force-cache")
    subprocess.run(command, check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def verify(artifact: dict, files: list, evidence: Path, verifier: Path) -> dict:
    version = artifact["version"]
    manifest = json.loads(read(evidence / "inputs.json", 1024 * 1024))
    if manifest["version"] != version:
        raise ValueError("stale SDK source evidence")
    for name in ("sdk.tar.gz", "version-template.py", "driver.sigstore.json", "driver.tgz", "driver-source.tar.gz", "version-template-LICENSE.txt"):
        if hashlib.sha256(read(evidence / name)).hexdigest() != manifest["sha256"][name]:
            raise ValueError("retained source evidence changed")
    verify_signature(evidence, version, verifier, offline=True)
    bundle = json.loads(read(evidence / "driver.sigstore.json", 2 * 1024 * 1024))
    commit = driver_revision(statement(bundle), version, hashlib.sha512(read(evidence / "driver.tgz")).hexdigest())
    if commit != manifest["driver_revision"]:
        raise ValueError("driver source revision differs from attestation")
    expected = {name[len("playwright/"):]: hashlib.sha256(raw).hexdigest()
                for name, raw in members(evidence / "sdk.tar.gz") if name.startswith("playwright/")}
    expected.update({"driver/package/" + name: hashlib.sha256(raw).hexdigest()
                     for name, raw in members(evidence / "driver.tgz")})
    expected["_repo_version.py"] = hashlib.sha256(sdk_version_file(
        read(evidence / "version-template.py", 1024 * 1024), version, manifest["sdk_revision"])).hexdigest()
    work = evidence / "generated"
    work.mkdir(exist_ok=False)
    for name, raw in members(evidence / "driver-source.tar.gz"):
        if name in GENERATORS or name.startswith(("docs/src/api/", "packages/protocol/spec/")):
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    api = work / "api.json"
    with api.open("wb") as stream:
        subprocess.run(["/usr/bin/node", "utils/doclint/generateApiJson.js"], cwd=work,
                       env={"PATH": "/usr/local/bin:/usr/bin:/bin", "API_JSON_MODE": "1"},
                       stdout=stream, stderr=subprocess.DEVNULL, timeout=30, check=True)
    expected["driver/package/api.json"] = hashlib.sha256(read(api, 8 * 1024 * 1024)).hexdigest()
    specs = [read(path, 1024 * 1024).decode() for path in sorted((work / "packages/protocol/spec").glob("*.yml"))]
    if not specs:
        raise ValueError("driver protocol definitions missing")
    protocol = "\n".join(text if text.endswith("\n") else text + "\n" for text in specs).encode()
    expected["driver/package/protocol.yml"] = hashlib.sha256(protocol).hexdigest()
    roots = {str(PurePosixPath(loc["path"]).parent.parent / "playwright") + "/"
             for loc in artifact.get("locations", []) if loc.get("path", "").endswith(
                 "/playwright-" + version + ".dist-info/METADATA")}
    if len(roots) != 1:
        raise ValueError("SDK install root is ambiguous")
    root = next(iter(roots))
    matched = []
    seen = set()
    for file in files:
        path = file.get("location", {}).get("path", "")
        if not path.startswith(root):
            continue
        relative = path[len(root):]
        if "/__pycache__/" in "/" + relative or relative in {"driver/LICENSE", "driver/README.md"}:
            continue
        digests = [d.get("value") for d in file.get("digests", []) if d.get("algorithm") == "sha256"]
        if not digests:
            if file.get("metadata", {}).get("type") == "RegularFile":
                raise ValueError("SDK file has no scanner content hash")
            continue
        if path in seen or len(digests) != 1 or expected.get(relative) != digests[0]:
            raise ValueError("SDK installed payload differs from source evidence: " + relative)
        seen.add(path)
        if relative == "_repo_version.py":
            basis = "reproduced_sdk_version_metadata"
        elif relative in {"driver/package/api.json", "driver/package/protocol.yml"}:
            basis = "reproduced_driver_metadata"
        elif relative.startswith("driver/package/"):
            basis = "sigstore_attested_driver_archive"
        else:
            basis = "immutable_sdk_source"
        matched.append({"path": path, "sha256": digests[0], "basis": basis})
    if set(expected) != {item["path"][len(root):] for item in matched}:
        raise ValueError("SDK runtime inventory is incomplete")
    return {"status": "verified_source_payload", "sdk_revision": manifest["sdk_revision"],
            "sdk_url": "https://github.com/microsoft/playwright-python/tree/" + manifest["sdk_revision"],
            "driver_revision": commit, "driver_url": REPO + "/tree/" + commit,
            "files": matched, "scope": "SDK source files and signed driver payload, including reproduced generated metadata",
            "limitations": ["not a wheel build attestation", "installed bytecode and packaging-only license/readme files are outside this source-content check"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--sigstore", type=Path, required=True)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    native = json.loads(read(args.syft, 64 * 1024 * 1024))
    results = {}
    for artifact in native.get("artifacts", []):
        if (artifact.get("type"), artifact.get("name")) != ("python", "playwright"):
            continue
        identifier = artifact["id"]
        if not re.fullmatch(r"[0-9a-f]{16}", identifier):
            raise ValueError("invalid package occurrence")
        evidence = args.evidence / identifier
        try:
            if args.download:
                collect(artifact["version"], evidence)
                verify_signature(evidence, artifact["version"], args.sigstore, offline=False)
                results[identifier] = {"status": "source_inputs_collected_signature_verified"}
            else:
                results[identifier] = verify(artifact, native.get("files", []), evidence, args.sigstore)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
            results[identifier] = {"status": "unverified", "gap": "Playwright source/driver verification unavailable or installed payload differs",
                                   "reason": str(error)[:400]}
    args.out.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
