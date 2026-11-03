"""Offline checks for automatic package-manager notice updates."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[2] / ".devcontainer"
SPEC = importlib.util.spec_from_file_location("refresh_npm_notices", HERE / "refresh-npm-notices.py")
REFRESH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFRESH)


def archive_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in files:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "npm"
        self.package = self.root / "node_modules/example"
        self.package.mkdir(parents=True)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.manifest_path = self.evidence / "provenance.json"
        self.notice = self.evidence / "example-LICENSE"
        self.notice.write_bytes(b"old notice")
        self.entry = {"name": "example", "version": "1.0", "license": "MIT",
                      "status": "upstream_evidence_retained", "source_kind": "integrity_checked_package_release",
                      "source_path": "package/LICENSE", "notice_file": "example-LICENSE",
                      "installed_filename": "LICENSE", "sha256": hashlib.sha256(b"old notice").hexdigest()}
        self.manifest = {"schema_version": 1, "npm_version": "1.0", "packages": [self.entry]}
        self.save()
        (self.root / "package.json").write_text(json.dumps({"name": "npm", "version": "2.0"}))
        self.installed = {"name": "example", "version": "2.0", "license": "MIT"}
        (self.package / "package.json").write_text(json.dumps(self.installed))
        (self.package / "index.js").write_bytes(b"module.exports = 2;\n")
        self.raw = archive_bytes([("package/package.json", json.dumps(self.installed).encode()),
                                  ("package/index.js", b"module.exports = 2;\n"),
                                  ("package/LICENSE", b"new notice")])
        self.metadata = {**self.installed, "gitHead": "b" * 40, "dist": {
            "tarball": "https://registry.npmjs.org/example/-/example-2.0.tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(self.raw).digest()).decode()}}
        self.network = patch.object(REFRESH, "fetch", side_effect=self.fetch)
        self.mock_fetch = self.network.start()
        self.addCleanup(self.network.stop)

    def fetch(self, url):
        if url.endswith(".tgz"):
            return self.raw
        if url.startswith("https://raw.githubusercontent.com/"):
            return b"new repository notice"
        return json.dumps(self.metadata).encode()

    def save(self):
        self.manifest_path.write_text(json.dumps(self.manifest, indent=2) + "\n")

    def refresh(self, **kwargs):
        return REFRESH.refresh(self.root, self.evidence, **kwargs)

    def test_version_bump_refreshes_notice_and_release_provenance(self):
        self.assertTrue(self.refresh())
        manifest = json.loads(self.manifest_path.read_text())
        entry = manifest["packages"][0]
        self.assertEqual(manifest["npm_version"], "2.0")
        self.assertEqual(entry["version"], "2.0")
        self.assertEqual(entry["release_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(entry["verified_installed_files"], 2)
        self.assertEqual(self.notice.read_bytes(), b"new notice")
        self.assertEqual(REFRESH.INSTALLER.install(self.root, self.evidence), 1)
        self.assertFalse(self.refresh(force=True, check=True))

    def test_unchanged_versions_need_no_network(self):
        self.manifest["npm_version"] = "2.0"
        self.entry["version"] = "2.0"
        self.save()
        self.assertFalse(self.refresh())
        self.mock_fetch.assert_not_called()

    def test_check_never_writes(self):
        before = self.manifest_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "needs refreshing"):
            self.refresh(check=True)
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_mismatched_installed_and_registry_licences_are_rejected(self):
        self.installed["license"] = "Apache-2.0"
        (self.package / "package.json").write_text(json.dumps(self.installed))
        with self.assertRaisesRegex(ValueError, "registry and installed"):
            self.refresh()
        self.mock_fetch.assert_called()
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_consistent_changed_licence_refreshes_without_legal_review(self):
        self.installed["license"] = "Apache-2.0"
        self.metadata["license"] = "Apache-2.0"
        (self.package / "package.json").write_text(json.dumps(self.installed))
        self.raw = archive_bytes([("package/package.json", json.dumps(self.installed).encode()),
                                  ("package/index.js", b"module.exports = 2;\n"),
                                  ("package/LICENSE", b"new upstream terms")])
        self.metadata["dist"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(self.raw).digest()).decode()
        self.refresh()
        updated = json.loads(self.manifest_path.read_text())["packages"][0]
        self.assertEqual(updated["license"], "Apache-2.0")
        self.assertEqual(self.notice.read_bytes(), b"new upstream terms")

    def test_registry_identity_mismatch_is_rejected(self):
        self.metadata["version"] = "3.0"
        with self.assertRaisesRegex(ValueError, "registry and installed"):
            self.refresh()
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_integrity_failure_preserves_evidence(self):
        self.raw += b"modified"
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            self.refresh()
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_weak_digest_cannot_override_stronger_mismatch(self):
        self.metadata["dist"]["integrity"] = "sha512-" + base64.b64encode(b"x" * 64).decode()
        self.metadata["dist"]["integrity"] += " sha256-" + base64.b64encode(hashlib.sha256(self.raw).digest()).decode()
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            self.refresh()

    def test_different_installed_payload_requires_review(self):
        (self.package / "index.js").write_bytes(b"different bundled build")
        with self.assertRaisesRegex(ValueError, "payload differs"):
            self.refresh()
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_added_installed_file_requires_review(self):
        (self.package / "extra.js").write_bytes(b"unaccounted code")
        with self.assertRaisesRegex(ValueError, "payload absent"):
            self.refresh()

    def test_symlink_payload_is_rejected(self):
        (self.package / "index.js").unlink()
        (self.package / "index.js").symlink_to(self.notice)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.refresh()
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_late_failure_leaves_earlier_evidence_untouched(self):
        self.manifest["packages"].append({**self.entry, "name": "other"})
        self.save()
        other = self.root / "node_modules/other"
        other.mkdir()
        (other / "package.json").write_text(json.dumps({"name": "other", "version": "2.0", "license": "BSD-3-Clause"}))
        before = self.manifest_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "registry and installed"):
            self.refresh()
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_missing_notice_recipe_retries_with_verified_payload(self):
        self.entry.update(status="unresolved", retry_missing_notice=True)
        self.save()
        self.refresh()
        updated = json.loads(self.manifest_path.read_text())["packages"][0]
        self.assertEqual(updated["status"], "upstream_evidence_retained")
        self.assertGreater(updated["verified_installed_files"], 0)
        self.assertNotIn("retry_missing_notice", updated)

    def test_unresolved_entry_is_not_promoted_from_a_declaration(self):
        self.entry["status"] = "unresolved"
        self.entry["reason"] = "No applicable notice established."
        self.save()
        (self.package / "index.js").write_bytes(b"native or bundled build differs")
        self.refresh()
        entry = json.loads(self.manifest_path.read_text())["packages"][0]
        self.assertEqual(entry["status"], "unresolved")
        self.assertEqual(entry["version"], "2.0")
        self.assertEqual(self.notice.read_bytes(), b"old notice")
        self.assertFalse((self.package / "LICENSE").exists())

    def test_removed_and_reintroduced_dependency(self):
        shutil.rmtree(self.package)
        self.refresh()
        self.assertTrue(json.loads(self.manifest_path.read_text())["packages"][0]["absent"])
        self.assertEqual(REFRESH.INSTALLER.install(self.root, self.evidence), 0)
        self.package.mkdir()
        (self.package / "package.json").write_text(json.dumps(self.installed))
        (self.package / "index.js").write_bytes(b"module.exports = 2;\n")
        with self.assertRaisesRegex(ValueError, "bundled package changed"):
            REFRESH.INSTALLER.install(self.root, self.evidence)
        self.refresh()
        self.assertNotIn("absent", json.loads(self.manifest_path.read_text())["packages"][0])
        self.assertEqual(REFRESH.INSTALLER.install(self.root, self.evidence), 1)

    def test_dependency_layout_change_requires_review(self):
        shutil.rmtree(self.root / "node_modules")
        with self.assertRaisesRegex(ValueError, "dependency layout changed"):
            self.refresh()

    def test_repository_fallback_tracks_release_commit(self):
        self.entry.update(source_kind="pinned_upstream_repository", source_commit="a" * 40,
                          source_url="https://raw.githubusercontent.com/example/project/" + "a" * 40 + "/LICENSE",
                          source_path="LICENSE")
        self.save()
        self.refresh()
        entry = json.loads(self.manifest_path.read_text())["packages"][0]
        self.assertIn("/" + "b" * 40 + "/LICENSE", entry["source_url"])
        self.assertEqual(self.notice.read_bytes(), b"new repository notice")

    def test_unpinned_repository_fallback_is_rejected(self):
        self.entry.update(source_kind="pinned_upstream_repository", source_commit="a" * 40,
                          source_url="https://raw.githubusercontent.com/example/project/main/LICENSE")
        self.save()
        with self.assertRaisesRegex(ValueError, "reviewed recipe"):
            self.refresh()

    def test_unsafe_archive_members_are_rejected(self):
        for name in ["../LICENSE", "/package/LICENSE", "package/./LICENSE", "package//LICENSE"]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "unsafe"):
                REFRESH.release_files(archive_bytes([(name, b"x")]))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            REFRESH.release_files(archive_bytes([("package/LICENSE", b"x"), ("package/LICENSE", b"y")]))

    def configure_readme(self, new_readme):
        previous = b"Old usage.\n\n## License\nMIT attribution.\n"
        self.notice.write_bytes(previous)
        self.entry.update(source_path="package/README.md", sha256=hashlib.sha256(previous).hexdigest())
        self.save()
        self.raw = archive_bytes([("package/package.json", json.dumps(self.installed).encode()),
                                  ("package/index.js", b"module.exports = 2;\n"),
                                  ("package/README.md", new_readme)])
        self.metadata["dist"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(self.raw).digest()).decode()

    def test_readme_usage_changes_can_refresh_automatically(self):
        self.configure_readme(b"New usage.\n\n## License\nMIT attribution.\n")
        self.refresh()
        self.assertTrue(self.notice.read_bytes().startswith(b"New usage."))

    def test_readme_attribution_change_refreshes_without_legal_review(self):
        self.configure_readme(b"Usage.\n\n## License\nNew attribution.\n")
        self.refresh()
        self.assertIn(b"New attribution.", self.notice.read_bytes())

    def test_removed_readme_licensing_section_records_a_gap(self):
        self.configure_readme(b"Usage only.\n")
        self.refresh()
        self.assertEqual(json.loads(self.manifest_path.read_text())["packages"][0]["status"], "unresolved")

    def test_archive_symlink_is_rejected(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("package/LICENSE")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            REFRESH.release_files(stream.getvalue())


if __name__ == "__main__":
    unittest.main()
