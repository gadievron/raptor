"""Offline checks for version-scoped Python notice additions."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


HERE = Path(__file__).resolve().parents[2] / ".devcontainer"
SPEC = importlib.util.spec_from_file_location("install_python_notices", HERE / "install-python-notices.py")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class PythonNoticeTests(unittest.TestCase):
    EVIDENCE = HERE / "python-notices"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.site = self.root / "site-packages"
        self.site.mkdir()
        self.evidence = self.root / "evidence"
        shutil.copytree(self.EVIDENCE, self.evidence)
        self.manifest = json.loads((self.evidence / "provenance.json").read_text())
        self.entry = self.manifest["packages"][0]
        self.package = self.site / self.entry["metadata_directory"]
        self.package.mkdir()
        self.metadata = (
            f"Metadata-Version: 2.1\nName: {self.entry['name']}\n"
            f"Version: {self.entry['version']}\nLicense: {self.entry['license']}\n"
        ).encode()
        (self.package / "METADATA").write_bytes(self.metadata)
        (self.package / "RECORD").write_bytes(b"original wheel inventory\n")
        self.target = self.package / self.entry["installed_filename"]

    def save_manifest(self):
        (self.evidence / "provenance.json").write_text(json.dumps(self.manifest))

    def install(self):
        return INSTALLER.install(self.site, self.evidence)

    def test_exact_notice_is_retained_without_changing_wheel_metadata(self):
        for _ in range(2):
            self.assertEqual(self.install(), 1)
            self.assertEqual(self.target.read_bytes(), (self.evidence / self.entry["notice_file"]).read_bytes())
            self.assertEqual((self.package / "METADATA").read_bytes(), self.metadata)
            self.assertEqual((self.package / "RECORD").read_bytes(), b"original wheel inventory\n")

    def test_changed_identity_requires_review(self):
        for header, value in [("Name", "other-project"), ("Version", "99.0.0"), ("License", "other licence")]:
            with self.subTest(header=header):
                data = self.metadata.decode().splitlines()
                data = [header + ": " + value if line.startswith(header + ":") else line for line in data]
                (self.package / "METADATA").write_text("\n".join(data) + "\n")
                with self.assertRaisesRegex(ValueError, "distribution changed"):
                    self.install()
                self.assertFalse(self.target.exists())

    def test_ambiguous_metadata_is_rejected(self):
        for header in ["Name", "Version", "License"]:
            with self.subTest(header=header):
                (self.package / "METADATA").write_bytes(self.metadata + f"{header}: duplicate\n".encode())
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    self.install()

    def test_changed_evidence_is_rejected(self):
        (self.evidence / self.entry["notice_file"]).write_bytes(b"modified licence")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.install()
        self.assertFalse(self.target.exists())

    def test_existing_different_notice_is_preserved(self):
        self.target.write_bytes(b"new upstream notice")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.install()
        self.assertEqual(self.target.read_bytes(), b"new upstream notice")

    def test_notice_symlink_cannot_redirect_writes(self):
        outside = self.root / "outside"
        outside.write_bytes(b"keep")
        self.target.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.install()
        self.assertEqual(outside.read_bytes(), b"keep")

    def test_metadata_symlink_is_rejected(self):
        metadata = self.package / "METADATA"
        metadata.unlink()
        outside = self.root / "outside"
        outside.write_bytes(self.metadata)
        metadata.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.install()

    def test_metadata_path_cannot_escape_site_packages(self):
        self.entry["metadata_directory"] = "../outside.dist-info"
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, "invalid evidence path"):
            self.install()

    def test_late_mismatch_leaves_earlier_notice_unwritten(self):
        entry = deepcopy(self.entry)
        entry.update(name="other", version="2.0", metadata_directory="other-1.0.dist-info")
        other = self.site / entry["metadata_directory"]
        other.mkdir()
        (other / "METADATA").write_text("Name: other\nVersion: 1.0\nLicense: MIT\n")
        self.manifest["packages"].append(entry)
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, "distribution changed"):
            self.install()
        self.assertFalse(self.target.exists())


class PydocstyleNoticeTests(PythonNoticeTests):
    EVIDENCE = HERE / "pydocstyle-notices"


if __name__ == "__main__":
    unittest.main()
