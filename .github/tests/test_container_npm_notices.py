"""Offline tests for version-scoped container notice additions."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parents[2] / ".devcontainer"
SPEC = importlib.util.spec_from_file_location("install_npm_notices", HERE / "install-npm-notices.py")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "npm"
        self.root.mkdir()
        self.evidence = HERE / "npm-notices"
        self.manifest = json.loads((self.evidence / "provenance.json").read_text())
        (self.root / "package.json").write_text(json.dumps({"name": "npm", "version": self.manifest["npm_version"]}))
        for entry in self.manifest["packages"]:
            package = self.root / "node_modules" / entry["name"]
            package.mkdir(parents=True)
            (package / "package.json").write_text(json.dumps({k: entry[k] for k in ("name", "version", "license")}))

    def install(self):
        with contextlib.redirect_stderr(io.StringIO()) as output:
            count = INSTALLER.install(self.root, self.evidence)
        return count, output.getvalue()

    def test_exact_evidence_and_unresolved_gap_survive_repeated_install(self):
        for _ in range(2):
            count, warning = self.install()
            self.assertEqual(count, 3)
            self.assertIn("@npmcli/agent", warning)
            for entry in self.manifest["packages"]:
                package = self.root / "node_modules" / entry["name"]
                if entry["status"] == "unresolved":
                    self.assertEqual([p.name for p in package.iterdir()], ["package.json"])
                else:
                    data = (package / entry["installed_filename"]).read_bytes()
                    self.assertEqual(data, (self.evidence / entry["notice_file"]).read_bytes())
                    self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])

    def test_late_package_mismatch_leaves_all_packages_untouched(self):
        entry = self.manifest["packages"][-1]
        (self.root / "node_modules" / entry["name"] / "package.json").write_text('{}')
        with self.assertRaisesRegex(ValueError, "package changed"):
            self.install()
        self.assertFalse(list(self.root.rglob("NOTICE")))
        self.assertFalse(list(self.root.rglob("LICENSE")))

    def test_npm_update_requires_evidence_review(self):
        (self.root / "package.json").write_text('{"name":"npm","version":"99.0.0"}')
        with self.assertRaisesRegex(ValueError, "npm version changed"):
            self.install()

    def test_existing_different_notice_is_preserved(self):
        entry = self.manifest["packages"][-1]
        target = self.root / "node_modules" / entry["name"] / entry["installed_filename"]
        target.write_bytes(b"new upstream notice")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.install()
        self.assertEqual(target.read_bytes(), b"new upstream notice")

    def test_symlink_cannot_redirect_notice_write(self):
        entry = self.manifest["packages"][-1]
        target = self.root / "node_modules" / entry["name"] / entry["installed_filename"]
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"keep")
        target.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.install()
        self.assertEqual(outside.read_bytes(), b"keep")

    def test_modified_evidence_is_rejected_before_writes(self):
        import shutil
        copy = Path(self.temp.name) / "evidence"
        shutil.copytree(self.evidence, copy)
        entry = self.manifest["packages"][-1]
        (copy / entry["notice_file"]).write_bytes(b"modified")
        self.evidence = copy
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.install()
        self.assertFalse(list(self.root.rglob("NOTICE")))
        self.assertFalse(list(self.root.rglob("LICENSE")))


if __name__ == "__main__":
    unittest.main()
