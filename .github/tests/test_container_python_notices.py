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
        self.license_header = self.entry.get("license_header", "License")
        self.metadata = (
            f"Metadata-Version: 2.4\nName: {self.entry['name']}\n"
            f"Version: {self.entry['version']}\n{self.license_header}: {self.entry['license']}\n"
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

    def test_unavailable_notice_warns_without_changing_installed_metadata(self):
        self.entry["status"] = "unresolved"
        self.entry.pop("sha256", None)
        self.save_manifest()
        self.assertEqual(self.install(), 0)
        self.assertFalse(self.target.exists())
        self.assertEqual((self.package / "METADATA").read_bytes(), self.metadata)

    def test_unresolved_name_cannot_emit_terminal_controls(self):
        import contextlib
        import io

        original = self.entry["name"]
        hostile = "project" + chr(27) + "[31m"
        self.entry.update(name=hostile, status="unresolved")
        self.save_manifest()
        metadata = self.metadata.replace(("Name: " + original + "\n").encode(),
                                         ("Name: " + hostile + "\n").encode(), 1)
        (self.package / "METADATA").write_bytes(metadata)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(self.install(), 0)
        warning = stderr.getvalue()
        self.assertNotIn(chr(27), warning)
        self.assertEqual(warning.count("\n"), 1)
        self.assertTrue(all(32 <= ord(c) < 127 for c in warning.rstrip("\n")))
        self.assertFalse(self.target.exists())
        self.assertEqual((self.package / "METADATA").read_bytes(), metadata)

    def test_metadata_mismatch_diagnostic_escapes_version_controls(self):
        version = "9.9" + chr(27) + "[31m"
        metadata = self.metadata.replace(("Version: " + self.entry["version"] + "\n").encode(),
                                         ("Version: " + version + "\n").encode(), 1)
        (self.package / "METADATA").write_bytes(metadata)
        with self.assertRaises(ValueError) as caught:
            self.install()
        diagnostic = str(caught.exception)
        self.assertNotIn(chr(27), diagnostic)
        self.assertTrue(all(32 <= ord(c) < 127 for c in diagnostic))
        self.assertFalse(self.target.exists())

    def test_removed_distribution_can_be_skipped(self):
        shutil.rmtree(self.package)
        self.assertEqual(INSTALLER.install(self.site, self.evidence, skip_absent=True), 0)
        with self.assertRaises(FileNotFoundError):
            self.install()

    def test_skip_absent_does_not_hide_version_mismatch(self):
        self.package.rename(self.site / "other-version.dist-info")
        with self.assertRaisesRegex(ValueError, "distribution changed"):
            INSTALLER.install(self.site, self.evidence, skip_absent=True)

    def test_present_distribution_still_requires_valid_metadata(self):
        (self.package / "METADATA").unlink()
        with self.assertRaises(FileNotFoundError):
            INSTALLER.install(self.site, self.evidence, skip_absent=True)

    def test_changed_identity_requires_review(self):
        for header, value in [("Name", "other-project"), ("Version", "99.0.0"), (self.license_header, "other licence")]:
            with self.subTest(header=header):
                data = self.metadata.decode().splitlines()
                data = [header + ": " + value if line.startswith(header + ":") else line for line in data]
                (self.package / "METADATA").write_text("\n".join(data) + "\n")
                with self.assertRaisesRegex(ValueError, "distribution changed"):
                    self.install()
                self.assertFalse(self.target.exists())

    def test_ambiguous_metadata_is_rejected(self):
        for header in ["Name", "Version", self.license_header]:
            with self.subTest(header=header):
                (self.package / "METADATA").write_bytes(self.metadata + f"{header}: duplicate\n".encode())
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    self.install()

    def test_unsupported_licence_header_is_rejected(self):
        self.entry["license_header"] = "Summary"
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, "unsupported licence"):
            self.install()
        self.assertFalse(self.target.exists())

    def test_conflicting_licence_fields_are_rejected(self):
        other = "License" if self.license_header == "License-Expression" else "License-Expression"
        (self.package / "METADATA").write_bytes(self.metadata + f"{other}: MIT\n".encode())
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.install()
        self.assertFalse(self.target.exists())

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
        (other / "METADATA").write_text(f"Name: other\nVersion: 1.0\n{self.license_header}: {self.entry['license']}\n")
        self.manifest["packages"].append(entry)
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, "distribution changed"):
            self.install()
        self.assertFalse(self.target.exists())


class PydocstyleNoticeTests(PythonNoticeTests):
    EVIDENCE = HERE / "pydocstyle-notices"


class OpenTelemetryNoticeTests(PythonNoticeTests):
    EVIDENCE = HERE / "opentelemetry-notices"


class SemgrepNoticeTests(PythonNoticeTests):
    EVIDENCE = HERE / "semgrep-notices"


class TerminalWarningTests(unittest.TestCase):
    def test_controls_bidi_and_long_names_are_printable_and_bounded(self):
        payloads = ["name\r\n::error::injected", "name\x1b[2J", "name\x85next",
                    "name\u202ereversed", "x" * 10000, "\U0001f642" * 10000]
        for payload in payloads:
            with self.subTest(payload=repr(payload[:30])):
                rendered = INSTALLER._term(payload)
                self.assertLessEqual(len(rendered), 2402)
                self.assertTrue(all(32 <= ord(c) < 127 for c in rendered))
                self.assertIsInstance(json.loads(rendered), str)

    def test_build_helper_needs_only_the_standard_library(self):
        import os
        import subprocess
        import sys

        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        with tempfile.TemporaryDirectory() as empty:
            result = subprocess.run([sys.executable, "-S", str(HERE / "install-python-notices.py"), "--help"],
                                    cwd=empty, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
