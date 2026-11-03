"""Offline regression checks for automatic Python notice refreshes."""
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parents[2] / ".devcontainer"
SPEC = importlib.util.spec_from_file_location("refresh_python_notices", HERE / "refresh-python-notices.py")
REFRESH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFRESH)


def source_archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "example-notices"
        self.evidence.mkdir()
        self.entry = {
            "name": "example", "version": "1.0", "license": "MIT", "license_spdx": "MIT",
            "metadata_directory": "example-1.0.dist-info", "notice_file": "example-LICENSE",
            "installed_filename": "LICENSE", "source_kind": "hash_checked_source_distribution",
            "source_path": "example-1.0/LICENSE", "sha256": "old",
        }
        self.manifest = self.evidence / "provenance.json"
        self.manifest.write_text(json.dumps({"schema_version": 1, "packages": [self.entry]}))
        self.notice = self.evidence / "example-LICENSE"
        self.notice.write_bytes(b"old notice")
        self.metadata = b"Name: example\nVersion: 2.0\nLicense-Expression: MIT\n"
        self.source = source_archive({"example-2.0/LICENSE": b"new upstream notice", "example-2.0/PKG-INFO": self.metadata})
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("example-2.0.dist-info/METADATA", self.metadata)
        self.wheel = stream.getvalue()
        self.release = {"urls": [
            {"packagetype": "sdist", "filename": "example-2.0.tar.gz", "url": "https://files.pythonhosted.org/source",
             "digests": {"sha256": hashlib.sha256(self.source).hexdigest()}},
            {"packagetype": "bdist_wheel", "filename": "example-2.0-py3-none-any.whl", "url": "https://files.pythonhosted.org/wheel",
             "digests": {"sha256": hashlib.sha256(self.wheel).hexdigest()}},
        ]}
        self.fetcher = patch.object(REFRESH, "fetch", side_effect=self.fetch)
        self.fetcher.start()
        self.addCleanup(self.fetcher.stop)

    def fetch(self, url):
        if url.endswith("/json"):
            return json.dumps(self.release).encode()
        return {"https://files.pythonhosted.org/source": self.source,
                "https://files.pythonhosted.org/wheel": self.wheel}[url]

    def refresh(self, check=False):
        return REFRESH.refresh(self.root, "example", "2.0", check)

    def test_version_bump_refreshes_metadata_notice_and_checksums(self):
        self.assertTrue(self.refresh())
        updated = json.loads(self.manifest.read_text())["packages"][0]
        self.assertEqual(updated["version"], "2.0")
        self.assertEqual(updated["metadata_directory"], "example-2.0.dist-info")
        self.assertEqual(updated["license_header"], "License-Expression")
        self.assertEqual(updated["sha256"], hashlib.sha256(self.notice.read_bytes()).hexdigest())
        self.assertEqual(self.notice.read_bytes(), b"new upstream notice")
        self.assertFalse(self.refresh(check=True))

    def test_check_never_writes(self):
        before = self.manifest.read_bytes()
        with self.assertRaisesRegex(ValueError, "needs refreshing"):
            self.refresh(check=True)
        self.assertEqual(before, self.manifest.read_bytes())
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_checksum_failure_preserves_evidence(self):
        self.source += b"changed"
        before = self.manifest.read_bytes()
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.refresh()
        self.assertEqual(before, self.manifest.read_bytes())
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_conflicting_wheel_and_source_licences_are_rejected(self):
        metadata = self.metadata.replace(b"MIT", b"Apache-2.0")
        with patch.object(REFRESH, "wheel_metadata", return_value=(metadata, "example-2.0.dist-info")):
            with self.assertRaisesRegex(ValueError, "wheel and source metadata disagree"):
                self.refresh()
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_consistent_changed_licence_refreshes_without_legal_review(self):
        metadata = self.metadata.replace(b"MIT", b"Apache-2.0")
        self.source = source_archive({"example-2.0/LICENSE": b"new terms", "example-2.0/PKG-INFO": metadata})
        self.release["urls"][0]["digests"]["sha256"] = hashlib.sha256(self.source).hexdigest()
        with patch.object(REFRESH, "wheel_metadata", return_value=(metadata, "example-2.0.dist-info")):
            self.refresh()
        updated = json.loads(self.manifest.read_text())["packages"][0]
        self.assertEqual(updated["license_spdx"], "Apache-2.0")
        self.assertEqual(self.notice.read_bytes(), b"new terms")

    def test_missing_notice_records_a_gap_and_preserves_old_reference(self):
        self.source = source_archive({"example-2.0/PKG-INFO": self.metadata})
        self.release["urls"][0]["digests"]["sha256"] = hashlib.sha256(self.source).hexdigest()
        self.refresh()
        updated = json.loads(self.manifest.read_text())["packages"][0]
        self.assertEqual(updated["status"], "unresolved")
        self.assertEqual(updated["version"], "2.0")
        self.assertIsNone(updated["sha256"])
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_source_layout_change_requires_review(self):
        with self.assertRaisesRegex(ValueError, "source layout changed"):
            REFRESH.tar_files(self.source, {"example-2.0/COPYING"})

    def test_duplicate_members_are_rejected(self):
        data = source_archive({"LICENSE": b"first"})
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for _ in range(2):
                member = tarfile.TarInfo("LICENSE")
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        self.assertTrue(data)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            REFRESH.tar_files(stream.getvalue(), {"LICENSE"})

    def test_archive_symlink_is_rejected(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("LICENSE")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            REFRESH.tar_files(stream.getvalue(), {"LICENSE"})

    def test_installed_versions_are_read_without_importing_packages(self):
        site = self.root / "site"
        info = site / "example-2.0.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_bytes(self.metadata)
        self.assertEqual(REFRESH.installed_versions(self.root, site), {"example": "2.0"})

    def test_batch_validation_precedes_writes(self):
        first = REFRESH.plan_refresh(self.root, "example", "2.0")
        with self.assertRaisesRegex(ValueError, "expected one"):
            plans = [first, REFRESH.plan_refresh(self.root, "unknown", "2.0")]
            REFRESH.apply_plans(plans)
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_unchanged_installed_version_needs_no_network(self):
        site = self.root / "site"
        info = site / "example-1.0.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_bytes(self.metadata.replace(b"2.0", b"1.0"))
        argv = ["refresh", "--evidence-root", str(self.root), "--site-packages", str(site), "--if-version-changed"]
        with patch("sys.argv", argv), patch.object(REFRESH, "fetch", side_effect=AssertionError("unexpected network")):
            REFRESH.main()
        self.assertEqual(self.notice.read_bytes(), b"old notice")

    def test_installed_version_bump_automatically_refreshes(self):
        site = self.root / "site"
        info = site / "example-2.0.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_bytes(self.metadata)
        argv = ["refresh", "--evidence-root", str(self.root), "--site-packages", str(site), "--if-version-changed"]
        with patch("sys.argv", argv):
            REFRESH.main()
        self.assertEqual(json.loads(self.manifest.read_text())["packages"][0]["version"], "2.0")
        self.assertEqual(self.notice.read_bytes(), b"new upstream notice")

    def test_removed_dependencies_need_no_refresh(self):
        site = self.root / "empty-site"
        site.mkdir()
        self.assertEqual(REFRESH.installed_versions(self.root, site), {})

    def test_conflicting_metadata_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "conflicting"):
            REFRESH.identity(self.metadata + b"License: MIT\n")

    def test_unreviewed_repository_fallback_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "explicit reviewed recipe"):
            REFRESH.repository_notice(self.entry, "2.0", self.source, "example-2.0")

    def test_repository_fallback_requires_matching_source(self):
        entry = deepcopy(self.entry)
        entry["name"] = "opentelemetry-util-http"
        entry["license_spdx"] = "Apache-2.0"
        commit = "a" * 40
        def fetch(url):
            if "/git/ref/" in url:
                return json.dumps({"object": {"type": "commit", "sha": commit}}).encode()
            if url.endswith("pyproject.toml"):
                return b'[project]\nlicense = "Apache-2.0"\n'
            return b"different source"
        paths = ["src/opentelemetry/util/http/" + x for x in ("__init__.py", "httplib.py", "py.typed", "version.py")]
        source = source_archive({"example-2.0/" + p: b"source" for p in paths})
        with patch.object(REFRESH, "fetch", side_effect=fetch):
            with self.assertRaisesRegex(ValueError, "source differs"):
                REFRESH.repository_notice(entry, "2.0", source, "example-2.0")


if __name__ == "__main__":
    unittest.main()
