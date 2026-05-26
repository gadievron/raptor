"""Tests for archive / tree target-identity provenance (core.run.provenance)."""

import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from core.run.provenance import (
    archive_snapshot,
    archive_target_identity,
    build_start_manifest,
    public_view,
)


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)


class TestArchiveSnapshot(unittest.TestCase):

    def test_zip(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "a.zip"
            _zip(p, {"f": b"x"})
            s = archive_snapshot(p)
            self.assertRegex(s["archive_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(s["archive_name"], "a.zip")
            self.assertEqual(s["format"], "zip")

    def test_non_archive_and_none(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "plain.txt"
            p.write_text("x")
            self.assertIsNone(archive_snapshot(p))
        self.assertIsNone(archive_snapshot(None))


class TestArchiveTargetIdentity(unittest.TestCase):

    def test_acquisition_stamp_only(self):
        # Acquisition stamp only — NO content_sha256 (the content-equivalence
        # id is the coverage store's, derived from the inventory).
        with TemporaryDirectory() as d:
            d = Path(d)
            ap = d / "a.zip"
            _zip(ap, {"f": b"x"})
            b = archive_target_identity(ap)
            self.assertEqual(b["source"], "archive")
            self.assertRegex(b["archive_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(b["archive_name"], "a.zip")
            self.assertEqual(b["format"], "zip")
            self.assertNotIn("content_sha256", b)

    def test_non_archive_none(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(archive_target_identity(Path(d) / "missing.zip"))


class TestBuildStartManifestTargetIdentity(unittest.TestCase):

    def test_explicit_identity_overrides_snapshot(self):
        ident = {"source": "archive", "archive_sha256": "a" * 64}
        m = build_start_manifest(target=None, target_identity=ident)
        self.assertEqual(m["target"], ident)

    def test_plain_directory_gets_source_marker(self):
        # A non-git/non-archive dir target gets the acquisition marker only
        # (no content hash — that's the store's equivalence id).
        with TemporaryDirectory() as d:
            m = build_start_manifest(target=d)
            self.assertEqual(m["target"], {"source": "directory"})

    def test_no_target_no_block(self):
        self.assertNotIn("target", build_start_manifest(target=None))


class TestPublicViewTarget(unittest.TestCase):

    def test_archive_acquisition_published_content_hash_dropped(self):
        md = {"command": "scan", "manifest": {
            "source_control": {"base_sha": "x", "dirty": False},
            "target": {"source": "archive", "archive_sha256": "a" * 64,
                       "archive_name": "a.zip", "format": "zip",
                       "content_sha256": "b" * 64},
        }}
        pv = public_view(md)
        t = pv["manifest"]["target"]
        self.assertEqual(t["archive_sha256"], "a" * 64)
        self.assertEqual(t["source"], "archive")
        self.assertEqual(t["format"], "zip")
        # content_sha256 is NOT published — it's the store's equivalence id,
        # never a manifest field.
        self.assertNotIn("content_sha256", t)

    def test_git_target_dropped(self):
        md = {"command": "scan", "manifest": {
            "source_control": {"base_sha": "x"},
            "target": {"vcs": "git", "commit": "deadbeef",
                       "branch": "secret/engagement", "dirty": False},
        }}
        pv = public_view(md)
        self.assertNotIn("target", pv.get("manifest", {}))
        self.assertNotIn("secret/engagement", json.dumps(pv))


class TestRewriteTargetArg(unittest.TestCase):

    def test_space_form(self):
        import raptor
        self.assertEqual(
            raptor._rewrite_target_arg(["--repo", "/a.zip", "-x"], "/a.zip", "/ex"),
            ["--repo", "/ex", "-x"])

    def test_eq_form(self):
        import raptor
        self.assertEqual(
            raptor._rewrite_target_arg(["--repo=/a.zip"], "/a.zip", "/ex"),
            ["--repo=/ex"])

    def test_binary_flag_and_passthrough(self):
        import raptor
        self.assertEqual(
            raptor._rewrite_target_arg(["--binary", "/a.zip"], "/a.zip", "/ex"),
            ["--binary", "/ex"])
        self.assertEqual(
            raptor._rewrite_target_arg(["--foo", "bar"], "/a.zip", "/ex"),
            ["--foo", "bar"])


class TestUnpackArchiveTarget(unittest.TestCase):

    def test_content_addressed_cache_and_reuse(self):
        import raptor
        with TemporaryDirectory() as d:
            d = Path(d)
            ap = d / "a.zip"
            _zip(ap, {"src/x.py": b"print()\n"})
            out1 = d / "proj" / "scan_1"
            out1.mkdir(parents=True)
            res = raptor._unpack_archive_target(
                str(ap), ["--repo", str(ap), "--no-codeql"], out1)
            self.assertIsNotNone(res)
            new_args, identity = res
            canonical = Path(new_args[new_args.index("--repo") + 1])
            # Extracted into <project>/_sources/<name>-<sha>/ — not the run dir.
            self.assertEqual(canonical.parent, d / "proj" / "_sources")
            # Dir name is human-readable (archive name) AND collision-free (sha).
            self.assertTrue(canonical.name.startswith("a.zip-"))
            self.assertTrue(canonical.name.endswith(identity["archive_sha256"]))
            self.assertTrue((canonical / "src" / "x.py").exists())
            self.assertEqual(identity["source"], "archive")
            self.assertNotIn("content_sha256", identity)  # equivalence id is the store's
            # Navigation symlink from the run dir.
            self.assertTrue((out1 / "_source").is_symlink())

            # A second run (same project, different run dir) REUSES the cached
            # extraction — no duplicate copy — and yields the same identity.
            out2 = d / "proj" / "scan_2"
            out2.mkdir(parents=True)
            new_args2, identity2 = raptor._unpack_archive_target(
                str(ap), ["--repo", str(ap)], out2)
            canonical2 = Path(new_args2[new_args2.index("--repo") + 1])
            self.assertEqual(canonical2, canonical)  # same cache dir, not duplicated
            self.assertEqual(identity2["archive_sha256"], identity["archive_sha256"])
            # Exactly one extraction dir under _sources.
            extracted_dirs = [p for p in (d / "proj" / "_sources").iterdir() if p.is_dir()]
            self.assertEqual(len(extracted_dirs), 1)

    def test_corrupt_archive_returns_none(self):
        import raptor
        with TemporaryDirectory() as d:
            d = Path(d)
            bad = d / "broken.gz"
            bad.write_bytes(b"\x1f\x8b\x08" + b"\xff" * 8)
            out_dir = d / "proj" / "scan"
            out_dir.mkdir(parents=True)
            self.assertIsNone(
                raptor._unpack_archive_target(str(bad), ["--repo", str(bad)], out_dir))


if __name__ == "__main__":
    unittest.main()
