"""/project binary content-witness pinning (store side).

The binary store is the one surface where run-writable content is
promoted to durable suppression authority (the env-build persist hint
names a path inside the run dir's write grant, and `absent` verdicts
from store binaries hard-suppress findings pre-LLM). The add is a
trust assertion about BYTES, so add pins sha256 and the registry
carries it; the load-side re-verification lives in
core/analysis/tests/test_binary_oracle_cli.py.
"""

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.hash import sha256_file
from core.project.project import Project, ProjectManager


class BinaryWitnessCliTest(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        root = Path(self.tmpdir.name)
        self.mgr = ProjectManager(projects_dir=root / "projects")
        self.target = root / "code"
        self.target.mkdir()
        self.mgr.create("myapp", str(self.target),
                        output_dir=str(root / "output"))
        self.bin_path = root / "app.debug"
        self.bin_path.write_bytes(b"\x7fELF" + b"\x00" * 28)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _run(self, *argv):
        from core.project.cli import main
        with patch("core.project.cli.ProjectManager",
                   return_value=self.mgr), \
             patch.object(sys, "argv", ["raptor-project", *argv]):
            main()

    def _witnesses(self):
        return self.mgr.load("myapp").binary_witnesses

    def test_add_pins_sha256(self):
        self._run("binary", "add", str(self.bin_path), "myapp")
        p = self.mgr.load("myapp")
        resolved = str(self.bin_path.resolve())
        self.assertIn(resolved, p.binaries)
        self.assertEqual(self._witnesses().get(resolved),
                         sha256_file(self.bin_path))

    def test_readd_after_rebuild_refreshes_witness(self):
        self._run("binary", "add", str(self.bin_path), "myapp")
        self.bin_path.write_bytes(b"\x7fELF" + b"\x01" * 28)
        self._run("binary", "add", str(self.bin_path), "myapp")
        resolved = str(self.bin_path.resolve())
        self.assertEqual(self._witnesses().get(resolved),
                         sha256_file(self.bin_path))
        # Still one store entry — a refresh is not a duplicate add.
        self.assertEqual(self.mgr.load("myapp").binaries.count(resolved), 1)

    def test_remove_drops_witness(self):
        self._run("binary", "add", str(self.bin_path), "myapp")
        self._run("binary", "remove", str(self.bin_path), "myapp")
        self.assertEqual(self._witnesses(), {})

    def test_clear_drops_witnesses(self):
        self._run("binary", "add", str(self.bin_path), "myapp")
        self._run("binary", "clear", "myapp")
        p = self.mgr.load("myapp")
        self.assertEqual(p.binaries, [])
        self.assertEqual(p.binary_witnesses, {})

    def test_roundtrip_preserves_witnesses(self):
        self._run("binary", "add", str(self.bin_path), "myapp")
        p = Project.from_dict(self.mgr.load("myapp").to_dict())
        resolved = str(self.bin_path.resolve())
        self.assertEqual(p.binary_witnesses.get(resolved),
                         sha256_file(self.bin_path))

    def test_from_dict_screens_typed_corruption(self):
        # A hand-edited / imported file with non-string witness values
        # must read as UNWITNESSED (enrichment-only tier), never crash
        # and never pass a non-string pin downstream.
        p = self.mgr.load("myapp")
        d = p.to_dict()
        d["binary_witnesses"] = {"/a": ["not", "str"], "/b": "", 3: "x",
                                 "/c": "deadbeef"}
        loaded = Project.from_dict(d)
        self.assertEqual(loaded.binary_witnesses, {"/c": "deadbeef"})
        d["binary_witnesses"] = "not-a-dict"
        self.assertEqual(Project.from_dict(d).binary_witnesses, {})


if __name__ == "__main__":
    unittest.main()
