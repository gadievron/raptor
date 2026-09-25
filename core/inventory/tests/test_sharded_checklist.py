"""Tests for the sharded ``checklist/`` layout (index + shards).

The on-disk contract is exercised from both sides: hand-built layouts
prove the READER contract (integrity verification, dir-local shard
paths, budgets, degrade directions) independent of any writer.
"""

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import core.inventory as inv
from core.inventory import (
    checklist_exists,
    iter_checklist_items,
    read_checklist,
    read_checklist_meta,
)


def _entry(path: str, names: list[str]) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": hashlib.sha256(path.encode()).hexdigest(),
        "sloc": 10,
        "items": [
            {"name": n, "kind": "function", "line_start": 1, "line_end": 5}
            for n in names
        ],
    }


def write_sharded(
    out_dir: Path,
    meta: dict[str, Any],
    shards: list[list[dict[str, Any]]],
) -> Path:
    """Hand-build a sharded checklist layout under *out_dir*."""
    shard_dir = out_dir / "checklist"
    shard_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, files in enumerate(shards):
        name = f"shard-part-{i:02d}.json"
        content = (json.dumps({"files": files}, separators=(",", ":"))
                   + "\n").encode("utf-8")
        (shard_dir / name).write_bytes(content)
        rows.append({
            "path": name,
            "file_count": len(files),
            "item_count": sum(
                len(f.get("items", [])) for f in files
                if isinstance(f, dict)),
            "sloc": sum(
                f.get("sloc", 0) for f in files if isinstance(f, dict)),
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    index = {
        "schema_version": 1,
        "meta": meta,
        "totals": {
            "files": sum(r["file_count"] for r in rows),
            "items": sum(r["item_count"] for r in rows),
            "sloc": sum(r["sloc"] for r in rows),
            "bytes": sum(r["bytes"] for r in rows),
        },
        "shards": rows,
    }
    (shard_dir / "index.json").write_text(json.dumps(index, indent=2))
    return shard_dir


class TestShardedRead(unittest.TestCase):

    def test_merges_shards_into_single_dict(self):
        with TemporaryDirectory() as d:
            meta = {"target_path": "/x", "total_files": 3, "summary": {}}
            s1 = [_entry("a/one.c", ["f1", "f2"])]
            s2 = [_entry("b/two.c", ["g1"]), _entry("b/three.c", ["h1"])]
            write_sharded(Path(d), meta, [s1, s2])

            loaded = read_checklist(d)
            self.assertEqual(loaded["target_path"], "/x")
            self.assertEqual(
                [f["path"] for f in loaded["files"]],
                ["a/one.c", "b/two.c", "b/three.c"],
            )

    def test_index_presence_is_the_discriminator(self):
        # A stale single-file beside a sharded dir must lose: the
        # index IS the discriminator.
        with TemporaryDirectory() as d:
            (Path(d) / "checklist.json").write_text(
                json.dumps({"target_path": "/stale", "files": []}))
            write_sharded(
                Path(d), {"target_path": "/fresh"},
                [[_entry("a.c", ["f"])]],
            )
            self.assertEqual(read_checklist(d)["target_path"], "/fresh")

    def test_single_file_form_stays_valid(self):
        with TemporaryDirectory() as d:
            (Path(d) / "checklist.json").write_text(
                json.dumps({"target_path": "/t", "files": []}))
            self.assertEqual(read_checklist(d)["target_path"], "/t")

    def test_reads_through_dangling_project_symlink(self):
        # Project slot went sharded (no project checklist.json); the
        # run dir's historical symlink dangles — reads through the run
        # dir must still find the project's sharded inventory.
        with TemporaryDirectory() as d:
            project = Path(d) / "proj"
            run = project / "run-001"
            run.mkdir(parents=True)
            write_sharded(project, {"v": "proj"}, [[_entry("a.c", ["f"])]])
            (run / "checklist.json").symlink_to("../checklist.json")
            self.assertEqual(read_checklist(run)["v"], "proj")
            self.assertTrue(checklist_exists(run))

    def test_missing_slot_reads_empty_without_side_effects(self):
        with TemporaryDirectory() as d:
            missing = Path(d) / "never"
            self.assertEqual(read_checklist(missing), {})
            self.assertFalse(missing.exists())
            self.assertFalse(checklist_exists(missing))


class TestIntegrityContract(unittest.TestCase):

    def _sharded(self, d: str) -> Path:
        return write_sharded(
            Path(d), {"target_path": "/t"},
            [[_entry("a.c", ["f"])], [_entry("b.c", ["g"])]],
        )

    def _index(self, shard_dir: Path) -> dict:
        return json.loads((shard_dir / "index.json").read_text())

    def _rewrite_index(self, shard_dir: Path, index: dict) -> None:
        (shard_dir / "index.json").write_text(json.dumps(index))

    def test_sha256_mismatch_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            victim = shard_dir / index["shards"][0]["path"]
            data = victim.read_bytes().replace(b'"a.c"', b'"z.c"')
            victim.write_bytes(data)
            self.assertEqual(read_checklist(d), {})

    def test_size_mismatch_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            victim = shard_dir / index["shards"][0]["path"]
            victim.write_bytes(victim.read_bytes() + b" ")
            self.assertEqual(read_checklist(d), {})

    def test_shard_path_with_separator_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            index["shards"][0]["path"] = "../shard-escape.json"
            self._rewrite_index(shard_dir, index)
            self.assertEqual(read_checklist(d), {})

    def test_shard_path_traversal_spelling_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            for hostile in ("..", "/etc/passwd", "shard-a/../b.json",
                            "shard-a\\b.json"):
                index["shards"][0]["path"] = hostile
                self._rewrite_index(shard_dir, index)
                self.assertEqual(read_checklist(d), {}, hostile)

    def test_unknown_schema_version_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            index["schema_version"] = 99
            self._rewrite_index(shard_dir, index)
            self.assertEqual(read_checklist(d), {})

    def test_duplicate_shard_path_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            index["shards"][1] = dict(index["shards"][0])
            self._rewrite_index(shard_dir, index)
            self.assertEqual(read_checklist(d), {})

    def test_symlink_shard_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            victim = shard_dir / index["shards"][0]["path"]
            real = shard_dir / "elsewhere.bin"
            real.write_bytes(victim.read_bytes())
            victim.unlink()
            victim.symlink_to(real.name)
            self.assertEqual(read_checklist(d), {})

    def test_missing_shard_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            (shard_dir / index["shards"][1]["path"]).unlink()
            self.assertEqual(read_checklist(d), {})

    def test_declared_bytes_over_shard_budget_refused(self):
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            index["shards"][0]["bytes"] = inv._MAX_CHECKLIST_SHARD_BYTES + 1
            self._rewrite_index(shard_dir, index)
            self.assertEqual(read_checklist(d), {})

    def test_update_checklist_refuses_forged_shards(self):
        from core.inventory import update_checklist
        with TemporaryDirectory() as d:
            shard_dir = self._sharded(d)
            index = self._index(shard_dir)
            victim = shard_dir / index["shards"][0]["path"]
            victim.write_bytes(victim.read_bytes() + b" ")
            with self.assertRaises(ValueError):
                update_checklist(d, lambda c: c)
            # The forged layout is untouched — never replaced with a
            # near-empty rebuild.
            self.assertTrue((shard_dir / "index.json").is_file())


class TestStreamingIterator(unittest.TestCase):

    def test_dict_input_unchanged(self):
        checklist = {"files": [_entry("a.c", ["f", "g"])]}
        rows = list(iter_checklist_items(checklist))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "a.c")

    def test_dir_input_streams_sharded(self):
        with TemporaryDirectory() as d:
            write_sharded(
                Path(d), {"target_path": "/t"},
                [[_entry("a.c", ["f1", "f2"])], [_entry("b.c", ["g1"])]],
            )
            rows = list(iter_checklist_items(d))
            self.assertEqual(
                [(fp, item["name"]) for fp, _, item in rows],
                [("a.c", "f1"), ("a.c", "f2"), ("b.c", "g1")],
            )

    def test_dir_input_single_file(self):
        with TemporaryDirectory() as d:
            (Path(d) / "checklist.json").write_text(json.dumps(
                {"files": [_entry("a.c", ["f"])]}))
            rows = list(iter_checklist_items(Path(d)))
            self.assertEqual(len(rows), 1)

    def test_dir_input_matches_read_checklist_walk(self):
        with TemporaryDirectory() as d:
            write_sharded(
                Path(d), {"target_path": "/t"},
                [[_entry("a.c", ["f"]), _entry("b.c", ["g"])],
                 [_entry("c.c", ["h"])]],
            )
            streamed = [
                (fp, item["name"])
                for fp, _, item in iter_checklist_items(d)
            ]
            merged = [
                (fp, item["name"])
                for fp, _, item in iter_checklist_items(read_checklist(d))
            ]
            self.assertEqual(streamed, merged)

    def test_missing_dir_yields_nothing(self):
        with TemporaryDirectory() as d:
            self.assertEqual(list(iter_checklist_items(Path(d) / "no")), [])

    def test_tampered_shard_truncates_walk(self):
        with TemporaryDirectory() as d:
            shard_dir = write_sharded(
                Path(d), {"target_path": "/t"},
                [[_entry("a.c", ["f"])], [_entry("b.c", ["g"])]],
            )
            index = json.loads((shard_dir / "index.json").read_text())
            victim = shard_dir / index["shards"][1]["path"]
            victim.write_bytes(victim.read_bytes() + b" ")
            rows = list(iter_checklist_items(d))
            # First shard already yielded; the forged second truncates.
            self.assertEqual([item["name"] for _, _, item in rows], ["f"])


class TestChecklistMeta(unittest.TestCase):

    def test_sharded_meta_reads_index_only(self):
        with TemporaryDirectory() as d:
            shard_dir = write_sharded(
                Path(d), {"target_path": "/t", "target_kind": "library"},
                [[_entry("a.c", ["f"])]],
            )
            # Prove the shard files are NOT read: replace them with
            # garbage — meta must still load from the index alone.
            index = json.loads((shard_dir / "index.json").read_text())
            for row in index["shards"]:
                (shard_dir / row["path"]).write_bytes(b"garbage")
            meta = read_checklist_meta(d)
            self.assertEqual(meta["target_path"], "/t")
            self.assertEqual(meta["target_kind"], "library")
            self.assertNotIn("files", meta)

    def test_single_file_meta_strips_files(self):
        with TemporaryDirectory() as d:
            (Path(d) / "checklist.json").write_text(json.dumps(
                {"target_path": "/t", "files": [_entry("a.c", ["f"])]}))
            meta = read_checklist_meta(d)
            self.assertEqual(meta["target_path"], "/t")
            self.assertNotIn("files", meta)

    def test_missing_meta_empty(self):
        with TemporaryDirectory() as d:
            self.assertEqual(read_checklist_meta(Path(d) / "no"), {})


class TestShardedWriter(unittest.TestCase):
    """The real writer's switch-over, packing, and swap semantics."""

    def _tiny(self, name: str, value: int) -> None:
        real = getattr(inv, name)
        setattr(inv, name, value)
        self.addCleanup(setattr, inv, name, real)

    def _big_checklist(self) -> dict[str, Any]:
        files = []
        for d in ("drivers/gpu", "drivers/net", "fs", "mm"):
            for i in range(6):
                files.append(_entry(f"{d}/file{i}.c", [f"fn_{d}_{i}"]))
        return {"target_path": "/t", "total_files": len(files),
                "files": files}

    def test_roundtrip_through_real_writer(self):
        from core.inventory import save_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 512)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 1024)
        with TemporaryDirectory() as d:
            data = self._big_checklist()
            save_checklist(d, data)
            index_path = Path(d) / "checklist" / "index.json"
            self.assertTrue(index_path.is_file())
            self.assertFalse((Path(d) / "checklist.json").exists())
            index = json.loads(index_path.read_text())
            self.assertGreater(len(index["shards"]), 1)
            # Every shard within the packing target (indivisible
            # single entries excepted — none here).
            for row in index["shards"]:
                self.assertLessEqual(row["bytes"], 1024 + 64, row)
            loaded = read_checklist(d)
            self.assertEqual(loaded["target_path"], "/t")
            self.assertEqual(
                sorted(f["path"] for f in loaded["files"]),
                sorted(f["path"] for f in data["files"]),
            )
            # Totals reconcile with the data.
            self.assertEqual(
                index["totals"]["files"], len(data["files"]))
            self.assertEqual(
                index["totals"]["items"],
                sum(len(f["items"]) for f in data["files"]))

    def test_switch_back_to_single_file(self):
        from core.inventory import save_checklist, update_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 512)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 1024)
        with TemporaryDirectory() as d:
            save_checklist(d, self._big_checklist())
            self.assertTrue(
                (Path(d) / "checklist" / "index.json").is_file())
            update_checklist(d, lambda c: {"files": []})
            self.assertTrue((Path(d) / "checklist.json").is_file())
            # The retired sharded dir must not shadow the fresh file.
            self.assertFalse(
                (Path(d) / "checklist" / "index.json").exists())
            self.assertEqual(read_checklist(d)["files"], [])

    def test_update_transform_over_sharded_artifact(self):
        from core.inventory import save_checklist, update_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 512)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 1024)
        with TemporaryDirectory() as d:
            save_checklist(d, self._big_checklist())

            def mark(checklist):
                for f in checklist["files"]:
                    f["marked"] = True
                return checklist

            update_checklist(d, mark)
            loaded = read_checklist(d)
            self.assertTrue(all(f["marked"] for f in loaded["files"]))

    def test_degenerate_flat_directory_hash_splits(self):
        from core.inventory import save_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 256)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 600)
        with TemporaryDirectory() as d:
            files = [_entry(f"flat/f{i}.c", [f"fn{i}"]) for i in range(12)]
            save_checklist(d, {"files": files})
            index = json.loads(
                (Path(d) / "checklist" / "index.json").read_text())
            self.assertGreater(len(index["shards"]), 1)
            loaded = read_checklist(d)
            self.assertEqual(len(loaded["files"]), 12)

    def test_write_is_deterministic(self):
        from core.inventory import save_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 512)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 1024)
        with TemporaryDirectory() as d1, TemporaryDirectory() as d2:
            data = self._big_checklist()
            save_checklist(d1, json.loads(json.dumps(data)))
            save_checklist(d2, json.loads(json.dumps(data)))
            i1 = json.loads(
                (Path(d1) / "checklist" / "index.json").read_text())
            i2 = json.loads(
                (Path(d2) / "checklist" / "index.json").read_text())
            self.assertEqual(
                [(r["path"], r["sha256"]) for r in i1["shards"]],
                [(r["path"], r["sha256"]) for r in i2["shards"]],
            )

    def test_reshard_replaces_previous_layout_atomically(self):
        from core.inventory import save_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 512)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 1024)
        with TemporaryDirectory() as d:
            save_checklist(d, self._big_checklist())
            smaller = {"target_path": "/t2",
                       "files": [_entry(f"a/f{i}.c", ["fn"])
                                 for i in range(20)]}
            save_checklist(d, smaller)
            loaded = read_checklist(d)
            self.assertEqual(loaded["target_path"], "/t2")
            self.assertEqual(len(loaded["files"]), 20)
            # No leftover swap dirs.
            leftovers = [p.name for p in Path(d).iterdir()
                         if p.name.startswith(".checklist-")]
            self.assertEqual(leftovers, [])

    def test_shard_names_pass_reader_validation(self):
        from core.inventory import _CHECKLIST_SHARD_NAME_RE, save_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 256)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 600)
        with TemporaryDirectory() as d:
            files = [_entry("weird dir/UPPER-case_x/f.c", ["fn"]),
                     _entry("ünïcode/f.c", ["fn"]),
                     _entry("f-at-root.c", ["fn"])]
            files += [_entry(f"deep/n{i}/f.c", [f"fn{i}"])
                      for i in range(8)]
            save_checklist(d, {"files": files})
            index = json.loads(
                (Path(d) / "checklist" / "index.json").read_text())
            for row in index["shards"]:
                self.assertRegex(row["path"],
                                 _CHECKLIST_SHARD_NAME_RE.pattern)
            self.assertEqual(len(read_checklist(d)["files"]), len(files))

    def test_streaming_iterator_over_written_layout(self):
        from core.inventory import save_checklist
        self._tiny("_MAX_CHECKLIST_BYTES", 512)
        self._tiny("_CHECKLIST_SHARD_TARGET_BYTES", 1024)
        with TemporaryDirectory() as d:
            data = self._big_checklist()
            save_checklist(d, data)
            names = sorted(
                item["name"] for _, _, item in iter_checklist_items(d))
            expected = sorted(
                item["name"]
                for _, _, item in iter_checklist_items(data))
            self.assertEqual(names, expected)


if __name__ == "__main__":
    unittest.main()


class TestReadSideEffectFree:
    """Pure reads must not create the lock file: O_CREAT in the run
    dir bumps the directory mtime, and mtime consumers (the
    understand bridge's newest-candidate ranking) read every READ as
    recency. Writers keep the creating lock; a reader with no lock
    file present goes lockless (pre-accessor exposure, safe
    direction), and a reader WITH a writer-created lock still
    contends."""

    def test_pure_read_never_bumps_dir_mtime(self, tmp_path):
        import json
        import os
        from core.inventory import read_checklist
        (tmp_path / "checklist.json").write_text(
            json.dumps({"files": [], "target_path": "/t"}))
        os.utime(tmp_path, (1e9, 1e9))
        assert read_checklist(tmp_path).get("target_path") == "/t"
        assert tmp_path.stat().st_mtime == 1e9
        assert not (tmp_path / "checklist.lock").exists()

    def test_meta_and_iter_reads_are_side_effect_free(self, tmp_path):
        import json
        import os
        from core.inventory import (
            iter_checklist_items,
            read_checklist_meta,
        )
        (tmp_path / "checklist.json").write_text(
            json.dumps({"files": [{"path": "a.c", "items": []}],
                        "target_path": "/t"}))
        os.utime(tmp_path, (1e9, 1e9))
        read_checklist_meta(tmp_path)
        list(iter_checklist_items(tmp_path))
        assert tmp_path.stat().st_mtime == 1e9
        assert not (tmp_path / "checklist.lock").exists()

    def test_reader_still_locks_when_writer_lock_exists(self, tmp_path):
        import fcntl
        import threading
        import time as _time
        from core.inventory import read_checklist, save_checklist
        save_checklist(tmp_path, {"files": [], "target_path": "/t"})
        lock = tmp_path / "checklist.lock"
        assert lock.exists()  # writer created it
        held = open(lock, "w")
        fcntl.flock(held, fcntl.LOCK_EX)
        got: list = []
        t = threading.Thread(
            target=lambda: got.append(read_checklist(tmp_path)))
        t.start()
        _time.sleep(0.2)
        assert not got  # reader is blocked on the writer's lock
        fcntl.flock(held, fcntl.LOCK_UN)
        held.close()
        t.join(timeout=10)
        assert got and got[0].get("target_path") == "/t"
