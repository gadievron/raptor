"""Tests for the per-model checkpoint store (/understand resume)."""

from __future__ import annotations

import json

import pytest

from core.run.resume import hash_whole_file, spend_floor_usd
from packages.code_understanding.checkpoint import (
    CHECKPOINT_DIRNAME,
    RUN_CONFIG_FILENAME,
    CheckpointStore,
    load_understand_run_config,
    save_understand_run_config,
    task_fingerprint,
    traces_task_key,
)


@pytest.fixture
def target(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "x.c").write_text("void f(char *p) {}\n")
    return repo


@pytest.fixture
def out_dir(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    return out


def _store(out_dir, target, *, mode="hunt", key="strcpy misuse"):
    return CheckpointStore(
        out_dir, mode=mode,
        fingerprint=task_fingerprint(mode, key, target),
        target=target,
    )


class TestRoundTrip:
    def test_save_then_load(self, out_dir, target):
        store = _store(out_dir, target)
        items = [{"file": "src/x.c", "line": 1, "function": "f"}]
        store.save("model-a", items, cost_usd=1.25)
        ckpt = store.load("model-a")
        assert ckpt is not None
        assert ckpt.items == items
        assert ckpt.cost_usd == 1.25
        assert ckpt.file_hashes == {
            "src/x.c": hash_whole_file(target / "src" / "x.c"),
        }

    def test_absolute_item_path_relativised(self, out_dir, target):
        store = _store(out_dir, target)
        store.save("model-a", [
            {"file": str(target / "src" / "x.c"), "line": 1},
        ], cost_usd=0.0)
        ckpt = store.load("model-a")
        assert "src/x.c" in ckpt.file_hashes

    def test_missing_model_returns_none(self, out_dir, target):
        assert _store(out_dir, target).load("model-a") is None

    def test_load_all_partitions_models(self, out_dir, target):
        store = _store(out_dir, target)
        store.save("model-a", [], cost_usd=0.5)
        found = store.load_all(["model-a", "model-b"])
        assert sorted(found) == ["model-a"]


class TestValidation:
    def test_foreign_fingerprint_rejected(self, out_dir, target):
        _store(out_dir, target, key="pattern one").save(
            "model-a", [], cost_usd=1.0,
        )
        other = _store(out_dir, target, key="pattern two")
        assert other.load("model-a") is None

    def test_foreign_mode_rejected(self, out_dir, target):
        # Same task key, different mode → different fingerprint AND
        # a mode mismatch; either alone must refuse.
        _store(out_dir, target, mode="hunt").save(
            "model-a", [], cost_usd=1.0,
        )
        assert _store(out_dir, target, mode="trace").load("model-a") is None

    def test_corrupt_checkpoint_rejected(self, out_dir, target):
        store = _store(out_dir, target)
        store.save("model-a", [], cost_usd=1.0)
        ckpt_dir = out_dir / CHECKPOINT_DIRNAME
        [path] = list(ckpt_dir.glob("*.json"))
        path.write_text("{broken")
        assert store.load("model-a") is None

    def test_non_dict_items_rejected(self, out_dir, target):
        store = _store(out_dir, target)
        store.save("model-a", [], cost_usd=0.0)
        [path] = list((out_dir / CHECKPOINT_DIRNAME).glob("*.json"))
        data = json.loads(path.read_text())
        data["items"] = ["not-a-dict"]
        path.write_text(json.dumps(data))
        assert store.load("model-a") is None

    def test_hostile_cost_clamped(self, out_dir, target):
        store = _store(out_dir, target)
        store.save("model-a", [], cost_usd=0.0)
        [path] = list((out_dir / CHECKPOINT_DIRNAME).glob("*.json"))
        data = json.loads(path.read_text())
        data["cost_usd"] = -5.0
        path.write_text(json.dumps(data))
        assert store.load("model-a").cost_usd == 0.0

    def test_model_name_collision_safe(self, out_dir, target):
        """Sanitised slugs can collide; the digest suffix must not."""
        store = _store(out_dir, target)
        store.save("a/b", [{"file": "src/x.c"}], cost_usd=1.0)
        store.save("a:b", [], cost_usd=2.0)
        assert store.load("a/b").cost_usd == 1.0
        assert store.load("a:b").cost_usd == 2.0


class TestDriftRecords:
    def test_records_cover_checkpointed_files(self, out_dir, target):
        store = _store(out_dir, target)
        store.save("model-a", [{"file": "src/x.c"}], cost_usd=0.0)
        ckpts = store.load_all(["model-a"])
        records = store.drift_records(ckpts)
        assert [(r.file, r.label) for r in records] == [
            ("src/x.c", "model-a"),
        ]
        assert records[0].stored_hash
        assert records[0].line_start is None  # whole-file evidence

    def test_unresolvable_file_carries_no_evidence(self, out_dir, target):
        store = _store(out_dir, target)
        store.save("model-a", [{"file": "../escape.c"}], cost_usd=0.0)
        ckpts = store.load_all(["model-a"])
        # The escaping path was refused at hash time (no record) —
        # never resolved outside the target.
        assert store.drift_records(ckpts) == []


class TestSpendFloor:
    def test_bump_is_monotonic(self, out_dir, target):
        store = _store(out_dir, target)
        store.set_segment(2)
        store.bump_spend_floor(3.0)
        store.bump_spend_floor(1.0)
        assert spend_floor_usd(out_dir) == 3.0


class TestRunConfigPin:
    def test_round_trip(self, out_dir):
        cfg = {"version": 1, "mode": "hunt", "pattern": "x",
               "models": ["a"]}
        path = save_understand_run_config(out_dir, cfg)
        assert path.name == RUN_CONFIG_FILENAME
        assert load_understand_run_config(out_dir) == cfg


class TestTaskIdentity:
    def test_traces_key_order_insensitive_keys(self):
        a = traces_task_key([{"trace_id": "t1", "entry": "main"}])
        b = traces_task_key([{"entry": "main", "trace_id": "t1"}])
        assert a == b

    def test_traces_key_content_sensitive(self):
        a = traces_task_key([{"trace_id": "t1"}])
        b = traces_task_key([{"trace_id": "t2"}])
        assert a != b

    def test_fingerprint_binds_mode_key_target(self, tmp_path):
        t1 = tmp_path / "one"
        t2 = tmp_path / "two"
        t1.mkdir()
        t2.mkdir()
        base = task_fingerprint("hunt", "k", t1)
        assert task_fingerprint("trace", "k", t1) != base
        assert task_fingerprint("hunt", "k2", t1) != base
        assert task_fingerprint("hunt", "k", t2) != base
