"""Cross-process serialisation of canonical study-artifact promotion.

The canonical ``<project>/concepts/domain-model.json`` (and
``patterns.json``) is a load → merge → write window shared by every
concurrent run of a project. These tests pin:

- the live multi-process race: N workers each repeatedly merge one
  unique concept; every worker's contribution must survive (the
  pre-lock promoter permanently dropped a run's whole study output);
- the merge semantics for two runs studying the SAME concept id:
  last promoter wins per ID, deterministically;
- promotion refuses unavailable locks instead of writing unlocked.
"""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
from pathlib import Path

import pytest

from core.testing.processes import reap_on_exit

REPO_ROOT = Path(__file__).resolve().parents[3]
_race_barrier = None


def _init_race_worker(barrier) -> None:
    # Set only in owned pool children; no parent/pytest-worker state changes.
    global _race_barrier
    _race_barrier = barrier


def _race_worker(args: tuple[int, str, str]) -> int:
    idx, canonical, td = args
    from core.concepts.model import Concept, DomainModel
    from core.concepts.study import merge_promote_domain_model

    run_model = Path(td) / f"run{idx}.json"
    DomainModel(
        target="t", source_root="s",
        concepts=[Concept(id=f"concept_{idx:03d}",
                          description=f"from run {idx}")],
    ).save(run_model)
    assert _race_barrier is not None
    _race_barrier.wait(timeout=30)
    for _ in range(20):
        merge_promote_domain_model(run_model, Path(canonical))
    return idx


@pytest.mark.slow
@pytest.mark.skipif(sys.platform == "win32", reason="fork start method")
def test_concurrent_promoters_lose_no_runs_output(tmp_path: Path) -> None:
    """8 racing processes × 20 promotes each, 6 trials: every worker's
    concept survives every trial. The pre-lock promoter lost a run's
    whole contribution in about half the trials under this load."""
    import multiprocessing as mp

    n = 8
    ctx = mp.get_context("fork")
    # Imports and process startup are incidental to promotion. Reuse the
    # workers, but give every trial fresh inputs/canonical state and align
    # all eight workers before the first promotion so each trial still races.
    with ctx.Pool(n, initializer=_init_race_worker,
                  initargs=(ctx.Barrier(n),)) as pool:
        for trial in range(6):
            canonical = tmp_path / f"t{trial}" / "domain-model.json"
            canonical.parent.mkdir(parents=True)
            completed = pool.map(
                _race_worker,
                [(i, str(canonical), str(canonical.parent))
                 for i in range(n)],
            )
            assert completed == list(range(n))
            data = json.loads(canonical.read_text())
            ids = sorted(c["id"] for c in data.get("concepts", []))
            missing = [f"concept_{i:03d}" for i in range(n)
                       if f"concept_{i:03d}" not in ids]
            assert not missing, (
                f"trial {trial}: lost updates {missing} (survivors: {ids})"
            )


def test_promoter_blocks_while_lock_held(tmp_path: Path) -> None:
    """Deterministic lock contract: with the sibling .lock flocked by
    another process, the promoter must not write until release."""
    fcntl = pytest.importorskip("fcntl")

    canonical = tmp_path / "domain-model.json"
    lock_path = tmp_path / "domain-model.json.lock"

    worker = tmp_path / "worker.py"
    worker.write_text(
        "import logging, sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from pathlib import Path\n"
        "from core.concepts.model import Concept, DomainModel\n"
        "from core.concepts.study import merge_promote_domain_model\n"
        f"base = Path({str(tmp_path)!r})\n"
        "run = base / 'run.json'\n"
        "DomainModel(target='t', source_root='s',\n"
        "            concepts=[Concept(id='c1', description='d')]"
        ").save(run)\n"
        "class ContentionSignal(logging.Handler):\n"
        "    def emit(self, record):\n"
        "        if 'held by another process' in record.getMessage():\n"
        "            print('CONTENDED', flush=True)\n"
        "handler = ContentionSignal()\n"
        "logger = logging.getLogger('core.atomic_fs.fs_lock')\n"
        "logger.addHandler(handler)\n"
        "logger.setLevel(logging.WARNING)\n"
        "merge_promote_domain_model(run, base / 'domain-model.json')\n"
        "print('DONE', flush=True)\n",
    )

    fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        home = tmp_path / "home"
        home.mkdir()
        env = dict(
            os.environ, PYTHONDONTWRITEBYTECODE="1", HOME=str(home),
            TMPDIR=str(tmp_path), XDG_CONFIG_HOME=str(home / "config"),
            XDG_CACHE_HOME=str(home / "cache"),
            XDG_DATA_HOME=str(home / "data"),
            RAPTOR_REGISTRY_HOME=str(tmp_path / "registry"),
            RAPTOR_OUT_DIR=str(tmp_path / "out"),
        )
        with reap_on_exit(subprocess.Popen(
            [sys.executable, str(worker)], env=env, cwd=str(tmp_path),
            stdout=subprocess.PIPE,
        )) as proc:
            try:
                # The real lock emits this only after a failed flock attempt.
                # An unlocked promoter reports DONE instead and fails promptly.
                with selectors.DefaultSelector() as ready:
                    ready.register(proc.stdout, selectors.EVENT_READ)
                    assert ready.select(timeout=30), "worker never reported contention"
                    message = os.read(proc.stdout.fileno(), 64)
                assert message == b"CONTENDED\n", (
                    f"promoter did not contend on the held lock: {message!r}"
                )
                assert not canonical.exists(), (
                    "promoter wrote the canonical model while another "
                    "process held the promotion lock"
                )
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
            assert proc.wait(timeout=60) == 0
            assert canonical.is_file()
    finally:
        os.close(fd)


def test_same_concept_last_promoter_wins_per_id(tmp_path: Path) -> None:
    """Two runs studying the SAME concept id: the later promoter's
    version replaces the earlier one wholesale — deterministic under
    the lock (promotions serialise, so 'later' is well-defined)."""
    from core.concepts.model import Concept, DomainModel
    from core.concepts.study import merge_promote_domain_model

    canonical = tmp_path / "domain-model.json"

    run_a = tmp_path / "a.json"
    DomainModel(target="t", source_root="s", concepts=[
        Concept(id="shared_concept", description="first, observed",
                confidence="observed"),
    ]).save(run_a)
    run_b = tmp_path / "b.json"
    DomainModel(target="t", source_root="s", concepts=[
        Concept(id="shared_concept", description="second, inferred",
                confidence="inferred"),
        Concept(id="only_b", description="b's own"),
    ]).save(run_b)

    merge_promote_domain_model(run_a, canonical)
    merge_promote_domain_model(run_b, canonical)

    data = json.loads(canonical.read_text())
    by_id = {c["id"]: c for c in data["concepts"]}
    assert set(by_id) == {"shared_concept", "only_b"}
    # New-run-wins-on-ID-collision: B's version, even at a weaker
    # confidence — replacement, not field-wise upgrade.
    assert by_id["shared_concept"]["description"] == "second, inferred"
    assert by_id["shared_concept"]["confidence"] == "inferred"


def test_promotion_creates_lock_sibling(tmp_path: Path) -> None:
    """The locked path is actually taken: the .lock sibling appears."""
    from core.concepts.model import Concept, DomainModel
    from core.concepts.study import merge_promote_domain_model

    canonical = tmp_path / "domain-model.json"
    run = tmp_path / "run.json"
    DomainModel(target="t", source_root="s",
                concepts=[Concept(id="c1", description="d")]).save(run)
    merge_promote_domain_model(run, canonical)
    assert canonical.is_file()
    assert (tmp_path / "domain-model.json.lock").is_file()


def test_lock_refusal_preserves_canonical(tmp_path, caplog) -> None:
    """An unavailable lock must refuse destructive unlocked promotion."""
    import logging

    from core.concepts.model import Concept, DomainModel
    from core.concepts.study import merge_promote_domain_model

    canonical = tmp_path / "domain-model.json"
    lock = tmp_path / "domain-model.json.lock"
    lock.symlink_to(tmp_path / "elsewhere")
    run = tmp_path / "run.json"
    DomainModel(target="t", source_root="s",
                concepts=[Concept(id="c1", description="d")]).save(run)
    with caplog.at_level(logging.WARNING, logger="core.concepts.study"):
        with pytest.raises(OSError):
            merge_promote_domain_model(run, canonical)
    assert not canonical.exists()


def test_patterns_promotion_takes_the_lock(tmp_path: Path) -> None:
    """merge_promote_patterns shares the promotion-lock discipline."""
    from core.json import save_json

    from core.concepts.study import merge_promote_patterns

    src = tmp_path / "run-patterns.json"
    canonical = tmp_path / "patterns.json"
    save_json(src, {"patterns": {"p1": {"description": "x"}}})
    merge_promote_patterns(src, canonical)
    save_json(src, {"patterns": {"p2": {"description": "y"}}})
    merge_promote_patterns(src, canonical)

    assert (tmp_path / "patterns.json.lock").is_file()
    data = json.loads(canonical.read_text())
    assert set(data["patterns"]) == {"p1", "p2"}
