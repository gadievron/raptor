"""Build-once cache for checklist-CLI corpora shared across audit tests.

Many audit tests need a real ``checklist.json`` built by the libexec
CLI over a tiny synthetic corpus. The build is deterministic for a
given corpus content (canonical-hash verified: two builds of the same
corpus at different roots produce identical inventories once the
``generated_at`` / ``target_path`` / ``_stat`` / frame-token fields
are stripped), so re-running the CLI in a fresh interpreter for every
test or module that starts from the same corpus only re-pays the CLI
startup and inventory-walk cost.

The session-scoped ``checklist_builds`` fixture (conftest.py) exposes
:class:`ChecklistBuildCache`: each DISTINCT corpus builds once per
pytest process (per xdist worker) and is shared from then on. Corpora
that differ in any byte hash to different keys and never share.

Sharing discipline:

* The shared target tree and built run dir are made read-only on
  disk after the build. A consumer that mutates either fails loudly
  (``PermissionError``) instead of silently poisoning every other
  consumer of the same corpus. Tests that need to mutate the corpus
  (e.g. adding a source file before building) keep their own private
  build.
* Consumers get a copy-on-write run dir via
  :meth:`SharedChecklistBuild.make_run_dir` — a private writable copy
  of the built artifacts for the audit stages to write into. The
  checklist frame is HMAC-stamped and slot-bound
  (``core.inventory.checklist_frame_mac``), so the copy is re-stamped
  for its new slot under the CURRENT test's key: consumers see
  exactly the verified-tier frame a fresh in-test build would earn
  (the per-test ``XDG_DATA_HOME`` isolation rotates the key between
  tests, so the shared build's original stamp could never verify).
* The shared TARGET path is handed out as-is: the checklist embeds
  the absolute target path it was built over, so consumers must pass
  ``SharedChecklistBuild.target`` (never a copy) as the target.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")


def set_tree_writable(root: Path, writable: bool) -> None:
    """Add or drop write permission on every dir/file under ``root``.

    Dropping makes accidental mutation of a shared tree fail loudly;
    adding restores normal cleanup semantics (session teardown, and
    the writable copies handed to consumers, whose ``copytree`` would
    otherwise inherit the read-only modes).
    """
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames:
            _set_writable(Path(dirpath) / name, writable)
        _set_writable(Path(dirpath), writable)


def _set_writable(path: Path, writable: bool) -> None:
    mode = path.stat().st_mode
    if writable:
        path.chmod(mode | stat.S_IWUSR)
    else:
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


@dataclass(frozen=True)
class SharedChecklistBuild:
    """One immutable checklist-CLI build, shared within a process.

    ``target`` is the tree the checklist was built over — read-only,
    handed to consumers directly (the checklist embeds this absolute
    path). ``built_out`` is the CLI's run dir — read-only, a copy
    source only: consumers write into :meth:`make_run_dir` copies.
    """

    target: Path
    built_out: Path

    def make_run_dir(self, dest: Path) -> Path:
        """Materialise a private writable copy of the built run dir.

        The frame token is re-minted for the new slot and the current
        key (the shared build's stamp is slot- and key-bound, so a
        plain copy would demote to the relocated/unstamped tier). The
        checklist is read with plain ``json`` — this process built it,
        so there is nothing to authenticate — and re-written through
        ``save_checklist``, the same stamping chokepoint a fresh
        build's writer uses.
        """
        shutil.copytree(self.built_out, dest)
        set_tree_writable(dest, True)
        from core.inventory import save_checklist
        from core.inventory.checklist_frame_mac import FRAME_TOKEN_KEY

        doc = json.loads((dest / "checklist.json").read_text())
        doc.pop(FRAME_TOKEN_KEY, None)
        save_checklist(dest, doc)
        return dest


class ChecklistBuildCache:
    """Builds each distinct corpus once and shares the result.

    Keyed by the corpus content (relative path + bytes of every
    file), so only byte-identical corpora ever share a build.
    """

    def __init__(self, mktemp: Callable[[str], Path]) -> None:
        self._mktemp = mktemp
        self._builds: dict[str, SharedChecklistBuild] = {}

    def build(self, corpus: Mapping[str, str]) -> SharedChecklistBuild:
        """Return the shared build for ``corpus``, building on first use.

        ``corpus`` maps target-relative file paths to file contents.
        """
        key = hashlib.sha256(
            json.dumps(sorted(corpus.items())).encode(),
        ).hexdigest()
        cached = self._builds.get(key)
        if cached is not None:
            return cached

        root = self._mktemp(f"shared-checklist-{key[:12]}")
        target = root / "target"
        out = root / "out"
        target.mkdir()
        out.mkdir()
        for rel, content in corpus.items():
            path = target / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        env = dict(
            os.environ,
            CLAUDECODE="1",
            _RAPTOR_TRUSTED="1",
            PYTHONPATH=str(_RAPTOR_DIR),
        )
        r = subprocess.run(
            [sys.executable, _CHECKLIST_CLI, str(target), str(out)],
            env=env, capture_output=True, text=True, check=False,
        )
        assert r.returncode == 0, f"build-checklist failed: {r.stderr}"
        assert (out / "checklist.json").exists()

        set_tree_writable(target, False)
        set_tree_writable(out, False)
        build = SharedChecklistBuild(target=target, built_out=out)
        self._builds[key] = build
        return build

    def restore_writability(self) -> None:
        """Re-add write permission on every shared tree (teardown aid:
        read-only modes must never outlive the session into pytest's
        retained-tmp garbage collection)."""
        for build in self._builds.values():
            set_tree_writable(build.target, True)
            set_tree_writable(build.built_out, True)
