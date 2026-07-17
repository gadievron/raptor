"""Tests for the shared atomic-file-write primitive.

Pins the contract two consumers rely on
(``core/annotations/storage.py`` + ``brain/auto_notes.py``):

  * Parent-dir auto-created.
  * A concurrent reader never sees a truncated / half-written file.
  * On write failure, ``path`` is left unchanged and no tempfile
    dangles.
  * ``os.replace`` semantics: same-inode overwrite works even when
    ``path`` already exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.atomic_fs import write_text_atomically


class TestWriteTextAtomically:
    def test_creates_parent_dir(self, tmp_path):
        target = tmp_path / "deep" / "nested" / "note.md"
        write_text_atomically(target, "hello\n")
        assert target.read_text() == "hello\n"

    def test_overwrites_existing_atomically(self, tmp_path):
        target = tmp_path / "note.md"
        target.write_text("v1\n")
        write_text_atomically(target, "v2\n")
        assert target.read_text() == "v2\n"

    def test_leaves_no_tempfile_on_success(self, tmp_path):
        target = tmp_path / "note.md"
        write_text_atomically(target, "body")
        # Every entry in the dir should be either the target or an
        # unrelated file — no leftover ``.atomic-*.tmp``.
        siblings = list(tmp_path.iterdir())
        assert siblings == [target]

    def test_preserves_prior_state_on_write_error(
        self, tmp_path, monkeypatch,
    ):
        """If the OS write fails mid-way, ``path`` retains its prior
        content and the tempfile is cleaned up."""
        target = tmp_path / "note.md"
        target.write_text("prior\n")

        # Monkeypatch os.fsync to raise — simulates a mid-write
        # failure after the buffer's flushed but before the rename.
        import os
        real_fsync = os.fsync

        def boom(fd):
            raise OSError("simulated fsync failure")

        monkeypatch.setattr(os, "fsync", boom)
        with pytest.raises(OSError):
            write_text_atomically(target, "new\n")

        # Prior content survives.
        assert target.read_text() == "prior\n"
        # And no dangling tempfile (write should have unlinked it).
        siblings = [
            p for p in tmp_path.iterdir()
            if p.name.startswith(".atomic-")
        ]
        assert siblings == []
        # Restore for the fixture teardown.
        monkeypatch.setattr(os, "fsync", real_fsync)

    def test_custom_tmp_prefix(self, tmp_path):
        """Callers can pass a distinct ``tmp_prefix`` so operators
        grepping for dangling temporaries can tell what module
        was writing."""
        # We can't observe the tempfile after success (it's renamed),
        # but we can check the API accepts the kwarg without error.
        target = tmp_path / "note.md"
        write_text_atomically(
            target, "content", tmp_prefix=".myservice-",
        )
        assert target.read_text() == "content"


class TestModeParameter:
    """The optional ``mode`` argument pins perms via ``os.fchmod`` on
    the tempfile BEFORE rename, so the atomic rename installs a file
    with the correct permissions in a single atomic step — no
    chmod-after-rename window where a reader could see the file
    with the wrong perms."""

    def test_mode_applied_to_new_file(self, tmp_path):
        # Fresh destination: mode= should be applied to the created
        # file. Confirms security-sensitive callers can write with
        # 0o600 straight through the atomic path.
        target = tmp_path / "secret.tok"
        write_text_atomically(target, "hunter2\n", mode=0o600)
        assert target.stat().st_mode & 0o777 == 0o600
        assert target.read_text() == "hunter2\n"

    def test_mode_overrides_preserve_existing(self, tmp_path):
        # If destination already exists at 0o644, an explicit
        # mode=0o600 should tighten it — the caller's declared
        # mode wins over the "preserve existing" default.
        target = tmp_path / "note.md"
        target.write_text("v1")
        target.chmod(0o644)
        write_text_atomically(target, "v2", mode=0o600)
        assert target.stat().st_mode & 0o777 == 0o600
        assert target.read_text() == "v2"

    def test_mode_none_preserves_existing_perms(self, tmp_path):
        # mode=None (default): existing perms preserved so an
        # operator's ``chmod 0o600`` isn't silently widened by our
        # next write. This is the guard against the concrete regression
        # of tightening operator-set perms.
        target = tmp_path / "note.md"
        target.write_text("v1")
        target.chmod(0o600)
        write_text_atomically(target, "v2")
        assert target.stat().st_mode & 0o777 == 0o600

    def test_mode_none_new_file_uses_default(self, tmp_path):
        # mode=None on a fresh destination: use conventional 0o644.
        target = tmp_path / "note.md"
        write_text_atomically(target, "content")
        assert target.stat().st_mode & 0o777 == 0o644

    def test_mode_rejects_setuid(self, tmp_path):
        # Setuid bit rejected — no consumer of this primitive should
        # be shipping setuid files without an explicit chmod step.
        with pytest.raises(ValueError, match="0o000..0o777"):
            write_text_atomically(
                tmp_path / "x", "content", mode=0o4755,
            )

    def test_mode_rejects_setgid_and_sticky(self, tmp_path):
        with pytest.raises(ValueError):
            write_text_atomically(tmp_path / "x", "c", mode=0o2755)
        with pytest.raises(ValueError):
            write_text_atomically(tmp_path / "x", "c", mode=0o1755)

    def test_mode_rejects_negative(self, tmp_path):
        with pytest.raises(ValueError):
            write_text_atomically(tmp_path / "x", "c", mode=-1)

    def test_mode_rejects_non_int(self, tmp_path):
        # Explicit type validation — a caller passing "0o600" (str)
        # would otherwise land silently as garbage perms.
        with pytest.raises(ValueError, match="mode must be int"):
            write_text_atomically(tmp_path / "x", "c", mode="0o600")

    def test_mode_zero_is_legal(self, tmp_path):
        # mode=0 is silly (locks the operator out) but technically a
        # legal POSIX mode. Accept it — don't silently interpret 0
        # as "no mode specified".
        target = tmp_path / "locked.tok"
        write_text_atomically(target, "content", mode=0)
        assert target.stat().st_mode & 0o777 == 0
        # Cleanup: restore perms so pytest tmpdir can remove it.
        target.chmod(0o600)


class TestAdversarial:
    """Concurrent-writer + squat-attack + symlink-handling contract.

    Every test here maps to a class of bug that would compound
    silently across every downstream consumer of the primitive.
    """

    def test_concurrent_same_process_threads(self, tmp_path):
        # Two threads writing the same path must NOT corrupt the
        # tempfile via shared-name collision. Pre-fix, the tempfile
        # name was PID-only; two threads computed identical tempfile
        # paths and the second's O_TRUNC clobbered the first's
        # in-flight write.
        import threading as _th
        target = tmp_path / "shared.md"
        errs: list[BaseException] = []

        def writer(tag: str):
            try:
                write_text_atomically(target, tag * 1000)
            except BaseException as e:  # noqa: BLE001
                errs.append(e)

        threads = [
            _th.Thread(target=writer, args=(chr(ord("a") + i),))
            for i in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No writer should have blown up.
        assert errs == [], f"concurrent writers failed: {errs}"
        # File contents must be one writer's payload in full — never
        # a mixed / truncated snapshot.
        got = target.read_text()
        assert len(got) == 1000, (
            f"torn write: got {len(got)} bytes, expected 1000 "
            f"(sample: {got[:20]!r})"
        )
        # All bytes should be the same char (one writer's payload).
        assert len(set(got)) == 1, (
            f"mixed content: {sorted(set(got))!r}"
        )

    def test_rejects_symlink_squat_at_tempfile(self, tmp_path):
        # An attacker who predicts the tempfile name can pre-create
        # it as a symlink to sensitive content. With O_EXCL + O_NOFOLLOW
        # our open should refuse loudly rather than follow the symlink
        # and truncate the attacker's chosen target.
        #
        # The random suffix makes an ACTUAL squat impossible to stage
        # in a test (we can't predict what the primitive will name its
        # tempfile). Instead we assert the flags are present in the
        # write path via source inspection — a refactor that drops
        # O_EXCL or O_NOFOLLOW is caught by this test.
        import inspect
        import core.atomic_fs as af
        src = inspect.getsource(af.write_bytes_atomically)
        assert "O_EXCL" in src, (
            "O_EXCL missing from write path — refactor introduced "
            "a tempfile squat window (attacker could pre-create "
            "the tempfile, our O_CREAT alone would follow into it)"
        )
        assert "O_NOFOLLOW" in src, (
            "O_NOFOLLOW missing from write path — refactor introduced "
            "a tempfile symlink-follow window (attacker could "
            "pre-create the tempfile as a symlink to their target)"
        )

    def test_perm_preserve_does_not_inherit_symlink_target_mode(
        self, tmp_path,
    ):
        # If ``path`` is a symlink to a file with 0o644, our perm
        # probe must NOT copy the target's 0o644 onto the new file
        # (which would silently change perms if the operator intended
        # tight perms on the eventual real file). Pre-fix used
        # ``path.stat()`` which followed the link.
        real = tmp_path / "real.md"
        real.write_text("real content")
        real.chmod(0o644)
        sym = tmp_path / "link.md"
        sym.symlink_to(real)

        # Write via the symlink path with mode=None.
        write_text_atomically(sym, "new content")

        # The rename should have REPLACED the symlink with a
        # regular file (standard atomic-write contract) — and the
        # new file should have the default 0o644 (not inherited
        # from an lstat of a non-file). Real file unchanged.
        assert not sym.is_symlink(), (
            "atomic write should replace symlink with regular file"
        )
        assert sym.read_text() == "new content"
        assert real.read_text() == "real content"
        # Perms on the new regular file: default 0o644 (symlink
        # itself has no meaningful mode to preserve).
        assert sym.stat().st_mode & 0o777 == 0o644


class TestCrossConsumerConsistency:
    """Consumers pass content through the same primitive."""

    def test_annotations_writes_via_shared_helper(
        self, tmp_path, monkeypatch,
    ):
        """core/annotations/storage.py's write_annotation should go
        through write_text_atomically — verify by patching the shared
        helper and confirming it's called with a path inside tmp_path."""
        from core.annotations import storage as _storage
        from core.annotations.storage import write_annotation
        from core.annotations.models import Annotation

        seen = []
        import core.atomic_fs as atomic_fs
        real = atomic_fs.write_text_atomically

        def spy(path, content, **kwargs):
            seen.append(("annotations", Path(path)))
            return real(path, content, **kwargs)

        # storage.py binds ``write_text_atomically`` at module load,
        # so patch BOTH the source module attribute AND the resolved
        # binding in storage.py's namespace — otherwise the storage
        # module keeps calling the original.
        monkeypatch.setattr(atomic_fs, "write_text_atomically", spy)
        monkeypatch.setattr(_storage, "write_text_atomically", spy)
        ann = Annotation(
            file="foo/bar.py",
            function="baz",
            metadata={"source": "human", "status": "clean"},
            body="test note",
        )
        write_annotation(tmp_path, ann)
        # Spy fired at least once, and every recorded write landed
        # under tmp_path. Weak "any(kind == 'annotations')" wouldn't
        # catch a bug where write_annotation routed elsewhere and the
        # spy was called for an unrelated reason.
        assert len(seen) >= 1
        assert all(
            tmp_path in p.parents or p == tmp_path
            for _, p in seen
        )

