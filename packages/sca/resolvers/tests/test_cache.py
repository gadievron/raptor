"""Tests for the resolver-cache wrapper.

The cache memoises ``ResolverResult`` keyed on a hash of the
resolver's declared MANIFEST_FILES. Hits skip the resolver
subprocess entirely; misses run it and cache the result.
"""

from __future__ import annotations

from pathlib import Path


from core.json import JsonCache
from packages.sca.resolvers import ResolverResult
from packages.sca.resolvers._cache import (
    cached_dry_run,
    cached_dry_run_batch,
    manifest_hash,
)


class _FakeResolver:
    """Minimal stand-in: declares MANIFEST_FILES + counts dry_run
    calls so the test can assert cache hits."""

    ecosystem = "PyPI"
    MANIFEST_FILES = ("requirements.txt",)
    proxy_hosts = ()

    def __init__(self, lockfile: bytes = b"resolved"):
        self.lockfile = lockfile
        self.calls = 0

    def is_available(self) -> bool:
        return True

    def matches(self, project_dir: Path) -> bool:
        return True

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        self.calls += 1
        return ResolverResult(
            ecosystem=self.ecosystem, success=True, available=True,
            proposed_lockfile=self.lockfile, raw_output="",
        )


class _NoManifestFilesResolver(_FakeResolver):
    """Resolver that doesn't declare MANIFEST_FILES — cache wrapper
    must fall through to the subprocess path."""
    MANIFEST_FILES = ()


def _make_project(tmp_path: Path, contents: str = "django==3.0.6\n") -> Path:
    project = tmp_path / "proj"
    project.mkdir(parents=True, exist_ok=True)
    (project / "requirements.txt").write_text(contents, encoding="utf-8")
    return project


# ---------------------------------------------------------------------------
# manifest_hash
# ---------------------------------------------------------------------------


class TestManifestHash:

    def test_returns_none_when_resolver_has_no_manifest_files(
        self, tmp_path: Path,
    ):
        project = _make_project(tmp_path)
        resolver = _NoManifestFilesResolver()
        assert manifest_hash(resolver, project) is None

    def test_returns_none_when_no_declared_file_present(
        self, tmp_path: Path,
    ):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert manifest_hash(_FakeResolver(), empty) is None

    def test_same_contents_yield_same_hash(self, tmp_path: Path):
        a = _make_project(tmp_path / "a", "django==3.0.6\n")
        b = _make_project(tmp_path / "b", "django==3.0.6\n")
        resolver = _FakeResolver()
        assert manifest_hash(resolver, a) == manifest_hash(resolver, b)

    def test_different_contents_yield_different_hash(self, tmp_path: Path):
        a = _make_project(tmp_path / "a", "django==3.0.6\n")
        b = _make_project(tmp_path / "b", "django==4.0.0\n")
        resolver = _FakeResolver()
        assert manifest_hash(resolver, a) != manifest_hash(resolver, b)


# ---------------------------------------------------------------------------
# cached_dry_run
# ---------------------------------------------------------------------------


class TestCachedDryRun:

    def test_first_call_is_a_miss(self, tmp_path: Path):
        project = _make_project(tmp_path)
        cache = JsonCache(root=tmp_path / "cache")
        resolver = _FakeResolver()
        result = cached_dry_run(resolver, project, cache=cache)
        assert resolver.calls == 1
        assert result.success
        assert result.proposed_lockfile == b"resolved"

    def test_second_call_is_a_hit(self, tmp_path: Path):
        project = _make_project(tmp_path)
        cache = JsonCache(root=tmp_path / "cache")
        resolver = _FakeResolver()
        cached_dry_run(resolver, project, cache=cache)
        cached_dry_run(resolver, project, cache=cache)
        # Resolver only called once; second call served from cache.
        assert resolver.calls == 1

    def test_manifest_change_invalidates_cache(self, tmp_path: Path):
        project = _make_project(tmp_path)
        cache = JsonCache(root=tmp_path / "cache")
        resolver = _FakeResolver()
        cached_dry_run(resolver, project, cache=cache)
        # Mutate the manifest — cache hash changes, so next call misses.
        (project / "requirements.txt").write_text(
            "django==4.0.0\n", encoding="utf-8",
        )
        cached_dry_run(resolver, project, cache=cache)
        assert resolver.calls == 2

    def test_different_resolver_class_does_not_share_cache(
        self, tmp_path: Path,
    ):
        """Two resolvers with the same ecosystem + same hash but
        different classes should not share cache entries — pip vs
        poetry produce different lockfile shapes."""
        project = _make_project(tmp_path)
        cache = JsonCache(root=tmp_path / "cache")

        class _Other(_FakeResolver):
            pass

        a = _FakeResolver()
        b = _Other()
        cached_dry_run(a, project, cache=cache)
        cached_dry_run(b, project, cache=cache)
        # Both called — they don't share.
        assert a.calls == 1
        assert b.calls == 1

    def test_no_manifest_files_falls_through_to_subprocess(
        self, tmp_path: Path,
    ):
        """Resolver without MANIFEST_FILES is opted out of caching —
        each call hits dry_run."""
        project = _make_project(tmp_path)
        cache = JsonCache(root=tmp_path / "cache")
        resolver = _NoManifestFilesResolver()
        cached_dry_run(resolver, project, cache=cache)
        cached_dry_run(resolver, project, cache=cache)
        assert resolver.calls == 2

    def test_failed_resolves_are_also_cached(self, tmp_path: Path):
        """If a resolve fails today and the manifest doesn't change,
        re-running shouldn't pay the subprocess cost again."""
        project = _make_project(tmp_path)
        cache = JsonCache(root=tmp_path / "cache")

        class _Failer:
            ecosystem = "PyPI"
            MANIFEST_FILES = ("requirements.txt",)
            proxy_hosts = ()
            def __init__(self): self.calls = 0
            def is_available(self): return True
            def matches(self, p): return True
            def dry_run(self, p, *, timeout=120):
                self.calls += 1
                return ResolverResult(
                    ecosystem="PyPI", success=False, available=True,
                    proposed_lockfile=None, error="resolution conflict",
                    raw_output="",
                )

        r = _Failer()
        cached_dry_run(r, project, cache=cache)
        cached_dry_run(r, project, cache=cache)
        assert r.calls == 1

    def test_lockfile_bytes_round_trip_through_cache(
        self, tmp_path: Path,
    ):
        """Lockfile bytes (esp. binary / non-UTF-8) must survive
        the JSON cache via base64."""
        project = _make_project(tmp_path)
        cache = JsonCache(root=tmp_path / "cache")
        binary = bytes(range(256))                 # full byte range
        resolver = _FakeResolver(lockfile=binary)
        cached_dry_run(resolver, project, cache=cache)
        # Hit on second call — and the lockfile bytes match.
        result = cached_dry_run(resolver, project, cache=cache)
        assert resolver.calls == 1
        assert result.proposed_lockfile == binary


# ---------------------------------------------------------------------------
# cached_dry_run_batch
# ---------------------------------------------------------------------------


class TestCachedDryRunBatch:

    def test_mixed_hits_and_misses(self, tmp_path: Path):
        cache = JsonCache(root=tmp_path / "cache")
        a = _make_project(tmp_path / "a", "django==3.0.6\n")
        b = _make_project(tmp_path / "b", "flask==1.1.0\n")
        resolver = _FakeResolver()

        # Pre-warm cache for `a`.
        cached_dry_run(resolver, a, cache=cache)
        assert resolver.calls == 1

        # Batch call: a (hit) + b (miss) → only b runs the resolver.
        results = cached_dry_run_batch(
            resolver, [a, b], cache=cache,
        )
        assert resolver.calls == 2
        assert len(results) == 2
        assert all(r.success for r in results)

    def test_input_order_preserved(self, tmp_path: Path):
        cache = JsonCache(root=tmp_path / "cache")
        a = _make_project(tmp_path / "a", "django==3.0.6\n")
        b = _make_project(tmp_path / "b", "flask==1.1.0\n")
        c = _make_project(tmp_path / "c", "requests==2.20.0\n")
        # Pre-cache `b` only with a different lockfile so we can
        # tell which result came from where.
        class _OtherLock(_FakeResolver):
            pass
        seeded = _OtherLock(lockfile=b"FROM-CACHE-FOR-B")
        cached_dry_run(seeded, b, cache=cache)
        # Use the seeded resolver class for the batch too so the
        # cache key matches.
        results = cached_dry_run_batch(
            seeded, [a, b, c], cache=cache,
        )
        assert len(results) == 3
        # Results align with input order.
        assert results[1].proposed_lockfile == b"FROM-CACHE-FOR-B"
