"""End-to-end coverage for ``--pin-debian``.

Exercises the whole chain on a real Dockerfile: parse → base-image suite
attribution → plan (newest-in-suite) → apply (the actual rewriter, in
place). Network is stubbed with a fake Debian registry + fake OSV. These
lock in the behaviour an earlier ad-hoc run proved by hand:

  * unpinned apt deps get pinned, an old pin gets bumped — to the version
    in the *base image's* suite, not "newest across all suites";
  * the rewriter preserves epoch (``4:…``) and ``+debNuN`` versions and the
    backslash line-continuation;
  * a non-Debian base (Ubuntu) is skipped, never guessed;
  * pinning is off without the flag;
  * a dep already at the suite version re-plans as ``up_to_date`` — the
    idempotency the ``--self-test`` pass-2 relies on.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Dict, List, Tuple

from packages.sca.harden import _apply, plan
from packages.sca.osv import OsvResult


@dataclasses.dataclass
class _FakeDeb:
    """Debian registry stub keyed by (suite, name)."""

    by_suite_pkg: Dict[Tuple[str, str], List[str]]
    ecosystem: str = "Debian"

    def list_versions(self, name: str) -> List[str]:  # pragma: no cover
        raise AssertionError("pin path must use versions_in_suite, not list_versions")

    def versions_in_suite(self, name: str, suite: str) -> List[str]:
        return list(self.by_suite_pkg.get((suite, name), []))


@dataclasses.dataclass
class _ExplodingDeb:
    """Fails if queried — proves the planner skips before any network call."""

    ecosystem: str = "Debian"

    def list_versions(self, name: str) -> List[str]:  # pragma: no cover
        raise AssertionError("registry must not be queried")

    def versions_in_suite(self, name: str, suite: str) -> List[str]:  # pragma: no cover
        raise AssertionError("registry must not be queried")


class _FakeOsv:
    """No advisories — every candidate ranks clean (OSV doesn't cover Debian)."""

    def query_batch(self, deps):
        return [OsvResult(dep_key=d.key(), advisories=[]) for d in deps]


def _plan(target: Path, registry, **kw):
    return plan(target=target, registries={"Debian": registry},
                osv=_FakeOsv(), offline=False, allow_major=False, **kw)


def test_pin_debian_pins_bumps_and_preserves_epoch(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN apt-get update && apt-get install -y \\\n"
        "    nginx curl gcc=4:12.2.0-2\n",
        encoding="utf-8",
    )
    reg = _FakeDeb({
        ("bookworm", "nginx"): ["1.22.1-9+deb12u6"],
        ("bookworm", "curl"): ["7.88.1-10+deb12u14"],
        ("bookworm", "gcc"): ["4:12.2.0-3"],          # epoch bump target
    })
    cands = _plan(tmp_path, reg, pin_debian=True)
    by = {c.name: c for c in cands}
    assert by["nginx"].status == "promoted"
    assert by["nginx"].to_version == "1.22.1-9+deb12u6"
    assert by["gcc"].status == "promoted"
    assert by["gcc"].from_version == "4:12.2.0-2"
    assert by["gcc"].to_version == "4:12.2.0-3"

    out = tmp_path / "_out"
    out.mkdir()
    changes = _apply(cands, target=tmp_path, out_dir=out,
                     allow_major_without_review=False, allow_degraded=False)
    assert changes and all(ch.skipped_reason is None for ch in changes)
    rewritten = next(out.rglob("Dockerfile")).read_text(encoding="utf-8")
    assert "nginx=1.22.1-9+deb12u6" in rewritten
    assert "curl=7.88.1-10+deb12u14" in rewritten
    assert "gcc=4:12.2.0-3" in rewritten              # epoch colon preserved
    assert "-y \\\n" in rewritten                      # continuation preserved


def test_pin_debian_uses_per_stage_suite(tmp_path: Path) -> None:
    """Each apt line is pinned within its own stage's base suite."""
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bullseye AS build\n"
        "RUN apt-get install -y gcc\n"
        "FROM debian:bookworm\n"
        "RUN apt-get install -y nginx\n",
        encoding="utf-8",
    )
    reg = _FakeDeb({
        ("bullseye", "gcc"): ["4:10.2.1-1"],
        ("bookworm", "nginx"): ["1.22.1-9+deb12u6"],
    })
    by = {c.name: c for c in _plan(tmp_path, reg, pin_debian=True)}
    assert by["gcc"].to_version == "4:10.2.1-1"        # bullseye
    assert by["nginx"].to_version == "1.22.1-9+deb12u6"  # bookworm


def test_pin_debian_skips_non_debian_base(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get install -y nginx\n", encoding="utf-8")
    by = {c.name: c for c in _plan(tmp_path, _ExplodingDeb(), pin_debian=True)}
    assert by["nginx"].status == "pinning_deferred"
    assert by["nginx"].to_version is None
    assert "ubuntu:22.04" in by["nginx"].detail


def test_pin_debian_off_by_default(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm\nRUN apt-get install -y nginx\n", encoding="utf-8")
    by = {c.name: c for c in _plan(tmp_path, _ExplodingDeb())}   # no pin_debian
    assert by["nginx"].status == "pinning_deferred"
    assert "--pin-debian" in by["nginx"].detail


def test_pin_debian_idempotent_at_suite_version(tmp_path: Path) -> None:
    """A dep already at the current suite version re-plans as up_to_date —
    this is what the self-test's pass-2 (now run *with* pin_debian) checks."""
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm\n"
        "RUN apt-get install -y nginx=1.22.1-9+deb12u6\n",
        encoding="utf-8",
    )
    reg = _FakeDeb({("bookworm", "nginx"): ["1.22.1-9+deb12u6"]})
    by = {c.name: c for c in _plan(tmp_path, reg, pin_debian=True)}
    assert by["nginx"].status == "up_to_date"
    assert by["nginx"].to_version is None
