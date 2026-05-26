"""Registry health check sub-command.

``raptor-sca health`` pings every registry client against a known-good package
and reports per-ecosystem reachability. Useful for:

- Pre-flight diagnostics (operator hits "all hardens fail" — was it the
  cache, the network, or a registry outage?).
- CI gating ("don't run /sca on this builder unless the registries are
  reachable").
- New-environment sanity-check (proxy whitelist set up correctly?).
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence

from core.json import JsonCache
from . import SCA_CACHE_ROOT
from . import default_client
from .registries.crates import CratesClient
from .registries.debian import DebianClient
from .registries.golang import GoClient
from .registries.homebrew import HomebrewClient
from .registries.maven import MavenClient
from .registries.npm import NpmClient
from .registries.nuget import NugetClient
from .registries.packagist import PackagistClient
from .registries.pypi import PyPIClient
from .registries.rubygems import RubyGemsClient

logger = logging.getLogger(__name__)


# ``(ecosystem, client_factory, probe_name)`` — probe_name is a known-good
# package whose existence we use as the heartbeat.
_PROBES = [
    ("PyPI", PyPIClient, "requests"),
    ("npm", NpmClient, "react"),
    ("crates.io", CratesClient, "serde"),
    ("RubyGems", RubyGemsClient, "rake"),
    ("Go", GoClient, "github.com/spf13/cobra"),
    ("Maven", MavenClient,
     "org.apache.logging.log4j:log4j-core"),
    ("Packagist", PackagistClient, "symfony/console"),
    ("NuGet", NugetClient, "Newtonsoft.Json"),
    ("Debian", DebianClient, "nginx"),
    ("Homebrew", HomebrewClient, "wget"),
]


@dataclass
class _ProbeResult:
    ecosystem: str
    probe: str
    ok: bool
    elapsed_ms: int
    versions_returned: int
    error: Optional[str] = None


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    _configure_logging(args.verbose)

    cache = JsonCache(root=SCA_CACHE_ROOT)
    http = default_client()

    results: List[_ProbeResult] = []
    for eco, factory, probe in _PROBES:
        client = factory(http, cache, offline=args.offline)
        results.append(_run_probe(client, eco, probe))

    _print_table(results)
    return 0 if all(r.ok for r in results) else 1


def _run_probe(client, eco: str, probe: str) -> _ProbeResult:
    t0 = time.monotonic()
    try:
        versions = client.list_versions(probe)
    except Exception as e:                  # noqa: BLE001
        elapsed = int((time.monotonic() - t0) * 1000)
        return _ProbeResult(
            ecosystem=eco, probe=probe, ok=False,
            elapsed_ms=elapsed, versions_returned=0,
            error=f"{type(e).__name__}: {e}",
        )
    elapsed = int((time.monotonic() - t0) * 1000)
    n = len(versions)
    return _ProbeResult(
        ecosystem=eco, probe=probe, ok=n > 0,
        elapsed_ms=elapsed, versions_returned=n,
        error=None if n > 0 else "registry returned 0 versions",
    )


def _print_table(results: List[_ProbeResult]) -> None:
    print(f"{'Ecosystem':<12} {'Probe':<40} {'Status':<10} "
          f"{'Time':<8} {'Versions':<10}")
    print("-" * 90)
    for r in results:
        status = "OK" if r.ok else "FAIL"
        print(f"{r.ecosystem:<12} {r.probe:<40} {status:<10} "
              f"{r.elapsed_ms:<8} {r.versions_returned:<10}")
        if r.error and not r.ok:
            print(f"             error: {r.error}")
    n_ok = sum(1 for r in results if r.ok)
    print(f"\n{n_ok}/{len(results)} registries healthy")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca health",
        description="Probe every registry client against a known package; "
                    "report reachability + latency. Returns non-zero if "
                    "any registry fails.",
    )
    p.add_argument("--offline", action="store_true",
                   help="probe cache only (skip network)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def _configure_logging(verbose: int) -> None:
    level = logging.WARNING - 10 * min(verbose, 2)
    logging.basicConfig(
        level=level, format="%(levelname)s %(name)s: %(message)s")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
