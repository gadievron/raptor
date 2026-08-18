"""Registry health check sub-command.

``raptor-sca health`` pings every registry client against a known-good package
and reports per-ecosystem reachability. Useful for:

- Pre-flight diagnostics (operator hits "all hardens fail" — was it the
  cache, the network, or a registry outage?).
- CI gating ("don't run /sca on this builder unless the registries are
  reachable").
- New-environment sanity-check (proxy allowlist set up correctly?).
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from core.json import JsonCache

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
    error: str | None = None


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    _configure_logging(args.verbose)

    # Throwaway cache: this is a LIVE reachability check. Reading
    # the shared cache would report stale verdicts (an earlier run
    # against a blocked registry caches an empty version list, and
    # every later health check "fails" in 0ms without touching the
    # network); writing to it would poison real scans the other way.
    import shutil
    import tempfile
    _cache_dir = tempfile.mkdtemp(prefix="raptor-sca-health-")
    cache = JsonCache(root=Path(_cache_dir))
    http = _ProbeBudgetClient(default_client())

    # Probes run in parallel and with a probe-sized HTTP budget (one
    # retry, short timeouts) — this is a reachability CHECK, not a
    # fetch: a blocked or dropped registry must show up as a fast
    # "unreachable" row, never stall the whole table behind the full
    # retry/backoff policy the real fetch paths use.
    from concurrent.futures import ThreadPoolExecutor
    results: list[_ProbeResult] = []
    # Capture the registry clients' swallowed-error WARNINGs so each
    # failed row can show its actual cause (see _ThreadLogCapture).
    # The parent logger is derived from an imported client class, not
    # a hardcoded name: module loggers are keyed by IMPORT path
    # (packages.sca.registries.*), while the "sca.registries.pypi:"
    # seen in output is message text, not the logger name.
    capture = _ThreadLogCapture()
    _reg_logger = logging.getLogger(
        PyPIClient.__module__.rsplit(".", 1)[0])
    _reg_logger.addHandler(capture)
    try:
        with ThreadPoolExecutor(max_workers=len(_PROBES),
                                thread_name_prefix="sca-health") as pool:
            futs = [
                pool.submit(_run_probe,
                            factory(http, cache, offline=args.offline),
                            eco, probe, capture)
                for eco, factory, probe in _PROBES
            ]
            results = [f.result() for f in futs]
    finally:
        _reg_logger.removeHandler(capture)
        shutil.rmtree(_cache_dir, ignore_errors=True)

    _print_table(results)
    return 0 if all(r.ok for r in results) else 1


class _ProbeBudgetClient:
    """Delegating HTTP client that clamps retry/timeout budgets.

    Registry clients call ``get_json``/``get_bytes`` with the
    module-default policy (5 retries, 600s total). Appropriate for
    real dependency fetches; pathological for a health probe against
    an unreachable registry.
    """

    _RETRIES = 1
    _TIMEOUT = 10
    _TOTAL_TIMEOUT = 30

    def __init__(self, inner) -> None:
        self._inner = inner

    def get_json(self, url, timeout=None, **kw):
        kw.setdefault("total_timeout", self._TOTAL_TIMEOUT)
        kw.setdefault("retries", self._RETRIES)
        return self._inner.get_json(
            url, timeout=timeout or self._TIMEOUT, **kw)

    def get_bytes(self, url, timeout=None, **kw):
        kw.setdefault("total_timeout", self._TOTAL_TIMEOUT)
        kw.setdefault("retries", self._RETRIES)
        return self._inner.get_bytes(
            url, timeout=timeout or self._TIMEOUT, **kw)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _ThreadLogCapture(logging.Handler):
    """Collect WARNING+ records per emitting thread.

    Registry clients deliberately swallow fetch errors — they log a
    WARNING and return an empty version list so a real scan degrades
    instead of aborting. Correct for scans; for a health check it
    reduced every failure to "registry returned 0 versions", hiding
    the actual cause (upstream proxy refusal, DNS, timeout) one log
    line above the table. Probes run in parallel threads, so records
    are attributed by ``record.thread`` and each probe reads back only
    its own.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self._by_thread: dict[int, list[str]] = {}
        self._lock2 = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        with self._lock2:
            self._by_thread.setdefault(record.thread, []).append(
                record.getMessage())

    def last_for_current_thread(self) -> str | None:
        with self._lock2:
            msgs = self._by_thread.get(threading.get_ident())
            return msgs[-1] if msgs else None


def _run_probe(client, eco: str, probe: str,
               capture: _ThreadLogCapture | None = None) -> _ProbeResult:
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
    error = None
    if n == 0:
        cause = capture.last_for_current_thread() if capture else None
        error = (_trim_cause(cause) if cause
                 else "registry returned 0 versions")
    return _ProbeResult(
        ecosystem=eco, probe=probe, ok=n > 0,
        elapsed_ms=elapsed, versions_returned=n,
        error=error,
    )


def _trim_cause(msg: str, limit: int = 220) -> str:
    """One line, bounded — table rows are not stack traces."""
    line = msg.splitlines()[0].strip()
    return line if len(line) <= limit else line[: limit - 1] + "…"



def _print_table(results: list[_ProbeResult]) -> None:
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
