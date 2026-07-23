"""Top-level capability broker — the dispatcher.

Given a RAPTOR mode and its requirements, the broker scores every
system in the fleet (local *and* remote) and picks the best one.

The local host has no special privilege — it competes on score like
every other system.  RAPTOR runs equally well on Ubuntu, Docker, and
macOS; the broker routes each mode to whatever system will finish it
fastest, regardless of where the operator launched the session.

A small tiebreak bonus avoids unnecessary transport overhead when
scores are effectively equal, but a beefy remote box will always
beat a lightweight local host.
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from core.broker.capabilities import (
    CapabilityVerdict,
    ModeRequirements,
    SystemCapabilities,
    MODE_REQUIREMENTS,
)
from core.broker.inventory import Inventory
from core.broker.probe import probe_system
from core.broker.provision import ProvisionResult, provision_tools
from core.broker.scoring import score_system
from core.broker.transport import (
    CommandResult,
    RemoteSystemEntry,
    Transport,
    TransportError,
    TransportKind,
)

logger = logging.getLogger(__name__)

# When local and remote score within this margin, prefer local to avoid
# transport overhead.  Small enough that a meaningfully better remote
# system always wins.
_LOCAL_TIEBREAK = 0.5


@dataclass(frozen=True)
class LocalExecution:
    """The local system won the scoring — run here, no transport needed."""

    capabilities: SystemCapabilities
    verdict: CapabilityVerdict


@dataclass(frozen=True)
class RemoteExecution:
    """A remote system won the scoring — execution routed over transport."""

    entry: RemoteSystemEntry
    capabilities: SystemCapabilities
    verdict: CapabilityVerdict
    transport: Transport
    remote_workdir: str
    provision_results: tuple[ProvisionResult, ...] = ()


def _build_transport(entry: RemoteSystemEntry) -> Transport:
    if entry.transport == TransportKind.SSH:
        from core.broker.ssh import SSHTransport

        return SSHTransport(entry)
    elif entry.transport == TransportKind.WINRM:
        from core.broker.winrm import WinRMTransport

        return WinRMTransport(entry)
    elif entry.transport == TransportKind.ADB:
        from core.broker.adb import ADBTransport

        return ADBTransport(entry)
    else:
        raise TransportError(f"unsupported transport: {entry.transport}")


class Broker:
    """System / Capability Broker for RAPTOR.

    Stateless dispatcher — all persistent state lives in the
    Inventory. Instantiate once per run; call ``resolve()`` to get
    an execution plan for a given mode.
    """

    def __init__(
        self,
        inventory: Optional[Inventory] = None,
        auto_provision: bool = False,
    ) -> None:
        self._inventory = inventory or Inventory()
        self._auto_provision = auto_provision
        self._local_caps: Optional[SystemCapabilities] = None

    @property
    def local_capabilities(self) -> SystemCapabilities:
        if self._local_caps is None:
            self._local_caps = SystemCapabilities.detect_local()
        return self._local_caps

    @property
    def inventory(self) -> Inventory:
        return self._inventory

    def resolve(
        self,
        mode: str,
        requirements: Optional[ModeRequirements] = None,
    ) -> LocalExecution | RemoteExecution:
        """Score every system (local + fleet) and route to the best one.

        The local host competes on score like any fleet member.  When
        scores are within ``_LOCAL_TIEBREAK``, local wins to avoid
        unnecessary transport overhead.
        """
        reqs = requirements or MODE_REQUIREMENTS.get(
            mode, ModeRequirements(mode=mode)
        )

        local_caps = self.local_capabilities
        local_verdict = local_caps.satisfies(reqs)
        local_score = (
            score_system(local_caps, mode) if local_verdict.met else -1.0
        )

        candidates = self._inventory.find_capable(reqs)
        best_remote: Optional[tuple[RemoteSystemEntry, SystemCapabilities, float]] = None
        for entry, caps in candidates:
            s = score_system(caps, mode, entry=entry)
            if best_remote is None or s > best_remote[2]:
                best_remote = (entry, caps, s)

        if best_remote and local_verdict.met:
            remote_entry, remote_caps, remote_score = best_remote
            if remote_score > local_score + _LOCAL_TIEBREAK:
                logger.info(
                    "mode '%s': remote %s (%.1f) beats local (%.1f) — routing remotely",
                    mode, remote_entry.alias, remote_score, local_score,
                )
                return self._prepare_remote(remote_entry, remote_caps, reqs)
            logger.info(
                "mode '%s': local (%.1f) wins over %s (%.1f)",
                mode, local_score, remote_entry.alias, remote_score,
            )
            return LocalExecution(
                capabilities=local_caps, verdict=local_verdict,
            )

        if local_verdict.met:
            logger.info("mode '%s': local only (%.1f), no remotes", mode, local_score)
            return LocalExecution(
                capabilities=local_caps, verdict=local_verdict,
            )

        if best_remote:
            remote_entry, remote_caps, remote_score = best_remote
            logger.info(
                "mode '%s': local incapable, routing to %s (%.1f)",
                mode, remote_entry.alias, remote_score,
            )
            return self._prepare_remote(remote_entry, remote_caps, reqs)

        if self._auto_provision:
            return self._provision_and_prepare(reqs)

        raise BrokerError(
            f"no system capable of running mode '{mode}' — "
            f"local: {local_verdict.summary()}; "
            f"no matching remote systems in inventory. "
            f"Register a system with `raptor broker add` or enable "
            f"auto-provisioning with --broker-auto-provision."
        )

    def probe_and_register(
        self, entry: RemoteSystemEntry
    ) -> SystemCapabilities:
        """Connect to a remote system, probe its capabilities, and
        add it to the inventory."""
        transport = _build_transport(entry)
        with transport:
            caps = probe_system(transport, entry)

        self._inventory.add(entry, caps)
        return caps

    def refresh(self, alias: str) -> SystemCapabilities:
        """Re-probe a registered system and update its cached capabilities."""
        entry = self._inventory.get(alias)
        if not entry:
            raise BrokerError(f"system '{alias}' not in inventory")
        return self.probe_and_register(entry)

    # -- internal ----------------------------------------------------------

    def _prepare_remote(
        self,
        entry: RemoteSystemEntry,
        caps: SystemCapabilities,
        reqs: ModeRequirements,
    ) -> RemoteExecution:
        transport = _build_transport(entry)
        transport.connect()

        remote_workdir = _remote_workdir(entry)
        transport.mkdir(remote_workdir)
        logger.info("remote workdir: %s", remote_workdir)

        verdict = caps.satisfies(reqs)
        return RemoteExecution(
            entry=entry,
            capabilities=caps,
            verdict=verdict,
            transport=transport,
            remote_workdir=remote_workdir,
        )

    def _provision_and_prepare(
        self, reqs: ModeRequirements
    ) -> RemoteExecution:
        """Find the best partial match, provision missing tools, and
        return a RemoteExecution plan."""
        best_entry: Optional[RemoteSystemEntry] = None
        best_caps: Optional[SystemCapabilities] = None
        best_missing: int = 999

        for entry in self._inventory.list_all():
            cached_caps = self._inventory.get_capabilities(entry.alias)
            if not cached_caps:
                continue
            merged = SystemCapabilities(
                alias=cached_caps.alias,
                os=cached_caps.os,
                arch=cached_caps.arch,
                tools=cached_caps.tools,
                ram_mb=cached_caps.ram_mb,
                cores=cached_caps.cores,
                free_disk_mb=cached_caps.free_disk_mb,
                labels=cached_caps.labels | entry.labels,
            )
            verdict = merged.satisfies(reqs)
            if verdict.missing_os or verdict.missing_arch:
                continue
            missing_count = len(verdict.missing_tools)
            if missing_count < best_missing:
                best_missing = missing_count
                best_entry = entry
                best_caps = merged

        if not best_entry or not best_caps:
            raise BrokerError(
                f"no system with compatible OS/arch for mode '{reqs.mode}' — "
                f"cannot auto-provision OS or architecture differences"
            )

        transport = _build_transport(best_entry)
        transport.connect()

        verdict = best_caps.satisfies(reqs)
        prov_results: tuple[ProvisionResult, ...] = ()

        if verdict.missing_tools:
            logger.info(
                "auto-provisioning %s on %s: %s",
                reqs.mode,
                best_entry.alias,
                ", ".join(sorted(verdict.missing_tools)),
            )
            results = provision_tools(
                transport, best_caps.os, verdict.missing_tools
            )
            prov_results = tuple(results)
            failed = [r for r in results if not r.success]
            if failed:
                transport.disconnect()
                raise BrokerError(
                    f"provisioning failed on {best_entry.alias}: "
                    + "; ".join(f"{r.tool}: {r.message}" for r in failed)
                )

            refreshed = probe_system(transport, best_entry)
            self._inventory.set_capabilities(best_entry.alias, refreshed)
            best_caps = refreshed

        remote_workdir = _remote_workdir(best_entry)
        transport.mkdir(remote_workdir)

        return RemoteExecution(
            entry=best_entry,
            capabilities=best_caps,
            verdict=best_caps.satisfies(reqs),
            transport=transport,
            remote_workdir=remote_workdir,
            provision_results=prov_results,
        )


class BrokerError(Exception):
    """Raised when the broker cannot satisfy a mode's requirements."""


def _remote_workdir(entry: RemoteSystemEntry) -> str:
    if entry.transport == TransportKind.WINRM:
        return f"C:\\raptor\\work\\{os.getpid()}"
    if entry.transport == TransportKind.ADB:
        return f"/data/local/tmp/raptor-work/{os.getpid()}"
    return f"/tmp/raptor-work/{os.getpid()}"
