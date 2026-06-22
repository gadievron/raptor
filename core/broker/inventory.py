"""Persistent inventory of remote systems.

Systems are stored as a JSON file under the RAPTOR config directory.
Each entry holds connection details and (optionally cached)
capability snapshots probed at registration or refresh time.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from core.broker.capabilities import (
    Architecture,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.transport import RemoteSystemEntry, TransportKind

logger = logging.getLogger(__name__)


def _default_inventory_path() -> Path:
    return Path.home() / ".raptor" / "broker" / "inventory.json"


class Inventory:
    """Manage the set of registered remote systems."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or _default_inventory_path()
        self._systems: Dict[str, RemoteSystemEntry] = {}
        self._capabilities: Dict[str, SystemCapabilities] = {}
        self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("failed to load inventory from %s: %s", self._path, exc)
            return

        for entry_dict in data.get("systems", []):
            entry = RemoteSystemEntry.from_dict(entry_dict)
            self._systems[entry.alias] = entry

        for alias, caps_dict in data.get("capabilities", {}).items():
            self._capabilities[alias] = SystemCapabilities(
                alias=alias,
                os=OperatingSystem(caps_dict["os"]),
                arch=Architecture(caps_dict["arch"]),
                tools=frozenset(caps_dict.get("tools", [])),
                ram_mb=caps_dict.get("ram_mb", 0),
                cores=caps_dict.get("cores", 0),
                free_disk_mb=caps_dict.get("free_disk_mb", 0),
                labels=frozenset(caps_dict.get("labels", [])),
            )

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "systems": [e.to_dict() for e in self._systems.values()],
            "capabilities": {
                alias: {
                    "os": caps.os.value,
                    "arch": caps.arch.value,
                    "tools": sorted(caps.tools),
                    "ram_mb": caps.ram_mb,
                    "cores": caps.cores,
                    "free_disk_mb": caps.free_disk_mb,
                    "labels": sorted(caps.labels),
                }
                for alias, caps in self._capabilities.items()
            },
        }
        self._path.write_text(json.dumps(data, indent=2) + "\n")

    # -- CRUD --------------------------------------------------------------

    def add(
        self,
        entry: RemoteSystemEntry,
        capabilities: Optional[SystemCapabilities] = None,
    ) -> None:
        self._systems[entry.alias] = entry
        if capabilities:
            self._capabilities[entry.alias] = capabilities
        self._save()
        logger.info("registered system %s (%s)", entry.alias, entry.host)

    def remove(self, alias: str) -> bool:
        removed = self._systems.pop(alias, None)
        self._capabilities.pop(alias, None)
        if removed:
            self._save()
            logger.info("removed system %s", alias)
        return removed is not None

    def get(self, alias: str) -> Optional[RemoteSystemEntry]:
        return self._systems.get(alias)

    def get_capabilities(self, alias: str) -> Optional[SystemCapabilities]:
        return self._capabilities.get(alias)

    def set_capabilities(
        self, alias: str, capabilities: SystemCapabilities
    ) -> None:
        self._capabilities[alias] = capabilities
        self._save()

    def list_all(self) -> List[RemoteSystemEntry]:
        return list(self._systems.values())

    def find_capable(
        self, requirements: ModeRequirements
    ) -> List[tuple[RemoteSystemEntry, SystemCapabilities]]:
        """Return systems whose cached capabilities satisfy *requirements*,
        ordered by best fit (fewest excess resources first)."""
        matches: list[tuple[RemoteSystemEntry, SystemCapabilities]] = []
        for alias, entry in self._systems.items():
            caps = self._capabilities.get(alias)
            if not caps:
                continue
            merged_caps = SystemCapabilities(
                alias=caps.alias,
                os=caps.os,
                arch=caps.arch,
                tools=caps.tools,
                ram_mb=caps.ram_mb,
                cores=caps.cores,
                free_disk_mb=caps.free_disk_mb,
                labels=caps.labels | entry.labels,
            )
            verdict = merged_caps.satisfies(requirements)
            if verdict.met:
                matches.append((entry, merged_caps))
        return matches
