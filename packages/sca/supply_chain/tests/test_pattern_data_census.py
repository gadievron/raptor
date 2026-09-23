"""ReDoS idiom census over the SCA supply-chain pattern DATA FILES.

The repo-wide census (``.github/tests/test_redos_idiom_census.py``)
walks source-level regex compiles plus the preflight corpus loader —
but its data-file arm imported only that one loader, so the SCA
loaders that compile raw regex strings from bundled JSON
(``exfil_destinations._load_rules`` and ``binary_in_package``'s
``name_suffix_opt_in`` rows) sat outside the census universe: a
MULTILINE-idiom pattern row planted in ``exfil_destinations.json``
was live while the census stayed green.

This module is the census's SCA data-file arm. It runs in the SCA
test tier (full project deps — the repo-wide census job installs
pytest only, and importing ``packages.sca`` needs the project deps),
and it reuses the census's own membership logic by loading that test
module from its file path, so there is exactly ONE definition of the
idiom.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

from packages.sca.supply_chain import (
    binary_in_package as _bip,
    exfil_destinations as _exfil,
)

_REPO = Path(__file__).resolve().parents[4]
_CENSUS_PATH = _REPO / ".github" / "tests" / "test_redos_idiom_census.py"


def _census():
    """Load the repo-wide census module (membership logic authority)."""
    spec = importlib.util.spec_from_file_location(
        "_redos_idiom_census_for_sca", _CENSUS_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Registered so dataclasses/typing resolution inside the module
    # works; removed afterwards to keep sys.modules clean.
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(spec.name, None)
    return mod


def _sca_data_file_members() -> list[tuple[str, str]]:
    """Every MULTILINE-idiom member among the patterns the SCA
    data-file loaders actually compile — taken from the loaders
    themselves, never a hardcoded pattern list."""
    census = _census()
    members: list[tuple[str, str]] = []
    # Exfil-destination rules: ``entry["pattern"]`` compiled raw
    # (flag-less, so only an inline (?m)/(?s) can make a member).
    _exfil._RULES_CACHE = None
    try:
        members.extend(
            (f"exfil:{rule.category}", rule.pattern.pattern)
            for rule in _exfil._load_rules()
            if rule.pattern is not None
            and census._compiled_is_member(rule.pattern)
        )
    finally:
        _exfil._RULES_CACHE = None
    # binary_in_package name_suffix_opt_in rows: raw regex strings
    # compiled flag-less by _is_per_platform_name. (The sibling
    # ``patterns`` rows are GLOBS routed through _glob_to_regex,
    # which escapes everything but the wildcards — an inline-flag
    # member is structurally impossible there.)
    _bip._ALLOWLIST = None
    try:
        for pat in (
            _bip._load_allowlist()
            .get("name_suffix_opt_in", {})
            .get("patterns", [])
        ):
            try:
                compiled = re.compile(pat)
            except re.error:
                continue  # the loader logs and ignores bad rows
            if census._compiled_is_member(compiled):
                members.append(("binary-name-suffix", pat))
    finally:
        _bip._ALLOWLIST = None
    return members


def test_sca_pattern_data_files_have_no_members() -> None:
    members = _sca_data_file_members()
    assert not members, (
        "blank-run-quadratic regex idiom in an SCA pattern data file — "
        "spell the anchor whitespace horizontally ([^\\S\\n]):\n  "
        + "\n  ".join(f"{src}: {pat}" for src, pat in members)
    )


def test_sca_data_arm_detects_a_planted_exfil_member(tmp_path) -> None:
    """Self-check: a MULTILINE-idiom pattern row planted in a scratch
    copy of exfil_destinations.json must be flagged (and only it, on
    the fixed corpus) — this is exactly the plant that stayed live
    while the repo-wide census passed."""
    scratch = tmp_path / "exfil_destinations.json"
    shutil.copy(_exfil._DATA_FILE, scratch)
    data = json.loads(scratch.read_text(encoding="utf-8"))
    data["entries"].append({
        "category": "planted",
        "severity": "medium",
        "reason": "census self-check plant",
        "pattern": "(?m)^\\s*planted-quadratic\\s*$",
    })
    scratch.write_text(json.dumps(data), encoding="utf-8")
    original = _exfil._DATA_FILE
    _exfil._DATA_FILE = scratch
    try:
        members = _sca_data_file_members()
    finally:
        _exfil._DATA_FILE = original
        _exfil._RULES_CACHE = None
    assert members == [
        ("exfil:planted", "(?m)^\\s*planted-quadratic\\s*$"),
    ]


def test_sca_data_arm_detects_a_planted_name_suffix_member(
    tmp_path, monkeypatch,
) -> None:
    """Same self-check for the binary_in_package allowlist rows —
    planted through the loader's own file path, since the census arm
    re-loads from disk."""
    scratch = tmp_path / "binary_opt_in_locations.json"
    shutil.copy(_bip._allowlist_path(), scratch)
    data = json.loads(scratch.read_text(encoding="utf-8"))
    data.setdefault("name_suffix_opt_in", {}).setdefault(
        "patterns", [],
    ).append("(?m)^\\s*planted-quadratic\\s*$")
    scratch.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(_bip, "_allowlist_path", lambda: scratch)
    try:
        members = _sca_data_file_members()
    finally:
        _bip._ALLOWLIST = None
    assert ("binary-name-suffix", "(?m)^\\s*planted-quadratic\\s*$") \
        in members
