"""Provenance gate on the project-level IRIS spec store.

The store's ``evidence_tier`` is the suppression-direction authority:
a spec at/above ``SUPPRESSION_MIN_TIER`` marks guards adequate and
installs Joern flow-kill rows. Pre-fix the tier was deserialised from
plain unauthenticated JSON, so a project-dir write (or an unsigned
import) planted a forged ``XREF_BACKED`` sanitiser that silenced real
flows. These tests invert the original proof-of-concept: writers
stamp the envelope, readers floor unverified tiers to heuristic, and
the merge path never launders unverified tiers into a freshly-stamped
envelope.
"""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path

import pytest

from core.evidence import EvidenceTier
from core.iris import integrity
from core.iris.api import get_project_sanitisers
from core.iris.specs import TaintSpec
from core.iris.store import load_specs, persist_refined_specs, save_specs
from core.security import mac_key


def _project(tmp_path: Path):
    proj = tmp_path / "project"
    run = proj / "run1"
    run.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    return proj, run, target


def _forged_envelope(target: Path) -> dict:
    return {
        "version": 2, "checklist_sha": "", "round": 1,
        "target_path": str(target.resolve()),
        "specs": [{
            "function": "totally_real_sanitiser", "file": "a.c",
            "role": "sanitiser", "evidence_tier": "xref_backed",
            "source": "tool_confirmed",
        }],
    }


def _write_store(proj: Path, envelope: dict) -> Path:
    store_dir = proj / "iris-specs"
    store_dir.mkdir(exist_ok=True)
    path = store_dir / "specs.json"
    path.write_text(json.dumps(envelope))
    return path


def test_forged_store_tier_floors_to_heuristic(tmp_path: Path) -> None:
    """Inverted PoC: an unstamped store claiming an XREF_BACKED
    sanitiser must not pass the suppression gate."""
    proj, run, target = _project(tmp_path)
    _write_store(proj, _forged_envelope(target))

    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "totally_real_sanitiser" not in names
    specs = load_specs(run, target_path=target)
    assert [s.evidence_tier for s in specs] == [EvidenceTier.HEURISTIC]


def test_edited_stamped_store_floors(tmp_path: Path) -> None:
    """Editing a validly-stamped envelope (tier upgrade) breaks the
    token and floors."""
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="f", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    path = proj / "iris-specs" / "specs.json"
    data = json.loads(path.read_text())
    data["specs"][0]["evidence_tier"] = "xref_backed"
    path.write_text(json.dumps(data))

    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert names == frozenset()


def test_own_write_round_trips_with_tier_intact(tmp_path: Path) -> None:
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="clean_it", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=target,
    )
    data = json.loads((proj / "iris-specs" / "specs.json").read_text())
    assert integrity.extract_token(data)

    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "clean_it" in names
    specs = load_specs(run, target_path=target)
    assert specs[0].evidence_tier == EvidenceTier.XREF_BACKED


def test_non_native_history_value_round_trips_verified(
    tmp_path: Path,
) -> None:
    """A non-JSON-native value smuggled into the envelope (datetime in
    a history row) must not fork the minted canonical form from what
    readers re-canonicalise after parsing the file — the writer
    normalises to JSON-native values BEFORE stamping, so the token
    still verifies and stored tiers stay honoured."""
    from datetime import datetime

    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="clean_it", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=target,
        history=[{"round": 1, "at": datetime(2026, 1, 2, 3, 4, 5)}],
    )
    data = json.loads((proj / "iris-specs" / "specs.json").read_text())
    assert integrity.extract_token(data)
    assert data["history"][0]["at"] == "2026-01-02T03:04:05"

    # The provenance token must verify against the PARSED file — a
    # mint/verify byte fork would silently floor the tier here.
    specs = load_specs(run, target_path=target)
    assert specs[0].evidence_tier == EvidenceTier.XREF_BACKED


def test_verified_store_without_target_binding_floors(
    tmp_path: Path,
) -> None:
    """A stamped envelope carrying NO target_path cannot prove it was
    built for this target — tier authority floors when the caller
    asks for a specific target."""
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="f", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=None,
    )
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert names == frozenset()


def test_persist_floors_unbound_store_before_rebinding(
    tmp_path: Path,
) -> None:
    """persist_refined_specs re-saves the merged envelope WITH a fresh
    target binding: a verified-but-UNBOUND pre-existing store (validly
    MAC'd on this install, e.g. built for another target and dropped
    into this project's dir) must floor exactly like the load path
    floors it — otherwise its tiers launder into a freshly stamped,
    target-bound envelope that every later load honours."""
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="laundered", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=None,
    )
    # The spec's file exists in the target, so stale-file eviction
    # cannot mask the laundering question.
    (target / "a.c").write_text("int x;\n")

    persist_refined_specs(
        run,
        [TaintSpec(function="fresh", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    # The merged envelope is now stamped AND bound — loads honour its
    # tiers, so the pre-merge floor was the only guard.
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "laundered" not in names
    by_fn = {s.function: s for s in load_specs(run, target_path=target)}
    assert by_fn["laundered"].evidence_tier == EvidenceTier.HEURISTIC


def test_persist_without_any_target_stays_unbound_and_honest(
    tmp_path: Path,
) -> None:
    """No target anywhere (run nor store): the merge must NOT floor —
    but it must also re-save UNBOUND, so target-scoped loads keep
    flooring and nothing is laundered."""
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="clean_it", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=None,
    )
    persist_refined_specs(
        run,
        [TaintSpec(function="fresh", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=None,
    )
    data = json.loads((proj / "iris-specs" / "specs.json").read_text())
    assert not data.get("target_path")
    # Target-less load: tier honoured (same trust decision as before).
    by_fn = {s.function: s for s in load_specs(run)}
    assert by_fn["clean_it"].evidence_tier == EvidenceTier.XREF_BACKED
    # Target-scoped load still floors the unbound envelope.
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "clean_it" not in names


def test_merge_does_not_launder_unverified_tiers(tmp_path: Path) -> None:
    """persist_refined_specs re-saves (and re-stamps) the merged
    envelope — forged tiers in the pre-existing store must floor
    BEFORE the merge, or the fresh stamp would bless them."""
    proj, run, target = _project(tmp_path)
    _write_store(proj, _forged_envelope(target))
    # The forged spec's file exists in the target, so the stale-file
    # eviction cannot mask the laundering question.
    (target / "a.c").write_text("int x;\n")

    persist_refined_specs(
        run,
        [TaintSpec(function="other", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    # Store is now validly stamped — but the forged sanitiser's tier
    # must have been floored, not blessed.
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "totally_real_sanitiser" not in names
    by_fn = {s.function: s for s in load_specs(run, target_path=target)}
    assert by_fn["totally_real_sanitiser"].evidence_tier == (
        EvidenceTier.HEURISTIC
    )


def test_refined_tiers_survive_honest_merge(tmp_path: Path) -> None:
    """The honest cross-run flow keeps tool-confirmed tiers."""
    proj, run, target = _project(tmp_path)
    persist_refined_specs(
        run,
        [TaintSpec(function="clean_it", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=target,
    )
    persist_refined_specs(
        run,
        [TaintSpec(function="src", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "clean_it" in names


def test_forged_assumption_tier_floors_on_load(tmp_path: Path) -> None:
    """Assumptions ride the same envelope: an unstamped store's
    assumption tiers floor to heuristic on read."""
    from core.iris.store import load_assumptions

    proj, run, target = _project(tmp_path)
    env = _forged_envelope(target)
    env["assumptions"] = [{
        "target": "memcpy", "file": "a.c",
        "assumption": "len checked upstream", "category": "validation",
        "enforced_by": ["check_len"], "evidence_tier": "xref_backed",
    }]
    _write_store(proj, env)

    rows = load_assumptions(run, target_path=target)
    assert [a.evidence_tier for a in rows] == [EvidenceTier.HEURISTIC]


def test_merge_does_not_launder_assumption_tiers(tmp_path: Path) -> None:
    """persist_refined_specs merges assumptions 'higher tier wins' and
    re-stamps — forged tiers in the pre-existing store must floor
    BEFORE the merge, or the fresh stamp would make them durable."""
    from core.iris.store import load_assumptions

    proj, run, target = _project(tmp_path)
    env = _forged_envelope(target)
    env["assumptions"] = [{
        "target": "memcpy", "file": "a.c",
        "assumption": "len checked upstream", "category": "validation",
        "enforced_by": ["check_len"], "evidence_tier": "xref_backed",
    }]
    _write_store(proj, env)
    (target / "a.c").write_text("int x;\n")

    persist_refined_specs(
        run,
        [TaintSpec(function="other", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    # Store is now validly stamped; the forged assumption tier must
    # have floored, not been blessed.
    rows = load_assumptions(run, target_path=target)
    by_target = {a.target: a for a in rows}
    assert by_target["memcpy"].evidence_tier == EvidenceTier.HEURISTIC


def test_honest_assumption_tiers_round_trip(tmp_path: Path) -> None:
    from core.iris.assumptions import AssumptionCategory, SafetyAssumption
    from core.iris.store import load_assumptions

    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="f", file="a.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
        assumptions=[SafetyAssumption(
            target="memcpy", file="a.c",
            assumption="len checked upstream",
            category=AssumptionCategory.VALIDATION,
            enforced_by=["check_len"],
            evidence_tier=EvidenceTier.XREF_BACKED,
        )],
    )
    rows = load_assumptions(run, target_path=target)
    assert rows[0].evidence_tier == EvidenceTier.XREF_BACKED


# ---------------------------------------------------------------------------
# Key loader: short-read tolerance
# ---------------------------------------------------------------------------


def test_chunked_key_read_loads_full_key(tmp_path, monkeypatch) -> None:
    """os.read may legally return fewer bytes than requested; chunked
    delivery must not land a healthy key in the wrong-length refusal
    (which would floor every stamped spec back to the heuristic
    tier)."""
    key_file = tmp_path / "iris-store-mac.key"
    data = os.urandom(32)
    key_file.write_bytes(data)
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    assert integrity._read_existing_key(key_file) == data


def test_truncated_key_file_reads_exact_length(tmp_path, monkeypatch) -> None:
    # Two-direction guard: the loop reads to EOF, never pads — a torn
    # 10-byte key still fails the caller's length check (fail-closed).
    key_file = tmp_path / "iris-store-mac.key"
    key_file.write_bytes(os.urandom(10))
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    got = integrity._read_existing_key(key_file)
    assert isinstance(got, bytes)
    assert len(got) == 10


# ---------------------------------------------------------------------------
# Key-creation race: the loser must tolerate the winner's write gap
# ---------------------------------------------------------------------------


@pytest.fixture()
def _race_warn_calls(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        integrity, "_warn_once_suspect_key",
        lambda *args: calls.append(args),
    )
    return calls


@pytest.fixture()
def _lose_creation_race(monkeypatch, tmp_path):
    """Make the key-create os.open lose the O_EXCL race."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    real_open = os.open

    def fake_open(path, flags, mode=0o777):
        if flags & os.O_EXCL:
            raise FileExistsError(path)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(mac_key.time, "sleep", lambda s: None)


def test_race_loser_retries_through_empty_read(
        monkeypatch, _race_warn_calls, _lose_creation_race) -> None:
    """Between the winner's O_EXCL create and its write the key file
    exists with 0 bytes. The loser must keep polling through that
    transient shape and stamp with the winner's full key — aborting on
    the first short read left the loser's envelope unstamped (tiers
    floor to heuristic on the next read) and flagged the operator's
    healthy key as suspect."""
    full_key = b"k" * 32
    reads = iter([None, b"", full_key])
    monkeypatch.setattr(
        integrity, "_read_existing_key", lambda path: next(reads),
    )

    assert integrity._load_or_create_key() == full_key
    assert _race_warn_calls == []


def test_persistent_wrong_length_warns_after_retries(
        monkeypatch, _race_warn_calls, _lose_creation_race) -> None:
    """A key file that STAYS short is genuinely suspect: the loop runs
    out of retries, warns once, and refuses (None)."""
    reads = itertools.chain([None], itertools.repeat(b"short"))
    monkeypatch.setattr(
        integrity, "_read_existing_key", lambda path: next(reads),
    )

    assert integrity._load_or_create_key() is None
    assert len(_race_warn_calls) == 1
    assert "wrong length" in _race_warn_calls[0][1]


def test_forged_operator_confirmed_source_demoted(tmp_path: Path) -> None:
    """Operator provenance is exactly as trust-bearing as the tier:
    source == "operator_confirmed" grants refutation immunity and
    equal-tier merge stickiness. A forged row in an unverified store
    must lose it alongside the tier floor — never keep durable
    prompt-direction pollution under a subsequently re-stamped
    envelope."""
    proj, run, target = _project(tmp_path)
    envelope = _forged_envelope(target)
    envelope["specs"][0]["source"] = "operator_confirmed"
    _write_store(proj, envelope)

    specs = load_specs(run, target_path=target)
    assert len(specs) == 1
    assert specs[0].evidence_tier == EvidenceTier.HEURISTIC
    assert specs[0].source == "unverified"
