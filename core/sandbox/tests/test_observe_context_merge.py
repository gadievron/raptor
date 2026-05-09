"""Tests for core.sandbox.observe_context_merge.

The merge utility is the integration point between sandbox(observe=True)
and /understand --map. These tests pin:

  * shape of the augmented context map (new top-level
    runtime_observation key, original keys untouched);
  * correlation logic — when a profile path matches an entry-point
    or sink file, the corresponding ID is surfaced;
  * non-destructive contract — caller's input dict is not mutated.
"""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from core.sandbox.observe_context_merge import (
    RUNTIME_OBSERVATION_KEY,
    merge_observation_into_context_map,
)
from core.sandbox.observe_profile import ConnectTarget, ObserveProfile


def _ctx() -> dict:
    """Minimal context-map.json fixture matching the shape produced
    by /understand --map (excerpt of MINIMAL_CONTEXT_MAP)."""
    return {
        "sources": [
            {"type": "http_route",
             "entry": "POST /api/query @ src/routes/query.py:34"},
        ],
        "sinks": [
            {"type": "db_query", "location": "src/db/query.py:89"},
        ],
        "trust_boundaries": [
            {"boundary": "JWT auth", "check": "src/middleware/auth.py:12"},
        ],
        "meta": {"target": "/some/repo", "app_type": "web_app"},
        "entry_points": [
            {"id": "EP-001", "type": "http_route",
             "file": "src/routes/query.py", "line": 34,
             "accepts": "JSON body"},
            {"id": "EP-002", "type": "http_route",
             "file": "src/admin/bulk.py", "line": 67,
             "accepts": "JSON body"},
        ],
        "sink_details": [
            {"id": "SINK-001", "type": "db_query",
             "file": "src/db/query.py", "line": 89},
            {"id": "SINK-002", "type": "file_write",
             "file": "src/uploads/save.py", "line": 12},
        ],
    }


def _profile() -> ObserveProfile:
    return ObserveProfile(
        paths_read=[
            "/some/repo/src/routes/query.py",
            "/some/repo/src/middleware/auth.py",
            "/etc/passwd",
        ],
        paths_written=[
            "/some/repo/src/uploads/save.py",
        ],
        paths_stat=["/etc/ld.so.preload"],
        connect_targets=[
            ConnectTarget(ip="1.2.3.4", port=443, family="AF_INET"),
        ],
    )


# ---------------------------------------------------------------------------
# Shape contract
# ---------------------------------------------------------------------------


class TestMergeShape:

    def test_runtime_observation_key_added(self):
        out = merge_observation_into_context_map(_ctx(), _profile())
        assert RUNTIME_OBSERVATION_KEY in out
        assert RUNTIME_OBSERVATION_KEY == "runtime_observation"

    def test_original_keys_preserved(self):
        ctx = _ctx()
        out = merge_observation_into_context_map(ctx, _profile())
        for key in ("sources", "sinks", "trust_boundaries", "meta",
                    "entry_points", "sink_details"):
            assert out[key] == ctx[key]

    def test_non_destructive(self):
        ctx = _ctx()
        snapshot = deepcopy(ctx)
        merge_observation_into_context_map(ctx, _profile())
        assert ctx == snapshot, (
            "merge must not mutate the input context_map; caller "
            "may keep the original."
        )

    def test_empty_context_map_yields_observation_only(self):
        out = merge_observation_into_context_map({}, _profile())
        assert RUNTIME_OBSERVATION_KEY in out
        assert out[RUNTIME_OBSERVATION_KEY]["paths_read"] == (
            _profile().paths_read
        )

    def test_none_context_map_handled_as_empty(self):
        out = merge_observation_into_context_map(None, _profile())
        assert RUNTIME_OBSERVATION_KEY in out


# ---------------------------------------------------------------------------
# Correlation logic
# ---------------------------------------------------------------------------


class TestCorrelations:

    def test_entry_point_runtime_confirmed_when_path_observed(self):
        out = merge_observation_into_context_map(_ctx(), _profile())
        confirmed = out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"]
        # EP-001 maps to src/routes/query.py — observed.
        assert "EP-001" in confirmed
        # EP-002 maps to src/admin/bulk.py — NOT observed.
        assert "EP-002" not in confirmed

    def test_sink_runtime_confirmed_via_paths_written(self):
        out = merge_observation_into_context_map(_ctx(), _profile())
        confirmed = out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["sinks_runtime_confirmed"]
        # SINK-002 maps to src/uploads/save.py which the profile
        # records under paths_written.
        assert "SINK-002" in confirmed
        # SINK-001 (db_query @ src/db/query.py) was not opened for
        # write — not confirmed by runtime evidence.
        assert "SINK-001" not in confirmed

    def test_external_reach_lists_connect_targets(self):
        out = merge_observation_into_context_map(_ctx(), _profile())
        reach = out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["external_reach"]
        assert reach == ["1.2.3.4:443 (AF_INET)"]

    def test_sink_path_in_paths_read_is_NOT_confirmed_as_sink(self):
        # Tightly: a sink with file X is "runtime confirmed" only if
        # X appears in paths_written. A read of X doesn't count —
        # operators rely on this distinction to find load-bearing
        # vs. probed sinks.
        ctx = _ctx()
        # Profile that reads (but doesn't write) the sink path:
        prof = ObserveProfile(
            paths_read=["/some/repo/src/db/query.py"],
        )
        out = merge_observation_into_context_map(ctx, prof)
        confirmed = out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["sinks_runtime_confirmed"]
        assert "SINK-001" not in confirmed

    def test_entry_point_without_id_skipped(self):
        ctx = {
            "entry_points": [
                {"file": "src/x.py"},  # no id
                {"id": "EP-X", "file": "src/y.py"},
            ],
        }
        prof = ObserveProfile(
            paths_read=["/abs/src/x.py", "/abs/src/y.py"],
        )
        out = merge_observation_into_context_map(ctx, prof)
        # The id-less entry can't be referenced; only EP-X surfaces.
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == ["EP-X"]


# ---------------------------------------------------------------------------
# Path-matching edge cases
# ---------------------------------------------------------------------------


class TestPathMatching:

    def test_substring_collision_avoided(self):
        # `src/admin/bulk.py` should not match `oo/bulk.py` or
        # `nadmin/bulk.py`. The merge uses a "/"-anchored suffix
        # match to avoid these collisions.
        ctx = {
            "entry_points": [
                {"id": "EP-1", "file": "src/admin/bulk.py"},
            ],
        }
        # An observed path that has the recorded relative as a
        # SUBSTRING (no "/" boundary) — must NOT match.
        prof = ObserveProfile(
            paths_read=["/abs/repo/oosrc/admin/bulk.py"],
        )
        out = merge_observation_into_context_map(ctx, prof)
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == []

    def test_exact_match_when_no_abs_prefix(self):
        # If observed path equals the recorded relative path
        # (caller already normalised), exact equality matches.
        ctx = {"entry_points": [{"id": "EP-1", "file": "src/x.py"}]}
        prof = ObserveProfile(paths_read=["src/x.py"])
        out = merge_observation_into_context_map(ctx, prof)
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == ["EP-1"]


# ---------------------------------------------------------------------------
# target_dir strict matching — defeats monorepo collisions
# ---------------------------------------------------------------------------


class TestTargetDirStrictMatching:
    """Path correlation in strict mode (target_dir set). Strict mode
    rejects same-named files in sibling directories — the suffix
    heuristic the default mode uses cannot tell them apart, so a
    monorepo with multiple ``src/utils.py`` files would mis-correlate
    every entry point under that name onto every observed read."""

    def test_strict_match_with_target_dir_prefix(self):
        ctx = {
            "entry_points": [
                {"id": "EP-1", "file": "src/routes/query.py"},
            ],
        }
        prof = ObserveProfile(
            paths_read=["/some/repo/src/routes/query.py"],
        )
        out = merge_observation_into_context_map(
            ctx, prof, target_dir="/some/repo",
        )
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == ["EP-1"]

    def test_strict_rejects_sibling_repo_collision(self):
        # Monorepo: target_dir is /work/services/billing. The
        # observed path lives in a SIBLING service that also has
        # src/utils.py — strict mode must NOT correlate.
        ctx = {
            "entry_points": [
                {"id": "EP-1", "file": "src/utils.py"},
            ],
            "meta": {"target": "/work/services/billing"},
        }
        prof = ObserveProfile(
            paths_read=["/work/services/auth/src/utils.py"],
        )
        out = merge_observation_into_context_map(ctx, prof)
        # Default target_dir was pulled from meta.target — strict.
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == []

    def test_strict_rejects_prefix_directory_attack(self):
        # target_dir /repo, observed path /repo-attacker/src/x.py.
        # Without "/"-boundary, /repo-attacker/... starts with "/repo"
        # — strict mode must reject because the boundary char is "-",
        # not "/".
        ctx = {
            "entry_points": [{"id": "EP-1", "file": "src/x.py"}],
        }
        prof = ObserveProfile(
            paths_read=["/repo-attacker/src/x.py"],
        )
        out = merge_observation_into_context_map(
            ctx, prof, target_dir="/repo",
        )
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == []

    def test_meta_target_used_as_default_target_dir(self):
        # When caller doesn't pass target_dir, meta.target from the
        # context map IS the source of truth. Verifies the auto-pull.
        ctx = {
            "entry_points": [{"id": "EP-1", "file": "src/x.py"}],
            "meta": {"target": "/abs/repo"},
        }
        prof = ObserveProfile(paths_read=["/abs/repo/src/x.py"])
        out = merge_observation_into_context_map(ctx, prof)
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == ["EP-1"]

    def test_explicit_target_dir_overrides_meta(self):
        # If both meta.target AND target_dir are set, the kwarg wins
        # — operator override is sticky.
        ctx = {
            "entry_points": [{"id": "EP-1", "file": "src/x.py"}],
            "meta": {"target": "/wrong/repo"},
        }
        prof = ObserveProfile(paths_read=["/right/repo/src/x.py"])
        out = merge_observation_into_context_map(
            ctx, prof, target_dir="/right/repo",
        )
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == ["EP-1"]

    def test_heuristic_mode_kept_for_no_target_dir_no_meta(self):
        # Backward-compat: caller without target_dir AND without
        # meta.target falls through to the suffix heuristic. Tests
        # in TestPathMatching above already cover its semantics; we
        # just check it didn't get accidentally disabled.
        ctx = {"entry_points": [{"id": "EP-1", "file": "src/x.py"}]}
        prof = ObserveProfile(paths_read=["/anywhere/src/x.py"])
        out = merge_observation_into_context_map(ctx, prof)
        # Suffix heuristic finds it.
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["entry_points_runtime_confirmed"] == ["EP-1"]

    def test_strict_match_for_sinks_too(self):
        # Strict mode applies to sink correlation as well, not just
        # entry points.
        ctx = {
            "sink_details": [
                {"id": "SINK-1", "file": "lib/output.py"},
            ],
        }
        prof = ObserveProfile(
            paths_written=["/somewhere-else/lib/output.py"],
        )
        out = merge_observation_into_context_map(
            ctx, prof, target_dir="/repo",
        )
        # Strict: observed not under /repo → no correlation.
        assert out[RUNTIME_OBSERVATION_KEY][
            "correlations"]["sinks_runtime_confirmed"] == []


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadataCarried:

    def test_binary_recorded(self):
        out = merge_observation_into_context_map(
            _ctx(), _profile(), binary="/usr/local/bin/probe",
        )
        assert out[RUNTIME_OBSERVATION_KEY]["binary"] == \
            "/usr/local/bin/probe"

    def test_command_recorded(self):
        out = merge_observation_into_context_map(
            _ctx(), _profile(),
            command=("/probe", "--once", "x"),
        )
        assert out[RUNTIME_OBSERVATION_KEY]["command"] == [
            "/probe", "--once", "x",
        ]

    def test_captured_at_default_is_iso8601_zulu(self):
        out = merge_observation_into_context_map(_ctx(), _profile())
        ts = out[RUNTIME_OBSERVATION_KEY]["captured_at"]
        # YYYY-MM-DDThh:mm:ssZ
        assert ts.endswith("Z")
        assert len(ts) == 20

    def test_captured_at_override_passed_through(self):
        out = merge_observation_into_context_map(
            _ctx(), _profile(),
            captured_at="2026-05-08T00:00:00Z",
        )
        assert out[RUNTIME_OBSERVATION_KEY]["captured_at"] == \
            "2026-05-08T00:00:00Z"


# ---------------------------------------------------------------------------
# Round-trip via JSON to lock the on-disk shape
# ---------------------------------------------------------------------------


class TestJsonRoundTrip:

    def test_full_payload_serialises_cleanly(self):
        out = merge_observation_into_context_map(
            _ctx(), _profile(),
            binary="/usr/bin/probe",
            command=("/usr/bin/probe", "--x"),
            captured_at="2026-05-08T00:00:00Z",
        )
        s = json.dumps(out)
        loaded = json.loads(s)
        # Spot-check key fields survive.
        obs = loaded[RUNTIME_OBSERVATION_KEY]
        assert obs["binary"] == "/usr/bin/probe"
        assert obs["paths_read"][0] == "/some/repo/src/routes/query.py"
        assert obs["connect_targets"][0]["ip"] == "1.2.3.4"
        assert obs["correlations"]["entry_points_runtime_confirmed"] == [
            "EP-001",
        ]
