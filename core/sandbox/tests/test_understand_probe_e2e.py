"""End-to-end test for the documented /understand --probe flow.

The MAP-7 step in ``.claude/skills/code-understanding/map.md``
describes a workflow:

  1. operator runs ``/understand --map`` to produce
     ``$WORKDIR/context-map.json`` (a static model of the codebase
     with entry points + sinks + trust boundaries);
  2. operator runs ``raptor-sandbox-observe --json --out $WORKDIR/probe
     -- /path/to/binary [args]`` to produce ``probe.json`` with the
     binary's runtime reach;
  3. operator merges via
     ``core.sandbox.observe_context_merge.merge_observation_into_context_map``;
  4. resulting context-map.json gets a ``runtime_observation`` key
     with correlations against entry points + sinks.

This test runs the FULL flow end-to-end on Linux:

  * builds a synthetic project tree with files corresponding to a
    set of entry points and sinks;
  * spawns ``/bin/cat`` against one of the source files via
    ``sandbox(observe=True)``;
  * loads the resulting profile from JSONL;
  * merges into a synthetic context map with target_dir set;
  * asserts the correlation surfaces the EXPECTED entry point ID
    and not unrelated ones.

Without this test, the merge-utility unit tests cover the dataclass
plumbing but never confirm the full skill workflow produces useful
signal at scale.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux ptrace + seccomp tracer — observe is Linux-only here",
)
class TestUnderstandProbeFlowE2E(unittest.TestCase):

    def setUp(self):
        from core.sandbox.probes import check_net_available
        from core.sandbox.seccomp import check_seccomp_available
        from core.sandbox.ptrace_probe import check_ptrace_available
        if not (check_net_available()
                and check_seccomp_available()
                and check_ptrace_available()):
            self.skipTest("observe prerequisites unavailable")

    def test_full_probe_flow_correlates_entry_points(self):
        from core.sandbox import run as sandbox_run
        from core.sandbox.observe_profile import (
            parse_observe_log,
        )
        from core.sandbox.observe_context_merge import (
            RUNTIME_OBSERVATION_KEY,
            merge_observation_into_context_map,
        )

        with TemporaryDirectory() as d:
            project = Path(d) / "myapp"
            (project / "src" / "routes").mkdir(parents=True)
            (project / "src" / "admin").mkdir(parents=True)
            (project / "src" / "db").mkdir(parents=True)

            # Entry-point files (read by the binary).
            ep_query = project / "src" / "routes" / "query.py"
            ep_query.write_text("# query handler\n")
            ep_admin = project / "src" / "admin" / "bulk.py"
            ep_admin.write_text("# admin endpoint\n")

            # Sink file (would be opened for write — we won't probe
            # this one, so it should NOT show up confirmed).
            sink_db = project / "src" / "db" / "query.py"
            sink_db.write_text("# db sink\n")

            # Synthetic context map — what /understand --map would
            # produce, with relative paths and meta.target.
            context_map = {
                "meta": {"target": str(project), "app_type": "test"},
                "entry_points": [
                    {"id": "EP-QUERY", "type": "http_route",
                     "file": "src/routes/query.py", "line": 1},
                    {"id": "EP-ADMIN", "type": "http_route",
                     "file": "src/admin/bulk.py", "line": 1},
                ],
                "sink_details": [
                    {"id": "SINK-DB", "type": "db_query",
                     "file": "src/db/query.py", "line": 1},
                ],
            }

            # Probe: /bin/cat reading the query entry-point file.
            # cat's filesystem reach: libc + ld.so + the file we
            # ask it to read. The "binary actually opened
            # src/routes/query.py" signal is what we want to
            # correlate against EP-QUERY.
            with TemporaryDirectory() as run_d:
                run_dir = Path(run_d) / "probe"
                run_dir.mkdir()
                # output= cannot be inside target= when target is
                # bind-mounted read-only — give them separate dirs.
                # The cat command needs target/ visible.
                result = sandbox_run(
                    ["/bin/cat", str(ep_query)],
                    target=str(project),
                    output=str(run_dir),
                    observe=True,
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(
                    result.returncode, 0,
                    f"cat should succeed; stderr={result.stderr!r}",
                )

                nonce = result.sandbox_info.get("observe_nonce")
                if nonce is None:
                    self.skipTest("audit didn't engage")

                profile = parse_observe_log(
                    run_dir, expected_nonce=nonce,
                )

                # Merge — auto-pulls target_dir from meta.target.
                merged = merge_observation_into_context_map(
                    context_map, profile,
                    binary="/bin/cat",
                    command=["/bin/cat", str(ep_query)],
                )

                obs = merged[RUNTIME_OBSERVATION_KEY]

                # The probed file's path is in paths_read.
                # Tracer records absolute paths; assert presence
                # of the absolute form OR the relative-stripped
                # form (parser passes both through).
                self.assertTrue(
                    str(ep_query) in profile.paths_read
                    or "src/routes/query.py" in profile.paths_read,
                    f"probe didn't record reading {ep_query}; "
                    f"paths_read={profile.paths_read!r}",
                )

                # EP-QUERY runtime-confirmed; EP-ADMIN not.
                confirmed = obs["correlations"][
                    "entry_points_runtime_confirmed"]
                self.assertIn(
                    "EP-QUERY", confirmed,
                    f"expected EP-QUERY runtime-confirmed; got "
                    f"{confirmed!r}",
                )
                self.assertNotIn(
                    "EP-ADMIN", confirmed,
                    f"EP-ADMIN was not probed; runtime confirmation "
                    f"is a false positive",
                )

                # SINK-DB was not probed for write. Should not be
                # confirmed.
                sinks_confirmed = obs["correlations"][
                    "sinks_runtime_confirmed"]
                self.assertEqual(
                    sinks_confirmed, [],
                    "no sinks were probed; runtime confirmation "
                    "is a false positive",
                )

                # connect_targets should be empty for /bin/cat —
                # confirms the parser doesn't false-positive on
                # other syscalls.
                self.assertEqual(
                    obs["connect_targets"], [],
                    "cat doesn't network",
                )

                # Round-trip through JSON to confirm the merged
                # context map is serialisable (operators write it
                # back to context-map.json).
                serialised = json.dumps(merged)
                loaded = json.loads(serialised)
                self.assertEqual(
                    loaded[RUNTIME_OBSERVATION_KEY]["binary"],
                    "/bin/cat",
                )


if __name__ == "__main__":
    unittest.main()
