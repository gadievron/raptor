"""Isolated interpreters on the SAGE boot-payload consent lane.

The install-capture display, the review/approve ceremony, the drift
check and the enforcement wrapper all spawn ``python3`` children whose
output decides what an operator is shown and what gets stamped
authorized. An interpreter-startup hook (a PYTHONPATH sitecustomize,
or a user-site ``.pth``/``usercustomize.py`` — the latter with zero
environment variables set) runs before any of that code and could
skew the display against the stamp. Every consent-lane call site
therefore invokes ``python3 -I`` (isolated mode: PYTHON* ignored,
user site never enabled), so the hook never loads at all.

Pinned here, both directions:

* every python3 invocation site in ``libexec/raptor-sage-setup``
  either carries ``-I`` or is one of the declared ambient sites —
  the sage_sdk prerequisite probe, knowledge seeding and agent
  registration legitimately resolve pip-installed (possibly
  ``pip --user``) packages, carry no consent authority, and MUST NOT
  gain ``-I`` silently (it would break user-site installs);
* the MCP wrapper execs the enforcement guard with ``-I``;
* behaviourally: the reviewer runs correctly under ``-I`` and a
  PYTHONPATH sitecustomize never loads into it.

The guard script's own isolation (shebang + re-exec guard) is covered
by .github/tests/test_libexec_marker_coverage.py and
test_interpreter_isolation.py.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SAGE_SETUP = REPO / "libexec" / "raptor-sage-setup"
SAGE_MCP = REPO / "libexec" / "raptor-sage-mcp"
REVIEWER = REPO / "core" / "sage" / "boot_payload_review.py"

# A python3 invocation site: `python3` followed by an option, a quoted
# path, or a variable — prose mentions ("python3," in help text,
# `need python3`) don't match.
_INVOCATION_RE = re.compile(r"python3\s+[-\"'$]")

# Ambient-env sites, by distinctive line content. Each must match
# exactly one invocation line; a new python3 site matches neither
# table and fails until it is classified.
AMBIENT_ALLOWED: dict[str, str] = {
    'python3 -c "import sage_sdk"': (
        "prerequisite probe: must see the operator's real package "
        "resolution, user site included"
    ),
    'python3 "$seed_script"': (
        "knowledge seeding imports sage_sdk from the ambient "
        "(possibly pip --user) install; no consent authority"
    ),
    'python3 "$register_script"': (
        "agent registration imports sage_sdk from the ambient "
        "(possibly pip --user) install; no consent authority"
    ),
}


def _invocation_lines() -> list[str]:
    lines = []
    for raw in SAGE_SETUP.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        if _INVOCATION_RE.search(stripped):
            lines.append(stripped)
    return lines


class TestSageSetupCallSites:
    def test_every_invocation_is_isolated_or_declared_ambient(self):
        unclassified = []
        for line in _invocation_lines():
            if "python3 -I" in line:
                continue
            if any(key in line for key in AMBIENT_ALLOWED):
                continue
            unclassified.append(line)
        assert unclassified == [], (
            "unclassified python3 site(s) in raptor-sage-setup — a "
            "consent-lane child takes -I, a package-resolving install "
            "step joins AMBIENT_ALLOWED with its reason:\n"
            + "\n".join(unclassified)
        )

    def test_ambient_table_rows_are_live_and_unique(self):
        """A stale allowlist row (site removed or since isolated) must
        fail too, so the table cannot rot."""
        lines = _invocation_lines()
        problems = []
        for key in AMBIENT_ALLOWED:
            hits = [ln for ln in lines if key in ln]
            if len(hits) != 1:
                problems.append(f"{key!r}: {len(hits)} matching site(s)")
                continue
            if "python3 -I" in hits[0]:
                problems.append(
                    f"{key!r}: site now isolated — drop the table row"
                )
        assert problems == [], "\n".join(problems)

    def test_consent_lane_carries_isolated_sites(self):
        """The named consent-lane children really are the -I carriers
        (guards against a refactor that deletes the sites and
        vacuously passes the closure above)."""
        text = SAGE_SETUP.read_text(encoding="utf-8")
        for fragment in (
            'python3 -I "$reviewer" compare',
            'python3 -I "$reviewer" tools-digest',
            'python3 -I "$reviewer" show-tool',
            'python3 -I "$reviewer" strip-tools',
            'python3 -I "$reviewer" "$decision"',
            'RAPTOR_DIR="$RAPTOR_DIR" python3 -I -c',
        ):
            assert fragment in text, f"missing consent-lane site: {fragment}"


class TestMcpWrapper:
    def test_guard_exec_is_isolated(self):
        text = SAGE_MCP.read_text(encoding="utf-8")
        assert (
            'exec python3 -I "$RAPTOR_DIR/libexec/raptor-sage-mcp-guard"'
            in text
        ), "the wrapper must exec the enforcement guard under -I"


class TestReviewerUnderIsolation:
    def _env(self, tmp: Path, **extra: str) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(tmp),
        }
        env.update(extra)
        return env

    def test_reviewer_works_and_hook_never_loads(self, tmp_path):
        tripwire = tmp_path / "tripwire"
        (tmp_path / "sitecustomize.py").write_text(
            "with open({0!r}, 'a', encoding='utf-8') as fh:\n"
            "    fh.write('loaded\\n')\n".format(str(tripwire)),
            encoding="utf-8",
        )
        capture = tmp_path / "capture"
        body = (
            "### initialize.instructions\n"
            "hello operator\n"
            "### sage_inception.message\n"
            "welcome\n"
        )
        capture.write_text(body, encoding="utf-8")
        proc = subprocess.run(
            ["python3", "-I", str(REVIEWER), "strip-tools",
             "--live", str(capture)],
            capture_output=True, text=True, timeout=60,
            env=self._env(tmp_path, PYTHONPATH=str(tmp_path)),
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == body  # byte-preserving split, no tools
        assert not tripwire.exists(), (
            "python3 -I still loaded a PYTHONPATH sitecustomize"
        )
