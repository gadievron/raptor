"""Identity lints for the deliberately-inline libexec/bin surfaces.

Why this test exists
--------------------
The trust-marker check is intentionally inlined in every libexec
script (not factored into a shared helper) so it cannot be subverted
by a single helper-module compromise and so it remains visible at the
top of every script during code review. The same reasoning covers the
other launcher-preamble surfaces: the bounded symlink-resolution loop,
the dangerous-env-strip sourcing line, and the
sys.path-then-process_init setup pair.

The cost of that decision is copy drift: the 72 trust-marker copies had
diverged into 13 hash-distinct bodies before these lints existed. This
module therefore pins two properties per surface:

* coverage — every script that must carry a surface carries it (a new
  script missing the block fails here), and
* identity — every copy matches ONE golden template byte-for-byte,
  modulo the explicitly declared per-script parameterization below
  (hint text, hop-loop label/exit-code, env-strip root variable).

Anything else is drift: fix the script, or — if the divergence is
genuinely intentional — add an explicit entry to the relevant table in
a reviewed change. Do not loosen the matching.

The protective lint markers are part of the golden templates: the
two-line ``# ruff: noqa`` prologue, the ``# fmt: off/on`` fence and the
``# noqa: E402`` inside the trust block exist so autofixers cannot
restructure the blocks (see RuffImmunityTests, which proves it against
whatever ruff is installed). Adding or removing a marker is drift too.

The inline faulthandler stanzas that used to precede the trust block
were deleted (dedup programme §D): core.startup.process_init — imported
by every python libexec script — enables faulthandler and registers the
SIGUSR1 stack dump, with the stderr-fileno guard the inline copies
lacked. FaulthandlerStanzaTests bans reintroduction; the two
``python3 -I`` sandbox shims (isolated mode — cannot import core.*)
keep an identity-pinned inline stanza by design.

Out of scope here: the runtime behaviour of the surfaces (covered by
the CLI tests and test_symlink_hop_bound.py).
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects libexec/ in its own
# worktree (RAPTOR_DIR may point at a different checkout).
REPO = Path(__file__).resolve().parents[2]
LIBEXEC = REPO / "libexec"
BIN = REPO / "bin"

_SENTINEL = "# ─── trust-marker check"
_END_SENTINEL = "─── end trust-marker check"
_TRUST_VARS = ("CLAUDECODE", "_RAPTOR_TRUSTED")

_HINT = "@HINT@"


# ─── golden templates ────────────────────────────────────────────────
# Extracted from the reconciled scripts; the only allowed per-script
# variation is the @HINT@ substitution declared in the tables below.

PY_TRUST_TEMPLATE = r'''# ─── trust-marker check (do not import; inline by design) ───
# fmt: off
import os  # noqa: E402
if not (os.environ.get("CLAUDECODE")
        or os.environ.get("_RAPTOR_TRUSTED")):
    sys.stderr.write(
        f"{sys.argv[0]}: internal dispatch script.\n"
        "  Run via '@HINT@' instead.\n"
        "  Tests / power users: set _RAPTOR_TRUSTED=1 to bypass.\n"
    )
    sys.exit(2)
# fmt: on
# ─── end trust-marker check ─────────────────────────────────'''

# Per-script hint (the command the refusal message redirects to).
# Default: bin/raptor.
PY_TRUST_HINTS = {
    "raptor-binary": "bin/raptor binary",
    "raptor-cve-diff": "bin/cve-diff",
    "raptor-cve-env": "bin/cve-env",
    "raptor-sca-run": "bin/raptor-sca",
}

# Whole-block singletons: bespoke by documented design (raptor-r2-
# sandboxed is invoked by r2pipe via R2PIPE_R2, not by operators, and
# uses the wrapper exit-code constant). Still identity-pinned.
PY_TRUST_SINGLETONS = {
    "raptor-r2-sandboxed": r'''# ─── trust-marker check (libexec convention) ───────────────
# fmt: off
import os  # noqa: E402

# Inline before any RAPTOR import (matches raptor-run-sandboxed,
# raptor-binary) so a malicious PYTHONPATH can't hijack
# core.* imports before the check fires. This script is invoked
# indirectly by r2pipe (via R2PIPE_R2 env), not by humans directly;
# unguarded invocation typically means a caller misconfiguration.
if not (os.environ.get("CLAUDECODE")
        or os.environ.get("_RAPTOR_TRUSTED")):
    sys.stderr.write(
        f"{sys.argv[0]}: internal dispatch script.\n"
        "  Set R2PIPE_R2 to this script's path and r2pipe will invoke "
        "it transparently (radare2_understand.analyse does this).\n"
        "  Tests / power users: set _RAPTOR_TRUSTED=1 to bypass.\n"
    )
    sys.exit(_RC_WRAPPER_TRUST_MISSING)
# fmt: on
# ─── end trust-marker check ────────────────────────────────''',
}

BASH_TRUST_TEMPLATE = r'''# ─── trust-marker check (do not source; inline by design) ───
if [ -z "${CLAUDECODE:-}" ] && [ -z "${_RAPTOR_TRUSTED:-}" ]; then
    echo "$0: internal dispatch script." >&2
    echo "  Run via '@HINT@' instead." >&2
    echo "  Tests / power users: set _RAPTOR_TRUSTED=1 to bypass." >&2
    exit 2
fi
# ─── end trust-marker check ─────────────────────────────────'''

BASH_TRUST_HINTS = {
    "raptor-frida": "bin/raptor frida",
}

# Two-line file prologue on every python libexec script. RUF100 off
# keeps `ruff check --fix` from stripping the deliberate noqa markers
# under configs where E402 is disabled; I001 off keeps import
# re-sorting away from the deliberately ordered preamble.
PY_PROLOGUE = (
    "# ruff: noqa: RUF100, I001",
    "# (preamble protection; see .github/tests/test_libexec_marker_coverage.py)",
)

# ─── sys.path preamble ───────────────────────────────────────────────

SYSPATH_INSERT = "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))"

# Named-root form: scripts that need the repo root elsewhere in the
# file bind it once and insert the binding. Accepted as canonical only
# when the bound expression is byte-identical to the majority insert's.
_NAMED_ROOT_BIND_RE = re.compile(
    r"^([A-Z][A-Z0-9_]*) = Path\(__file__\)\.resolve\(\)\.parents\[1\]$"
)
_NAMED_ROOT_INSERT_RE = re.compile(
    r"^sys\.path\.insert\(0, str\(([A-Z][A-Z0-9_]*)\)\)$"
)


def _named_root_insert_index(lines):
    """Index of a canonical named-root sys.path insert, or None.

    Matches exactly one insert of the form
    ``sys.path.insert(0, str(REPO_ROOT))`` preceded by
    ``REPO_ROOT = Path(__file__).resolve().parents[1]`` (any
    ALL_CAPS name), at top level.
    """
    inserts = [
        (i, ln) for i, ln in enumerate(lines)
        if "sys.path.insert" in ln
    ]
    if len(inserts) != 1:
        return None
    idx, line = inserts[0]
    m = _NAMED_ROOT_INSERT_RE.match(line.strip())
    if m is None or line != line.strip():
        return None
    var = m.group(1)
    for ln in lines[:idx]:
        b = _NAMED_ROOT_BIND_RE.match(ln)
        if b is not None and b.group(1) == var:
            return idx
    return None

PROCESS_INIT = "import core.startup.process_init  # noqa: E402,F401"

# Scripts whose repo-root resolution deliberately deviates from the
# majority one-liner (named root variable reused later, second package
# path, conditional insert, embedded child snippet). Values are the
# exact sys.path.insert-carrying lines, stripped, in file order.
SYSPATH_VARIANTS = {
    "raptor-audit": ("sys.path.insert(0, str(_RAPTOR_DIR))",),
    "raptor-binary-oracle-e2e": ("sys.path.insert(0, str(RAPTOR))",),
    "raptor-bq-query": ("sys.path.insert(0, str(_RAPTOR_ROOT))",),
    "raptor-cve-diff": (
        "sys.path.insert(0, str(_RAPTOR_DIR))",
        'sys.path.insert(0, str(_RAPTOR_DIR / "packages" / "cve_diff"))',
    ),
    "raptor-cve-env": (
        "sys.path.insert(0, str(_RAPTOR_DIR))",
        'sys.path.insert(0, str(_RAPTOR_DIR / "packages" / "cve_env"))',
    ),
    "raptor-enrich-context-map-frida": ("sys.path.insert(0, str(_RAPTOR_DIR))",),
    "raptor-enrich-context-map-mitigation": ("sys.path.insert(0, str(_ROOT))",),
    "raptor-lifecycle-hook": ("sys.path.insert(0, str(REPO_ROOT))",),
    "raptor-migrate-journal": ("sys.path.insert(0, str(REPO))",),
    "raptor-r2-sandboxed": ("sys.path.insert(0, str(_RAPTOR_DIR))",),
    "raptor-self-test": (
        "sys.path.insert(0, str(_RAPTOR_DIR))",
        # embedded tool-sandbox-matrix harness child snippet — the
        # child's repo root arrives via the trusted spec argument (the
        # harness also pins the child's RAPTOR_DIR from the same spec).
        'sys.path.insert(0, spec["raptor_dir"])',
        # embedded egress-deny harness child snippet — hard lookup of
        # RAPTOR_DIR (KeyError if unset), the sanctioned sys.path form;
        # the parent case pins RAPTOR_DIR before spawning it.
        'sys.path.insert(0, os.environ["RAPTOR_DIR"])',
    ),
    "raptor-run-sandboxed": ("sys.path.insert(0, raptor_dir)",),
    "raptor-sca-refit-calibration": ("sys.path.insert(0, str(_REPO_ROOT))",),
    "raptor-sca-run": ("sys.path.insert(0, str(_REPO))",),
    "raptor-session-init": (
        "sys.path.insert(0, str(REPO_ROOT))",
        # embedded python3 -c child snippet (mandated RAPTOR_DIR pattern)
        '"import sys,os;sys.path.insert(0,os.environ[\'RAPTOR_DIR\']);"',
    ),
}

# The two `python3 -I` sandbox shims: isolated mode, no repo imports,
# no sys.path mutation, no process_init — by design.
NO_SYSPATH_PREAMBLE = {"raptor-pid1-shim", "raptor-seatbelt-shim"}

# ─── faulthandler ────────────────────────────────────────────────────

# Inline faulthandler stanzas are banned: the process_init import that
# SyspathPreambleIdentityTests already requires on every python script
# enables faulthandler and registers the SIGUSR1 stack dump (with the
# stderr-fileno guard the deleted inline copies lacked). The only
# permitted carriers are the two `python3 -I` sandbox shims — isolated
# mode means no repo sys.path, so they cannot import
# core.startup.process_init and keep the stanza inline by design.
FAULTHANDLER_INLINE_SHIMS = {"raptor-pid1-shim", "raptor-seatbelt-shim"}

FAULTHANDLER_STANZA = '''faulthandler.enable()
if hasattr(signal, "SIGUSR1"):
    faulthandler.register(signal.SIGUSR1, all_threads=True, file=sys.stderr)'''

# ─── bash surfaces (keyed by path relative to repo root) ─────────────

# Bounded symlink-resolution loop instances. Value: list of loop
# specs in file order; a spec is either (label, exit_code, extra_lines)
# for the canonical SCRIPT/DIR loop, or an exact block string for the
# declared singletons. Behavioural coverage (the loop really
# terminates on a cycle) lives in test_symlink_hop_bound.py.
_CC_TRUST_EXTRA_ECHO = (
    '        echo "  (likely a symlink cycle; refusing to resolve further)" >&2'
)

SYMLINK_LOOPS = {
    "bin/cve-diff": [("cve-diff", 1, ())],
    "bin/cve-env": [("cve-env", 1, ())],
    "bin/raptor": [
        # main self-resolution loop: `command -p` so dirname/readlink
        # resolve via the system default PATH, immune to a hostile
        # ambient PATH before the scrub runs — and self-contained
        # under behavioural extraction (no helper functions).
        r'''SCRIPT="$0"
_symhops=0
while [ -L "$SCRIPT" ]; do
    _symhops=$((_symhops + 1))
    if [ "$_symhops" -gt 32 ]; then
        echo "raptor: symlink hop limit exceeded resolving $0" >&2
        exit 1
    fi
    DIR="$(cd "$(command -p dirname "$SCRIPT")" && pwd)"
    SCRIPT="$(command -p readlink "$SCRIPT")"
    [[ "$SCRIPT" != /* ]] && SCRIPT="$DIR/$SCRIPT"
done
unset _symhops''',
        # env-strip self-resolution loop: namespaced variables because
        # it runs in the operator's launcher scope before RAPTOR_DIR
        # exists; cd -P + BASH_SOURCE by design (BSD readlink lacks -f).
        r'''_raptor_self="${BASH_SOURCE[0]}"
_symhops=0
while [ -L "$_raptor_self" ]; do
    _symhops=$((_symhops + 1))
    if [ "$_symhops" -gt 32 ]; then
        echo "raptor: symlink hop limit exceeded resolving $0" >&2
        exit 1
    fi
    _raptor_link_dir="$(cd -P "$(dirname "$_raptor_self")" && pwd)"
    _raptor_self="$(readlink "$_raptor_self")"
    [[ "$_raptor_self" != /* ]] && _raptor_self="$_raptor_link_dir/$_raptor_self"
done
unset _symhops''',
    ],
    "bin/raptor-sca": [("raptor-sca", 1, ())],
    "libexec/raptor-agentic": [("raptor-agentic", 1, ())],
    "libexec/raptor-cc-trust-check": [
        ("raptor-cc-trust-check", 3, (_CC_TRUST_EXTRA_ECHO,)),
    ],
    "libexec/raptor-frida": [("raptor-frida", 1, ())],
    "libexec/raptor-llm-scorecard": [("raptor-llm-scorecard", 1, ())],
    "libexec/raptor-sage-mcp": [("raptor-sage-mcp", 3, ())],
    "libexec/raptor-sage-setup": [("raptor-sage-setup", 3, ())],
    "libexec/raptor-threat-model": [("raptor-threat-model", 1, ())],
}

# Dangerous-env-strip sourcing line per carrier. The root-variable
# prefix is the per-script parameter (llm-scorecard resolves REPO_ROOT;
# bin/raptor sources before RAPTOR_DIR exists).
ENV_STRIP_LINES = {
    "bin/cve-diff": '. "$RAPTOR_DIR/core/security/_dangerous_env_strip.sh"',
    "bin/cve-env": '. "$RAPTOR_DIR/core/security/_dangerous_env_strip.sh"',
    "bin/raptor": '. "$_raptor_self_dir/../core/security/_dangerous_env_strip.sh"',
    "bin/raptor-sca": '. "$RAPTOR_DIR/core/security/_dangerous_env_strip.sh"',
    "libexec/raptor-agentic": '. "$RAPTOR_DIR/core/security/_dangerous_env_strip.sh"',
    "libexec/raptor-frida": '. "$RAPTOR_DIR/core/security/_dangerous_env_strip.sh"',
    "libexec/raptor-llm-scorecard": '. "$REPO_ROOT/core/security/_dangerous_env_strip.sh"',
    "libexec/raptor-threat-model": '. "$RAPTOR_DIR/core/security/_dangerous_env_strip.sh"',
}

# Bash scripts that do not exec python3 with ambient env and carry no
# strip by design (current state, pinned so a change is a decision).
NO_ENV_STRIP = {
    "libexec/raptor-cc-trust-check",
    "libexec/raptor-sage-mcp",
    "libexec/raptor-sage-setup",
}


def _symlink_block(label: str, exit_code: int, extra: tuple = ()) -> str:
    lines = [
        'SCRIPT="$0"',
        "_symhops=0",
        'while [ -L "$SCRIPT" ]; do',
        "    _symhops=$((_symhops + 1))",
        '    if [ "$_symhops" -gt 32 ]; then',
        f'        echo "{label}: symlink hop limit exceeded resolving $0" >&2',
        *extra,
        f"        exit {exit_code}",
        "    fi",
        '    DIR="$(cd "$(dirname "$SCRIPT")" && pwd)"',
        '    SCRIPT="$(readlink "$SCRIPT")"',
        '    [[ "$SCRIPT" != /* ]] && SCRIPT="$DIR/$SCRIPT"',
        "done",
        "unset _symhops",
    ]
    return "\n".join(lines)


def _libexec_scripts() -> list[Path]:
    """All `libexec/raptor-*` files (excluding test dir + caches)."""
    out = []
    for p in sorted(LIBEXEC.glob("raptor-*")):
        if p.is_dir():
            continue
        out.append(p)
    return out


def _shebang(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()[0]


def _python_scripts() -> list[Path]:
    return [p for p in _libexec_scripts() if "python" in _shebang(p)]


def _bash_scripts() -> list[Path]:
    """Bash scripts under both bin/ and libexec/."""
    out = [p for p in sorted(BIN.iterdir()) if p.is_file() and "bash" in _shebang(p)]
    out += [p for p in _libexec_scripts() if "bash" in _shebang(p)]
    return out


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO))


def _trust_block(text: str) -> str | None:
    """The sentinel-delimited trust block, or None when malformed."""
    lines = text.splitlines()
    starts = [
        i for i, ln in enumerate(lines)
        if _SENTINEL in ln and "end" not in ln
    ]
    ends = [i for i, ln in enumerate(lines) if _END_SENTINEL in ln]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        return None
    return "\n".join(lines[starts[0] : ends[0] + 1])


def _symhops_blocks(text: str) -> list[str]:
    """Every `_symhops=0` block: init-var line through unset line."""
    lines = text.splitlines()
    blocks = []
    for i, ln in enumerate(lines):
        if ln.strip() != "_symhops=0":
            continue
        j = next(
            k for k in range(i, len(lines))
            if lines[k].strip() == "unset _symhops"
        )
        blocks.append("\n".join(lines[i - 1 : j + 1]))
    return blocks


class LibexecMarkerCoverageTests(unittest.TestCase):
    """Every libexec/raptor-* script must inline the trust-marker check."""

    def test_at_least_one_libexec_script_exists(self):
        """Sanity — guards against the test silently passing on a broken
        worktree where libexec/ is empty.
        """
        self.assertGreater(len(_libexec_scripts()), 0,
                           msg="no libexec scripts discovered")

    def test_every_script_has_sentinel_comment(self):
        """The sentinel comment opens (and closes) the check block."""
        missing = []
        for path in _libexec_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            if _SENTINEL not in text:
                missing.append(path.name)
        self.assertEqual(
            missing, [],
            msg=(
                "These libexec scripts are missing the inline trust-marker "
                "check. Paste the block from any existing script (search "
                "for `# ─── trust-marker check`).\nMissing: "
                + ", ".join(missing)
            ),
        )

    def test_check_references_all_trust_vars(self):
        """The check must gate on every documented trust marker.

        Catches drift like: someone adds a new marker to docs/CONTRIBUTING
        but forgets to update some scripts. All scripts must check the
        same set.
        """
        problems = []
        for path in _libexec_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            if _SENTINEL not in text:
                continue  # covered by the sentinel test above
            missing_vars = [v for v in _TRUST_VARS if v not in text]
            if missing_vars:
                problems.append(f"{path.name}: missing {missing_vars}")
        self.assertEqual(
            problems, [],
            msg="trust-marker checks reference incomplete env-var sets:\n"
                + "\n".join(problems),
        )

    def test_check_appears_near_top(self):
        """The check must run before any meaningful work — i.e., before
        ``sys.path`` is mutated (if any) and before non-stdlib imports.

        Heuristic: the sentinel must appear within the first 100 lines.
        That's loose enough to permit long module docstrings (raptor-
        pid1-shim has a 60-line one and lands at line ~80) but tight
        enough to catch a check accidentally pushed to the bottom of
        the file.
        """
        late = []
        for path in _libexec_scripts():
            lines = path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
            for i, line in enumerate(lines, 1):
                if _SENTINEL in line:
                    if i > 100:
                        late.append(f"{path.name}: line {i}")
                    break
        self.assertEqual(
            late, [],
            msg="trust-marker checks appear too late in these scripts "
                "(must be within first 100 lines):\n" + "\n".join(late),
        )


class TrustBlockIdentityTests(unittest.TestCase):
    """Every trust-marker block matches its golden template exactly."""

    def test_python_blocks_match_golden_template(self):
        problems = []
        for path in _python_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            block = _trust_block(text)
            if block is None:
                problems.append(
                    f"{path.name}: malformed block (need exactly one start "
                    "and one end sentinel, in order)"
                )
                continue
            if path.name in PY_TRUST_SINGLETONS:
                expected = PY_TRUST_SINGLETONS[path.name]
            else:
                hint = PY_TRUST_HINTS.get(path.name, "bin/raptor")
                expected = PY_TRUST_TEMPLATE.replace(_HINT, hint)
            if block != expected:
                problems.append(f"{path.name}: block deviates from template")
        self.assertEqual(
            problems, [],
            msg=(
                "python trust-marker blocks drifted from the golden "
                "template (copy it verbatim from PY_TRUST_TEMPLATE in "
                "this test; per-script hints go in PY_TRUST_HINTS):\n"
                + "\n".join(problems)
            ),
        )

    def test_bash_blocks_match_golden_template(self):
        problems = []
        for path in _bash_scripts():
            if _rel(path).startswith("bin/"):
                continue  # covered by test_bin_entry_points_carry_no_gate
            text = path.read_text(encoding="utf-8", errors="replace")
            block = _trust_block(text)
            if block is None:
                problems.append(f"{path.name}: malformed or missing block")
                continue
            hint = BASH_TRUST_HINTS.get(path.name, "bin/raptor")
            expected = BASH_TRUST_TEMPLATE.replace(_HINT, hint)
            if block != expected:
                problems.append(f"{path.name}: block deviates from template")
        self.assertEqual(
            problems, [],
            msg=(
                "bash trust-marker blocks drifted from the golden template "
                "(BASH_TRUST_TEMPLATE; per-script hints in "
                "BASH_TRUST_HINTS):\n" + "\n".join(problems)
            ),
        )

    def test_bin_entry_points_carry_no_gate(self):
        """bin/ scripts are the operator entry points the refusal message
        redirects to — a trust gate there would lock operators out.
        """
        offenders = [
            _rel(p)
            for p in sorted(BIN.iterdir())
            if p.is_file()
            and _SENTINEL in p.read_text(encoding="utf-8", errors="replace")
        ]
        self.assertEqual(offenders, [],
                         msg=f"trust-marker gate on bin/ entry points: "
                             f"{offenders}")

    def test_python_prologue_protection_lines(self):
        """Lines 2-3 of every python script are the protection prologue."""
        problems = []
        for path in _python_scripts():
            lines = path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
            if tuple(lines[1:3]) != PY_PROLOGUE:
                problems.append(path.name)
        self.assertEqual(
            problems, [],
            msg=(
                "python scripts without the exact two-line protection "
                "prologue after the shebang (PY_PROLOGUE):\n"
                + "\n".join(problems)
            ),
        )


class SyspathPreambleIdentityTests(unittest.TestCase):
    """Repo-root sys.path setup + process_init import, one spelling."""

    def test_preamble_matches_declared_form(self):
        problems = []
        for path in _python_scripts():
            lines = path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
            inserts = [ln.strip() for ln in lines if "sys.path.insert" in ln]
            pi_lines = [
                ln for ln in lines
                if ln.startswith("import core.startup.process_init")
            ]
            name = path.name
            if name in NO_SYSPATH_PREAMBLE:
                if inserts or pi_lines:
                    problems.append(
                        f"{name}: -I shim must not touch sys.path or "
                        f"import process_init (found {inserts + pi_lines})"
                    )
                continue
            if pi_lines != [PROCESS_INIT]:
                problems.append(
                    f"{name}: process_init import must appear exactly once "
                    f"as {PROCESS_INIT!r} (found {pi_lines})"
                )
                continue
            if name in SYSPATH_VARIANTS:
                if tuple(inserts) != SYSPATH_VARIANTS[name]:
                    problems.append(
                        f"{name}: sys.path lines deviate from the declared "
                        f"variant (found {inserts})"
                    )
                continue
            if inserts == [SYSPATH_INSERT]:
                i = lines.index(SYSPATH_INSERT)
            else:
                named = _named_root_insert_index(lines)
                if named is None:
                    problems.append(
                        f"{name}: expected the majority insert "
                        f"{SYSPATH_INSERT!r} or the named-root form "
                        "(NAME = Path(__file__).resolve().parents[1]; "
                        "sys.path.insert(0, str(NAME))) "
                        f"(found {inserts}); genuinely variant scripts "
                        "must be declared in SYSPATH_VARIANTS"
                    )
                    continue
                i = named
            if lines[i + 1 : i + 2] != [PROCESS_INIT]:
                problems.append(
                    f"{name}: process_init import must directly follow the "
                    "sys.path insert"
                )
        self.assertEqual(
            problems, [],
            msg="sys.path preamble drift:\n" + "\n".join(problems),
        )


class FaulthandlerStanzaTests(unittest.TestCase):
    """No inline faulthandler outside the two -I shims; shims pinned."""

    def test_no_inline_faulthandler_outside_the_shims(self):
        offenders = [
            path.name
            for path in _python_scripts()
            if path.name not in FAULTHANDLER_INLINE_SHIMS
            and "faulthandler"
            in path.read_text(encoding="utf-8", errors="replace")
        ]
        self.assertEqual(
            offenders, [],
            msg=(
                "inline faulthandler use in libexec scripts — the "
                "mandatory core.startup.process_init import already "
                "enables faulthandler and registers the SIGUSR1 stack "
                "dump (with the stderr-fileno guard the old inline "
                "copies lacked). Delete the stanza; only the two "
                "`python3 -I` shims in FAULTHANDLER_INLINE_SHIMS may "
                "carry one:\n" + "\n".join(offenders)
            ),
        )

    def test_shims_carry_the_pinned_stanza(self):
        problems = []
        for name in sorted(FAULTHANDLER_INLINE_SHIMS):
            text = (LIBEXEC / name).read_text(
                encoding="utf-8", errors="replace",
            )
            if text.count("import faulthandler\n") != 1:
                problems.append(
                    f"{name}: expected exactly one `import faulthandler`"
                )
            if text.count(FAULTHANDLER_STANZA) != 1:
                problems.append(
                    f"{name}: enable/register stanza deviates from "
                    "FAULTHANDLER_STANZA"
                )
        self.assertEqual(
            problems, [],
            msg="-I shim faulthandler stanza drift:\n" + "\n".join(problems),
        )


class BashLauncherSurfaceTests(unittest.TestCase):
    """Symlink-loop and env-strip identity across bin/ + libexec/."""

    def test_every_bash_script_is_classified(self):
        """Coverage direction: a new bash script must be added to the
        symlink table and to exactly one env-strip table.
        """
        names = {_rel(p) for p in _bash_scripts()}
        self.assertEqual(
            names, set(SYMLINK_LOOPS),
            msg="bash script set no longer matches SYMLINK_LOOPS — "
                "declare the newcomer's loop (or investigate the removal)",
        )
        self.assertEqual(
            names, set(ENV_STRIP_LINES) | NO_ENV_STRIP,
            msg="bash script set no longer matches ENV_STRIP_LINES ∪ "
                "NO_ENV_STRIP — classify the newcomer explicitly",
        )
        self.assertEqual(
            set(ENV_STRIP_LINES) & NO_ENV_STRIP, set(),
            msg="a script cannot be both env-strip carrier and exempt",
        )

    def test_symlink_loops_match_golden_template(self):
        problems = []
        for path in _bash_scripts():
            rel = _rel(path)
            text = path.read_text(encoding="utf-8", errors="replace")
            expected = [
                spec if isinstance(spec, str) else _symlink_block(*spec)
                for spec in SYMLINK_LOOPS.get(rel, [])
            ]
            actual = _symhops_blocks(text)
            if actual != expected:
                problems.append(
                    f"{rel}: {len(actual)} loop(s) found, "
                    f"{len(expected)} declared"
                    + (
                        "; body deviates from template"
                        if len(actual) == len(expected)
                        else ""
                    )
                )
            # every symlink while-loop must be one of the pinned blocks
            # (match statement lines only — the hop-bound rationale
            # comment in raptor-cc-trust-check quotes the loop header)
            n_loops = sum(
                1 for ln in text.splitlines()
                if ln.strip().startswith("while [ -L ")
            )
            if n_loops != len(expected):
                problems.append(
                    f"{rel}: {n_loops} `while [ -L` loop(s) but "
                    f"{len(expected)} declared — undeclared loop?"
                )
        self.assertEqual(
            problems, [],
            msg=(
                "bounded symlink-loop drift (golden body in "
                "_symlink_block; per-script label/exit-code/extra "
                "message in SYMLINK_LOOPS):\n" + "\n".join(problems)
            ),
        )

    def test_env_strip_sourcing_line_is_canonical(self):
        problems = []
        for path in _bash_scripts():
            rel = _rel(path)
            text = path.read_text(encoding="utf-8", errors="replace")
            source_lines = [
                ln for ln in text.splitlines()
                if ln.strip().startswith(". ")
                and "_dangerous_env_strip.sh" in ln
            ]
            if rel in NO_ENV_STRIP:
                if source_lines or "_dangerous_env_strip" in text:
                    problems.append(
                        f"{rel}: declared exempt but references the strip "
                        "fragment — move it to ENV_STRIP_LINES"
                    )
                continue
            expected_line = ENV_STRIP_LINES.get(rel)
            if expected_line is None:
                problems.append(
                    f"{rel}: unclassified (see "
                    "test_every_bash_script_is_classified)"
                )
            elif source_lines != [expected_line]:
                problems.append(
                    f"{rel}: expected exactly [{expected_line!r}], "
                    f"found {source_lines}"
                )
        self.assertEqual(
            problems, [],
            msg="dangerous-env-strip sourcing drift:\n"
                + "\n".join(problems),
        )


class RuffImmunityTests(unittest.TestCase):
    """`ruff check --fix` / `ruff format` cannot restructure the
    protected blocks — proof that the protective markers work against
    whatever ruff version is installed.
    """

    @staticmethod
    def _ruff_cmd() -> list[str] | None:
        if importlib.util.find_spec("ruff") is not None:
            return [sys.executable, "-m", "ruff"]
        exe = shutil.which("ruff")
        return [exe] if exe else None

    def _protected_regions(self, text: str) -> tuple:
        lines = text.splitlines()
        return (
            tuple(lines[1:3]),                     # prologue
            _trust_block(text),                    # trust-marker block
            tuple(
                ln for ln in lines
                if "sys.path.insert" in ln
                or ln.startswith("import core.startup.process_init")
            ),                                     # preamble
        )

    def _run_and_compare(self, subcmd: list[str]):
        ruff = self._ruff_cmd()
        if ruff is None:
            self.skipTest("ruff not installed")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            originals = {}
            for script in _python_scripts():
                text = script.read_text(encoding="utf-8")
                originals[script.name] = text
                (tmp / (script.name + ".py")).write_text(
                    text, encoding="utf-8",
                )
            # Exit code is irrelevant (unfixable diagnostics elsewhere
            # in the files are fine) — only the bytes matter.
            subprocess.run(
                [*ruff, *subcmd, str(tmp)],
                capture_output=True,
                timeout=300,
                check=False,
            )
            problems = []
            for name, before in originals.items():
                after = (tmp / (name + ".py")).read_text(encoding="utf-8")
                if self._protected_regions(after) != \
                        self._protected_regions(before):
                    problems.append(name)
            self.assertEqual(
                problems, [],
                msg=(
                    f"ruff {' '.join(subcmd)} restructured protected "
                    "preamble blocks in: " + ", ".join(problems)
                ),
            )

    def test_ruff_check_fix_leaves_protected_blocks_intact(self):
        self._run_and_compare(["check", "--fix", "--no-cache"])

    def test_ruff_format_leaves_protected_blocks_intact(self):
        self._run_and_compare(["format", "--no-cache"])


class ExecutableModeBitTests(unittest.TestCase):
    """Every dispatch script is exec'd by path. A script whose exec
    bit is lost — in a patch application, an archive/copy step, or a
    checkout on a filter that drops modes — fails at spawn time with
    exit 126 on whatever host runs it first, far from the change that
    dropped the bit. Pin BOTH the committed git mode and the on-disk
    bit for the whole libexec/ + bin/ surface."""

    def _tracked_entries(self) -> list[tuple[str, str]]:
        proc = subprocess.run(
            ["git", "ls-files", "--stage", "--", "libexec", "bin"],
            cwd=REPO, capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            self.skipTest("not a git checkout (or git unavailable)")
        entries: list[tuple[str, str]] = []
        for line in proc.stdout.splitlines():
            meta, _tab, path = line.partition("\t")
            if not path:
                continue
            entries.append((meta.split()[0], path))
        return entries

    def test_every_dispatch_script_is_committed_executable(self):
        bad = [f"{path} (mode {mode})"
               for mode, path in self._tracked_entries()
               if mode != "100755"]
        self.assertEqual(
            bad, [],
            msg=("dispatch scripts committed without the exec bit "
                 "(expected git mode 100755): " + ", ".join(bad)),
        )

    def test_every_dispatch_script_is_executable_on_disk(self):
        missing = []
        for _mode, path in self._tracked_entries():
            f = REPO / path
            if f.is_file() and not os.access(f, os.X_OK):
                missing.append(path)
        self.assertEqual(
            missing, [],
            msg=("dispatch scripts present but not executable on "
                 "disk: " + ", ".join(missing)),
        )


if __name__ == "__main__":
    unittest.main()
