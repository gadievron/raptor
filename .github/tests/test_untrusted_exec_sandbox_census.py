"""Doc-lint: instruction lanes that build or run the untrusted target
stay inside the sandbox.

Why this test exists
--------------------
The crash-analysis workflow hands agents a HOSTILE repository (cloned
from a public bug tracker) and instructs them to rebuild it and run
the resulting binary. The mechanical containment for that class of
operation is `libexec/raptor-run-sandboxed`; an instruction file that
shows a bare `make` / `./program` recipe, an `export LD_LIBRARY_PATH`
+ direct-run idiom, or a "fall back to direct execution" escape hatch
steers the agent into executing attacker code with the operator's
full ambient authority. Nothing enforces these instructions
mechanically — the agents run Bash freely — so the instruction text
IS the control, and this census pins it.

Same doctrine for the exploit personas: the live prompt lane
(packages/llm_analysis/crash_agent.py) mandates inlining the
vulnerability trigger in the PoC because RAPTOR runs PoCs under
Landlock and cross-binary execution is blocked; a persona telling the
model to `system("./vulnerable_binary ...")` re-opens the bare-exec
lane for every free-Bash session that loads it.

One documented exemption: `rr record`. rr needs `ptrace` and perf
counters, which the sandbox denies, so recording the untrusted binary
runs bare by explicit decision. The census does not ban the idiom; it
pins that the exemption rationale travels IN THE SAME FILE as every
`rr record` recipe (test below) — a bare recording instruction with no
stated residual is drift, not a decision.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]

# Instruction files whose fenced examples drive builds/runs of the
# untrusted crash-analysis target.
_CRASH_LANES = (
    ".claude/agents/crash-analysis-agent.md",
    ".claude/agents/function-trace-generator-agent.md",
    ".claude/agents/crash-analyzer-agent.md",
    ".claude/agents/crash-analyzer-checker-agent.md",
    ".claude/agents/coverage-analysis-generator-agent.md",
    ".claude/skills/crash-analysis/function-tracing/SKILL.md",
    ".claude/skills/crash-analysis/gcov-coverage/SKILL.md",
    ".claude/skills/crash-analysis/rr-debugger/SKILL.md",
)

# Lanes that instruct a rebuild / preprocess / execution of the
# untrusted tree and must therefore name the sandbox wrapper.
_MUST_NAME_SANDBOX = (
    ".claude/agents/crash-analysis-agent.md",
    ".claude/agents/function-trace-generator-agent.md",
    ".claude/agents/crash-analyzer-agent.md",
    ".claude/agents/crash-analyzer-checker-agent.md",
    ".claude/agents/coverage-analysis-generator-agent.md",
    ".claude/skills/crash-analysis/function-tracing/SKILL.md",
    ".claude/skills/crash-analysis/gcov-coverage/SKILL.md",
)

_PERSONA_DIR = "tiers/personas"

# A loader-variable export makes the subsequent run bypass the
# sandbox's environment sanitisation (the sandbox ALWAYS strips
# LD_LIBRARY_PATH/LD_PRELOAD) — the recipe only works bare, so its
# presence documents an unsandboxed run.
_LOADER_EXPORT_RE = re.compile(
    r"^\s*(?:export\s+)?LD_(?:LIBRARY_PATH|PRELOAD)=", re.MULTILINE)

# Bare build/run command lines inside fenced examples of the crash
# lanes: the target build (`make` / `cmake --build` / `ninja` — every
# build-tool target executes the untrusted build scripts' commands,
# `clean` included) or any produced binary (`./program`, `./a.out`,
# `./trace_to_perfetto` — native code, or a parser fed bytes the
# untrusted target emitted) invoked with no wrapper. An `env VAR=...`
# prefix does not launder the run.
_BARE_RUN_RE = re.compile(
    r"^\s*(?:env\s+(?:[A-Za-z_]\w*=\S*\s+)+)?"
    r"(?:make\b[^\n]*"
    r"|cmake\s+--build\b[^\n]*"
    r"|ninja\b[^\n]*"
    r"|\./[\w.\-]+(?:\s[^\n]*)?"
    r")$",
    re.MULTILINE,
)

# The one sanctioned bare-execution idiom (see module docstring): the
# exemption text that must accompany it in the same file.
_RR_RECORD_RE = re.compile(r"\brr record\b")
_RR_EXEMPTION_RE = re.compile(r"[Ss]andbox exemption")

# Persona instructions to spawn the analysed target from the PoC.
_SPAWN_TARGET_RES = (
    re.compile(r"""system\(\s*["']\./"""),
    re.compile(r"execve\(\)\s+or\s+system\(\)"),
    re.compile(r"""execl?p?\(\s*["']\./"""),
)


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8", errors="replace")


class UntrustedExecSandboxCensusTests(unittest.TestCase):
    def test_lanes_exist(self):
        for rel in _CRASH_LANES:
            self.assertTrue((REPO / rel).is_file(), f"missing lane: {rel}")

    def test_no_loader_variable_direct_run_idiom(self):
        """Instrumented-target runs must resolve their runtime library
        via a link-time rpath and execute inside the sandbox — never
        via an LD_* export in the operator environment."""
        problems = []
        for rel in _CRASH_LANES:
            for m in _LOADER_EXPORT_RE.finditer(_read(rel)):
                problems.append(f"{rel}: {m.group(0).strip()}")
        self.assertEqual(problems, [], msg=(
            "loader-variable export idiom found — the sandbox strips "
            "LD_* by design, so these recipes only work as bare "
            "(unsandboxed) runs; bake an rpath at the instrumented "
            "link instead:\n" + "\n".join(problems)))

    def test_no_direct_execution_fallback(self):
        """Sandbox degradation must refuse, never fall back to running
        the attacker-built binary bare."""
        problems = []
        for rel in _CRASH_LANES:
            text = _read(rel)
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r"fall\s*back to direct execution", line,
                             re.IGNORECASE):
                    problems.append(f"{rel}:{i}: {line.strip()}")
        self.assertEqual(problems, [], msg=(
            "direct-execution fallback language found — the fallback "
            "IS the mainline once the trigger condition is routine; "
            "fix the sandboxed path instead:\n" + "\n".join(problems)))

    def test_untrusted_build_and_run_lanes_name_the_sandbox(self):
        """Every lane that rebuilds or executes the untrusted tree
        must route those steps through libexec/raptor-run-sandboxed."""
        problems = [rel for rel in _MUST_NAME_SANDBOX
                    if "raptor-run-sandboxed" not in _read(rel)]
        self.assertEqual(problems, [], msg=(
            "these lanes instruct building/preprocessing/running the "
            "untrusted target but never name the sandbox wrapper "
            "(libexec/raptor-run-sandboxed):\n" + "\n".join(problems)))

    def test_no_bare_target_build_or_run_examples(self):
        """Fenced examples are copied verbatim; a bare `make` /
        `./program` line in a crash lane is an unsandboxed execution
        of attacker code."""
        problems = []
        for rel in _CRASH_LANES:
            for m in _BARE_RUN_RE.finditer(_read(rel)):
                problems.append(f"{rel}: {m.group(0).strip()}")
        self.assertEqual(problems, [], msg=(
            "bare build/run examples found — wrap them in "
            "libexec/raptor-run-sandboxed --output-dir <dir> ...:\n"
            + "\n".join(problems)))

    def test_rr_record_exemption_is_documented(self):
        """`rr record` cannot ride libexec/raptor-run-sandboxed (rr
        needs ptrace and perf counters the sandbox denies), so
        recording the untrusted binary is a documented unsandboxed
        residual. Any lane showing `rr record` must carry the
        exemption rationale in the same file — never a silent bare
        run."""
        problems = []
        for rel in _CRASH_LANES:
            text = _read(rel)
            if not _RR_RECORD_RE.search(text):
                continue
            if not (_RR_EXEMPTION_RE.search(text) and "ptrace" in text):
                problems.append(rel)
        self.assertEqual(problems, [], msg=(
            "`rr record` recipe without the in-file sandbox-exemption "
            "rationale (ptrace/perf-counter requirement, residual "
            "scope) — document the decision next to the recipe:\n"
            + "\n".join(problems)))

    def test_personas_never_instruct_spawning_the_target(self):
        """Exploit PoCs inline the vulnerability trigger; RAPTOR runs
        PoCs under Landlock where cross-binary execution is blocked.
        A persona mandating execve()/system() of the target steers
        free-Bash sessions into bare execution of the hostile binary."""
        persona_files = sorted((REPO / _PERSONA_DIR).glob("*.md"))
        self.assertGreater(len(persona_files), 1)
        problems = []
        for path in persona_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern in _SPAWN_TARGET_RES:
                for m in pattern.finditer(text):
                    problems.append(
                        f"{path.relative_to(REPO)}: {m.group(0)}")
        self.assertEqual(problems, [], msg=(
            "persona instructs spawning the analysed target — inline "
            "the trigger in the PoC instead (the sandbox blocks "
            "cross-binary execution):\n" + "\n".join(problems)))


if __name__ == "__main__":
    unittest.main()
