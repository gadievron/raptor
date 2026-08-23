"""Workflow-consistency tests over the .claude/agents frontmatter.

The agent .md files are prompts, but their frontmatter is the enforced
capability surface (tool grants, per-agent PreToolUse hooks). These
tests pin the Rule-of-Two decisions documented in docs/security.md so
a frontmatter edit cannot silently re-grow a severed leg:

  * crash-analysis pipeline: only the fetcher touches the network;
    orchestrator, analyzer, checker, and generators carry no
    WebFetch/WebSearch.
  * the fetcher is fetch-only (Read, Write, WebFetch) with the
    domain-allowlist hook wired.
  * every WebFetch grant in the agent set is paired with the
    PreToolUse domain hook or is an explicitly listed exception.
"""

import unittest
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[3]
_AGENTS_DIR = _REPO / ".claude" / "agents"

# Agents whose WebFetch is deliberately NOT hook-gated. offsec-specialist
# is the inherent all-tools / needs-HITL exception (docs/security.md).
_WEBFETCH_HOOK_EXEMPT = {"offsec-specialist"}

_NETWORK_TOOLS = {"WebFetch", "WebSearch"}


def _frontmatter(path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise AssertionError(f"{path.name}: missing frontmatter")
    block = text[4:].split("\n---", 1)[0]
    try:
        data = yaml.safe_load(block)
    except yaml.YAMLError:
        # Some agent descriptions embed prose that is not valid YAML
        # (offsec-specialist's multi-line example transcript). Fall
        # back to extracting the single-line keys this suite reasons
        # about; such an agent then reads as having no hooks, which is
        # the conservative direction for the assertions below.
        data = {}
        for line in block.splitlines():
            for key in ("name", "tools"):
                prefix = f"{key}:"
                if line.startswith(prefix):
                    data[key] = line[len(prefix):].strip()
    if not isinstance(data, dict):
        raise TypeError(f"{path.name}: frontmatter is not a mapping")
    return data


def _tools(front):
    raw = front.get("tools")
    if raw is None:
        return None  # all-tools default
    return {t.strip() for t in str(raw).split(",") if t.strip()}


def _pretooluse_hook_commands(front, matcher):
    commands = []
    hooks = front.get("hooks")
    if not isinstance(hooks, dict):
        return commands
    for entry in hooks.get("PreToolUse") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("matcher") != matcher:
            continue
        for hook in entry.get("hooks") or []:
            if isinstance(hook, dict) and hook.get("type") == "command":
                commands.append(str(hook.get("command", "")))
    return commands


def _webfetch_hook_commands(front):
    return _pretooluse_hook_commands(front, "WebFetch")


def _load_all():
    agents = {}
    for path in sorted(_AGENTS_DIR.glob("*.md")):
        front = _frontmatter(path)
        agents[front.get("name", path.stem)] = front
    return agents


class TestCrashPipelinePins(unittest.TestCase):

    def setUp(self):
        self.agents = _load_all()

    def test_orchestrator_has_no_network_tools(self):
        tools = _tools(self.agents["crash-analysis-agent"])
        self.assertIsNotNone(tools, "orchestrator must pin an explicit "
                                    "tool list, not the all-tools default")
        self.assertEqual(
            tools,
            {"Read", "Write", "Edit", "Bash", "Grep", "Glob", "Task"},
        )

    def test_analyzer_and_checker_have_no_network_tools(self):
        for name in ("crash-analyzer", "crash-analysis-checker",
                     "function-trace-generator", "coverage-analyzer"):
            tools = _tools(self.agents[name])
            self.assertIsNotNone(
                tools, f"{name} must pin an explicit tool list")
            self.assertFalse(
                tools & _NETWORK_TOOLS,
                f"{name} must not carry network tools; has {tools}")

    def test_fetcher_is_fetch_only(self):
        front = self.agents["crash-report-fetcher"]
        self.assertEqual(_tools(front), {"Read", "Write", "WebFetch"})

    def test_fetcher_webfetch_is_anchor_gated(self):
        front = self.agents["crash-report-fetcher"]
        commands = _webfetch_hook_commands(front)
        self.assertTrue(commands, "fetcher must wire the WebFetch hook")
        self.assertTrue(
            any("webfetch-domain-allowlist.py" in c
                and "--anchor-file" in c for c in commands))

    def test_hook_script_exists_and_is_executable_python(self):
        hook = _REPO / ".claude" / "hooks" / "webfetch-domain-allowlist.py"
        self.assertTrue(hook.is_file())
        first = hook.read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first.startswith("#!"))


class TestGHArchiveAgentPins(unittest.TestCase):
    """Pin the gh-archive Rule-of-Two decision (docs/security.md):
    Bash is narrowed to the typed BigQuery wrapper + the evidence-kit
    ingest script via a per-agent PreToolUse allowlist hook."""

    def setUp(self):
        self.front = _load_all()["oss-investigator-gh-archive-agent"]

    def test_tool_list_is_pinned(self):
        self.assertEqual(_tools(self.front), {"Bash", "Read", "Write"})

    def test_bash_allowlist_hook_is_wired(self):
        commands = _pretooluse_hook_commands(self.front, "Bash")
        self.assertTrue(commands, "gh-archive agent must wire the Bash "
                                  "command-allowlist hook")
        joined = " ".join(commands)
        self.assertIn("bash-command-allowlist.py", joined)
        self.assertIn("libexec/raptor-bq-query", joined)
        self.assertIn("ingest_bq_events.py", joined)

    def test_hook_allows_only_the_two_typed_commands(self):
        # The allowlist must not quietly grow a broad interpreter grant
        # (a bare "python3"/"bash" prefix would be arbitrary exec).
        import shlex
        commands = _pretooluse_hook_commands(self.front, "Bash")
        self.assertEqual(len(commands), 1)
        argv = shlex.split(commands[0])
        prefixes = argv[argv.index(next(
            a for a in argv if a.endswith("bash-command-allowlist.py")
        )) + 1:]
        self.assertEqual(prefixes, [
            "libexec/raptor-bq-query",
            ("python3 .claude/skills/oss-forensics/github-evidence-kit/"
             "scripts/ingest_bq_events.py"),
        ])

    def test_hook_script_exists_and_is_executable_python(self):
        hook = _REPO / ".claude" / "hooks" / "bash-command-allowlist.py"
        self.assertTrue(hook.is_file())
        first = hook.read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first.startswith("#!"))

    def test_wrapper_and_ingest_script_exist(self):
        self.assertTrue((_REPO / "libexec" / "raptor-bq-query").is_file())
        self.assertTrue(
            (_REPO / ".claude" / "skills" / "oss-forensics" /
             "github-evidence-kit" / "scripts" /
             "ingest_bq_events.py").is_file())


class TestWebFetchGrantsAreGated(unittest.TestCase):

    def test_every_webfetch_grant_carries_the_domain_hook(self):
        for name, front in _load_all().items():
            if name in _WEBFETCH_HOOK_EXEMPT:
                continue
            tools = _tools(front)
            grants_webfetch = tools is None or "WebFetch" in tools
            if not grants_webfetch:
                continue
            self.assertIsNotNone(
                tools,
                f"{name}: all-tools default silently grants WebFetch — "
                "pin an explicit tool list or add to the exempt set")
            commands = _webfetch_hook_commands(front)
            self.assertTrue(
                any("webfetch-domain-allowlist.py" in c for c in commands),
                f"{name}: WebFetch granted without the domain-allowlist "
                "PreToolUse hook")


if __name__ == "__main__":
    unittest.main()
