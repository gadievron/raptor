"""Environment-variable documentation drift guard (daily CI scan).

Self-contained, stdlib-only. Extracts every environment variable the
tree reads or writes and compares the result against the documented
set in ``docs/environment.md`` — the regression class where a new
operator knob ships without documentation, or documentation describes
a variable that no longer exists in code.

Extraction (the mechanical inventory)
-------------------------------------
Python (AST, no regex-over-source):
  ``os.environ[K]`` load/store/del, ``os.environ.get/setdefault/pop``,
  ``os.getenv`` / ``os.putenv`` / ``os.unsetenv`` (through ``import os
  as _os`` aliases and ``from os import environ/getenv`` too), plus
  string-key subscript *writes* on env-shaped dict names (``env``,
  ``child_env``, ``spawn_env``...) — the RAPTOR-builds-a-child-
  environment seam. Keys that are ``NAME`` constants rather than
  string literals are resolved through the module's (then the tree's)
  ``NAME = "VAR"`` assignments; an env-name constant (``FOO_ENV =
  "RAPTOR_FOO"``) additionally counts as a read on its own, because
  such constants are routinely passed through helper functions
  (``_env_number(_KEEPALIVE_ENV, ...)``) where the actual
  ``os.environ.get`` key is an opaque parameter.
  ``env_flag("VAR", ...)`` calls (``core.config``'s shared
  boolean-toggle parser, bare or attribute form) count as reads at
  the call site — inside the helper the ``os.environ.get`` key is an
  opaque parameter.
  ``monkeypatch.setenv/delenv`` calls are recorded but excluded from
  the primary inventory (test scaffolding, not a code-level
  consumer).

Bash (``bin/*`` and every ``libexec/`` script with a sh/bash shebang):
  ``$VAR`` / ``${VAR...}`` reads and ``export VAR=`` writes of
  ALL-CAPS names. A name assigned in the same script *without*
  ``export`` is a script-local and its reads are ignored — unless the
  script contains a self-defaulting assignment
  (``VAR="${VAR:-default}"``), the take-it-from-the-environment knob
  pattern, which counts as a read.

Declared tables:
  the policy lists in ``core/config/__init__.py``
  (``SAFE_ENV_ALLOWLIST``, ``SAFE_ENV_PREFIXES``,
  ``DANGEROUS_ENV_VARS``, ``PROXY_ENV_VARS``, ``LLM_API_KEY_VARS``,
  ``LLM_ROUTING_ENV_VARS``, ``LLM_ROUTING_ENV_PREFIXES``) are parsed
  by AST so a variable that only appears as policy data is still
  inventoried.

Classification heuristics (first match wins)
--------------------------------------------
1. ``OVERRIDES`` — curated name → class map for the cases below
   misjudge; every entry carries a reason in the comment.
2. ``declared-only`` — the name appears in a policy table but is never
   read or written by code. Documented via the table's own doc
   section, not per-variable.
3. ``test-only`` — every occurrence is under a test path
   (``tests/``, ``test/``, ``conftest.py``, ``fixtures``,
   ``.github/``) or is monkeypatch-only.
4. ``external-standard`` — the name belongs to another ecosystem's
   contract (proxy family, ``AWS_*``, ``XDG_*``, ``GITHUB_*``,
   locale/terminal, provider SDK credentials...). RAPTOR consumes or
   forwards them but does not define their meaning.
5. ``internal`` — plumbing RAPTOR sets for its own children: name
   starts with ``_RAPTOR``, or production code *writes* it (export /
   ``os.environ[k]=`` / child-env dict) — the operator is not the one
   who sets it.
6. ``operator`` — everything else that production code reads: a knob
   the operator may set. New knobs land here by default, so an
   undocumented one fails the scan (fail-closed toward documentation).

CI semantics (baseline pattern, cf. ``check_miswiring.py``):
  * an ``operator``-class variable absent from ``docs/environment.md``
    FAILS unless keyed in ``env_docs_baseline.json`` (target: empty —
    document, don't baseline; every entry needs a ``note``);
  * a variable documented in ``docs/environment.md`` that no longer
    exists in the inventory FAILS (stale docs);
  * undocumented ``internal`` / ``external-standard`` / ``test-only``
    variables warn only.

Usage:
    python3 .github/scripts/check_env_docs.py            # CI mode
    python3 .github/scripts/check_env_docs.py --root <tree>
    python3 .github/scripts/check_env_docs.py --json out.json
    python3 .github/scripts/check_env_docs.py --list [class]

Exit codes: 0 clean (warnings only), 1 findings, 2 usage error.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

PY_ROOTS = ["core", "packages", "plugins", "engine", "libexec"]
ROOT_PY_FILES = [
    "raptor.py", "raptor_agentic.py", "raptor_codeql.py",
    "raptor_fuzzing.py", "conftest.py",
]
BASH_ROOTS = ["bin", "libexec"]

SKIP_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", "out", ".out", ".tox",
    ".venv", "venv", "build", "dist", "worktrees",
}

TEST_PATH_MARKERS = ("tests/", "test/", "fixtures/", ".github/")

# Policy tables parsed out of core/config/__init__.py. Names that appear
# only here are class "declared-only" (documented via the table's doc
# section, not per-variable).
CONFIG_TABLES = (
    "SAFE_ENV_ALLOWLIST",
    "SAFE_ENV_PREFIXES",
    "DANGEROUS_ENV_VARS",
    "PROXY_ENV_VARS",
    "GIT_ENV_VARS",
    "LLM_API_KEY_VARS",
    "LLM_ROUTING_ENV_VARS",
    "LLM_ROUTING_ENV_PREFIXES",
)
CONFIG_FILE = "core/config/__init__.py"

# --- classification data -------------------------------------------------

# Another ecosystem defines these names; RAPTOR consumes/forwards them.
EXTERNAL_NAMES = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "HOME", "PATH", "SHELL", "USER", "LOGNAME", "HOSTNAME", "PWD",
    "OLDPWD", "SHLVL", "EDITOR", "VISUAL", "PAGER", "BROWSER",
    "TERMINAL", "TERM", "COLORTERM", "DISPLAY", "TZ", "TMPDIR",
    "LANG", "LANGUAGE", "COLUMNS", "CI", "DEBIAN_FRONTEND",
    "PYTHONPATH", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
    "PYTHONUSERBASE", "PYTHONHASHSEED", "PYTHONSTARTUP", "PYTHONHOME",
    "VIRTUAL_ENV", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS",
    "JAVA_HOME", "JAVA_OPTS", "GRADLE_OPTS", "MAVEN_OPTS", "GOPATH",
    "GOCACHE", "GOFLAGS", "GOMODCACHE", "CARGO_HOME", "RUSTUP_HOME",
    "CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS", "MAKEFLAGS",
    "DOCKER_HOST", "DOCKER_CONFIG", "COMPOSE_PROJECT_NAME",
    "KUBECONFIG", "GIT_DIR", "GIT_TERMINAL_PROMPT", "GIT_ASKPASS",
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
    "GH_TOKEN", "GITHUB_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
    "OLLAMA_HOST", "IFS", "CDPATH", "BASH_ENV", "ENV",
    "PROMPT_COMMAND", "HOSTALIASES", "RES_OPTIONS", "LOCPATH",
    "NLSPATH", "GCONV_PATH", "USERNAME",
    # Sanitizer / fuzzing runtime contracts
    "ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS", "LSAN_OPTIONS",
    "ASAN_SYMBOLIZER_PATH",
    # Claude Code / Anthropic tooling contract (consumed by the CC CLI,
    # forwarded or set by RAPTOR).
    "CLAUDECODE", "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH", "CLAUDE_CODE_SKIP_VERTEX_AUTH",
    "ANTHROPIC_MODEL", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL",
    "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_MANTLE",
    "CLAUDE_ENV_FILE",
    # Harness supervision contract (read by core.run.supervisor to
    # detect subagent background shells and their kill cap).
    "CLAUDE_SUBAGENT_BG_SHELL_MAX_MS", "CLAUDE_CODE_CHILD_SESSION",
    "AI_AGENT",
    # Other ecosystems' detection / SDK surface
    "PYTEST_CURRENT_TEST", "CONDA_DEFAULT_ENV", "AZURE_OPENAI_ENDPOINT",
})

EXTERNAL_PREFIXES = (
    "AWS_", "XDG_", "LC_", "GIT_", "GITHUB_", "RUNNER_", "AFL_",
    "SEMGREP_", "GRADLE_", "NPM_", "PIP_", "UV_",
    "OTEL_", "VERTEX_", "GOOGLE_CLOUD_", "CLOUD_ML_",
)

# Provider SDK credential names — external contracts, but operator-
# facing in the docs (the operator must set them for the feature to
# work). Classified external-standard; documented in environment.md's
# credentials section.
API_KEY_HINT = re.compile(r"_(API_KEY|API_TOKEN|ACCESS_KEY|SECRET)S?$")

# Bash names that are shell builtins / runtime state, never env config.
BASH_NOISE = frozenset({
    "BASH_SOURCE", "BASH_REMATCH", "BASH_VERSION", "BASHPID",
    "FUNCNAME", "LINENO", "PIPESTATUS", "PPID", "RANDOM", "SECONDS",
    "REPLY", "OPTARG", "OPTIND", "EUID", "UID", "OSTYPE", "MACHTYPE",
    "HOSTTYPE", "SHELLOPTS", "GLOBIGNORE", "EPOCHSECONDS",
    "EPOCHREALTIME", "SRANDOM", "COMP_WORDS", "COMP_CWORD", "PS1",
    "PS2", "PS4", "SUDO_USER", "SUDO_UID", "SUDO_GID",
})

# Env-shaped dict variable names whose string-key subscript WRITES are
# treated as building a child environment.
ENV_DICT_NAME = re.compile(
    r"(^|_)(env|environ|env_vars|envs)$|^(env|environ)[0-9]*$",
)

# Curated per-name class overrides. Keep small; prefer fixing the
# heuristics. Reason on every line.
OVERRIDES: dict[str, str] = {
    # Env contract of the sandboxed r2 wrappers (libexec/raptor-r2-
    # sandboxed, raptor-run-sandboxed): set programmatically by the
    # invoking RAPTOR code, not by operators.
    "OUTPUT_DIR": "internal",
    "R2_TARGET_DIR": "internal",
    # Set by the privileged netns launcher when it re-execs the
    # coordinator (core/sandbox/netns_coordinator.py).
    "RAPTOR_COORD_FROM_LAUNCHER": "internal",
    # Legacy operator env interface for the sanitizer cut; the code
    # also re-exports resolved values to children (which trips the
    # written-and-read → internal heuristic), but the read side is an
    # operator knob and must stay documented.
    "RAPTOR_SANITIZER_CUT": "operator",
    "RAPTOR_SANITIZER_CUT_NO_LEXICAL": "operator",
    "RAPTOR_SANITIZER_CUT_PARITY_LOG": "operator",
    # Written into .mcp.json by libexec/raptor-sage-setup and read
    # back by libexec/raptor-sage-mcp — setup plumbing, not knobs.
    "SAGE_IDENTITY_PATH": "internal",
    "SAGE_PROJECT": "internal",
    "SAGE_PROVIDER": "internal",
}

VAR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CAPS_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


class Occurrence:
    __slots__ = ("file", "kind", "line")

    def __init__(self, file: str, line: int, kind: str):
        self.file = file
        self.line = line
        self.kind = kind  # read|write|delete|child-write|export|
        #                   bash-read|declared|monkeypatch

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "kind": self.kind}


class Inventory:
    def __init__(self) -> None:
        self.vars: dict[str, list[Occurrence]] = defaultdict(list)
        self.prefixes: dict[str, list[Occurrence]] = defaultdict(list)

    def add(self, name: str, occ: Occurrence) -> None:
        self.vars[name].append(occ)

    def add_prefix(self, prefix: str, occ: Occurrence) -> None:
        self.prefixes[prefix].append(occ)


# --- python extraction ----------------------------------------------------

def _collect_module_facts(tree: ast.Module) -> tuple[set, set, set, dict]:
    """(os aliases, environ aliases, getenv aliases, str-const map)."""
    os_names: set[str] = {"os"}
    environ_names: set[str] = set()
    getenv_names: set[str] = set()
    consts: dict[str, str | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    os_names.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "os":
                for alias in node.names:
                    bound = alias.asname or alias.name
                    if alias.name == "environ":
                        environ_names.add(bound)
                    elif alias.name == "getenv":
                        getenv_names.add(bound)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) \
                else [node.target]
            if (
                len(targets) == 1
                and isinstance(targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                name = targets[0].id
                # Conflicting re-assignments poison the entry.
                if name in consts and consts[name] != node.value.value:
                    consts[name] = None
                else:
                    consts[name] = node.value.value
    return os_names, environ_names, getenv_names, {
        k: v for k, v in consts.items() if v is not None
    }


class _PyScanner(ast.NodeVisitor):
    """Collects os.environ / os.getenv accesses and child-env writes."""

    def __init__(self, rel: str, inv: Inventory, tree: ast.Module,
                 global_consts: dict[str, str]):
        self.rel = rel
        self.inv = inv
        (self.os_names, self.environ_names, self.getenv_names,
         self.consts) = _collect_module_facts(tree)
        self.global_consts = global_consts

    def _name_of(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            # Resolve NAME-constant keys: same module first, then the
            # tree-wide constant map (imported *_ENV names).
            return self.consts.get(node.id) or \
                self.global_consts.get(node.id)
        return None

    def _is_os_environ(self, node: ast.AST) -> bool:
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.os_names
        ):
            return True
        return isinstance(node, ast.Name) and node.id in self.environ_names

    def _record(self, key: ast.AST, line: int, kind: str) -> None:
        name = self._name_of(key)
        if name and VAR_NAME.match(name):
            self.inv.add(name, Occurrence(self.rel, line, kind))

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._is_os_environ(node.value):
            ctx = node.ctx
            kind = (
                "read" if isinstance(ctx, ast.Load)
                else "delete" if isinstance(ctx, ast.Del)
                else "write"
            )
            self._record(node.slice, node.lineno, kind)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for tgt in node.targets:
            if (
                isinstance(tgt, ast.Subscript)
                and isinstance(tgt.value, ast.Name)
                and ENV_DICT_NAME.search(tgt.value.id)
                and not self._is_os_environ(tgt.value)
            ):
                self._record(tgt.slice, node.lineno, "child-write")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            # os.environ.get / setdefault / pop
            if (
                self._is_os_environ(func.value)
                and func.attr in ("get", "setdefault", "pop")
                and node.args
            ):
                kind = {
                    "get": "read", "setdefault": "write", "pop": "delete",
                }[func.attr]
                self._record(node.args[0], node.lineno, kind)
            # os.getenv / putenv / unsetenv
            elif (
                isinstance(func.value, ast.Name)
                and func.value.id in self.os_names
                and func.attr in ("getenv", "putenv", "unsetenv")
                and node.args
            ):
                kind = {
                    "getenv": "read", "putenv": "write",
                    "unsetenv": "delete",
                }[func.attr]
                self._record(node.args[0], node.lineno, kind)
            # monkeypatch.setenv / delenv — recorded, excluded later
            elif (
                func.attr in ("setenv", "delenv")
                and node.args
                and "monkeypatch" in ast.dump(func.value).lower()
            ):
                self._record(node.args[0], node.lineno, "monkeypatch")
        # bare getenv() from ``from os import getenv``
        if (
            isinstance(func, ast.Name)
            and func.id in self.getenv_names
            and node.args
        ):
            self._record(node.args[0], node.lineno, "read")
        # core.config.env_flag(name, default) — the shared boolean-
        # toggle parser wraps os.environ.get, so the call site is the
        # real read of the variable (inside the helper the key is an
        # opaque parameter).
        if (
            (
                (isinstance(func, ast.Name) and func.id == "env_flag")
                or (isinstance(func, ast.Attribute)
                    and func.attr == "env_flag")
            )
            and node.args
        ):
            self._record(node.args[0], node.lineno, "read")
        self.generic_visit(node)


def _parse_config_tables(root: Path, inv: Inventory) -> None:
    path = root / CONFIG_FILE
    try:
        tree = ast.parse(path.read_text(encoding="utf-8",
                                        errors="replace"))
    except (OSError, SyntaxError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        target = node.targets[0]
        tname = None
        if isinstance(target, ast.Name):
            tname = target.id
        elif isinstance(target, ast.Attribute):
            tname = target.attr
        if tname not in CONFIG_TABLES:
            continue
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                occ = Occurrence(CONFIG_FILE, sub.lineno,
                                 f"declared:{tname}")
                if tname.endswith("PREFIXES"):
                    inv.add_prefix(sub.value, occ)
                elif VAR_NAME.match(sub.value):
                    inv.add(sub.value, occ)


# --- bash extraction --------------------------------------------------------

_BASH_ASSIGN = re.compile(
    r"^\s*(?:(export|local|readonly|declare(?:\s+-\S+)*)\s+)?"
    r"([A-Z][A-Z0-9_]*)=",
)
_BASH_EXPORT_BARE = re.compile(r"^\s*export\s+([A-Z][A-Z0-9_]*)\s*$")
_BASH_READ = re.compile(r"\$\{?([A-Z][A-Z0-9_]*)")
_BASH_SELF_DEFAULT = re.compile(r"\$\{([A-Z][A-Z0-9_]*)[:#%/^,\-+=?}]")
_ENV_PREFIX_ASSIGN = re.compile(
    r"(?:^|\s)([A-Z][A-Z0-9_]*)=\S*\s+[a-zA-Z_./\"$]",
)


def _shebang_kind(path: Path) -> str:
    try:
        head = path.open("rb").read(80).split(b"\n", 1)[0]
    except OSError:
        return ""
    if b"python" in head:
        return "python"
    if b"bash" in head or head.strip().endswith(b"/sh"):
        return "bash"
    return ""


def _scan_bash(path: Path, rel: str, inv: Inventory) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    locals_: set[str] = set()
    exported: set[str] = set()
    reads: dict[str, int] = {}
    self_defaulting: set[str] = set()
    stripped: list[tuple[int, str]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") \
            else ""
        if line.strip():
            stripped.append((lineno, line))
    for lineno, line in stripped:
        m = _BASH_ASSIGN.match(line)
        if m:
            kw, name = m.group(1), m.group(2)
            if kw == "export":
                exported.add(name)
                inv.add(name, Occurrence(rel, lineno, "export"))
            else:
                locals_.add(name)
            # VAR="${VAR:-default}" — the take-it-from-the-environment
            # knob pattern: the assignment itself reads the variable.
            if re.search(
                r"\$\{" + re.escape(name) + r"[:#%/^,\-+=?}]",
                line[m.end():],
            ):
                self_defaulting.add(name)
        m = _BASH_EXPORT_BARE.match(line)
        if m:
            exported.add(m.group(1))
            inv.add(m.group(1), Occurrence(rel, lineno, "export"))
        # VAR=x command — env for a single child
        for m in _ENV_PREFIX_ASSIGN.finditer(line):
            name = m.group(1)
            if _BASH_ASSIGN.match(line.strip()) and \
                    line.strip().startswith(name + "="):
                continue  # plain assignment, already handled
            inv.add(name, Occurrence(rel, lineno, "child-write"))
        for m in _BASH_READ.finditer(line):
            reads.setdefault(m.group(1), lineno)
    for name, lineno in sorted(reads.items()):
        if name in BASH_NOISE:
            continue
        if (
            name in locals_
            and name not in exported
            and name not in self_defaulting
        ):
            continue  # plain script-local
        inv.add(name, Occurrence(rel, lineno, "bash-read"))


# --- tree walk ---------------------------------------------------------------

def _iter_files(root: Path):
    seen: set[Path] = set()
    for sub in PY_ROOTS + BASH_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p in seen:
                continue
            rel_parts = p.relative_to(root).parts
            if any(part in SKIP_DIR_NAMES for part in rel_parts):
                continue
            seen.add(p)
            yield p
    for name in ROOT_PY_FILES:
        p = root / name
        if p.is_file():
            yield p


_ENVISH_CONST = re.compile(r"(^_?[A-Z][A-Z0-9_]*_ENV$|_ENV_[A-Z0-9_]+$)")


def scan_tree(root: Path) -> Inventory:
    inv = Inventory()
    py: list[tuple[str, ast.Module]] = []
    for p in _iter_files(root):
        rel = p.relative_to(root).as_posix()
        if p.suffix == ".py":
            kind = "python"
        elif p.suffix in (".sh", ".bash"):
            kind = "bash"
        elif p.suffix == "":
            kind = _shebang_kind(p)
        else:
            continue
        if kind == "python":
            try:
                tree = ast.parse(p.read_text(encoding="utf-8",
                                             errors="replace"))
            except SyntaxError:
                continue
            py.append((rel, tree))
        elif kind == "bash":
            _scan_bash(p, rel, inv)
    # Tree-wide map of env-name constants (FOO_ENV = "RAPTOR_FOO",
    # _ENV_MODE = ...) so a key imported from a sibling module still
    # resolves. Conflicts poison the entry (kept unresolvable).
    global_consts: dict[str, str | None] = {}
    for _rel, tree in py:
        for name, value in _collect_module_facts(tree)[3].items():
            if not _ENVISH_CONST.search(name):
                continue
            if name in global_consts and global_consts[name] != value:
                global_consts[name] = None
            else:
                global_consts[name] = value
    global_consts = {
        k: v for k, v in global_consts.items() if v is not None
    }
    for rel, tree in py:
        scanner = _PyScanner(rel, inv, tree, global_consts)
        scanner.visit(tree)
        # Env-name constants count as a read even when the actual
        # os.environ access hides behind a helper parameter
        # (``_env_number(_KEEPALIVE_ENV, ...)``): the constant's
        # existence in production code IS the consumer declaration.
        for cname, value in scanner.consts.items():
            # Trailing underscore = a prefix constant (``"AWS_"``),
            # not a variable name.
            if (
                _ENVISH_CONST.search(cname)
                and CAPS_NAME.match(value)
                and not value.endswith("_")
            ):
                for node in ast.walk(tree):
                    if (
                        isinstance(node, ast.Assign)
                        and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name)
                        and node.targets[0].id == cname
                    ):
                        inv.add(value,
                                Occurrence(rel, node.lineno, "read"))
                        break
    _parse_config_tables(root, inv)
    return inv


# --- classification ---------------------------------------------------------

def _is_test_path(rel: str) -> bool:
    return (
        rel.startswith(("test/", "tests/", ".github/"))
        or "/tests/" in rel
        or "/test/" in rel
        or "/fixtures/" in rel
        or rel.endswith("conftest.py")
        or rel == "conftest.py"
    )


def classify(name: str, occs: list[Occurrence]) -> str:
    if name in OVERRIDES:
        return OVERRIDES[name]
    live = [o for o in occs if o.kind != "monkeypatch"]
    declared = [o for o in live if o.kind.startswith("declared:")]
    code = [o for o in live if not o.kind.startswith("declared:")]
    if not code:
        return "declared-only"
    if all(_is_test_path(o.file) for o in code):
        return "test-only"
    if name in EXTERNAL_NAMES or name.startswith(EXTERNAL_PREFIXES):
        return "external-standard"
    if API_KEY_HINT.search(name) and any(
        o.kind == "declared:LLM_API_KEY_VARS" for o in declared
    ):
        return "external-standard"
    if name.startswith("_"):
        return "internal"
    prod = [o for o in code if not _is_test_path(o.file)]
    prod_reads = [o for o in prod if o.kind in ("read", "bash-read")]
    prod_writes = [o for o in prod
                   if o.kind in ("write", "export", "child-write")]
    if prod_writes and not prod_reads:
        # RAPTOR only ever sets it — plumbing for children (or for an
        # external tool's contract, caught by EXTERNAL_* above).
        return "internal"
    if prod_writes and prod_reads:
        # Set by one RAPTOR layer, read by another — plumbing across
        # the process boundary. Operator knobs are read-only in code.
        return "internal"
    return "operator"


# --- docs parsing ------------------------------------------------------------

DOC_PATH = "docs/environment.md"
_DOC_ROW = re.compile(r"^\|([^|]*)\|")
_DOC_HEADING = re.compile(r"^#{2,4}\s+(.*)")
_DOC_TOKEN = re.compile(r"`([A-Za-z_][A-Za-z0-9_*]*)`")


def documented_vars(root: Path) -> tuple[set[str], set[str], set[str]]:
    """(documented names, documented prefixes, mentioned names).

    A variable counts as *documented* when a backticked token for it
    appears in the first cell of a markdown table row or in a
    ##/###/#### heading (multiple tokens per cell/heading allowed;
    ``FOO_*`` documents a prefix family). Any backticked token
    elsewhere in the page counts as *mentioned* — enough to silence
    the warn-only classes (internal / external-standard), but not to
    satisfy the operator-documentation requirement.
    """
    path = root / DOC_PATH
    names: set[str] = set()
    prefixes: set[str] = set()
    mentioned: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return names, prefixes, mentioned
    for line in text.splitlines():
        line = line.strip()
        m = _DOC_ROW.match(line)
        cell = None
        if m:
            cell = m.group(1)
        else:
            m = _DOC_HEADING.match(line)
            if m:
                cell = m.group(1)
        for token in _DOC_TOKEN.findall(cell or ""):
            if token.endswith("*"):
                prefixes.add(token[:-1])
            else:
                names.add(token)
        for token in _DOC_TOKEN.findall(line):
            if not token.endswith("*"):
                mentioned.add(token)
    return names, prefixes, mentioned


# --- baseline ----------------------------------------------------------------

DEFAULT_BASELINE = Path(__file__).resolve().parent / "env_docs_baseline.json"


def load_baseline(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# --- main --------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path,
                    default=Path(__file__).resolve().parents[2])
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--json", type=Path, help="dump inventory as JSON")
    ap.add_argument("--list", nargs="?", const="all", metavar="CLASS",
                    help="print the inventory (optionally one class)")
    args = ap.parse_args()

    if not args.root.is_dir():
        print(f"[env-docs] bad --root: {args.root}", file=sys.stderr)
        return 2

    inv = scan_tree(args.root)
    classes = {
        name: classify(name, occs) for name, occs in inv.vars.items()
    }

    if args.json:
        payload = {
            name: {
                "class": classes[name],
                "occurrences": [o.to_dict() for o in occs],
            }
            for name, occs in sorted(inv.vars.items())
        }
        payload["__prefixes__"] = {
            p: [o.to_dict() for o in occs]
            for p, occs in sorted(inv.prefixes.items())
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n",
                             encoding="utf-8")

    if args.list:
        for name in sorted(inv.vars):
            cls = classes[name]
            if args.list not in ("all", cls):
                continue
            kinds = sorted({o.kind for o in inv.vars[name]})
            print(f"{name:40s} {cls:18s} {','.join(kinds)}")
        return 0

    doc_names, doc_prefixes, mentioned = documented_vars(args.root)
    baseline = load_baseline(args.baseline)

    def is_documented(name: str) -> bool:
        return name in doc_names or any(
            name.startswith(p) for p in doc_prefixes
        )

    failures: list[str] = []
    warns: list[str] = []

    for name in sorted(inv.vars):
        cls = classes[name]
        if is_documented(name):
            continue
        if cls == "operator":
            if name in baseline:
                note = baseline[name].get("note", "") \
                    if isinstance(baseline[name], dict) else ""
                warns.append(
                    f"baselined undocumented operator var: {name}"
                    f"{' — ' + note if note else ''}"
                )
            else:
                occ = inv.vars[name][0]
                failures.append(
                    f"undocumented operator-facing variable: {name} "
                    f"(first seen {occ.file}:{occ.line}) — add it to "
                    f"{DOC_PATH}"
                )
        elif (cls in ("internal", "external-standard")
                and name not in mentioned):
            warns.append(f"undocumented {cls} variable: {name}")

    # Documented names must exist somewhere in the inventory. The
    # policy-table identifiers (LLM_API_KEY_VARS etc.) are legitimate
    # doc references to code constants, not variables.
    known = set(inv.vars)
    for name in sorted(doc_names):
        if name in known or name in CONFIG_TABLES:
            continue
        if any(name.startswith(p) for p in inv.prefixes):
            continue  # documented member of a declared prefix family
        failures.append(
            f"documented variable no longer exists in code: {name} — "
            f"remove or fix its entry in {DOC_PATH}"
        )
    for p in sorted(doc_prefixes):
        if p in inv.prefixes:
            continue
        if any(v.startswith(p) for v in known):
            continue
        failures.append(
            f"documented prefix family has no members in code: {p}* — "
            f"remove or fix its entry in {DOC_PATH}"
        )

    stale_baseline = sorted(
        k for k in baseline
        if k not in known or is_documented(k) or classes.get(k) != "operator"
    )
    for k in stale_baseline:
        warns.append(f"stale baseline entry: {k}")

    for w in warns:
        print(f"[env-docs] WARN {w}")
    if failures:
        for f in failures:
            print(f"[env-docs] FAIL {f}")
        print(
            f"[env-docs] {len(failures)} finding(s). Operator-facing "
            f"variables must be documented in {DOC_PATH}; stale doc "
            "entries must be removed. Deliberate exceptions go in "
            f"{args.baseline.name} with a note.",
        )
        return 1

    counts = defaultdict(int)
    for cls in classes.values():
        counts[cls] += 1
    summary = ", ".join(
        f"{counts[c]} {c}" for c in (
            "operator", "internal", "external-standard", "test-only",
            "declared-only",
        )
    )
    print(
        f"[env-docs] clean: {len(inv.vars)} variables ({summary}); "
        f"{len(doc_names)} documented, {len(baseline)} baselined, "
        f"{len(warns)} warning(s).",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
