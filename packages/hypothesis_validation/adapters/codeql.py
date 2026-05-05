"""CodeQL adapter — hypothesis validation via LLM-generated .ql queries.

CodeQL is the right tool when the hypothesis is about inter-procedural
dataflow, taint propagation, or call-graph reachability — things
syntactic tools cannot answer. The LLM-generated rule is a single .ql
query.

Unlike Coccinelle/Semgrep which scan source directly, CodeQL needs a
pre-built database. The adapter's constructor takes the database path;
callers (e.g. /agentic, /audit) build the database once per codebase
and reuse it across hypotheses. Database build is expensive (minutes to
hours) and is NOT this adapter's responsibility.

The IRIS pattern (ICLR 2025): LLM infers source/sink specs and writes a
small bespoke .ql query; CodeQL executes it; results validate or refute
the hypothesis. IRIS achieved 2x CodeQL's recall (55 vs 27 CVEs) using
this pattern.
"""

import json
import shutil
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional

from .base import ToolAdapter, ToolCapability, ToolEvidence, make_sandbox_runner


_SYNTAX_EXAMPLE = """\
/**
 * @name Tainted size flows to malloc
 * @kind path-problem
 * @id raptor/tainted-malloc-size
 */
import cpp
import semmle.code.cpp.security.FlowSources

class TaintedMallocConfig extends TaintTracking::Configuration {
  TaintedMallocConfig() { this = "TaintedMallocConfig" }
  override predicate isSource(DataFlow::Node src) {
    src.asExpr() instanceof FlowSource
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "malloc" and
      sink.asExpr() = fc.getArgument(0)
    )
  }
}

from TaintedMallocConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select sink, src, sink, "Tainted size in malloc"
"""


class CodeQLAdapter(ToolAdapter):
    """Adapter wrapping CodeQL CLI for hypothesis validation.

    Args:
        database_path: Pre-built CodeQL database for the target codebase.
            Required at run() time; if None at construction, the adapter
            is_available() returns False until set_database() is called.
        codeql_bin: Override CodeQL CLI path. Defaults to PATH lookup.
        sandbox: When True (default), run codeql in a network-blocked
            sandbox via core.sandbox.run. Falls back gracefully to
            subprocess.run when the sandbox isn't available on the host.
            Set False for tests or trusted environments.
    """

    def __init__(
        self,
        database_path: Optional[Path] = None,
        codeql_bin: Optional[str] = None,
        *,
        sandbox: bool = True,
    ):
        self._database_path = Path(database_path) if database_path else None
        self._codeql_bin = codeql_bin or shutil.which("codeql")
        self._sandbox = sandbox

    @property
    def name(self) -> str:
        return "codeql"

    def set_database(self, database_path: Path) -> None:
        """Update the database to query against. Useful when the adapter
        is constructed before a database has been built."""
        self._database_path = Path(database_path)

    def is_available(self) -> bool:
        if not self._codeql_bin:
            return False
        if not self._database_path:
            return False
        if not self._database_path.exists():
            return False
        return True

    def describe(self) -> ToolCapability:
        return ToolCapability(
            name=self.name,
            good_for=[
                "Inter-procedural dataflow tracking (taint from source to sink)",
                "Call-graph reachability analysis",
                "Type-system-aware queries (subtypes, overrides)",
                "Multi-file pattern matching with semantic context",
                "Cross-function precondition checking",
            ],
            bad_for=[
                "Single-function patterns — use coccinelle or semgrep (faster, no DB needed)",
                "Path satisfiability with concrete inputs — use smt",
                "Languages without a CodeQL extractor",
                "Hypotheses where the database isn't built yet",
            ],
            syntax_example=_SYNTAX_EXAMPLE,
            languages=["c", "cpp", "java", "python", "javascript", "typescript", "go", "csharp", "ruby", "swift"],
        )

    def run(
        self,
        rule: str,
        target: Path,
        *,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> ToolEvidence:
        """Run an LLM-generated .ql query against the configured database.

        The `target` argument is informational only — CodeQL always
        queries the database (set at construction or via set_database).
        Callers should pass target=database_path or target=source_root
        for audit-trail clarity.

        timeout defaults to 300s. Heavy queries can opt into a longer
        wall-clock by passing timeout= explicitly. The previous default
        (1800s) created DoS exposure: a malformed LLM-generated query
        could stall a single hypothesis for 30 minutes.
        """
        if not self._codeql_bin:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="codeql CLI is not installed",
            )
        if not self._database_path:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="no CodeQL database configured (set_database() first)",
            )
        if not self._database_path.exists():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"CodeQL database not found: {self._database_path}",
            )
        if not rule or not rule.strip():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False, error="empty rule",
            )

        if env is None:
            from core.config import RaptorConfig
            env = RaptorConfig.get_safe_env()

        # codeql wants the .ql in a query pack alongside a qlpack.yml.
        # Generate both in a temp dir, then `codeql pack install` so that
        # the LLM's query can resolve standard-library imports
        # (semmle.python.security.dataflow.*, etc.) which the pack's
        # dependencies pull in. Without the install step, queries that
        # use anything beyond the bare `import python` core fail to
        # compile.
        try:
            with TemporaryDirectory(prefix="codeql_hv_") as tmp:
                pack_dir = Path(tmp) / "hv-pack"
                pack_dir.mkdir(parents=True, exist_ok=True)
                query_file = pack_dir / "query.ql"
                qlpack = pack_dir / "qlpack.yml"

                query_file.write_text(rule)
                qlpack.write_text(_qlpack_yaml(rule))

                runner = (
                    make_sandbox_runner(target=self._database_path)
                    if self._sandbox else subprocess.run
                )

                # Install pack dependencies (downloads or links the
                # standard library packs the query may import).
                # Cached after first run so subsequent invocations are
                # fast. Failure here doesn't abort — the query may not
                # need any external imports.
                try:
                    runner(
                        [self._codeql_bin, "pack", "install", str(pack_dir)],
                        capture_output=True, text=True,
                        timeout=120, env=env,
                    )
                except Exception as e:
                    # Pack install is best-effort. If the query has no
                    # external imports it will still compile.
                    pass

                sarif_path = Path(tmp) / "result.sarif"
                cmd = [
                    self._codeql_bin,
                    "database", "analyze",
                    str(self._database_path),
                    str(query_file),
                    "--format=sarif-latest",
                    f"--output={sarif_path}",
                    "--no-rerun",
                ]
                try:
                    proc = runner(
                        cmd, capture_output=True, text=True,
                        timeout=timeout, env=env,
                    )
                except subprocess.TimeoutExpired:
                    return ToolEvidence(
                        tool=self.name, rule=rule, success=False,
                        error=f"codeql timeout after {timeout}s",
                    )
                except OSError as e:
                    return ToolEvidence(
                        tool=self.name, rule=rule, success=False,
                        error=f"failed to invoke codeql: {e}",
                    )

                if proc.returncode != 0 or not sarif_path.exists():
                    err = (proc.stderr or proc.stdout or "").strip()
                    return ToolEvidence(
                        tool=self.name, rule=rule, success=False,
                        error=err[:500] or f"codeql returned {proc.returncode}",
                    )

                matches = _parse_sarif(sarif_path)
        except OSError as e:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"workspace setup failed: {e}",
            )

        n = len(matches)
        files = sorted({m["file"] for m in matches if m.get("file")})
        if n:
            summary = f"{n} match{'es' if n != 1 else ''} in {len(files)} file{'s' if len(files) != 1 else ''}"
        else:
            summary = "no matches"

        return ToolEvidence(
            tool=self.name,
            rule=rule,
            success=True,
            matches=matches,
            summary=summary,
        )


def _qlpack_yaml(rule: str) -> str:
    """Build a minimal qlpack.yml that imports the right standard library.

    Heuristic: peek at the rule's `import` lines for the language. The
    standard CodeQL libraries are named `cpp`, `python`, `java`, etc.;
    matching dependencies are `codeql/<lang>-all`.
    """
    lang = "cpp"  # default for /audit's primary use case
    for line in rule.splitlines()[:20]:
        s = line.strip()
        if s.startswith("import "):
            head = s.split()[1].split(".")[0].lower()
            if head in {"cpp", "java", "python", "javascript", "go", "csharp", "ruby", "swift"}:
                lang = head
                break

    return (
        "name: raptor/hv-pack\n"
        "version: 0.0.0\n"
        f"library: false\n"
        "dependencies:\n"
        f"  codeql/{lang}-all: \"*\"\n"
    )


def _parse_sarif(sarif_path: Path) -> List[Dict]:
    """Extract matches from a CodeQL SARIF file."""
    try:
        data = json.loads(sarif_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    matches: List[Dict] = []
    for run in data.get("runs", []) or []:
        for result in run.get("results", []) or []:
            msg = result.get("message", {})
            text = msg.get("text", "") if isinstance(msg, dict) else str(msg)
            file = ""
            line = 0
            locs = result.get("locations", []) or []
            if locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation", {})
                file = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = int((phys.get("region", {}) or {}).get("startLine", 0))
            matches.append({
                "file": file,
                "line": line,
                "rule": result.get("ruleId", ""),
                "message": text,
            })
    return matches
