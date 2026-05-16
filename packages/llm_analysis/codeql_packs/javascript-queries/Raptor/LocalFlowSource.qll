/**
 * Provides RAPTOR's `LocalFlowSource` for JavaScript / TypeScript —
 * a data-flow source class covering CLI / process-local user-controlled
 * inputs that the stdlib `RemoteFlowSource` excludes.
 *
 * Selects existing stdlib threat-model sources tagged `commandargs`
 * (process.argv, yargs, optimist, commander), `environment`
 * (process.env reads), `stdin` (process.stdin reads), and `file`
 * (file reads of attacker-controlled paths). Includes `remote` so a
 * single LocalFlowSource-based query covers BOTH local and remote
 * inputs — matches IRIS validation semantics where the LLM's claim
 * might describe either kind.
 *
 * Mirrors the design of packages/llm_analysis/codeql_packs/python-queries/
 * Raptor/LocalFlowSource.qll. Adding a category here is the only change
 * needed to widen IRIS Tier 1's source coverage in JS.
 */

import javascript

// Selection kept in sync across the four RAPTOR LocalFlowSource
// libraries (Python / JS / Java / Go); see python-queries/Raptor/
// LocalFlowSource.qll for the authoritative category list and the
// rationale for inclusions / exclusions.
class LocalFlowSource extends ThreatModelSource {
  LocalFlowSource() {
    this.getThreatModel() =
      [
        "remote", "commandargs", "environment", "stdin", "file",
        "database", "view-component-input"
      ]
  }
}
