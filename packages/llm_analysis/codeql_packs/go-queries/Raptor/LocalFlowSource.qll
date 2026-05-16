/**
 * Provides RAPTOR's `LocalFlowSource` for Go — a data-flow source
 * class covering process-local user-controlled inputs that the stdlib
 * `RemoteFlowSource` excludes.
 *
 * Selects stdlib `SourceNode` instances by threat-model category:
 * `commandargs` (os.Args), `environment` (os.Getenv, godotenv,
 * envconfig, gobuffalo/envy), `stdin` (os.Stdin reads), `file`
 * (file reads of attacker-controlled paths). Includes `remote` so
 * a single LocalFlowSource-based query covers both local and remote
 * inputs — matches IRIS validation semantics where the LLM's claim
 * might describe either kind.
 *
 * Mirrors the Python and Java patterns. SourceNode is abstract with
 * an abstract `getThreatModel()`, so we extend `DataFlow::Node` and
 * gate via `instanceof` cast plus the data-extension `sourceNode`
 * predicate (covers YAML model entries that don't go through the
 * SourceNode hierarchy).
 */

import go
import semmle.go.security.FlowSources
import semmle.go.dataflow.ExternalFlow

// Selection kept in sync across the four RAPTOR LocalFlowSource
// libraries (Python / JS / Java / Go); see python-queries/Raptor/
// LocalFlowSource.qll for the authoritative category list and the
// rationale for inclusions / exclusions.
class LocalFlowSource extends DataFlow::Node {
  LocalFlowSource() {
    this.(SourceNode).getThreatModel() =
      [
        "remote", "commandargs", "environment", "stdin", "file",
        "database", "view-component-input"
      ]
    or
    sourceNode(this,
      [
        "remote", "commandargs", "environment", "stdin", "file",
        "database", "view-component-input"
      ])
  }
}
