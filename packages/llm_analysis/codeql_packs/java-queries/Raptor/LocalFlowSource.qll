/**
 * Provides RAPTOR's `LocalFlowSource` for Java — a data-flow source
 * class covering process-local user-controlled inputs that the stdlib
 * `RemoteFlowSource` excludes.
 *
 * Selects existing stdlib `SourceNode` subclasses by threat-model
 * category: `commandargs` (main args[]), `environment` (System.getenv,
 * System.getProperty), `stdin` (System.in / Scanner), `file` (file
 * reads of attacker-controlled paths), and Java's broader `local`
 * category. Includes `remote` so a single LocalFlowSource-based
 * query covers both local and remote inputs.
 *
 * Mirrors the design of packages/llm_analysis/codeql_packs/python-queries/
 * Raptor/LocalFlowSource.qll. Adding a category here is the only
 * change needed to widen IRIS Tier 1's source coverage in Java.
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow

/**
 * Implementation note: extending `SourceNode` directly fails to
 * compile because `SourceNode.getThreatModel()` is abstract and we
 * have nothing meaningful to override it with — we want to *filter*
 * existing sources, not declare a new one. We therefore extend
 * `DataFlow::Node` and gate on the threat-model selection via an
 * `instanceof` cast.
 *
 * `sourceNode(this, kind)` covers data-extension model entries that
 * register sources via the YAML model files (e.g. `argv` /
 * `environment` annotations on framework APIs) without going through
 * the Java SourceNode hierarchy. This keeps coverage comprehensive
 * even when stdlib YAML models tag sources outside the SourceNode
 * class system.
 */
// Selection kept in sync across the four RAPTOR LocalFlowSource
// libraries (Python / JS / Java / Go); see python-queries/Raptor/
// LocalFlowSource.qll for the authoritative category list and the
// rationale for inclusions / exclusions. Java additionally includes
// the broad `local` category, which the Java stdlib uses as an
// umbrella for sources that don't fit a more specific bucket.
class LocalFlowSource extends DataFlow::Node {
  LocalFlowSource() {
    this.(SourceNode).getThreatModel() =
      [
        "remote", "local", "commandargs", "environment", "stdin",
        "file", "database", "view-component-input"
      ]
    or
    sourceNode(this,
      [
        "remote", "local", "commandargs", "environment", "stdin",
        "file", "database", "view-component-input"
      ])
  }
}
