/**
 * Provides RAPTOR's `LocalFlowSource` — a data-flow source class
 * covering CLI / process-local user-controlled inputs that CodeQL's
 * stdlib `RemoteFlowSource` intentionally excludes.
 *
 * Used by IRIS Tier 1 dataflow validation when the LLM's claim
 * involves an attacker-controlled value reaching a sensitive sink
 * via:
 *   - `sys.argv` / `sys.orig_argv`               (commandargs)
 *   - `os.environ`, `os.getenv`, `os.environb`   (environment)
 *   - `sys.stdin.read*`, `input()`, `raw_input`  (stdin)
 *   - file reads of attacker-controlled paths    (file)
 *
 * Implementation note: rather than re-modelling each API, we leverage
 * CodeQL's existing `ThreatModelSource` infrastructure. The stdlib
 * already models all the relevant APIs and tags them with threat-model
 * categories; this class just selects the subset that maps to local /
 * process-boundary inputs. See:
 *   ~/.codeql/packages/codeql/threat-models/.../threat-model-grouping.model.yml
 *
 * Includes `remote` as well, so a query using `LocalFlowSource` covers
 * BOTH local and remote inputs without needing two parallel queries —
 * matches IRIS validation semantics where the LLM's claim might
 * describe either kind of input.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts

/**
 * A data-flow source representing process-local user input
 * (CLI args, env vars, stdin, file contents) plus remote sources.
 *
 * Subtype selectors mirror the threat-model categories in the CodeQL
 * threat-models pack. Adding a category here is the only change needed
 * to widen IRIS Tier 1's source coverage.
 */
class LocalFlowSource extends ThreatModelSource {
  LocalFlowSource() {
    this.getThreatModel() =
      ["remote", "commandargs", "environment", "stdin", "file"]
  }
}
