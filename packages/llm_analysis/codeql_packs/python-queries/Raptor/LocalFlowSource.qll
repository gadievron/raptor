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
 *
 * Threat-model categories selected here (kept in sync across the four
 * RAPTOR LocalFlowSource libraries — Python / JS / Java / Go):
 *
 *   - `remote`   — network sources (HTTP, RPC, message queues, etc.).
 *                  Included so a single `LocalFlowSource` query covers
 *                  both local and remote inputs.
 *   - `commandargs` — argv-style command-line parameters.
 *   - `environment` — env-variable reads.
 *   - `stdin`    — stdin reads / interactive input.
 *   - `file`     — reads of attacker-controlled file paths.
 *   - `database` — values fetched from a (possibly attacker-influenced)
 *                  data store, used as second-order taint sources.
 *   - `view-component-input` — JS-specific client-side inputs (URL
 *                  fragments, query strings, postMessage payloads);
 *                  no-op on Python/Java/Go but cheap to include for
 *                  cross-language consistency.
 *
 * Threat-model categories deliberately excluded:
 *   - `reverse-dns` — DNS-based attacker control is rare and noisy;
 *                  add when a real claim names it.
 *
 * If an LLM-generated claim involves a category outside the list
 * above, Tier 1 will return zero matches and PR-B's verdict relaxation
 * will refute (potentially incorrectly). The list above is the
 * authoritative answer to "what does our LocalFlowSource cover" — keep
 * this docblock and the predicate body in sync.
 */
class LocalFlowSource extends ThreatModelSource {
  LocalFlowSource() {
    this.getThreatModel() =
      [
        "remote", "commandargs", "environment", "stdin", "file",
        "database", "view-component-input"
      ]
  }
}
