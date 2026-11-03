# Model broker registry

To contribute a standard broker, edit only
[`core/llm/model_brokers/registry.json`](../core/llm/model_brokers/registry.json). Add one entry to the
`brokers` array under the existing `version: 1` envelope:

```json
{
  "name": "examplebroker",
  "upstream_base_url": "https://api.example.com",
  "api_path": "/v1",
  "auth_scheme": "Bearer"
}
```

Python validates the catalog and supplies credential handling, dispatcher
routes, SDK construction, model-family handling, and tests. Every catalog
entry automatically gets a local HTTP forwarding test; contributors do not
need to edit Python, test fixtures, or environment documentation tables.
The file accepts full-line and inline `//` or `#` comments through the shared
RAPTOR configuration parser. URLs and comment markers inside strings are
preserved. Restart RAPTOR after changing the catalog.

- `name`: unique lowercase route name. Native provider names and aliases
  are reserved by Python. All entries here are brokers: the prefix is
  removed when identifying underlying model lineage.
- `upstream_base_url`: bare HTTPS origin, without a trailing slash, API
  path, credentials, query, or fragment.
- `api_path`: the API root, such as `/v1`, `/api/v1`, `/openai/v1`, or an
  empty string. This avoids hardcoding different gateway paths in Python.
- `auth_scheme`: `Bearer` (default) or `Token`. Controls the `Authorization`
  header independently of the environment variable's spelling.
- `credential_suffix`: `API_KEY` (default) or `API_TOKEN`. Selects a provider's
  credential naming convention. Python derives `<UPPERCASE_NAME>_<suffix>`;
  arbitrary `api_key_env` values are rejected. Replicate uses
  `"auth_scheme": "Bearer"` with `"credential_suffix": "API_TOKEN"`, so it
  reads `REPLICATE_API_TOKEN` and sends `Authorization: Bearer`.
- `protocol`: optional; defaults to `openai`. The Python-owned `http` option
  preserves raw dispatcher forwarding for a gateway such as Replicate whose
  native API is not an OpenAI chat API. It does not add an SDK adapter.

Operators still choose a model and supply credentials. For an OpenAI-compatible
broker, a `models.json` entry needs no API base:

```json
{
  "models": [
    {"provider": "examplebroker", "model": "vendor/model-id"}
  ]
}
```

Export `EXAMPLEBROKER_API_KEY` before starting RAPTOR, or use the existing
`models.json` credential seeding mechanism. Registration or exporting a key
alone never changes the default model. The operator must select the broker.

Broker SDK calls require the RAPTOR dispatcher. The parent consumes the key,
removes it from its environment, and injects authentication per upstream
request. Spawned dispatcher workers have broker credential variables removed
even from explicit environment overlays. SDK clients receive a dummy key and
talk over the dispatcher socket; there is no direct-network fallback. Missing
credentials produce the dispatcher's `503 provider not configured` response.
An `api_base` conflicting with the registry is rejected rather than forwarding
a broker credential to another endpoint. Existing inline keys in an
operator-owned `models.json` remain readable by processes with access to that
file; the registry does not change filesystem access policy.

For raw HTTP gateways, address the dispatcher at
`/<name><api_path>/<resource>` with the existing worker capability token.
Selecting `protocol: http` does not claim OpenAI SDK compatibility.

Python has final authority. JSON cannot register executable hooks, import
modules, add arbitrary authentication headers, override native adapters, or
borrow their credentials. Anthropic, Google, OpenAI, Mistral, and Cohere stay
in the direct-provider layer; cloud signing and request transformations stay
in Python. A new protocol or authentication mechanism requires a reviewed
Python adapter. Adding another broker using existing behavior requires only
another JSON entry.

The catalog is bundled installation data, never discovered in a scanned
project or downloaded at runtime. Endpoint changes redirect that broker's
credentials and require review. Invalid catalog data disables the entire
broker catalog with a diagnostic; native providers and unrelated tools remain
available. Attempts to use a broker then fail explicitly. CI validates the
catalog through the registry tests, and the environment inventory reads
credential names from the JSON directly.

Python-owned environment variables take precedence: runtime validation rejects
catalog entries whose derived credential names are already declared in RAPTOR's
Python source. The source inventory is read without importing those modules,
cached once per process, and checked again before a broker credential is read
or consumed. The environment-inventory CI check also checks collisions.
There are no aliases or compatibility mappings;
Credential naming and HTTP authentication are independent.
