# Function-taxonomy data packs

Versioned name-vocabulary packs merged into taxonomy categories at
import time. Convention (shared with `core/audit/data/vocab_packs/` and
the crypto API packs at `engine/coccinelle/source_intel/crypto/packs/`):
**seeds < pack < learned** — the category constant in
`core/function_taxonomy/__init__.py` keeps a marked seed set of <= 9
exemplars; the pack carries the catalog bulk as data; anything
project-specific is learned at run time (study loop / IRIS), never
added here.

## parser_apis.json

High-CVE-density parser/decoder entry points (the `PARSER_FUNCS`
category — fuzz prioritisation, binary surface classification, Frida
flow-trace hooks). Consumed as `PARSER_SEED_FUNCS | pack` — a missing
or malformed pack degrades to seeds-only, never an import error.

Entry shape:

```json
{
  "name": "XML_ParseBuffer",          // exact exported symbol name
  "library": "expat",                 // which library owns it
  "provenance": ["cve-fix-diff"],     // how we know it matters
  "cves": ["CVE-2015-1283"]           // the security fixes that touched it
}
```

Provenance values:

* `cve-fix-diff` — harvested by `libexec/raptor-parser-pack-harvest`
  from CVE-referencing fix commits of the library's own history: the
  name is a public-API function that a security fix modified (hunk
  enclosing-context, filtered to the library's exported-namespace
  patterns from `core/dataflow/data/parser_pack_sources.json`).
* `legacy-catalog` — inherited from the pre-migration hardcoded
  `PARSER_FUNCS` list (curation rationale lived in code comments; kept
  because consumers depended on it, upgraded to `cve-fix-diff` when a
  harvest corroborates it).

## Refreshing

```
libexec/raptor-parser-pack-harvest --clone-root <dir-of-clones> [--dry-run]
```

Clone the libraries listed in `core/dataflow/data/parser_pack_sources.json`
under one root (partial clones fine — pass `--allow-promisor-fetch`),
then run the harvester. Merging is **additive only**: a refresh can add
entries and CVE provenance but never removes an entry — shrinking the
pack silently regresses every consumer, so pruning is a deliberate
manual edit with review, not a regeneration side effect.

Initial pack (2026-08-16): 37 legacy-catalog entries + 97 harvested
names / 1 corroboration from 49 distinct CVEs across expat, libxml2,
jansson, json-c, cJSON, libpng (real fix-history harvest of 13 cloned
repos; libraries without harvestable clones — openssl, lua, cpython,
libtiff, bzip2 — remain legacy-only until a future refresh).
