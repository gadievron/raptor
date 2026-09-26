# Taint spec packs

Curated source/sink/sanitizer/propagator vocabulary as data, loaded
fail-closed by `core/taint/packs.py`. Convention (shared with
`core/function_taxonomy/data/packs/` and `core/audit/data/vocab_packs/`):
**seeds < pack < learned** — these packs stay small curated seed sets
(<= 9 exemplars per role per sink class); anything project-specific is
learned at run time (IRIS / study loop) and enters through the bounded
intake in `core/taint/learned_intake.py`, never added here.

Layout: `<language>/<pack>.json`, addressed by pack NAME
(`python/web-injection-core`) — the loader never accepts a filesystem
path, and refuses any pack that resolves inside a scanned target tree.

Entry rules the loader enforces (see the module docstring for the full
format):

* every entry carries `provenance` (accepted values are the
  models-as-data emitter's `ACCEPTED_PROVENANCE`) and a bounded,
  printable `rationale` saying WHY the claim holds;
* match fields are exact dotted names / identifiers — no regex;
* `method_name` sinks must declare `confidence: "heuristic"`;
* `unless_kwargs` values match literal call-site tokens only;
* sanitizers may not restate a curated
  `core/dataflow/known_safe_calls.py` callee (that table is merged in
  automatically: transform entries kill, validate entries tag);
* `kill` sanitizers must name explicit sink classes (no wildcard);
* propagator `"narrowing": true` is legal only in these
  operator-controlled files and must be visible in review.

The stored-taint kinds (`stored_read` / `stored_write`, paired by
`store_key`) are used by `second-order-stores`: a `stored_read`
source's return carries the store's taint, a `stored_write` hit is a
finding of the entry's class, and entries sharing a `store_key` label
declare the same store's write and read halves (cross-request pairing
consumes the label; the label itself is free-form lowercase).

## Shipped packs (python)

* `web-injection-core` — stdlib/common sinks for command-injection,
  sql-injection, code-injection, path-traversal, template-injection
  and xss; tag/kill sanitizer exemplars; stdlib propagators.
* `frameworks-flask` — flask.request surfaces + route-param binding;
  send_file / redirect sinks.
* `frameworks-django` — route-param binding + QueryDict source;
  RawSQL / raw() / extra() and redirect sinks.
* `frameworks-fastapi` — route-param binding; redirect / file /
  HTML-response sinks (fastapi and starlette import spellings).
* `second-order-stores` — stored-taint pairs over the common stores
  (Django ORM save/filter, DB-API execute-parameters/fetch, redis
  set/get, pickle dumps/loads) plus the pickle.loads
  deserialization sink.
* `secrets-flow` — credential sources (getpass, env reads, keyring,
  boto3 credentials) and secret-exposure sinks (logging, print,
  query-string encoding, exception messages, subprocess argv);
  tag-only redaction sanitizers.
* `template-engines` — constructor-level SSTI sinks the core pack
  lacks: from_string surfaces (jinja2 dotted + receiver-hinted
  method form, native-types jinja2, django Engine), tornado, bottle,
  Cheetah, chameleon. The render-call sinks (jinja2.Template,
  render_template_string, mako, django.template.Template) stay in
  `web-injection-core`.
