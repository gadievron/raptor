"""Distilled grammar references for checker synthesis engines.

Each constant is a prompt-sized subset of the engine's grammar —
enough for the LLM to emit syntactically valid rules without
hallucinating constructs that don't exist.

Coccinelle reference distilled from the official SmPL grammar:
https://coccinelle.gitlabpages.inria.fr/website/docs/main_grammar.html

Semgrep reference distilled from the official rule syntax docs:
https://semgrep.dev/docs/writing-rules/rule-syntax
"""

COCCINELLE_GRAMMAR = r"""\
## Coccinelle SmPL quick reference (subset for checker synthesis)

### Rule structure

A rule has a metavariable header between @@ delimiters, then a body:

```
@ rulename @
<metavariable declarations>
@@
<pattern body>
```

Anonymous rules omit the name:

```
@@
<metavariable declarations>
@@
<pattern body>
```

### Metavariable types

Declare metavariables between the @@ delimiters, one per line,
terminated by semicolons:

```
expression E;              -- any C expression
expression E1, E2;         -- multiple on one line
identifier id;             -- a name (variable, function, field)
type T;                    -- a C type
statement S;               -- a statement (incl. compound)
statement list SL;         -- zero or more statements
constant C;                -- a compile-time constant
position pos;              -- attaches to a token to record location
declaration D;             -- a declaration
parameter P;               -- a function parameter
parameter list PL;         -- zero or more parameters
local idexpression E;      -- local variable expression
```

Typed metavariables (constrain the C type):

```
expression int E;          -- expression of type int
expression char *E;        -- expression of type char *
{int, unsigned int} E;     -- expression matching any listed type
```

### Position metavariables

Position metavariables record WHERE a match occurs. Attach with @:

```
@ rule @
expression E;
position pos;
@@
  malloc@pos(E)
```

IMPORTANT: RAPTOR's Coccinelle harness requires at least one position
metavariable to emit structured match output. Always include one.

### Context mode (*)

Prefix a line with * to match without transforming. Use this for
detection rules that report but don't modify code:

```
@ rule @
expression E;
position pos;
@@
* kfree@pos(E)
```

### Transformation (minus/plus)

Remove lines with - prefix, add with + prefix:

```
@@
expression E;
@@
- kfree(E);
+ kfree_safe(E);
```

### Ellipsis (...)

`...` matches any sequence of statements/declarations between two
code points:

```
@@
expression E;
@@
  E = malloc(...);
  ...
  return ...;
```

### When clauses

Constrain what the ellipsis `...` may pass over:

```
... when != expr           -- ... must NOT pass over expr
... when == expr           -- ... MUST pass over expr
... when any               -- match even if other paths exist
... when strict            -- all execution paths must match
... when forall            -- all bindings must satisfy
... when exists            -- at least one binding suffices
```

Example — malloc without free:

```
@ rule @
expression E;
position pos;
@@
* E@pos = malloc(...)
  ... when != free(E)
```

Example — use after free:

```
@ rule @
expression E;
position pos;
@@
  kfree(E);
  ... when != E = ...
* E@pos
```

### Disjunction

Group alternatives with ( ... | ... ) — opening paren, pipe, and
closing paren must be in column 0 or preceded by backslash:

```
@@
expression E;
position pos;
@@
(
  snprintf@pos(..., E)
|
  sprintf@pos(..., E)
|
  fprintf@pos(..., E)
)
```

### Rule dependencies

```
@ rule2 depends on rule1 @    -- only runs if rule1 matched
@ rule2 depends on !rule1 @   -- only runs if rule1 did NOT match
@ rule2 depends on ever r1 @  -- r1 matched somewhere in the file
@ rule2 depends on never r1 @ -- r1 never matched in the file
```

### Script rules

```
@ script:python depends on rule1 @
p << rule1.pos;
@@
cocci.print_main("msg", p)
```

### Common patterns for security checkers

Missing NULL check after allocation:

```
@ rule @
expression E;
position pos;
@@
* E@pos = \(malloc\|calloc\|realloc\)(...)
  ... when != E == NULL
      when != E != NULL
      when != !E
```

Double free:

```
@ rule @
expression E;
position pos;
@@
  kfree(E);
  ... when != E = ...
* kfree@pos(E)
```

Format string (user-controlled format argument):

```
@ rule @
expression E;
position pos;
@@
(
* snprintf@pos(..., E)
|
* sprintf@pos(..., E)
|
* printf@pos(E)
)
```

### Syntax pitfalls (AVOID these)

- Do NOT invent functions like `is_string_constant()` — Coccinelle
  has no such built-in. Use metavariable type constraints instead.
- `when` clauses attach to `...` (ellipsis), not to expressions.
  `E when != ...` is invalid; `... when != E` is correct.
- Metavariable names are case-sensitive. Conventionally uppercase.
- Every metavariable must be declared. Undeclared names cause parse
  errors.
- The `*` context-mode prefix goes at the start of the line, before
  any whitespace.
- String constants use `"..."` — Coccinelle matches C string literal
  syntax, not SmPL-level regex.
- Parentheses in disjunctions ( | ) must start in column 0.
"""

SEMGREP_GRAMMAR = r"""\
## Semgrep rule syntax quick reference (subset for checker synthesis)

### Rule file structure

A Semgrep rule file is YAML with a top-level `rules:` list. Each
entry is one rule:

```yaml
rules:
- id: rule-id-kebab-case
  languages: [python]
  severity: HIGH
  message: >-
    Description of what was found.
  pattern: unsafe_function(...)
```

### Required fields

Every rule MUST have:
- `id`: unique kebab-case identifier
- `languages`: list of target languages
- `severity`: one of LOW, MEDIUM, HIGH, CRITICAL
  (legacy values ERROR, WARNING, INFO still accepted)
- `message`: human-readable description
- One pattern operator (see below)

### Supported languages

`python`, `javascript`, `typescript`, `java`, `go`, `ruby`, `c`,
`cpp`, `csharp`, `rust`, `kotlin`, `swift`, `scala`, `php`, `lua`,
`bash`, `json`, `yaml`, `xml`, `html`, `generic`

### Pattern operators (pick ONE top-level)

```yaml
pattern: <code pattern>           # match this pattern
patterns:                         # AND — all must match
  - pattern: ...
  - pattern: ...
pattern-either:                   # OR — any can match
  - pattern: ...
  - pattern: ...
pattern-regex: <regex>            # match raw regex
```

For taint (source-to-sink) rules use `mode: taint` with
`pattern-sources` and `pattern-sinks` instead of the above.
See the Taint mode section below.

### Pattern syntax

Metavariables capture values:

```yaml
pattern: $FUNC($ARG1, $ARG2)     # named metavariables
pattern: foo(...)                 # ... matches any arguments
pattern: foo($...ARGS)            # spread metavar (0+ args)
pattern: $_ ($ARG)               # $_ = anonymous "don't care"
pattern: |                        # multi-line pattern
  if $COND:
      $BODY
```

Metavariables are NEVER quoted. `$VAR` in a pattern matches any
expression; `"$VAR"` matches the literal string `$VAR`. To match
a function call that takes any string argument, use
`foo($ARG)` — NOT `foo("$ARG")`.

String literal matching: `"..."` in a pattern matches any single
string literal. `foo("...")` matches `foo("hello")` but not
`foo(variable)`.

Ellipsis `...` in statement position matches zero or more statements:

```yaml
pattern: |
  $X = dangerous()
  ...
  sink($X)
```

### Combining patterns (AND logic)

`patterns:` requires ALL sub-patterns to match the same code.
Negation operators (`pattern-not`, `pattern-not-inside`) MUST be
inside a `patterns:` list to take effect:

```yaml
patterns:
  - pattern: subprocess.run($CMD, shell=True)
  - pattern-not: subprocess.run("...", shell=True)
```

### Negation operators

These ONLY work inside `patterns:` — never at the top level.
If placed alongside a top-level `pattern:`, they are silently
ignored (no error, but negation has no effect).

```yaml
pattern-not: <pattern>            # exclude matches of this
pattern-not-inside: |             # exclude if inside this
  with suppress(...):
      ...
pattern-not-regex: <regex>        # exclude regex matches
```

### Contextual operators

```yaml
pattern-inside: |                 # require match is inside
  def $FUNC(...):
      ...
pattern-inside: |                 # nested function context
  class $CLS:
      ...
```

### Metavariable constraints

```yaml
patterns:
  - pattern: $FUNC($ARG)
  - metavariable-regex:
      metavariable: $FUNC
      regex: (exec|eval|system)   # left-anchored by default
  - metavariable-comparison:
      metavariable: $SIZE
      comparison: $SIZE > 1024
  - metavariable-pattern:
      metavariable: $ARG
      pattern: user_input(...)
```

Note: `metavariable-regex` is LEFT-ANCHORED by default. To match
anywhere in the string, prefix with `.*`: `regex: .*(exec|eval)`.

### Taint mode

For source-to-sink data flow tracking:

```yaml
rules:
- id: sqli-taint
  mode: taint
  languages: [python]
  severity: HIGH
  message: SQL injection
  pattern-sources:
    - pattern: flask.request.$ATTR
  pattern-sinks:
    - pattern: cursor.execute($QUERY, ...)
  pattern-sanitizers:
    - pattern: sanitize($X)
```

Taint mode fields:
- `mode: taint` (required — without it, `pattern-sources` and
  `pattern-sinks` are rejected as invalid)
- `pattern-sources`: where tainted data enters (required)
- `pattern-sinks`: where tainted data is dangerous (required for
  checker synthesis — without sinks, the rule matches nothing useful)
- `pattern-sanitizers`: (optional) what cleans tainted data
- `pattern-propagators`: (optional) how taint spreads

When to use taint mode vs pattern mode:
- Taint mode: when the bug is a DATA FLOW from untrusted input to
  a dangerous sink (SQL injection, XSS, command injection, SSRF).
- Pattern mode: when the bug is a STRUCTURAL pattern (weak hash,
  hardcoded secret, missing check, use of deprecated API).

Each source/sink/sanitizer entry accepts `exact` (bool) and
`by-side-effect` (bool). Sources default to `exact: false`
(subexpressions carry taint); sinks default to `exact: true`.

Source/sink entries support `focus-metavariable` to narrow what
carries taint:

```yaml
pattern-sources:
  - pattern: |
      def $FUNC(..., $PARAM, ...):
          ...
    focus-metavariable: $PARAM
```

### focus-metavariable

Narrow the reported match to a specific metavariable:

```yaml
patterns:
  - pattern: $FUNC($X, $Y)
  - focus-metavariable: $X
```

### Common patterns for security checkers

SQL injection (taint mode — preferred for source-to-sink flows):

```yaml
rules:
- id: flask-sqli-taint
  mode: taint
  languages: [python]
  severity: HIGH
  message: SQL injection via user input
  pattern-sources:
    - pattern-either:
      - pattern: request.form[$_]
      - pattern: request.args.get(...)
  pattern-sinks:
    - patterns:
      - pattern-either:
        - pattern: $CURSOR.execute($QUERY, ...)
        - pattern: $CURSOR.execute($QUERY)
      - focus-metavariable: $QUERY
```

Note: the sink wraps `pattern-either` + `focus-metavariable` inside
a `patterns:` list. See the pitfall below about combining these.

Hardcoded credentials:

```yaml
rules:
- id: hardcoded-password
  languages: [python]
  severity: HIGH
  message: Hardcoded password
  patterns:
    - pattern: $VAR = "..."
    - metavariable-regex:
        metavariable: $VAR
        regex: (password|passwd|secret|token)
```

Missing input validation:

```yaml
rules:
- id: unvalidated-redirect
  mode: taint
  languages: [python]
  severity: HIGH
  message: Open redirect
  pattern-sources:
    - pattern: request.args.get(...)
  pattern-sinks:
    - pattern: redirect($URL)
```

### Syntax pitfalls (AVOID these)

- `pattern` and `patterns` are mutually exclusive at the same level.
  Use `patterns:` with a list when combining, or `pattern:` alone.
- **`pattern-not` / `pattern-not-inside` at the top level are
  SILENTLY IGNORED.** They MUST be inside a `patterns:` list:
  ```yaml
  patterns:                          # correct
    - pattern: cursor.execute(...)
    - pattern-not: cursor.execute("...")
  ```
  NOT:
  ```yaml
  pattern: cursor.execute(...)       # WRONG — pattern-not is ignored
  pattern-not: cursor.execute("...")  # silently dropped, no error
  ```
- `pattern-either` entries each need their own `pattern:` key:
  ```yaml
  pattern-either:
    - pattern: foo(...)     # correct
    - pattern: bar(...)
  ```
  NOT:
  ```yaml
  pattern-either:
    - foo(...)              # WRONG — missing pattern: key
  ```
- Metavariable names MUST start with `$` and be UPPERCASE:
  `$VAR` is valid, `$query` (lowercase) is treated as a literal
  identifier and will silently fail to match.
- NEVER put metavariables inside quotes in a pattern.
  `foo($ARG)` matches `foo(x)`. `foo("$ARG")` matches only the
  literal string `"$ARG"` and silently produces zero results.
- `"..."` inside a pattern matches any single string literal.
  `foo("...")` matches `foo("hello")` but NOT `foo(variable)`.
  This is distinct from `...` (no quotes) which matches any
  expression.
- Multi-line patterns use `|` (literal block scalar) after
  `pattern:`, not quotes. Indentation matters — the pattern body
  must be indented consistently relative to the `pattern: |` line.
- `...` in a pattern matches zero or more arguments OR statements
  depending on context. In function calls `foo(...)` it matches
  any arguments. In statement position it matches any statements.
- `mode: taint` rules CANNOT use `pattern:` / `patterns:` /
  `pattern-either:` at the top level — they use `pattern-sources`
  and `pattern-sinks` instead.
- Using `pattern-sources` or `pattern-sinks` WITHOUT `mode: taint`
  is a schema error. Always include `mode: taint` when using these.
- To combine `pattern-either` with `focus-metavariable` inside
  `pattern-sinks` (or `pattern-sources`), wrap BOTH in a `patterns:`
  list as a single sink entry:
  ```yaml
  pattern-sinks:
    - patterns:                        # correct — single entry
      - pattern-either:
        - pattern: $DB.execute($Q)
        - pattern: $DB.executemany($Q, ...)
      - focus-metavariable: $Q
  ```
  NOT:
  ```yaml
  pattern-sinks:
    - pattern-either:                  # WRONG — two separate entries
      - pattern: $DB.execute($Q)
    - focus-metavariable: $Q           # rejected: not a valid sink
  ```
- The `languages` field is a list, not a string:
  `languages: [python]` not `languages: python`.
  The language MUST match the target file. A rule with
  `languages: [javascript]` silently produces zero matches on
  Python files (no error).
- Rule IDs must be kebab-case with no spaces or special characters.
"""

