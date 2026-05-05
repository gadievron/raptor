# Typed Plan Layer for `hypothesis_validation` (follow-up to PR #309)

Design doc for adding a category-theoretic typed-plan layer on top of the
`hypothesis_validation` substrate introduced in PR #309. The PR already
enforces the LLM-tool-LLM separation; this document describes the additions
that turn its architectural invariants into consequences of a type system,
and that make the deferred iteration loop safe to wire in.

## Background

PR #309 introduces `packages/hypothesis_validation/`, an LLM-tool-LLM substrate
in which the LLM forms hypotheses ("input X flows unchecked to sink Y"),
deterministic tools (Coccinelle, Semgrep, CodeQL, SMT) validate them, and
verdicts (`confirmed` / `inconclusive` / `refuted`) are computed mechanically
from tool evidence — never claimed directly by the LLM.

Three architectural invariants are enforced and tested:

- LLM cannot claim *confirmed* without matches → downgraded to *refuted*.
- LLM cannot claim *refuted* with matches present → downgraded to *inconclusive*.
- Tool failure → *inconclusive* (absence of evidence ≠ evidence of absence).

This document proposes the next layer: typing the substrate so these invariants
become consequences of the type system rather than rules enforced by
hand-written checks, and so multi-adapter aggregation and (later) iteration
compose by construction.

## Mapping existing concepts to typed equivalents

| Existing concept                       | Typed name                  | What naming it buys                            |
| -------------------------------------- | --------------------------- | ---------------------------------------------- |
| Hypothesis ("X flows to Y")            | object in **Hyp**           | typed projections into each adapter language   |
| Four adapters (SmPL, YAML, .ql, SMT)   | morphisms `Hyp → Evidence`  | composition + adapter selection by type        |
| confirmed / inconclusive / refuted     | agreement lattice           | multi-adapter aggregation as one combinator    |
| "Confirmed without matches → refuted"  | Galois connection LLM⊣Tools | invariant becomes a theorem                    |
| "Tool failure → inconclusive"          | bottom-preserving morphism  | composes safely under iteration                |
| `<untrusted_tool_output>` tags         | lens on the prompt          | refactor-safe prompt construction              |
| `sandbox=True`, `env=safe_env`         | effect annotation in Kleisli| iteration cannot smuggle in effects            |
| Single-shot; iteration deferred        | the boundary                | where types pay rent most (see §"Iteration")   |

## Concrete additions to `packages/hypothesis_validation/`

### 1. Type the hypothesis itself

Currently the hypothesis lives as free-form text in the LLM prompt. Promoting
it to a Pydantic model removes a class of failures where the natural-language
phrasing under-specifies what an adapter should look for.

```python
class Hypothesis(BaseModel):
    cwe: str                            # "CWE-78"
    source: SourceLocation              # kind ∈ {network, file, env, ...}
    sink:   SinkLocation                # kind ∈ {exec, sql, deref, ...}
    flow:   list[FlowStep]
    expected_sanitizers: list[Pattern]
    smt_constraints: list[str] = []
    rationale: str                      # LLM reasoning; explicitly NOT a verdict
```

### 2. Adapters as functorial projections, not just runners

Each adapter declares both how to *project* a `Hypothesis` into its query
language and how to *run* the projection. The `project` is where the existing
prompt templates that turn a hypothesis into SmPL / YAML / .ql / SMT live,
made first-class.

```python
class AdapterSpec(BaseModel):
    name:       str
    applicable: Callable[[Hypothesis], bool]          # type-level filter
    project:    Callable[[Hypothesis], AdapterQuery]  # the functorial part
    run:        Callable[[AdapterQuery, Target], Evidence]
    effects:    set[Effect]                           # {Network=False, FS=ro, ...}
    cost:       Cost
```

`applicable` lets the runner skip adapters that cannot say anything about a
given hypothesis — SMT skips a hypothesis with no constraints, Coccinelle
skips a hypothesis without C source, and so on.

### 3. Verdicts as an explicit agreement lattice

Replace the three downgrade rules with one combinator. The current invariants
become a property of `meet ∘ verdict_from` rather than three separate
hand-coded checks.

```python
class Verdict(str, Enum):
    REFUTED      = "refuted"
    INCONCLUSIVE = "inconclusive"     # bottom
    CONFIRMED    = "confirmed"

def meet(a: Verdict, b: Verdict) -> Verdict:
    """Agreement lattice: equal verdicts compose; disagreement is bottom."""
    return a if a == b else Verdict.INCONCLUSIVE

def verdict_from(ev: Evidence, llm_claim: Verdict) -> Verdict:
    if ev.error:                                       return Verdict.INCONCLUSIVE
    matches = bool(ev.matches)
    if llm_claim is Verdict.CONFIRMED and not matches: return Verdict.REFUTED
    if llm_claim is Verdict.REFUTED   and     matches: return Verdict.INCONCLUSIVE
    return llm_claim

def aggregate(evs: list[Evidence], llm_claim: Verdict) -> Verdict:
    return reduce(meet, (verdict_from(e, llm_claim) for e in evs))
```

The existing `test_security.py` invariant tests become one-line lattice
property checks (idempotence, commutativity, INCONCLUSIVE-as-bottom).

### 4. Provenance edges so evidence cannot float free

Add `refers_to: HypothesisHash` on every `Evidence` and `Match`. The runner
refuses to combine evidence whose `refers_to` differ. This pre-emptively kills
a class of bugs in any future iteration loop where evidence from hypothesis
*n−1* could leak into hypothesis *n*.

### 5. The `<untrusted_tool_output>` envelope as a real lens

The hardening commit's tag-neutralisation logic is exactly the `put` half of
a lens on the LLM prompt context. Making it explicit means future changes to
the prompt format cannot accidentally bypass neutralisation — the lens laws
are CI-checkable properties.

```python
prompt_lens = Lens[PromptCtx, list[Match]](
    get = lambda ctx: ctx.tool_section,
    put = lambda ctx, ms: ctx.with_tool_section(neutralise_tags(ms)),
)

# Property tests:
#   get(put(s, a)) == a
#   put(s, get(s)) == s
```

## Iteration: where the types earn their keep

The deferred iteration loop is where this stops being decoration. The
IEEE-ISTAS 2025 result that PR #309 cites — 37.6 % more critical findings
after five rounds of self-critique — is precisely the failure mode that
typed plans prevent. Each iteration step gets a Hoare-style postcondition:
the *uncertainty* about the hypothesis must strictly decrease, in
evidence-lattice terms, before another LLM call is permitted.

```python
class IterationStep(BaseModel):
    hypothesis: Hypothesis
    evidence:   list[Evidence]
    verdict:    Verdict

    @model_validator(mode="after")
    def grounded(self):
        assert self.verdict == aggregate(self.evidence, llm_claim=self.verdict)
        return self

def must_progress(prev: IterationStep, curr: IterationStep) -> None:
    assert curr.hypothesis != prev.hypothesis            # actual refinement
    assert info_content(curr) > info_content(prev)       # strictly decreasing
                                                         # uncertainty measure
```

A "refine" that does not strictly progress is rejected before any tool runs;
a loop that cannot progress terminates by construction. This is the property
that distinguishes IRIS / SAILOR-style tool-grounded iteration from raw
self-critique, and here it falls out of the type system rather than from
operator discipline.

## Suggested follow-up PR scope

Mergeable in the same shape and spirit as PR #309 — additions with
backward-compatible defaults, the way the hardening commit added
`subprocess_runner=...` to existing runners.

1. `types.py` — `Hypothesis`, `SourceLocation`, `SinkLocation`, `FlowStep`,
   `Verdict`, `Evidence`, `Match`, `AdapterSpec`.
2. Convert each existing adapter to `AdapterSpec` (the `project` is the
   prompt template that already exists; `run` is the existing function
   unchanged).
3. `verdict.py` — `meet`, `verdict_from`, `aggregate`. Existing invariant
   tests become lattice property tests.
4. `provenance.py` — `HypothesisHash`; runner refuses cross-hypothesis
   evidence combination.
5. `prompt_lens.py` — formalise the `<untrusted_tool_output>` envelope as a
   lens; tag neutralisation moves inside `put`; lens laws as tests.
6. Ship `IterationStep` and `must_progress` as exported skeletons but
   **do not wire them in** — the next PR drops in cleanly on top.

The 104 + 31 existing tests should pass untouched. New tests are mostly
property-style (lattice algebra, lens laws, provenance integrity).

## How this composes with an AST-typed plan checker

Once `AdapterSpec` exists, a plan is a DAG of typed `AdapterSpec` morphisms
between artifact types. A plan validator can type-check projections,
applicability, and effect annotations against a registry before any tool
runs — eliminating the most common LLM agent failure mode (hallucinated
shapes of tool inputs and outputs) at compile time. The plan executor is
what PR #309 already ships; the AST checker meets it in the middle.

The first real consumer mentioned alongside PR #309 — IRIS-style dataflow
validation in `/agentic` — then becomes the first real client of the
typed-plan layer, rather than a one-off integration.