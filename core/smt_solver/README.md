# SMT correctness contracts and C quality checks

This package solves explicit mathematical models. A solver verdict becomes
evidence about C code only after a consumer binds the model to source values,
types, control flow, and the target layout. The source-linked consumers live
in [core/audit](../audit/); the generic path parser also accepts diagnostic
models that do not establish those facts.

The common quality-check obligation is:

```text
admitted entry values AND reaching guards AND defined prefix AND issue
```

SAT exhibits an issue in that model. UNSAT excludes it in that model. Caller
reachability, the active build configuration, and any omitted memory semantics
remain separate questions. The result must retain its assumptions and scope.

## Choosing a question

| Question | Existing support | Source facts needed for a C claim |
| --- | --- | --- |
| Can addition, subtraction, or multiplication exceed its result range? | Signed and unsigned predicates in [csem.py](csem.py); source binding in [arithmetic_operation.py](../audit/arithmetic_operation.py) and [overflow_disproof.py](../audit/overflow_disproof.py). | Target ABI, operand declarations, integer promotions, the common result type, storage domains, reaching guards, and defined preceding evaluation. Unsigned wrap is defined C behavior; its existence alone does not establish a programming error. |
| Can division or remainder be undefined? | `division_undefined` in [csem.py](csem.py). | Promoted operand types and a source-bound operation. Test a zero divisor and, for signed operands, minimum divided by minus one. [integer_division.py](../audit/integer_division.py) binds one explicitly quoted atomic `/` or `%` site under an explicit ABI, validates its entry/prefix guards, and independently replays the witness. Explicit zero-divisor and signed-overflow hypotheses select different fault predicates; unknown subjects decline. Unsupported sites and safe operations remain inconclusive for a whole-function claim. |
| Can a shift have an invalid count or signed result? | `shift_count_invalid` and `left_shift_undefined` in [csem.py](csem.py); [integer_shift.py](../audit/integer_shift.py) checks atomic source shift counts. | Independently promoted left operand and count, their signedness, and the language version. The strict signed left-shift predicate models C99/C11 requirements; its SAT result alone is not a C++ undefined-behavior claim. |
| Can a conversion change an integer value? | `conversion_changes_value` and `truncation_loses_bits` in [csem.py](csem.py). | Explicit source/destination widths and signedness, target conversion behavior, and the property that requires value preservation. These predicates model specified bit-pattern conversions; an implementation-defined or deliberately narrowing conversion is not automatically a defect. |
| Can an index leave an array's bounds? | [array_bounds.py](../audit/array_bounds.py) binds a deliberately small local fixed-array read model. | The selected object and extent, index identity and type, entry domains, guards, and defined prefixes. Pointer arithmetic, dynamic allocations, aliases, and object lifetimes need additional models. |
| Does a signed/unsigned comparison use the intended integer values? | Explicit signed/unsigned comparisons in [bitvec.py](bitvec.py); conditional comparison diagnostics in [condition_smt.py](../audit/condition_smt.py). | Actual comparison conversions, including promotions and rank. Flipping a uniform profile is not a substitute for C's per-expression conversion rules. |
| Can a mutation break an invariant? | [invariant_smt.py](../audit/invariant_smt.py). | An admitted transition and reaching predicates. This is mathematical-integer induction: initialization, C overflow/conversions, aliasing, and application reachability are outside that proof. `preserved_nonneg` is conditional and remains inconclusive in aggregate. |

Shift-count checks preserve the separate promoted operand types and replay
negative/oversized counts independently. Signed left-shift value faults still
need explicit language-standard semantics beyond that count oracle. Typed conversion checks and comparison checks need per-expression
conversion facts before their mathematical witnesses become C counterexamples.
Uninitialized-value checks would additionally need definition/use tracking and
an initialization state per SSA value. Dynamic buffer checks would need object
identity, allocation extent, lifetime, and pointer-offset relations.

## Binding a source model

Use an explicit [IntegerABI](integer_abi.py) and preserve its complete record
and provenance. Widths are target facts, not host guesses. `sizeof` uses target
C bytes; the integer layout does not supply pointer, aggregate, or Boolean
storage layouts. [sizeof_model.py](sizeof_model.py) declines missing facts.

[arithmetic_types.py](../audit/arithmetic_types.py) admits supported builtin
integer types and value-preserving common frames. Mixed promoted signedness,
unresolved aliases, and wider guard variables can require a richer encoding.
Do not turn an unavailable type model into a guessed 32-bit or 64-bit proof.

Bind guards to the selected operation and the value snapshot at that point.
[arithmetic_guards.py](../audit/arithmetic_guards.py) and the prefix admission
code decline unsupported control flow or invalidated values. The generic
predicate API expects consistent scalar identities: callers must provide SSA
names when values change. Independent call return symbols do not establish
callee purity, unchanged globals, or unchanged memory. The explicit assignment
and address-exposure barriers are conservative checks, not a general effect
analysis; absence of a rejected argument does not establish purity.

Source-linked SAT witnesses are independently replayed by
[integer_witness.py](../audit/integer_witness.py). Replay checks storage domains,
the complete admitted guard set, the converted result range, and the selected
issue. Completing an omitted parameter with zero earns no authority until
that assignment passes those checks. Function-entry witnesses retain the
caller/build assumptions recorded by `source_model_scope`.

Legacy untyped guard models and width-only narrowing observations remain
diagnostic. Keep their classification in [evidence_grade.py](../audit/evidence_grade.py)
and consumer gates; a label, model, or successful native query cannot promote
an unbound observation into a source proof.

## Native query ownership

- Construct solvers through [session.py](session.py). Use `check_solver` inside
  an active `query_budget`; direct native `check()` bypasses that budget.
  Expiry returns unknown without a new query, so a previous native model or
  core cannot supply evidence for the skipped query. Process boundaries need
  explicit deadline handoff, as in the invariant workers.
- Use `scoped` for temporary assertions and propagate rollback failures.
  Continuing after failed cleanup can solve a different formula.
- [track_frames](assertion_frames.py) requires a fresh assertion frame. Call
  the returned frame's `check()` and use its captured native core positions
  and origins. Display labels may repeat and are not assertion identities.
  External checks cannot establish ownership for that frame.
- An optimizer's negative status can mean an exhausted Pareto frontier.
  `TrackedFrames.check()` requires an owned contradiction core before treating
  that status as UNSAT. A preferred witness is an optional objective, not an
  independent source-validity check.
- Keep every expression in its query's Z3 context. Bitvector bindings must
  match the declared uniform profile width. Registry keys can be aliases or
  derived expressions; generated symbols must avoid underlying declarations
  as well as those keys.
- Use [format_vars](witness.py) to evaluate registered identities. Native
  declaration names and generated aliases from `format_witness` are display
  diagnostics. They cannot identify an unrelated source variable. Model
  completion must not mutate the caller's model or repair a failed replay.

## Interpreting partial results

The path API returns `feasible=None` when supported predicates are satisfiable
but other predicates could not be encoded. Its model describes the encoded
subset. Do not clear `unknown` or `unknown_reasons` to obtain a positive result.
UNSAT of a sound weakening can still refute a conjunction, but dropping an
unmodeled state transition can merge different values. Such a refutation needs
native core ownership inside one mutation-free segment; dual-profile subset
probes must retain the barriers too.

Call summaries are optional callee-model assumptions surfaced in
`summary_axioms`. `refutation_uses_call_terms` describes native core dependence,
not a source return type or reachability proof. The dual-profile checker keeps
the selected width assumption and does not implement mixed C conversions.

The legacy `wp_predicate`, `wp_conjuncts`, and `wp_complete` fields describe
implication-based constraint reduction. Equivalence is relative to the supplied
background axioms. These fields are not a program weakest precondition or an
initialization/reachability proof. Undecided reduction keeps the conjunct and
marks the summary incomplete; optional reduction failures preserve the primary
verdict and its diagnostic model.

For new encoders, test both counterexamples and exclusions against an independent
integer or source evaluator. Small exhaustive domains help check bitvector
primitives, but do not establish C promotion rules for sub-`int` operands.
Include private contexts, invalid domains, unknown/expired queries, incomplete
predicates, mutations, and source-model refusal cases when they affect the
encoder's contract. Bind cached or worker results to the same source, ABI,
operation, and assumptions used by the query.

Source integer adapters admit closed objective labels around one backtick-quoted
expression, for example:

```text
Potential zero divisor in `Value / Count`.
invalid shift count in `Value << Count`
comparison is always false: `Value < 0`
```

A CWE tag and `potential`/`possible` metadata are optional. Labels may follow
the expression. Array bounds also accepts a bare `Data[Index]` as an implicit
read-bounds objective. Negated, conditional, or otherwise qualified prose is
inconclusive; callers must not discard those qualifications to manufacture a
positive goal. The source model's entry constraints and caller reachability
remain separate from this objective admission.

Legacy overflow objectives use the same closed goal admission while retaining
whole-expression quotes, individually quoted operands, unquoted operands and
explicit `plus`/`minus`/`times` operators. Expression extraction alone does not
certify an overflow goal. Both source confirmation and auxiliary disproof,
including literal-caller tuples, require a complete positive integer
`overflow`/`underflow`/`wraparound` label. Source receipts carry a separate goal
contract alongside their integer-model contract.

Closed overflow goals also accept `arithmetic overflow`, `addition overflow`
and `multiplication overflow`. The last two require `+` and `*` respectively
in the bound expression; one operation cannot supply a witness for the other.
`truncation overflow` is not an arithmetic-range objective and is not admitted
by this checker.

QUALITY also proposes direct builtin unsigned-integer initializer conversions
whose source storage range can exceed the destination range, including
equal-width signed-to-unsigned conversions. `check-integer-conversion` binds a
closed objective to one initializer and an explicit target ABI, for example:

```text
Potential non-representable unsigned conversion in `Small = Value`.
```

It checks
typed reaching guards and prefix admission, then independently replays a
reachable value-changing conversion. A guard excluding such values produces
no positive receipt; an unreachable or unsupported site remains inconclusive.

These source observations remain diagnostic and cannot verify unintended bug
intent, promote alone, or refute a whole function. Boolean and signed
destinations, aliases, non-atomic initializers, mutation and ambiguous sites
receive no source-conversion credit. The older width-only narrowing diagnostic
keeps its existing scope. Candidate preparation does not enter the solver;
new conversion leads follow existing leads within the same finite budgets.

QUALITY comparison candidates may also use simple controlling parameter/literal
comparisons and direct early-return checks to propose a constant test. This
preparation uses bounded, value-preserving storage intervals, without solver or
SSA credit. It does not assume a test's own truth, flatten disjunctions, guess
literal widths, or generate a constant from an empty candidate range. These
hints follow prior source leads within the existing budgets. The comparison
oracle must still validate the complete prefix, typed guards, source identity
and reachable entry; mutation or unsupported control flow cannot earn a proof
from candidate metadata.

QUALITY may also propose impossible grouped builtin mask tests, for example
the following closed objective:

```text
Comparison is always false in `(Flags & 5) == 2`.
```

The source comparison
oracle binds one matching `==` or `!=` test with an immutable builtin entry
parameter and small integer literals. It preserves the actual C/C++ operator
precedence, promotions and target ABI. Entry satisfiability, an exact bitvector
proof that the contrary truth is impossible, and independent witness replay
are required. This catches impossible bit combinations inside an otherwise
plausible result interval. The observation remains diagnostic and non-refuting;
it does not prove unintended bug intent. Mask candidate preparation is bounded
and solver-free, and follows prior leads within the same discovery limits.

Fixed local-array reads also admit one affine index such as `Data[Index+1]`
or `Data[Index-1]`, with an immutable builtin parameter and a small nonnegative
integer literal. The actual source tree must match the complete read goal.
Index arithmetic uses its promoted type: unsigned results wrap modulo that
width, while signed arithmetic must already satisfy the existing prefix
checker. Unproved signed arithmetic remains unsupported even when a more
precise path model might establish it. Both direct witnesses and literal-caller
tuples independently replay the computed index; the parameter value alone is
not a bounds witness. Discovery remains a solver-free candidate stage.

Division and remainder faults may also use one affine denominator, for example
`Value / (Count-1)`. The source oracle retains the denominator expression's
promotions before applying the division's usual arithmetic conversions. This
distinguishes a signed `-1` divisor from an unsigned wrapped value. The complete
closed objective, unique actual source operation, prefix definedness, feasible
entry and independent replay remain mandatory. Unproved signed denominator
arithmetic is unsupported; a safe or unknown result never clears a function.
QUALITY preparation proposes bounded storage/type candidates after prior leads,
without performing native queries or granting source-path credit.

For a signed affine denominator, typed reaching guards may establish the
subexpression's definedness. The oracle first proves entry feasibility, then
requires signed addition/subtraction overflow to be impossible for every
admitted entry before checking the division fault. These checks share one
query deadline. A wider numerator does not widen the denominator's earlier
arithmetic; an overflowing, undecided or unreachable subexpression earns no
receipt. For example, `Count > 0` makes `Count-1` defined while still admitting
a zero divisor at `Count == 1`.

Invariant-preservation receipts describe a mathematical transition assuming the
supplied invariant held before that transition. They do not establish its
initialisation, source reachability or C integer semantics. Preserved sites,
including functions with no relevant mutations, are diagnostic observations;
they cannot refute a source-level claim or justify clean conversion. Concrete
transition witnesses remain diagnostic too. Historical invariant refutation
records cannot regain authority through a channel alias or `:witness` suffix.

The QUALITY source checker also enumerates builtin signed unary negation.
It applies integer promotions, requires a feasible source entry and replays
the signed-minimum witness independently. The `check-unary-negation` receipt
is diagnostic: a local arithmetic witness does not establish caller reachability,
and a safe or unsupported negation never clears the source claim.
