# Design Proposal: ZKPoX libxml2 Fidelity Differential

*Status: Design proposal / planned work. Closes the single largest
credibility gap remaining after the Phase 1.7 target-03 PR.*

*Related: `docs/proposals/zkpox-phase-1.5.x.md` (verification gap),
`docs/zkpox-scope.md` (scope-of-trust), `core/zkpox/targets/03-libxml2-cve-2017-9047.c`
(the extraction this proposal validates).*

---

## 1. The gap in one paragraph

ZKPoX target #3 proves that a witness drives an out-of-bounds write in a
**hand-extracted, freestanding** reproduction of libxml2's
`xmlSnprintfElementContent` (CVE-2017-9047). Because SP1's RISC-V guest
has no libc, the extraction open-codes `strlen`/`strcat` (`z03_strlen`,
`z03_strcat_n`) and *asserts in a comment* that "the bug is ...
faithfully reproduced." Nothing mechanical backs that assertion. As a
non-cryptographer reviewer put it on 2026-05-11: the proof currently
says *"this small re-implementation has a bug,"* not *"the real library
does."* A skeptical CVD recipient is right to distrust a comment. This
proposal builds a mechanical oracle that turns the comment into a
per-witness, every-PR assertion.

## 2. Goal

For **every** `03-*.bin` witness in the corpus, assert that our
freestanding extraction and **pre-fix upstream libxml2** agree on the
OOB outcome — both overflow, or both don't, on identical input. Any
disagreement fails CI. The deliverable is a differential test, not a
second re-implementation.

Success criterion: a reviewer no longer takes the extraction on faith.
CI proves, witness by witness, that the gadget verdict tracks ground
truth from the real pre-fix function under ASan.

## 3. The bug (ground truth being matched)

From `targets/03-libxml2-cve-2017-9047.c` and upstream `valid.c`:

- In the `XML_ELEMENT_CONTENT_ELEMENT` branch, `len = strlen(buf)` is
  captured **once** at entry.
- The code appends `content->prefix` and `":"` (buffer grows by
  `prefix_len + 1`), then checks room for `content->name` against the
  **stale** `len`.
- With a prefix, the name-fit check is wrong by exactly `prefix_len + 1`
  bytes, so the final `strcat` runs past the caller's buffer.
- Fixed in GNOME/libxml2 `932cc9896ab4` ("Fix buffer size checks in
  xmlSnprintfElementContent", 2017-06-03) by recomputing a combined
  qname length up front. **Parent (pre-fix) commit: `0741801`.**

Geometry that the witnesses assume (must be preserved exactly):

- Buffer `size = 32`. (At `size = 16`, targets 01/02's geometry, the
  math admits no overflow — target 03 deliberately brings its own
  buffer size.)
- Max bytes past the buffer with an empty caller `buf`:
  `prefix_len + name_len + 2 - size`, capped by the bypass checks at
  `prefix_len - 8` (up to 14 bytes for `size = 32`).
- Upstream signature:
  `xmlSnprintfElementContent(char *buf, int size, xmlElementContentPtr content, int englob)`.

## 4. Witness encoding (shared contract)

The ASan driver MUST decode the identical layout target 03 uses:

```
input[0]                                    prefix_len (u8, 0..255)
input[1]                                    name_len   (u8, 0..255)
input[2 .. 2+prefix_len]                    prefix bytes
input[2+prefix_len .. 2+prefix_len+name_len]  name bytes
n < 2 + prefix_len + name_len               → no-op (victim returns early)
```

## 5. Deliverables

### 5.1 Vendored pre-fix slice — `core/zkpox/test/fixtures/libxml2-slice/`

Vendor the **real** `xmlSnprintfElementContent` from `valid.c` at commit
`0741801`, plus the minimal surrounding declarations needed to compile
host-native:

- the `xmlElementContent` / `xmlElementContentPtr` struct (only the
  fields the function touches: `type`, `name`, `prefix`, `c1`, `c2`),
- `xmlStrlen` (or `#include <string.h>` host-side — see §7),
- just enough glue / typedefs (`xmlChar`) to build.

~300 lines. Keep an upstream-provenance header: source file, commit
hash, and a note that **only** the slice was vendored, unmodified except
for compile glue. The whole point is byte-faithfulness to upstream — any
edit to the function body voids the differential.

### 5.2 ASan driver — `core/zkpox/test/fixtures/libxml2-driver.c` (~30 lines)

- Read a witness file (argv) into a buffer.
- Decode `(prefix_len, name_len, prefix, name)` per §4.
- Construct the `xmlElementContent` the function expects
  (`type = XML_ELEMENT_CONTENT_ELEMENT`, `name`/`prefix` as
  NUL-terminated copies of the witness slices).
- Allocate the caller buffer with the **same geometry** (`size = 32`)
  and call the real function.
- Build with `-fsanitize=address`. ASan is the OOB oracle: exit 0 = no
  overflow observed, non-zero (ASan abort) = overflow. Driver prints a
  one-line verdict (`OOB` / `clean`) for the harness to parse.

### 5.3 Differential harness step

Extend `core/zkpox/test/run-tests.sh` (new `--fidelity` mode, or fold
into the default 03 sweep):

1. Build the ASan driver once.
2. For each `03-*.bin`: run the SP1 gadget (execute mode, read
   `verdicts.oob_detected`) **and** the ASan driver.
3. Assert both report OOB in the **same direction**. Mismatch on any
   witness → non-zero exit with the offending witness name.
4. The corpus is already labelled — 6 `*-crash` and 9 `*-benign`
   witnesses — so the same step doubles as a confusion-matrix check
   against the filename labels (gadget vs. label vs. ASan, three-way
   agreement).

### 5.4 CI wiring

Add the fidelity step to the zkpox-regression job in
`.github/workflows/tests.yml`. ASan + a ~300-line host build is cheap
(seconds); it does **not** pull the SP1 proving stack, so it fits the
fast tier. Gate it so it runs whenever `targets/03-*` or the fixtures
change.

## 6. Cheaper fallback (if vendoring the slice is fiddly)

Pin pre-fix libxml2 as a git submodule at `0741801`, build via its own
autoconf, and have the driver link against the built `.a`/`.so` and call
`xmlSnprintfElementContent` directly. Pros: zero risk of a vendoring
edit diverging from upstream. Cons: heavier CI (full libxml2 configure +
build), submodule management. Recommend trying §5.1 first; fall back
only if the function's internal dependencies pull in too much of
`valid.c`.

## 7. The one real risk: caller frame fidelity

The differential is only honest if the driver reproduces the **same
buffer geometry and caller context** the witnesses assume — the
`size = 32` stack buffer and the `prefix_len - 8` bypass checks. If the
real function's actual callers in libxml2 set up a different frame (e.g.
a larger buffer, or a pre-populated `buf`), then driving it with
target-03 geometry tests a frame that never occurs upstream — and we've
just built a second re-implementation with extra steps.

Mitigation: before trusting the green check, confirm against upstream
that (a) the `size = 32` / empty-`buf` entry condition is a real call
shape, or (b) document explicitly that the differential validates the
*function's* overflow semantics under a chosen frame, not a specific
upstream call site. State which claim the bundle is making. The
freestanding `strlen`/`strcat` are not the fidelity risk — the caller
frame is.

A second, smaller note: host `string.h` `strlen`/`strcat` differ from
the guest's open-coded versions only in performance, not semantics, so
using libc on the host side is fine and actually strengthens the
argument (we match upstream *and* a different strlen implementation
agrees).

## 8. Effort & payoff

~half a day. The strcat/strlen surface is small and freestanding-
friendly once the slice is accepted; the driver is ~30 lines. Payoff:
the single biggest credibility win available post-merge — "we believe
the extraction is faithful" becomes "every witness produces identical
OOB outcomes between our extraction and pre-fix libxml2, mechanically
verified on every PR."

## 9. Open questions

- Should the differential also assert quantitative agreement
  (`oob_first_offset` / bytes-past-buffer), or just direction? Direction
  is the credibility claim; offset agreement is a stronger bonus if the
  ASan driver can report the overflow size cheaply.
- Generalisation: if this pattern works, every future "extracted real
  CVE" target (vs. synthetic gadgets) should ship with its own
  differential fixture. Worth a shared `fixtures/<cve>/` convention and
  a generic `--fidelity` harness rather than per-target glue.

---

*Filed from the 2026-05-11 non-cryptographer review of the zkpox-dev PR
(reviewer Q1). Verified against current tree 2026-05-31: target 03 and
the 15 `03-*` witnesses present; `core/zkpox/test/fixtures/` not yet
created.*
