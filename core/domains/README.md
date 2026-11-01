# Shared domain boundaries

`core.domains` provides offline Public Suffix List (PSL) lookups, including
ICANN and PRIVATE hosting rules. It has no third-party dependencies.

```python
from core.domains import load_suffix_rules, registrable_domain

registrable_domain("attachments.victim.s3.amazonaws.com")
# 'victim.s3.amazonaws.com'

rules = load_suffix_rules()
# rules.exact, rules.wildcard, rules.exceptions are frozenset[str].
# Wildcard and exception entries omit the '*.' and '!' prefixes.
```

The sets live in `core/domains/public_suffix.py`, loaded lazily and cached
from `core/domains/data/public_suffix_list.dat`. The snapshot retains the
upstream version and license header. Consumers should use the lookup API
rather than implement their own fixed-label suffix comparisons.

Lookups return `None` for public suffixes themselves, and return IP literals
as their own identity. Unknown TLDs use the PSL default `*` rule. Unicode
labels are converted to Punycode without the legacy IDNA-2003 folding of
`faß.de` into `fass.de`. This is not a URL or full IDNA validation API.
Missing or invalid data raises an exception; callers choose their own
failure policy. No network request or heuristic fallback occurs at runtime.
Policy-specific extra hosting boundaries belong in consumers, not this list.

## Refresh and licensing

The snapshot comes from https://publicsuffix.org/list/public_suffix_list.dat
and is licensed under MPL-2.0 (https://mozilla.org/MPL/2.0/). The original
license notice is preserved verbatim. The full license is bundled in
[data/LICENSE.MPL-2.0](data/LICENSE.MPL-2.0); see the repository's
[third-party notices](../../THIRD_PARTY_NOTICES.md) for the scope of this
exception to RAPTOR's MIT license. The lookup code and refresh tooling remain
MIT-licensed. Distributions containing the list must include its notices and
license information and make its MPL-covered source available.

`.github/workflows/refresh-public-suffix-list.yml` downloads, validates, and
tests the list weekly or on manual dispatch, then opens or updates a refresh
PR. It does not auto-merge. It also tests facility changes on pull requests.
Refresh locally with `python .github/scripts/refresh_public_suffix_list.py`.
A failed download or validation preserves the previous snapshot.

This initial patch supplies the facility without migrating existing callers.
Candidates include the WebFetch hook, sandbox DNS-exfiltration grouping, and
supply-chain typosquat domain comparisons.
