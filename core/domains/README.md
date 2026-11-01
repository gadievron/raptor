# Shared domain boundaries

`core.domains` provides offline Public Suffix List (PSL) lookups, including
ICANN and PRIVATE hosting rules. It has no third-party dependencies.

```python
from core.domains import domain_boundary, load_suffix_rules, registrable_domain

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

## Boundary provenance and private DNS

Use `domain_boundary(host)` when a decision depends on the origin of the
boundary. It returns a frozen `DomainBoundary` with `hostname`,
`registrable_domain`, `public_suffix`, `rule`, and `source`:

- `source="psl"`: an explicit exact, wildcard, or exception rule from the
  bundled ICANN/PRIVATE list. `rule` retains its `*.` or `!` prefix.
- `source="default"`: the PSL default `*` rule for an unlisted suffix.
  For example, `api.office.local` yields `office.local`. This is a naming
  heuristic and does not establish shared ownership in private DNS.
- `source="ip"`: an IP literal; its normalized identity is returned.

Single-label names such as `localhost` and `buildserver` have no registrable
domain. Public suffixes themselves also return `None` for that field.
The original `registrable_domain(host)` API keeps its default-rule behavior;
security decisions requiring provenance must use `domain_boundary`.

DNS names and labels are checked against their 253/63-character ASCII limits
before suffix matching. Invalid input raises `InvalidHostname` (a `ValueError`
subclass). Underscore-containing internal names require explicit opt-in:
`domain_boundary("api.service_name.internal", allow_underscores=True)`.
The same length limits apply. The PSL snapshot parser remains strict.
Unicode labels use Punycode without the legacy IDNA-2003 folding of `faß.de`
into `fass.de`. This is not a URL or full IDNA validation API.

Missing or invalid data raises an exception; callers choose their own failure
policy. No network request or heuristic fallback for missing data occurs.
Policy-specific extra hosting or private DNS boundaries belong in consumers,
not the upstream list.

### Consumer policies

SCA suppresses same-owner typosquat candidates only when both domains match
an explicit PSL boundary. Default-rule matches cannot suppress a finding.
It opts into underscore-containing names for source analysis. Missing or
invalid PSL data aborts the domain scan, including empty source trees.

Sandbox DNS-exfiltration detection also accepts internal names. It can group
unknown suffixes to detect suspicious subdomain fan-out, but labels that
evidence as heuristic. It normalizes host identities before counting them.
Missing/invalid PSL data emits `dns_exfil_unavailable`, giving the run at
least a notable verdict. Malformed telemetry hosts do not discard valid
exfiltration signals from the rest of the run.

### WebFetch hook adoption (PR #1044)

Use the policy helper rather than repeating provenance checks:

```python
from core.domains import host_matches_anchor

try:
    allowed = host_matches_anchor(host, anchor_host, extra_hosts=extra_hosts)
except (OSError, ValueError):
    return 2  # Unavailable data or invalid input: deny the tool call.
```

Arguments are hostnames/IP literals, not URLs. The helper allows the exact
normalized anchor host, an exact explicitly listed extra host, or a shared
non-None domain from explicit PSL rules. It validates the data even for
exact matches. Unknown/private suffixes, single-label names, and IPs receive
only exact-host/extra-host grants. Extras do not grant their subdomains.
Any wider private DNS permission needs a separately configured operator
boundary. Strict hostname validation applies; underscore support is not a
fetch grant. HTTPS, operator-provenance anchors, and decision logging remain
the hook's responsibility.

For analysis callers, `same_registrable_domain(a, b)` returns True only for
shared explicit PSL boundaries. It does not treat identical IPs, public
suffixes, or unknown-suffix names as sharing a registrable domain. It also
raises on unavailable/invalid data. Internal source analysis can explicitly
opt into `allow_underscores=True`.

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

Sandbox DNS-exfiltration grouping and supply-chain typosquat comparisons use
this facility. WebFetch hook adoption is handled separately in PR #1044.
