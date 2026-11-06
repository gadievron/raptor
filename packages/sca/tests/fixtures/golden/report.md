# SCA Report — /repo



**Captured at:** not recorded

**Run:** repo

**Target:** /repo

## Summary


| Metric | Value |

|---|---|

| Advisory match | 2 |

| Cache evictions | — |

| Cache hits | — |

| Cache misses | — |

| Captured findings | 7 |

| Dependencies analysed | — |

| KEV matches | 1 |

| Project license | not recorded |

| Recorded signal | 4 |

| Scan limitation | 1 |

## Limitations


- Regenerated from recorded findings; no dependency analysis or network queries ran. Original inventory completeness and cache statistics are unknown.

- OSV lookups failed transiently for 1 ecosystem

- 1 suppressed result(s) retained; hidden from quick view

Outcome: partial. Captured findings: 7.

## Findings


| Ref | Tool | Rule | Location | Status | Scanner level | Security severity | Scanner security score |

|---|---|---|---|---|---|---|---|

| F00001 | sca | sca:vulnerable_dependency | /repo/package.json | Advisory match | — | critical | — |

| F00002 | sca | sca:vulnerable_dependency | /repo/requirements.txt | Advisory match | — | medium | — |

| F00003 | sca | sca:hygiene:loose_pin | /repo/package.json | Recorded signal | — | low | — |

| F00004 | sca | sca:supply_chain:typosquat_candidate | /repo/requirements.txt | Recorded signal | — | high | — |

| F00005 | sca | sca:supply_chain:image_capability_drift | /repo/Dockerfile | Recorded signal | — | medium | — |

| F00006 | sca | sca:license:denied | /repo/package.json | Recorded signal | — | high | — |

| F00007 | sca | sca:scan_health:osv_lookup_failed | unknown | Scan limitation | — | info | — |

## Finding details


### F00001: sca:vulnerable_dependency


lodash@4.17.20: Command injection in template (CVE-2021-23337) &#91;KEV&#93; &#91;EPSS 0.97&#93;

### F00002: sca:vulnerable_dependency


requests@2.19.0: Credentials leak on redirect (CVE-2018-18074) &#91;EPSS 0.12&#93;

### F00003: sca:hygiene:loose_pin


express uses a caret range; patch releases land silently

### F00004: sca:supply_chain:typosquat_candidate


reqeusts is 1 edit from requests (top-1k package)

### F00005: sca:supply_chain:image_capability_drift


rebuilt image gained network capability

### F00006: sca:license:denied


left-pad is AGPL-3.0-only; policy denies AGPL

### F00007: sca:scan_health:osv_lookup_failed


OSV lookups failed transiently for 1 ecosystem

## Stage Results


| Stage | State | Reason | Duration seconds |

|---|---|---|---|

| dependency analysis | unknown |  | — |

**KEV**: 1 unsuppressed known-exploited advisory matches.

Advisory matches and supply-chain signals do not by themselves establish exploitability. Reachability, suppression, and evidence retain their recorded meanings.

## Finding classes


| Class | Recorded rows |

|---|---|

| sca:hygiene:loose_pin | 1 |

| sca:license:denied | 1 |

| sca:scan_health:osv_lookup_failed | 1 |

| sca:supply_chain:image_capability_drift | 1 |

| sca:supply_chain:typosquat_candidate | 1 |

| sca:vulnerable_dependency | 2 |

## Dependency summary


| Severity | Count |

|---|---|

| Critical | 1 |

Vulnerable findings: **2**

active: **1**

suppressed: **1**

KEV-listed: **1**

### Reachability breakdown


| Verdict | Count |

|---|---|

| Likely called | 1 |

## Vulnerable dependencies


| Severity | Dep | Advisory | Reachability | KEV | EPSS | Fix |

|---|---|---|---|---|---|---|

| Critical | npm:lodash@4.17.20 | GHSA-aaaa-bbbb-cccc (CVE-2021-23337) | Likely called | True | 0.97 | 4.17.21 |

| Medium (suppressed) | PyPI:requests@2.19.0 | GHSA-dddd-eeee-ffff (CVE-2018-18074) | Not evaluated | False | 0.12 | 2.20.0 |

Supply-chain findings: **2**

## Supply-chain findings


| Severity | Kind | Dep | Detail |

|---|---|---|---|

| High | typosquat_candidate | PyPI:reqeusts | reqeusts is 1 edit from requests (top-1k package) |

| Medium | image_capability_drift | OCI:alpine | rebuilt image gained network capability |

Hygiene findings: **1**

## Hygiene findings


| Severity | Kind | Dep | Detail |

|---|---|---|---|

| Low | loose_pin | npm:express | express uses a caret range; patch releases land silently |

License findings: **1**

## License findings


| Severity | Kind | Dep | Detail |

|---|---|---|---|

| High | denied | npm:left-pad | left-pad is AGPL-3.0-only; policy denies AGPL |

## Dependency and policy evidence


### F00001: lodash


| Field | Value |

|---|---|

| Package | lodash |

| Ecosystem | npm |

| Version | 4.17.20 |

| Fixed version | 4.17.21 |

| KEV | True |

| EPSS | 0.97 |

| Reachability | likely_called |

| CVSS | 9.8 |

| Suppressed | False |

| Suppression reason | — |

#### Recorded dependency evidence


```json
{
  "advisory": {
    "aliases": [
      "CVE-2021-23337"
    ],
    "cwe_ids": [
      "CWE-94"
    ],
    "fixed_versions": [
      "4.17.21"
    ],
    "id": "GHSA-aaaa-bbbb-cccc",
    "modified": "2024-02-01T08:30:00+00:00",
    "published": "2024-01-15T12:00:00+00:00",
    "references": [
      "https://example.invalid/advisory"
    ],
    "severity": {
      "score": 9.8,
      "severity": "critical",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "summary": "Command injection in template"
  },
  "alias_name": "my-lodash",
  "all_advisories": [
    {
      "aliases": [
        "CVE-2021-23337"
      ],
      "cwe_ids": [
        "CWE-94"
      ],
      "fixed_versions": [
        "4.17.21"
      ],
      "id": "GHSA-aaaa-bbbb-cccc",
      "modified": "2024-02-01T08:30:00+00:00",
      "published": "2024-01-15T12:00:00+00:00",
      "references": [
        "https://example.invalid/advisory"
      ],
      "severity": {
        "score": 9.8,
        "severity": "critical",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      "summary": "Command injection in template"
    },
    {
      "aliases": [
        "CVE-2021-23337"
      ],
      "fixed_versions": [
        "4.17.21"
      ],
      "id": "PYSEC-2021-0001",
      "modified": "2024-02-01T08:30:00+00:00",
      "published": "2024-01-15T12:00:00+00:00",
      "references": [
        "https://example.invalid/advisory"
      ],
      "severity": {
        "score": 7.2,
        "severity": "high",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      "summary": "Duplicate record for the same CVE"
    }
  ],
  "commented_out": false,
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "declared_in": "/repo/package.json",
  "direct": true,
  "ecosystem": "npm",
  "epss": 0.97,
  "exploit_evidence": {
    "edb_ids": [
      50001
    ],
    "github_poc_urls": [
      "https://example.invalid/poc"
    ],
    "has_any": true,
    "kev_listed": true,
    "msf_modules": [
      "exploit/multi/http/lodash_template"
    ]
  },
  "exposure_factor": 0.0,
  "fixed_version": "4.17.21",
  "in_kev": true,
  "is_lockfile": false,
  "name": "lodash",
  "parser_confidence": {
    "level": "high",
    "numeric": 0.95,
    "reason": "exact manifest pin"
  },
  "pin_style": "exact",
  "purl": "pkg:npm/lodash@4.17.20",
  "raptor_risk_estimate": 68.05093727603116,
  "reachability": {
    "confidence": {
      "level": "high",
      "numeric": 0.95,
      "reason": "call site found"
    },
    "evidence": [
      "src/app.js:42"
    ],
    "verdict": "likely_called"
  },
  "related_findings": [],
  "risk_components": {
    "calibration_status": "unverified",
    "cvss_base": 98.00000000000001,
    "cvss_source": "numeric",
    "depth_multiplier": 1.0,
    "epss_multiplier": 0.884721,
    "exploit_evidence_multiplier": 1.0,
    "exposure_multiplier": 0.45,
    "final": 68.05093727603116,
    "kev_multiplier": 1.9326,
    "parser_confidence": 0.95,
    "reachability_multiplier": 1.0,
    "ssvc_automatable_multiplier": 1.0,
    "version_match_confidence": 0.95
  },
  "scope": "main",
  "source_kind": "manifest",
  "transitive_depth": 0,
  "version": "4.17.20",
  "version_match_confidence": {
    "level": "high",
    "numeric": 0.95,
    "reason": "exact manifest pin"
  }
}
```

### F00002: requests


| Field | Value |

|---|---|

| Package | requests |

| Ecosystem | PyPI |

| Version | 2.19.0 |

| Fixed version | 2.20.0 |

| KEV | False |

| EPSS | 0.12 |

| Reachability | not_evaluated |

| CVSS | 5.0 |

| Suppressed | True |

| Suppression reason | accepted: internal-only service |

#### Recorded dependency evidence


```json
{
  "advisory": {
    "aliases": [
      "CVE-2018-18074"
    ],
    "fixed_versions": [
      "2.20.0"
    ],
    "id": "GHSA-dddd-eeee-ffff",
    "modified": "2024-02-01T08:30:00+00:00",
    "published": "2024-01-15T12:00:00+00:00",
    "references": [
      "https://example.invalid/advisory"
    ],
    "severity": {
      "score": 5.0,
      "severity": "medium",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "summary": "Credentials leak on redirect"
  },
  "alias_name": null,
  "all_advisories": [
    {
      "aliases": [
        "CVE-2018-18074"
      ],
      "fixed_versions": [
        "2.20.0"
      ],
      "id": "GHSA-dddd-eeee-ffff",
      "modified": "2024-02-01T08:30:00+00:00",
      "published": "2024-01-15T12:00:00+00:00",
      "references": [
        "https://example.invalid/advisory"
      ],
      "severity": {
        "score": 5.0,
        "severity": "medium",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      "summary": "Credentials leak on redirect"
    }
  ],
  "commented_out": false,
  "cvss_score": 5.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "declared_in": "/repo/requirements.txt",
  "direct": true,
  "ecosystem": "PyPI",
  "epss": 0.12,
  "exploit_evidence": null,
  "exposure_factor": 0.0,
  "fixed_version": "2.20.0",
  "in_kev": false,
  "is_lockfile": false,
  "name": "requests",
  "parser_confidence": {
    "level": "high",
    "numeric": 0.95,
    "reason": "exact manifest pin"
  },
  "pin_style": "exact",
  "purl": "pkg:pypi/requests@2.19.0",
  "raptor_risk_estimate": 6.158131572712499,
  "reachability": {
    "confidence": {
      "level": "low",
      "numeric": 0.3,
      "reason": "reachability stage skipped for this ecosystem"
    },
    "evidence": [],
    "verdict": "not_evaluated"
  },
  "related_findings": [],
  "risk_components": {
    "calibration_status": "unverified",
    "cvss_base": 50.0,
    "cvss_source": "numeric",
    "depth_multiplier": 1.0,
    "epss_multiplier": 0.494316,
    "exploit_evidence_multiplier": 1.0,
    "exposure_multiplier": 0.45,
    "final": 6.158131572712499,
    "kev_multiplier": 1.0,
    "parser_confidence": 0.95,
    "reachability_multiplier": 0.6135,
    "ssvc_automatable_multiplier": 1.0,
    "version_match_confidence": 0.95
  },
  "scope": "main",
  "source_kind": "manifest",
  "transitive_depth": 0,
  "version": "2.19.0",
  "version_match_confidence": {
    "level": "high",
    "numeric": 0.95,
    "reason": "exact manifest pin"
  }
}
```

### F00003: express


| Field | Value |

|---|---|

| Package | express |

| Ecosystem | npm |

| Version | 4.0.0 |

| Fixed version | — |

| KEV | — |

| EPSS | — |

| Reachability | not recorded |

| CVSS | — |

| Suppressed | False |

| Suppression reason | — |

#### Recorded dependency evidence


```json
{
  "alias_name": null,
  "commented_out": false,
  "confidence": {
    "level": "high",
    "numeric": 0.95,
    "reason": "manifest says ^4.0.0"
  },
  "ecosystem": "npm",
  "is_lockfile": false,
  "kind": "loose_pin",
  "name": "express",
  "pin_style": "caret",
  "purl": "pkg:npm/express@4.0.0",
  "scope": "main",
  "version": "4.0.0"
}
```

### F00004: reqeusts


| Field | Value |

|---|---|

| Package | reqeusts |

| Ecosystem | PyPI |

| Version | 1.0.0 |

| Fixed version | — |

| KEV | — |

| EPSS | — |

| Reachability | not recorded |

| CVSS | — |

| Suppressed | False |

| Suppression reason | — |

#### Recorded dependency evidence


```json
{
  "alias_name": null,
  "commented_out": false,
  "confidence": {
    "level": "medium",
    "numeric": 0.7,
    "reason": "edit-distance heuristic"
  },
  "ecosystem": "PyPI",
  "evidence": {
    "edit_distance": 1,
    "target": "requests"
  },
  "kind": "typosquat_candidate",
  "name": "reqeusts",
  "version": "1.0.0"
}
```

### F00005: alpine


| Field | Value |

|---|---|

| Package | alpine |

| Ecosystem | OCI |

| Version | 3.19 |

| Fixed version | — |

| KEV | — |

| EPSS | — |

| Reachability | not recorded |

| CVSS | — |

| Suppressed | False |

| Suppression reason | — |

#### Recorded dependency evidence


```json
{
  "alias_name": null,
  "commented_out": false,
  "confidence": {
    "level": "high",
    "numeric": 0.95,
    "reason": "capability diff"
  },
  "ecosystem": "OCI",
  "evidence": {
    "added_buckets": [
      "network"
    ],
    "removed_buckets": []
  },
  "kind": "image_capability_drift",
  "name": "alpine",
  "version": "3.19"
}
```

### F00006: left-pad


| Field | Value |

|---|---|

| Package | left-pad |

| Ecosystem | npm |

| Version | 1.3.0 |

| Fixed version | — |

| KEV | — |

| EPSS | — |

| Reachability | not recorded |

| CVSS | — |

| Suppressed | False |

| Suppression reason | — |

#### Recorded dependency evidence


```json
{
  "alias_name": null,
  "commented_out": false,
  "confidence": {
    "level": "high",
    "numeric": 0.95,
    "reason": "registry-declared license"
  },
  "ecosystem": "npm",
  "kind": "license_denied",
  "name": "left-pad",
  "purl": "pkg:npm/left-pad@1.3.0",
  "spdx": "AGPL-3.0-only",
  "version": "1.3.0"
}
```

### F00007: Osv lookup failed


| Field | Value |

|---|---|

| Package | — |

| Ecosystem | — |

| Version | — |

| Fixed version | — |

| KEV | — |

| EPSS | — |

| Reachability | not recorded |

| CVSS | — |

| Suppressed | False |

| Suppression reason | — |

#### Recorded dependency evidence


```json
{
  "failed_ecosystems": [
    "Cargo"
  ],
  "kind": "osv_lookup_failed"
}
```

## Source artifacts


- /repo/findings.json
