# SCA Compromise-Detection Corpus

Fixtures and an evaluation harness for asking the question: **"if we
had run ``raptor-sca`` against this project at the time the
compromise was active, would we have surfaced it?"**

Each fixture pins a known supply-chain incident at the malicious
package version, declares the signal class(es) we expect SCA to
fire on that fixture, and is scored by the harness as PASS / FAIL.

## Layout

```
tests/sca-e2e/compromise-corpus/
├── <incident-slug>/
│   ├── fixture/             # minimal project tree (manifest + lockfile only)
│   ├── expected.yaml        # required signal(s) — kind, severity floor, etc.
│   └── metadata.yaml        # incident metadata + public references
└── README.md
```

## Safety properties (load-bearing)

This corpus is the question "can we detect the compromise
**without** executing or fetching the malicious payload?" — which
is also the production CI question, since by the time a developer
has ``npm install``ed the malicious tarball, half of the
attacker's payload has already detonated (preinstall scripts,
host fingerprinting, exfil-on-import).

The harness enforces four safety properties:

1. **Manifest-only fixtures.** Each fixture is restricted to a
   small allowlist of manifest + lockfile filenames (``package.json``,
   ``pom.xml``, ``Pipfile.lock``, ``Dockerfile``, …). The harness
   refuses to run a fixture containing any file outside this
   allowlist OR any of the usual installed-deps directories
   (``node_modules/`` / ``venv/`` / ``vendor/`` / ``target/``).
2. **No registry fetches by default.** The harness invokes
   ``raptor-sca`` with ``--offline`` so the SCA pipeline relies on
   cached OSV / KEV / advisory data rather than re-fetching the
   malicious package's registry metadata at evaluation time.
3. **No package-manager subprocesses.** ``raptor-sca`` in scan mode
   does not shell out to ``npm install`` / ``pip install`` /
   ``mvn`` — manifest parsing is in-process and skips lifecycle
   hooks. (For the cascade-resolution code path that historically
   could shell out, ``--offline`` short-circuits it.)
4. **Detection from metadata alone.** Every signal class exercised
   here (``vuln_dep``, ``install_hook_suspicious``,
   ``typosquat_candidate``, ``recent_publish``,
   ``maintainer_change``, ``image_capability_drift``) operates on
   advisory records or manifest-parsed metadata — not on the
   malicious package's source bytes.

### When you need the actual malicious bytes

A few advanced signal classes (binary capability fingerprinting,
malware-string heuristics on the package contents) do require the
malicious payload. **Never** ``npm install`` or ``pip install`` a
known-malicious version on the dev host. Instead pull bytes from
the ``DataDog/malicious-software-packages-dataset`` archive (the
samples are AES-encrypted with the password ``infected`` to keep
them from being executed accidentally), decrypt in a
disposable sandbox, and run the binary-content detectors there.
The corpus harness deliberately does not support this mode today;
adding it requires sandboxing the SCA subprocess as well so the
extracted bytes can't escape into the host filesystem.

## Running the harness

```
libexec/raptor-sca-compromise-check tests/sca-e2e/compromise-corpus
```

The harness:
  1. Walks each fixture directory
  2. Subprocess-invokes ``raptor-sca`` on the fixture
  3. Reads ``findings.json`` and matches against ``expected.yaml``
  4. Outputs a per-fixture PASS / FAIL plus an aggregate catch rate

Exit code 0 if every fixture's expected signal(s) fired, 1
otherwise — suitable as a CI gate.

## Adding fixtures

1. Create ``<incident-slug>/fixture/`` with the minimal manifest +
   lockfile that depends on the malicious version.
2. Write ``expected.yaml`` listing the signal class(es) and floors.
3. Write ``metadata.yaml`` with incident name, date, and public refs
   (advisory IDs, post-mortem URLs, OSSF MAL-YYYY-NNNN identifiers).
4. Run the harness; iterate until the fixture passes.

## Incidents in this corpus

See ``metadata.yaml`` in each fixture directory.

## Signal classes NOT covered by the corpus (and why)

The corpus is metadata-only static fixtures. Four signal classes
the SCA pipeline ships don't fit that model — they're exercised
elsewhere (unit tests against mocked data), not here.

| Signal | Why static fixtures don't exercise it | Where it IS covered |
|---|---|---|
| ``recent_publish`` | Fires when a package's ``first_publish`` is within 30 days. Malicious packages get yanked quickly, taking the registry's publish-date metadata with them; a fixture pinning a specific malicious version watches the signal decay as the package is removed. | ``packages/sca/supply_chain/tests/test_registry_metadata.py`` — unit tests against a fixture ``_Meta`` object with a recent ``first_publish``. |
| ``maintainer_change`` | Fires when the maintainer list changed between the two most-recent versions, OR a maintainer joined within 14 days. Both windows decay rapidly; pinning a version where the change was recent only works for a narrow time window. | Same: ``test_registry_metadata.py``. |
| ``image_capability_drift`` | Requires (1) live OCI registry access to fetch the image's binary, (2) a pre-populated fingerprint baseline file, (3) a CLI flag (``enable_image_drift``) that isn't yet plumbed through to the operator-facing CLI. None of these compose with manifest-only static fixtures. | ``packages/sca/tests/test_image_drift.py`` — unit tests against a mocked OCI client + in-memory baselines. ``raptor-sca fingerprint`` CLI exercises the same primitives manually. |
| ``binary_capability_delta`` | Fires inside the ``bump`` flow, not the ``scan`` flow — the detector runs only when SCA is asked to evaluate a version upgrade for a binary-payload dep (Dockerfile FROM bump, GHA Docker-action bump). The corpus harness drives the scan path. | ``packages/sca/bump/tests/test_binary_capability_delta.py`` — unit tests against stubbed radare2 fingerprints. |

Adding these to the corpus would require either (a) a stateful
harness mode that pre-stages baselines + drives the bump flow, or
(b) mocked-registry test infrastructure that the manifest-only
threat model deliberately avoids. Skipped today; the unit-test
coverage of the underlying detectors is the floor.

Public references:

* OSSF malicious-packages — https://github.com/ossf/malicious-packages
* Datadog dataset (encrypted samples) — https://github.com/DataDog/malicious-software-packages-dataset
* OSV.dev — https://osv.dev
