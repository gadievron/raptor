# SCA Modes Corpus

Real-shape fixtures exercising the SCA pipeline's operator-facing
modes (``scan`` / ``bump`` / ``fix`` / ``check`` / ``whatif``)
end-to-end. Companion to the compromise-detection corpus:

* The compromise corpus answers "would we detect this known
  attack?" — narrow, signal-class-focused.
* The modes corpus answers "do the different commands produce
  sensible output on a real-shape project?" — wide, mode-coverage-
  focused.

## Layout

```
tests/sca-e2e/modes-corpus/
├── <fixture-name>/
│   ├── fixture/             # project tree (manifest + Dockerfile + GHA)
│   ├── expected.yaml        # per-mode expectations
│   └── metadata.yaml        # fixture description
└── README.md
```

Fixtures intentionally pin OLD vulnerable versions to give SCA
real findings to chew on. That lets ``scan`` produce non-empty
output, ``fix --cve-only`` produce non-empty rewrites, and
``bump --whatif`` produce non-Clean verdicts.

## Modes covered

| Mode | What we assert |
|---|---|
| ``scan`` | exits 0, emits findings.json with >0 rows, expected ecosystems present |
| ``bump --whatif`` (default) | exits 0, surfaces Dockerfile FROM / GHA action surfaces, does NOT modify source tree |
| ``fix --cve-only`` | exits 0, writes ``proposed/`` directory with rewritten manifests, source tree untouched |

The harness asserts each mode's load-bearing invariants — not full
output equality, since output content depends on time-varying
upstream data (advisories, npm/PyPI version availability, etc).

## Running

```
libexec/raptor-sca-modes-check tests/sca-e2e/modes-corpus
```

Exit 0 if every mode on every fixture passes its assertions; 1
otherwise.

## Why these aren't unit tests

Each mode dispatches through ``raptor-sca``'s top-level CLI,
spawns one or more subprocess pipelines (resolvers, registry
clients, OSV queries), and writes to a real on-disk output dir.
Unit tests mock all of that. The modes corpus exercises the
end-to-end shape — including subprocess-boundary issues like
the ``.home/`` pollution bug (``2ecb0af1``) and the JsonCache
reaper perf bug (``c108f36a``), both of which slipped through
the unit-test layer.

## Source-tree non-mutation

Fixtures are copied to a tempdir before each mode invocation
(same pattern as the compromise harness). This lets us assert
"the source tree is unchanged" after each mode runs — important
for ``fix`` and ``bump --apply`` which DO mutate, but only into
the ``proposed/`` directory or the tempdir respectively.
