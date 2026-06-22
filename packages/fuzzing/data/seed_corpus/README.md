# RAPTOR built-in fuzzing seed corpus

This is the default corpus RAPTOR uses when the operator does not pass
`--corpus` and autonomous corpus generation is unavailable or not selected.

Keep it small, boring, and reviewable. The goal is not to ship every useful
testcase in the world; it is to give AFL++/libFuzzer enough structured shapes
to start mutating from something better than four hard-coded bytes.

Contribution rules:

- Add tiny seeds only. Keep individual files under a few KB.
- Do not add real credentials, customer data, private keys, captures, or crash
  reproducers from third-party targets.
- Prefer broadly useful parser shapes: JSON, XML, HTTP, CSV, paths, integer
  boundaries, format strings, command-style prefixes.
- Update `manifest.json` when adding a seed.
- Seed filenames in the manifest must be flat bare filenames once materialised.
