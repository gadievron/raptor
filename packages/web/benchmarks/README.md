# Web regression packs

This directory holds offline regression manifests for `/web`.

The harness does not attack a target in CI. Run the scanner against a lab you
own, keep the resulting `web_scan_report.json`, then evaluate it against a
manifest:

```bash
python3 -m packages.web.benchmark \
  --manifest packages/web/benchmarks/lab-regression.example.json \
  --report-dir out/web-regression
```

Each case says which finding types or check IDs must still appear. A missing
report fails the suite. A validator no-match does not refute a RAPTOR web
oracle finding, so the benchmark only grades the scanner's own report.

