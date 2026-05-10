# Pinned upstream sources

Real-target fixtures referenced by corpus findings. Kept out of tree
(see `FIXTURES.md`) and fetched on demand to
``out/dataflow-corpus-fixtures/<name>/``.

Re-cloning at any sha other than the pin invalidates the labels
written against that sha — the setup script verifies this before the
corpus runner proceeds.

## OWASP Benchmark Java

- Upstream: https://github.com/OWASP-Benchmark/BenchmarkJava
- Pinned sha: `b06d6efaebd577a327514364951916e7df3290b4`
- Local path: `out/dataflow-corpus-fixtures/owasp-benchmark-java/`
- Why: 2740 hand-labelled Java test cases across CWE-22/78/79/89/90/327/328/330/501/614/643. Each test has a built-in TP-or-FP verdict in `expectedresults-1.2.csv`; FPs are the same pattern as their TP siblings with a sanitizer applied. Canonical missing_sanitizer_model fixture set.
- Build command (used by CodeQL DB creation): `mvn -B -DskipTests clean package`
- Setup: `out/dataflow-corpus-fixtures/owasp-benchmark-java/` is the on-demand clone target. Re-clone with:
  ```
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava \
      out/dataflow-corpus-fixtures/owasp-benchmark-java
  cd out/dataflow-corpus-fixtures/owasp-benchmark-java
  git fetch --depth 1 origin b06d6efaebd577a327514364951916e7df3290b4
  git checkout b06d6efaebd577a327514364951916e7df3290b4
  ```

### Regenerating the OWASP corpus entries

The committed `core/dataflow/corpus/findings/owasp_*` entries were
produced by running CodeQL CWE-78 against the pinned OWASP Benchmark
clone. Reproducing exactly:

```
# 1. Clone (see above)
# 2. Build CodeQL DB (the build hits Maven, takes ~3-5 minutes)
codeql database create /tmp/owasp-codeql-db \
    --language=java \
    --command="mvn -B -DskipTests clean package" \
    --source-root=out/dataflow-corpus-fixtures/owasp-benchmark-java \
    --overwrite

# 3. Analyze for CWE-78
codeql database analyze /tmp/owasp-codeql-db \
    codeql/java-queries:Security/CWE/CWE-078 \
    --format=sarif-latest --output=/tmp/owasp-cwe78.sarif

# 4. Generate corpus entries (deterministic with --seed)
python3 -m core.dataflow.owasp_corpus_generator \
    --sarif /tmp/owasp-cwe78.sarif \
    --expected-results out/dataflow-corpus-fixtures/owasp-benchmark-java/expectedresults-1.2.csv \
    --out-dir core/dataflow/corpus/findings \
    --target-count 30 --cwe 78 --seed 42
```

Re-running with `--seed 42` reproduces the same 30 entries. Different
seed picks a different sample with the same TP/FP balance — the
existing committed entries should be removed first
(`rm core/dataflow/corpus/findings/owasp_*`) since their finding-ids
won't match.
