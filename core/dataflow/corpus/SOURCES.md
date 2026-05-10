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

## Juice Shop

- Upstream: https://github.com/juice-shop/juice-shop
- Pinned sha: `3b178fd07b9f754c9d444d818448cfe58168943f`
- Local path: `out/dataflow-corpus-fixtures/juice-shop/`
- Why: Juice Shop ships paired vulnerable / fixed code in
  `data/static/codefixes/`. Each `*Challenge.info.yml` describes the
  vulnerability, and per-challenge `_correct.ts` variants show the
  intended mitigation. Excellent source for `framework_mitigation`
  FPs (Sequelize parameter binding, auth middleware) and
  `type_constraint` FPs (Angular `bypassSecurityTrust*` on values
  not used in HTML render contexts).
- Setup:
  ```
  git clone --depth 1 https://github.com/juice-shop/juice-shop \
      out/dataflow-corpus-fixtures/juice-shop
  cd out/dataflow-corpus-fixtures/juice-shop
  git fetch --depth 1 origin 3b178fd07b9f754c9d444d818448cfe58168943f
  git checkout 3b178fd07b9f754c9d444d818448cfe58168943f
  ```

## WebGoat

- Upstream: https://github.com/WebGoat/WebGoat
- Pinned sha: `7d3343d08c360d4751e5298e1fe910463b7731a1`
- Local path: `out/dataflow-corpus-fixtures/webgoat/`
- Why: Spring/JDBC educational app. Lessons are organised
  `introduction/` (intentional vulns — TPs), `mitigation/` (fixed
  versions — `framework_mitigation` FPs, plus a few `dead_code`
  cases where the lesson is keyword-matching rather than running
  SQL), and `advanced/`. Inverted authz checks (IDOR), SSRF
  endpoints that don't actually fetch URLs, and PreparedStatement
  mitigations all surface here.
- Setup:
  ```
  git clone --depth 1 https://github.com/WebGoat/WebGoat \
      out/dataflow-corpus-fixtures/webgoat
  cd out/dataflow-corpus-fixtures/webgoat
  git fetch --depth 1 origin 7d3343d08c360d4751e5298e1fe910463b7731a1
  git checkout 7d3343d08c360d4751e5298e1fe910463b7731a1
  ```

### Regenerating the Juice Shop + WebGoat hand-labels

The `juiceshop_*` and `webgoat_*` entries are hand-curated. The
manifest lives in `core/dataflow/handlabel_seed.py` as a tuple of
`SeedEntry` records — each names the fixture file, the source/sink
line numbers, the producer + rule_id, the verdict + fp_category,
and a written rationale citing the specific defence (or absence
thereof). Adding entries means appending tuples to `JUICE_SHOP` or
`WEBGOAT` in that file; re-running:

```
python3 -m core.dataflow.handlabel_seed
```

reads each fixture's source line for the snippet and writes paired
JSONs into `core/dataflow/corpus/findings/`. Existing finding ids
are deterministic (hash of producer + rule + source/sink locations)
so re-running with the same manifest is idempotent. Removing entries
means the orphan files in `findings/` need to be deleted manually —
the script doesn't garbage-collect.
