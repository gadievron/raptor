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

## source_intel CVE fixtures (memory-corruption, C/C++)

Pinned upstream sources for the source_intel arc's memory-corruption seed (PR0 source_intel extension). Each entry is a real CVE; the local clone is pinned at the *vulnerable* commit (parent of the fix) so cocci sees the buggy code shape.

### curl — CVE-2018-14618 (NTLM integer overflow)

- Upstream: https://github.com/curl/curl
- Pinned sha (vulnerable): `19ebc282172ff204648f350c6e716197d5b4d221`
- Fix sha: `57d299a499155d4b327e341c6024e293b0418243`
- Local path: `out/dataflow-corpus-fixtures/curl/`
- Bug location: `lib/curl_ntlm_core.c`, function `Curl_ntlm_core_mk_nt_hash`, line 560
- CWE: CWE-190 → CWE-122 (integer overflow in `malloc(len * 2)` where `len = strlen(password)`, wraps on 32-bit when password > 2GB → undersized buffer → heap overflow on subsequent write)
- Why this fixture: classic integer-promotion → undersized-alloc pattern. Exercises source_intel axis 3 (size_kind=multiplied, user-controlled source) and axis 7 (integer-promotion hazard catalog). License: curl is MIT/X11 derivative; verbatim ≤10-line snippet in the Finding record is fair-use research excerpt.
- Setup:
  ```
  git clone --depth 1 https://github.com/curl/curl \
      out/dataflow-corpus-fixtures/curl
  cd out/dataflow-corpus-fixtures/curl
  git fetch --depth 1 origin 19ebc282172ff204648f350c6e716197d5b4d221
  git checkout 19ebc282172ff204648f350c6e716197d5b4d221
  ```

### Linux kernel — CVE-2017-7541 (brcmfmac action-frame overflow, CWE-120)

- Upstream: https://github.com/torvalds/linux
- Pinned sha (vulnerable): `76b825ab870be3281edac4ae8a414da6e54b0d3a`
- Fix sha: `8f44c9a41386729fea410e688959ddaa9d51be7c`
- Local path: `out/dataflow-corpus-fixtures/linux-cve-2017-7541/`
- Bug location: `drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c`, function `brcmf_cfg80211_mgmt_tx`, action-frame branch ~line 4937–4948
- CWE: CWE-120 (frame `len` from NL80211 user input up to 2304 bytes flows into `action_frame->data[]` (1800 bytes) via downstream memcpy without bounds check)
- Why this fixture: classic missing-bounds-check shape. Axis 2 (proximity — no guard between user-input entry and copy) + axis 3 (size source = user-controlled function parameter).
- Setup (sparse-checkout — only the affected file checked out to keep disk footprint small):
  ```
  git clone --filter=blob:none --no-checkout https://github.com/torvalds/linux \
      out/dataflow-corpus-fixtures/linux-cve-2017-7541
  cd out/dataflow-corpus-fixtures/linux-cve-2017-7541
  git sparse-checkout set drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c
  git checkout 76b825ab870be3281edac4ae8a414da6e54b0d3a
  ```

### Linux kernel — CVE-2021-37159 (HSO USB double-free, CWE-415 + CWE-416)

- Upstream: https://github.com/torvalds/linux
- Pinned sha (vulnerable): `6206b7981a36476f4695d661ae139f7db36a802d`
- Fix sha: `a6ecfb39ba9d7316057cea823b196b734f6b18ca`
- Local path: `out/dataflow-corpus-fixtures/linux-cve-2021-37159/`
- Bug location: `drivers/net/usb/hso.c`, function `hso_create_net_device`, single-exit-label pattern ~lines 2495–2569
- CWE: CWE-415 + CWE-416 (single `exit:` label calls `hso_free_net_device(hso_dev, true)` unconditionally; partial-init failures lead to freeing already-freed resources from the upstream init path)
- Why this fixture: classic error-path-cleanup double-free shape. Axis 3 (alloc/free pairing — same pointer freed twice on certain error paths) + axis 2 (no reallocation between the two frees).
- Setup:
  ```
  git clone --filter=blob:none --no-checkout https://github.com/torvalds/linux \
      out/dataflow-corpus-fixtures/linux-cve-2021-37159
  cd out/dataflow-corpus-fixtures/linux-cve-2021-37159
  git sparse-checkout set drivers/net/usb/hso.c
  git checkout 6206b7981a36476f4695d661ae139f7db36a802d
  ```

### Linux kernel — CVE-2022-32250 (netfilter nf_tables UAF, CWE-416)

- Upstream: https://github.com/torvalds/linux
- Pinned sha (vulnerable): `6c465408a7709cf180cde7569e141191b67a175c`
- Fix sha: `520778042ccca019f3ffa136dd0ca565c486cedd`
- Local path: `out/dataflow-corpus-fixtures/linux-cve-2022-32250/`
- Bug location: `net/netfilter/nf_tables_api.c`, function `nft_expr_init` ~lines 2873–2898
- CWE: CWE-416 (`nft_expr_init` allocates expression body without checking `NFT_STATEFUL_EXPR`; non-stateful expression attached to a set causes UAF during set destruction)
- Why this fixture: well-documented kernel UAF with clear pre-condition (missing flag check). Axis 2 (no proximate stateful-flag guard) + axis 3 (alloc/free pairing across function boundary) + axis 4 (privilege gradient — reachable via CAP_NET_ADMIN in user/net namespace).
- Setup:
  ```
  git clone --filter=blob:none --no-checkout https://github.com/torvalds/linux \
      out/dataflow-corpus-fixtures/linux-cve-2022-32250
  cd out/dataflow-corpus-fixtures/linux-cve-2022-32250
  git sparse-checkout set net/netfilter/nf_tables_api.c
  git checkout 6c465408a7709cf180cde7569e141191b67a175c
  ```

### Linux kernel — CVE-2019-15291 (flexcop USB NULL deref, CWE-476)

- Upstream: https://github.com/torvalds/linux
- Pinned sha (vulnerable): `d52741728a518afe536d22dc6e9b60193c5fa942`
- Fix sha: `1b976fc6d684e3282914cdbe7a8d68fdce19095c`
- Local path: `out/dataflow-corpus-fixtures/linux-cve-2019-15291/`
- Bug location: `drivers/media/usb/b2c2/flexcop-usb.c`, function `flexcop_usb_probe` ~line 545
- CWE: CWE-476 (missing `bNumEndpoints >= 1` check before downstream endpoint deref; malicious USB device with empty altsetting reaches an implicit `endpoint[0]` dereference)
- Why this fixture: classic missing-sanity-check NULL deref. Axis 2 (no proximate guard on `intf->cur_altsetting->desc.bNumEndpoints`) + axis 3 (provenance — descriptor data from untrusted USB device).
- Setup:
  ```
  git clone --filter=blob:none --no-checkout https://github.com/torvalds/linux \
      out/dataflow-corpus-fixtures/linux-cve-2019-15291
  cd out/dataflow-corpus-fixtures/linux-cve-2019-15291
  git sparse-checkout set drivers/media/usb/b2c2/flexcop-usb.c
  git checkout d52741728a518afe536d22dc6e9b60193c5fa942
  ```

### Linux kernel — CVE-2019-12382 (drm_edid_load unchecked kstrdup, CWE-476)

- Upstream: https://github.com/torvalds/linux (tag `v5.1`)
- Fix sha: `9f1f1a2dab38d4ce87a13565cf4dc1b73bef3a5f` (drm-misc)
- Local path: `out/dataflow-corpus-fixtures/linux-cve-2019-12382/`
- Bug location: `drivers/gpu/drm/drm_edid_load.c`, function `drm_load_edid_firmware`, line 292
- CWE: CWE-476 (kstrdup result stored without NULL check → subsequent strsep derefs NULL on alloc failure)
- Phase A note: this expands the corpus with a real CVE in the source_intel-target shape (unchecked allocator-return). source_intel verdict on this entry is currently UNCERTAIN — kstrdup is `__malloc`-annotated (not `__must_check`) in upstream `include/linux/string.h`, in SUFFIX position (`extern char *kstrdup(...) __malloc;`) which spatch 1.3 can't parse for attribute matching. Per-alias cocci rules + macro-aware discovery would close this gap (axis-1-expansion).
- Setup: `git clone --filter=blob:none --no-checkout https://github.com/torvalds/linux out/dataflow-corpus-fixtures/linux-cve-2019-12382 && cd out/dataflow-corpus-fixtures/linux-cve-2019-12382 && git sparse-checkout set drivers/gpu/drm/drm_edid_load.c && git checkout v5.1`

### Linux kernel — CVE-2019-12614 (powerpc dlpar unchecked kstrdup, CWE-476)

- Upstream: https://github.com/torvalds/linux (tag `v5.1`)
- Fix sha: `efa9ace68e487ddd29c2b4d6dd23242158f1f607` (powerpc)
- Local path: `out/dataflow-corpus-fixtures/linux-cve-2019-12614/`
- Bug location: `arch/powerpc/platforms/pseries/dlpar.c`, function `dlpar_parse_cc_property`, line 63
- CWE: CWE-476 (same shape as 12382: kstrdup result stored without NULL check; downstream deref of prop->name)
- Phase A note: same __malloc + suffix-position gap.

### Linux kernel — CVE-2019-12615 (sparc mdesc unchecked kstrdup_const, CWE-476)

- Upstream: https://github.com/torvalds/linux (tag `v5.1`)
- Fix sha: `80caf43549e7e41a695c6d1e11066286538b336f` (sparc)
- Local path: `out/dataflow-corpus-fixtures/linux-cve-2019-12615/`
- Bug location: `arch/sparc/kernel/mdesc.c`, function `get_vdev_port_node_info`, line 358
- CWE: CWE-476 (kstrdup_const result stored without NULL check; downstream deref)
- Phase A note: same gap as 12382/12614.

### Why each kernel CVE gets its own clone

Each CVE pins to a different upstream SHA, so they can't share a single working tree. The sparse-checkout pattern keeps each clone tiny (a single source file at the pinned commit, ~few KB on disk).

### Axis-1 evidence gap on the kstrdup-class CVEs

The three 2019 unchecked-kstrdup CVEs (12382, 12614, 12615) are real CWE-476 bugs that source_intel's axis-1 model COULD speak to if the macro/preprocessor situation were different. The actual blocker:

1. Kernel `__must_check` and `__malloc` are MACROS that expand to `__attribute__((...))`. spatch 1.3 doesn't preprocess; it sees the macro tokens.
2. Both macros occupy SUFFIX position on function declarations (`extern T f(...) __malloc;`). spatch 1.3's SmPL grammar rejects trailing-attribute-on-function-declarator.

Closing this gap requires one or more of:
- Generated per-alias cocci rules (`@must_check_X@` matches `__must_check T f(...);` directly without trying to bind to `__attribute__` semantics)
- spatch grammar growth for suffix attributes
- A new rule type ("unchecked allocator call") that pattern-matches the CALL SITE shape instead of binding to the declaration's attribute

The kstrdup CVEs are in the corpus today as substrate-validation fixtures; their source_intel verdict will remain UNCERTAIN until one of the above lands.

### Regenerating the Juice Shop + WebGoat hand-labels

The `juiceshop_*` and `webgoat_*` entries are hand-curated. The
manifest lives in `core/dataflow/scripts/handlabel_seed.py` as a
tuple of `SeedEntry` records — each names the fixture file, the
source/sink line numbers, the producer + rule_id, the verdict +
fp_category, and a written rationale citing the specific defence
(or absence thereof). Adding entries means appending tuples to
`JUICE_SHOP` or `WEBGOAT` in that file; re-running:

```
python3 core/dataflow/scripts/handlabel_seed.py
```

reads each fixture's source line for the snippet and writes paired
JSONs into `core/dataflow/corpus/findings/`. Existing finding ids
are deterministic (hash of producer + rule + source/sink locations)
so re-running with the same manifest is idempotent. Removing entries
means the orphan files in `findings/` need to be deleted manually —
the script doesn't garbage-collect.
