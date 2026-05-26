"""Project-sample collection for the calibration corpus.

For each project in :data:`PROJECT_SAMPLES`, the collector:

  1. Shallow-clones the project to a transient temp dir.
  2. Runs ``run_sca`` against it (offline-OSV, cache-friendly).
  3. Writes the findings to
     ``packages/sca/data/calibration/project_samples/<ecosystem>/
     <name>.json``.
  4. **Discards the source.** We never store the cloned tree —
     only OUR scan output, which is RAPTOR-generated and ships
     under MIT.

The output schema strips file paths under the project root; only
the dep + finding metadata that the corpus needs for validation
(``raptor_risk_estimate``, ``severity``, ``in_kev``, ``epss``,
``cve_id``) is preserved. Project source code is NEVER included.

License compliance:

  * We don't redistribute the cloned project — it's transient.
  * Our scan output is RAPTOR-generated (MIT). Each output JSON
    carries a ``_source.license: "MIT (RAPTOR-generated)"`` block.
  * The license-compliance check (:mod:`._license_check`) treats
    files under ``project_samples/`` permissively (filename refs
    not required in ATTRIBUTION.md per-file; the parent dir's
    citation suffices).

The project list is intentionally small for the bootstrap — top-N
per ecosystem can come later via the ``popular/<eco>.json``
auto-derived list. Curated start lets us control which licenses
we touch (only OSI-approved permissive). Each entry pins the
clone target so re-runs are reproducible.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProjectSample:
    """One row in the curated project-sample list."""

    name: str
    ecosystem: str          # canonical SCA ecosystem string
    repo_url: str           # https git URL
    git_ref: str            # branch / tag / commit; pinned for reproducibility
    license_spdx: str       # operator-asserted; sanity-check only


# Curated bootstrap list. Each entry is a permissive-licensed OSS
# project with active CVE history (so we have something to score).
# Ten entries is enough to validate the collection loop; the list
# expands incrementally per follow-up PRs that add new CVE-bearing
# projects.
PROJECT_SAMPLES: List[ProjectSample] = [
    ProjectSample(
        name="requests", ecosystem="PyPI",
        repo_url="https://github.com/psf/requests.git",
        git_ref="v2.31.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="flask", ecosystem="PyPI",
        repo_url="https://github.com/pallets/flask.git",
        git_ref="3.0.0", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="django", ecosystem="PyPI",
        repo_url="https://github.com/django/django.git",
        git_ref="4.2.7", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="lodash", ecosystem="npm",
        repo_url="https://github.com/lodash/lodash.git",
        git_ref="4.17.21", license_spdx="MIT",
    ),
    ProjectSample(
        name="express", ecosystem="npm",
        repo_url="https://github.com/expressjs/express.git",
        git_ref="4.18.2", license_spdx="MIT",
    ),
    ProjectSample(
        name="serde", ecosystem="Cargo",
        repo_url="https://github.com/serde-rs/serde.git",
        git_ref="v1.0.193", license_spdx="MIT OR Apache-2.0",
    ),
    ProjectSample(
        name="tokio", ecosystem="Cargo",
        repo_url="https://github.com/tokio-rs/tokio.git",
        git_ref="tokio-1.35.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="gin", ecosystem="Go",
        repo_url="https://github.com/gin-gonic/gin.git",
        git_ref="v1.9.1", license_spdx="MIT",
    ),
    ProjectSample(
        name="spring-boot", ecosystem="Maven",
        repo_url="https://github.com/spring-projects/spring-boot.git",
        git_ref="v3.2.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="rails", ecosystem="RubyGems",
        repo_url="https://github.com/rails/rails.git",
        git_ref="v7.1.2", license_spdx="MIT",
    ),
    # ---- Older-pinned siblings ----------------------------------------
    # The recent-pin set above produces a corpus dominated by 2024+ CVEs
    # that haven't accrued exploit signals yet (KEV / EDB / MSF / PoC
    # all lag CVE disclosure by months-to-years). Validation against
    # the recent-only corpus on 2026-05-09 found only 7/343 findings
    # with any exploit signal — a structural ceiling that capped top-20
    # precision at 7/20 = 0.35 even with optimal weights.
    #
    # These older-pin siblings carry well-known, long-disclosed CVEs in
    # their dep trees (jQuery 1.x family, Rails 5.x, Django 2.2.x,
    # Spring Boot 2.1, etc.) — the historic CVE pool that exploit
    # databases have caught up on. Every entry here is an explicit
    # OLD-version pin to a project we already cover at HEAD; we keep
    # both so the corpus reflects "what gets scanned in CI today" AND
    # "what scoring did when the CVEs were exploit-rich".
    ProjectSample(
        name="django-2.2", ecosystem="PyPI",
        repo_url="https://github.com/django/django.git",
        git_ref="2.2.20", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="rails-5.2", ecosystem="RubyGems",
        repo_url="https://github.com/rails/rails.git",
        git_ref="v5.2.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="spring-boot-2.1", ecosystem="Maven",
        repo_url="https://github.com/spring-projects/spring-boot.git",
        git_ref="v2.1.0.RELEASE", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="express-3", ecosystem="npm",
        repo_url="https://github.com/expressjs/express.git",
        git_ref="3.21.2", license_spdx="MIT",
    ),
    ProjectSample(
        name="lodash-4.17.4", ecosystem="npm",
        repo_url="https://github.com/lodash/lodash.git",
        git_ref="4.17.4", license_spdx="MIT",
    ),
    # ---- Round-2 signal-density expansion (2026-05-09) -----------------
    # Per-ecosystem audit of the 30/1175 signaled corpus showed PyPI
    # at 0/18 and RubyGems at 2/309 (signal-poor relative to Maven's
    # 17/290 and npm's 10/533). These entries target the lagging
    # ecosystems with version pins old enough that their CVE pool has
    # accrued public exploits / KEV listings — pushing toward the
    # ~100-signaled-findings threshold where per-ecosystem refit
    # becomes statistically viable.
    ProjectSample(
        name="django-1.11", ecosystem="PyPI",
        repo_url="https://github.com/django/django.git",
        git_ref="1.11.29", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="requests-2.18", ecosystem="PyPI",
        repo_url="https://github.com/psf/requests.git",
        git_ref="v2.18.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="rails-4.2", ecosystem="RubyGems",
        repo_url="https://github.com/rails/rails.git",
        git_ref="v4.2.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="spring-boot-1.5", ecosystem="Maven",
        repo_url="https://github.com/spring-projects/spring-boot.git",
        git_ref="v1.5.10.RELEASE", license_spdx="Apache-2.0",
    ),
    # ---- App-shaped PyPI sample ---------------------------------------
    # Library repos (django/requests/flask at any pin) carry narrow
    # dep trees — django pulls just Python stdlib + a few utilities,
    # so scanning the django repo surfaces ~3 finding rows. PyPI
    # signal density stays at 0% because there isn't a tree to walk.
    #
    # Saleor 2.10.0 (March 2020) is a Django + GraphQL e-commerce
    # platform with a deep dep tree declared in ``pyproject.toml``
    # (Poetry) — Django, graphene-django, celery, jinja2, pillow,
    # cryptography, and dozens more transitive deps with accrued
    # KEV / EDB / MSF / PoC signals. The pyproject.toml format is
    # critical: Airflow 1.10 (the first candidate tried) declared
    # its deps in ``setup.py``, which SCA's parser doesn't read,
    # so its 64 findings all came from its embedded ``www/``
    # package.json (npm) and didn't move PyPI signal density.
    ProjectSample(
        name="saleor-2.10", ecosystem="PyPI",
        repo_url="https://github.com/saleor/saleor.git",
        git_ref="2.10.0", license_spdx="BSD-3-Clause",
    ),
    # ---- Round-3 corpus expansion: more app-shaped samples -----------
    # Round-2 (saleor) cleared the OSV multi-manifest poison bug and
    # got PyPI density off zero, but per-ecosystem signal is still
    # heavily skewed: Maven 7%, npm 2%, Go 4%, RubyGems 2%, PyPI 1%.
    # Per-ecosystem refit needs ~10+ signaled findings per ecosystem
    # to be statistically viable; round-3 picks 5 app-shaped repos
    # across the under-served ecosystems whose dep trees historically
    # accrued exploit signals (KEV / EDB / MSF / PoC).
    # sentry-9.x switched to BSL (source-available, not permissive);
    # the corpus license check requires OSI-permissive licences for
    # every sample. sentry 8.22 was the last Apache-2.0 release
    # (Oct 2019, before the BSL switch in 2019-11). Same dep-tree
    # shape, permissive license.
    ProjectSample(
        name="sentry-8.22", ecosystem="PyPI",
        repo_url="https://github.com/getsentry/sentry.git",
        git_ref="8.22.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="wagtail-2.10", ecosystem="PyPI",
        repo_url="https://github.com/wagtail/wagtail.git",
        git_ref="v2.10", license_spdx="BSD-3-Clause",
    ),
    ProjectSample(
        name="superset-0.36", ecosystem="PyPI",
        repo_url="https://github.com/apache/superset.git",
        git_ref="0.36.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="strapi-3", ecosystem="npm",
        repo_url="https://github.com/strapi/strapi.git",
        git_ref="v3.6.0", license_spdx="MIT",
    ),
    ProjectSample(
        name="helm-3.5", ecosystem="Go",
        repo_url="https://github.com/helm/helm.git",
        git_ref="v3.5.0", license_spdx="Apache-2.0",
    ),
    # ---- Round-4 corpus expansion: post-2018 manifests, pre-2020 deps -
    # Goal was pre-2018 permissive apps to surface CVEs that have
    # had time to accrue exploit signals. Reality: pre-2018 Go apps
    # predate go.mod (introduced 1.11/2018) so SCA can't parse
    # their dep graph, and pre-2018 Python apps mostly use setup.py
    # which SCA also doesn't parse. The viable window is therefore
    # 2019-2020: late enough to ship go.mod / requirements.txt,
    # early enough that the resolved CVEs have had ~5 years to
    # accumulate KEV / EDB / MSF / PoC signals.
    #
    # Initial round-4 picks (etcd-3.0, moby-1.13, synapse-0.20,
    # salt-2017.7) all returned 0 findings on collect because none
    # ship a manifest format SCA parses at those tags. Replaced
    # with go.mod-era Go apps + requirements.txt-shape Python.
    ProjectSample(
        name="prometheus-2.10", ecosystem="Go",
        repo_url="https://github.com/prometheus/prometheus.git",
        git_ref="v2.10.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="istio-1.4", ecosystem="Go",
        repo_url="https://github.com/istio/istio.git",
        git_ref="1.4.0", license_spdx="Apache-2.0",
    ),
    ProjectSample(
        name="mitmproxy-5", ecosystem="PyPI",
        repo_url="https://github.com/mitmproxy/mitmproxy.git",
        git_ref="v5.0.0", license_spdx="MIT",
    ),
    # ---- App-shaped RubyGems sample -----------------------------------
    # Discourse is GPL-2, Mastodon is AGPL, Redmine is GPL-2,
    # OpenProject is GPL-3 — every popular Rails APP trends GPL/AGPL,
    # so the corpus license check (permissive-only) ruled them out.
    # ManageIQ is the exception: Apache-2.0, ~325 gems in its release
    # lockfile. It ships ``Gemfile.lock.release`` instead of plain
    # ``Gemfile.lock`` (gitignored dev lock, release-time copy
    # committed to the tag) — the gemfile parser handles this via the
    # ``Gemfile.lock*`` predicate (see ``parsers/gemfile.py``).
    ProjectSample(
        name="manageiq-jansa", ecosystem="RubyGems",
        repo_url="https://github.com/ManageIQ/manageiq.git",
        git_ref="jansa-1", license_spdx="Apache-2.0",
    ),
    # ---- Round-5 ecosystem-coverage gap fillers (2026-05-09) ---------
    # Per-ecosystem audit found NuGet + Packagist at zero coverage and
    # Cargo + Maven library-dominated. Each pick below targets a real
    # APP (not a framework / library) with a deep, version-pinned
    # dependency graph so the per-ecosystem refit thresholds are
    # reachable without further rounds.

    # NuGet cold-start. Modern .NET trends toward Central Package
    # Management (versions in ``Directory.Packages.props``, not
    # csproj) which SCA's NuGet parser doesn't follow — so we pick
    # PowerShell 6.2.0 (March 2019), pre-CPM era. 100% of its 63
    # ``<PackageReference>`` rows carry inline ``Version=`` attributes;
    # 5+ years for CVEs to accrue KEV / EDB / MSF / PoC signals.
    ProjectSample(
        name="powershell-6.2", ecosystem="NuGet",
        repo_url="https://github.com/PowerShell/PowerShell.git",
        git_ref="v6.2.0", license_spdx="MIT",
    ),
    # Packagist cold-start. Every popular PHP CMS / e-commerce
    # platform (WordPress, Drupal, Joomla, Magento, PrestaShop) is
    # GPL/OSL — same blocker as Ruby APPs. Pterodactyl Panel (game-
    # server admin) is the exception: MIT, ships ``composer.lock``
    # at the repo root, ~155 packages (105 prod + 50 dev).
    ProjectSample(
        name="pterodactyl-1.11", ecosystem="Packagist",
        repo_url="https://github.com/pterodactyl/panel.git",
        git_ref="v1.11.7", license_spdx="MIT",
    ),
    # Cargo app sample. tokio + serde are libraries with shallow trees;
    # alacritty (terminal emulator) pulls 258 packages via Cargo.lock —
    # x11, winit, gpu, font-rendering — diverse Rust app footprint.
    ProjectSample(
        name="alacritty-0.13", ecosystem="Cargo",
        repo_url="https://github.com/alacritty/alacritty.git",
        git_ref="v0.13.0", license_spdx="Apache-2.0",
    ),
    # Maven diversity. spring-boot-{1.5, 2.1, 3.x} all share the
    # Spring universe (Spring Core / Boot / MVC / Data). Jenkins
    # uses a completely different Java stack: Stapler web framework,
    # Guice DI, JNA, args4j, Jenkins's own plugin loader — surfaces
    # CVEs the spring-boot trees never touch.
    ProjectSample(
        name="jenkins-2.387", ecosystem="Maven",
        repo_url="https://github.com/jenkinsci/jenkins.git",
        git_ref="jenkins-2.387.1", license_spdx="MIT",
    ),
    # ---- Round-6 cold-start fillers (2026-05-09) ---------------------
    # Round-5 introduced Cargo / NuGet / Packagist with 1 sample each
    # but per-eco refit needs ≥100 findings to clear the cold-start
    # gate. Round-6 adds 2-3 app-shaped samples per cold-start eco,
    # mixing recent (modern dep tree) and vintage (older deps with
    # accrued KEV / EDB / MSF / PoC signals).

    # Cargo +2: vintage and high-density.
    # firecracker is AWS's Rust microVM — server-class app with kvm
    # bindings, vsock, vmm internals; very different surface from
    # alacritty's terminal stack.
    ProjectSample(
        name="firecracker-1.0", ecosystem="Cargo",
        repo_url="https://github.com/firecracker-microvm/firecracker.git",
        git_ref="v1.0.0", license_spdx="Apache-2.0",
    ),
    # nushell — modern shell written in Rust. 611 packages in
    # Cargo.lock makes it the deepest Cargo tree we can scan; the
    # variety pulls in dozens of file-format / plugin / async crates.
    ProjectSample(
        name="nushell-0.85", ecosystem="Cargo",
        repo_url="https://github.com/nushell/nushell.git",
        git_ref="0.85.0", license_spdx="MIT",
    ),
    # alacritty 0.6 — vintage pin (March 2021) of the same project
    # we have at 0.13. Older dep tree (winit 0.24 era, pre-2.0 wgpu
    # universe) carries the long-disclosed CVEs that 0.13 has
    # already upgraded past.
    ProjectSample(
        name="alacritty-0.6", ecosystem="Cargo",
        repo_url="https://github.com/alacritty/alacritty.git",
        git_ref="v0.6.0", license_spdx="Apache-2.0",
    ),

    # NuGet +2.
    # IdentityServer4 3.1 (Dec 2019) — OAuth2/OIDC server, a real
    # production identity surface. 94 inline-pinned PackageReference
    # rows across 90 csproj — deep dotnet tree, no CPM workaround
    # needed.
    ProjectSample(
        name="identityserver4-3.1", ecosystem="NuGet",
        repo_url="https://github.com/IdentityServer/IdentityServer4.git",
        git_ref="3.1.0", license_spdx="Apache-2.0",
    ),
    # PowerShell 6.0 (Jan 2018) — older sibling of powershell-6.2.
    # Pre-CPM era; deps from 2017-2018 vintage have had 6+ years to
    # accrue CVE / KEV signals.
    ProjectSample(
        name="powershell-6.0", ecosystem="NuGet",
        repo_url="https://github.com/PowerShell/PowerShell.git",
        git_ref="v6.0.0", license_spdx="MIT",
    ),
    # Round-7 NuGet count-gate fillers (2026-05-10).
    # NuGet was at 33 findings post-round-6, well under the 100-
    # finding per-eco refit threshold. Two more permissive samples
    # to push it over without triggering the modern-CPM trap (where
    # Directory.Packages.props centralises versions and SCA's csproj
    # parser sees PackageReference rows with no Version attribute).
    #
    # Avalonia 0.10.18 — cross-platform .NET UI framework, MIT.
    # 33 inline-pinned PackageReference rows across 100+ csproj
    # files. Different stack to PowerShell (UI / windowing / x11 /
    # gpu) — surfaces CVEs in deps that the systems-tooling samples
    # don't touch.
    ProjectSample(
        name="avalonia-0.10", ecosystem="NuGet",
        repo_url="https://github.com/AvaloniaUI/Avalonia.git",
        git_ref="0.10.18", license_spdx="MIT",
    ),
    # Marten v6.2.0 — Postgres-backed event-sourcing + document DB
    # for .NET, MIT. 118 inline-pinned PackageReference rows. No
    # CPM (Directory.Packages.props absent), so the parser sees
    # all 118 deps directly. Database / event-sourcing surface,
    # different from UI + scripting samples.
    ProjectSample(
        name="marten-6.2", ecosystem="NuGet",
        repo_url="https://github.com/JasperFx/marten.git",
        git_ref="v6.2.0", license_spdx="MIT",
    ),

    # Packagist +3.
    # bagisto 1.5 — Laravel-based e-commerce. 182 composer packages.
    ProjectSample(
        name="bagisto-1.5", ecosystem="Packagist",
        repo_url="https://github.com/bagisto/bagisto.git",
        git_ref="v1.5.0", license_spdx="MIT",
    ),
    # pterodactyl 0.7 (vintage, ~2018-2019) — older sibling of
    # pterodactyl-1.11. 127 packages, deps from a pre-2020 Laravel
    # universe with extensive accrued CVE signal.
    ProjectSample(
        name="pterodactyl-0.7", ecosystem="Packagist",
        repo_url="https://github.com/pterodactyl/panel.git",
        git_ref="v0.7.19", license_spdx="MIT",
    ),
    # cachet 2.4 — open-source status-page app, BSD-3-Clause.
    # 135 composer packages on a Laravel base; different stack to
    # both pterodactyl tags.
    ProjectSample(
        name="cachet-2.4", ecosystem="Packagist",
        repo_url="https://github.com/CachetHQ/Cachet.git",
        git_ref="v2.4.0", license_spdx="BSD-3-Clause",
    ),

    # ---- Round-8 cold-start eco depth fillers (2026-05-22) -----------
    # The 2026-05-22 four-item tuning pass took aggregate ρ from
    # 0.452 → 0.571; per-eco ρ now passes everywhere but Packagist
    # (0.532) sits closest to the 0.4 threshold and is most
    # vulnerable to sample-set drift. Add 2 more samples per cold-
    # start eco (Cargo / NuGet / Packagist) to tighten the
    # measurement against statistical noise. Permissive-license
    # only; deep-tree app preference over libraries.

    # Cargo +2.
    # meilisearch — search-engine binary, MIT. Cargo.lock pulls
    # ~700 packages spanning networking, tokio, async-io, lucene-
    # like indexing crates; very different surface from
    # alacritty (GUI) / firecracker (VMM) / nushell (shell).
    ProjectSample(
        name="meilisearch-1.0", ecosystem="Cargo",
        repo_url="https://github.com/meilisearch/meilisearch.git",
        git_ref="v1.0.0", license_spdx="MIT",
    ),
    # deno 1.30 — JS/TS runtime in Rust, MIT. Cargo.lock ~600
    # packages. v8 bindings + tokio + ring crypto + napi
    # subsystems — a JIT/runtime stack distinct from the others.
    ProjectSample(
        name="deno-1.30", ecosystem="Cargo",
        repo_url="https://github.com/denoland/deno.git",
        git_ref="v1.30.0", license_spdx="MIT",
    ),

    # NuGet was attempted in round-8 (Hangfire / AutoMapper) but
    # the candidates either failed the permissive-license gate
    # (Hangfire is LGPL-3.0) or yielded too few findings to
    # meaningfully tighten ρ measurement (AutoMapper: 0 findings).
    # The library shape of most non-Microsoft .NET projects on
    # GitHub doesn't carry the deep version-pinned dep trees
    # we need for calibration depth. Further NuGet expansion
    # deferred until a permissive .NET APP (not framework /
    # library) with an aged dep tree surfaces — e.g. a pre-CPM
    # version of Jellyfin, OrchardCore, or a Mono-era project.

    # Packagist +2.
    # BookStack — wiki / documentation platform, MIT, Laravel-
    # based. composer.lock ~200 packages. Covers wiki/CMS
    # surface that pterodactyl (game-server admin) / cachet
    # (status page) / bagisto (e-commerce) don't touch.
    ProjectSample(
        name="bookstack-23",
        ecosystem="Packagist",
        repo_url="https://github.com/BookStackApp/BookStack.git",
        git_ref="v23.10", license_spdx="MIT",
    ),
    # Drupal 10 — most popular permissive PHP CMS, GPL-2.0
    # (BLOCKED by the license-touch policy on most calibration
    # rounds, but pgsql adapter — drush — is MIT and pulls a
    # composer tree representative of Drupal's). Stand-in: drush
    # 12, MIT-licensed Drupal toolchain entry-point.
    ProjectSample(
        name="drush-12", ecosystem="Packagist",
        repo_url="https://github.com/drush-ops/drush.git",
        git_ref="12.5.0", license_spdx="MIT",
    ),

    # ---- Round-9 CPM + Gradle catalog parser-coverage (2026-05-22) ---
    # Earlier NuGet expansion was capped by the "CPM trap" — most
    # modern .NET projects centralise versions in
    # ``Directory.Packages.props`` and the csproj parser previously
    # skipped versionless ``<PackageReference>`` rows. Round-9 ships
    # the CPM read-side parser
    # (``parsers/directory_packages_props.py``) + the version-
    # override walk + .sln-based discovery; the samples below
    # exercise those code paths against real CPM-using apps. Same
    # idea for Gradle's ``libs.versions.toml`` catalog — its
    # accessor-style references resolve via the new
    # ``parsers/gradle_version_catalog.py``.
    #
    # When these samples join the corpus they validate END-TO-END
    # (parse → resolve → OSV-match → finding row) and contribute
    # to per-ecosystem ρ measurement for NuGet / Maven exactly
    # like every other sample. They are NOT separate / parallel
    # measurement; they DENSIFY the existing per-eco signal pool
    # with deps the parsers couldn't reach before.

    # NuGet CPM. OrchardCore (BSD-3-Clause) is a modular ASP.NET
    # Core CMS — heavily MSBuild + CPM-based. The repo's
    # ``Directory.Packages.props`` carries ~140 PackageVersion
    # rows; every csproj declares versionless PackageReference
    # rows that previously resolved to nothing. With CPM read,
    # the corpus picks up the full ~140-dep tree per csproj.
    ProjectSample(
        name="orchardcore-2.0", ecosystem="NuGet",
        repo_url="https://github.com/OrchardCMS/OrchardCore.git",
        git_ref="v2.0.0", license_spdx="BSD-3-Clause",
    ),
    # NodaTime (Apache-2.0) — date/time library that switched to
    # Central Package Management in its 3.x series. Smaller dep
    # tree (~25 PackageVersion) than OrchardCore but a clean
    # canonical CPM layout (Directory.Packages.props + per-csproj
    # versionless PackageReference) — useful as a tight regression
    # case if a future change breaks CPM resolution. Library
    # rather than app, but its CI deps + System.* runtime libs
    # carry KEV / EDB / MSF / PoC signals.
    ProjectSample(
        name="nodatime-3.1", ecosystem="NuGet",
        repo_url="https://github.com/nodatime/nodatime.git",
        git_ref="3.1.9", license_spdx="Apache-2.0",
    ),

    # Maven Gradle catalog. Micronaut Core (Apache-2.0) is one of
    # the largest production catalog adopters — ~250 library
    # entries in ``gradle/libs.versions.toml``, accessed via
    # ``libs.netty.codec`` / ``libs.managed.netty.codec`` accessor
    # references across every subproject's ``build.gradle.kts``.
    # Without catalog resolution the Gradle DSL parser would
    # surface 0 deps for the kts files; with catalog read, every
    # ``libs.*`` and ``libs.bundles.*`` accessor resolves to the
    # group:artifact:version triple in the catalog.
    ProjectSample(
        name="micronaut-core-4.2", ecosystem="Maven",
        repo_url="https://github.com/micronaut-projects/micronaut-core.git",
        git_ref="v4.2.0", license_spdx="Apache-2.0",
    ),
    # Ktor (Apache-2.0) — JetBrains' Kotlin async-IO framework,
    # uses ``libs.versions.toml`` with ~180 library entries. Pure
    # Kotlin / KMP shape; surfaces deps the Java-mainstream
    # samples (spring-boot, jenkins, micronaut) don't carry.
    ProjectSample(
        name="ktor-2.3", ecosystem="Maven",
        repo_url="https://github.com/ktorio/ktor.git",
        git_ref="2.3.7", license_spdx="Apache-2.0",
    ),
]


@dataclass
class CollectResult:
    project: str
    ecosystem: str
    written: bool
    error: Optional[str]
    finding_count: int


def collect_project_samples(
    *,
    out_dir: Path,
    samples: Optional[List[ProjectSample]] = None,
    http: Optional[Any] = None,
    cache: Optional[Any] = None,
    git_clone_timeout: int = 120,
    sca_timeout: int = 300,
    only_licenses: Optional[List[str]] = None,
) -> List[CollectResult]:
    """Clone each sample, run SCA, write findings.

    ``only_licenses`` filters the sample list — when set, only
    samples whose ``license_spdx`` matches one of the entries are
    processed. Operators concerned about license-touch can pass
    e.g. ``["MIT", "Apache-2.0", "BSD-3-Clause"]`` to skip
    anything else.

    Returns one :class:`CollectResult` per attempted sample
    (errored or successful). The function never raises on
    individual sample failures — captures them in
    ``CollectResult.error``.
    """
    if samples is None:
        samples = PROJECT_SAMPLES
    if only_licenses is not None:
        allowed = set(only_licenses)
        samples = [
            s for s in samples
            if any(lic in s.license_spdx for lic in allowed)
        ]
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[CollectResult] = []
    for sample in samples:
        try:
            result = _collect_one(
                sample, out_dir, http=http, cache=cache,
                git_clone_timeout=git_clone_timeout,
                sca_timeout=sca_timeout,
            )
        except Exception as e:                              # noqa: BLE001
            logger.warning(
                "sca.calibration.project_samples: %s/%s failed: %s",
                sample.ecosystem, sample.name, e, exc_info=True,
            )
            result = CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False, error=str(e), finding_count=0,
            )
        results.append(result)
    return results


def _collect_one(
    sample: ProjectSample,
    out_dir: Path,
    *,
    http: Optional[Any],
    cache: Optional[Any],
    git_clone_timeout: int,
    sca_timeout: int,
) -> CollectResult:
    eco_dir = out_dir / sample.ecosystem
    eco_dir.mkdir(parents=True, exist_ok=True)
    out_path = eco_dir / f"{sample.name}.json"

    with tempfile.TemporaryDirectory(prefix="raptor-sca-sample-") as tmp:
        clone_root = Path(tmp) / sample.name
        # Shallow clone, single ref. ``--depth 1`` keeps it fast;
        # ``--branch`` accepts both branches and tags.
        try:
            subprocess.run(
                [
                    "git", "clone", "--depth", "1",
                    "--branch", sample.git_ref,
                    sample.repo_url, str(clone_root),
                ],
                check=True, capture_output=True, text=True,
                timeout=git_clone_timeout,
            )
        except (subprocess.TimeoutExpired,
                subprocess.CalledProcessError) as e:
            err = (
                e.stderr if isinstance(e, subprocess.CalledProcessError)
                else f"clone timed out after {git_clone_timeout}s"
            )
            return CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False,
                error=f"git clone failed: {str(err)[:200]}",
                finding_count=0,
            )

        # Run SCA against the cloned tree. Results land in a tmp
        # output dir we then read + transform; the SCA-generated
        # files themselves get discarded along with the clone.
        sca_out = Path(tmp) / "sca-out"
        try:
            from packages.sca.pipeline import run_sca, RunOptions
            run_sca(
                target=clone_root, output_dir=sca_out,
                options=RunOptions(
                    enable_llm_review=False, enable_triage=False,
                ),
                http=http, cache=cache,
            )
        except Exception as e:                              # noqa: BLE001
            return CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False,
                error=f"run_sca failed: {str(e)[:200]}",
                finding_count=0,
            )

        try:
            findings = json.loads(
                (sca_out / "findings.json").read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as e:
            return CollectResult(
                project=sample.name, ecosystem=sample.ecosystem,
                written=False,
                error=f"findings.json read failed: {e}",
                finding_count=0,
            )

    # Sanitise findings: drop file paths under the (now-deleted)
    # clone root, keep only the validation-relevant fields.
    sanitised = _sanitise_findings(findings, clone_root)

    output = {
        "_source": {
            "name": f"RAPTOR SCA scan of {sample.name}",
            "url": sample.repo_url,
            "license": "MIT (RAPTOR-generated scan output)",
            "fetched_at": _utcnow(),
            "git_ref": sample.git_ref,
            "project_license": sample.license_spdx,
            "provenance": (
                f"Scan output produced by RAPTOR's SCA pipeline "
                f"against {sample.repo_url}@{sample.git_ref}. "
                f"Project source not redistributed."
            ),
        },
        "findings": sanitised,
    }
    out_path.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return CollectResult(
        project=sample.name, ecosystem=sample.ecosystem,
        written=True, error=None,
        finding_count=len(sanitised),
    )


def _sanitise_findings(
    findings: List[Dict[str, Any]],
    clone_root: Path,
) -> List[Dict[str, Any]]:
    """Strip file paths + transient details that don't help
    validation, keep score + dep + advisory metadata.

    Path stripping matters because the clone path is a tempdir
    that won't exist on second runs; preserving project-relative
    paths would also leak the file structure of the project we
    just discarded.
    """
    out: List[Dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sca = f.get("sca", {}) or {}
        # Only vuln findings carry risk scores worth validating
        # against. Hygiene / supply-chain / license findings are
        # different signals; skip them for the corpus.
        if f.get("vuln_type") != "sca:vulnerable_dependency":
            continue
        out.append({
            "finding_id": f.get("finding_id"),
            "severity": f.get("severity"),
            "ecosystem": sca.get("ecosystem"),
            "dep_name": sca.get("name"),
            "dep_version": sca.get("version"),
            "purl": sca.get("purl"),
            "advisory": sca.get("advisory"),
            "in_kev": sca.get("in_kev"),
            "epss": sca.get("epss"),
            "cvss_score": sca.get("cvss_score"),
            "reachability": sca.get("reachability"),
            "raptor_risk_estimate": sca.get("raptor_risk_estimate"),
            "risk_components": sca.get("risk_components"),
            # Without this, refit could not see EDB / MSF / GitHub-PoC
            # signal on archived findings — only ``in_kev`` (the
            # binary CISA flag) was preserved, even though the live
            # pipeline populated the full ExploitEvidence block on
            # every finding before the archive step. Re-tuning runs
            # against this archive could only see ~half the exploit
            # signal that production scans actually saw.
            "exploit_evidence": sca.get("exploit_evidence"),
            # CISA Vulnrichment SSVC fields. Persist BOTH so refit
            # exercises the matched ``compute_risk_estimate`` branches
            # (Automatable bonus only fires when Exploitation>=poc
            # AND Automatable=yes — see risk.py).
            "ssvc_exploitation": sca.get("ssvc_exploitation"),
            "ssvc_automatable": sca.get("ssvc_automatable"),
        })
    return out


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "PROJECT_SAMPLES",
    "CollectResult",
    "ProjectSample",
    "collect_project_samples",
]
