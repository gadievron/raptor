"""RAPTOR SCA Package - Software Composition Analysis.

Canonical host allowlist for /sca network egress.  Consumed by:

  - ``packages.sca.agent`` when launching raptor-sca as a sandboxed
    subprocess (``proxy_hosts=list(SCA_ALLOWED_HOSTS)``).
  - ``raptor_agentic.py`` Phase 1b (same pattern).
  - raptor-sca's own ``packages.sca.__init__.default_client()`` which
    constructs an ``EgressClient`` with the same set.

When a new registry or feed is added on the raptor-sca side, add the
host here too so the sandbox permits the traffic.
"""

# The full set of hosts /sca needs to reach for vulnerability data and
# registry metadata.  Mirrors the authoritative list in the raptor-sca
# branch at ``packages/sca/__init__.py``.  Ordered by purpose.
SCA_ALLOWED_HOSTS: tuple[str, ...] = (
    # Vulnerability feeds
    "api.osv.dev",
    "osv-vulnerabilities.storage.googleapis.com",   # OSV offline-DB zip mirror
    "www.cisa.gov",                                 # KEV feed
    "api.first.org",                                # EPSS scores
    # Registry metadata (harden / typosquat / supply-chain heuristics)
    "pypi.org",
    "registry.npmjs.org",
    "crates.io",
    "rubygems.org",
    "proxy.golang.org",
    "search.maven.org",
    "repo.packagist.org",
    "api.nuget.org",
    "sources.debian.org",
    "formulae.brew.sh",
    # Source-archive downloads (version-diff review + wheel-metadata fallback)
    "files.pythonhosted.org",                       # PyPI sdist/wheel archives
    "static.crates.io",                             # Cargo crate tarballs
    "sum.golang.org",                               # Go module checksums
    "repo.maven.apache.org",                        # Maven/Gradle source jars
    "repo1.maven.org",                              # Maven Central mirror
    "api.github.com",                               # GHA ref→SHA resolution
)
