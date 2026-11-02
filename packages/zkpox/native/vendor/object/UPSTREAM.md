# object 0.37.3 decoder-dependency override

Source: https://crates.io/crates/object/0.37.3
Repository: https://github.com/gimli-rs/object
Upstream revision: 916c47b90e5c0bea139ca4bdfc53811f7d2c3383
Published crate SHA256: ff76201f031d8863c38aa7f905eca4f53abbfa15f609db4277d44cd8938f33fe
License: Apache-2.0 OR MIT; both license texts are retained here.

The source, build script, tests and upstream documentation are copied unchanged
from the checksum-verified published crate. The sole functional change is in
Cargo.toml: the optional ruzstd dependency's minimum version changes from 0.8.1
to 0.9.1. The generated manifest's header is replaced with a provenance pointer.
The registry Cargo.lock, original manifest, and registry bookkeeping files are
omitted; the workspace Cargo.lock is authoritative.

Rationale: SP1 6.5.0 requires object 0.37.x, whose last published release still
requires ruzstd 0.8.x. RustSec RUSTSEC-2026-0344 lists ruzstd >=0.9.1 as fixed:
https://rustsec.org/advisories/RUSTSEC-2026-0344.html
The workspace patches this package by path to use the maintained fixed decoder
without changing SP1 or modifying object's parsing/writing implementation.
Backtrace is also updated to 0.3.77 so its optional decoder dependency no longer
keeps ruzstd 0.8.x in the lockfile; its object 0.40 dependency uses the registry.

Remove this override once SP1's supported dependency graph uses only fixed
decoder versions. Regenerate and inspect the workspace lockfile before removing
it. Keep these notices and the original upstream licenses when distributing the
vendored source.

The published crate omits its integration-test fixtures. Standalone upstream
integration tests need `gimli-rs/object-testfiles` revision
`5b121e59e36d00567366691765c0fce3cb72b5e3` available as `testfiles/`, matching the
upstream submodule pin. The native workspace excludes this vendor package from
workspace membership; ordinary RAPTOR native checks do not require those files.
