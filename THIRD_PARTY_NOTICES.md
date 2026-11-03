# Third-party notices

RAPTOR's original code is licensed under the [MIT license](LICENSE).
Bundled third-party material retains its own license as described below;
the MIT license does not replace those terms.

## Public Suffix List

- File: `core/domains/data/public_suffix_list.dat`
- Source: https://publicsuffix.org/list/public_suffix_list.dat
- Project: https://publicsuffix.org/
- License: Mozilla Public License 2.0 (MPL-2.0)
- Full license: [core/domains/data/LICENSE.MPL-2.0](core/domains/data/LICENSE.MPL-2.0)

The snapshot preserves upstream notices and its version/commit header.
It is distributed in its original, readable source form. Modifications to
this file remain subject to MPL-2.0 when distributed. Preserve its notices,
license information, and source availability in downstream distributions,
including containers or other bundles that include this data.

RAPTOR's independently written lookup implementation, refresh script, tests,
and workflow remain MIT-licensed. Loading the list into runtime frozensets
does not relicense the list or those separate implementation files. Any
future distributed generated files derived from the list must retain the
applicable MPL licensing and provide access to the corresponding source.

## SecOpsAgentKit submodule

- Path: `.claude/skills/SecOpsAgentKit` (when initialized).
- Upstream: [AgentSecOps/SecOpsAgentKit](https://github.com/AgentSecOps/SecOpsAgentKit).
- Pinned revision: `6e25a4bc57432437889bda57da52ce4c414b9e82`.
- Documentation, including Markdown skills and reference material:
  CC-BY-SA-4.0.
- Code and configuration: CC-BY-SA-4.0 OR MPL-2.0, at the recipient's choice.
- Attribution and full licence texts: the submodule's upstream
  [LICENSE.md](https://github.com/AgentSecOps/SecOpsAgentKit/blob/6e25a4bc57432437889bda57da52ce4c414b9e82/LICENSE.md).

Credit belongs to the SecOpsAgentKit contributors. These files retain their
upstream terms; RAPTOR's MIT licence does not replace them. Preserve the
upstream licence and attribution when distributing a populated submodule,
and identify modifications under the applicable licence. A plain RAPTOR
source archive does not populate the submodule.

## SCA calibration data

Files under `packages/sca/data/calibration/` contain RAPTOR-generated
assessments and signals derived from external vulnerability datasets.
Source credits, retained fields, and applicable upstream terms are documented
in [the calibration attribution file](packages/sca/data/calibration/ATTRIBUTION.md).
RAPTOR's MIT licence applies to its original fields and code; it does not
replace the terms of upstream data.

## CVE-diff benchmark samples

The inputs in `packages/cve_diff/data/samples/` include vulnerability metadata
from the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)
and upstream advisories. RAPTOR's selection and generated assessments do
not relicense upstream descriptions. NVD API attribution:

> This product uses the NVD API but is not endorsed or certified by the NVD.

## Dataflow corpus source excerpts

The finding JSONs under `core/dataflow/corpus/findings/` retain selected
source lines from OWASP Benchmark Java, WebGoat, Juice Shop, curl, and
Linux kernel files. These excerpts retain their upstream licences,
including GPLv2 variants, MIT, the curl licence, and a Broadcom permissive
grant. The complete upstream fixture repositories are fetched separately.

The [corpus source and licence inventory](core/dataflow/corpus/SOURCES.md#licensing-of-retained-excerpts)
identifies each origin and scope. Copyright/author notices, permission and
warranty notices, and licence texts are preserved in the corpus
[licence directory](core/dataflow/corpus/licenses/). Preserve that inventory
and licence directory when redistributing the excerpt collection.

RAPTOR's independently authored code and annotations retain the MIT licence;
it does not replace the licences of the copied source excerpts.


## Container Node.js runtime

The Linux container uses its system Node.js for both the CLI and Playwright;
Playwright's duplicate bundled Node executable is removed. The installed Node
license and third-party notices are available at `/usr/share/doc/nodejs/LICENSE`,
with package copyright information at `/usr/share/doc/nodejs/copyright`.
These components retain their own terms. Playwright and npm retain their
separate package notices.

Earlier image releases that included Playwright's bundled Node runtime retain
the notices shipped with those releases.

## CPython license evidence fixture

The [complete upstream CPython license](packages/sca/tests/fixtures/licenses/cpython-LICENSE)
is retained as a license-identification fixture. It comes from the official
[Python 3.14.10 source release](https://www.python.org/ftp/python/3.14.10/Python-3.14.10.tar.xz).
Python's project declaration is PSF-2.0; incorporated software retains its own
terms, as the retained license explains. RAPTOR's license association does not
replace those terms or certify that a binary was built from a particular source.

## Container Chromium browser

The Linux container ships Debian's unbranded Chromium package for browser
automation. Its version-matched copyright inventory and license texts are
installed at `/usr/share/doc/chromium/copyright`, with referenced common texts
under `/usr/share/common-licenses`. Debian provides the corresponding source
through its [Chromium source package](https://tracker.debian.org/pkg/chromium).
Chromium and its incorporated third-party components retain their respective
terms. This package replaces Google Chrome for Testing in new container builds;
older image releases retain their original browser and associated terms.

## Container package license supplements

Debian Python package copyright notices are installed under
`/usr/share/doc/python3-pip/`, `/usr/share/doc/python3-setuptools/`, and
`/usr/share/doc/python3-wheel/`, with shared texts in `/usr/share/common-licenses/`.

The [upstream manifest for @npmcli/agent 4.0.2](https://github.com/npm/agent/blob/db7852869c74ceb8985d7c36b291a2e7a866741c/package.json)
declares ISC and names GitHub Inc. as its author. Its
[ISC reference supplement](.devcontainer/npm-notices/agent-ISC-reference.txt)
retains that declaration and attribution alongside the standard ISC text.
The supplement distinguishes the standard reference text from an
upstream-authored package notice.

`spdx-exceptions` and `spdx-license-ids` retain their upstream READMEs and
full CC-BY-3.0 and CC0-1.0 reference texts. Installed, version-specific
supplements are available in the packages' `NOTICE` files and under
`/usr/share/doc/raptor-npm-notices/`.
