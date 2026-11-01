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
