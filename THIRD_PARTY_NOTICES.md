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
