"""The shipped javascript seed packs: every dotted name pinned
against the real Node / Express / template-engine API surface (a
misspelled name matches nothing and becomes a silent detection gap),
the curated seed discipline held, and the emissibility report over
the set fully accounted.

The pinned tables below cite the API each entry was verified
against; a seed edit must update the matching pin deliberately.
"""

from __future__ import annotations

import pytest

from core.taint.mad_matrix import emissibility_report
from core.taint.packs import (
    MAX_TAINT_CLASSES_PER_ENTRY,
    PackSet,
    default_pack_names,
    load_packs,
)


@pytest.fixture(scope="module")
def pack_set() -> PackSet:
    return load_packs(default_pack_names("javascript"))


def test_shipped_javascript_pack_names():
    assert default_pack_names("javascript") == (
        "javascript/frameworks-express",
        "javascript/template-engines",
        "javascript/web-injection-core",
    )


# ---------------------------------------------------------------------
# Canonical-name pins (the seed-correctness table)
# ---------------------------------------------------------------------

#: match → the real API it names. Node core: nodejs.org/api (child
#: process, vm, fs, path, querystring, buffer); globals: ECMA-262 /
#: Node globals; Express 4/5: expressjs.com/en/api (req.*, res.*);
#: template engines: the npm package's documented top-level API.
EXPECTED_SINKS = {
    # child_process — https://nodejs.org/api/child_process.html
    "child_process.exec": "command-injection",
    "child_process.execSync": "command-injection",
    "child_process.spawn": "command-injection",
    "child_process.spawnSync": "command-injection",
    "child_process.execFile": "command-injection",
    "child_process.execFileSync": "command-injection",
    "child_process.fork": "command-injection",
    # eval family — ECMA-262 eval / Function; https://nodejs.org/api/vm.html
    "eval": "code-injection",
    "Function": "code-injection",
    "vm.runInThisContext": "code-injection",
    "vm.runInNewContext": "code-injection",
    "vm.runInContext": "code-injection",
    "vm.Script": "code-injection",
    "vm.compileFunction": "code-injection",
    # fs path sinks — https://nodejs.org/api/fs.html
    "fs.readFile": "path-traversal",
    "fs.readFileSync": "path-traversal",
    "fs.writeFile": "path-traversal",
    "fs.writeFileSync": "path-traversal",
    "fs.createReadStream": "path-traversal",
    "fs.createWriteStream": "path-traversal",
    # Express Response — res.redirect/location/sendFile/download/send
    "express.Response.redirect": "url-redirection",
    "express.Response.location": "url-redirection",
    "express.Response.sendFile": "path-traversal",
    "express.Response.download": "path-traversal",
    "express.Response.send": "xss",
    # template engines — ejs.co (render/compile), pugjs.org
    # (render/compile), handlebarsjs.com (compile), mustache.js
    # (render), mozilla.github.io/nunjucks (renderString), lodash
    # (_.template)
    "ejs.render": "template-injection",
    "ejs.compile": "template-injection",
    "pug.render": "template-injection",
    "pug.compile": "template-injection",
    "handlebars.compile": "template-injection",
    "mustache.render": "template-injection",
    "nunjucks.renderString": "template-injection",
    "lodash.template": "template-injection",
}

#: match → taint classes. Express 4/5 Request properties (params /
#: query / body / cookies / headers; cookies via cookie-parser,
#: headers via http.IncomingMessage).
EXPECTED_SOURCES = {
    "express.Request.params": ("user-input",),
    "express.Request.query": ("user-input",),
    "express.Request.body": ("user-input",),
    "express.Request.cookies": ("user-input",),
    "express.Request.headers": ("user-input",),
}

#: match → (from, to) flow edges. Node path.join/resolve/normalize,
#: querystring.unescape; globals decodeURIComponent / decodeURI /
#: Buffer.from / JSON.parse.
EXPECTED_PROPAGATORS = {
    "path.join": (("Argument[*]", "ReturnValue"),),
    "path.resolve": (("Argument[*]", "ReturnValue"),),
    "path.normalize": (("Argument[0]", "ReturnValue"),),
    "decodeURIComponent": (("Argument[0]", "ReturnValue"),),
    "decodeURI": (("Argument[0]", "ReturnValue"),),
    "querystring.unescape": (("Argument[0]", "ReturnValue"),),
    "Buffer.from": (("Argument[0]", "ReturnValue"),),
    "JSON.parse": (("Argument[0]", "ReturnValue"),),
}

#: Pack-declared sanitizers (the curated table rides in beside them).
#: path.basename is TAG, not kill: its return can still be '..'.
EXPECTED_PACK_SANITIZERS = {
    "path.basename": ("tag", ("path-traversal",)),
}


def test_sink_names_and_classes_match_the_verified_table(pack_set):
    live = {s.match: s.sink_class for s in pack_set.sinks}
    assert live == EXPECTED_SINKS


def test_source_names_match_the_verified_table(pack_set):
    live = {s.match: s.taint_classes for s in pack_set.sources}
    assert live == EXPECTED_SOURCES


def test_propagator_flows_match_the_verified_table(pack_set):
    live = {
        p.match: tuple((f.src, f.dst) for f in p.flows)
        for p in pack_set.propagators
    }
    assert live == EXPECTED_PROPAGATORS


def test_pack_sanitizers_match_and_never_shadow_curated(pack_set):
    pack_side = {
        z.match: (z.semantics, z.sink_classes)
        for z in pack_set.sanitizers if z.tier == "pack"
    }
    assert pack_side == EXPECTED_PACK_SANITIZERS
    curated = {z.match for z in pack_set.curated_sanitizers}
    assert not set(pack_side) & curated


def test_every_entry_carries_catalog_provenance_and_rationale(pack_set):
    for entry in (*pack_set.sources, *pack_set.sinks,
                  *pack_set.propagators):
        assert entry.provenance == "framework_catalog", entry.match
        assert entry.rationale.strip(), entry.match


def test_all_sinks_carry_a_cwe(pack_set):
    for sink in pack_set.sinks:
        assert sink.cwe.startswith("CWE-"), sink.match


# ---------------------------------------------------------------------
# Seed discipline
# ---------------------------------------------------------------------


def test_at_most_nine_exemplars_per_role_per_class(pack_set):
    per_class: dict[tuple[str, str], int] = {}
    for sink in pack_set.sinks:
        key = ("sink", sink.sink_class)
        per_class[key] = per_class.get(key, 0) + 1
    for src in pack_set.sources:
        for cls in src.taint_classes:
            key = ("source", cls)
            per_class[key] = per_class.get(key, 0) + 1
    for prop in pack_set.propagators:
        key = ("propagator", "stdlib")
        per_class[key] = per_class.get(key, 0) + 1
    offenders = {k: n for k, n in per_class.items() if n > 9}
    assert not offenders, offenders


def test_no_entry_exceeds_the_class_cap(pack_set):
    for src in pack_set.sources:
        assert len(src.taint_classes) <= MAX_TAINT_CLASSES_PER_ENTRY


def test_no_narrowing_propagators_in_the_javascript_seeds(pack_set):
    assert not any(p.narrowing for p in pack_set.propagators)


# ---------------------------------------------------------------------
# Emissibility over the shipped set
# ---------------------------------------------------------------------


def test_emissibility_report_accounts_for_every_entry(pack_set):
    report = emissibility_report(pack_set, language="javascript")
    total = (len(pack_set.sources) + len(pack_set.sinks)
             + len(pack_set.sanitizers) + len(pack_set.propagators))
    assert report.emissible_rows + len(report.rejected) == total
    counts = dict(report.counts)
    # sources + sinks + operator-grade propagators are emissible;
    # sanitizers never are (barrier channel closed).
    assert counts["sourceModel"] == len(pack_set.sources)
    assert counts["sinkModel"] == len(pack_set.sinks)
    assert counts["summaryModel"] == len(pack_set.propagators)
    sanitizer_rejects = [r for r in report.rejected
                         if r.row.startswith("sanitizer:")]
    assert len(sanitizer_rejects) == len(pack_set.sanitizers)
    assert all("barrier" in r.reason for r in sanitizer_rejects)
