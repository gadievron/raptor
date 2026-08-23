"""The programme's Java threat-model authority — one table, two consumers.

The b44 enforcement-flip stop-ship exposed a structural hazard: the
taint-free fold tier (:mod:`core.analysis.const_fold_java`) and the
postpass source-kind locator (:mod:`core.analysis.sanitizer_cut_postpass`)
each carried their OWN classification of the ``System.getenv`` /
``System.getProperty`` API family — attacker-uncontrolled in one table,
taint source in the other. The contradiction was invisible on a corpus
with no environment-taint fixtures and suppressed six real Juliet
findings the moment enforcement went live.

This module is the single authority both consumers derive from, so the
same API can never be a taint source in one table and taint-free in the
other — the invariant is asserted at import time and pinned by
``test_threat_model_authority.py``, which fails the build if either
consumer stops deriving.

Decided semantics (programme threat model = the corpus threat models:
Juliet treats environment/properties/console/file as attacker-influenced,
and the pipeline passes CodeQL ``--threat-model=local`` which groups the
same kinds):

* ``System.getenv`` and ``System.getProperty`` are TAINT SOURCES.  The
  b37-era no-``setProperty`` tree proof only rules out in-process
  writes; the environment itself is the attack surface under this
  model, so no scan can make these reads taint-free.
* A ``Properties.getProperty`` read that b22's strict resolver proves
  to yield only file-constant / literal-default values is a CONSTANT —
  the resolver proves the value; that is different from trusting the
  API and is unaffected by this table.
* JVM constant FIELDS (``File.separator`` family, JDK class constants
  such as ``ResultSet.TYPE_FORWARD_ONLY``) carry no request or
  environment data and stay taint-free.

Two-authority split (do not merge them): this module answers "is this
API family a TAINT SOURCE?"; the CWE danger models
(:mod:`core.dataflow.smt_barrier` lineage, consumed via
``_union_member_check``/``_literals_clear_danger``) answer "can this
concrete constant violate this finding class?". A taint-free claim
composes BOTH — non-source per this module AND members clearing the
danger models — at the fold boundary. Deriving one from the other was
evaluated and rejected in b45: they classify different things.
"""

from __future__ import annotations


# ``System.<name>(...)`` reads that ARE taint sources under the
# programme threat model.  Deriving consumers: the postpass environment
# source kind (patterns below) and — by exclusion — the fold tier.
ENVIRONMENT_SOURCE_SYSTEM_READS: frozenset[str] = frozenset({
    "getenv",
    "getProperty",
})

# ``System.<name>(...)`` reads that are NOT taint sources and may fold
# to TAINT_FREE.  Empty under the current model: every known System
# read returns environment-influenced data.  Any future addition must
# argue why the API cannot carry attacker influence under threat-model
# local, and cannot overlap the source set (asserted below).
NON_SOURCE_SYSTEM_READS: frozenset[str] = frozenset()

# JVM constant fields (accessed as ``Cls.field``, never method calls):
# compile-time/JVM-defined values with no attacker channel.
NON_SOURCE_JVM_CONSTANT_FIELDS: frozenset[str] = frozenset({
    "separator",
    "pathSeparator",
    "separatorChar",
})

# The invariant the b44 counterexample proved load-bearing: an API the
# locator treats as a taint source must never fold taint-free.
_overlap = ENVIRONMENT_SOURCE_SYSTEM_READS & NON_SOURCE_SYSTEM_READS
assert not _overlap, (
    "threat-model contradiction: %r classified as both taint source "
    "and taint-free" % sorted(_overlap)
)


def environment_source_patterns() -> tuple[str, ...]:
    """Locator regexes for the environment source kind, derived from
    the source set so a newly added source API automatically becomes a
    locator pattern and can never be folded taint-free."""
    return tuple(
        r"System\s*\.\s*%s\s*\(" % name
        for name in sorted(ENVIRONMENT_SOURCE_SYSTEM_READS)
    )


__all__ = [
    "ENVIRONMENT_SOURCE_SYSTEM_READS",
    "NON_SOURCE_JVM_CONSTANT_FIELDS",
    "NON_SOURCE_SYSTEM_READS",
    "environment_source_patterns",
]
