"""Minimal consumer of ctx so SCA's reachability layer flips
the verdict from ``not_reachable`` to ``imported`` — proves
the Python import-detection layer correctly recognises ``import``
of the malicious dep."""

import ctx


def make_context():
    return ctx
