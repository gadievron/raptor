"""Shared constants for the taint test batteries."""

#: The spec universe the hand-computed extractor/engine batteries were
#: computed against. Those tests assert exact candidate and event sets
#: over fixtures that call subprocess/open/eval-family APIs, so they
#: load THIS pinned list, not the growing shipped default — a new seed
#: pack adding a second claim on the same callee (the secrets pack's
#: argv-visibility entry on subprocess.run, for example) must not
#: silently re-derive every hand-computed expectation. Seed-content
#: coverage of the full shipped set lives in test_seed_packs.py and
#: test_sink_packs.py, which always load ``default_pack_names``.
HAND_COMPUTED_PACKS = (
    "python/frameworks-django",
    "python/frameworks-fastapi",
    "python/frameworks-flask",
    "python/web-injection-core",
)
