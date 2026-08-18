"""Negative control: "deserialization" keyword family (Python).

Safe deserialization only — json.loads and yaml.safe_load. No pickle,
no yaml.load, no Marshal. The unsafe-shape pattern must not match any
line of this fixture.
"""

import json

import yaml


def load_config(text):
    return json.loads(text)


def load_manifest(stream):
    # safe_load resolves no Python objects — the safe idiom the
    # unsafe-shape pattern (yaml.load / pickle.loads) must not match.
    return yaml.safe_load(stream)
