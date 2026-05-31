"""Corpus drivers for the binary-oracle precision harness.

Each driver implements the ``CorpusDriver`` protocol from
``binary_oracle_precision`` — it knows how to build/test/cover a single
corpus and emit the context dict the harness consumes.

Add a new corpus by writing a driver module here and registering it
below. Keep the registration explicit so the available corpora are
discoverable from one place.
"""

from typing import Any, Dict

from .synthetic import driver as _synthetic_driver
from .zlib import driver as _zlib_driver
from .libsodium import driver as _libsodium_driver
from .snappy import driver as _snappy_driver
from .leveldb import driver as _leveldb_driver
from .regex_rust import driver as _regex_rust_driver
from .zstd_holdout import driver as _zstd_holdout_driver

REGISTRY: Dict[str, Any] = {
    _synthetic_driver.name: _synthetic_driver,
    _zlib_driver.name: _zlib_driver,
    _libsodium_driver.name: _libsodium_driver,
    _snappy_driver.name: _snappy_driver,
    _leveldb_driver.name: _leveldb_driver,
    _regex_rust_driver.name: _regex_rust_driver,
    _zstd_holdout_driver.name: _zstd_holdout_driver,
}
