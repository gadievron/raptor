"""Unused depth lookup preparation must not affect constant tables."""

import tracemalloc

import pytest

from core.audit import return_domain as rd


@pytest.fixture(autouse=True)
def clear_return_domain_caches():
    from core.audit import return_domain as rd
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(
        rd, {"_DOMAIN_CACHE": {}, "_CONSTANTS_CACHE": {}},
        lock=rd._DOMAIN_CACHE_LOCK,
    ):
        yield


def test_definitionless_files_keep_guards_and_later_tables_independent(tmp_path):
    empty = '#if defined(FEATURE)\nint ordinary;\n#endif\n'
    (tmp_path / 'a.c').write_text(empty)
    (tmp_path / 'b.h').write_text(
        '#ifndef HEADER_GUARD\n#define HEADER_GUARD\n#define ERR_FATAL (-2)\n#endif\n',
    )
    (tmp_path / 'c.h').write_text('#ifdef FEATURE\n#define ERR_CONDITIONAL -9\n#endif\n')
    (tmp_path / 'd.h').write_text('enum errors { ERR_CODE = -3 };\n')
    (tmp_path / 'z.c').write_text(empty)
    assert rd._constants_for_root(tmp_path, rd._Budget(1000)) == {
        'ERR_FATAL': -2, 'ERR_CODE': -3,
    }


def test_definitionless_conditional_file_avoids_dense_depth_table(tmp_path):
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = '#if defined(FEATURE)\nint ordinary;\n#endif\n' * 30000
    (tmp_path / 'a.c').write_text(source)
    rd._constants_for_root(tmp_path, rd._Budget(1000))
    rd.clear_cache()
    tracemalloc.start()
    try:
        table = rd._constants_for_root(tmp_path, rd._Budget(1000))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert table == {}
    assert peak < len(source) * 3
