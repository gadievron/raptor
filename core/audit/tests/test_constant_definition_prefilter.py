"""Definition discovery retains its lexical and decoding semantics."""

import pytest

from core.audit import constant_resolution as cr


@pytest.mark.parametrize(('raw', 'expected'), [
    (b'int ordinary;\n', {}),
    (b'// invalid UTF-8: \xff\nint ordinary;\n', {}),
    (b'#de\\\nfine SPLIT 1\n', {}),
    (b'e\\\nnum { SPLIT = 1 };\n', {}),
    (b'#de/**/fine SPLIT 1\n', {}),
    (b'/* #define FALSE_MACRO 1\nenum { FALSE_ENUM = 2 }; */\n', {}),
    (b'// invalid UTF-8: \xff\n#define ANSWER 42\n', {'ANSWER': '42'}),
    (b'# define ANSWER 42\n', {'ANSWER': '42'}),
    (b'enum limits { LIMIT = 4 };\n', {'LIMIT': '4'}),
    (b'#define ANSWER \\\n42\n', {'ANSWER': '42'}),
])
def test_definition_discovery_boundaries(tmp_path, raw, expected):
    (tmp_path / 'a.c').write_bytes(raw)
    definitions = cr._scan_definitions(tmp_path)
    assert {name: records[0].body for name, records in definitions.items()} == expected
    assert all(len(records) == 1 for records in definitions.values())
