"""C checks share native source lines without changing standalone behavior."""

import pytest

from core.audit import prefilter


def test_c_checker_splits_native_lines_once():
    class Source(str):
        native_splits = 0

        def splitlines(self, keepends=False):
            if not keepends:
                self.native_splits += 1
            return super().splitlines(keepends)

    source = Source('int f(void) {\n  return 0;\n}\n')
    result = prefilter.PrefilterResult(file='x.c', function='f', language='c')
    prefilter._check_c_patterns(result, source, 1, None, None)
    assert source.native_splits == 1
    assert result.hits == []


@pytest.mark.parametrize('separator', ['\n', '\r\n', '\x0c', '\u2028'])
@pytest.mark.parametrize(('checker', 'source', 'guarded'), [
    (prefilter._check_c_assign_in_cond, 'if (x = 0) {\n  return;\n}', False),
    (prefilter._check_c_missing_bounds, 'int f(int i) {\n  return a[i];\n}', True),
    (prefilter._check_c_use_after_free, 'free(p);\np->field = 1;\nfree(p);', True),
    (prefilter._check_c_toctou, 'access(path, 0);\nopen(path, 0);', False),
    (prefilter._check_c_post_loop_oob, 'for (i = 0; i < cap; i++) {\n  a[i] = 0;\n}\na[i] = 1;', True),
])
def test_shared_lines_preserve_standalone_hits(checker, source, guarded, separator):
    source = source.replace('\n', separator)
    lines = source.splitlines()
    original_lines = lines.copy()
    independent = prefilter.PrefilterResult(file='x.c', function='f', language='c')
    shared = prefilter.PrefilterResult(file='x.c', function='f', language='c')
    args = (prefilter._GuardViews(independent, source),) if guarded else ()
    checker(independent, source, 7, *args)
    args = (prefilter._GuardViews(shared, source),) if guarded else ()
    checker(shared, source, 7, *args, _source_lines=lines)
    assert independent.hits
    assert shared == independent
    assert lines == original_lines
